# Repo runbook — foxyDesktopVPN (Tauri rewrite)

Manual steps only. CI never creates the repo (AC15): `.github/workflows/build.yml`
contains no `gh repo create` step and must never gain one — verify with
`grep -ri "repo.create" .github/` (expect empty).

`<ORG>/<REPO>` below is a placeholder (e.g. `you/foxyDesktopVPN` or
`you/foxy-tauri`). Substitute your real values; do not invent an org.

## 1. Create the public repo (once, from this worktree)

```sh
gh repo create <ORG>/<REPO> --public --source=. --remote=origin --push
```

If the remote already exists, point and push instead:

```sh
git remote add origin git@github.com:<ORG>/<REPO>.git  # or `gh repo ...` URL
git push -u origin main && git push --tags
```

## 2. Worktrees (this project uses one worktree per task)

```sh
git worktree list
git worktree add ../foxyDesktopVPN-wt-<name> -b impl/<name>
# when done: git worktree remove ../foxyDesktopVPN-wt-<name>
```

## 3. Firefox account sign-in (email + password)

Sign-in mirrors the reference client (`Vauth/FoxyVPN`): the app asks for the
Firefox account email and password, derives the onepw `authPW` (PBKDF2
quickStretch → HKDF), calls
`POST https://api.accounts.firefox.com/v1/account/login`, handles the emailed
confirmation code when FxA asks for it, then exchanges the session token for
an access/refresh pair via the Hawk-signed `fxa-credentials` grant. No browser
is opened and no client registration is needed — it uses the same public FxA
client id as the reference client.

The session is stored in the OS keychain (`foxy-desktop-vpn` / `fxa-session`)
and refreshed on launch, so returning users are auto-logged-in. The password
is never stored, only the token pair.

The server list comes from Mozilla's public Remote Settings collection
(`vpn-serverlist`); override it for local testing with:

```sh
FOXYVPN_SERVERS_URL=http://127.0.0.1:8787/servers
```

Notes:
- Some exit IPs get a Fastly bot challenge (`HTTP 406`) instead of a JSON
  answer. Like the reference client, the app solves it automatically: it fetches
  the challenge page, answers the proof-of-work / PAT / client-metrics rounds,
  posts the answers back and retries the login with the issued cookies. Only a
  captcha or an unsolvable challenge becomes an error.

## 4. Updater signing key + secrets (Task 10 / AC14)

A keypair was generated once locally with an empty password; the minisign
public key is committed in `src-tauri/tauri.conf.json`
(`plugins.updater.pubkey`). The private key stays outside the repo at
`~/.tauri/foxy.key` — back it up, and never commit it. To rotate, regenerate
and paste the new public key:

```sh
cargo tauri signer generate -w ~/.tauri/foxy.key -p "" --ci
```

Still manual: replace `<org>/<repo>` in `plugins.updater.endpoints` with the
real repo path after `gh repo create` (step 1).

Store the private key as Actions secrets (repo Settings → Secrets → Actions):

- `TAURI_SIGNING_PRIVATE_KEY` — contents of `~/.tauri/foxy.key`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — the password entered at keygen
  (empty string if none)

Without these secrets CI still builds green but emits unsigned bundles and the
`release` job refuses to publish (no `.sig` → no `latest.json`).

## 5. Release / update check (AC14)

```sh
git tag v0.2.0 && git push --tags   # CI builds, signs, publishes Release + latest.json
```

Manual verify: install vN, publish vN+1, confirm the app offers the update
(prompt or silent) without reinstall.

## 6. UI minimality re-audit (AC10/11/12)

`src/app.rs` must contain ONLY: the sign-in form (email + password + submit),
server list (city/country + Pick), Connect/Disconnect toggle + status line,
error/status lines. No split-tunnel/DNS screens, no dead buttons — every
handler sets a status or error signal synchronously before any `await`.

## 7. Connect: the local proxy data plane (proxy-only mode)

Pressing Connect runs the reference client's data plane (`src-tauri/src/dataplane.rs`):

1. The stored FxA access token is refreshed if needed, then Guardian mints a
   short-lived **proxy pass**: `GET https://vpn.mozilla.org/api/v1/fpn/token`
   (401/403 → re-sign-in prompt, 429 → quota error). The pass is renewed at
   half-life while connected.
2. The picked server resolves to its edge from Remote Settings (hostname +
   port, e.g. `faor73.m1.fastly-masque.net:2499`), TLS is opened with ALPN
   `h2`, and each target becomes an HTTP/2 `CONNECT host:port` stream with
   `proxy-authorization: Bearer <pass>` — H2UpstreamSession's protocol.
3. Two local proxies listen (reference defaults): **SOCKS5 `127.0.0.1:1080`**
   and **HTTP `127.0.0.1:8080`**. Local/loopback destinations are refused
   (never tunneled), exactly like the reference proxies.
4. The exit IP is read *through* the tunnel from
   `https://www.cloudflare.com/cdn-cgi/trace` and shown on the status line
   together with the proxy endpoints.
5. If `gsettings` + `org.gnome.system.proxy` exist, the desktop's system proxy
   is set to manual → `127.0.0.1:8080` (HTTP/HTTPS) and `127.0.0.1:1080`
   (SOCKS). The previous values are snapshotted to
   `~/.config/foxy-desktop-vpn/system-proxy.json`; **Disconnect** restores them,
   and every app launch restores any snapshot left by a killed session, so a
   crash can never leave a dead proxy configured.

Without gsettings (or on other desktops), point apps manually:

```sh
export https_proxy=http://127.0.0.1:8080 http_proxy=http://127.0.0.1:8080
export all_proxy=socks5://127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

Manual verify (while Connected):

```sh
ss -ltn | grep -E ':(1080|8080)'                     # both proxies up
curl -s -x http://127.0.0.1:8080 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc)='
curl -s --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace | grep -E '^(ip|loc)='
gsettings get org.gnome.system.proxy mode            # 'manual' while up
```

Both proxied traces must show the exit IP printed on the status line (and
`loc=` matching the picked server), while a direct `curl` shows your own IP.
After Disconnect: ports gone, `mode` back to its previous value.

Not ported from the reference app (follow-ups): UDP/TCP-redirect SOCKS
commands other than CONNECT (UDP ASSOCIATE returns "not supported"), DoH
bootstrap/edge IP pinning, TLS ClientHello splitting, upstream-proxy chaining,
and the TUN/fully-system mode (AC9).
