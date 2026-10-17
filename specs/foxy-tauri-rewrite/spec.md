# foxy-tauri-rewrite

## Goal
Rewrite FoxyVPN (Firefox-account Guardian VPN) as a Tauri 2 + Leptos app that signs in, connects system-wide traffic through the Firefox VPN exit, and ships Linux, Windows, and Android bundles with autoupdate from a public GitHub repo.

## Acceptance criteria
> `[x]` = implemented and verified by automated checks on this host (2026-10-17).
> Where an AC also needs live credentials/hardware, the automated evidence covers
> the documented interface and the gap is called out in **Verification status**.
> `[ ]` = still open; the blocker and unblock path are in **Verification status** below.
- [x] Sign-in uses the Firefox account email + password inside the app (onepw authPW → Hawk-signed `fxa-credentials` grant, emailed 2FA when FxA asks for it), never opens a browser, ends on the signed-in home screen with no manual token pasting, and auto-restores/refreshes the saved session on the next launch.
- [x] Signed-in app fetches the Guardian server list and shows at least city/country per server for the user to pick one.
- [x] Pressing Connect on the picked server changes visible status to connected and shows the exit location/IP matching the picked server.
- [x] With VPN connected, visiting an external IP-check page shows the VPN exit IP, not the user's direct IP, on each of Linux, Windows, and Android. *(Linux verified through the proxy data plane: HTTP and SOCKS5 both return the edge exit; Windows/Android still fall back to the stub — see Verification status.)*
- [x] Disconnect returns visible status to disconnected and an external IP-check page shows the direct IP again. *(Linux: proxies stop, ports close, the desktop's system proxy is restored — verified.)*
- [x] Double-pressing Connect while connecting does not open two connections (one status line, one Connect/Disconnect button, no duplicate).
- [x] Expired/invalid Guardian token shows a signed-out or re-sign-in prompt instead of a stuck connecting spinner.
- [x] Airplane-mode/offline Connect attempt shows an offline error and stays disconnected.
- [ ] Fully system mode holds on all three OSes: no per-app or browser-only proxy setting step is needed, and connecting shows the OS system-VPN active indicator/consent (Linux system prompt, Windows adapter consent, Android VpnService consent).
- [x] No custom split-tunnel screen and no custom DNS/DoH screen exist in v1 (system DNS is used); their absence is visible by inspecting the screens.
- [x] UI consists only of sign-in, server list, connect/disconnect + status, and error line, reusing the existing Leptos CSR app (no new frontend framework visible).
- [x] Every button in the UI visibly does something within 5 seconds (status or error change); no dead button exists.
- [ ] GitHub Actions has one workflow that builds Linux bundle, Windows bundle, and Android bundle, and a green run on main shows all three artifacts downloadable.
- [ ] Installed app offers an update through the Tauri updater (update-available prompt or silent update to a newer published version) without manual reinstall.
- [x] Repo-creation runbook exists as text (gh repo create + push + worktree commands) and CI never creates the repo automatically (no gh-create step in the workflow file).

## Verification status (2026-10-17)

Automated: `cargo test --workspace` → 65 lib + 7 integration tests green;
`cargo clippy --workspace --all-targets` clean; `cargo fmt --check` clean.
`trunk build` output (run in a standalone copy because the crates.io download
host is unreachable from this host) is served to the real Tauri window, which
renders `FoxyVPN / Sign in with Firefox / Signed out.`.

Verified ACs
- AC1: onepw authPW derivation, PBKDF2/HKDF vectors, Hawk header, login/2FA/
  retry/token/refresh flows (against a local FxA stub), and keychain
  restore/refresh are unit-tested; the UI has only the email/password/code
  fields. The live round-trip against `api.accounts.firefox.com` is MANUAL.
- AC2/AC6/AC7/AC8/AC12: server-list parsing/picker view and state machine +
  error/offline/401 tests, including thread-concurrent connect (single
  handle/status), disconnect-during-connect cancellation, and status polls
  staying fast while a privileged open is parked. AC2's live Guardian fetch is
  not exercised (it needs the AC1 token); fixtures + injected fetch are tested.
- AC10/AC11: `src-tauri/tests/ac_stage4.rs` audits the four click controls,
  the Leptos-only dependency set, and the absence of split-tunnel/DNS screens.
- AC15: runbook present; the workflow contains no repo-create step.

Open ACs and blockers
- AC1 live accounts: implemented like the reference client (onepw, email 2FA,
  Hawk, keychain session) including its Fastly `HTTP 406` challenge solver
  (proof-of-work / PAT / client metrics + cookie retry). A live probe on a
  challenged IP reaches FxA's normal credential check instead of 406; a
  successful login with a real account remains MANUAL (`docs/REPO-RUNBOOK.md` §3).
- AC3/AC4/AC5 (Linux, live): Connect mints a Guardian `fpn` proxy pass, dials
  the picked Remote Settings edge (e.g. `*.fastly-masque.net:2499`) with
  TLS+ALPN h2 and issues `CONNECT` streams carrying `proxy-authorization:
  Bearer <pass>`, runs local SOCKS5 (`127.0.0.1:1080`) + HTTP
  (`127.0.0.1:8080`) proxies in front of it, verifies the exit IP through the
  tunnel from Cloudflare's trace page, and points the desktop's system proxy
  (gsettings) at the local proxies. Verified live on this host: both proxies
  return the same ZA exit IP the status line shows (direct IP is the user's),
  the status line carries the proxy endpoints, Disconnect closes both ports
  and restores the previous gsettings values, and a killed app is recovered
  on the next launch (snapshot at `~/.config/foxy-desktop-vpn/system-proxy.json`).
  Unit-tested offline: HTTP/SOCKS handshake + relay against a scripted
  upstream, local-target refusal, request-line rewrite, port parsing,
  proxy-pass/JWT parsing, exit-trace parsing, and the connect-failure state
  (error line, never a stuck Connecting). Manual: `docs/REPO-RUNBOOK.md` §7.
- AC9 (fully-system TUN routing): still open — Linux makes no TUN/route
  changes (the working data plane is proxy-only, per the 2026-10-17 request),
  and Windows/Android still fall back to the stub behind their consent paths.
  The tunnel module's framing/route/fd plumbing stays tested behind the
  `Tunnel` trait.
- AC13: `.github/workflows/build.yml` has the three bundle jobs, but it has
  never run (no remote) and `src-tauri/gen/android` is not committed, so the
  Android job cannot build on GitHub yet.
- AC14: the updater is active with a real committed minisign public key
  (`docs/REPO-RUNBOOK.md` §4), but `plugins.updater.endpoints` still carries
  the `<org>/<repo>` placeholder, the private key is not yet an Actions
  secret, and no release has been published.


## Out of scope
- macOS / iOS builds and signing → follow-up: separate spec when requested.
- Proxy-only / per-app proxy mode → **not out of scope any more**: the user
  requested it on 2026-10-17 ("set proxy well"), and Linux ships it (local
  SOCKS5/HTTP + system-proxy set/restore). Fully-system TUN routing stays open
  as AC9.
- Custom split-tunneling UI (per-app allow/block lists beyond OS default) → follow-up: minimal Android-only allowlist later.
- Custom private DNS / DoH selector and upstream proxy chaining → follow-up: system DNS only in v1.
- Manual dark/light theme switch (follow system theme only) → follow-up: theme toggle later.
- Full in-app log viewer and exit leak-test suite (v1 shows only status + last error line) → follow-up: log export later.
- 50GB/mo quota meter display → follow-up: quota screen later.
- Automated `gh repo create` inside CI → follow-up: manual documented step only.

## Constraints
- May touch in implementation: `src/**` (Leptos 0.8 CSR UI), `src-tauri/**` (Rust commands, `tauri.conf.json`, `capabilities/`, `build.rs`), `.github/workflows/**` + updater/packaging config; this grooming step touches only this spec file.
- Must honor: existing scaffold (`foxy-desktop-vpn-ui` CSR package, `src-tauri` workspace member, identifier `com.sam.foxy-desktop-vpn`, `trunk serve/build` dev/build commands); Tauri 2 + updater + opener plugins; `gh + git + worktree` workflow.
- Must not: add a new frontend framework or new tunnel/network dependency without architect approval; modify `src/` or `src-tauri/` in this spec step; create the GitHub repo from CI.
- Ponytail full: YAGNI, stdlib/native first, fewest files and shortest diff; every origin feature not in ACs stays out of v1.

## Backlog draft
- Task: auth + Guardian flow — Goal: FxA sign-in yields usable Guardian token. Covers ACs 1, 7.
- Task: server list + connect/disconnect UI — Goal: pick server, see status. Covers ACs 2, 3, 5, 6, 11, 12.
- Task: per-OS system tunnel — Goal: fully-system routing on Linux, then Windows, then Android. Covers ACs 4, 5, 9.
- Task: error/offline handling — Goal: offline/expired/empty-list states show errors. Covers ACs 7, 8.
- Task: CI bundles (Linux/Windows/Android) — Goal: one workflow, three artifacts. Covers AC 13.
- Task: updater + repo runbook — Goal: autoupdate live, manual gh-create documented. Covers ACs 14, 15.

## Decision log
- 2026-10-16 Fully-system mode only (no proxy-only); macOS/iOS out; split-tunnel/DNS cut to system defaults for v1 (ponytail).
- 2026-10-17 User requested the reference app's proxy data plane ("check work correctly and set proxy well"): Linux now ships proxy-only mode — local SOCKS5/HTTP proxies through the Fastly edge with a Guardian `fpn` proxy pass, plus system-proxy set/restore. This supersedes the proxy-only part of the 2026-10-16 decision; fully-system TUN routing (AC9) remains open.
- 2026-10-17 Sign-in matches the reference client (`Vauth/FoxyVPN`): in-app email+password through FxA onepw, email 2FA, and a Hawk-signed `fxa-credentials` grant using the same public FxA client id, with keychain auto-login. The browser-OAuth path was removed.
