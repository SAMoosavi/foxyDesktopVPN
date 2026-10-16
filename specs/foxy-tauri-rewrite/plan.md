# foxy-tauri-rewrite — plan

## Context
- Scaffold: Tauri 2 app (`com.sam.foxy-desktop-vpn`), Leptos 0.8 CSR frontend
  (`foxy-desktop-vpn-ui`, `trunk serve/build`), `src-tauri` workspace member with only
  `tauri` + `tauri-plugin-opener` + `serde(_json)`. No lockfile committed, no CI yet.
- Origin (ground truth): `Vauth/FoxyVPN` — Android/Kotlin app that signs in with a Firefox
  account, obtains a Guardian proxy pass, and routes whole-device traffic through the
  Firefox VPN Fastly edge over an HTTP/2 tunnel; native engine is `hev-socks5-tunnel`
  (tun2socks); Go port reference is `firefox-vpn-client`. v1 scope is fully-system mode
  only; split-tunnel / custom DNS / proxy-only / quota / log-viewer are cut (spec Out of scope).
- Constraints (binding): no new frontend framework; no new tunnel/network dependency without
  architect approval; this step writes only `specs/`; CI must never create the GitHub repo.

## Options & trade-offs

### Tunnel engine (the big decision)
- **A. Three native per-OS stacks** (Linux NetworkManager/WireGuard, Windows Wintun service,
  Android VpnService in Kotlin). Best OS integration, but three codebases, three test paths,
  weeks of work. Rejected: violates ponytail (fewest files, ≤1-session tasks).
- **B. (Chosen) One Rust tunnel core + thin per-OS bring-up.** Port the proven behavior —
  Guardian token → Fastly edge HTTP/2 CONNECT tunnel → TUN tun2socks forwarding (the
  `firefox-vpn-client` + `hev-socks5-tunnel` logic) — as a single Rust module in
  `src-tauri`. Per-OS code is only interface bring-up + consent: Linux TUN + default route,
  Windows Wintun TUN handle, Android `VpnService` fd passed to the Rust core via the Tauri
  mobile entry point. The OS system-VPN indicator still fires on all three because each OS
  sees a real VPN interface + consent dialog (AC9), and there is one engine to test.
- **C. Hand off to an installed WireGuard/VPN app.** Least code, but requires a per-app
  install/config step → directly violates AC9. Rejected.

### Auth flow
- **Chosen: system browser via `opener` (already present) + loopback/deep-link callback.**
  `auth_sign_in` opens accounts.firefox.com; FxA redirects to `foxyvpn://oauth/callback`
  (or localhost loopback) which the app captures — no token pasting (AC1). Rejected: embedded
  WebView login (weaker phishing story, more code) and manual token paste (violates AC1).

### Guardian HTTP + secure storage
- HTTP needs async + HTTP/2 CONNECT. **Propose `reqwest`** (de-facto standard, one dep) —
  **requires architect approval** per spec constraints; alternative raw `hyper` is more code,
  rejected on ponytail grounds but available if the approval is denied.
- Token storage: **propose `keyring` crate (OS keychain)** — approval required. Rejected:
  Tauri `store` plugin (plaintext JSON next to the binary, weaker for a VPN token).

### Updater signing
- **Chosen: `tauri-plugin-updater` + minisign keypair (standard Tauri flow).** Keypair generated
  once locally; pubkey ships in `tauri.conf.json`; private key + password live only as GitHub
  Actions secrets; CI signs bundles and publishes `.sig` + `latest.json` to GitHub Releases.
  Rejected: unsigned/manual-download updates (violates AC14) and custom update server (new infra).

## Chosen design

### Tauri commands (minimal surface; all state behind one mutex for AC6)
| Command | Direction | Notes |
|---|---|---|
| `auth_sign_in` | UI→Rust | opens system browser, returns immediately; result arrives via event |
| `auth_sign_out` | UI→Rust | clears keychain token, emits `auth-changed` |
| `list_servers` | UI→Rust | Guardian server list → `[{id, city, country, …}]` (AC2) |
| `vpn_connect(server_id)` | UI→Rust | idempotent: connecting/connected + repeat call = no-op (AC6) |
| `vpn_disconnect` | UI→Rust | tears down tunnel, restores routes (AC5) |
| `vpn_status` | UI→Rust | `{state, server, exit_ip, last_error}` polled by UI (AC3/5/12) |

Events: `auth-changed`, `vpn-state` (push state changes so every button visibly reacts ≤5s, AC12).
State machine: `Disconnected → Connecting → Connected`, `Connecting → Disconnected (error)`,
guard: `connect` while `Connecting|Connected` = no-op. Token 401 → `SignedOut` + re-sign-in
prompt (AC7). Offline at connect → `last_error=offline`, stays `Disconnected` (AC8).

### Tunnel core (`src-tauri`, one module, OS shims behind `#[cfg]`)
- `tunnel::{connect(config) -> handle, disconnect(handle)}` — TUN read/write loop ↔ HTTP/2
  tunnel to the Fastly edge selected from the Guardian server list, using the Guardian token.
- Linux: `tun` device + default-route via netlink/`ip` (prompt = system auth dialog).
- Windows: Wintun TUN handle (consent = adapter-install prompt).
- Android: `VpnService` (Tauri mobile entry point) consent + fd → same Rust core.
- System DNS is used as-is (AC10: no DNS screen). No split-tunnel UI (AC10).

### Frontend (reuse Leptos 0.8 CSR, `src/`, no new framework — AC11)
Four views only: sign-in button → server list (city/country) → Connect/Disconnect + status
line → error line. No split-tunnel/DNS screens exist (AC10). Every button updates status or
error ≤5s (AC12).

### Data shape
```rust
Server { id: String, city: String, country: String, hostname: String }
VpnStatus { state: Disconnected|Connecting|Connected, server: Option<String>, exit_ip: Option<String>, last_error: Option<String> }
```

### Updater + CI
- `tauri-plugin-updater` (approval required), `bundle.plugins.updater: {active, endpoints:
  [https://github.com/<org>/<repo>/releases/latest/download/latest.json], pubkey}`.
- One workflow `.github/workflows/build.yml`, three jobs (linux / windows / android) via
  `tauri-action`; artifacts: AppImage+deb (Linux), nsis (Windows), apk (Android); signed
  updater artifacts + `latest.json` on Releases. Android job needs JDK 17 + NDK + `tauri
  android init` output committed.
- Repo runbook is a text file (`specs/foxy-tauri-rewrite/runbook.md` or repo `docs/`); the
  workflow contains **no** `gh repo create` step (AC15).

## How each part will be verified
- Tunnel/state: `cargo test -p foxy-desktop-vpn` — state-machine unit tests (double-connect
  no-op, offline stays disconnected, 401 → signed-out). Command: `cargo test`.
- Frontend smoke: `trunk build` succeeds; `cargo tauri dev` shows the 4 views.
- AC3/4/5 per OS: connect → `vpn_status.exit_ip` matches picked server; external IP-check page
  shows exit IP, then direct IP after disconnect (manual check on each OS).
- AC9: OS indicator observed (Linux auth prompt, Windows adapter consent, Android VpnService
  consent).
- AC10/11/12: UI audit — screens are only the four; no dead button (click each, ≤5s feedback).
- AC13: green Actions run on main with three downloadable artifacts.
- AC14: install vN, publish vN+1, observe update prompt / silent update without reinstall.
- AC15: runbook followed verbatim on a fresh clone; `grep -r "repo create" .github/` empty.

## Risks
1. **New deps need approval** (`reqwest`/`hyper`, TUN/`wintun`, `keyring`, updater, deep-link).
   Mitigation: task 2 starts with the approval ask; fallback is std-only `TcpStream`+hand-rolled
   H2 (slower, noted). Escalate to `team-lead` if denied.
2. **Guardian/FxA is unofficial/undocumented** — endpoints may shift. Mitigation: isolate all
   Guardian HTTP in one module; pin + test against recorded fixtures; failure surfaces as
   re-sign-in prompt (AC7), never a stuck spinner.
3. **Android toolchain (JDK/NDK, VpnService via Tauri mobile)** is the least certain. Mitigation:
   do Linux first, Windows second, Android last; Android failure blocks only its task.
4. **Wintun driver signing / Windows consent friction.** Mitigation: use released wintun.dll,
   document consent in runbook.
5. **No committed lockfile** (`/Cargo.lock` gitignored) → unreproducible CI. Mitigation: task 1
   commits the lockfile or documents why not.

## Dependency approval gate (ask architect before implementing)
`reqwest` (or hyper), TUN crate + wintun, `keyring`, `tauri-plugin-updater`,
`tauri-plugin-deep-link` (+ single-instance if needed). No code using them lands before approval.
