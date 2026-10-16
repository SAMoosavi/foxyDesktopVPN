# foxy-tauri-rewrite — tasks

> Task shape per spec-grooming: one-line Goal, short description, ACs covered, ≤1 session.
> First task is always scaffold + one passing test. Every spec AC is mapped; no AC is orphaned.

## AC index (from `spec.md`, in checkbox order)
1. Browser sign-in → signed-in home, no token pasting · 2. Server list with city/country ·
3. Connect → connected status + exit location/IP · 4. IP-check shows exit IP (Linux/Windows/Android) ·
5. Disconnect → disconnected + direct IP · 6. Double-Connect opens one connection ·
7. Expired token → re-sign-in prompt · 8. Offline Connect → offline error, stays disconnected ·
9. Fully-system mode + OS indicator/consent on all three OSes · 10. No split-tunnel/DNS screens ·
11. UI = 4 elements only, Leptos CSR · 12. Every button reacts ≤5s · 13. One workflow, 3 bundles, green run ·
14. Updater works without reinstall · 15. Runbook exists; CI never creates the repo.

## Dependency approval gate (blocking for tasks 2–5, 10)
New deps (`reqwest`/hyper, TUN/wintun, `keyring`, `tauri-plugin-updater`, `tauri-plugin-deep-link`)
require architect approval per spec constraints. If denied, escalate to `team-lead` before coding.

---

1. **Scaffold + one passing test.** — Goal: `cargo test` green and `trunk build` smoke pass on the untouched scaffold.
   Wire a single placeholder test (e.g. initial `VpnState::Disconnected`) in `src-tauri`, commit the
   lockfile (or document why not), record `cargo test` + `trunk build` output. Covers: harness for all ACs.
2. **FxA sign-in via system browser.** — Goal: sign-in completes in the browser, app lands on signed-in home (depends on #1).
   `auth_sign_in` (opener) + deep-link/loopback callback + `auth_sign_out`; token to OS keychain (approval-gated).
   Verify: click sign-in → browser → home screen, no pasting. Covers ACs 1, 12.
3. **Server list fetch + picker UI.** — Goal: signed-in user sees city/country list and picks a server (depends on #2).
   `list_servers` (Guardian API, approval-gated HTTP) + Leptos list view; empty-list shows error line, not spinner.
   Verify: list renders with city/country. Covers ACs 2, 12.
4. **Connect/disconnect commands + state machine + status UI.** — Goal: one guarded connection with visible status (depends on #3).
   `vpn_connect`/`vpn_disconnect`/`vpn_status` + `Disconnected→Connecting→Connected` mutex guard (repeat connect = no-op)
   + status/exit-IP/error line in Leptos; stub tunnel backend behind a trait so this lands before per-OS work.
   Verify: `cargo test` (double-connect single-handle, status transitions) + UI shows status. Covers ACs 3, 5 (status half), 6, 11, 12.
5. **Linux system tunnel.** — Goal: fully-system routing on Linux via the Rust tunnel core (depends on #4).
   TUN + Fastly HTTP/2 tunnel (port of `firefox-vpn-client`/`hev-socks5-tunnel` behavior) + default route + system prompt.
   Verify: IP-check shows exit IP; disconnect restores direct IP; OS prompt observed. Covers ACs 4 (Linux), 9 (Linux).
6. **Windows system tunnel.** — Goal: same core routing on Windows via Wintun (depends on #5).
   Wintun TUN bring-up + adapter consent; core `tunnel` module unchanged. Verify: IP-check + consent observed.
   Covers ACs 4 (Windows), 9 (Windows).
7. **Android system tunnel.** — Goal: same core routing on Android via VpnService fd (depends on #5; parallel with #6).
   Tauri mobile entry point + VpnService consent + fd handoff to Rust core; commit `tauri android init` outputs.
   Verify: IP-check + VpnService consent observed. Covers ACs 4 (Android), 9 (Android).
8. **Error/offline/expired-token handling.** — Goal: every failure shows a message, never a stuck spinner (depends on #4).
   Offline-at-connect error + stays disconnected; Guardian 401 → signed-out/re-sign-in prompt; error-line UI.
   Verify: `cargo test` (offline + 401 transitions) + airplane-mode manual check. Covers ACs 7, 8.
9. **CI: one workflow, three bundles.** — Goal: green run on main yields Linux + Windows + Android artifacts (depends on #6, #7).
   `.github/workflows/build.yml` (3 jobs via `tauri-action`; JDK/NDK for Android); assert no `gh repo create` in workflow.
   Verify: green run + three downloadable artifacts. Covers AC 13.
10. **Updater + signing live.** — Goal: installed app updates without reinstall (depends on #9).
    `tauri-plugin-updater` (approval-gated) + minisign keypair (pubkey in config, private key as Actions secrets) +
    signed `.sig`/`latest.json` on Releases. Verify: install vN → publish vN+1 → update prompt/silent update.
    Covers AC 14.
11. **Repo runbook + v1 UI audit.** — Goal: manual repo steps documented and UI proven minimal (depends on #9).
    Text runbook (`gh repo create` + push + worktree commands; CI-must-not-create-repo note) + audit: only 4 UI elements,
    no split-tunnel/DNS screens, every button reacts ≤5s. Verify: runbook followed verbatim; `grep repo.create .github/` empty.
    Covers ACs 10, 15 (plus final sweep of 11, 12).

## Coverage check
AC1→#2 · AC2→#3 · AC3→#4 · AC4→#5/#6/#7 · AC5→#4(status)/#5–#7(restore) · AC6→#4 · AC7→#8 ·
AC8→#8 · AC9→#5/#6/#7 · AC10→#11 · AC11→#4 · AC12→#2/#3/#4, swept in #11 · AC13→#9 · AC14→#10 · AC15→#11.
