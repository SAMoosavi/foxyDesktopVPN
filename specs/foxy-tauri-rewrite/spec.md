# foxy-tauri-rewrite

## Goal
Rewrite FoxyVPN (Firefox-account Guardian VPN) as a Tauri 2 + Leptos app that signs in, connects system-wide traffic through the Firefox VPN exit, and ships Linux, Windows, and Android bundles with autoupdate from a public GitHub repo.

## Acceptance criteria
- [ ] Sign-in starts in the app and completes via Firefox account in the system browser, ending on a signed-in home screen with no manual token pasting.
- [ ] Signed-in app fetches the Guardian server list and shows at least city/country per server for the user to pick one.
- [ ] Pressing Connect on the picked server changes visible status to connected and shows the exit location/IP matching the picked server.
- [ ] With VPN connected, visiting an external IP-check page shows the VPN exit IP, not the user's direct IP, on each of Linux, Windows, and Android.
- [ ] Disconnect returns visible status to disconnected and an external IP-check page shows the direct IP again.
- [ ] Double-pressing Connect while connecting does not open two connections (one status line, one Connect/Disconnect button, no duplicate).
- [ ] Expired/invalid Guardian token shows a signed-out or re-sign-in prompt instead of a stuck connecting spinner.
- [ ] Airplane-mode/offline Connect attempt shows an offline error and stays disconnected.
- [ ] Fully system mode holds on all three OSes: no per-app or browser-only proxy setting step is needed, and connecting shows the OS system-VPN active indicator/consent (Linux system prompt, Windows adapter consent, Android VpnService consent).
- [ ] No custom split-tunnel screen and no custom DNS/DoH screen exist in v1 (system DNS is used); their absence is visible by inspecting the screens.
- [ ] UI consists only of sign-in, server list, connect/disconnect + status, and error line, reusing the existing Leptos CSR app (no new frontend framework visible).
- [ ] Every button in the UI visibly does something within 5 seconds (status or error change); no dead button exists.
- [ ] GitHub Actions has one workflow that builds Linux bundle, Windows bundle, and Android bundle, and a green run on main shows all three artifacts downloadable.
- [ ] Installed app offers an update through the Tauri updater (update-available prompt or silent update to a newer published version) without manual reinstall.
- [ ] Repo-creation runbook exists as text (gh repo create + push + worktree commands) and CI never creates the repo automatically (no gh-create step in the workflow file).

## Out of scope
- macOS / iOS builds and signing → follow-up: separate spec when requested.
- Proxy-only / per-app proxy mode → follow-up: rejected for v1 by fully-system-mode decision.
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
