//! Stage-4 verification gaps for specs/foxy-tauri-rewrite (tester-owned).
//!
//! Unit tests in `src/lib.rs` already cover sequential double-connect,
//! offline, 401 and empty-string server id. This file pins what they miss:
//! thread-concurrent connect (AC6), the reaction-budget harness (AC12), the
//! v1 UI minimality audit (AC10/11), the email/password + 2FA sign-in static
//! half (AC1, no browser, reference-client onepw flow), and the
//! CI/updater/runbook config files (AC13/14/15) resolved via
//! `CARGO_MANIFEST_DIR` so they run from any cwd.

use foxy_desktop_vpn_lib::{VpnState, VpnStore, vpn_connect_impl, vpn_disconnect_impl};
use std::time::{Duration, Instant};

/// Only one test touches the tunnel path; it scrubs the desktop-session env
/// vars so `auth_session_present()` is false and the open takes the fast,
/// side-effect-free stub fallback (unprivileged `ip` fails fast, no pkexec
/// prompt, no route mutation). RAII restores the vars even on panic.
struct NoDesktopSession {
    saved_display: Option<std::ffi::OsString>,
    saved_wayland: Option<std::ffi::OsString>,
}

impl NoDesktopSession {
    fn enter() -> Self {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // Leaked guard: held for the rest of the process. Only one test
        // scrubs env and no other test reads these vars, so this cannot
        // order-depend or deadlock anything else in this binary.
        let guard = LOCK.lock().unwrap();
        std::mem::forget(guard);
        let saved_display = std::env::var_os("DISPLAY");
        let saved_wayland = std::env::var_os("WAYLAND_DISPLAY");
        // SAFETY: env mutation is serialized by LOCK above and no other test
        // in this binary reads these vars.
        unsafe {
            std::env::remove_var("DISPLAY");
            std::env::remove_var("WAYLAND_DISPLAY");
        }
        Self {
            saved_display,
            saved_wayland,
        }
    }
}

impl Drop for NoDesktopSession {
    fn drop(&mut self) {
        // SAFETY: same serialization as `enter`; restores pre-test values.
        unsafe {
            if let Some(v) = self.saved_display.take() {
                std::env::set_var("DISPLAY", v);
            }
            if let Some(v) = self.saved_wayland.take() {
                std::env::set_var("WAYLAND_DISPLAY", v);
            }
        }
    }
}

/// AC6 edge: N threads hammering connect concurrently still yield one
/// connection — every caller sees the identical status line.
#[test]
fn concurrent_connect_keeps_single_connection() {
    let _no_session = NoDesktopSession::enter();
    let store = std::sync::Arc::new(VpnStore::default());
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let store = std::sync::Arc::clone(&store);
            std::thread::spawn(move || {
                vpn_connect_impl(
                    &store,
                    if i % 2 == 0 {
                        "us-california"
                    } else {
                        "jp-tokyo"
                    },
                )
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for r in &results {
        assert_eq!(r.state, VpnState::Connected);
        assert_eq!(*r, results[0], "all racers must see one status line");
    }
    assert!(results[0].exit_ip.is_some());
    assert_eq!(
        foxy_desktop_vpn_lib::vpn_status_impl(&store).state,
        VpnState::Connected
    );
    vpn_disconnect_impl(&store);
}

/// AC12 harness: the status-line read behind every button stays far inside
/// the 5s "every button visibly does something" budget.
///
/// NOTE (spec evidence): AC12 requires a *visible reaction* ≤5s, not full
/// connect completion — the UI sets `Connecting…`/error synchronously before
/// any await, and `begin_browser_sign_in` returns immediately (unit-tested in
/// lib.rs). Full completion timing is MANUAL. The earlier stall (status polls
/// blocked behind a blocking `pkexec` open because the status mutex was held
/// across tunnel bring-up) is fixed: bring-up now runs on a separate tunnel
/// gate, pinned by `status_polls_stay_responsive_during_slow_open` in
/// src/lib.rs.
#[test]
fn status_polls_stay_within_reaction_budget() {
    let store = VpnStore::default();
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = foxy_desktop_vpn_lib::vpn_status_impl(&store);
    }
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "1000 status polls took {:?}",
        start.elapsed()
    );
}
/// AC10/AC11 audit: v1 UI keeps the reference flow's controls only — email +
/// password (and emailed code) submit, Pick, Connect/Disconnect toggle,
/// sign-out — in the reused Leptos CSR app, with no new frontend framework,
/// no split-tunnel screen and no DNS/DoH screen.
#[test]
fn ui_is_four_controls_leptos_only_no_tunnel_or_dns_screens() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let app = std::fs::read_to_string(format!("{manifest}/../src/app.rs"))
        .expect("src/app.rs must exist");
    assert_eq!(
        app.matches("on:click").count(),
        3,
        "click handlers: Pick, Connect/Disconnect toggle, sign-out"
    );
    assert_eq!(
        app.matches("on:submit").count(),
        2,
        "submit handlers: sign-in and 2FA code"
    );
    for label in [
        "Sign in with Firefox",
        "Continue",
        "Verify",
        "Pick",
        "Connect",
        "Disconnect",
        "Sign out",
    ] {
        assert!(app.contains(label), "UI missing control {label:?}");
    }
    assert!(
        app.contains("type=\"email\""),
        "sign-in needs an email field"
    );
    assert!(
        app.contains("type=\"password\""),
        "sign-in needs a password field"
    );
    let lower = app.to_lowercase();
    for banned in ["split", "dns", "doh"] {
        assert!(
            !lower.contains(banned),
            "v1 must have no split-tunnel/DNS screen, found {banned:?} in src/app.rs"
        );
    }
    let root_cargo = std::fs::read_to_string(format!("{manifest}/../Cargo.toml"))
        .expect("workspace Cargo.toml must exist");
    assert!(
        root_cargo.contains("leptos"),
        "UI must reuse the Leptos CSR app"
    );
    for framework in ["react", "yew", "dioxus", "vue", "svelte", "angular"] {
        assert!(
            !root_cargo.to_lowercase().contains(framework),
            "no new frontend framework allowed, found {framework:?}"
        );
    }
}
/// AC1 static half: sign-in mirrors the reference client (email + password
/// → onepw authPW → optional emailed code → Hawk-signed fxa-credentials grant)
/// with no browser and no token pasting; the keychain session is restored and
/// refreshed on launch (auto-login). The live round-trip is MANUAL.
#[test]
fn sign_in_uses_fxa_onepw_without_a_browser() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let lib = std::fs::read_to_string(format!("{manifest}/src/lib.rs"))
        .expect("src-tauri/src/lib.rs must exist");
    assert!(
        lib.contains("derive_auth_pw") && lib.contains("hawk_header"),
        "sign-in must use the onepw authPW + Hawk flow"
    );
    assert!(
        lib.contains("\"fxa-credentials\"") && lib.contains("verify_two_factor"),
        "sign-in must exchange the FXA session for tokens and support emailed 2FA"
    );
    assert!(
        !lib.contains("open_url") && !lib.contains("begin_browser_sign_in"),
        "sign-in must not open a browser"
    );
    let app = std::fs::read_to_string(format!("{manifest}/../src/app.rs"))
        .expect("src/app.rs must exist");
    assert!(
        app.contains("auth_restore"),
        "the app must auto-restore its saved session on launch"
    );
    assert!(
        app.contains("auth_verify_code"),
        "the app must offer the emailed confirmation-code step"
    );
    let lower = app.to_lowercase();
    assert!(
        !lower.contains("paste"),
        "no manual token pasting allowed (AC1)"
    );
    assert!(!lower.contains("token"), "no token field in the UI (AC1)");
}

/// AC13 config: one workflow, three bundle jobs (linux/windows/android), each
/// uploading artifacts built via tauri-action. Green run on main is MANUAL.
#[test]
fn ci_workflow_builds_three_bundles() {
    let path = format!(
        "{}/../.github/workflows/build.yml",
        env!("CARGO_MANIFEST_DIR")
    );
    let yml = std::fs::read_to_string(&path).expect("build.yml must exist");
    for job in ["build-linux", "build-windows", "build-android"] {
        assert!(yml.contains(job), "workflow missing job {job}");
    }
    assert!(
        yml.contains("tauri-action"),
        "bundles must build via tauri-action"
    );
    assert!(
        yml.matches("upload-artifact").count() >= 3,
        "each bundle job must upload its artifacts"
    );
    for artifact in ["AppImage", "nsis", "apk"] {
        assert!(yml.contains(artifact), "workflow missing {artifact} bundle");
    }
}

/// AC15 config: runbook exists as text (manual gh-create + worktree steps)
/// and CI never creates the repo automatically.
#[test]
fn runbook_exists_and_ci_never_creates_repo() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let runbook = format!("{manifest}/../docs/REPO-RUNBOOK.md");
    let text = std::fs::read_to_string(&runbook).expect("docs/REPO-RUNBOOK.md must exist");
    assert!(
        text.contains("gh repo create"),
        "runbook must document manual repo creation"
    );
    assert!(
        text.contains("worktree"),
        "runbook must document worktree commands"
    );
    let yml =
        std::fs::read_to_string(format!("{manifest}/../.github/workflows/build.yml")).unwrap();
    assert!(
        !yml.to_lowercase().contains("repo create"),
        "workflow must not contain a gh repo-create step"
    );
}

/// AC14 config: Tauri updater is active with a releases endpoint, a real
/// minisign pubkey, and wiring in Rust deps + capabilities. Live update
/// (install vN → publish vN+1) is MANUAL — the private key must be stored as
/// Actions secrets per docs/REPO-RUNBOOK.md, and the endpoint still carries the
/// `<org>/<repo>` placeholder until the repo is created.
#[test]
fn updater_active_with_releases_endpoint() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let conf = std::fs::read_to_string(format!("{manifest}/tauri.conf.json"))
        .expect("tauri.conf.json must exist");
    let v: serde_json::Value = serde_json::from_str(&conf).unwrap();
    let updater = &v["plugins"]["updater"];
    assert_eq!(updater["active"], true);
    let endpoints = updater["endpoints"].as_array().expect("endpoints array");
    assert!(
        endpoints
            .iter()
            .any(|e| e.as_str().unwrap_or("").contains("releases")),
        "updater endpoint must point at GitHub Releases"
    );
    let pubkey = updater["pubkey"].as_str().expect("pubkey string");
    assert!(
        !pubkey.to_lowercase().contains("todo"),
        "updater pubkey must be a real minisign key, not a placeholder"
    );
    assert!(
        pubkey.len() > 60 && pubkey.starts_with("dW50cnVzdGVk"),
        "updater pubkey must be a base64 minisign public key"
    );
    let backend_cargo = std::fs::read_to_string(format!("{manifest}/Cargo.toml"))
        .expect("src-tauri Cargo.toml must exist");
    assert!(
        backend_cargo.contains("tauri-plugin-updater"),
        "updater plugin must be a backend dependency"
    );
    let caps = std::fs::read_to_string(format!("{manifest}/capabilities/default.json"))
        .expect("capabilities/default.json must exist");
    assert!(
        caps.contains("updater"),
        "updater permission must be granted"
    );
}
