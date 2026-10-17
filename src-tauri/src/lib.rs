// Task 2: Firefox Accounts sign-in with email + password, ported from the
// reference client `Vauth/FoxyVPN`: onepw (PBKDF2 quickStretch → authPW) →
// POST /account/login → optional emailed 2FA code → Hawk-signed
// /oauth/token with grant_type=fxa-credentials → access + refresh token.
// No browser is opened. The session lives in the OS keychain and is
// refreshed on launch, so returning users are auto-logged-in.
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use reqwest::header::{HeaderMap, SET_COOKIE};
use tauri::{AppHandle, Emitter, Manager, State};

pub mod dataplane;

// Placeholder state harness for the VPN state machine (tasks 4+).
// ponytail: minimal enum+struct only; transitions/guards land in task 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum VpnState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VpnStatus {
    pub state: VpnState,
    pub server: Option<String>,
    pub exit_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Where the local proxies listen once the data plane is up, e.g.
    /// "SOCKS5 127.0.0.1:1080 · HTTP 127.0.0.1:8080".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
}

// Task 4: stub tunnel backend (AC3/5 status half, AC6). The trait is the seam the
// per-OS bring-up (tasks 5–7) implements; the stub opens one fake handle and
// returns a fixture exit IP so connect/disconnect + UI land first.
pub trait Tunnel {
    fn open(server: &str) -> String;
    fn close();
}

pub struct StubTunnel;

impl Tunnel for StubTunnel {
    fn open(server: &str) -> String {
        stub_exit_ip(server)
    }
    fn close() {}
}

/// Fixture exit IP per server id (TEST-NET-3, never routed); unknown ids share the default.
pub fn stub_exit_ip(server: &str) -> String {
    match server {
        "us-california" => "203.0.113.7".into(),
        "de-berlin" => "203.0.113.23".into(),
        "jp-tokyo" => "203.0.113.42".into(),
        _ => "203.0.113.7".into(),
    }
}

// Task 5: Linux system tunnel (AC4/AC9 Linux: fully-system routing + OS auth
// prompt). ponytail: std only — no new `tun`/netlink dep (architect approval
// required per tasks.md gate, not requested from this worktree). The TUN
// bring-up pieces (`ip` argv via `pkexec`, route parsing, Guardian CONNECT
// framing) are built and tested here, but the live data plane (tun2socks ↔
// Fastly HTTP/2) still needs the approved dep. Bringing the default route up
// before that loop exists would blackhole all traffic while the UI claims
// "Connected", so this module deliberately makes NO route changes yet: every
// open returns the stub with a clear note (AC8: a failed connect never leaves
// the machine half-routed). Hardware IP-check is manual.
#[cfg(target_os = "linux")]
pub mod linux_tunnel {
    use super::{StubTunnel, Tunnel};

    pub const TUN_NAME: &str = "foxyvpn0";
    pub const TUN_ADDR: &str = "10.42.0.1/30";

    /// Edge host for a server: prefer the Guardian hostname, else derive it.
    pub fn edge_host(server: &str, hostname: &str) -> String {
        if hostname.is_empty() {
            format!("{server}.guardian.vpn.mozilla.org")
        } else {
            hostname.to_owned()
        }
    }

    /// CONNECT request to the Fastly edge, authorized by the Guardian token
    /// (upstream speaks HTTP/2 CONNECT; same headers, std-built string; sent
    /// by the live data plane once the approved TUN/H2 dep lands).
    pub fn connect_request(host: &str, token: &str) -> String {
        format!(
            "CONNECT {host}:443 HTTP/1.1\r\n\
             Host: {host}:443\r\n\
             Authorization: Bearer {token}\r\n\
             Proxy-Authorization: Bearer {token}\r\n\r\n"
        )
    }

    /// Parse `ip route show`: gateway + device of the `default` line.
    pub fn parse_default_route(ip_route: &str) -> Option<(String, String)> {
        ip_route.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            if words.next() != Some("default") {
                return None;
            }
            let mut gateway = None;
            let mut dev = None;
            let mut rest = words.peekable();
            while let Some(word) = rest.next() {
                if word == "via" {
                    gateway = rest.next().map(str::to_owned);
                } else if word == "dev" {
                    dev = rest.next().map(str::to_owned);
                }
            }
            gateway.zip(dev)
        })
    }

    /// TUN preflight with no side effects and no prompt: the device node must
    /// open read-write (/dev/net/tun is 0666, so presence ≠ permission — the
    /// privileged `ip` step sorts that out, failing fast when refused).
    pub fn tun_available() -> Result<(), String> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map(|_| ())
            .map_err(|e| format!("TUN unavailable ({e}) — non-root/CI? using stub tunnel."))
    }

    /// Pure argv constructor so tests pin the escalation framing (pkexec =
    /// the AC9 system auth prompt) without executing anything.
    pub fn privileged_argv(program: &str, args: &[&str]) -> (String, Vec<String>) {
        let mut full = vec![program.to_owned()];
        full.extend(args.iter().map(|s| s.to_string()));
        ("pkexec".to_owned(), full)
    }

    pub struct TunnelOpen {
        pub exit_ip: String,
        pub used_stub: bool,
        pub note: Option<String>,
    }

    /// Linux open: preflight, then the stub. No TUN/route mutation happens
    /// until the data plane exists (see the module comment), so a connect can
    /// never blackhole traffic while reporting "Connected".
    pub fn open_or_fallback(server: &str) -> TunnelOpen {
        open_with_probe(server, tun_available())
    }

    /// Injectable preflight so tests pin the fallback path deterministically.
    pub fn open_with_probe(server: &str, preflight: Result<(), String>) -> TunnelOpen {
        let note = match preflight {
            Err(note) => note,
            Ok(()) => "Linux data plane needs the approved TUN/H2 dep — no route changes made; using stub tunnel."
                .to_owned(),
        };
        TunnelOpen {
            exit_ip: StubTunnel::open(server),
            used_stub: true,
            note: Some(note),
        }
    }

    /// No-op: no interface or route was changed, so nothing needs restoring.
    pub fn close_system() {}
}

// Task 6: Windows system tunnel (AC4/AC9 Windows: fully-system routing via
// Wintun + adapter-install consent). ponytail: std only — no new `wintun` dep
// (architect approval required per tasks.md gate, not requested from this
// worktree). The module is unconditional std-only so its config/framing parsing
// + fallback path unit-test on Linux; anything touching WinAPI later stays
// behind #[cfg(target_os = "windows")]. Live path: `Adapter::create` on the
// FoxyVPN pool name triggers the Windows adapter-install consent dialog (the
// AC9 OS indicator), then the shared CONNECT framing + packet loop run as on
// Linux. Until the `wintun` crate lands, ANY open falls back to StubTunnel with
// a clear note, so `cargo test` stays green everywhere (hardware IP-check and
// the consent dialog are manual).
pub mod windows_tunnel {
    use super::{StubTunnel, Tunnel};

    /// Wintun adapter pool name — the label shown in the adapter-install
    /// consent dialog (AC9 indicator).
    pub const ADAPTER_NAME: &str = "FoxyVPN";
    pub const TUN_ADDR: &str = "10.42.0.2";
    pub const WINTUN_DLL: &str = "wintun.dll";

    /// Edge host for a server: prefer the Guardian hostname, else derive it.
    pub fn edge_host(server: &str, hostname: &str) -> String {
        if hostname.is_empty() {
            format!("{server}.guardian.vpn.mozilla.org")
        } else {
            hostname.to_owned()
        }
    }

    /// CONNECT request to the Fastly edge, authorized by the Guardian token
    /// (same headers as the Linux path; sent by the live data plane once the
    /// approved `wintun` dep lands).
    pub fn connect_request(host: &str, token: &str) -> String {
        format!(
            "CONNECT {host}:443 HTTP/1.1\r\n\
             Host: {host}:443\r\n\
             Authorization: Bearer {token}\r\n\
             Proxy-Authorization: Bearer {token}\r\n\r\n"
        )
    }

    /// Parse `route print -4`: gateway of the `0.0.0.0/0.0.0.0` line, saved so
    /// disconnect can confirm the direct route is back (AC5).
    pub fn parse_route_print(route_print: &str) -> Option<String> {
        route_print.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            if words.next() != Some("0.0.0.0") {
                return None;
            }
            if words.next() != Some("0.0.0.0") {
                return None;
            }
            words.next().map(str::to_owned)
        })
    }

    /// Wintun preflight with no side effects and no prompt: off-Windows it is
    /// always unavailable; on Windows the driver check needs the approved
    /// `wintun` crate, so it reports that until the dep lands (no silent fake).
    pub fn wintun_available() -> Result<(), String> {
        #[cfg(target_os = "windows")]
        return Err(
            "Wintun bring-up needs the approved `wintun` crate — using stub tunnel.".into(),
        );
        #[cfg(not(target_os = "windows"))]
        return Err("Wintun is Windows-only — using stub tunnel.".into());
    }

    pub struct TunnelOpen {
        pub exit_ip: String,
        pub used_stub: bool,
        pub note: Option<String>,
    }

    /// Smallest-viable Windows open: preflight → Wintun adapter.
    /// ANY failure → StubTunnel with a clear note (green tests, no hangs).
    pub fn open_or_fallback(server: &str) -> TunnelOpen {
        open_with_probe(server, wintun_available())
    }

    /// Injectable preflight so tests pin the fallback path deterministically.
    pub fn open_with_probe(server: &str, preflight: Result<(), String>) -> TunnelOpen {
        let fallback = |note: String| TunnelOpen {
            exit_ip: StubTunnel::open(server),
            used_stub: true,
            note: Some(note),
        };
        if let Err(note) = preflight {
            return fallback(note);
        }
        let _edge = edge_host(server, "");
        let _adapter = ADAPTER_NAME;
        fallback(
            "Wintun adapter install needs the approved `wintun` crate + one adapter-consent click — using stub tunnel."
                .into(),
        )
    }

    /// Tear down the FoxyVPN adapter; Windows restores the previous default
    /// route automatically (AC5: IP-check shows the direct IP again). No-op
    /// until the `wintun` crate lands, so disconnect never prompts or hangs on
    /// the fallback path.
    pub fn close_system() {}
}

// Task 7: Android system tunnel (AC4/AC9 Android: fully-system routing via
// VpnService consent + fd handoff to the shared Rust core). ponytail: std only
// — no new TUN/H2 dep (architect approval required per tasks.md gate, not
// requested from this worktree). The module is unconditional std-only so its
// config/framing/fd-plumbing parsing + fallback path unit-test on Linux;
// anything touching the Android runtime (VpnService, JNI) stays behind
// #[cfg(target_os = "android")] inside `vpnsvc_available`. Live path: VpnService
// consent → Builder.establish() fd → set_tun_fd(fd) → shared CONNECT framing +
// packet loop as on Linux. Until the TUN/H2 dep lands, ANY open falls back to
// StubTunnel with a clear note, so `cargo test` stays green everywhere
// (hardware IP-check and the VpnService consent dialog are manual).
//
// MOBILE GLUE FOLLOW-UP (`tauri android init` outputs not committed — heavy,
// so the Rust side lands first):
// 1. Run `cargo tauri android init` → commits `src-tauri/gen/android` + `gen/android`
//    (AndroidManifest.xml with BIND_VPN_SERVICE permission + SERVICE_INTERFACE
//    intent-filter, FoxyVpnService.kt extending android.net.VpnService).
// 2. FoxyVpnService.onStartCommand: VpnService.prepare(ctx) consent intent when
//    needed → Builder().setSession("FoxyVPN").addAddress(TUN_ADDR, TUN_PREFIX)
//    .addRoute("0.0.0.0", 0).addDnsServer(DNS).setMtu(MTU).establish() →
//    detachFd() → android_tunnel::set_tun_fd(fd) here → vpn_connect(server).
// 3. `run()` below already carries #[cfg_attr(mobile, tauri::mobile_entry_point)]
//    — no change needed there.
// Manual verify: VpnService consent dialog → IP-check shows exit IP (AC4/AC9).
pub mod android_tunnel {
    use super::{StubTunnel, Tunnel};
    use std::sync::{Mutex, OnceLock};

    /// VpnService service-interface action (AC9: the consent dialog path).
    pub const SERVICE_INTERFACE: &str = "android.net.VpnService";
    pub const TUN_ADDR: &str = "10.42.0.2";
    pub const TUN_PREFIX: u8 = 30;
    pub const MTU: u16 = 1500;
    /// System DNS is used as-is (AC10: no DNS screen).
    pub const DNS: &str = "10.42.0.1";

    /// Edge host for a server: prefer the Guardian hostname, else derive it.
    pub fn edge_host(server: &str, hostname: &str) -> String {
        if hostname.is_empty() {
            format!("{server}.guardian.vpn.mozilla.org")
        } else {
            hostname.to_owned()
        }
    }

    /// CONNECT request to the Fastly edge, authorized by the Guardian token
    /// (same headers as the Linux/Windows paths; sent by the live data plane
    /// once the approved TUN/H2 dep lands).
    pub fn connect_request(host: &str, token: &str) -> String {
        format!(
            "CONNECT {host}:443 HTTP/1.1\r\n\
             Host: {host}:443\r\n\
             Authorization: Bearer {token}\r\n\
             Proxy-Authorization: Bearer {token}\r\n\r\n"
        )
    }

    /// Parse the tun fd the Kotlin side hands over (Builder.establish() →
    /// ParcelFileDescriptor.detachFd(), passed as a decimal string). Rejects
    /// negatives/non-numbers so a bad handoff never becomes a live fd.
    pub fn parse_tun_fd(raw: &str) -> Option<i32> {
        raw.trim().parse::<i32>().ok().filter(|fd| *fd >= 0)
    }

    /// Builder config the Kotlin FoxyVpnService applies before establish():
    /// one address, the default route (fully-system, AC9), MTU, system DNS.
    pub struct BuilderConfig {
        pub address: String,
        pub prefix: u8,
        pub mtu: u16,
        pub dns: String,
        pub routes: Vec<String>,
    }

    pub fn builder_config() -> BuilderConfig {
        BuilderConfig {
            address: TUN_ADDR.into(),
            prefix: TUN_PREFIX,
            mtu: MTU,
            dns: DNS.into(),
            routes: vec!["0.0.0.0/0".into()],
        }
    }

    /// Slot for the fd handed over from Kotlin; consumed once per connect.
    fn tun_fd_slot() -> &'static Mutex<Option<i32>> {
        static SLOT: OnceLock<Mutex<Option<i32>>> = OnceLock::new();
        SLOT.get_or_init(|| Mutex::new(None))
    }

    /// Stash the establish() fd (called via the mobile glue, see above).
    /// Returns false for a bad fd so Kotlin can re-establish instead.
    pub fn set_tun_fd(fd: i32) -> bool {
        if fd < 0 {
            return false;
        }
        *tun_fd_slot().lock().unwrap() = Some(fd);
        true
    }

    pub fn take_tun_fd() -> Option<i32> {
        tun_fd_slot().lock().unwrap().take()
    }

    /// VpnService preflight with no side effects and no prompt: off-Android it
    /// is always unavailable; on Android the fd handoff needs the approved
    /// TUN/H2 dep, so it reports that until the dep lands (no silent fake).
    pub fn vpnsvc_available() -> Result<(), String> {
        #[cfg(target_os = "android")]
        return Err(
            "VpnService bring-up needs the approved TUN/H2 dep — using stub tunnel.".into(),
        );
        #[cfg(not(target_os = "android"))]
        return Err("VpnService is Android-only — using stub tunnel.".into());
    }

    pub struct TunnelOpen {
        pub exit_ip: String,
        pub used_stub: bool,
        pub note: Option<String>,
    }

    /// Smallest-viable Android open: preflight → stashed fd → Rust core.
    /// ANY failure → StubTunnel with a clear note (green tests, no hangs).
    pub fn open_or_fallback(server: &str) -> TunnelOpen {
        match vpnsvc_available() {
            Err(note) => open_with_probe(server, None, Err(note)),
            Ok(()) => open_with_probe(server, take_tun_fd(), Ok(())),
        }
    }

    /// Injectable fd + preflight so tests pin each path deterministically.
    pub fn open_with_probe(
        server: &str,
        fd: Option<i32>,
        preflight: Result<(), String>,
    ) -> TunnelOpen {
        let fallback = |note: String| TunnelOpen {
            exit_ip: StubTunnel::open(server),
            used_stub: true,
            note: Some(note),
        };
        if let Err(note) = preflight {
            return fallback(note);
        }
        if fd.is_none() {
            return fallback(
                "no VpnService fd yet — complete the consent step first — using stub tunnel."
                    .into(),
            );
        }
        let _edge = edge_host(server, "");
        fallback(
            "fd handoff needs the approved TUN/H2 dep + one VpnService consent click — using stub tunnel."
                .into(),
        )
    }

    /// Tear down the VpnService session; Android restores the previous default
    /// route automatically (AC5: IP-check shows the direct IP again). No-op
    /// until the TUN/H2 dep lands, so disconnect never hangs on fallback.
    pub fn close_system() {}
}

/// Platform tunnel open: each OS tries its system path with stub fallback;
/// other OSes use the stub.
#[cfg(target_os = "linux")]
fn open_tunnel(server: &str) -> String {
    linux_tunnel::open_or_fallback(server).exit_ip
}
#[cfg(target_os = "windows")]
fn open_tunnel(server: &str) -> String {
    windows_tunnel::open_or_fallback(server).exit_ip
}
#[cfg(target_os = "android")]
fn open_tunnel(server: &str) -> String {
    android_tunnel::open_or_fallback(server).exit_ip
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
fn open_tunnel(server: &str) -> String {
    StubTunnel::open(server)
}

#[cfg(target_os = "linux")]
fn close_platform_tunnel() {
    linux_tunnel::close_system();
    StubTunnel::close();
}
#[cfg(target_os = "windows")]
fn close_platform_tunnel() {
    windows_tunnel::close_system();
    StubTunnel::close();
}
#[cfg(target_os = "android")]
fn close_platform_tunnel() {
    android_tunnel::close_system();
    StubTunnel::close();
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
fn close_platform_tunnel() {
    StubTunnel::close();
}

/// Teardown shared by every platform: stop the local proxies/edge session
/// first (dataplane::stop also restores the system proxy we replaced), then
/// the platform-specific cleanup.
fn close_tunnel() {
    dataplane::stop();
    close_platform_tunnel();
}

/// What a tunnel opener reports: the exit IP plus — when the data plane is
/// real — where the local proxies are listening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelResult {
    pub exit_ip: String,
    pub proxy: Option<String>,
}

pub type Opener = fn(&str) -> Result<TunnelResult, String>;

/// Default opener: the platform stub (used by every offline unit test).
/// `run()` swaps in the real data-plane opener once the app is up.
fn stub_opener(server: &str) -> Result<TunnelResult, String> {
    Ok(TunnelResult {
        exit_ip: open_tunnel(server),
        proxy: None,
    })
}

#[derive(Default)]
struct VpnInner {
    status: VpnStatus,
    handles: u32,  // open stub-tunnel handles; guard keeps this ≤1 (AC6)
    opening: bool, // a bring-up owns the tunnel gate right now
    epoch: u64,    // attempt id; a stale open must not settle a newer attempt
}

pub struct VpnStore {
    inner: Mutex<VpnInner>,
    /// Wakes concurrent connect callers once a bring-up settles, so every
    /// racer reports the same status line without busy-waiting (AC6).
    settled: std::sync::Condvar,
    /// Serializes slow tunnel bring-up/teardown *outside* `inner`, so status
    /// polls and UI reads never sit behind a blocking `pkexec`/TUN open (AC12).
    tunnel_gate: Mutex<()>,
    /// Who opens the data plane. Default = platform stub (offline tests);
    /// `run()` installs the real proxy-data-plane opener.
    opener: Mutex<Opener>,
}

impl Default for VpnStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(VpnInner::default()),
            settled: std::sync::Condvar::new(),
            tunnel_gate: Mutex::new(()),
            opener: Mutex::new(stub_opener),
        }
    }
}

impl VpnStore {
    /// Swap in the opener that should run on Connect (the real data plane in
    /// the app; a test double in tests).
    pub fn set_opener(&self, opener: Opener) {
        *self.opener.lock().unwrap() = opener;
    }
}

/// One guarded connection: repeat connect while Connecting|Connected is a no-op (AC6).
///
/// The privileged open runs on the tunnel gate, not on `inner`: a slow
/// `pkexec` handshake must not stall `vpn_status`/disconnect polling (AC12).
pub fn vpn_connect_impl(store: &VpnStore, server: &str) -> VpnStatus {
    let mut guard = store.inner.lock().unwrap();
    match guard.status.state {
        VpnState::Connected => guard.status.clone(),
        VpnState::Connecting => store
            .settled
            .wait_while(guard, |inner| inner.status.state == VpnState::Connecting)
            .map(|inner| inner.status.clone())
            .unwrap_or_default(),
        VpnState::Disconnected => {
            if server.is_empty() {
                guard.status.last_error = Some("Pick a server first.".into());
                return guard.status.clone();
            }
            guard.epoch += 1;
            let attempt = guard.epoch;
            guard.opening = true;
            guard.status.state = VpnState::Connecting;
            guard.status.server = Some(server.to_owned());
            guard.status.last_error = None;
            guard.status.exit_ip = None;
            guard.status.proxy = None;
            guard.handles = 1;
            drop(guard);

            let _gate = store.tunnel_gate.lock().unwrap();
            let opener = *store.opener.lock().unwrap();
            let outcome = opener(server);
            let mut guard = store.inner.lock().unwrap();
            guard.opening = false;
            if guard.epoch == attempt {
                match outcome {
                    Ok(result) => {
                        guard.status.exit_ip = Some(result.exit_ip);
                        guard.status.proxy = result.proxy;
                        guard.status.state = VpnState::Connected;
                        let status = guard.status.clone();
                        drop(guard);
                        store.settled.notify_all();
                        status
                    }
                    Err(message) => {
                        // A failed bring-up must never leave a Connecting
                        // spinner or a half-started proxy behind: land
                        // Disconnected with the reason on the status line.
                        guard.handles = 0;
                        guard.status = VpnStatus {
                            state: VpnState::Disconnected,
                            server: None,
                            exit_ip: None,
                            last_error: Some(message),
                            proxy: None,
                        };
                        let status = guard.status.clone();
                        drop(guard);
                        close_tunnel();
                        store.settled.notify_all();
                        status
                    }
                }
            } else {
                // Disconnect (or a newer attempt) superseded this open while it
                // was in flight: tear the fresh tunnel down instead of
                // resurrecting a cancelled connection.
                let status = guard.status.clone();
                drop(guard);
                close_tunnel();
                store.settled.notify_all();
                status
            }
        }
    }
}

/// Tear down the connection; exit IP clears so IP-check shows the direct IP (AC5).
/// Status is reset under the short lock; only the actual teardown waits on the gate.
pub fn vpn_disconnect_impl(store: &VpnStore) -> VpnStatus {
    let mut guard = store.inner.lock().unwrap();
    // Invalidate any in-flight open; that thread tears its own tunnel down.
    guard.epoch += 1;
    let teardown_now = guard.handles > 0 && !guard.opening;
    guard.handles = 0;
    guard.status = VpnStatus::default();
    let status = guard.status.clone();
    drop(guard);
    // Wake connect callers parked on an in-flight attempt; they re-check state.
    store.settled.notify_all();
    if teardown_now {
        let _gate = store.tunnel_gate.lock().unwrap();
        close_tunnel();
    }
    status
}

// Task 8: error/offline/expired-token handling (AC7: expired token →
// re-sign-in prompt, never a stuck spinner; AC8: offline connect → offline
// error, stays disconnected). Reuses VpnStatus.last_error + AuthState; no new
// screens. Tests pass explicit bools so they stay offline-deterministic; only
// the Tauri command wrappers below touch the real network.
pub const OFFLINE_ERROR: &str = "Offline — check your connection and try again.";
pub const EXPIRED_TOKEN_ERROR: &str = "Session expired — please sign in again.";
pub const SIGNED_OUT_ERROR: &str = "Signed out — please sign in again.";
pub const GUARDIAN_HOST: &str = "vpn.mozilla.org"; // must match GUARDIAN_SERVERS_URL

/// Offline probe (std only): can we open TCP to the Guardian front door? DNS
/// failure or refused/timeout ⇒ offline. ~2s worst case, keeping buttons
/// reactive (AC12). Airplane-mode behavior is a manual check (see runbook).
pub fn default_online() -> bool {
    use std::net::ToSocketAddrs;
    format!("{GUARDIAN_HOST}:443")
        .to_socket_addrs()
        .map(|mut addrs| {
            addrs.any(|addr| {
                std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
            })
        })
        .unwrap_or(false)
}

/// True when a Guardian failure string is an auth rejection (expired/invalid
/// token) rather than a network blip or an empty list. Matches the status
/// code reqwest embeds via `error_for_status`, not body text.
pub fn is_unauthorized(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("401") || lower.contains("unauthorized")
}

/// Connect with explicit preflight: offline or signed-out stays Disconnected
/// with an error line (never Connecting); repeat connect on an active
/// connection stays a no-op (AC6), even offline.
pub fn vpn_connect_with(
    store: &VpnStore,
    auth: Option<&AuthState>,
    server: &str,
    online: bool,
) -> VpnStatus {
    if vpn_status_impl(store).state != VpnState::Disconnected {
        return vpn_connect_impl(store, server);
    }
    if !online {
        let mut guard = store.inner.lock().unwrap();
        guard.status.last_error = Some(OFFLINE_ERROR.into());
        return guard.status.clone();
    }
    if auth.is_some_and(|a| !signed_in(a)) {
        let mut guard = store.inner.lock().unwrap();
        guard.status.last_error = Some(SIGNED_OUT_ERROR.into());
        return guard.status.clone();
    }
    vpn_connect_impl(store, server)
}

/// Guardian 401 (AC7): drop the dead token, tear down any half-open tunnel,
/// and land Disconnected with a re-sign-in prompt — never a stuck Connecting.
pub fn handle_guardian_unauthorized(store: &VpnStore, auth: &AuthState) -> VpnStatus {
    clear_token(auth);
    let mut guard = store.inner.lock().unwrap();
    let should_close = guard.handles > 0;
    if should_close {
        guard.handles = 0;
    }
    guard.status = VpnStatus {
        state: VpnState::Disconnected,
        server: None,
        exit_ip: None,
        last_error: Some(EXPIRED_TOKEN_ERROR.into()),
        proxy: None,
    };
    let status = guard.status.clone();
    drop(guard);
    if should_close {
        close_tunnel();
    }
    status
}

pub fn vpn_status_impl(store: &VpnStore) -> VpnStatus {
    store.inner.lock().unwrap().status.clone()
}

#[tauri::command]
fn vpn_connect(store: State<VpnStore>, auth: State<AuthState>, server: String) -> VpnStatus {
    // Repeat press on a live connection is a no-op (AC6) — no revalidation.
    if vpn_status_impl(&store).state != VpnState::Disconnected {
        return vpn_connect_impl(&store, &server);
    }
    // Offline or signed-out never opens a tunnel (AC8); the error line says so.
    if !default_online() {
        return vpn_connect_with(&store, Some(&auth), &server, false);
    }
    vpn_connect_with(&store, Some(&auth), &server, true)
}

#[tauri::command]
fn vpn_disconnect(store: State<VpnStore>) -> VpnStatus {
    vpn_disconnect_impl(&store)
}

#[tauri::command]
fn vpn_status(store: State<VpnStore>) -> VpnStatus {
    vpn_status_impl(&store)
}

pub const AUTH_CHANGED_EVENT: &str = "auth-changed";

// ---- Firefox Accounts sign-in (onepw + Hawk), ported from Vauth/FoxyVPN ----
pub const FXA_API_BASE: &str = "https://api.accounts.firefox.com/v1";
/// Public Firefox Accounts client id used by the reference FoxyVPN client for
/// the `fxa-credentials` grant. No client secret is involved.
pub const FIREFOX_CLIENT_ID: &str = "5882386c6d801776";
pub const FIREFOX_SCOPE: &str = "profile https://identity.mozilla.com/apps/vpn";
pub const MOZILLA_VPN_USER_AGENT: &str = "MozillaVPN/2.35.0 (sys:linux; iap:true)";
const PICL_PREFIX: &str = "identity.mozilla.com/picl/v1/";
const QUICK_STRETCH_ROUNDS: u32 = 1000;
const FXA_ERRNO_INVALID_PARAMETER: i64 = 107;
const DEFAULT_ACCESS_TOKEN_TTL_SECONDS: i64 = 24 * 60 * 60;
/// Refresh a little before the access token actually expires.
const REFRESH_MARGIN_SECS: i64 = 60;

const KEYRING_SERVICE: &str = "foxy-desktop-vpn";
const KEYRING_USER: &str = "fxa-session";

#[derive(Default)]
pub struct AuthState {
    token: Mutex<Option<String>>,
    refresh: Mutex<Option<String>>,
    expires_at: Mutex<i64>,
    /// FxA session token awaiting the emailed confirmation code (2FA).
    pending_session: Mutex<Option<String>>,
}

/// What the keychain keeps: access + refresh token and expiry, so a launch can
/// silently renew an expired session (auto-login).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix seconds; 0 means unknown/expired.
    #[serde(default)]
    pub expires_at: i64,
}

impl Session {
    pub fn needs_refresh(&self, now: i64) -> bool {
        self.expires_at <= now + REFRESH_MARGIN_SECS
    }
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---- onepw crypto ----

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32, length: usize) -> Vec<u8> {
    let rounds = rounds.max(1);
    let mut out = Vec::with_capacity(length.div_ceil(32) * 32);
    let mut block_index: u32 = 1;
    while out.len() < length {
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_sha256(password, &salt_block);
        let mut t = u;
        for _ in 2..=rounds {
            u = hmac_sha256(password, &u);
            for (acc, byte) in t.iter_mut().zip(u.iter()) {
                *acc ^= *byte;
            }
        }
        out.extend_from_slice(&t);
        block_index += 1;
    }
    out.truncate(length);
    out
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hmac_sha256(salt, ikm);
    let mut out = Vec::with_capacity(length.div_ceil(32) * 32);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < length {
        let mut data = previous;
        data.extend_from_slice(info);
        data.push(counter);
        let block = hmac_sha256(&prk, &data);
        out.extend_from_slice(&block);
        previous = block.to_vec();
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}

fn b64_std(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// FxA strips spaces/zero-width characters and lowercases the email.
pub fn normalize_email(email: &str) -> String {
    email
        .chars()
        .filter(|c| !is_ignorable(*c))
        .collect::<String>()
        .trim()
        .to_lowercase()
}

/// Confirmation codes are digits; strip any whitespace/zero-width noise.
pub fn sanitize_code(code: &str) -> String {
    code.chars()
        .filter(|c| !is_ignorable(*c))
        .collect::<String>()
        .trim()
        .to_owned()
}

fn is_ignorable(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')
}

/// authPW = hex(HKDF(PBKDF2-SHA256(password, "…quickStretch:<email>", 1000, 32),
///                    "…authPW", 32)) — the onepw protocol the reference client uses.
pub fn derive_auth_pw(email: &str, password: &str) -> String {
    let salt = format!("{PICL_PREFIX}quickStretch:{email}");
    let stretched = pbkdf2_hmac_sha256(
        password.as_bytes(),
        salt.as_bytes(),
        QUICK_STRETCH_ROUNDS,
        32,
    );
    let derived = hkdf(
        &stretched,
        &[0u8; 32],
        format!("{PICL_PREFIX}authPW").as_bytes(),
        32,
    );
    hex_encode(&derived)
}

/// sessionToken → Hawk id (first 32 bytes, hex) and HMAC key (second 32 bytes).
pub fn derive_hawk_credentials(session_token_hex: &str) -> Option<(String, [u8; 32])> {
    let token = hex_decode(session_token_hex)?;
    let expanded = hkdf(
        &token,
        &[0u8; 32],
        format!("{PICL_PREFIX}sessionToken").as_bytes(),
        64,
    );
    let id = hex_encode(&expanded[..32]);
    let key: [u8; 32] = expanded[32..64].try_into().ok()?;
    Some((id, key))
}

struct UrlParts<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn split_url(url: &str) -> Option<UrlParts<'_>> {
    let (rest, default_port) = if let Some(rest) = url.strip_prefix("https://") {
        (rest, 443)
    } else {
        (url.strip_prefix("http://")?, 80)
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host, port.parse().ok()?)
        }
        _ => (authority, default_port),
    };
    (!host.is_empty()).then_some(UrlParts { host, port, path })
}

/// `Hawk id=…, ts=…, nonce=…, mac=…[, hash=…]` as expected by FxA.
fn hawk_header(method: &str, url: &str, token_id: &str, key: &[u8], body: &str) -> Option<String> {
    let parts = split_url(url)?;
    let ts = now_secs().to_string();
    let mut nonce_bytes = [0u8; 6];
    getrandom::getrandom(&mut nonce_bytes).ok()?;
    let nonce = b64url(&nonce_bytes);
    Some(hawk_header_with(
        method, &parts, token_id, key, body, &ts, &nonce,
    ))
}

fn hawk_header_with(
    method: &str,
    parts: &UrlParts<'_>,
    token_id: &str,
    key: &[u8],
    body: &str,
    ts: &str,
    nonce: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let payload_hash = if body.is_empty() {
        String::new()
    } else {
        let mut payload = Vec::with_capacity(body.len() + 32);
        payload.extend_from_slice(b"hawk.1.payload\napplication/json\n");
        payload.extend_from_slice(body.as_bytes());
        payload.push(b'\n');
        b64_std(&Sha256::digest(&payload))
    };
    let normalized = format!(
        "hawk.1.header\n{ts}\n{nonce}\n{}\n{}\n{}\n{}\n{payload_hash}\n\n",
        method.to_uppercase(),
        parts.path,
        parts.host,
        parts.port
    );
    let mac = b64_std(&hmac_sha256(key, normalized.as_bytes()));
    let mut header =
        format!("Hawk id=\"{token_id}\", ts=\"{ts}\", nonce=\"{nonce}\", mac=\"{mac}\"");
    if !payload_hash.is_empty() {
        header.push_str(&format!(", hash=\"{payload_hash}\""));
    }
    header
}

// ---- Fastly "Client Challenge" ----
//
// Some exit IPs get an HTTP 406 from api.accounts.firefox.com with a Fastly
// bot-challenge page instead of a JSON error. The reference client solves it
// (proof-of-work / PAT / client metrics, posting the answers back for a
// cookie), so we do the same; otherwise sign-in would fail on those networks.

const SOLVER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
const HTML_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const POW_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MAX_POST_BACK_ROUNDS: usize = 3;

static CHALLENGE_COOKIES: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();

fn challenge_cookie_jar() -> &'static Mutex<Vec<(String, String)>> {
    CHALLENGE_COOKIES.get_or_init(|| Mutex::new(Vec::new()))
}

fn upsert_cookie(jar: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some(slot) = jar.iter_mut().find(|(n, _)| n == name) {
        slot.1 = value.to_owned();
    } else {
        jar.push((name.to_owned(), value.to_owned()));
    }
}

fn absorb_set_cookies(headers: &HeaderMap, jar: &mut Vec<(String, String)>) {
    for header in headers.get_all(SET_COOKIE) {
        let Ok(raw) = header.to_str() else { continue };
        let pair = raw.split(';').next().unwrap_or_default().trim();
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if !name.is_empty() {
            upsert_cookie(jar, name.trim(), value.trim());
        }
    }
}

fn cookie_header() -> Option<String> {
    let jar = challenge_cookie_jar().lock().ok()?;
    if jar.is_empty() {
        return None;
    }
    Some(
        jar.iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

fn solver_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("could not build the challenge client: {e}"))
}

fn solver_send(
    client: &reqwest::blocking::Client,
    method: reqwest::Method,
    url: &str,
    jar: &mut Vec<(String, String)>,
    accept: &str,
    body: Option<String>,
    origin: Option<&str>,
) -> Result<(u16, String), String> {
    let mut request = client
        .request(method, url)
        .header("User-Agent", SOLVER_UA)
        .header("Accept", accept);
    if let Some(origin) = origin {
        request = request.header("Origin", origin);
    }
    if let Some(body) = body {
        request = request
            .header("Content-Type", "application/json")
            .body(body);
    }
    if !jar.is_empty() {
        let cookies = jar
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        request = request.header("Cookie", cookies);
    }
    let response = request
        .send()
        .map_err(|e| format!("challenge request failed: {e}"))?;
    let status = response.status().as_u16();
    absorb_set_cookies(response.headers(), jar);
    let text = response.text().unwrap_or_default();
    Ok((status, text))
}

fn solver_get(
    client: &reqwest::blocking::Client,
    url: &str,
    jar: &mut Vec<(String, String)>,
    accept: &str,
) -> Result<String, String> {
    let (status, text) = solver_send(client, reqwest::Method::GET, url, jar, accept, None, None)?;
    if !(200..300).contains(&status) {
        return Err(format!("GET {url} returned HTTP {status}"));
    }
    Ok(text)
}

fn challenge_prefix(page: &str) -> Option<String> {
    const PREFIX: &str = "/_fs-ch-";
    let start = page.find(PREFIX)?;
    let rest = &page[start + PREFIX.len()..];
    let end = rest
        .char_indices()
        .find(|(_, c)| !c.is_ascii_alphanumeric())
        .map(|(i, _)| i)
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some(format!("{PREFIX}{}", &rest[..end]))
}

/// Last `init([...], "token", ...)` call in the challenge script.
fn parse_challenge_init(script: &str) -> Option<(Vec<serde_json::Value>, String)> {
    let mut search_from = 0;
    let mut init_at = None;
    while let Some(found) = script[search_from..].find("init(") {
        init_at = Some(search_from + found + "init(".len());
        search_from += found + "init(".len();
    }
    let mut cursor = script.get(init_at?..)?;
    let array_start = cursor.find('[')?;
    cursor = &cursor[array_start..];
    let consumed = json_array_end(cursor)?;
    let challenges: serde_json::Value = serde_json::from_str(&cursor[..consumed]).ok()?;
    let array = challenges.as_array()?.clone();
    if array.is_empty() {
        return None;
    }
    let token = first_quoted_string(&cursor[consumed..])?;
    Some((array, token))
}

fn json_array_end(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in text.bytes().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn first_quoted_string(text: &str) -> Option<String> {
    let start = text.find('"')?;
    let rest = &text[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn solve_pow(base: &str, target_hex: &str) -> Option<String> {
    use sha2::Digest as _;
    let target = hex_decode(target_hex)?;
    if target.len() != 32 {
        return None;
    }
    for a in POW_ALPHABET {
        for b in POW_ALPHABET {
            let suffix = format!("{}{}", *a as char, *b as char);
            let digest = sha2::Sha256::digest(format!("{base}{suffix}").as_bytes());
            if digest.as_slice() == target.as_slice() {
                return Some(suffix);
            }
        }
    }
    None
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn base_origin(prefix_url: &str) -> &str {
    match prefix_url.find("/_fs-ch-") {
        Some(index) if index > 0 => &prefix_url[..index],
        _ => prefix_url,
    }
}

fn client_metrics_answer() -> serde_json::Value {
    serde_json::json!({
        "ty": "clientmetrics",
        "webdriver": false,
        "bot_detection_result": { "bot_detected": false, "bot_kind": null },
        "browser_metrics": { "client_data": "{}", "error_trace": null },
        "detector_results": {},
        "v": 2,
    })
}

fn answer_challenge(
    client: &reqwest::blocking::Client,
    prefix_url: &str,
    token: &str,
    challenge: &serde_json::Value,
    jar: &mut Vec<(String, String)>,
) -> Result<serde_json::Value, String> {
    let data = challenge.get("data").cloned().unwrap_or_default();
    let ty = challenge
        .get("ty")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    match ty {
        "pow" => {
            let base = data
                .get("base")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let hash = data
                .get("hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let answer = solve_pow(base, hash)
                .ok_or_else(|| format!("no proof-of-work solution found for base {base}"))?;
            Ok(serde_json::json!({
                "ty": "pow",
                "base": base,
                "answer": answer,
                "hmac": data.get("hmac").cloned().unwrap_or_default(),
                "expires": data.get("expires").cloned().unwrap_or_default(),
            }))
        }
        "pat" => {
            let url = format!("{prefix_url}/pat?token={}", percent_encode(token));
            let (status, text) = solver_send(
                client,
                reqwest::Method::POST,
                &url,
                jar,
                "text/plain",
                Some(String::new()),
                Some(base_origin(prefix_url)),
            )?;
            if status == 400 || status == 401 {
                return Ok(serde_json::json!({ "ty": "pat", "auth": "" }));
            }
            if !(200..300).contains(&status) {
                return Err(format!("PAT request returned HTTP {status}"));
            }
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("could not parse PAT response: {e}"))?;
            let auth = value
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if auth.is_empty() {
                return Err("empty PAT auth token".into());
            }
            Ok(serde_json::json!({ "ty": "pat", "auth": auth }))
        }
        "clientmetrics" => Ok(client_metrics_answer()),
        other => Err(format!(
            "unsupported Fastly challenge type '{other}' (captcha cannot be solved automatically)"
        )),
    }
}

fn solve_on_host(base: &str) -> Result<(), String> {
    let client = solver_client()?;
    let mut jar: Vec<(String, String)> = Vec::new();
    let page_url = format!("{base}/");
    let page = solver_get(&client, &page_url, &mut jar, HTML_ACCEPT)?;
    if !(page.contains("/_fs-ch-") && page.contains("Client Challenge")) {
        return Err("host did not serve a Fastly challenge page".into());
    }
    let prefix = challenge_prefix(&page)
        .ok_or_else(|| format!("challenge asset prefix not found on {base}"))?;
    let prefix_url = format!("{base}{prefix}");
    let script = solver_get(
        &client,
        &format!("{prefix_url}/script.js?reload=true"),
        &mut jar,
        HTML_ACCEPT,
    )?;
    let (mut challenges, mut token) =
        parse_challenge_init(&script).ok_or("challenge init() call not found in script")?;

    for _ in 0..MAX_POST_BACK_ROUNDS {
        let mut answers = Vec::with_capacity(challenges.len());
        for challenge in &challenges {
            answers.push(answer_challenge(
                &client,
                &prefix_url,
                &token,
                challenge,
                &mut jar,
            )?);
        }
        let body = serde_json::json!({ "token": token, "data": answers }).to_string();
        let (status, text) = solver_send(
            &client,
            reqwest::Method::POST,
            &format!("{prefix_url}/fst-post-back"),
            &mut jar,
            "application/json",
            Some(body),
            Some(base_origin(&prefix_url)),
        )?;
        if !(200..300).contains(&status) {
            return Err(format!("challenge post-back returned HTTP {status}"));
        }
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("could not parse challenge response: {e}"))?;
        if value.get("status").and_then(|v| v.as_str()) == Some("success") {
            let check = solver_get(&client, &page_url, &mut jar, HTML_ACCEPT)?;
            if check.contains("/_fs-ch-") && check.contains("Client Challenge") {
                return Err("challenge cookie not accepted on this exit IP".into());
            }
            if jar.is_empty() {
                return Err("challenge completed but no cookies were issued".into());
            }
            let mut store = challenge_cookie_jar()
                .lock()
                .map_err(|_| "cookie store poisoned")?;
            for (name, cookie_value) in jar {
                upsert_cookie(&mut store, &name, &cookie_value);
            }
            return Ok(());
        }
        let next_challenges = value.get("ch").and_then(|v| v.as_array()).cloned();
        let next_token = value
            .get("tok")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        match next_challenges {
            Some(next) if !next.is_empty() && !next_token.is_empty() => {
                challenges = next;
                token = next_token;
            }
            _ => return Err(format!("unexpected challenge post-back response: {text}")),
        }
    }
    Err(format!(
        "Fastly challenge did not complete within {MAX_POST_BACK_ROUNDS} rounds"
    ))
}

/// Solve the Fastly challenge and remember the cookies it issues, so the next
/// FxA request passes. Tries the API host first, then the web host.
pub fn solve_fastly_challenge() -> Result<(), String> {
    let mut last_error = String::from("host did not serve a Fastly challenge page");
    for base in [
        "https://api.accounts.firefox.com",
        "https://accounts.firefox.com",
    ] {
        match solve_on_host(base) {
            Ok(()) => return Ok(()),
            Err(error) if error.contains("did not serve a Fastly challenge page") => {}
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

// ---- FxA HTTP ----

#[derive(Debug)]
pub struct FxaError {
    pub message: String,
    pub errno: Option<i64>,
    pub status: u16,
}

fn fxa_do(
    base: &str,
    path: &str,
    session_token: Option<&str>,
    body: &str,
) -> Result<serde_json::Value, FxaError> {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let hawk = match session_token {
        Some(token) => {
            let Some((id, key)) = derive_hawk_credentials(token) else {
                return Err(FxaError {
                    message: "Invalid Firefox session token.".into(),
                    errno: None,
                    status: 0,
                });
            };
            let Some(hawk) = hawk_header("POST", &url, &id, &key, body) else {
                return Err(FxaError {
                    message: "Could not sign the Firefox Accounts request.".into(),
                    errno: None,
                    status: 0,
                });
            };
            Some(hawk)
        }
        None => None,
    };
    let client = reqwest::blocking::Client::new();
    let (status, text) = {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut request = client
                .post(&url)
                .header("User-Agent", MOZILLA_VPN_USER_AGENT)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .timeout(Duration::from_secs(30))
                .body(body.to_owned());
            if let Some(hawk) = &hawk {
                request = request.header("Authorization", hawk);
            }
            if let Some(cookies) = cookie_header() {
                request = request.header("Cookie", cookies);
            }
            let response = request.send().map_err(|e| FxaError {
                message: format!("Could not reach Firefox Accounts: {e}"),
                errno: None,
                status: 0,
            })?;
            let status = response.status().as_u16();
            let text = response.text().unwrap_or_default();
            if status == 406 && attempt < 3 {
                // Fastly bot challenge: solve it, then retry with its cookies.
                solve_fastly_challenge().map_err(|error| FxaError {
                    message: format!(
                        "Firefox challenged this connection and the challenge could not be solved: {error}"
                    ),
                    errno: None,
                    status: 406,
                })?;
                continue;
            }
            break (status, text);
        }
    };
    if status >= 400 {
        let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        let message = if status == 406 {
            "Firefox blocked this connection as automated (HTTP 406) — try another network or VPN."
                .to_owned()
        } else {
            value
                .get("message")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    format!("Firefox Accounts rejected the request (HTTP {status}).")
                })
        };
        return Err(FxaError {
            message,
            errno: value.get("errno").and_then(|v| v.as_i64()),
            status,
        });
    }
    serde_json::from_str(&text).map_err(|e| FxaError {
        message: format!("Invalid Firefox Accounts response: {e}"),
        errno: None,
        status,
    })
}

#[derive(Debug)]
pub enum LoginOutcome {
    SignedIn(Session),
    /// Email confirmation required: the token must be kept for the code step.
    NeedsVerification(String),
}

/// Email + password sign-in, exactly as the reference client: onepw login with
/// `verificationMethod=email-2fa`, falling back if the server rejects it.
pub fn login_with(email: &str, password: &str, now: i64) -> Result<LoginOutcome, String> {
    login_with_at(FXA_API_BASE, email, password, now)
}

/// Injectable base URL so the full login flow can be tested offline.
pub fn login_with_at(
    base: &str,
    email: &str,
    password: &str,
    now: i64,
) -> Result<LoginOutcome, String> {
    let email = normalize_email(email);
    if email.is_empty() || !email.contains('@') {
        return Err("Enter your Firefox account email.".into());
    }
    if password.is_empty() {
        return Err("Enter your Firefox account password.".into());
    }
    let auth_pw = derive_auth_pw(&email, password);
    let with_2fa = serde_json::json!({
        "email": email,
        "authPW": auth_pw,
        "verificationMethod": "email-2fa",
    })
    .to_string();
    let data = match fxa_do(base, "/account/login", None, &with_2fa) {
        Ok(data) => data,
        Err(error) if error.errno == Some(FXA_ERRNO_INVALID_PARAMETER) => {
            let plain = serde_json::json!({ "email": email, "authPW": auth_pw }).to_string();
            fxa_do(base, "/account/login", None, &plain).map_err(|e| e.message)?
        }
        Err(error) => return Err(error.message),
    };
    let session_token = data
        .get("sessionToken")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty())
        .ok_or("Firefox Accounts returned no session token.")?
        .to_owned();
    if data
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        Ok(LoginOutcome::SignedIn(oauth_token_at(
            base,
            &session_token,
            now,
        )?))
    } else {
        Ok(LoginOutcome::NeedsVerification(session_token))
    }
}

/// Submit the emailed confirmation code, then exchange the session token for
/// an access/refresh token pair.
pub fn verify_two_factor(session_token: &str, code: &str, now: i64) -> Result<Session, String> {
    verify_two_factor_at(FXA_API_BASE, session_token, code, now)
}

pub fn verify_two_factor_at(
    base: &str,
    session_token: &str,
    code: &str,
    now: i64,
) -> Result<Session, String> {
    let code = sanitize_code(code);
    if code.is_empty() {
        return Err("Enter the confirmation code from your email.".into());
    }
    let body = serde_json::json!({ "code": code }).to_string();
    fxa_do(base, "/session/verify_code", Some(session_token), &body).map_err(|e| e.message)?;
    oauth_token_at(base, session_token, now)
}

fn oauth_token_at(base: &str, session_token: &str, now: i64) -> Result<Session, String> {
    let body = serde_json::json!({
        "client_id": FIREFOX_CLIENT_ID,
        "grant_type": "fxa-credentials",
        "scope": FIREFOX_SCOPE,
        "access_type": "offline",
    })
    .to_string();
    let data = fxa_do(base, "/oauth/token", Some(session_token), &body).map_err(|e| e.message)?;
    session_from_response(&data, now, None)
}

/// Renew an expired access token at launch (keeps auto-login working).
pub fn refresh_session(refresh_token: &str, now: i64) -> Result<Session, String> {
    refresh_session_at(FXA_API_BASE, refresh_token, now)
}

pub fn refresh_session_at(base: &str, refresh_token: &str, now: i64) -> Result<Session, String> {
    let body = serde_json::json!({
        "client_id": FIREFOX_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": FIREFOX_SCOPE,
    })
    .to_string();
    let data = fxa_do(base, "/oauth/token", None, &body).map_err(|e| e.message)?;
    session_from_response(&data, now, Some(refresh_token))
}

fn session_from_response(
    data: &serde_json::Value,
    now: i64,
    previous_refresh: Option<&str>,
) -> Result<Session, String> {
    let access_token = data
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|t| !t.trim().is_empty())
        .ok_or("Firefox Accounts returned no access token.")?
        .to_owned();
    let expires_in = data
        .get("expires_in")
        .and_then(|v| v.as_i64())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_ACCESS_TOKEN_TTL_SECONDS);
    Ok(Session {
        access_token,
        refresh_token: data
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .or_else(|| previous_refresh.map(str::to_owned)),
        expires_at: now + expires_in,
    })
}

// ---- session storage / restore ----

pub fn load_session() -> Option<Session> {
    let raw = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .ok()?
        .get_password()
        .ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // Tolerate a bare legacy token as well as the JSON session blob.
    Some(serde_json::from_str(raw).unwrap_or_else(|_| Session {
        access_token: raw.to_owned(),
        refresh_token: None,
        expires_at: 0,
    }))
}

fn save_session(session: &Session) {
    if !cfg!(test)
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        && let Ok(json) = serde_json::to_string(session)
    {
        let _ = entry.set_password(&json);
    }
}

pub fn apply_session(state: &AuthState, session: &Session) {
    save_session(session);
    *state.token.lock().unwrap() = Some(session.access_token.clone());
    *state.refresh.lock().unwrap() = session.refresh_token.clone();
    *state.expires_at.lock().unwrap() = session.expires_at;
}

/// Restore silently: valid token → use it; expired + refresh token → renew;
/// otherwise still try the access token (a 401 lands on the re-sign-in prompt).
pub fn restore_session_with(
    load: impl FnOnce() -> Option<Session>,
    refresh: impl FnOnce(&str) -> Result<Session, String>,
    now: i64,
) -> Option<Session> {
    let session = load()?;
    if !session.needs_refresh(now) {
        return Some(session);
    }
    if let Some(refresh_token) = session.refresh_token.as_deref()
        && let Ok(renewed) = refresh(refresh_token)
    {
        return Some(renewed);
    }
    (!session.access_token.trim().is_empty()).then_some(session)
}

pub fn signed_in(state: &AuthState) -> bool {
    state.token.lock().unwrap().is_some()
}

pub fn clear_token(state: &AuthState) {
    // Never touch the real keychain under `cfg(test)`.
    if !cfg!(test)
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
    {
        let _ = entry.delete_credential();
    }
    state.token.lock().unwrap().take();
    state.refresh.lock().unwrap().take();
    *state.expires_at.lock().unwrap() = 0;
    state.pending_session.lock().unwrap().take();
}

#[derive(serde::Serialize, Clone)]
struct AuthChanged {
    signed_in: bool,
    /// Present when Firefox Accounts (or a 401) needs a fresh sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Set when the emailed confirmation code is required.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    needs_verification: bool,
}

#[tauri::command]
fn auth_sign_in(
    app: AppHandle,
    auth: State<AuthState>,
    email: String,
    password: String,
) -> AuthChanged {
    match login_with(&email, &password, now_secs()) {
        Ok(LoginOutcome::SignedIn(session)) => {
            apply_session(&auth, &session);
            *auth.pending_session.lock().unwrap() = None;
            let changed = AuthChanged {
                signed_in: true,
                error: None,
                needs_verification: false,
            };
            let _ = app.emit(AUTH_CHANGED_EVENT, changed.clone());
            changed
        }
        Ok(LoginOutcome::NeedsVerification(session_token)) => {
            *auth.pending_session.lock().unwrap() = Some(session_token);
            AuthChanged {
                signed_in: false,
                error: None,
                needs_verification: true,
            }
        }
        Err(error) => AuthChanged {
            signed_in: false,
            error: Some(error),
            needs_verification: false,
        },
    }
}

#[tauri::command]
fn auth_verify_code(app: AppHandle, auth: State<AuthState>, code: String) -> AuthChanged {
    let Some(session_token) = auth.pending_session.lock().unwrap().clone() else {
        return AuthChanged {
            signed_in: false,
            error: Some("Start sign-in again — no pending Firefox session.".into()),
            needs_verification: false,
        };
    };
    match verify_two_factor(&session_token, &code, now_secs()) {
        Ok(session) => {
            apply_session(&auth, &session);
            *auth.pending_session.lock().unwrap() = None;
            let changed = AuthChanged {
                signed_in: true,
                error: None,
                needs_verification: false,
            };
            let _ = app.emit(AUTH_CHANGED_EVENT, changed.clone());
            changed
        }
        Err(error) => AuthChanged {
            signed_in: false,
            error: Some(error),
            needs_verification: true,
        },
    }
}

/// Auto-login on launch: restore (and if needed refresh) the keychain session.
#[tauri::command]
fn auth_restore(auth: State<AuthState>) -> AuthChanged {
    let restored = restore_session_with(
        load_session,
        |refresh_token| refresh_session(refresh_token, now_secs()),
        now_secs(),
    );
    let signed_in = restored.is_some();
    if let Some(session) = restored {
        apply_session(&auth, &session);
    }
    AuthChanged {
        signed_in,
        error: None,
        needs_verification: false,
    }
}

#[tauri::command]
fn auth_sign_out(app: AppHandle) -> Result<(), String> {
    let auth: State<AuthState> = app.state();
    clear_token(&auth);
    app.emit(
        AUTH_CHANGED_EVENT,
        AuthChanged {
            signed_in: false,
            error: None,
            needs_verification: false,
        },
    )
    .map_err(|e| e.to_string())
}

// Task 3: server list fetch + picker UI (AC2: city/country list; AC12: no spinner, error line).
// Source: Mozilla's public Remote Settings collection (same as the reference
// client) — no auth needed, one request, fixture fallback on failure.
pub const REMOTE_SETTINGS_URL: &str = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records";
/// Override for local testing / mirrors.
pub const SERVERS_URL_ENV: &str = "FOXYVPN_SERVERS_URL";

fn servers_url() -> String {
    std::env::var(SERVERS_URL_ENV)
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| REMOTE_SETTINGS_URL.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Server {
    pub id: String,
    pub city: String,
    pub country: String,
    #[serde(default)]
    pub hostname: String,
    /// Edge port for the `connect` path (Remote Settings `port`, e.g. 2499).
    /// 0/absent means the HTTPS default.
    #[serde(default)]
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServerList {
    pub servers: Vec<Server>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn fixture_servers() -> Vec<Server> {
    vec![
        Server {
            id: "us-california".into(),
            city: "Los Angeles".into(),
            country: "United States".into(),
            hostname: "us-california.guardian.vpn.mozilla.org".into(),
            port: 443,
        },
        Server {
            id: "de-berlin".into(),
            city: "Berlin".into(),
            country: "Germany".into(),
            hostname: "de-berlin.guardian.vpn.mozilla.org".into(),
            port: 443,
        },
        Server {
            id: "jp-tokyo".into(),
            city: "Tokyo".into(),
            country: "Japan".into(),
            hostname: "jp-tokyo.guardian.vpn.mozilla.org".into(),
            port: 443,
        },
    ]
}

/// Parse Remote Settings records:
/// `data[] .country {name, code, cities[{name, code, servers[{hostname,
/// quarantined, protocols[{name, host}]}]}]}` (a record may hold the country
/// object directly). One entry per city, using its first healthy server.
pub fn parse_servers(value: &serde_json::Value) -> Vec<Server> {
    let records = value
        .get("data")
        .and_then(|v| v.as_array())
        .or_else(|| value.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut servers = Vec::new();
    for record in records {
        let country = record.get("country").unwrap_or(record);
        let country_name = country
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let country_code = country
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if country_name.is_empty()
            || country_code.is_empty()
            || country_name.eq_ignore_ascii_case("CatchAll Anycast")
        {
            continue;
        }
        let Some(cities) = country.get("cities").and_then(|v| v.as_array()) else {
            continue;
        };
        for city in cities {
            let city_name = city
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if city_name.is_empty() {
                continue;
            }
            let city_code = city
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let Some(server) = city
                .get("servers")
                .and_then(|v| v.as_array())
                .and_then(|nodes| {
                    nodes.iter().find(|node| {
                        !node
                            .get("quarantined")
                            .and_then(|q| q.as_bool())
                            .unwrap_or(false)
                    })
                })
            else {
                continue;
            };
            let id = if city_code.is_empty() {
                format!(
                    "{}-{}",
                    country_code.to_lowercase(),
                    city_name.to_lowercase().replace(' ', "-")
                )
            } else {
                format!(
                    "{}-{}",
                    country_code.to_lowercase(),
                    city_code.to_lowercase()
                )
            };
            servers.push(Server {
                id,
                city: city_name.to_owned(),
                country: country_name.to_owned(),
                hostname: connect_host(server),
                port: connect_port(server),
            });
        }
    }
    servers
}

fn connect_host(server: &serde_json::Value) -> String {
    let hostname = server
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if let Some(protocols) = server.get("protocols").and_then(|v| v.as_array()) {
        for protocol in protocols {
            if protocol.get("name").and_then(|v| v.as_str()) == Some("connect") {
                return protocol
                    .get("host")
                    .and_then(|v| v.as_str())
                    .filter(|host| !host.is_empty())
                    .unwrap_or(hostname)
                    .to_owned();
            }
        }
    }
    hostname.to_owned()
}

/// Edge port for the `connect` path: the `connect` protocol's port when the
/// record declares one, else the node's own port, else HTTPS.
fn connect_port(server: &serde_json::Value) -> u16 {
    if let Some(protocols) = server.get("protocols").and_then(|v| v.as_array()) {
        for protocol in protocols {
            if protocol.get("name").and_then(|v| v.as_str()) == Some("connect")
                && let Some(port) = protocol.get("port").and_then(|v| v.as_u64())
                && port != 0
                && port <= u16::MAX as u64
            {
                return port as u16;
            }
        }
    }
    match server.get("port").and_then(|v| v.as_u64()) {
        Some(port) if port != 0 && port <= u16::MAX as u64 => port as u16,
        _ => 443,
    }
}

fn fetch_live_servers() -> Result<Vec<Server>, String> {
    let body: serde_json::Value = reqwest::blocking::Client::new()
        .get(servers_url())
        .header("User-Agent", MOZILLA_VPN_USER_AGENT)
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .map_err(|e| e.to_string())?;
    Ok(parse_servers(&body))
}

pub fn resolve_servers_with(fetch: impl FnOnce() -> Result<Vec<Server>, String>) -> ServerList {
    match fetch() {
        Ok(servers) if !servers.is_empty() => ServerList {
            servers,
            error: None,
        },
        Ok(_) => ServerList {
            servers: fixture_servers(),
            error: Some("Server list is empty — showing sample servers.".into()),
        },
        Err(e) => ServerList {
            servers: fixture_servers(),
            error: Some(format!(
                "Could not fetch the server list ({e}) — showing sample servers."
            )),
        },
    }
}

#[tauri::command]
fn list_servers() -> ServerList {
    resolve_servers_with(fetch_live_servers)
}

/// Resolve the picked server id to its edge authority (hostname + port) from
/// the live Remote Settings list.
fn edge_target(server_id: &str) -> Result<(String, u16), String> {
    let servers =
        fetch_live_servers().map_err(|e| format!("Could not fetch the server list ({e})."))?;
    let server = servers
        .iter()
        .find(|server| server.id == server_id)
        .ok_or_else(|| format!("Server '{server_id}' is not in the server list."))?;
    if server.hostname.is_empty() {
        return Err("This server has no edge hostname.".into());
    }
    let port = if server.port == 0 { 443 } else { server.port };
    Ok((server.hostname.clone(), port))
}

/// The real data-plane opener installed by `run()`: mint a Guardian proxy
/// pass, dial the chosen edge, start the local SOCKS5 + HTTP proxies, verify
/// the exit IP through the tunnel, and point the desktop's system proxy at it.
/// Every failure comes back as an error string (shown on the status line),
/// never as a fake Connected.
fn open_dataplane(server_id: &str) -> Result<TunnelResult, String> {
    let session = load_session().ok_or_else(|| SIGNED_OUT_ERROR.to_owned())?;
    let access_token = if session.needs_refresh(now_secs()) {
        let refresh = session
            .refresh_token
            .clone()
            .ok_or_else(|| EXPIRED_TOKEN_ERROR.to_owned())?;
        refresh_session(&refresh, now_secs())?.access_token
    } else {
        session.access_token
    };
    let pass = dataplane::fetch_proxy_pass(&access_token)?;
    let (host, port) = edge_target(server_id)?;
    let info = dataplane::start(&host, port, pass.token, pass.expires_at)?;
    let mut label = info.proxy_label();
    if !info.system_proxy {
        label.push_str(" — set these in your apps (no system proxy settings found)");
    }
    Ok(TunnelResult {
        exit_ip: info.exit_ip,
        proxy: Some(label),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Undo a previous run's proxy change first (crash recovery), so a killed
    // session never leaves the desktop pointing at a dead local proxy.
    dataplane::restore_system_proxy();
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(AuthState::default())
        .manage(VpnStore::default())
        .setup(|app| {
            // Real data plane: local SOCKS5/HTTP proxies in front of the
            // Fastly edge, exactly like the reference client.
            app.state::<VpnStore>().set_opener(open_dataplane);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            auth_sign_in,
            auth_verify_code,
            auth_restore,
            auth_sign_out,
            list_servers,
            vpn_connect,
            vpn_disconnect,
            vpn_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Instant;

    #[test]
    fn initial_status_is_disconnected() {
        assert_eq!(VpnStatus::default().state, VpnState::Disconnected);
    }

    // ---- Fastly challenge solver (offline pieces) ----

    #[test]
    fn opener_failure_lands_disconnected_with_the_reason() {
        fn always_fails(_: &str) -> Result<TunnelResult, String> {
            Err("edge dial failed".into())
        }
        let store = VpnStore::default();
        store.set_opener(always_fails);
        let status = vpn_connect_impl(&store, "de-berlin");
        assert_eq!(status.state, VpnState::Disconnected);
        assert_eq!(status.last_error.as_deref(), Some("edge dial failed"));
        assert!(status.exit_ip.is_none());
        assert!(status.proxy.is_none());
        // Never a stuck Connecting spinner, never a fake handle (AC7-style).
        assert_eq!(vpn_status_impl(&store).state, VpnState::Disconnected);
        assert_eq!(store.inner.lock().unwrap().handles, 0);
        assert!(!store.inner.lock().unwrap().opening);
    }

    #[test]
    fn data_plane_opener_reports_proxy_endpoints_on_the_status() {
        fn with_proxy(_: &str) -> Result<TunnelResult, String> {
            Ok(TunnelResult {
                exit_ip: "203.0.113.9".into(),
                proxy: Some("SOCKS5 127.0.0.1:1080 · HTTP 127.0.0.1:8080".into()),
            })
        }
        let store = VpnStore::default();
        store.set_opener(with_proxy);
        let status = vpn_connect_impl(&store, "de-berlin");
        assert_eq!(status.state, VpnState::Connected);
        assert_eq!(status.exit_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(
            status.proxy.as_deref(),
            Some("SOCKS5 127.0.0.1:1080 · HTTP 127.0.0.1:8080")
        );
        // Disconnect tears the data plane down and clears the label.
        let down = vpn_disconnect_impl(&store);
        assert_eq!(down.state, VpnState::Disconnected);
        assert!(down.proxy.is_none() && down.exit_ip.is_none());
    }

    #[test]
    fn parse_servers_carries_the_edge_port() {
        let value = serde_json::json!({
            "data": [
                {
                    "name": "South Africa", "code": "ZA",
                    "cities": [{
                        "name": "South Africa", "code": "FAOR",
                        "servers": [{"hostname": "faor73.m1.fastly-masque.net", "port": 2499}]
                    }]
                },
                {
                    "name": "Germany", "code": "DE",
                    "cities": [{
                        "name": "Berlin", "code": "BER",
                        "servers": [{
                            "hostname": "edge.example",
                            "port": 443,
                            "protocols": [{"name": "connect", "host": "connect.example", "port": 8443}]
                        }]
                    }]
                }
            ]
        });
        let servers = parse_servers(&value);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].hostname, "faor73.m1.fastly-masque.net");
        assert_eq!(servers[0].port, 2499);
        assert_eq!(servers[0].id, "za-faor");
        assert_eq!(servers[1].hostname, "connect.example");
        assert_eq!(servers[1].port, 8443);
        assert!(fixture_servers().iter().all(|server| server.port == 443));
    }

    #[test]
    fn challenge_prefix_is_extracted_from_page() {
        let page = "<html><script src=\"/_fs-ch-ab12CD/script.js\"></script>";
        assert_eq!(challenge_prefix(page).as_deref(), Some("/_fs-ch-ab12CD"));
        assert_eq!(challenge_prefix("no challenge here"), None);
    }

    #[test]
    fn challenge_init_parses_last_call_with_token() {
        let script = r#"init([{"ty":"clientmetrics"}], "first", "id");
            var x = init([{"ty":"pow","data":{"base":"b"}},{"ty":"pat"}], "tok-123", "id");"#;
        let (challenges, token) = parse_challenge_init(script).expect("init call parses");
        assert_eq!(challenges.len(), 2);
        assert_eq!(token, "tok-123");
        assert!(
            parse_challenge_init("no init call").is_none(),
            "missing init must not parse"
        );
    }

    #[test]
    fn json_array_end_respects_strings_and_nesting() {
        let text = r#"[{"a":"]}"},[1,2]], "tok""#;
        assert_eq!(json_array_end(text), Some(18));
        assert_eq!(&text[18..22], ", \"t");
    }

    #[test]
    fn pow_solver_finds_two_char_suffix() {
        // sha256("solverselftest" + "jG") =
        // 00ec20e24db75b270c2287f6b7c74a7a727856ea64c7515efec0a0445f85e797
        let hash = "00ec20e24db75b270c2287f6b7c74a7a727856ea64c7515efec0a0445f85e797";
        assert_eq!(solve_pow("solverselftest", hash).as_deref(), Some("jG"));
    }

    #[test]
    fn pow_solver_rejects_bad_targets() {
        assert_eq!(solve_pow("base", "00"), None);
        assert_eq!(solve_pow("base", "zz"), None);
        assert_eq!(solve_pow("solverselftest", &"0".repeat(64)), None);
    }

    #[test]
    fn client_metrics_answer_matches_fastly_shape() {
        let answer = client_metrics_answer();
        assert_eq!(answer["ty"], "clientmetrics");
        assert_eq!(answer["webdriver"], false);
        assert_eq!(answer["bot_detection_result"]["bot_detected"], false);
        assert!(answer["bot_detection_result"]["bot_kind"].is_null());
    }

    #[test]
    fn percent_encode_leaves_unreserved_and_escapes_rest() {
        assert_eq!(percent_encode("aZ09-._~"), "aZ09-._~");
        assert_eq!(percent_encode("a b/+"), "a%20b%2F%2B");
    }

    #[test]
    fn connect_transitions_to_connected_with_exit_ip() {
        let store = VpnStore::default();
        assert_eq!(vpn_status_impl(&store).state, VpnState::Disconnected);
        let status = vpn_connect_impl(&store, "de-berlin");
        assert_eq!(status.state, VpnState::Connected);
        assert_eq!(status.server.as_deref(), Some("de-berlin"));
        assert_eq!(status.exit_ip.as_deref(), Some("203.0.113.23"));
        assert!(status.last_error.is_none());
        assert_eq!(vpn_status_impl(&store).state, VpnState::Connected);
    }

    #[test]
    fn double_connect_is_noop_with_single_handle() {
        let store = VpnStore::default();
        let first = vpn_connect_impl(&store, "us-california");
        let second = vpn_connect_impl(&store, "jp-tokyo");
        assert_eq!(second, first, "repeat connect must not change state");
        assert_eq!(second.server.as_deref(), Some("us-california"));
        assert_eq!(store.inner.lock().unwrap().handles, 1);
    }

    // Disconnect during an in-flight open must return immediately (status is
    // reset under the short lock) and leave no connection behind.
    #[test]
    fn disconnect_during_connecting_cancels_without_waiting_on_open() {
        let store = std::sync::Arc::new(VpnStore::default());
        let gate = store.tunnel_gate.lock().unwrap(); // park the bring-up
        let connect_store = std::sync::Arc::clone(&store);
        let handle = std::thread::spawn(move || vpn_connect_impl(&connect_store, "jp-tokyo"));
        let deadline = Instant::now() + Duration::from_secs(2);
        while vpn_status_impl(&store).state != VpnState::Connecting {
            assert!(
                Instant::now() < deadline,
                "connect never reached Connecting"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let start = Instant::now();
        let status = vpn_disconnect_impl(&store);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "disconnect waited on the in-flight open: {:?}",
            start.elapsed()
        );
        assert_eq!(status.state, VpnState::Disconnected);
        drop(gate);
        let cancelled = handle.join().unwrap();
        assert_eq!(cancelled.state, VpnState::Disconnected);
        let inner = store.inner.lock().unwrap();
        assert_eq!(inner.handles, 0);
        assert!(!inner.opening);
        drop(inner);
        assert_eq!(vpn_status_impl(&store).state, VpnState::Disconnected);
        // The next connect still works (no leaked handle/cancelled epoch).
        assert_eq!(
            vpn_connect_impl(&store, "de-berlin").state,
            VpnState::Connected
        );
        vpn_disconnect_impl(&store);
    }

    // AC12 + AC6 regression: a slow privileged bring-up parks on the tunnel
    // gate, so status polls keep answering instead of blocking behind it.
    #[test]
    fn status_polls_stay_responsive_during_slow_open() {
        let store = std::sync::Arc::new(VpnStore::default());
        let gate = store.tunnel_gate.lock().unwrap(); // simulate a slow pkexec/TUN open
        let connect_store = std::sync::Arc::clone(&store);
        let handle = std::thread::spawn(move || vpn_connect_impl(&connect_store, "de-berlin"));
        let deadline = Instant::now() + Duration::from_secs(2);
        while vpn_status_impl(&store).state != VpnState::Connecting {
            assert!(
                Instant::now() < deadline,
                "connect never reached Connecting"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = vpn_status_impl(&store);
        }
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "status blocked behind tunnel bring-up: {:?}",
            start.elapsed()
        );
        drop(gate);
        assert_eq!(handle.join().unwrap().state, VpnState::Connected);
        vpn_disconnect_impl(&store);
    }

    #[test]
    fn disconnect_returns_to_disconnected_and_clears_exit_ip() {
        let store = VpnStore::default();
        vpn_connect_impl(&store, "us-california");
        let status = vpn_disconnect_impl(&store);
        assert_eq!(status.state, VpnState::Disconnected);
        assert!(status.exit_ip.is_none());
        assert!(status.server.is_none());
        assert_eq!(store.inner.lock().unwrap().handles, 0);
        // Disconnect when already disconnected is a harmless no-op.
        assert_eq!(vpn_disconnect_impl(&store).state, VpnState::Disconnected);
    }

    #[test]
    fn connect_without_server_stays_disconnected_with_error() {
        let store = VpnStore::default();
        let status = vpn_connect_impl(&store, "");
        assert_eq!(status.state, VpnState::Disconnected);
        assert!(status.last_error.is_some());
        assert_eq!(store.inner.lock().unwrap().handles, 0);
    }

    // Task 8 (AC8): offline connect → offline error, stays Disconnected, no stuck Connecting.
    #[test]
    fn offline_connect_stays_disconnected_with_offline_error() {
        let store = VpnStore::default();
        let auth = AuthState::default();
        apply_session(&auth, &test_session("tok123"));
        let status = vpn_connect_with(&store, Some(&auth), "de-berlin", false);
        assert_eq!(status.state, VpnState::Disconnected);
        assert_ne!(status.state, VpnState::Connecting);
        assert!(status.exit_ip.is_none());
        assert_eq!(store.inner.lock().unwrap().handles, 0);
        assert!(
            status
                .last_error
                .unwrap_or_default()
                .to_lowercase()
                .contains("offline"),
            "offline failure must name itself on the error line"
        );
        // Token untouched — offline is not an auth failure.
        assert!(signed_in(&auth));
    }

    #[test]
    fn offline_repeat_connect_keeps_active_connection() {
        let store = VpnStore::default();
        let live = vpn_connect_impl(&store, "us-california");
        assert_eq!(live.state, VpnState::Connected);
        let repeat = vpn_connect_with(&store, None, "jp-tokyo", false);
        assert_eq!(repeat, live, "repeat connect must not clobber state");
    }

    #[test]
    fn signed_out_connect_prompts_resignin() {
        let store = VpnStore::default();
        let auth = AuthState::default();
        assert!(!signed_in(&auth));
        let status = vpn_connect_with(&store, Some(&auth), "de-berlin", true);
        assert_eq!(status.state, VpnState::Disconnected);
        assert_eq!(store.inner.lock().unwrap().handles, 0);
        assert!(
            status
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("sign in"),
            "must prompt re-sign-in, got: {:?}",
            status.last_error.as_deref()
        );
    }

    // Task 8 (AC7): Guardian 401 → token cleared, Disconnected + re-sign-in, tunnel torn down.
    #[test]
    fn guardian_401_clears_token_and_prompts_resignin() {
        let store = VpnStore::default();
        let auth = AuthState::default();
        apply_session(&auth, &test_session("expired-tok"));
        let up = vpn_connect_with(&store, Some(&auth), "de-berlin", true);
        assert_eq!(up.state, VpnState::Connected);
        let status = handle_guardian_unauthorized(&store, &auth);
        assert!(!signed_in(&auth), "dead token must be cleared");
        assert_eq!(status.state, VpnState::Disconnected);
        assert_ne!(status.state, VpnState::Connecting);
        assert!(status.server.is_none() && status.exit_ip.is_none());
        assert_eq!(store.inner.lock().unwrap().handles, 0);
        assert_eq!(status.last_error.as_deref(), Some(EXPIRED_TOKEN_ERROR));
    }

    #[test]
    fn unauthorized_detection_spots_401_not_generic_failures() {
        assert!(is_unauthorized(
            "Could not reach Guardian (401 Unauthorized for url https://vpn.mozilla.org/) — showing sample servers."
        ));
        assert!(is_unauthorized("HTTP 401 fetching servers"));
        assert!(!is_unauthorized(
            "Could not reach Guardian (dns error: failed to lookup address) — showing sample servers."
        ));
        assert!(!is_unauthorized(OFFLINE_ERROR));
        assert!(!is_unauthorized(SIGNED_OUT_ERROR));
        assert!(!is_unauthorized(
            "Server list is empty — showing sample servers."
        ));
    }

    fn test_session(token: &str) -> Session {
        Session {
            access_token: token.into(),
            refresh_token: Some("refresh-token".into()),
            expires_at: i64::MAX,
        }
    }

    #[test]
    fn sign_out_clears_the_session() {
        let auth = AuthState::default();
        assert!(!signed_in(&auth));
        apply_session(&auth, &test_session("tok123"));
        assert!(signed_in(&auth));
        clear_token(&auth);
        assert!(!signed_in(&auth));
        assert!(auth.refresh.lock().unwrap().is_none());
        assert_eq!(*auth.expires_at.lock().unwrap(), 0);
    }

    /// One-shot FxA stub. Responses are matched by path prefix and consumed in
    /// order, so a test can script login → oauth/token (including retries).
    struct StubRoute {
        path: &'static str,
        status: u16,
        body: &'static str,
    }

    fn route(path: &'static str, status: u16, body: &'static str) -> StubRoute {
        StubRoute { path, status, body }
    }

    fn spawn_fxa_stub(mut routes: Vec<StubRoute>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            while !routes.is_empty() {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 16384];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = request.split_whitespace().nth(1).unwrap_or("").to_owned();
                let index = routes
                    .iter()
                    .position(|route| path.starts_with(route.path))
                    .unwrap_or(0);
                let route = routes.remove(index);
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    route.status,
                    if route.status == 200 { "OK" } else { "Error" },
                    route.body.len(),
                    route.body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        base
    }

    #[test]
    fn pbkdf2_sha256_matches_rfc_vectors() {
        assert_eq!(
            hex_encode(&pbkdf2_hmac_sha256(b"password", b"salt", 1, 32)),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        assert_eq!(
            hex_encode(&pbkdf2_hmac_sha256(b"password", b"salt", 2, 32)),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        assert_eq!(
            hex_encode(&pbkdf2_hmac_sha256(b"password", b"salt", 4096, 32)),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn hkdf_matches_rfc5869_case_one() {
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm = hkdf(&ikm, &salt, &info, 42);
        assert_eq!(
            hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn auth_pw_matches_the_reference_client() {
        // Computed independently (Python hashlib/hmac) from the onepw recipe in
        // Vauth/FoxyVPN: PBKDF2 quickStretch → HKDF authPW.
        assert_eq!(
            derive_auth_pw("test@example.com", "password"),
            "a624b128b0e54c3377fe16ca819c09d867827328bd8c740e620bffe3d1208475"
        );
        assert_ne!(
            derive_auth_pw("test@example.com", "password"),
            derive_auth_pw("other@example.com", "password")
        );
    }

    #[test]
    fn emails_and_codes_are_normalized_like_the_reference_client() {
        assert_eq!(
            normalize_email("  Test@Example.COM\u{200b}  "),
            "test@example.com"
        );
        assert_eq!(normalize_email("a b@c.d"), "ab@c.d");
        assert_eq!(sanitize_code(" 12 34 56\u{feff} "), "123456");
    }

    #[test]
    fn hawk_header_matches_the_reference_format() {
        let session_token = "11".repeat(32);
        let (id, key) = derive_hawk_credentials(&session_token).unwrap();
        assert_eq!(
            id,
            "e462cde2fecf14d504630468f70826e11b0c89d5958b5052edc40cc91cdfef30"
        );
        let parts = split_url("https://api.accounts.firefox.com/v1/oauth/token").unwrap();
        let header = hawk_header_with(
            "POST",
            &parts,
            &id,
            &key,
            "{\"code\":\"123456\"}",
            "1700000000",
            "AAAAAAAA",
        );
        // MAC/hash computed independently (Python hmac/hashlib).
        assert_eq!(
            header,
            "Hawk id=\"e462cde2fecf14d504630468f70826e11b0c89d5958b5052edc40cc91cdfef30\", ts=\"1700000000\", nonce=\"AAAAAAAA\", mac=\"qV4jhvjVZHFS06F2pQLyl5v2/rVXDOlULf9EICf3HYA=\", hash=\"Ep9IOeekIfor0O8wOtlEW2ta9aXArsz34Sju2Ketz/I=\""
        );
    }

    const SESSION_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn login_signs_in_with_password_and_returns_tokens() {
        let base = spawn_fxa_stub(vec![
            route(
                "/account/login",
                200,
                concat!(
                    r#"{"sessionToken":""#,
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    r#"","verified":true}"#
                ),
            ),
            route(
                "/oauth/token",
                200,
                r#"{"access_token":"at","refresh_token":"rt","expires_in":3600}"#,
            ),
        ]);
        let outcome = login_with_at(&base, " Test@Example.com ", "password", 1_000).unwrap();
        match outcome {
            LoginOutcome::SignedIn(session) => {
                assert_eq!(session.access_token, "at");
                assert_eq!(session.refresh_token.as_deref(), Some("rt"));
                assert_eq!(session.expires_at, 4_600);
            }
            LoginOutcome::NeedsVerification(_) => panic!("expected a signed-in session"),
        }
    }

    #[test]
    fn login_requests_email_2fa_then_verifies_the_code() {
        let base = spawn_fxa_stub(vec![
            route(
                "/account/login",
                200,
                concat!(
                    r#"{"sessionToken":""#,
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    r#"","verified":false}"#
                ),
            ),
            route("/session/verify_code", 200, "{}"),
            route(
                "/oauth/token",
                200,
                r#"{"access_token":"at2","refresh_token":"rt2","expires_in":10}"#,
            ),
        ]);
        let pending = match login_with_at(&base, "a@b.co", "password", 0).unwrap() {
            LoginOutcome::NeedsVerification(token) => token,
            LoginOutcome::SignedIn(_) => panic!("unverified account must need the emailed code"),
        };
        assert_eq!(pending, SESSION_HEX);
        let session = verify_two_factor_at(&base, &pending, " 123 456 ", 100).unwrap();
        assert_eq!(session.access_token, "at2");
        assert_eq!(session.refresh_token.as_deref(), Some("rt2"));
        assert_eq!(session.expires_at, 110);
    }

    #[test]
    fn login_retries_without_verification_method_on_errno_107() {
        let base = spawn_fxa_stub(vec![
            route(
                "/account/login",
                400,
                r#"{"errno":107,"message":"invalid parameter"}"#,
            ),
            route(
                "/account/login",
                200,
                concat!(
                    r#"{"sessionToken":""#,
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    r#"","verified":true}"#
                ),
            ),
            route(
                "/oauth/token",
                200,
                r#"{"access_token":"at3","expires_in":60}"#,
            ),
        ]);
        match login_with_at(&base, "a@b.co", "password", 0).unwrap() {
            LoginOutcome::SignedIn(session) => assert_eq!(session.access_token, "at3"),
            LoginOutcome::NeedsVerification(_) => panic!("expected signed-in after retry"),
        }
    }

    #[test]
    fn bad_password_is_reported_to_the_user() {
        let base = spawn_fxa_stub(vec![route(
            "/account/login",
            401,
            r#"{"errno":101,"message":"Incorrect password"}"#,
        )]);
        let error = login_with_at(&base, "a@b.co", "wrong", 0).unwrap_err();
        assert!(error.contains("Incorrect password"), "{error}");
    }

    #[test]
    fn refresh_keeps_the_previous_refresh_token_when_omitted() {
        let base = spawn_fxa_stub(vec![route(
            "/oauth/token",
            200,
            r#"{"access_token":"at4","expires_in":3600}"#,
        )]);
        let session = refresh_session_at(&base, "rt-old", 10).unwrap();
        assert_eq!(session.access_token, "at4");
        assert_eq!(session.refresh_token.as_deref(), Some("rt-old"));
        assert_eq!(session.expires_at, 3_610);
    }

    #[test]
    fn auto_login_restores_or_refreshes_the_saved_session() {
        let valid = Session {
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            expires_at: 10_000,
        };
        assert_eq!(
            restore_session_with(
                || Some(valid.clone()),
                |_| panic!("valid token must not refresh"),
                1_000
            ),
            Some(valid)
        );

        let expired = Session {
            access_token: "old".into(),
            refresh_token: Some("rt".into()),
            expires_at: 10,
        };
        let renewed = Session {
            access_token: "new".into(),
            refresh_token: Some("rt2".into()),
            expires_at: 90_000,
        };
        assert_eq!(
            restore_session_with(
                || Some(expired.clone()),
                |token| {
                    assert_eq!(token, "rt");
                    Ok(renewed.clone())
                },
                1_000
            ),
            Some(renewed)
        );

        assert_eq!(
            restore_session_with(|| Some(expired.clone()), |_| Err("offline".into()), 1_000),
            Some(expired)
        );
        assert_eq!(restore_session_with(|| None, |_| unreachable!(), 0), None);

        let blank = Session {
            access_token: "   ".into(),
            refresh_token: None,
            expires_at: 0,
        };
        assert_eq!(
            restore_session_with(|| Some(blank), |_| unreachable!(), 0),
            None
        );
    }

    #[test]
    fn servers_carry_city_and_country() {
        let list = resolve_servers_with(|| Ok(fixture_servers()));
        assert!(list.error.is_none());
        assert!(!list.servers.is_empty());
        for s in &list.servers {
            assert!(!s.city.is_empty(), "{s:?}");
            assert!(!s.country.is_empty(), "{s:?}");
        }
    }

    #[test]
    fn fetch_failure_falls_back_to_fixture_with_error() {
        let list = resolve_servers_with(|| Err("offline".into()));
        assert!(!list.servers.is_empty());
        assert!(list.error.is_some());
        for s in &list.servers {
            assert!(!s.city.is_empty());
            assert!(!s.country.is_empty());
        }
    }

    #[test]
    fn remote_settings_records_parse_city_country_and_connect_host() {
        let body: serde_json::Value = serde_json::json!({
            "data": [
                {"country": {"name": "Germany", "code": "DE", "cities": [
                    {"name": "Berlin", "code": "BER", "servers": [
                        {"hostname": "bad.example", "quarantined": true,
                         "protocols": [{"name": "connect", "host": "bad.example"}]},
                        {"hostname": "ber2.example", "quarantined": false,
                         "protocols": [{"name": "connect", "host": "ber2.example", "port": 443}]}
                    ]}
                ]}},
                {"country": {"name": "CatchAll Anycast", "code": "XX", "cities": [
                    {"name": "Nowhere", "code": "NW", "servers": [{"hostname": "x.example"}]}
                ]}},
                {"country": {"name": "Bad", "code": "BD", "cities": []}}
            ]
        });
        let servers = parse_servers(&body);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "de-ber");
        assert_eq!(servers[0].city, "Berlin");
        assert_eq!(servers[0].country, "Germany");
        assert_eq!(servers[0].hostname, "ber2.example");
    }

    // Task 5 (Linux): route/config parsing, fallback path, guard single-handle.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_default_route_parses_gateway_and_dev() {
        let out = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n\
                   192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.5\n";
        assert_eq!(
            linux_tunnel::parse_default_route(out),
            Some(("192.168.1.1".into(), "eth0".into()))
        );
        assert_eq!(
            linux_tunnel::parse_default_route("192.168.1.0/24 dev eth0 scope link\n"),
            None
        );
        assert_eq!(
            linux_tunnel::parse_default_route("default dev tun0 scope link\n"),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_edge_and_connect_request_carry_guardian_config() {
        assert_eq!(
            linux_tunnel::edge_host("x", "edge.example.com"),
            "edge.example.com"
        );
        assert_eq!(
            linux_tunnel::edge_host("us-california", ""),
            "us-california.guardian.vpn.mozilla.org"
        );
        let req = linux_tunnel::connect_request("edge.example.com", "tok123");
        assert!(req.starts_with("CONNECT edge.example.com:443"), "{req}");
        assert!(req.contains("Bearer tok123"), "{req}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_privileged_argv_escalates_via_pkexec() {
        // pkexec framing is the AC9 system auth prompt; pinned without exec.
        let (prog, args) = linux_tunnel::privileged_argv("ip", &["tuntap", "add"]);
        assert_eq!(prog, "pkexec");
        assert_eq!(args, vec!["ip", "tuntap", "add"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fallback_uses_stub_with_clear_note() {
        let opened =
            linux_tunnel::open_with_probe("de-berlin", Err("simulated: no TUN in CI".into()));
        assert!(opened.used_stub);
        assert_eq!(opened.exit_ip, stub_exit_ip("de-berlin"));
        assert_eq!(opened.note.as_deref(), Some("simulated: no TUN in CI"));
    }

    // AC8 safety: a passing preflight alone must not bring up a route with no
    // data plane behind it (would blackhole all traffic while "Connected").
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_open_stays_stub_without_data_plane() {
        let opened = linux_tunnel::open_with_probe("de-berlin", Ok(()));
        assert!(opened.used_stub);
        assert!(
            opened.note.unwrap_or_default().contains("data plane"),
            "note must say the live data plane is missing"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_preflight_agrees_with_device_node() {
        // Deterministic where TUN is absent (CI); vacuous where present.
        if !std::path::Path::new("/dev/net/tun").exists() {
            assert!(linux_tunnel::tun_available().is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_double_connect_keeps_single_handle() {
        let store = VpnStore::default();
        let first = vpn_connect_impl(&store, "us-california");
        let second = vpn_connect_impl(&store, "jp-tokyo");
        assert_eq!(second, first, "repeat connect must not change state");
        assert_eq!(store.inner.lock().unwrap().handles, 1);
        vpn_disconnect_impl(&store);
    }

    // Task 6 (Windows): adapter config/framing parsing + fallback path; plain
    // #[test] (no cfg gate) so they run on this Linux host, and the module is
    // std-only so it compiles here. Guard tests above stay untouched.
    #[test]
    fn windows_edge_and_connect_request_carry_guardian_config() {
        assert_eq!(
            windows_tunnel::edge_host("x", "edge.example.com"),
            "edge.example.com"
        );
        assert_eq!(
            windows_tunnel::edge_host("us-california", ""),
            "us-california.guardian.vpn.mozilla.org"
        );
        let req = windows_tunnel::connect_request("edge.example.com", "tok123");
        assert!(req.starts_with("CONNECT edge.example.com:443"), "{req}");
        assert!(req.contains("Bearer tok123"), "{req}");
    }

    #[test]
    fn windows_route_print_parses_default_gateway() {
        let out = "IPv4 Route Table\r\n\
                   Network Destination        Netmask          Gateway       Interface  Metric\r\n\
                             0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.10     35\r\n\
                           127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\r\n";
        assert_eq!(
            windows_tunnel::parse_route_print(out),
            Some("192.168.1.1".into())
        );
        assert_eq!(
            windows_tunnel::parse_route_print("127.0.0.0  255.0.0.0  On-link  127.0.0.1  331\n"),
            None
        );
        assert_eq!(windows_tunnel::parse_route_print(""), None);
    }

    #[test]
    fn windows_adapter_constants_pin_consent_label() {
        // ADAPTER_NAME is the label in the adapter-install consent dialog (AC9).
        assert_eq!(windows_tunnel::ADAPTER_NAME, "FoxyVPN");
        assert!(!windows_tunnel::TUN_ADDR.is_empty());
        assert_eq!(windows_tunnel::WINTUN_DLL, "wintun.dll");
    }

    #[test]
    fn windows_fallback_uses_stub_with_clear_note() {
        let opened =
            windows_tunnel::open_with_probe("jp-tokyo", Err("simulated: no Wintun in CI".into()));
        assert!(opened.used_stub);
        assert_eq!(opened.exit_ip, stub_exit_ip("jp-tokyo"));
        assert_eq!(opened.note.as_deref(), Some("simulated: no Wintun in CI"));
        // Live path also falls back until the `wintun` dep is approved.
        let live = windows_tunnel::open_with_probe("jp-tokyo", Ok(()));
        assert!(live.used_stub);
        assert!(live.note.unwrap_or_default().contains("wintun"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn windows_preflight_reports_windows_only_off_windows() {
        assert!(windows_tunnel::wintun_available().is_err());
    }

    // Task 7 (Android): fd-plumbing/framing parsing + fallback path; plain
    // #[test] (no cfg gate) so they run on this Linux host, and the module is
    // std-only so it compiles here. Guard tests above stay untouched.
    #[test]
    fn android_edge_and_connect_request_carry_guardian_config() {
        assert_eq!(
            android_tunnel::edge_host("x", "edge.example.com"),
            "edge.example.com"
        );
        assert_eq!(
            android_tunnel::edge_host("us-california", ""),
            "us-california.guardian.vpn.mozilla.org"
        );
        let req = android_tunnel::connect_request("edge.example.com", "tok123");
        assert!(req.starts_with("CONNECT edge.example.com:443"), "{req}");
        assert!(req.contains("Bearer tok123"), "{req}");
    }

    #[test]
    fn android_tun_fd_parsing_rejects_bad_handoff() {
        assert_eq!(android_tunnel::parse_tun_fd("42"), Some(42));
        assert_eq!(android_tunnel::parse_tun_fd("  7  "), Some(7));
        assert_eq!(android_tunnel::parse_tun_fd("-1"), None);
        assert_eq!(android_tunnel::parse_tun_fd("abc"), None);
        assert_eq!(android_tunnel::parse_tun_fd(""), None);
        assert!(!android_tunnel::set_tun_fd(-1));
    }

    #[test]
    fn android_builder_config_pins_system_route_and_dns() {
        // Fully-system default route + system DNS, no split-tunnel/DNS UI (AC10).
        let cfg = android_tunnel::builder_config();
        assert_eq!(cfg.address, android_tunnel::TUN_ADDR);
        assert_eq!(cfg.prefix, android_tunnel::TUN_PREFIX);
        assert_eq!(cfg.mtu, android_tunnel::MTU);
        assert_eq!(cfg.dns, android_tunnel::DNS);
        assert_eq!(cfg.routes, vec!["0.0.0.0/0"]);
    }

    #[test]
    fn android_service_constants_pin_consent_label() {
        // SERVICE_INTERFACE is the intent-filter action in the follow-up
        // AndroidManifest.xml (AC9 consent path).
        assert_eq!(android_tunnel::SERVICE_INTERFACE, "android.net.VpnService");
        assert!(!android_tunnel::TUN_ADDR.is_empty());
    }

    #[test]
    fn android_fd_slot_hands_off_once() {
        assert!(android_tunnel::set_tun_fd(42));
        assert_eq!(android_tunnel::take_tun_fd(), Some(42));
        assert_eq!(android_tunnel::take_tun_fd(), None);
    }

    #[test]
    fn android_fallback_uses_stub_with_clear_note() {
        let opened = android_tunnel::open_with_probe(
            "de-berlin",
            None,
            Err("simulated: no VpnService in CI".into()),
        );
        assert!(opened.used_stub);
        assert_eq!(opened.exit_ip, stub_exit_ip("de-berlin"));
        assert_eq!(
            opened.note.as_deref(),
            Some("simulated: no VpnService in CI")
        );
        // Consent done (fd present) but live core missing → stub with fd note.
        let no_core = android_tunnel::open_with_probe("de-berlin", Some(42), Ok(()));
        assert!(no_core.used_stub);
        assert!(no_core.note.unwrap_or_default().contains("TUN/H2"));
        // Preflight passed but no fd yet → stub with consent note.
        let no_fd = android_tunnel::open_with_probe("de-berlin", None, Ok(()));
        assert!(no_fd.used_stub);
        assert!(no_fd.note.unwrap_or_default().contains("consent"));
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn android_preflight_reports_android_only_off_android() {
        assert!(android_tunnel::vpnsvc_available().is_err());
    }
}
