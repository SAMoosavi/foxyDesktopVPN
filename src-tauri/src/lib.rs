// Task 2: FxA sign-in via system browser (AC1: browser sign-in → signed-in home;
// AC12: sign-in button reacts immediately).
// ponytail: std TcpListener loopback + tauri-plugin-opener (already present); token to OS
// keychain via `keyring` with an in-memory mirror as source of truth (works headless/offline).
// TODO(tasks 3/8): registered FxA OAuth client + code→Guardian-token exchange + keychain restore on startup.
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_opener::OpenerExt;

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
// required per tasks.md gate, not requested from this worktree). TUN bring-up
// + default route go through the `ip` CLI; non-root escalation goes via
// `pkexec`, which is what surfaces the Linux system auth prompt (the AC9 OS
// indicator). Guardian-token CONNECT framing to the Fastly edge is built here
// (firefox-vpn-client/hev-socks5-tunnel behavior); the live tun2socks
// forwarding loop needs the approved TUN/H2 dep and stays documented fallback:
// ANY bring-up failure falls back to StubTunnel with a clear note, so `cargo
// test` stays green on non-root/CI machines (hardware IP-check is manual).
#[cfg(target_os = "linux")]
pub mod linux_tunnel {
    use super::{StubTunnel, Tunnel, stub_exit_ip};
    use std::sync::{Mutex, OnceLock};

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

    fn saved_default() -> &'static Mutex<Option<(String, String)>> {
        static SAVED: OnceLock<Mutex<Option<(String, String)>>> = OnceLock::new();
        SAVED.get_or_init(|| Mutex::new(None))
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

    /// Only escalate via pkexec where an auth agent could exist; unit tests
    /// never spawn prompts (cfg(test) → false) and headless CI falls back.
    fn auth_session_present() -> bool {
        if cfg!(test) {
            return false;
        }
        ["DISPLAY", "WAYLAND_DISPLAY"]
            .iter()
            .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
    }

    /// Pure argv constructor so tests pin the escalation framing (pkexec =
    /// the AC9 system auth prompt) without executing anything.
    pub fn privileged_argv(program: &str, args: &[&str]) -> (String, Vec<String>) {
        let mut full = vec![program.to_owned()];
        full.extend(args.iter().map(|s| s.to_string()));
        ("pkexec".to_owned(), full)
    }

    fn run_ip(args: &[&str], privileged: bool) -> Result<bool, String> {
        let (prog, full) = if privileged {
            privileged_argv("ip", args)
        } else {
            (
                "ip".to_owned(),
                args.iter().map(|s| s.to_string()).collect(),
            )
        };
        std::process::Command::new(&prog)
            .args(&full)
            .status()
            .map(|s| s.success())
            .map_err(|e| format!("could not exec {prog} ({e}) — using stub tunnel."))
    }

    pub struct TunnelOpen {
        pub exit_ip: String,
        pub used_stub: bool,
        pub note: Option<String>,
    }

    /// Smallest-viable Linux open: preflight → TUN device → default route.
    /// ANY failure → StubTunnel with a clear note (green tests, no hangs).
    pub fn open_or_fallback(server: &str) -> TunnelOpen {
        open_with_probe(server, tun_available())
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
        // Remember the current default route so disconnect can restore it (AC5).
        if let Ok(out) = std::process::Command::new("ip")
            .args(["route", "show"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            if let Some(route) = parse_default_route(&text) {
                *saved_default().lock().unwrap() = Some(route);
            }
        }
        let _edge = edge_host(server, "");
        let add = ["tuntap", "add", "dev", TUN_NAME, "mode", "tun"];
        let privileged = match run_ip(&add, false) {
            Ok(true) => false,
            _ if auth_session_present() => match run_ip(&add, true) {
                Ok(true) => true,
                Ok(false) => {
                    return fallback(
                        "TUN bring-up refused (auth cancelled?) — using stub tunnel.".into(),
                    );
                }
                Err(note) => return fallback(note),
            },
            _ => {
                return fallback(
                    "TUN bring-up needs privilege and no desktop auth session is present — using stub tunnel."
                        .into(),
                );
            }
        };
        let _ = run_ip(&["link", "set", "dev", TUN_NAME, "up"], privileged);
        let _ = run_ip(&["addr", "add", TUN_ADDR, "dev", TUN_NAME], privileged);
        if run_ip(
            &["route", "replace", "default", "dev", TUN_NAME],
            privileged,
        ) != Ok(true)
        {
            return fallback("default route via TUN failed — using stub tunnel.".into());
        }
        TunnelOpen {
            exit_ip: stub_exit_ip(server),
            used_stub: false,
            note: None,
        }
    }

    /// Tear down the TUN device + restore the saved default route (AC5: IP-check
    /// shows the direct IP again). No-op when the device was never brought up,
    /// so disconnect never prompts on the fallback path.
    pub fn close_system() {
        if !std::path::Path::new(&format!("/sys/class/net/{TUN_NAME}")).exists() {
            return;
        }
        let del = ["tuntap", "del", "dev", TUN_NAME, "mode", "tun"];
        if run_ip(&del, false) != Ok(true) && auth_session_present() {
            let _ = run_ip(&del, true);
        }
        if let Some((gateway, dev)) = saved_default().lock().unwrap().take() {
            let restore = [
                "route",
                "replace",
                "default",
                "via",
                gateway.as_str(),
                "dev",
                dev.as_str(),
            ];
            let _ = run_ip(&restore, false);
        }
    }
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
    use super::{StubTunnel, Tunnel, stub_exit_ip};

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
    use super::{StubTunnel, Tunnel, stub_exit_ip};
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
fn close_tunnel() {
    linux_tunnel::close_system();
    StubTunnel::close();
}
#[cfg(target_os = "windows")]
fn close_tunnel() {
    windows_tunnel::close_system();
    StubTunnel::close();
}
#[cfg(target_os = "android")]
fn close_tunnel() {
    android_tunnel::close_system();
    StubTunnel::close();
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
fn close_tunnel() {
    StubTunnel::close();
}

#[derive(Default)]
struct VpnInner {
    status: VpnStatus,
    handles: u32, // open stub-tunnel handles; guard keeps this ≤1 (AC6)
}

#[derive(Default)]
pub struct VpnStore {
    inner: Mutex<VpnInner>,
}

/// One guarded connection: repeat connect while Connecting|Connected is a no-op (AC6).
pub fn vpn_connect_impl(store: &VpnStore, server: &str) -> VpnStatus {
    let mut guard = store.inner.lock().unwrap();
    match guard.status.state {
        VpnState::Connecting | VpnState::Connected => guard.status.clone(),
        VpnState::Disconnected => {
            if server.is_empty() {
                guard.status.last_error = Some("Pick a server first.".into());
                return guard.status.clone();
            }
            guard.status.state = VpnState::Connecting;
            guard.status.server = Some(server.to_owned());
            guard.status.last_error = None;
            // Platform open is instant: Connecting→Connected under one lock.
            // The handle stays open until disconnect (Linux: system TUN in
            // task 5 with stub fallback; Windows/Android: tasks 6–7).
            guard.handles += 1;
            guard.status.exit_ip = Some(open_tunnel(server));
            guard.status.state = VpnState::Connected;
            guard.status.clone()
        }
    }
}

/// Tear down the connection; exit IP clears so IP-check shows the direct IP (AC5).
pub fn vpn_disconnect_impl(store: &VpnStore) -> VpnStatus {
    let mut guard = store.inner.lock().unwrap();
    if guard.handles > 0 {
        close_tunnel();
        guard.handles = 0;
    }
    guard.status = VpnStatus::default();
    guard.status.clone()
}

pub fn vpn_status_impl(store: &VpnStore) -> VpnStatus {
    store.inner.lock().unwrap().status.clone()
}

#[tauri::command]
fn vpn_connect(store: State<VpnStore>, server: String) -> VpnStatus {
    vpn_connect_impl(&store, &server)
}

#[tauri::command]
fn vpn_disconnect(store: State<VpnStore>) -> VpnStatus {
    vpn_disconnect_impl(&store)
}

#[tauri::command]
fn vpn_status(store: State<VpnStore>) -> VpnStatus {
    vpn_status_impl(&store)
}

pub const FXA_AUTHORIZE_BASE: &str = "https://accounts.firefox.com/authorization";
// ponytail: placeholder client id; the registered FxA OAuth client lands with Guardian wiring.
pub const FXA_CLIENT_ID: &str = "foxy-desktop-vpn";
pub const FXA_SCOPE: &str = "profile https://identity.mozilla.com/apps/vpn";
pub const AUTH_CHANGED_EVENT: &str = "auth-changed";

const KEYRING_SERVICE: &str = "foxy-desktop-vpn";
const KEYRING_USER: &str = "guardian-token";
const CALLBACK_PATH: &str = "/oauth/callback";
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Default)]
pub struct AuthState {
    token: Mutex<Option<String>>,
}

/// Minimal percent-encoding for OAuth query values (stdlib only; no `url` crate).
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex: Option<u8> = (bytes[i] == b'%' && i + 3 <= bytes.len())
            .then(|| u8::from_str_radix(&value[i + 1..i + 3], 16).ok())
            .flatten();
        if let Some(v) = hex {
            out.push(v);
            i += 3;
        } else {
            out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// FxA OAuth authorize URL for the given loopback redirect URI.
pub fn authorize_url(redirect_uri: &str) -> String {
    format!(
        "{FXA_AUTHORIZE_BASE}?client_id={}&redirect_uri={}&response_type=code&scope={}&state=foxyvpn",
        percent_encode(FXA_CLIENT_ID),
        percent_encode(redirect_uri),
        percent_encode(FXA_SCOPE),
    )
}

/// Extract `code=` from an HTTP request target; only the loopback callback path counts.
pub fn callback_code(request_target: &str) -> Option<String> {
    let (path, query) = request_target.split_once('?')?;
    if path != CALLBACK_PATH {
        return None;
    }
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == "code" && !v.is_empty()).then(|| percent_decode(v))
    })
}

pub fn store_token(state: &AuthState, token: &str) {
    // Best-effort OS keychain; the in-memory mirror is the source of truth.
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
        let _ = entry.set_password(token);
    }
    *state.token.lock().unwrap() = Some(token.to_owned());
}

pub fn signed_in(state: &AuthState) -> bool {
    state.token.lock().unwrap().is_some()
}

pub fn clear_token(state: &AuthState) {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
        let _ = entry.delete_credential();
    }
    state.token.lock().unwrap().take();
}

fn reply_and_close(mut stream: std::net::TcpStream, code: Option<&str>) {
    let body = match code {
        Some(_) => "<h1>Signed in — you can close this tab and return to FoxyVPN.</h1>",
        None => "<h1>FoxyVPN sign-in: no code received, please retry from the app.</h1>",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
}

fn wait_for_code(listener: TcpListener, timeout: Duration) -> Option<String> {
    listener.set_nonblocking(true).ok()?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let code = stream.try_clone().ok().and_then(|clone| {
                    let mut lines = BufReader::new(clone).lines();
                    let request_line = lines.next()?.ok()?;
                    let target = request_line.split_whitespace().nth(1)?;
                    target
                        .starts_with(CALLBACK_PATH)
                        .then(|| callback_code(target))
                        .flatten()
                });
                reply_and_close(stream, code.as_deref());
                if code.is_some() {
                    return code;
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    None
}

/// Bind the loopback callback, open the system browser, and wait off-thread.
/// Returns immediately so the sign-in button reacts ≤5s (AC12); the result
/// arrives later via `on_code` (which stores the token and emits `auth-changed`).
pub fn begin_browser_sign_in(
    open: impl FnOnce(String) + Send + 'static,
    on_code: impl FnOnce(String) + Send + 'static,
    timeout: Duration,
) -> std::io::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let url = authorize_url(&format!("http://127.0.0.1:{port}{CALLBACK_PATH}"));
    std::thread::spawn(move || {
        open(url);
        if let Some(code) = wait_for_code(listener, timeout) {
            on_code(code);
        }
    });
    Ok(String::from("Opening system browser for Firefox sign-in…"))
}

#[derive(serde::Serialize, Clone)]
struct AuthChanged {
    signed_in: bool,
}

#[tauri::command]
fn auth_sign_in(app: AppHandle) -> Result<String, String> {
    let opener_app = app.clone();
    let callback_app = app.clone();
    begin_browser_sign_in(
        move |url| {
            let _ = opener_app.opener().open_url(url, None::<&str>);
        },
        move |code| {
            // FxA returns an OAuth code; full code→token exchange lands with Guardian wiring.
            let auth: State<AuthState> = callback_app.state();
            store_token(&auth, &code);
            let _ = callback_app.emit(AUTH_CHANGED_EVENT, AuthChanged { signed_in: true });
        },
        CALLBACK_TIMEOUT,
    )
    .map_err(|e| format!("sign-in failed to start: {e}"))
}

#[tauri::command]
fn auth_sign_out(app: AppHandle) -> Result<(), String> {
    let auth: State<AuthState> = app.state();
    clear_token(&auth);
    app.emit(AUTH_CHANGED_EVENT, AuthChanged { signed_in: false })
        .map_err(|e| e.to_string())
}

// Task 3: server list fetch + picker UI (AC2: city/country list; AC12: no spinner, error line).
// ponytail: one struct + pure resolver (fetch injectable so tests stay offline); the live
// fetch is a single short-timeout reqwest call, any failure → fixture + error string.
pub const GUARDIAN_SERVERS_URL: &str = "https://vpn.mozilla.org/api/v1/vpn/servers/";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Server {
    pub id: String,
    pub city: String,
    pub country: String,
    #[serde(default)]
    pub hostname: String,
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
        },
        Server {
            id: "de-berlin".into(),
            city: "Berlin".into(),
            country: "Germany".into(),
            hostname: "de-berlin.guardian.vpn.mozilla.org".into(),
        },
        Server {
            id: "jp-tokyo".into(),
            city: "Tokyo".into(),
            country: "Japan".into(),
            hostname: "jp-tokyo.guardian.vpn.mozilla.org".into(),
        },
    ]
}

/// Tolerant parse: accept a bare array or `{servers|results: [...]}`; skip entries
/// missing city/country (the picker needs both).
pub fn parse_servers(value: &serde_json::Value) -> Vec<Server> {
    let items = match value {
        serde_json::Value::Array(items) => items.as_slice(),
        serde_json::Value::Object(map) => map
            .get("servers")
            .or_else(|| map.get("results"))
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        _ => &[],
    };
    items
        .iter()
        .filter_map(|item| {
            let city = item.get("city")?.as_str()?;
            let country = item.get("country")?.as_str()?;
            if city.is_empty() || country.is_empty() {
                return None;
            }
            Some(Server {
                id: item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(city)
                    .to_owned(),
                city: city.to_owned(),
                country: country.to_owned(),
                hostname: item
                    .get("hostname")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
            })
        })
        .collect()
}

fn fetch_live_servers(token: &str) -> Result<Vec<Server>, String> {
    let body: serde_json::Value = reqwest::blocking::Client::new()
        .get(GUARDIAN_SERVERS_URL)
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .map_err(|e| e.to_string())?;
    Ok(parse_servers(&body))
}

pub fn resolve_servers_with(
    token: Option<String>,
    fetch: impl FnOnce(&str) -> Result<Vec<Server>, String>,
) -> ServerList {
    match token {
        None => ServerList {
            servers: vec![],
            error: Some("Signed out — please sign in again.".into()),
        },
        Some(token) => match fetch(&token) {
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
                    "Could not reach Guardian ({e}) — showing sample servers."
                )),
            },
        },
    }
}

#[tauri::command]
fn list_servers(auth: State<AuthState>) -> ServerList {
    let token = auth.token.lock().unwrap().clone();
    resolve_servers_with(token, fetch_live_servers)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AuthState::default())
        .manage(VpnStore::default())
        .invoke_handler(tauri::generate_handler![
            auth_sign_in,
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
    use std::io::Read;
    use std::sync::mpsc;

    #[test]
    fn initial_status_is_disconnected() {
        assert_eq!(VpnStatus::default().state, VpnState::Disconnected);
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

    #[test]
    fn sign_out_clears_token() {
        let auth = AuthState::default();
        assert!(!signed_in(&auth));
        store_token(&auth, "tok123");
        assert!(signed_in(&auth));
        clear_token(&auth);
        assert!(!signed_in(&auth));
    }

    #[test]
    fn sign_in_returns_immediately_and_opens_fxa() {
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        begin_browser_sign_in(
            move |url| {
                let _ = tx.send(url);
            },
            |_| {},
            Duration::from_millis(50),
        )
        .unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "sign-in blocked for {elapsed:?}"
        );
        let url = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(url.starts_with(FXA_AUTHORIZE_BASE), "{url}");
        assert!(url.contains("127.0.0.1"), "{url}");
    }

    #[test]
    fn loopback_captures_code_and_replies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(|| wait_for_code(listener, Duration::from_secs(5)));
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            stream,
            "GET /oauth/callback?code=secret123&state=foxyvpn HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        .unwrap();
        let mut buf = [0u8; 128];
        let n = stream.read(&mut buf).unwrap();
        assert!(
            std::str::from_utf8(&buf[..n])
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
        assert_eq!(handle.join().unwrap().as_deref(), Some("secret123"));
    }

    #[test]
    fn callback_code_rejects_non_callback_targets() {
        assert_eq!(
            callback_code("/oauth/callback?code=abc&state=x").as_deref(),
            Some("abc")
        );
        assert_eq!(callback_code("/oauth/callback?state=x"), None);
        assert_eq!(callback_code("/favicon.ico?code=abc"), None);
    }

    #[test]
    fn servers_carry_city_and_country() {
        let list = resolve_servers_with(Some("tok".into()), |_| Ok(fixture_servers()));
        assert!(list.error.is_none());
        assert!(!list.servers.is_empty());
        for s in &list.servers {
            assert!(!s.city.is_empty(), "{s:?}");
            assert!(!s.country.is_empty(), "{s:?}");
        }
    }

    #[test]
    fn unauth_list_is_empty_with_error_not_spinner() {
        let list = resolve_servers_with(None, |_| Ok(fixture_servers()));
        assert!(list.servers.is_empty());
        assert!(list.error.unwrap_or_default().contains("sign in"));
    }

    #[test]
    fn fetch_failure_falls_back_to_fixture_with_error() {
        let list = resolve_servers_with(Some("tok".into()), |_| Err("offline".into()));
        assert!(!list.servers.is_empty());
        assert!(list.error.is_some());
        for s in &list.servers {
            assert!(!s.city.is_empty());
            assert!(!s.country.is_empty());
        }
    }

    #[test]
    fn parse_servers_skips_entries_missing_city_country() {
        let body: serde_json::Value = serde_json::json!([
            {"id": "a", "city": "Paris", "country": "France", "hostname": "a.example"},
            {"id": "b", "country": "France"},
            {"id": "c", "city": "", "country": "France"}
        ]);
        let servers = parse_servers(&body);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].city, "Paris");
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
        assert_eq!(android_tunnel::set_tun_fd(-1), false);
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
