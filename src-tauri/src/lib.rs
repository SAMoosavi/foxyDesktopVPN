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
            // Stub open is instant: Connecting→Connected under one lock.
            // The handle stays open until disconnect (real tunnel in tasks 5–7).
            guard.handles += 1;
            guard.status.exit_ip = Some(StubTunnel::open(server));
            guard.status.state = VpnState::Connected;
            guard.status.clone()
        }
    }
}

/// Tear down the connection; exit IP clears so IP-check shows the direct IP (AC5).
pub fn vpn_disconnect_impl(store: &VpnStore) -> VpnStatus {
    let mut guard = store.inner.lock().unwrap();
    if guard.handles > 0 {
        StubTunnel::close();
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
}
