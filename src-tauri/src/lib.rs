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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VpnState {
    #[default]
    Disconnected,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VpnStatus {
    pub state: VpnState,
    pub server: Option<String>,
    pub exit_ip: Option<String>,
    pub last_error: Option<String>,
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AuthState::default())
        .invoke_handler(tauri::generate_handler![auth_sign_in, auth_sign_out])
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
}
