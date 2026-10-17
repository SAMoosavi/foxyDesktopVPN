use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;

    // Sync binding returning the raw Promise: avoids borrowing a Closure across an await.
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"], js_name = "listen")]
    fn listen_raw(event: &str, handler: &JsValue) -> js_sys::Promise;
}

#[derive(Serialize, Deserialize, Clone)]
struct AuthChanged {
    signed_in: bool,
    // Task 8 (AC7): present when a 401 expires the session — the re-sign-in prompt.
    #[serde(default)]
    error: Option<String>,
    // FxA emailed confirmation code required (reference-client 2FA flow).
    #[serde(default)]
    needs_verification: bool,
}

#[derive(Serialize)]
struct Credentials {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct CodeArgs {
    code: String,
}

#[derive(Deserialize, Clone)]
struct Server {
    id: String,
    city: String,
    country: String,
}

#[derive(Deserialize)]
struct ServerList {
    #[serde(default)]
    servers: Vec<Server>,
    #[serde(default)]
    error: Option<String>,
}

// Task 4: connect/disconnect + status UI (AC3/5 status half, AC6, AC11).
// One toggle button + one status line (state + exit IP) + the error line;
// repeat connect is a backend no-op, so double-press can't duplicate.
#[derive(Deserialize, Clone)]
struct VpnStatus {
    #[serde(default)]
    state: String,
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    exit_ip: Option<String>,
    #[serde(default)]
    last_error: Option<String>,
    /// Local proxy endpoints while connected (data plane is running).
    #[serde(default)]
    proxy: Option<String>,
}

#[derive(Serialize)]
struct ConnectArgs {
    server: String,
}

fn describe_vpn(status: &VpnStatus) -> (bool, String, Option<String>) {
    let up = status.state == "Connected";
    let mut line = if up {
        format!(
            "Connected — {} (exit IP {})",
            status.server.clone().unwrap_or_default(),
            status.exit_ip.clone().unwrap_or_default()
        )
    } else if status.state == "Connecting" {
        String::from("Connecting…")
    } else {
        String::from("Disconnected")
    };
    // Data plane up: show where the local proxies listen, so apps can be
    // pointed at them (reference client's "Proxy active • SOCKS/HTTP" line).
    if let Some(proxy) = status.proxy.clone() {
        line.push_str(" — proxy ");
        line.push_str(&proxy);
    }
    (up, line, status.last_error.clone())
}

#[derive(Deserialize)]
struct TauriEvent {
    payload: AuthChanged,
}

#[component]
pub fn App() -> impl IntoView {
    let (signed_in, set_signed_in) = signal(false);
    let (status, set_status) = signal(String::from("Signed out."));
    // FxA email/password sign-in, with the emailed 2FA step (reference flow).
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (code, set_code) = signal(String::new());
    let (needs_verification, set_needs_verification) = signal(false);
    let (auth_error, set_auth_error) = signal(Option::<String>::None);
    // Task 3: server list (AC2) + picked server; errors render as a line, never a spinner.
    let (servers, set_servers) = signal(Vec::<Server>::new());
    let (servers_error, set_servers_error) = signal(Option::<String>::None);
    let (picked, set_picked) = signal(Option::<String>::None);
    // Task 4: single toggle + status line (state + exit IP) + error line.
    let (connected, set_connected) = signal(false);
    let (vpn_line, set_vpn_line) = signal(String::from("Disconnected"));
    let (vpn_error, set_vpn_error) = signal(Option::<String>::None);

    // Backend `auth-changed` events drive the signed-in home (sign-in callback or sign-out).
    Effect::new(move || {
        let handler: Closure<dyn Fn(JsValue)> = Closure::new(move |event: JsValue| {
            if let Ok(ev) = serde_wasm_bindgen::from_value::<TauriEvent>(event) {
                set_signed_in.set(ev.payload.signed_in);
                set_status.set(if ev.payload.signed_in {
                    String::from("Signed in — welcome home.")
                } else if let Some(err) = ev.payload.error {
                    err
                } else {
                    String::from("Signed out.")
                });
            }
        });
        spawn_local(async move {
            let _ = JsFuture::from(listen_raw("auth-changed", handler.as_ref())).await;
            // ponytail: single app-lifetime listener, never unlistened.
            handler.forget();
        });
    });

    // Auto-login: restore the keychain session on launch, so a returning user
    // lands on the signed-in home without a browser or re-entering anything.
    Effect::new(move || {
        spawn_local(async move {
            let value = invoke("auth_restore", JsValue::UNDEFINED).await;
            if let Ok(changed) = serde_wasm_bindgen::from_value::<AuthChanged>(value)
                && changed.signed_in
            {
                set_signed_in.set(true);
                set_status.set(String::from("Signed in — welcome back."));
            }
        });
    });

    let sign_in = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email = email.get_untracked();
        let password = password.get_untracked();
        // Immediate feedback (AC12); failures land on the error line.
        set_auth_error.set(None);
        if email.trim().is_empty() || password.is_empty() {
            set_auth_error.set(Some(String::from(
                "Enter your Firefox account email and password.",
            )));
            return;
        }
        set_status.set(String::from("Signing in…"));
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&Credentials { email, password })
                .unwrap_or(JsValue::UNDEFINED);
            let value = invoke("auth_sign_in", args).await;
            match serde_wasm_bindgen::from_value::<AuthChanged>(value) {
                Ok(changed) => {
                    set_password.set(String::new());
                    set_signed_in.set(changed.signed_in);
                    set_needs_verification.set(changed.needs_verification);
                    if changed.signed_in {
                        set_status.set(String::from("Signed in — welcome back."));
                    } else {
                        set_status.set(String::from("Signed out."));
                        set_auth_error.set(changed.error);
                    }
                }
                Err(_) => {
                    set_status.set(String::from("Signed out."));
                    set_auth_error.set(Some(String::from("Sign-in call failed — please retry.")))
                }
            }
        });
    };

    let verify = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let code = code.get_untracked();
        set_auth_error.set(None);
        if code.trim().is_empty() {
            set_auth_error.set(Some(String::from(
                "Enter the confirmation code from your email.",
            )));
            return;
        }
        set_status.set(String::from("Verifying…"));
        spawn_local(async move {
            let args =
                serde_wasm_bindgen::to_value(&CodeArgs { code }).unwrap_or(JsValue::UNDEFINED);
            let value = invoke("auth_verify_code", args).await;
            match serde_wasm_bindgen::from_value::<AuthChanged>(value) {
                Ok(changed) => {
                    set_code.set(String::new());
                    set_signed_in.set(changed.signed_in);
                    set_needs_verification.set(changed.needs_verification);
                    if changed.signed_in {
                        set_status.set(String::from("Signed in — welcome back."));
                    } else {
                        set_status.set(String::from("Signed out."));
                        set_auth_error.set(changed.error);
                    }
                }
                Err(_) => {
                    set_status.set(String::from("Signed out."));
                    set_auth_error.set(Some(String::from(
                        "Verification call failed — please retry.",
                    )))
                }
            }
        });
    };
    let sign_out = move |_| {
        // Immediate feedback (AC12); the signed-out state arrives via `auth-changed`.
        set_status.set(String::from("Signing out…"));
        spawn_local(async move {
            invoke("auth_sign_out", JsValue::UNDEFINED).await;
        });
    };

    // Task 4: one toggle button (repeat connect = backend no-op, AC6); every
    // press updates the status or error line immediately (AC12).
    let toggle_vpn = move |_| {
        set_vpn_error.set(None);
        if connected.get_untracked() {
            set_vpn_line.set(String::from("Disconnecting…"));
            spawn_local(async move {
                let value = invoke("vpn_disconnect", JsValue::UNDEFINED).await;
                match serde_wasm_bindgen::from_value::<VpnStatus>(value) {
                    Ok(s) => {
                        let (up, line, err) = describe_vpn(&s);
                        set_connected.set(up);
                        set_vpn_line.set(line);
                        set_vpn_error.set(err);
                    }
                    Err(_) => {
                        set_vpn_error.set(Some(String::from("VPN call failed — please retry.")))
                    }
                }
            });
        } else {
            let Some(id) = picked.get_untracked() else {
                set_vpn_error.set(Some(String::from("Pick a server first.")));
                return;
            };
            set_vpn_line.set(String::from("Connecting…"));
            spawn_local(async move {
                let args = serde_wasm_bindgen::to_value(&ConnectArgs { server: id })
                    .unwrap_or(JsValue::UNDEFINED);
                let value = invoke("vpn_connect", args).await;
                match serde_wasm_bindgen::from_value::<VpnStatus>(value) {
                    Ok(s) => {
                        let (up, line, err) = describe_vpn(&s);
                        set_connected.set(up);
                        set_vpn_line.set(line);
                        set_vpn_error.set(err);
                    }
                    Err(_) => {
                        // Task 8: never a stuck "Connecting…" — fall back to Disconnected + error line.
                        set_vpn_line.set(String::from("Disconnected"));
                        set_vpn_error.set(Some(String::from("VPN call failed — please retry.")))
                    }
                }
            });
        }
    };

    // Fetch the list whenever the signed-in home appears; failures land on the error line.
    Effect::new(move || {
        if signed_in.get() {
            spawn_local(async move {
                let value = invoke("list_servers", JsValue::UNDEFINED).await;
                match serde_wasm_bindgen::from_value::<ServerList>(value) {
                    Ok(list) => {
                        set_servers.set(list.servers);
                        set_servers_error.set(list.error);
                    }
                    Err(_) => set_servers_error
                        .set(Some(String::from("Could not load servers — please retry."))),
                }
            });
        } else {
            set_servers.set(Vec::new());
            set_servers_error.set(None);
            set_picked.set(None);
            set_connected.set(false);
            set_vpn_line.set(String::from("Disconnected"));
            set_vpn_error.set(None);
        }
    });

    view! {
        <main class="container">
            <h1>"FoxyVPN"</h1>
            {move || {
                if signed_in.get() {
                    view! {
                        <div>
                            <p>"Signed in ✓"</p>
                            <ul>
                                {move || {
                                    servers
                                        .get()
                                        .into_iter()
                                        .map(|s| {
                                            let label = format!("{}, {}", s.city, s.country);
                                            let pick_id = s.id.clone();
                                            view! {
                                                <li>
                                                    {label} " "
                                                    <button on:click=move |_| {
                                                        set_picked.set(Some(pick_id.clone()));
                                                    }>"Pick"</button>
                                                </li>
                                            }
                                        })
                                        .collect::<Vec<_>>()
                                }}
                            </ul>
                            {move || {
                                picked
                                    .get()
                                    .map(|id| view! { <p>"Picked: " {id}</p> }.into_any())
                                    .unwrap_or_else(|| ().into_any())
                            }}
                            <button on:click=toggle_vpn>
                                {move || if connected.get() { "Disconnect" } else { "Connect" }}
                            </button>
                            <p>{move || vpn_line.get()}</p>
                            {move || {
                                vpn_error
                                    .get()
                                    .map(|e| view! { <p class="error">{e}</p> }.into_any())
                                    .unwrap_or_else(|| ().into_any())
                            }}
                            {move || {
                                servers_error
                                    .get()
                                    .map(|e| view! { <p class="error">{e}</p> }.into_any())
                                    .unwrap_or_else(|| ().into_any())
                            }}
                            <button on:click=sign_out>"Sign out"</button>
                        </div>
                    }
                        .into_any()
                } else if needs_verification.get() {
                    view! {
                        <div>
                            <h2>"Sign in with Firefox"</h2>
                            <p>"Enter the confirmation code sent to your email"</p>
                            <form class="signin" on:submit=verify>
                                <input
                                    type="text"
                                    placeholder="Confirmation code"
                                    inputmode="numeric"
                                    autocomplete="one-time-code"
                                    prop:value=move || code.get()
                                    on:input=move |ev| set_code.set(event_target_value(&ev))
                                />
                                <button type="submit">"Verify"</button>
                            </form>
                            {move || {
                                auth_error
                                    .get()
                                    .map(|e| view! { <p class="error">{e}</p> }.into_any())
                                    .unwrap_or_else(|| ().into_any())
                            }}
                        </div>
                    }
                        .into_any()
                } else {
                    view! {
                        <div>
                            <h2>"Sign in with Firefox"</h2>
                            <form class="signin" on:submit=sign_in>
                                <input
                                    type="email"
                                    placeholder="Firefox account email"
                                    autocomplete="username"
                                    prop:value=move || email.get()
                                    on:input=move |ev| set_email.set(event_target_value(&ev))
                                />
                                <input
                                    type="password"
                                    placeholder="Password"
                                    autocomplete="current-password"
                                    prop:value=move || password.get()
                                    on:input=move |ev| set_password.set(event_target_value(&ev))
                                />
                                <button type="submit">"Continue"</button>
                            </form>
                            {move || {
                                auth_error
                                    .get()
                                    .map(|e| view! { <p class="error">{e}</p> }.into_any())
                                    .unwrap_or_else(|| ().into_any())
                            }}
                        </div>
                    }
                        .into_any()
                }
            }}
            <p>{move || status.get()}</p>
        </main>
    }
}
