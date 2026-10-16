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
}

#[derive(Serialize)]
struct ConnectArgs {
    server: String,
}

fn describe_vpn(status: &VpnStatus) -> (bool, String, Option<String>) {
    let up = status.state == "Connected";
    let line = if up {
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

    let sign_in = move |_| {
        // Immediate feedback (AC12); the signed-in home arrives via `auth-changed`.
        set_status.set(String::from("Opening system browser…"));
        spawn_local(async move {
            let msg = invoke("auth_sign_in", JsValue::UNDEFINED)
                .await
                .as_string()
                .unwrap_or_default();
            if !msg.is_empty() {
                set_status.set(msg);
            }
        });
    };
    let sign_out = move |_| {
        spawn_local(async move {
            invoke("auth_sign_out", JsValue::UNDEFINED).await;
        });
    };

    // Task 4: one toggle button (repeat connect = backend no-op, AC6); every
    // press updates the status or error line immediately (AC12).
    let toggle_vpn = move |_| {
        set_vpn_error.set(None);
        if connected.get_untracked() {
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
                } else {
                    view! {
                        <div>
                            <button on:click=sign_in>"Sign in with Firefox"</button>
                        </div>
                    }
                        .into_any()
                }
            }}
            <p>{move || status.get()}</p>
        </main>
    }
}
