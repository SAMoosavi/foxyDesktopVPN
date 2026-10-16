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
                                                        // Immediate feedback (AC12); connect lands in task 4.
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
