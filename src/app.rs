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

#[derive(Deserialize)]
struct TauriEvent {
    payload: AuthChanged,
}

#[component]
pub fn App() -> impl IntoView {
    let (signed_in, set_signed_in) = signal(false);
    let (status, set_status) = signal(String::from("Signed out."));

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

    view! {
        <main class="container">
            <h1>"FoxyVPN"</h1>
            {move || {
                if signed_in.get() {
                    view! {
                        <div>
                            <p>"Signed in ✓"</p>
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
