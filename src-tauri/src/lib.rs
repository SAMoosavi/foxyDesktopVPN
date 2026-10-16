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

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_status_is_disconnected() {
        assert_eq!(VpnStatus::default().state, VpnState::Disconnected);
    }
}
