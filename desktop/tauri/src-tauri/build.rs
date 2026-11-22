/// App commands registered with `invoke_handler` in `src/main.rs`.
///
/// Declaring them in the app manifest makes Tauri check every app command
/// against the capabilities, like plugin commands. Without a manifest, Tauri
/// lets any page loaded in a window call them, whatever its origin.
///
/// tauri-build generates the permissions `allow-<command>` and
/// `deny-<command>` (underscores become dashes) for each entry. A command
/// that is missing here is denied, so keep this list, the handler in
/// `src/main.rs` and `capabilities/default.json` in sync.
const APP_COMMANDS: &[&str] = &[
    "get_app_info",
    "get_service_manager_status",
    "start_service",
    "get_state",
    "set_state",
    "should_show",
    "should_handle_prompts",
    "send_tauri_http_request",
    "open_dir",
];

fn main() {
    if let Err(error) = tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(APP_COMMANDS)),
    ) {
        panic!("tauri-build failed: {error:#}");
    }
}
