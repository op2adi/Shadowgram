//! Shadowgram Tauri Backend
//!
//! IPC bridge between React frontend and Rust core.

mod commands;
mod profile;
mod state;
mod transport;

use tauri::{generate_context, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    println!("Starting Shadowgram v{}", env!("CARGO_PKG_VERSION"));

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let profile_name =
                std::env::var("SHADOWGRAM_PROFILE").unwrap_or_else(|_| "default".to_string());
            let profile_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| e.to_string())?
                .join("profiles")
                .join(profile_name);
            let app_state = state::AppState::new(profile_dir)?;
            app.manage(app_state);

            println!("Shadowgram initialized successfully");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::ping,
            commands::get_version,
            commands::create_identity,
            commands::reset_identity,
            commands::get_identity,
            commands::export_identity_qr,
            commands::scan_identity_qr,
            commands::add_contact,
            commands::update_contact,
            commands::get_contacts,
            commands::create_chat,
            commands::refresh_chat_destination,
            commands::get_chats,
            commands::send_message,
            commands::get_messages,
            commands::get_diagnostics,
            commands::start_client,
            commands::stop_client,
        ])
        .run(generate_context!())
        .expect("error while running Shadowgram");
}
