//! Shadowgram Tauri Backend
//!
//! IPC bridge between React frontend and Rust core.

mod commands;
mod state;

pub use commands::*;
pub use state::*;

use shadowgram_messenger::Client;
use tauri::{
    Manager,
    generate_handler,
    generate_context,
};

/// Run the Shadowgram Tauri application
pub fn run() {
    println!("Starting Shadowgram v{}", env!("CARGO_PKG_VERSION"));

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // Initialize app state
            let app_state = AppState::new()?;
            app.manage(app_state);

            println!("Shadowgram initialized successfully");
            Ok(())
        })
        .invoke_handler(generate_handler![
            commands::ping,
            commands::get_version,
            commands::create_identity,
            commands::get_identity,
            commands::export_identity_qr,
            commands::scan_identity_qr,
            commands::add_contact,
            commands::get_contacts,
            commands::create_chat,
            commands::send_message,
            commands::get_messages,
            commands::start_client,
            commands::stop_client,
        ])
        .run(generate_context!())
        .expect("error while running Shadowgram");
}