//! Tauri Command Handlers

use crate::state::{AppState, StoredChat, StoredContact, StoredIdentity, StoredMessage};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

#[tauri::command]
pub fn ping() -> Result<String, String> {
    Ok("pong".to_string())
}

#[tauri::command]
pub fn get_version() -> Result<String, String> {
    Ok(env!("CARGO_PKG_VERSION").to_string())
}

#[tauri::command]
pub fn create_identity(state: State<AppState>) -> Result<IdentityResponse, String> {
    let timestamp = now();
    let fingerprint = format!("sg-{timestamp:08x}");
    let qr_data = format!("shadowgram://identity/{fingerprint}");

    let identity = StoredIdentity {
        fingerprint: fingerprint.clone(),
        qr_data: qr_data.clone(),
    };

    *state.identity.lock() = Some(identity);

    Ok(IdentityResponse {
        fingerprint,
        qr_data,
    })
}

#[tauri::command]
pub fn get_identity(state: State<AppState>) -> Result<Option<IdentityResponse>, String> {
    Ok(state.identity.lock().clone().map(|identity| IdentityResponse {
        fingerprint: identity.fingerprint,
        qr_data: identity.qr_data,
    }))
}

#[tauri::command]
pub fn export_identity_qr(state: State<AppState>) -> Result<String, String> {
    let identity = state.identity.lock();
    let Some(identity) = identity.as_ref() else {
        return Err("Identity not created".to_string());
    };

    Ok(identity.qr_data.clone())
}

#[tauri::command]
pub fn scan_identity_qr(image_data: String, _state: State<AppState>) -> Result<ScannedIdentity, String> {
    let fingerprint = image_data
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown-contact")
        .to_string();

    Ok(ScannedIdentity {
        display_id: fingerprint.chars().take(8).collect(),
        fingerprint,
        verified: false,
    })
}

#[tauri::command]
pub fn add_contact(
    fingerprint: String,
    alias: String,
    state: State<AppState>,
) -> Result<bool, String> {
    if fingerprint.trim().is_empty() {
        return Err("Fingerprint is required".to_string());
    }

    if alias.trim().is_empty() {
        return Err("Alias is required".to_string());
    }

    let mut contacts = state.contacts.lock();
    if let Some(existing) = contacts.iter_mut().find(|contact| contact.fingerprint == fingerprint) {
        existing.alias = alias;
        return Ok(true);
    }

    contacts.push(StoredContact {
        fingerprint,
        alias,
        trust_level: 0,
    });

    Ok(true)
}

#[tauri::command]
pub fn get_contacts(state: State<AppState>) -> Result<Vec<ContactEntry>, String> {
    Ok(state
        .contacts
        .lock()
        .iter()
        .cloned()
        .map(|contact| ContactEntry {
            alias: contact.alias,
            fingerprint: contact.fingerprint,
            trust_level: contact.trust_level,
        })
        .collect())
}

#[tauri::command]
pub fn create_chat(contact_fingerprint: String, state: State<AppState>) -> Result<ChatInfo, String> {
    if state
        .contacts
        .lock()
        .iter()
        .all(|contact| contact.fingerprint != contact_fingerprint)
    {
        return Err("Contact not found".to_string());
    }

    let mut chats = state.chats.lock();
    if let Some(existing) = chats
        .iter()
        .find(|chat| chat.contact_fingerprint == contact_fingerprint)
        .cloned()
    {
        return Ok(ChatInfo {
            id: existing.id,
            contact_fingerprint: existing.contact_fingerprint,
            created_at: existing.created_at,
        });
    }

    let chat = StoredChat {
        id: format!("chat-{}", now()),
        contact_fingerprint,
        created_at: now(),
    };

    let response = ChatInfo {
        id: chat.id.clone(),
        contact_fingerprint: chat.contact_fingerprint.clone(),
        created_at: chat.created_at,
    };

    chats.push(chat);
    Ok(response)
}

#[tauri::command]
pub fn get_chats(state: State<AppState>) -> Result<Vec<ChatInfo>, String> {
    Ok(state
        .chats
        .lock()
        .iter()
        .cloned()
        .map(|chat| ChatInfo {
            id: chat.id,
            contact_fingerprint: chat.contact_fingerprint,
            created_at: chat.created_at,
        })
        .collect())
}

#[tauri::command]
pub fn send_message(chat_id: String, content: String, state: State<AppState>) -> Result<MessageResponse, String> {
    if content.trim().is_empty() {
        return Err("Message content is required".to_string());
    }

    let chat_exists = state.chats.lock().iter().any(|chat| chat.id == chat_id);
    if !chat_exists {
        return Err("Chat not found".to_string());
    }

    let timestamp = now();
    let message_id = format!("msg-{timestamp}");

    let message = StoredMessage {
        id: message_id.clone(),
        content,
        direction: "outgoing".to_string(),
        timestamp,
        status: "sent".to_string(),
    };

    state
        .messages
        .lock()
        .entry(chat_id)
        .or_default()
        .push(message);

    Ok(MessageResponse {
        message_id,
        status: "sent".to_string(),
        timestamp,
    })
}

#[tauri::command]
pub fn get_messages(
    chat_id: String,
    limit: i32,
    offset: i32,
    state: State<AppState>,
) -> Result<Vec<MessageEntry>, String> {
    let limit = limit.max(1) as usize;
    let offset = offset.max(0) as usize;

    let messages = state.messages.lock();
    let chat_messages = messages.get(&chat_id).cloned().unwrap_or_default();

    Ok(chat_messages
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|message| MessageEntry {
            id: message.id,
            content: message.content,
            direction: message.direction,
            timestamp: message.timestamp,
            status: message.status,
        })
        .collect())
}

#[tauri::command]
pub fn start_client(state: State<AppState>) -> Result<bool, String> {
    *state.client_running.lock() = true;
    Ok(true)
}

#[tauri::command]
pub fn stop_client(state: State<AppState>) -> Result<bool, String> {
    *state.client_running.lock() = false;
    Ok(true)
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct IdentityResponse {
    pub fingerprint: String,
    pub qr_data: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ScannedIdentity {
    pub fingerprint: String,
    pub display_id: String,
    pub verified: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ContactEntry {
    pub fingerprint: String,
    pub alias: String,
    pub trust_level: u8,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ChatInfo {
    pub id: String,
    pub contact_fingerprint: String,
    pub created_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct MessageResponse {
    pub message_id: String,
    pub status: String,
    pub timestamp: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct MessageEntry {
    pub id: String,
    pub content: String,
    pub direction: String,
    pub timestamp: u64,
    pub status: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
