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
    let mut identity = state.identity.lock();

    if let Some(existing) = identity.as_ref() {
        return Ok(identity_response(existing));
    }

    let timestamp = now();
    let stored = StoredIdentity {
        fingerprint: generate_fingerprint(),
        qr_data: String::new(),
        generation: 1,
        rotated_from: Vec::new(),
        created_at: timestamp,
        updated_at: timestamp,
    };

    let mut stored = stored;
    stored.qr_data = qr_payload(&stored.fingerprint);
    let response = identity_response(&stored);
    *identity = Some(stored);

    Ok(response)
}

#[tauri::command]
pub fn rotate_identity(state: State<AppState>) -> Result<IdentityResponse, String> {
    let mut identity = state.identity.lock();
    let Some(existing) = identity.as_mut() else {
        return Err("Create an identity before rotating it".to_string());
    };

    existing.rotated_from.push(existing.fingerprint.clone());
    existing.fingerprint = generate_fingerprint();
    existing.qr_data = qr_payload(&existing.fingerprint);
    existing.generation += 1;
    existing.updated_at = now();

    Ok(identity_response(existing))
}

#[tauri::command]
pub fn get_identity(state: State<AppState>) -> Result<Option<IdentityResponse>, String> {
    Ok(state.identity.lock().as_ref().map(identity_response))
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
        display_id: fingerprint.chars().take(12).collect(),
        fingerprint,
        verified: false,
    })
}

#[tauri::command]
pub fn add_contact(
    fingerprint: String,
    alias: String,
    state: State<AppState>,
) -> Result<ContactEntry, String> {
    let fingerprint = normalized(&fingerprint);
    let alias = normalized(&alias);

    if fingerprint.is_empty() {
        return Err("Fingerprint is required".to_string());
    }

    if alias.is_empty() {
        return Err("Alias is required".to_string());
    }

    if own_fingerprint(&state).as_deref() == Some(fingerprint.as_str()) {
        return Err("You cannot add your own fingerprint as a contact".to_string());
    }

    let mut contacts = state.contacts.lock();
    if let Some(existing) = contacts.iter_mut().find(|contact| contact.fingerprint == fingerprint) {
        existing.alias = alias;
        existing.status = "active".to_string();
        existing.updated_at = now();
        return Ok(contact_entry(existing));
    }

    let contact = StoredContact {
        id: format!("contact-{}", now_nanos()),
        fingerprint,
        alias,
        trust_level: 0,
        status: "active".to_string(),
        previous_fingerprints: Vec::new(),
        updated_at: now(),
    };

    let response = contact_entry(&contact);
    contacts.push(contact);
    Ok(response)
}

#[tauri::command]
pub fn update_contact(
    existing_fingerprint: String,
    alias: String,
    new_fingerprint: String,
    state: State<AppState>,
) -> Result<ContactEntry, String> {
    let existing_fingerprint = normalized(&existing_fingerprint);
    let alias = normalized(&alias);
    let new_fingerprint = normalized(&new_fingerprint);

    if existing_fingerprint.is_empty() {
        return Err("Existing fingerprint is required".to_string());
    }

    if alias.is_empty() {
        return Err("Alias is required".to_string());
    }

    if new_fingerprint.is_empty() {
        return Err("New fingerprint is required".to_string());
    }

    if own_fingerprint(&state).as_deref() == Some(new_fingerprint.as_str()) {
        return Err("You cannot replace a contact with your own fingerprint".to_string());
    }

    let mut contacts = state.contacts.lock();
    let Some(contact_index) = contacts.iter().position(|contact| {
        contact.fingerprint == existing_fingerprint
            || contact.previous_fingerprints.iter().any(|value| value == &existing_fingerprint)
    }) else {
        return Err("Contact not found".to_string());
    };

    if contacts.iter().enumerate().any(|(index, contact)| {
        index != contact_index && contact.fingerprint == new_fingerprint
    }) {
        return Err("Another contact already uses that fingerprint".to_string());
    }

    let contact = &mut contacts[contact_index];
    if new_fingerprint != contact.fingerprint {
        let previous = contact.fingerprint.clone();
        if !contact.previous_fingerprints.iter().any(|value| value == &previous) {
            contact.previous_fingerprints.push(previous);
        }
        contact.fingerprint = new_fingerprint;
    }

    contact.alias = alias;
    contact.status = "active".to_string();
    contact.updated_at = now();

    Ok(contact_entry(contact))
}

#[tauri::command]
pub fn get_contacts(state: State<AppState>) -> Result<Vec<ContactEntry>, String> {
    Ok(state
        .contacts
        .lock()
        .iter()
        .cloned()
        .map(|contact| ContactEntry {
            id: contact.id,
            alias: contact.alias,
            fingerprint: contact.fingerprint,
            trust_level: contact.trust_level,
            status: contact.status,
            previous_fingerprints: contact.previous_fingerprints,
            updated_at: contact.updated_at,
        })
        .collect())
}

#[tauri::command]
pub fn create_chat(contact_fingerprint: String, state: State<AppState>) -> Result<ChatInfo, String> {
    let contact_fingerprint = normalized(&contact_fingerprint);
    let contact_exists = state
        .contacts
        .lock()
        .iter()
        .any(|contact| contact.fingerprint == contact_fingerprint);

    if !contact_exists {
        return Err("Contact not found".to_string());
    }

    let mut chats = state.chats.lock();
    if let Some(existing) = chats
        .iter()
        .find(|chat| chat.contact_fingerprint == contact_fingerprint)
        .cloned()
    {
        return Ok(chat_entry(&existing));
    }

    let chat = StoredChat {
        id: format!("chat-{}", now_nanos()),
        contact_fingerprint,
        created_at: now(),
        immutable_history: true,
    };

    let response = chat_entry(&chat);
    chats.push(chat);
    Ok(response)
}

#[tauri::command]
pub fn refresh_chat_destination(chat_id: String, state: State<AppState>) -> Result<ChatInfo, String> {
    let mut chats = state.chats.lock();
    let Some(chat) = chats.iter_mut().find(|chat| chat.id == chat_id) else {
        return Err("Chat not found".to_string());
    };

    let old_fingerprint = chat.contact_fingerprint.clone();
    let contacts = state.contacts.lock();
    let Some(contact) = contacts.iter().find(|contact| {
        contact
            .previous_fingerprints
            .iter()
            .any(|value| value == &old_fingerprint)
    }) else {
        return Err("No updated fingerprint is known for this chat".to_string());
    };

    if contact.fingerprint == old_fingerprint {
        return Ok(chat_entry(chat));
    }

    chat.contact_fingerprint = contact.fingerprint.clone();
    let refreshed = chat.clone();
    drop(chats);
    drop(contacts);

    append_system_message(
        &state,
        &refreshed.id,
        format!(
            "Destination refreshed from {} to {}. History remains immutable.",
            old_fingerprint, refreshed.contact_fingerprint
        ),
        "refreshed",
    );

    Ok(chat_entry(&refreshed))
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
            immutable_history: chat.immutable_history,
        })
        .collect())
}

#[tauri::command]
pub fn send_message(chat_id: String, content: String, state: State<AppState>) -> Result<MessageResponse, String> {
    let content = normalized(&content);
    if content.is_empty() {
        return Err("Message content is required".to_string());
    }

    let chat = {
        let chats = state.chats.lock();
        chats
            .iter()
            .find(|chat| chat.id == chat_id)
            .cloned()
            .ok_or_else(|| "Chat not found".to_string())?
    };

    let timestamp = now();
    let message_id = format!("msg-{}", now_nanos());
    let destination_fingerprint = chat.contact_fingerprint.clone();

    let (status, error) = {
        let contacts = state.contacts.lock();
        if contacts
            .iter()
            .any(|contact| contact.fingerprint == destination_fingerprint)
        {
            ("sent".to_string(), None)
        } else if let Some(contact) = contacts.iter().find(|contact| {
            contact
                .previous_fingerprints
                .iter()
                .any(|value| value == &destination_fingerprint)
        }) {
            (
                "failed".to_string(),
                Some(format!(
                    "User does not exist at {} anymore. {} now uses {}. Refresh the chat destination before sending again.",
                    destination_fingerprint, contact.alias, contact.fingerprint
                )),
            )
        } else {
            (
                "failed".to_string(),
                Some(format!(
                    "User does not exist at {}. Ask your contact for a current fingerprint.",
                    destination_fingerprint
                )),
            )
        }
    };

    let message = StoredMessage {
        id: message_id.clone(),
        content,
        direction: "outgoing".to_string(),
        timestamp,
        status: status.clone(),
        error: error.clone(),
        destination_fingerprint,
        immutable: true,
    };

    state
        .messages
        .lock()
        .entry(chat.id)
        .or_default()
        .push(message);

    Ok(MessageResponse {
        message_id,
        status,
        timestamp,
        error,
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
            error: message.error,
            destination_fingerprint: message.destination_fingerprint,
            immutable: message.immutable,
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
    pub generation: u32,
    pub rotated_from: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ScannedIdentity {
    pub fingerprint: String,
    pub display_id: String,
    pub verified: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ContactEntry {
    pub id: String,
    pub fingerprint: String,
    pub alias: String,
    pub trust_level: u8,
    pub status: String,
    pub previous_fingerprints: Vec<String>,
    pub updated_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ChatInfo {
    pub id: String,
    pub contact_fingerprint: String,
    pub created_at: u64,
    pub immutable_history: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct MessageResponse {
    pub message_id: String,
    pub status: String,
    pub timestamp: u64,
    pub error: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct MessageEntry {
    pub id: String,
    pub content: String,
    pub direction: String,
    pub timestamp: u64,
    pub status: String,
    pub error: Option<String>,
    pub destination_fingerprint: String,
    pub immutable: bool,
}

fn append_system_message(state: &State<AppState>, chat_id: &str, content: String, status: &str) {
    let timestamp = now();
    let message = StoredMessage {
        id: format!("msg-{}", now_nanos()),
        content,
        direction: "system".to_string(),
        timestamp,
        status: status.to_string(),
        error: None,
        destination_fingerprint: "system".to_string(),
        immutable: true,
    };

    state
        .messages
        .lock()
        .entry(chat_id.to_string())
        .or_default()
        .push(message);
}

fn own_fingerprint(state: &State<AppState>) -> Option<String> {
    state
        .identity
        .lock()
        .as_ref()
        .map(|identity| identity.fingerprint.clone())
}

fn identity_response(identity: &StoredIdentity) -> IdentityResponse {
    IdentityResponse {
        fingerprint: identity.fingerprint.clone(),
        qr_data: identity.qr_data.clone(),
        generation: identity.generation,
        rotated_from: identity.rotated_from.clone(),
        created_at: identity.created_at,
        updated_at: identity.updated_at,
    }
}

fn contact_entry(contact: &StoredContact) -> ContactEntry {
    ContactEntry {
        id: contact.id.clone(),
        fingerprint: contact.fingerprint.clone(),
        alias: contact.alias.clone(),
        trust_level: contact.trust_level,
        status: contact.status.clone(),
        previous_fingerprints: contact.previous_fingerprints.clone(),
        updated_at: contact.updated_at,
    }
}

fn chat_entry(chat: &StoredChat) -> ChatInfo {
    ChatInfo {
        id: chat.id.clone(),
        contact_fingerprint: chat.contact_fingerprint.clone(),
        created_at: chat.created_at,
        immutable_history: chat.immutable_history,
    }
}

fn normalized(value: &str) -> String {
    value.trim().to_string()
}

fn qr_payload(fingerprint: &str) -> String {
    format!("shadowgram://identity/{fingerprint}")
}

fn generate_fingerprint() -> String {
    format!("sg-{:x}", now_nanos())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
