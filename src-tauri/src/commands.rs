//! Tauri command handlers backed by the durable profile store.

use crate::profile::{
    invite_to_string, now, now_nanos, parse_invite, ContactEndpoint, DiagnosticEntry, StoredMessage,
};
use crate::state::{AppState, TorCommand, TorStatus};
use crate::tor_manager;
use crate::transport;
use tauri::{AppHandle, State};

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
    let endpoint = current_endpoint(&state);
    let identity = {
        let mut store = state.store.lock();
        store.ensure_identity(endpoint)?
    };
    Ok(identity_response(identity))
}

#[tauri::command]
pub fn reset_identity(state: State<AppState>) -> Result<bool, String> {
    let mut store = state.store.lock();
    store.reset_identity()?;
    Ok(true)
}

#[tauri::command]
pub fn get_identity(state: State<AppState>) -> Result<Option<IdentityResponse>, String> {
    let store = state.store.lock();
    Ok(store.data().identity.clone().map(identity_response))
}

#[tauri::command]
pub fn export_identity_qr(state: State<AppState>) -> Result<String, String> {
    let store = state.store.lock();
    let identity = store
        .data()
        .identity
        .clone()
        .ok_or_else(|| "Identity not created".to_string())?;
    Ok(identity.invite_payload)
}

#[tauri::command]
pub fn scan_identity_qr(image_data: String) -> Result<ScannedIdentity, String> {
    let invite = parse_invite(&image_data)?;
    Ok(ScannedIdentity {
        fingerprint: invite.fingerprint.clone(),
        display_id: invite.fingerprint.chars().take(12).collect(),
        invite_payload: image_data,
        verified: invite.endpoint.is_some(),
    })
}

#[tauri::command]
pub fn add_contact(
    fingerprint: String,
    alias: String,
    state: State<AppState>,
) -> Result<ContactEntry, String> {
    let parsed = parse_invite(&fingerprint)?;
    let invite_payload = if fingerprint.trim().starts_with("shadowgram://invite/")
        || fingerprint.trim().starts_with('{')
    {
        fingerprint
    } else {
        invite_to_string(&parsed)?
    };
    let contact = {
        let mut store = state.store.lock();
        store.upsert_contact(alias, invite_payload, parsed)?
    };
    Ok(contact_entry(contact))
}

#[tauri::command]
pub fn update_contact(
    existing_fingerprint: String,
    alias: String,
    new_fingerprint: String,
    state: State<AppState>,
) -> Result<ContactEntry, String> {
    let parsed = parse_invite(&new_fingerprint)?;
    let invite_payload = if new_fingerprint.trim().starts_with("shadowgram://invite/")
        || new_fingerprint.trim().starts_with('{')
    {
        new_fingerprint
    } else {
        invite_to_string(&parsed)?
    };
    let mut store = state.store.lock();
    let original = store
        .data()
        .contacts
        .iter()
        .find(|contact| contact.fingerprint == existing_fingerprint)
        .cloned()
        .ok_or_else(|| "Contact not found".to_string())?;
    let mut updated = store.upsert_contact(alias, invite_payload, parsed)?;
    if updated.fingerprint != original.fingerprint {
        if let Some(contact) = store
            .data_mut()
            .contacts
            .iter_mut()
            .find(|contact| contact.id == original.id)
        {
            contact
                .previous_fingerprints
                .push(original.fingerprint.clone());
            updated.previous_fingerprints = contact.previous_fingerprints.clone();
        }
        for chat in store.data_mut().chats.iter_mut() {
            if chat.contact_fingerprint == original.fingerprint {
                // Keep stale route until explicit refresh.
            }
        }
        store.push_diag(DiagnosticEntry::warn(
            "contact.rotated",
            format!(
                "Contact {} rotated from {} to {}",
                updated.alias, original.fingerprint, updated.fingerprint
            ),
        ));
        store.save()?;
    }
    Ok(contact_entry(updated))
}

#[tauri::command]
pub fn get_contacts(state: State<AppState>) -> Result<Vec<ContactEntry>, String> {
    let store = state.store.lock();
    Ok(store
        .data()
        .contacts
        .clone()
        .into_iter()
        .map(contact_entry)
        .collect())
}

#[tauri::command]
pub fn create_chat(
    contact_fingerprint: String,
    state: State<AppState>,
) -> Result<ChatInfo, String> {
    let mut store = state.store.lock();
    Ok(chat_entry(store.create_chat(contact_fingerprint.trim())?))
}

#[tauri::command]
pub fn refresh_chat_destination(
    chat_id: String,
    state: State<AppState>,
) -> Result<ChatInfo, String> {
    let mut store = state.store.lock();
    let chat = store
        .data()
        .chats
        .iter()
        .find(|chat| chat.id == chat_id)
        .cloned()
        .ok_or_else(|| "Chat not found".to_string())?;
    let contact = store
        .data()
        .contacts
        .iter()
        .find(|contact| {
            contact
                .previous_fingerprints
                .iter()
                .any(|previous| previous == &chat.contact_fingerprint)
        })
        .cloned()
        .ok_or_else(|| "No updated fingerprint is known for this chat".to_string())?;

    if let Some(existing) = store
        .data_mut()
        .chats
        .iter_mut()
        .find(|existing| existing.id == chat_id)
    {
        existing.contact_fingerprint = contact.fingerprint.clone();
    }
    store.append_message(
        &chat.id,
        StoredMessage {
            id: format!("msg-{}", now_nanos()),
            content: format!(
                "Chat destination refreshed from {} to {}. Prior history remains immutable.",
                chat.contact_fingerprint, contact.fingerprint
            ),
            direction: "system".to_string(),
            timestamp: now(),
            status: "refreshed".to_string(),
            error: None,
            destination_fingerprint: contact.fingerprint.clone(),
            immutable: true,
            delivered_at: Some(now()),
            retry_count: 0,
        },
    )?;
    let refreshed = store
        .data()
        .chats
        .iter()
        .find(|existing| existing.id == chat.id)
        .cloned()
        .ok_or_else(|| "Chat not found".to_string())?;
    Ok(chat_entry(refreshed))
}

#[tauri::command]
pub fn get_chats(state: State<AppState>) -> Result<Vec<ChatInfo>, String> {
    let store = state.store.lock();
    Ok(store
        .data()
        .chats
        .clone()
        .into_iter()
        .map(chat_entry)
        .collect())
}

#[tauri::command]
pub fn get_messages(
    chat_id: String,
    limit: i32,
    offset: i32,
    state: State<AppState>,
) -> Result<Vec<MessageEntry>, String> {
    let store = state.store.lock();
    let limit = limit.max(1) as usize;
    let offset = offset.max(0) as usize;
    Ok(store
        .messages_for_chat(&chat_id)
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(message_entry)
        .collect())
}

#[tauri::command]
pub fn get_diagnostics(state: State<AppState>) -> Result<Vec<DiagnosticResponse>, String> {
    let store = state.store.lock();
    Ok(store
        .diagnostics()
        .into_iter()
        .map(diagnostic_entry)
        .collect())
}

#[tauri::command]
pub fn send_message(
    chat_id: String,
    content: String,
    state: State<AppState>,
) -> Result<MessageResponse, String> {
    let content = content.trim().to_string();
    if content.is_empty() {
        return Err("Message content is required".to_string());
    }

    let (destination_fingerprint, dest_onion) = {
        let store = state.store.lock();
        let chat = store
            .data()
            .chats
            .iter()
            .find(|chat| chat.id == chat_id)
            .cloned()
            .ok_or_else(|| "Chat not found".to_string())?;
        let contact = store
            .data()
            .contacts
            .iter()
            .find(|c| c.fingerprint == chat.contact_fingerprint)
            .cloned()
            .ok_or_else(|| "Contact not found for chat".to_string())?;
        (chat.contact_fingerprint, contact.onion)
    };

    let message = StoredMessage {
        id: format!("msg-{}", now_nanos()),
        content: content.clone(),
        direction: "outgoing".to_string(),
        timestamp: now(),
        status: "queued".to_string(),
        error: None,
        destination_fingerprint,
        immutable: true,
        delivered_at: None,
        retry_count: 0,
    };

    {
        let mut store = state.store.lock();
        store.append_message(&chat_id, message.clone())?;
        store.push_diag(DiagnosticEntry::info(
            "message.queued",
            format!("Queued message {} for durable delivery", message.id),
        ));
        store.save()?;
    }

    // If Tor is running and we have a destination onion address, dispatch the
    // send via the async Tor manager.  Otherwise fall through to the legacy
    // plaintext transport so LAN testing still works.
    let tor_dispatched = if let (Some(onion), Some(tx)) =
        (dest_onion, state.tor_tx.lock().clone())
    {
        tx.try_send(TorCommand::SendMessage {
            chat_id: chat_id.clone(),
            message_id: message.id.clone(),
            content,
            dest_onion: onion,
        })
        .is_ok()
    } else {
        false
    };

    if !tor_dispatched {
        // Legacy path — still useful for same-LAN testing without Tor.
        let _ = transport::attempt_delivery(&state.store, &chat_id, &message);
    }

    let status = {
        let store = state.store.lock();
        store
            .messages_for_chat(&chat_id)
            .into_iter()
            .find(|entry| entry.id == message.id)
            .map(|entry| entry.status)
            .unwrap_or_else(|| "queued".to_string())
    };

    Ok(MessageResponse {
        message_id: message.id,
        status,
        timestamp: message.timestamp,
        error: None,
    })
}

/// Start the Tor transport (bootstrap Arti + launch onion service).
/// The first call spawns the async manager; subsequent calls are no-ops.
#[tauri::command]
pub fn start_client(state: State<AppState>, app: AppHandle) -> Result<bool, String> {
    // Guard: don't spawn twice.
    if state.tor_tx.lock().is_some() {
        return Ok(true);
    }

    let profile_dir = {
        let s = state.store.lock();
        s.profile_dir().to_path_buf()
    };

    let store = state.store.clone();
    let tor_status = state.tor_status.clone();

    let tx = state.runtime.block_on(async {
        tor_manager::spawn(&profile_dir, store, tor_status, app).await
    });

    *state.tor_tx.lock() = Some(tx);
    *state.client_running.lock() = true;
    Ok(true)
}

#[tauri::command]
pub fn stop_client(state: State<AppState>) -> Result<bool, String> {
    *state.tor_tx.lock() = None;
    transport::stop_listener(state)?;
    Ok(true)
}

/// Return the current Tor bootstrap / onion-service status.
#[tauri::command]
pub fn get_tor_status(state: State<AppState>) -> Result<TorStatus, String> {
    Ok(state.tor_status.lock().clone())
}

fn current_endpoint(_state: &State<AppState>) -> Option<ContactEndpoint> {
    // No longer used — the onion address is the canonical endpoint now.
    None
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct IdentityResponse {
    pub fingerprint: String,
    pub fingerprint_full: String,
    pub qr_data: String,
    pub invite_payload: String,
    pub generation: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ScannedIdentity {
    pub fingerprint: String,
    pub display_id: String,
    pub invite_payload: String,
    pub verified: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ContactEntry {
    pub id: String,
    pub fingerprint: String,
    pub alias: String,
    pub trust_level: u8,
    pub status: String,
    pub invite_payload: String,
    pub previous_fingerprints: Vec<String>,
    pub endpoint: Option<ContactEndpoint>,
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
    pub delivered_at: Option<u64>,
    pub retry_count: u32,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct DiagnosticResponse {
    pub level: String,
    pub stage: String,
    pub message: String,
    pub timestamp: u64,
}

fn identity_response(identity: crate::profile::StoredIdentity) -> IdentityResponse {
    IdentityResponse {
        fingerprint: identity.fingerprint,
        fingerprint_full: identity.fingerprint_full,
        qr_data: identity.invite_payload.clone(),
        invite_payload: identity.invite_payload,
        generation: identity.generation,
        created_at: identity.created_at,
        updated_at: identity.updated_at,
    }
}

fn contact_entry(contact: crate::profile::StoredContact) -> ContactEntry {
    ContactEntry {
        id: contact.id,
        fingerprint: contact.fingerprint,
        alias: contact.alias,
        trust_level: 1,
        status: contact.status,
        invite_payload: contact.invite_payload,
        previous_fingerprints: contact.previous_fingerprints,
        endpoint: contact.endpoint,
        updated_at: contact.updated_at,
    }
}

fn chat_entry(chat: crate::profile::StoredChat) -> ChatInfo {
    ChatInfo {
        id: chat.id,
        contact_fingerprint: chat.contact_fingerprint,
        created_at: chat.created_at,
        immutable_history: chat.immutable_history,
    }
}

fn message_entry(message: StoredMessage) -> MessageEntry {
    MessageEntry {
        id: message.id,
        content: message.content,
        direction: message.direction,
        timestamp: message.timestamp,
        status: message.status,
        error: message.error,
        destination_fingerprint: message.destination_fingerprint,
        immutable: message.immutable,
        delivered_at: message.delivered_at,
        retry_count: message.retry_count,
    }
}

fn diagnostic_entry(entry: DiagnosticEntry) -> DiagnosticResponse {
    DiagnosticResponse {
        level: entry.level,
        stage: entry.stage,
        message: entry.message,
        timestamp: entry.timestamp,
    }
}
