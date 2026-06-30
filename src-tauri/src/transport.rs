//! Lightweight local/LAN validation transport for the Tauri shell.

use crate::profile::{now, now_nanos, ContactEndpoint, ProfileStore, StoredMessage};
use crate::state::AppState;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tauri::State;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryRequest {
    pub sender_fingerprint: String,
    pub sender_invite: String,
    pub recipient_fingerprint: String,
    pub chat_id: String,
    pub message_id: String,
    pub content: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryResponse {
    pub accepted: bool,
    pub error: Option<String>,
}

pub fn start_listener(state: State<AppState>) -> Result<u16, String> {
    if *state.client_running.lock() {
        return Ok((*state.listener_port.lock()).unwrap_or(0));
    }

    let listener = bind_listener()?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    *state.client_running.lock() = true;
    *state.listener_port.lock() = Some(port);

    {
        let mut store = state.store.lock();
        let endpoint = Some(ContactEndpoint {
            host: advertised_host(),
            port,
        });
        store.update_identity_endpoint(endpoint)?;
        store.push_diag(crate::profile::DiagnosticEntry::info(
            "transport.online",
            format!("Listening for deliveries on port {}", port),
        ));
        store.save()?;
    }

    let store = state.store.clone();
    let running = state.client_running.clone();
    thread::spawn(move || {
        for incoming in listener.incoming() {
            if !*running.lock() {
                break;
            }
            let Ok(mut stream) = incoming else {
                continue;
            };
            let _ = handle_connection(&mut stream, &store);
        }
    });

    let retry_store = state.store.clone();
    let retry_running = state.client_running.clone();
    thread::spawn(move || {
        while *retry_running.lock() {
            retry_pending(&retry_store);
            thread::sleep(Duration::from_secs(5));
        }
    });

    Ok(port)
}

pub fn stop_listener(state: State<AppState>) -> Result<bool, String> {
    *state.client_running.lock() = false;
    Ok(true)
}

pub fn attempt_delivery(
    store: &Arc<Mutex<ProfileStore>>,
    chat_id: &str,
    message: &StoredMessage,
) -> Result<(), String> {
    let (endpoint, sender_invite, sender_fingerprint) = {
        let store_guard = store.lock();
        let chat = store_guard
            .data()
            .chats
            .iter()
            .find(|chat| chat.id == chat_id)
            .cloned()
            .ok_or_else(|| "Chat not found".to_string())?;
        let contact = store_guard
            .data()
            .contacts
            .iter()
            .find(|contact| contact.fingerprint == chat.contact_fingerprint)
            .cloned()
            .ok_or_else(|| "Contact not found".to_string())?;
        let identity = store_guard
            .data()
            .identity
            .clone()
            .ok_or_else(|| "Identity not created".to_string())?;
        (
            contact.endpoint,
            identity.invite_payload,
            identity.fingerprint,
        )
    };

    let Some(endpoint) = endpoint else {
        let mut store_guard = store.lock();
        store_guard.update_message_status(
            chat_id,
            &message.id,
            "queued".to_string(),
            Some("Recipient has no reachable endpoint in the invite payload".to_string()),
            None,
            message.retry_count + 1,
        )?;
        store_guard.push_diag(crate::profile::DiagnosticEntry::warn(
            "message.queued",
            format!(
                "Queued message {} because the contact has no route",
                message.id
            ),
        ));
        store_guard.save()?;
        return Err("Recipient not reachable".to_string());
    };

    let request = DeliveryRequest {
        sender_fingerprint,
        sender_invite,
        recipient_fingerprint: message.destination_fingerprint.clone(),
        chat_id: chat_id.to_string(),
        message_id: message.id.clone(),
        content: message.content.clone(),
        timestamp: message.timestamp,
    };

    let address = format!("{}:{}", endpoint.host, endpoint.port);
    match send_request(&address, &request) {
        Ok(response) if response.accepted => {
            let mut store_guard = store.lock();
            store_guard.update_message_status(
                chat_id,
                &message.id,
                "delivered".to_string(),
                None,
                Some(now()),
                message.retry_count,
            )?;
            store_guard.push_diag(crate::profile::DiagnosticEntry::info(
                "message.delivered",
                format!("Delivered message {} to {}", message.id, address),
            ));
            store_guard.save()?;
            Ok(())
        }
        Ok(response) => {
            let error = response
                .error
                .unwrap_or_else(|| "Recipient not reachable".to_string());
            let mut store_guard = store.lock();
            store_guard.update_message_status(
                chat_id,
                &message.id,
                "failed".to_string(),
                Some(error.clone()),
                None,
                message.retry_count + 1,
            )?;
            store_guard.push_diag(crate::profile::DiagnosticEntry::warn(
                "message.failed",
                format!("Message {} failed: {}", message.id, error),
            ));
            store_guard.save()?;
            Err(error)
        }
        Err(error) => {
            let mut store_guard = store.lock();
            store_guard.update_message_status(
                chat_id,
                &message.id,
                "queued".to_string(),
                Some(error.clone()),
                None,
                message.retry_count + 1,
            )?;
            store_guard.push_diag(crate::profile::DiagnosticEntry::warn(
                "message.queued",
                format!("Queued message {}: {}", message.id, error),
            ));
            store_guard.save()?;
            Err(error)
        }
    }
}

fn retry_pending(store: &Arc<Mutex<ProfileStore>>) {
    let pending = {
        let store_guard = store.lock();
        store_guard.pending_outbound()
    };

    for (chat_id, message) in pending {
        let _ = attempt_delivery(store, &chat_id, &message);
    }
}

fn handle_connection(
    stream: &mut TcpStream,
    store: &Arc<Mutex<ProfileStore>>,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    let request: DeliveryRequest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;

    let response = {
        let mut store_guard = store.lock();
        let identity = store_guard
            .data()
            .identity
            .clone()
            .ok_or_else(|| "Identity not created".to_string())?;

        if identity.fingerprint != request.recipient_fingerprint {
            DeliveryResponse {
                accepted: false,
                error: Some(format!(
                    "Recipient not found: {}",
                    request.recipient_fingerprint
                )),
            }
        } else {
            let sender_invite = crate::profile::parse_invite(&request.sender_invite)?;
            let sender_contact = store_guard.upsert_contact(
                sender_invite.fingerprint.clone(),
                request.sender_invite.clone(),
                sender_invite.clone(),
            )?;
            let chat = store_guard.create_chat(&sender_contact.fingerprint)?;
            store_guard.append_message(
                &chat.id,
                StoredMessage {
                    id: format!("msg-{}", now_nanos()),
                    content: request.content.clone(),
                    direction: "incoming".to_string(),
                    timestamp: request.timestamp,
                    status: "delivered".to_string(),
                    error: None,
                    destination_fingerprint: identity.fingerprint.clone(),
                    immutable: true,
                    delivered_at: Some(now()),
                    retry_count: 0,
                },
            )?;
            store_guard.push_diag(crate::profile::DiagnosticEntry::info(
                "message.received",
                format!("Received message from {}", request.sender_fingerprint),
            ));
            store_guard.save()?;
            DeliveryResponse {
                accepted: true,
                error: None,
            }
        }
    };

    let payload = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
    stream.write_all(&payload).map_err(|e| e.to_string())?;
    Ok(())
}

fn send_request(address: &str, request: &DeliveryRequest) -> Result<DeliveryResponse, String> {
    let mut stream = TcpStream::connect(address).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let payload = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    stream.write_all(&payload).map_err(|e| e.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&response).map_err(|e| e.to_string())
}

fn bind_listener() -> Result<TcpListener, String> {
    for port in 41000..41100 {
        if let Ok(listener) = TcpListener::bind(("0.0.0.0", port)) {
            listener.set_nonblocking(false).map_err(|e| e.to_string())?;
            return Ok(listener);
        }
    }
    Err("No free local listener port found".to_string())
}

fn advertised_host() -> String {
    std::env::var("SHADOWGRAM_ADVERTISE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{InvitePayload, ProfileStore};
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("shadowgram-transport-{name}-{}", now_nanos()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn loopback_delivery_acknowledges_missing_recipient() {
        let dir = temp_dir("missing");
        let store = Arc::new(Mutex::new(ProfileStore::load_or_init(dir).unwrap()));
        {
            let mut guard = store.lock();
            guard.ensure_identity(None).unwrap();
        }

        let listener = bind_listener().unwrap();
        let port = listener.local_addr().unwrap().port();
        let store_clone = store.clone();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = handle_connection(&mut stream, &store_clone);
            }
        });

        let response = send_request(
            &format!("127.0.0.1:{port}"),
            &DeliveryRequest {
                sender_fingerprint: "sender".to_string(),
                sender_invite: crate::profile::invite_to_string(&InvitePayload {
                    version: 1,
                    fingerprint: "sender".to_string(),
                    public_key_base64: String::new(),
                    endpoint: None,
                    onion: None,
                })
                .unwrap(),
                recipient_fingerprint: "wrong".to_string(),
                chat_id: "chat".to_string(),
                message_id: "msg".to_string(),
                content: "hello".to_string(),
                timestamp: now(),
            },
        )
        .unwrap();

        assert!(!response.accepted);
    }
}
