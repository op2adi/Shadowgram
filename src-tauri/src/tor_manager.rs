//! Async Tor manager: bootstraps Arti, runs the onion service, and routes
//! messages through the `MessageTransport` trait.
//!
//! The manager lives on the tokio Runtime stored in `AppState` and receives
//! work via an `mpsc::Receiver<TorCommand>`.  Tauri commands remain
//! synchronous — they push a `TorCommand` and return immediately, letting
//! the manager handle delivery in the background.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use shadowgram_network::{
    decode_frame, DirectTorTransport, MessageTransport, MessageType, NetworkEnvelope,
    ShadowgramTor,
};
use parking_lot::Mutex;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing;

use crate::profile::{now, now_nanos, DiagnosticEntry, ProfileStore, StoredMessage};
use crate::state::{TorCommand, TorStatus};

const OUTBOX_RETRY_SECS: u64 = 30;

/// Spawn the Tor manager task on the current tokio runtime.
///
/// Must be called from within a tokio runtime context (e.g. inside
/// `runtime.block_on(async { ... })`).
/// Returns the `mpsc::Sender` side so Tauri commands can dispatch work.
pub async fn spawn(
    profile_dir: &Path,
    store: Arc<Mutex<ProfileStore>>,
    tor_status: Arc<Mutex<TorStatus>>,
    app_handle: AppHandle,
) -> mpsc::Sender<TorCommand> {
    let (tx, rx) = mpsc::channel::<TorCommand>(64);
    let profile_dir = profile_dir.to_path_buf();

    tokio::spawn(async move {
        if let Err(e) = run(profile_dir, store, tor_status, app_handle, rx).await {
            tracing::error!("Tor manager exited with error: {e}");
        }
    });

    tx
}

async fn run(
    profile_dir: std::path::PathBuf,
    store: Arc<Mutex<ProfileStore>>,
    tor_status: Arc<Mutex<TorStatus>>,
    app_handle: AppHandle,
    mut rx: mpsc::Receiver<TorCommand>,
) -> Result<(), String> {
    tracing::info!("Tor manager: bootstrapping Arti…");

    let (sg_tor, mut inbound_stream) = ShadowgramTor::start(&profile_dir)
        .await
        .map_err(|e| e.to_string())?;

    {
        let mut status = tor_status.lock();
        status.bootstrapped = true;
        status.onion_address = sg_tor.onion_address();
        status.error = None;
    }

    // Update our own invite payload with the new onion address.
    if let Some(onion) = sg_tor.onion_endpoint() {
        let mut s = store.lock();
        let _ = s.update_identity_onion(onion.clone());
        tracing::info!("Onion service ready: {onion}");
    }

    emit_tor_status(&app_handle, &tor_status);

    let transport = Arc::new(DirectTorTransport::new(sg_tor.clone()));

    // Spawn outbox retry loop.
    {
        let store2 = store.clone();
        let transport2 = transport.clone();
        let app2 = app_handle.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(OUTBOX_RETRY_SECS)).await;
                retry_pending(&store2, &transport2, &app2).await;
            }
        });
    }

    // Main select loop: handle commands OR inbound Tor streams.
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    TorCommand::SendMessage { chat_id, message_id, content, dest_onion } => {
                        handle_send(
                            &store, &transport, &app_handle,
                            chat_id, message_id, content, dest_onion,
                        ).await;
                    }
                    TorCommand::RetryPending => {
                        retry_pending(&store, &transport, &app_handle).await;
                    }
                }
            }
            stream_req = inbound_stream.next() => {
                let Some(req) = stream_req else { break };
                let store2 = store.clone();
                let app2 = app_handle.clone();
                tokio::spawn(async move {
                    handle_inbound(req, store2, app2).await;
                });
            }
        }
    }

    Ok(())
}

// ─── Outbound ────────────────────────────────────────────────────────────────

async fn handle_send(
    store: &Arc<Mutex<ProfileStore>>,
    transport: &Arc<DirectTorTransport>,
    app: &AppHandle,
    chat_id: String,
    message_id: String,
    content: String,
    dest_onion: String,
) {
    let envelope = NetworkEnvelope::new(MessageType::Message, content.as_bytes().to_vec());

    match transport.send(&dest_onion, &envelope).await {
        Ok(()) => {
            let mut s = store.lock();
            let _ = s.update_message_status(
                &chat_id, &message_id,
                "delivered".into(), None, Some(now()), 0,
            );
            let _ = s.save();
            let _ = app.emit("sg://message-received", ());
        }
        Err(e) => {
            let err = e.to_string();
            tracing::warn!("Send failed ({err}); message queued for retry");
            let mut s = store.lock();
            let _ = s.update_message_status(
                &chat_id, &message_id,
                "queued".into(), Some(err), None, 0,
            );
            let _ = s.save();
        }
    }
}

async fn retry_pending(
    store: &Arc<Mutex<ProfileStore>>,
    transport: &Arc<DirectTorTransport>,
    app: &AppHandle,
) {
    let pending = {
        let s = store.lock();
        s.pending_outbound()
    };

    for (chat_id, msg) in pending {
        // Resolve onion address for this message's destination.
        let onion = {
            let s = store.lock();
            s.data()
                .contacts
                .iter()
                .find(|c| c.fingerprint == msg.destination_fingerprint)
                .and_then(|c| c.onion.clone())
        };
        let Some(dest_onion) = onion else { continue };

        handle_send(
            store, transport, app,
            chat_id, msg.id.clone(), msg.content.clone(), dest_onion,
        )
        .await;
    }
}

// ─── Inbound ─────────────────────────────────────────────────────────────────

async fn handle_inbound(
    req: tor_hsservice::StreamRequest,
    store: Arc<Mutex<ProfileStore>>,
    app: AppHandle,
) {
    let mut stream = match ShadowgramTor::accept_stream(req).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Failed to accept inbound Tor stream: {e}");
            return;
        }
    };

    // Read until EOF, then decode the SGM1 frame.
    let mut buf = Vec::new();
    if let Err(e) = stream.read_to_end(&mut buf).await {
        tracing::warn!("Inbound stream read error: {e}");
        return;
    }

    let envelope = match decode_frame(&buf) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Bad frame from inbound stream: {e}");
            return;
        }
    };

    let content = match String::from_utf8(envelope.payload.clone()) {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("Inbound message payload is not UTF-8");
            return;
        }
    };

    // We don't know the sender's fingerprint from the Tor stream alone.
    // For now store under "unknown" — Phase F will wire in the signed prekey
    // handshake to authenticate the sender.
    let sender_fp = "unknown".to_string();

    let mut s = store.lock();
    let identity_fp = s
        .data()
        .identity
        .as_ref()
        .map(|i| i.fingerprint.clone())
        .unwrap_or_default();

    // Find or create chat.
    let chat_result = s.create_chat(&sender_fp);
    let chat_id = match chat_result {
        Ok(chat) => chat.id,
        Err(_) => {
            // Contact not yet known — store a diagnostic and drop.
            s.push_diag(DiagnosticEntry::warn(
                "message.unknown-sender",
                "Received message from unknown sender; add them as a contact first".into(),
            ));
            return;
        }
    };

    let msg = StoredMessage {
        id: format!("msg-{}", now_nanos()),
        content,
        direction: "incoming".into(),
        timestamp: now(),
        status: "delivered".into(),
        error: None,
        destination_fingerprint: identity_fp,
        immutable: true,
        delivered_at: Some(now()),
        retry_count: 0,
    };

    if s.append_message(&chat_id, msg).is_ok() {
        let _ = s.save();
        // Notify the frontend that new messages are available.
        let _ = app.emit("sg://message-received", ());
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn emit_tor_status(app: &AppHandle, status: &Arc<Mutex<TorStatus>>) {
    let s = status.lock().clone();
    let _ = app.emit("sg://tor-status", s);
}
