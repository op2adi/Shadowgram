//! Shadowgram client implementation.

use crate::{
    ChatSession, Contact, ContactDiscoveryPSI, ContactStore, DeviceInfo, DeviceSync, GroupChat,
    GroupEncryptedMessage, GroupInfo, GroupMember, MemberRole, MemoryContactStore, Message,
    MessageDirection, MessageStatus, PsiResult, SyncOperation,
};
use parking_lot::RwLock;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use shadowgram_crypto::{
    aead::AeadCipher,
    key_exchange::{HybridKeypair, HybridResponder, KeyExchangeMessage},
};
use shadowgram_identity::{Identity, PublicIdentity};
use shadowgram_network::{
    dht::DhtNode, mixnet::MixnetClient, tor::TorTransport, MessageType, NetworkEnvelope,
};
use shadowgram_storage::{Database, DbConfig, EncryptedCache};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct ClientConfig {
    pub storage_path: String,
    pub use_tor: bool,
    pub use_mixnet: bool,
    pub cover_traffic: bool,
    pub rotation_days: u64,
    pub max_message_size: usize,
    pub db_key: Option<[u8; 32]>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            storage_path: "./shadowgram_data".into(),
            use_tor: true,
            use_mixnet: false,
            cover_traffic: true,
            rotation_days: 30,
            max_message_size: 65536,
            db_key: None,
        }
    }
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Initialization failed: {0}")]
    InitializationFailed(String),
    #[error("Not connected")]
    NotConnected,
    #[error("Already running")]
    AlreadyRunning,
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Identity error: {0}")]
    IdentityError(String),
    #[error("Crypto error: {0}")]
    CryptoError(String),
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    #[error("Group not found: {0}")]
    GroupNotFound(String),
    #[error("Contact not found: {0}")]
    ContactNotFound(String),
    #[error("Message error: {0}")]
    MessageError(String),
    #[error("Serialization failed: {0}")]
    SerializationError(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientState {
    Created,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
}

#[derive(Clone)]
struct DirectSession {
    send_key: [u8; 32],
    receive_key: [u8; 32],
    conversation_id: String,
    send_counter: u64,
    seen_incoming_sequences: HashSet<u64>,
}

struct PendingInitiator {
    keypair: HybridKeypair,
}

struct SessionStore {
    direct_sessions: RwLock<HashMap<String, DirectSession>>,
    chats: RwLock<HashMap<String, ChatSession>>,
    groups: RwLock<HashMap<String, GroupChat>>,
    pending_initiators: RwLock<HashMap<String, PendingInitiator>>,
    pending_responses: RwLock<Vec<NetworkEnvelope>>,
    group_messages: RwLock<HashMap<String, Vec<StoredGroupMessage>>>,
}

impl SessionStore {
    fn new() -> Self {
        Self {
            direct_sessions: RwLock::new(HashMap::new()),
            chats: RwLock::new(HashMap::new()),
            groups: RwLock::new(HashMap::new()),
            pending_initiators: RwLock::new(HashMap::new()),
            pending_responses: RwLock::new(Vec::new()),
            group_messages: RwLock::new(HashMap::new()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredBlob {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}

#[derive(Serialize, Deserialize)]
struct DirectHandshakePayload {
    sender_fingerprint: String,
    recipient_fingerprint: String,
    stage: HandshakeStage,
    exchange: KeyExchangeMessage,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum HandshakeStage {
    Initiation,
    Response,
}

#[derive(Serialize, Deserialize)]
struct DirectMessagePayload {
    sender_fingerprint: String,
    recipient_fingerprint: String,
    conversation_id: String,
    sequence: u64,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    tag: [u8; 16],
}

/// Stored group message.
///
/// The `plaintext_message` is the decoded `Message` for local display.
/// The `encrypted_msg_bytes` holds the serialized `GroupEncryptedMessage`
/// for forwarding to other members over the network.
#[derive(Serialize, Deserialize, Clone)]
struct StoredGroupMessage {
    id: String,
    sender_fingerprint: String,
    /// Decrypted `Message` for local display.
    plaintext_message: Message,
    /// Serialized `GroupEncryptedMessage` bytes for network transport.
    encrypted_msg_bytes: Vec<u8>,
    sent_at: u64,
}

#[derive(Serialize, Deserialize)]
struct GroupCommitEnvelope {
    group_id: String,
    commit: crate::group::Commit,
}

pub struct Client {
    config: ClientConfig,
    state: Arc<RwLock<ClientState>>,
    running: Arc<RwLock<bool>>,
    identity: Arc<RwLock<Option<Arc<Identity>>>>,
    sessions: Arc<SessionStore>,
    contacts: Arc<RwLock<MemoryContactStore>>,
    database: Arc<RwLock<Option<Database>>>,
    cache: Arc<RwLock<EncryptedCache>>,
    tor: Arc<RwLock<Option<TorTransport>>>,
    mixnet: Arc<RwLock<Option<MixnetClient>>>,
    dht: Arc<RwLock<Option<DhtNode>>>,
    device_sync: Arc<RwLock<DeviceSync>>,
    storage_key: Arc<RwLock<Option<[u8; 32]>>>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        Ok(Self {
            config,
            state: Arc::new(RwLock::new(ClientState::Created)),
            running: Arc::new(RwLock::new(false)),
            identity: Arc::new(RwLock::new(None)),
            sessions: Arc::new(SessionStore::new()),
            contacts: Arc::new(RwLock::new(MemoryContactStore::new())),
            database: Arc::new(RwLock::new(None)),
            cache: Arc::new(RwLock::new(EncryptedCache::new())),
            tor: Arc::new(RwLock::new(None)),
            mixnet: Arc::new(RwLock::new(None)),
            dht: Arc::new(RwLock::new(None)),
            device_sync: Arc::new(RwLock::new(DeviceSync::new("default".to_string()))),
            storage_key: Arc::new(RwLock::new(None)),
        })
    }

    pub fn with_defaults() -> Result<Self, ClientError> {
        Self::new(ClientConfig::default())
    }

    pub fn state(&self) -> ClientState {
        *self.state.read()
    }

    pub fn is_connected(&self) -> bool {
        *self.state.read() == ClientState::Connected
    }

    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    pub fn identity(&self) -> Option<Arc<Identity>> {
        self.identity.read().clone()
    }

    pub fn fingerprint(&self) -> Option<String> {
        self.identity
            .read()
            .as_ref()
            .map(|identity| identity.public().fingerprint_full.clone())
    }

    pub fn create_identity(&self) -> Result<Arc<Identity>, ClientError> {
        let identity =
            Identity::generate().map_err(|e| ClientError::IdentityError(e.to_string()))?;
        let storage_key = self.ensure_storage_key()?;

        if let Some(db) = self.database.read().as_ref() {
            db.store_identity(
                &identity.public().fingerprint_full,
                &identity
                    .public()
                    .to_bytes()
                    .map_err(|e| ClientError::IdentityError(e.to_string()))?,
                &identity
                    .serialize_encrypted(&storage_key)
                    .map_err(|e| ClientError::IdentityError(e.to_string()))?,
            )
            .map_err(|e| ClientError::StorageError(e.to_string()))?;
        }

        let identity = Arc::new(identity);
        *self.identity.write() = Some(identity.clone());
        self.device_sync
            .write()
            .queue_operation(SyncOperation::IdentityUpdate {
                new_fingerprint: identity.public().fingerprint_full.clone(),
            });
        Ok(identity)
    }

    pub fn load_identity(&self, fingerprint: &str) -> Result<Arc<Identity>, ClientError> {
        let storage_key = self.ensure_storage_key()?;
        let db_guard = self.database.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| ClientError::StorageError("Database is not open".into()))?;
        let row = db
            .load_identity(fingerprint)
            .map_err(|e| ClientError::StorageError(e.to_string()))?
            .ok_or_else(|| ClientError::IdentityError("Identity not found in storage".into()))?;
        let public = PublicIdentity::from_serialized(&row.public_identity)
            .map_err(|e| ClientError::IdentityError(e.to_string()))?;
        let identity = Arc::new(
            Identity::deserialize_encrypted(public, &row.encrypted_private_key, &storage_key)
                .map_err(|e| ClientError::IdentityError(e.to_string()))?,
        );
        *self.identity.write() = Some(identity.clone());
        Ok(identity)
    }

    pub async fn start(&self) -> Result<(), ClientError> {
        if *self.running.read() {
            return Err(ClientError::AlreadyRunning);
        }

        *self.state.write() = ClientState::Connecting;

        let storage_dir = self.storage_dir();
        std::fs::create_dir_all(&storage_dir)
            .map_err(|e| ClientError::StorageError(e.to_string()))?;
        let key = self.ensure_storage_key()?;

        let db_config = DbConfig {
            path: storage_dir.join("shadowgram.sqlite3"),
            encryption_key: key,
            ..Default::default()
        };
        let mut db =
            Database::new(db_config).map_err(|e| ClientError::StorageError(e.to_string()))?;
        db.open()
            .map_err(|e| ClientError::StorageError(e.to_string()))?;

        if let Some(row) = db
            .load_latest_identity()
            .map_err(|e| ClientError::StorageError(e.to_string()))?
        {
            let public = PublicIdentity::from_serialized(&row.public_identity)
                .map_err(|e| ClientError::IdentityError(e.to_string()))?;
            let identity = Arc::new(
                Identity::deserialize_encrypted(public, &row.encrypted_private_key, &key)
                    .map_err(|e| ClientError::IdentityError(e.to_string()))?,
            );
            *self.identity.write() = Some(identity);
        }

        *self.database.write() = Some(db);

        if self.config.use_tor {
            let mut tor = TorTransport::new();
            tor.bootstrap()
                .await
                .map_err(|e| ClientError::NetworkError(e.to_string()))?;
            *self.tor.write() = Some(tor);
        }

        if self.config.use_mixnet {
            *self.mixnet.write() = Some(MixnetClient::new(Default::default()));
        }

        *self.dht.write() = Some(
            DhtNode::new(Default::default())
                .map_err(|e| ClientError::NetworkError(e.to_string()))?,
        );

        *self.state.write() = ClientState::Connected;
        *self.running.write() = true;
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), ClientError> {
        if !*self.running.read() {
            return Ok(());
        }
        *self.state.write() = ClientState::Disconnecting;
        self.tor.write().take();
        self.mixnet.write().take();
        self.cache.write().clear();
        *self.state.write() = ClientState::Disconnected;
        *self.running.write() = false;
        Ok(())
    }

    /// Rotate the local identity.
    ///
    /// 1. Generates a fresh identity keypair.
    /// 2. Marks the old identity inactive in the DB (cannot be loaded again).
    /// 3. Purges all in-memory session state tied to the old fingerprint.
    /// 4. Clears the encrypted cache.
    /// 5. Returns the new identity fingerprint.
    ///
    /// After rotation, callers must re-initiate key exchanges with all
    /// contacts using the new identity.
    pub fn rotate_identity(&self) -> Result<String, ClientError> {
        let storage_key = self.ensure_storage_key()?;

        let new_identity =
            Identity::generate().map_err(|e| ClientError::IdentityError(e.to_string()))?;
        let new_fp = new_identity.public().fingerprint_full.clone();

        // Persist new identity
        if let Some(db) = self.database.read().as_ref() {
            // Deactivate all existing identities
            db.deactivate_all_identities()
                .map_err(|e| ClientError::StorageError(e.to_string()))?;

            db.store_identity(
                &new_identity.public().fingerprint_full,
                &new_identity
                    .public()
                    .to_bytes()
                    .map_err(|e| ClientError::IdentityError(e.to_string()))?,
                &new_identity
                    .serialize_encrypted(&storage_key)
                    .map_err(|e| ClientError::IdentityError(e.to_string()))?,
            )
            .map_err(|e| ClientError::StorageError(e.to_string()))?;
        }

        // Purge all in-memory session state
        self.sessions.direct_sessions.write().clear();
        self.sessions.chats.write().clear();
        self.sessions.groups.write().clear();
        self.sessions.pending_initiators.write().clear();
        self.sessions.pending_responses.write().clear();
        self.sessions.group_messages.write().clear();
        self.cache.write().clear();

        // Install new identity
        *self.identity.write() = Some(Arc::new(new_identity));
        // Invalidate cached storage key so it is re-derived on next access.
        *self.storage_key.write() = None;

        Ok(new_fp)
    }

    /// Permanently wipe all local data.
    ///
    /// Removes the storage directory (database, master key, cached state).
    /// Zeroizes in-memory secrets. This is a best-effort operation: the OS
    /// may not guarantee secure erase of disk blocks, but we overwrite the
    /// master key file before deleting it.
    ///
    /// After this call the client is unusable; drop it.
    pub fn wipe_local_data(&self) -> Result<(), ClientError> {
        // Stop any active connection first
        self.sessions.direct_sessions.write().clear();
        self.sessions.chats.write().clear();
        self.sessions.groups.write().clear();
        self.sessions.pending_initiators.write().clear();
        self.sessions.pending_responses.write().clear();
        self.sessions.group_messages.write().clear();
        self.cache.write().clear();

        // Zeroize and remove the master key file
        let storage_dir = self.storage_dir();
        let key_path = storage_dir.join("master.key");
        if key_path.exists() {
            // Best-effort overwrite before deletion
            let _ = std::fs::write(&key_path, [0u8; 32]);
            let _ = std::fs::remove_file(&key_path);
        }

        // Close and remove the database file
        {
            let mut db_guard = self.database.write();
            if let Some(mut db) = db_guard.take() {
                let _ = db.close();
            }
        }

        // Remove the entire storage directory
        if storage_dir.exists() {
            std::fs::remove_dir_all(&storage_dir)
                .map_err(|e| ClientError::StorageError(format!("wipe failed: {}", e)))?;
        }

        // Clear the in-memory identity
        *self.identity.write() = None;

        // Zeroize the cached storage key
        if let Some(mut key) = self.storage_key.write().take() {
            use zeroize::Zeroize;
            key.zeroize();
        }

        Ok(())
    }

    pub async fn initiate_key_exchange(
        &self,
        identity: &Identity,
        contact_fingerprint: &str,
    ) -> Result<NetworkEnvelope, ClientError> {
        let keypair = HybridKeypair::generate_initiator();
        let exchange = KeyExchangeMessage::from_initiator(
            keypair.x25519_public(),
            keypair.mlkem_encapsulation_key(),
        );
        self.sessions.pending_initiators.write().insert(
            contact_fingerprint.to_string(),
            PendingInitiator { keypair },
        );

        let payload = DirectHandshakePayload {
            sender_fingerprint: identity.public().fingerprint_full.clone(),
            recipient_fingerprint: contact_fingerprint.to_string(),
            stage: HandshakeStage::Initiation,
            exchange,
        };
        let mut envelope = NetworkEnvelope::new(
            MessageType::Handshake,
            serde_json::to_vec(&payload)
                .map_err(|e| ClientError::SerializationError(e.to_string()))?,
        );
        envelope.pad_to_constant_size(1024);
        Ok(envelope)
    }

    pub async fn respond_to_key_exchange(
        &self,
        _identity: &Identity,
    ) -> Result<NetworkEnvelope, ClientError> {
        self.sessions
            .pending_responses
            .write()
            .pop()
            .ok_or_else(|| ClientError::MessageError("No pending key exchange response".into()))
    }

    pub async fn is_session_established(&self, fingerprint: &str) -> bool {
        self.sessions
            .direct_sessions
            .read()
            .contains_key(fingerprint)
    }

    pub async fn send_message(
        &self,
        contact_fingerprint: &str,
        mut message: Message,
    ) -> Result<NetworkEnvelope, ClientError> {
        let mut sessions = self.sessions.direct_sessions.write();
        let session = sessions
            .get_mut(contact_fingerprint)
            .ok_or_else(|| ClientError::SessionNotFound(contact_fingerprint.to_string()))?;
        let nonce = sequence_nonce(session.send_counter, 0x01);
        let plaintext = message
            .serialize()
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;
        let (ciphertext, tag) = AeadCipher::encrypt_chacha20(
            &session.send_key,
            &nonce,
            &plaintext,
            session.conversation_id.as_bytes(),
        )
        .map_err(|e| ClientError::CryptoError(e.to_string()))?;
        message.direction = MessageDirection::Outgoing;
        message.status = MessageStatus::Sent;
        self.persist_message(&session.conversation_id, session.send_counter + 1, &message)?;
        let payload = DirectMessagePayload {
            sender_fingerprint: self
                .fingerprint()
                .ok_or_else(|| ClientError::IdentityError("Identity not loaded".into()))?,
            recipient_fingerprint: contact_fingerprint.to_string(),
            conversation_id: session.conversation_id.clone(),
            sequence: session.send_counter,
            nonce,
            ciphertext,
            tag,
        };
        session.send_counter += 1;
        let mut envelope = NetworkEnvelope::new(
            MessageType::Message,
            serde_json::to_vec(&payload)
                .map_err(|e| ClientError::SerializationError(e.to_string()))?,
        );
        envelope.pad_to_constant_size(1024);
        Ok(envelope)
    }

    pub async fn process_network_message(
        &self,
        envelope: NetworkEnvelope,
    ) -> Result<(), ClientError> {
        match envelope.msg_type {
            MessageType::Handshake => self.handle_key_exchange(envelope).await,
            MessageType::Message => self.handle_incoming_message(envelope).await,
            MessageType::Ratchet => self.handle_ratchet_update(envelope).await,
            MessageType::Control => self.handle_control_message(envelope).await,
            MessageType::Cover => Ok(()),
        }
    }

    pub async fn get_pending_messages(&self, contact_fingerprint: &str) -> Vec<Message> {
        let Some(session) = self
            .sessions
            .direct_sessions
            .read()
            .get(contact_fingerprint)
            .cloned()
        else {
            return Vec::new();
        };
        self.load_messages(&session.conversation_id)
            .unwrap_or_default()
    }

    pub async fn create_group(
        &self,
        name: &str,
        creator: &Identity,
    ) -> Result<String, ClientError> {
        let group_id = random_id("group");
        let creator_key = creator
            .public()
            .to_bytes()
            .map_err(|e| ClientError::IdentityError(e.to_string()))?;
        let group = GroupChat::create(
            group_id.clone(),
            creator.public().fingerprint_full.clone(),
            creator_key,
            Some(name.to_string()),
        );
        self.sessions
            .groups
            .write()
            .insert(group_id.clone(), group);
        if let Some(db) = self.database.read().as_ref() {
            let _ = db.ensure_conversation(&group_id, 2, None, self.fingerprint().as_deref());
        }
        Ok(group_id)
    }

    pub async fn add_member_to_group(
        &self,
        group_id: &str,
        member_fingerprint: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let contact = self
            .get_contact(member_fingerprint)
            .ok_or_else(|| ClientError::ContactNotFound(member_fingerprint.to_string()))?;
        let mut groups = self.sessions.groups.write();
        let group = groups
            .get_mut(group_id)
            .ok_or_else(|| ClientError::GroupNotFound(group_id.to_string()))?;
        if group
            .members()
            .iter()
            .any(|member| member.fingerprint == member_fingerprint && member.left_at.is_none())
        {
            return Err(ClientError::MessageError(
                "Member already exists in group".into(),
            ));
        }
        let member = GroupMember {
            fingerprint: member_fingerprint.to_string(),
            display_name: Some(contact.alias),
            role: MemberRole::Member,
            key_package: contact.public_identity,
            joined_at: current_timestamp(),
            left_at: None,
        };
        let commit = group
            .add_member(member)
            .map_err(|e| ClientError::MessageError(e.to_string()))?;
        serde_json::to_vec(&GroupCommitEnvelope {
            group_id: group_id.to_string(),
            commit,
        })
        .map_err(|e| ClientError::SerializationError(e.to_string()))
    }

    /// Encrypt and send a group message.
    ///
    /// Uses ChaCha20-Poly1305 AEAD. The plaintext is stored locally for
    /// display; only the AEAD ciphertext is put in the network envelope.
    pub async fn send_group_message(
        &self,
        group_id: &str,
        mut message: Message,
    ) -> Result<NetworkEnvelope, ClientError> {
        let sender = self
            .fingerprint()
            .ok_or_else(|| ClientError::IdentityError("Identity not loaded".into()))?;
        let mut groups = self.sessions.groups.write();
        let group = groups
            .get_mut(group_id)
            .ok_or_else(|| ClientError::GroupNotFound(group_id.to_string()))?;
        if !group
            .members()
            .iter()
            .any(|member| member.fingerprint == sender && member.left_at.is_none())
        {
            return Err(ClientError::MessageError(
                "Current identity is not an active group member".into(),
            ));
        }
        let plaintext = message
            .serialize()
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        // AEAD encrypt with ChaCha20-Poly1305
        let enc_msg = group
            .encrypt_message(&plaintext, &sender)
            .map_err(|e| ClientError::CryptoError(e.to_string()))?;
        let enc_bytes = enc_msg
            .to_bytes()
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        message.direction = MessageDirection::Outgoing;
        message.status = MessageStatus::Sent;

        // Store plaintext locally for display; send ciphertext over the network
        self.sessions
            .group_messages
            .write()
            .entry(group_id.to_string())
            .or_default()
            .push(StoredGroupMessage {
                id: message.id.clone(),
                sender_fingerprint: sender,
                plaintext_message: message,
                encrypted_msg_bytes: enc_bytes.clone(),
                sent_at: current_timestamp(),
            });

        let mut envelope = NetworkEnvelope::new(MessageType::Message, enc_bytes);
        envelope.pad_to_constant_size(1024);
        Ok(envelope)
    }

    /// Returns locally stored group messages (decrypted at send/receive time).
    pub async fn get_group_messages(&self, group_id: &str) -> Vec<Message> {
        self.sessions
            .group_messages
            .read()
            .get(group_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.plaintext_message)
            .collect()
    }

    /// Receive and decrypt an incoming group message.
    ///
    /// Stores the decrypted message for retrieval via `get_group_messages`.
    pub async fn receive_group_message(
        &self,
        enc_bytes: &[u8],
    ) -> Result<Message, ClientError> {
        let enc_msg = GroupEncryptedMessage::from_bytes(enc_bytes)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;
        let group_id = enc_msg.group_id.clone();
        let sender = enc_msg.sender.clone();

        let mut groups = self.sessions.groups.write();
        let group = groups
            .get_mut(&group_id)
            .ok_or_else(|| ClientError::GroupNotFound(group_id.clone()))?;

        let plaintext = group
            .decrypt_message(&enc_msg)
            .map_err(|e| ClientError::CryptoError(e.to_string()))?;

        let mut message = Message::deserialize(&plaintext)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;
        message.direction = MessageDirection::Incoming;
        message.status = MessageStatus::Delivered;

        self.sessions
            .group_messages
            .write()
            .entry(group_id.clone())
            .or_default()
            .push(StoredGroupMessage {
                id: message.id.clone(),
                sender_fingerprint: sender,
                plaintext_message: message.clone(),
                encrypted_msg_bytes: enc_bytes.to_vec(),
                sent_at: current_timestamp(),
            });

        Ok(message)
    }

    pub async fn process_group_commit(&self, commit: Vec<u8>) -> Result<(), ClientError> {
        let envelope: GroupCommitEnvelope = serde_json::from_slice(&commit)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;
        let mut groups = self.sessions.groups.write();
        let group = groups
            .get_mut(&envelope.group_id)
            .ok_or_else(|| ClientError::GroupNotFound(envelope.group_id.clone()))?;
        group
            .process_commit(&envelope.commit)
            .map_err(|e| ClientError::MessageError(e.to_string()))
    }

    pub fn add_contact(&self, contact: Contact) -> Result<(), ClientError> {
        self.contacts
            .read()
            .add(contact.clone())
            .map_err(|e| ClientError::StorageError(e.to_string()))?;
        if let Some(db) = self.database.read().as_ref() {
            db.store_contact(
                &contact.fingerprint,
                &contact.alias,
                &contact.public_identity,
                contact.trust_level as u8,
            )
            .map_err(|e| ClientError::StorageError(e.to_string()))?;
        }
        Ok(())
    }

    pub fn get_contact(&self, fingerprint: &str) -> Option<Contact> {
        self.contacts.read().get(fingerprint).unwrap_or(None)
    }

    pub fn list_contacts(&self) -> Vec<Contact> {
        self.contacts.read().list().unwrap_or_default()
    }

    pub fn remove_contact(&self, fingerprint: &str) -> Result<(), ClientError> {
        self.contacts
            .read()
            .remove(fingerprint)
            .map_err(|e| ClientError::StorageError(e.to_string()))
    }

    pub fn run_contact_discovery_psi(&self, remote_hashes: &[Vec<u8>]) -> PsiResult {
        let contacts = self.list_contacts();
        let fingerprints: Vec<String> = contacts.iter().map(|c| c.fingerprint.clone()).collect();
        ContactDiscoveryPSI::new(fingerprints).discover_common(remote_hashes)
    }

    pub fn register_device(&self, device: DeviceInfo) -> Result<(), ClientError> {
        self.device_sync.write().register_device(device);
        Ok(())
    }

    pub fn get_pending_sync(&self) -> Vec<SyncOperation> {
        self.device_sync.write().take_pending_ops()
    }

    pub fn complete_sync_operation(&self, _index: usize) {}

    async fn handle_key_exchange(&self, envelope: NetworkEnvelope) -> Result<(), ClientError> {
        let payload: DirectHandshakePayload = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;
        match payload.stage {
            HandshakeStage::Initiation => {
                let their_x25519 = payload
                    .exchange
                    .parse_initiator_x25519()
                    .map_err(|e| ClientError::CryptoError(e.to_string()))?;
                let their_mlkem = payload
                    .exchange
                    .parse_initiator_mlkem_key()
                    .map_err(|e| ClientError::CryptoError(e.to_string()))?;
                let (responder, ciphertext, responder_x25519) =
                    HybridResponder::new(&their_x25519, &their_mlkem)
                        .map_err(|e| ClientError::CryptoError(e.to_string()))?;
                let key = responder
                    .shared_secret()
                    .derive_keys(b"shadowgram-direct-session")
                    .map_err(|e| ClientError::CryptoError(e.to_string()))?;
                let keys = derive_directional_session_keys(
                    &key,
                    SessionRole::Responder,
                    &payload.sender_fingerprint,
                    &payload.recipient_fingerprint,
                );
                self.establish_direct_session(&payload.sender_fingerprint, keys);
                let response = DirectHandshakePayload {
                    sender_fingerprint: payload.recipient_fingerprint.clone(),
                    recipient_fingerprint: payload.sender_fingerprint.clone(),
                    stage: HandshakeStage::Response,
                    exchange: KeyExchangeMessage::from_responder(
                        &responder_x25519,
                        responder.mlkem_encapsulation_key(),
                        &ciphertext,
                    ),
                };
                let mut response_envelope = NetworkEnvelope::new(
                    MessageType::Handshake,
                    serde_json::to_vec(&response)
                        .map_err(|e| ClientError::SerializationError(e.to_string()))?,
                );
                response_envelope.pad_to_constant_size(1024);
                self.sessions
                    .pending_responses
                    .write()
                    .push(response_envelope);
                Ok(())
            }
            HandshakeStage::Response => {
                let mut pending = self.sessions.pending_initiators.write();
                let pending = pending.remove(&payload.sender_fingerprint).ok_or_else(|| {
                    ClientError::SessionNotFound(format!(
                        "No pending initiator state for {}",
                        payload.sender_fingerprint
                    ))
                })?;
                let their_x25519 = payload
                    .exchange
                    .parse_initiator_x25519()
                    .map_err(|e| ClientError::CryptoError(e.to_string()))?;
                let ciphertext = payload
                    .exchange
                    .parse_responder_ciphertext()
                    .map_err(|e| ClientError::CryptoError(e.to_string()))?;
                let mut keypair = pending.keypair;
                let shared = keypair
                    .initiator_finish(&their_x25519, &ciphertext)
                    .map_err(|e| ClientError::CryptoError(e.to_string()))?;
                let key = shared
                    .derive_keys(b"shadowgram-direct-session")
                    .map_err(|e| ClientError::CryptoError(e.to_string()))?;
                let keys = derive_directional_session_keys(
                    &key,
                    SessionRole::Initiator,
                    &payload.recipient_fingerprint,
                    &payload.sender_fingerprint,
                );
                self.establish_direct_session(&payload.sender_fingerprint, keys);
                Ok(())
            }
        }
    }

    async fn handle_incoming_message(&self, envelope: NetworkEnvelope) -> Result<(), ClientError> {
        let payload: DirectMessagePayload = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;
        let mut sessions = self.sessions.direct_sessions.write();
        let session = sessions
            .get_mut(&payload.sender_fingerprint)
            .ok_or_else(|| ClientError::SessionNotFound(payload.sender_fingerprint.clone()))?;
        if !session.seen_incoming_sequences.insert(payload.sequence) {
            return Err(ClientError::MessageError(format!(
                "Replay detected for sequence {}",
                payload.sequence
            )));
        }
        let plaintext = AeadCipher::decrypt_chacha20(
            &session.receive_key,
            &payload.nonce,
            &payload.ciphertext,
            &payload.tag,
            payload.conversation_id.as_bytes(),
        )
        .map_err(|e| ClientError::CryptoError(e.to_string()))?;
        let mut message = Message::deserialize(&plaintext)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;
        message.direction = MessageDirection::Incoming;
        message.status = MessageStatus::Delivered;
        self.persist_message(&payload.conversation_id, payload.sequence + 1, &message)
    }

    async fn handle_ratchet_update(&self, _envelope: NetworkEnvelope) -> Result<(), ClientError> {
        Err(ClientError::MessageError(
            "Ratchet updates are not implemented in the core client yet".into(),
        ))
    }

    async fn handle_control_message(&self, _envelope: NetworkEnvelope) -> Result<(), ClientError> {
        Err(ClientError::MessageError(
            "Control messages are not implemented in the core client yet".into(),
        ))
    }

    fn storage_dir(&self) -> PathBuf {
        PathBuf::from(&self.config.storage_path)
    }

    fn ensure_storage_key(&self) -> Result<[u8; 32], ClientError> {
        if let Some(key) = *self.storage_key.read() {
            return Ok(key);
        }
        let key = if let Some(key) = self.config.db_key {
            key
        } else {
            let dir = self.storage_dir();
            std::fs::create_dir_all(&dir).map_err(|e| ClientError::StorageError(e.to_string()))?;
            let path = dir.join("master.key");
            if path.exists() {
                let bytes =
                    std::fs::read(&path).map_err(|e| ClientError::StorageError(e.to_string()))?;
                let array: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| ClientError::StorageError("Invalid master key length".into()))?;
                array
            } else {
                let mut bytes = [0u8; 32];
                OsRng.fill_bytes(&mut bytes);
                std::fs::write(&path, bytes)
                    .map_err(|e| ClientError::StorageError(e.to_string()))?;
                bytes
            }
        };
        *self.storage_key.write() = Some(key);
        Ok(key)
    }

    fn establish_direct_session(&self, contact_fingerprint: &str, keys: SessionKeys) {
        let our_fingerprint = self.fingerprint().unwrap_or_else(|| "unknown".into());
        let conversation_id = direct_conversation_id(&our_fingerprint, contact_fingerprint);
        self.sessions.direct_sessions.write().insert(
            contact_fingerprint.to_string(),
            DirectSession {
                send_key: keys.send_key,
                receive_key: keys.receive_key,
                conversation_id: conversation_id.clone(),
                send_counter: 0,
                seen_incoming_sequences: HashSet::new(),
            },
        );
        let mut chat = ChatSession::new(our_fingerprint, contact_fingerprint.to_string());
        chat.set_state(crate::chat::ChatState::Established);
        self.sessions
            .chats
            .write()
            .insert(contact_fingerprint.to_string(), chat);
        if let Some(db) = self.database.read().as_ref() {
            let _ = db.ensure_conversation(
                &conversation_id,
                1,
                Some(contact_fingerprint),
                self.fingerprint().as_deref(),
            );
        }
    }

    fn persist_message(
        &self,
        conversation_id: &str,
        sequence: u64,
        message: &Message,
    ) -> Result<(), ClientError> {
        let db_guard = self.database.read();
        let Some(db) = db_guard.as_ref() else {
            return Ok(());
        };
        db.ensure_conversation(conversation_id, 1, None, self.fingerprint().as_deref())
            .map_err(|e| ClientError::StorageError(e.to_string()))?;
        let storage_key = self.ensure_storage_key()?;
        let serialized = message
            .serialize()
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;
        let encrypted = encrypt_blob(&storage_key, conversation_id.as_bytes(), &serialized)
            .map_err(|e| ClientError::CryptoError(e.to_string()))?;
        db.store_message(
            conversation_id,
            sequence,
            if message.direction == MessageDirection::Incoming {
                1
            } else {
                2
            },
            &encrypted,
            match message.status {
                MessageStatus::Composed => 0,
                MessageStatus::Sending => 1,
                MessageStatus::Sent => 2,
                MessageStatus::Delivered => 3,
                MessageStatus::Read => 4,
                MessageStatus::Failed => 5,
            },
        )
        .map_err(|e| ClientError::StorageError(e.to_string()))
    }

    fn load_messages(&self, conversation_id: &str) -> Result<Vec<Message>, ClientError> {
        let db_guard = self.database.read();
        let Some(db) = db_guard.as_ref() else {
            return Ok(Vec::new());
        };
        let rows = db
            .get_messages(conversation_id, 200, 0)
            .map_err(|e| ClientError::StorageError(e.to_string()))?;
        let storage_key = self.ensure_storage_key()?;
        rows.into_iter()
            .map(|row| {
                let plaintext =
                    decrypt_blob(&storage_key, conversation_id.as_bytes(), &row.envelope)
                        .map_err(|e| ClientError::CryptoError(e.to_string()))?;
                Message::deserialize(&plaintext)
                    .map_err(|e| ClientError::SerializationError(e.to_string()))
            })
            .collect()
    }
}

fn encrypt_blob(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = AeadCipher::generate_nonce();
    let (ciphertext, tag) =
        AeadCipher::encrypt_chacha20(key, &nonce, plaintext, aad).map_err(|e| e.to_string())?;
    bincode::serialize(&StoredBlob {
        nonce,
        ciphertext,
        tag,
    })
    .map_err(|e| e.to_string())
}

fn decrypt_blob(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, String> {
    let blob: StoredBlob = bincode::deserialize(blob).map_err(|e| e.to_string())?;
    AeadCipher::decrypt_chacha20(key, &blob.nonce, &blob.ciphertext, &blob.tag, aad)
        .map_err(|e| e.to_string())
}

fn sequence_nonce(sequence: u64, direction_marker: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&direction_marker.to_le_bytes());
    nonce[4..].copy_from_slice(&sequence.to_le_bytes());
    nonce
}

#[derive(Clone, Copy)]
struct SessionKeys {
    send_key: [u8; 32],
    receive_key: [u8; 32],
}

#[derive(Clone, Copy)]
enum SessionRole {
    Initiator,
    Responder,
}

fn derive_directional_session_keys(
    shared_key: &[u8; 32],
    role: SessionRole,
    initiator_fingerprint: &str,
    responder_fingerprint: &str,
) -> SessionKeys {
    let initiator_to_responder = blake3::keyed_hash(
        shared_key,
        format!(
            "shadowgram-session:initiator:{}:responder:{}",
            initiator_fingerprint, responder_fingerprint
        )
        .as_bytes(),
    );
    let responder_to_initiator = blake3::keyed_hash(
        shared_key,
        format!(
            "shadowgram-session:responder:{}:initiator:{}",
            responder_fingerprint, initiator_fingerprint
        )
        .as_bytes(),
    );
    match role {
        SessionRole::Initiator => SessionKeys {
            send_key: *initiator_to_responder.as_bytes(),
            receive_key: *responder_to_initiator.as_bytes(),
        },
        SessionRole::Responder => SessionKeys {
            send_key: *responder_to_initiator.as_bytes(),
            receive_key: *initiator_to_responder.as_bytes(),
        },
    }
}

fn direct_conversation_id(a: &str, b: &str) -> String {
    if a <= b {
        format!("direct:{}:{}", a, b)
    } else {
        format!("direct:{}:{}", b, a)
    }
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{}-{}", prefix, encode_hex(&bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

impl Drop for Client {
    fn drop(&mut self) {
        if *self.running.read() {
            self.cache.write().clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = Client::with_defaults().unwrap();
        assert_eq!(client.state(), ClientState::Created);
        assert!(!client.is_running());
        assert!(client.identity().is_none());
    }

    #[test]
    fn test_create_identity() {
        let client = Client::with_defaults().unwrap();
        let identity = client.create_identity().unwrap();

        assert!(!identity.public().display_fingerprint().is_empty());
        assert_eq!(
            client.fingerprint(),
            Some(identity.public().fingerprint_full.clone())
        );
    }

    #[test]
    fn test_contact_management() {
        let client = Client::with_defaults().unwrap();

        let contact = Contact::new("test_fp".to_string(), "Test User".to_string(), vec![]);

        client.add_contact(contact.clone()).unwrap();

        let retrieved = client.get_contact("test_fp").unwrap();
        assert_eq!(retrieved.fingerprint, "test_fp");

        let contacts = client.list_contacts();
        assert_eq!(contacts.len(), 1);
    }
}
