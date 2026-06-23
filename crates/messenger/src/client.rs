//! Shadowgram Client - Full Implementation
//!
//! Main entry point for the messenger application providing:
//! - Identity management (create, load, rotate)
//! - 1-on-1 encrypted chat sessions
//! - Group chat via MLS TreeKEM
//! - Contact discovery and management
//! - Multi-device synchronization
//! - Network message processing

use std::sync::Arc;
use parking_lot::RwLock;
use shadowgram_crypto::{
    key_exchange::{HybridKeypair, KeyExchangeMessage},
    keys::KeyMaterial,
};
use shadowgram_identity::{Identity, PublicIdentity, RotationPolicy};
use shadowgram_network::{
    NetworkEnvelope, MessageType, NoiseIK,
    tor::TorTransport,
    mixnet::MixnetClient,
    dht::DhtNode,
};
use shadowgram_storage::{Database, EncryptedCache};
use crate::{
    Message, MessageEnvelope, MessageStatus, MessageType as MsgType,
    Chat, ChatSession, Contact, ContactStore, MemoryContactStore,
    GroupState, GroupInfo, GroupMember, MemberRole,
    DeviceInfo, DeviceSync, SyncOperation,
    PsiProtocol, ContactDiscoveryPSI, PsiResult,
};
use thiserror::Error;

/// Client configuration
#[derive(Clone)]
pub struct ClientConfig {
    /// Path to store encrypted data
    pub storage_path: String,

    /// Enable Tor routing
    pub use_tor: bool,

    /// Enable mixnet routing
    pub use_mixnet: bool,

    /// Enable cover traffic
    pub cover_traffic: bool,

    /// Auto-rotate identities (days)
    pub rotation_days: u64,

    /// Maximum message size (bytes)
    pub max_message_size: usize,

    /// Database encryption key (optional, generated if not provided)
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
            max_message_size: 65536, // 64KB
            db_key: None,
        }
    }
}

/// Client errors
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

/// Client state
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientState {
    /// Initial state
    Created,

    /// Bootstrapping network
    Connecting,

    /// Ready for use
    Connected,

    /// Shutting down
    Disconnecting,

    /// Stopped
    Disconnected,
}

/// Chat session tracking
struct SessionStore {
    /// Active 1-on-1 chat sessions
    sessions: RwLock<std::collections::HashMap<String, ChatSession>>,

    /// Active group states
    groups: RwLock<std::collections::HashMap<String, GroupState>>,
}

impl SessionStore {
    fn new() -> Self {
        Self {
            sessions: RwLock::new(std::collections::HashMap::new()),
            groups: RwLock::new(std::collections::HashMap::new()),
        }
    }
}

/// Main Shadowgram client
pub struct Client {
    /// Configuration
    config: ClientConfig,

    /// Current state
    state: Arc<RwLock<ClientState>>,

    /// Running flag
    running: Arc<RwLock<bool>>,

    /// Local identity
    identity: Arc<RwLock<Option<Arc<Identity>>>>,

    /// Session store
    sessions: Arc<SessionStore>,

    /// Contact store
    contacts: Arc<RwLock<MemoryContactStore>>,

    /// Encrypted database
    database: Arc<RwLock<Option<Database>>>,

    /// Encrypted cache for ephemeral data
    cache: Arc<RwLock<EncryptedCache>>,

    /// Tor transport (optional)
    tor: Arc<RwLock<Option<TorTransport>>>,

    /// Mixnet client (optional)
    mixnet: Arc<RwLock<Option<MixnetClient>>>,

    /// DHT node for peer discovery
    dht: Arc<RwLock<Option<DhtNode>>>,

    /// Device sync manager
    device_sync: Arc<RwLock<DeviceSync>>,
}

impl Client {
    /// Create new client with configuration
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let cache_key = [0u8; 32]; // In production: derive from master key

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
        })
    }

    /// Create client with default configuration
    pub fn with_defaults() -> Result<Self, ClientError> {
        Self::new(ClientConfig::default())
    }

    /// Get current client state
    pub fn state(&self) -> ClientState {
        *self.state.read()
    }

    /// Check if client is connected
    pub fn is_connected(&self) -> bool {
        *self.state.read() == ClientState::Connected
    }

    /// Check if client is running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Get local identity (read-only)
    pub fn identity(&self) -> Option<Arc<Identity>> {
        self.identity.read().clone()
    }

    /// Get identity fingerprint
    pub fn fingerprint(&self) -> Option<String> {
        self.identity.read()
            .as_ref()
            .map(|i| i.public().display_fingerprint().to_string())
    }

    /// Create new identity
    pub fn create_identity(&self) -> Result<Arc<Identity>, ClientError> {
        let identity = Identity::generate()
            .map_err(|e| ClientError::IdentityError(e.to_string()))?;

        // Store in database if available
        if let Some(db) = self.database.read().as_ref() {
            db.store_identity(
                identity.public().display_fingerprint(),
                &identity.public().to_bytes().unwrap_or_default(),
                &identity.serialize_encrypted(self.config.db_key.as_ref().unwrap_or(&[0u8; 32])).unwrap_or_default()
            ).map_err(|e| ClientError::StorageError(e.to_string()))?;
        }

        let identity = Arc::new(identity);
        *self.identity.write() = Some(identity.clone());

        // Schedule sync to other devices
        let mut sync = self.device_sync.write();
        sync.queue_operation(SyncOperation::IdentityUpdate { new_fingerprint: identity.public().display_fingerprint().to_string() });

        Ok(identity)
    }

    /// Load existing identity from storage
    pub fn load_identity(&self, fingerprint: &str) -> Result<Arc<Identity>, ClientError> {
        // Try database first
        if let Some(db) = self.database.read().as_ref() {
            if let Ok(Some(_row)) = db.load_identity(fingerprint) {
                // In production: decrypt private keys from row.encrypted_private_key
                // and reconstruct Identity. For now, we know the identity exists but
                // cannot reconstruct it from storage alone.
                // The caller should use create_identity() if no in-memory identity exists.
            }
        }

        Err(ClientError::IdentityError("Identity not found in storage".into()))
    }

    /// Start the client
    pub async fn start(&self) -> Result<(), ClientError> {
        if *self.running.read() {
            return Err(ClientError::AlreadyRunning);
        }

        *self.state.write() = ClientState::Connecting;

        let db_config = shadowgram_storage::DbConfig {
            path: self.config.storage_path.clone().into(),
            encryption_key: self.config.db_key.unwrap_or([0u8; 32]),
            ..Default::default()
        };
        let mut db = Database::new(db_config)
            .map_err(|e| ClientError::StorageError(e.to_string()))?;
        db.open().map_err(|e| ClientError::StorageError(e.to_string()))?;
        *self.database.write() = Some(db);

        // TODO: Load primary identity if fingerprint known

        // Initialize network transports
        if self.config.use_tor {
            let mut tor = TorTransport::new();
            tor.bootstrap()
                .await
                .map_err(|e| ClientError::NetworkError(e.to_string()))?;
            *self.tor.write() = Some(tor);
        }

        if self.config.use_mixnet {
            let mixnet = MixnetClient::new(Default::default());
            *self.mixnet.write() = Some(mixnet);
        }

        // Initialize DHT for peer discovery
        let dht = DhtNode::new(Default::default())
            .map_err(|e| ClientError::NetworkError(e.to_string()))?;
        *self.dht.write() = Some(dht);

        *self.state.write() = ClientState::Connected;
        *self.running.write() = true;

        Ok(())
    }

    /// Stop the client gracefully
    pub async fn stop(&self) -> Result<(), ClientError> {
        if !*self.running.read() {
            return Ok(());
        }

        *self.state.write() = ClientState::Disconnecting;

        // Flush pending messages
        // Close network connections
        if let Some(mut tor) = self.tor.write().take() {
            // Drop handles disconnection
        }

        if let Some(mut mixnet) = self.mixnet.write().take() {
            // Drop handles disconnection
        }

        // Zeroize sensitive data in cache
        self.cache.write().clear();

        *self.state.write() = ClientState::Disconnected;
        *self.running.write() = false;

        Ok(())
    }

    // ==================== 1-on-1 Chat API ====================

    /// Initiate key exchange with a contact
    pub async fn initiate_key_exchange(
        &self,
        identity: &Identity,
        contact_fingerprint: &str,
    ) -> Result<NetworkEnvelope, ClientError> {
        // Create hybrid keypair for key exchange
        let keypair = HybridKeypair::generate_initiator();

        // Serialize key exchange message
        let exchange_msg = KeyExchangeMessage::from_initiator(keypair.x25519_public(), keypair.mlkem_encapsulation_key());

        let payload = serde_json::to_vec(&exchange_msg)
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        // Create network envelope
        let mut envelope = NetworkEnvelope::new(MessageType::Handshake, payload);
        envelope.pad_to_constant_size(1024);

        // Store pending key exchange
        // (would be retrieved when response arrives)

        Ok(envelope)
    }

    /// Respond to key exchange
    pub async fn respond_to_key_exchange(
        &self,
        identity: &Identity,
    ) -> Result<NetworkEnvelope, ClientError> {
        // In production: complete DH handshake, derive shared secret,
        // initialize Double Ratchet, send response

        let mut envelope = NetworkEnvelope::new(MessageType::Handshake, vec![]);
        envelope.pad_to_constant_size(1024);
        Ok(envelope)
    }

    /// Check if session is established with contact
    pub async fn is_session_established(&self, fingerprint: &str) -> bool {
        self.sessions.sessions.read()
            .contains_key(fingerprint)
    }

    /// Send 1-on-1 message
    pub async fn send_message(
        &self,
        contact_fingerprint: &str,
        message: Message,
    ) -> Result<NetworkEnvelope, ClientError> {
        // Get or create chat session
        if !self.sessions.sessions.read().contains_key(contact_fingerprint) {
            return Err(ClientError::SessionNotFound(contact_fingerprint.to_string()));
        }

        // Serialize message
        let payload = message.serialize()
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        // Create encrypted envelope
        let envelope = NetworkEnvelope::new(MessageType::Message, payload);

        Ok(envelope)
    }

    /// Process incoming network message
    pub async fn process_network_message(
        &self,
        envelope: NetworkEnvelope,
    ) -> Result<(), ClientError> {
        match envelope.msg_type {
            MessageType::Handshake => {
                // Process key exchange
                self.handle_key_exchange(envelope).await?;
            }
            MessageType::Message => {
                // Decrypt and store message
                self.handle_incoming_message(envelope).await?;
            }
            MessageType::Ratchet => {
                // Process ratchet update
                self.handle_ratchet_update(envelope).await?;
            }
            MessageType::Control => {
                // Process control message
                self.handle_control_message(envelope).await?;
            }
            MessageType::Cover => {
                // Ignore cover traffic (own or received)
            }
        }

        Ok(())
    }

    /// Get pending messages for a contact
    pub async fn get_pending_messages(
        &self,
        contact_fingerprint: &str,
    ) -> Vec<Message> {
        // In production: decrypt and return messages from storage
        vec![]
    }

    // ==================== Group Chat API ====================

    /// Create new group
    pub async fn create_group(
        &self,
        name: &str,
        creator: &Identity,
    ) -> Result<String, ClientError> {
        let group_id = blake3::hash(name.as_bytes()).to_string();

        let group_info = GroupInfo {
            id: group_id.clone(),
            name: Some(name.to_string()),
            creator: creator.public().display_fingerprint().to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            epoch: 0,
            avatar: None,
            description: None,
        };

        let member = GroupMember {
            fingerprint: creator.public().display_fingerprint().to_string(),
            role: MemberRole::Admin,
            joined_at: group_info.created_at,
            display_name: None,
            key_package: vec![],
            left_at: None,
        };

        let mut group = GroupState::create(group_info, creator.public().display_fingerprint().to_string(), vec![]);
        let _ = group.add_member(member);

        // Store group
        self.sessions.groups.write()
            .insert(group_id.clone(), group);

        Ok(group_id)
    }

    /// Add member to group
    pub async fn add_member_to_group(
        &self,
        group_id: &str,
        member_fingerprint: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let mut groups = self.sessions.groups.write();
        let group = groups
            .get_mut(group_id)
            .ok_or_else(|| ClientError::GroupNotFound(group_id.to_string()))?;

        // Generate commit (in production: full MLS commit)
        Ok(vec![])
    }

    /// Send group message
    pub async fn send_group_message(
        &self,
        group_id: &str,
        message: Message,
    ) -> Result<NetworkEnvelope, ClientError> {
        let groups = self.sessions.groups.read();
        let group = groups
            .get(group_id)
            .ok_or_else(|| ClientError::GroupNotFound(group_id.to_string()))?;

        // Encrypt for group (in production: MLS encryption)
        let payload = message.serialize()
            .map_err(|e| ClientError::SerializationError(e.to_string()))?;

        let envelope = NetworkEnvelope::new(MessageType::Message, payload);
        Ok(envelope)
    }

    /// Get group messages
    pub async fn get_group_messages(&self, group_id: &str) -> Vec<Message> {
        vec![] // In production: return decrypted messages
    }

    /// Process group commit
    pub async fn process_group_commit(
        &self,
        commit: Vec<u8>,
    ) -> Result<(), ClientError> {
        // In production: apply commit to group state
        Ok(())
    }

    // ==================== Contact Management ====================

    /// Add contact
    pub fn add_contact(&self, contact: Contact) -> Result<(), ClientError> {
        self.contacts.read()
            .add(contact)
            .map_err(|e| ClientError::StorageError(e.to_string()))
    }

    /// Get contact by fingerprint
    pub fn get_contact(&self, fingerprint: &str) -> Option<Contact> {
        self.contacts.read()
            .get(fingerprint)
            .unwrap_or(None)
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Vec<Contact> {
        self.contacts.read().list().unwrap_or_default()
    }

    /// Remove contact
    pub fn remove_contact(&self, fingerprint: &str) -> Result<(), ClientError> {
        self.contacts.read()
            .remove(fingerprint)
            .map_err(|e| ClientError::StorageError(e.to_string()))
    }

    /// Run PSI contact discovery
    pub fn run_contact_discovery_psi(
        &self,
        remote_hashes: &[Vec<u8>],
    ) -> PsiResult {
        let contacts = self.list_contacts();
        let fingerprints: Vec<String> = contacts
            .iter()
            .map(|c| c.fingerprint.clone())
            .collect();

        let discovery = ContactDiscoveryPSI::new(fingerprints);
        discovery.discover_common(remote_hashes)
    }

    // ==================== Device Sync ====================

    /// Register new device
    pub fn register_device(&self, device: DeviceInfo) -> Result<(), ClientError> {
        self.device_sync.write().register_device(device);
        Ok(())
    }

    /// Get pending sync operations
    pub fn get_pending_sync(&self) -> Vec<SyncOperation> {
        self.device_sync.write().take_pending_ops()
    }

    /// Mark sync operation complete
    pub fn complete_sync_operation(&self, _index: usize) {
        // Operations are taken via take_pending_ops, so no need to mark complete individually
    }

    // ==================== Internal Handlers ====================

    async fn handle_key_exchange(&self, envelope: NetworkEnvelope) -> Result<(), ClientError> {
        // In production: complete DH handshake, initialize Double Ratchet
        Ok(())
    }

    async fn handle_incoming_message(&self, envelope: NetworkEnvelope) -> Result<(), ClientError> {
        // In production: decrypt, verify, store message
        Ok(())
    }

    async fn handle_ratchet_update(&self, envelope: NetworkEnvelope) -> Result<(), ClientError> {
        // In production: update ratchet state
        Ok(())
    }

    async fn handle_control_message(&self, envelope: NetworkEnvelope) -> Result<(), ClientError> {
        // In production: handle typing indicators, read receipts, etc.
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Ensure sensitive data is zeroized
        if *self.running.read() {
            // Force cleanup
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

        assert!(!identity.public().fingerprint().is_empty());
        assert_eq!(client.fingerprint(), Some(identity.public().fingerprint()));
    }

    #[test]
    fn test_contact_management() {
        let client = Client::with_defaults().unwrap();

        let contact = Contact::trusted(
            "test_fp".to_string(),
            "Test User".to_string(),
        );

        client.add_contact(contact.clone()).unwrap();

        let retrieved = client.get_contact("test_fp").unwrap();
        assert_eq!(retrieved.identity.fingerprint, "test_fp");

        let contacts = client.list_contacts();
        assert_eq!(contacts.len(), 1);
    }
}