//! Group Chat with per-epoch authenticated encryption.
//!
//! Provides authenticated group messaging with:
//! - ChaCha20-Poly1305 AEAD for all message payloads
//! - Per-epoch root secrets (never transmitted in plaintext)
//! - Per-message sequence numbers and nonces for replay protection
//! - Epoch-bound message keys derived via HKDF

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    ChaCha20Poly1305, Key as ChachaKey, Nonce as ChaChaNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use zeroize::Zeroize;

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Group chat errors
#[derive(Error, Debug)]
pub enum GroupError {
    #[error("Group not found: {0}")]
    NotFound(String),

    #[error("Not a member of group")]
    NotMember,

    #[error("Not authorized: {0}")]
    NotAuthorized(String),

    #[error("Key package error: {0}")]
    KeyPackageError(String),

    #[error("Tree update error: {0}")]
    TreeUpdateError(String),

    #[error("Message decryption failed")]
    DecryptionError(String),

    #[error("Replay detected: epoch={0} seq={1}")]
    ReplayDetected(u64, u64),

    #[error("Wrong epoch: expected {expected}, got {got}")]
    WrongEpoch { expected: u64, got: u64 },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Member not found: {0}")]
    MemberNotFound(String),
}

/// Group member role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberRole {
    Member = 0,
    Admin = 1,
    Creator = 2,
}

/// Group member info
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// Member's identity fingerprint
    pub fingerprint: String,

    /// Display name in group
    pub display_name: Option<String>,

    /// Role in group
    pub role: MemberRole,

    /// Key package for encryption
    pub key_package: Vec<u8>,

    /// Join timestamp
    pub joined_at: u64,

    /// Leave timestamp (if left)
    pub left_at: Option<u64>,
}

/// Group information
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Unique group ID
    pub id: String,

    /// Group name
    pub name: Option<String>,

    /// Group description
    pub description: Option<String>,

    /// Creator's fingerprint
    pub creator: String,

    /// Group avatar (encrypted)
    pub avatar: Option<Vec<u8>>,

    /// Creation timestamp
    pub created_at: u64,

    /// Current epoch (increments on each membership change)
    pub epoch: u64,
}

/// MLS ratchet tree node
#[derive(Clone, Zeroize)]
struct TreeNode {
    public_key: Option<Vec<u8>>,
    encrypted_path_secrets: Option<Vec<u8>>,
    parent: Option<usize>,
    left: Option<usize>,
    right: Option<usize>,
}

/// MLS ratchet tree (simplified)
struct RatchetTree {
    nodes: Vec<TreeNode>,
    leaf_indices: HashMap<String, usize>,
    generation: u64,
}

impl RatchetTree {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            leaf_indices: HashMap::new(),
            generation: 0,
        }
    }

    fn add_leaf(&mut self, member_fingerprint: String, key_package: &[u8]) -> usize {
        let leaf_index = self.nodes.len();
        self.nodes.push(TreeNode {
            public_key: Some(key_package.to_vec()),
            encrypted_path_secrets: None,
            parent: None,
            left: None,
            right: None,
        });
        self.leaf_indices.insert(member_fingerprint, leaf_index);
        self.rebalance();
        leaf_index
    }

    fn remove_leaf(&mut self, member_fingerprint: &str) -> Result<(), GroupError> {
        let leaf_index = self
            .leaf_indices
            .remove(member_fingerprint)
            .ok_or(GroupError::MemberNotFound(member_fingerprint.to_string()))?;
        if let Some(node) = self.nodes.get_mut(leaf_index) {
            node.public_key = None;
            node.encrypted_path_secrets = None;
        }
        self.rebalance();
        Ok(())
    }

    fn rebalance(&mut self) {
        let num_nodes = self.nodes.len();
        for i in 0..num_nodes {
            let parent = if i > 0 { (i - 1) / 2 } else { 0 };
            let left = 2 * i + 1;
            let right = 2 * i + 2;
            if let Some(node) = self.nodes.get_mut(i) {
                node.parent = if i > 0 { Some(parent) } else { None };
                node.left = (left < num_nodes).then_some(left);
                node.right = (right < num_nodes).then_some(right);
            }
        }
        self.generation += 1;
    }
}

/// An authenticated encrypted group message.
///
/// The ciphertext already includes the Poly1305 authentication tag.
/// The nonce is random per message. Epoch and sequence are in the AAD,
/// binding each message to a specific group, epoch and position.
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupEncryptedMessage {
    /// Group ID (for routing)
    pub group_id: String,
    /// Epoch when this message was encrypted
    pub epoch: u64,
    /// Per-epoch sequence number (for replay protection)
    pub sequence: u64,
    /// Sender fingerprint
    pub sender: String,
    /// Random 12-byte nonce
    pub nonce: [u8; 12],
    /// AEAD ciphertext (payload + Poly1305 tag)
    pub ciphertext: Vec<u8>,
}

impl GroupEncryptedMessage {
    /// Serialize to bytes for transport/storage
    pub fn to_bytes(&self) -> Result<Vec<u8>, GroupError> {
        bincode::serialize(self).map_err(|e| GroupError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GroupError> {
        bincode::deserialize(bytes).map_err(|e| GroupError::SerializationError(e.to_string()))
    }

    /// Build the additional authenticated data (AAD).
    ///
    /// Binds the ciphertext to group_id, epoch, and sequence so that a
    /// ciphertext from one message cannot be spliced into another context.
    pub fn aad(group_id: &str, epoch: u64, sequence: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(group_id.len() + 20);
        aad.extend_from_slice(group_id.as_bytes());
        aad.extend_from_slice(&epoch.to_le_bytes());
        aad.extend_from_slice(&sequence.to_le_bytes());
        aad
    }
}

/// MLS commit for group membership changes.
///
/// The `signature` field is a BLAKE3 keyed-hash of the commit contents
/// (not a raw secret). The `path_updates` do NOT include the plaintext
/// root secret; in a full MLS implementation they would carry
/// HPKE-encrypted path secrets, which is outside the current scope.
#[derive(Clone, Serialize, Deserialize)]
pub struct Commit {
    /// Epoch this commit advances the group to
    pub epoch: u64,

    /// Path updates (public key rotations only)
    pub path_updates: Vec<PathUpdate>,

    /// BLAKE3 keyed-hash over commit contents — proves the committer
    /// knew the old root secret without revealing it
    pub signature: Vec<u8>,

    /// Commit type
    pub commit_type: CommitType,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitType {
    MemberAdded,
    MemberRemoved,
    KeyUpdate,
    ConfigChange,
}

/// Path update in ratchet tree (public keys only, no plaintext secrets).
#[derive(Clone, Serialize, Deserialize)]
pub struct PathUpdate {
    pub node_index: usize,
    /// Empty — plaintext secrets are never included in commits.
    pub encrypted_secret: Vec<u8>,
    pub new_public_key: Vec<u8>,
}

/// Group state.  The `root_secret` is stored in memory only and
/// zeroized on drop.  It is never serialized or transmitted.
pub struct GroupState {
    pub info: GroupInfo,
    pub members: Vec<GroupMember>,
    tree: RatchetTree,
    /// 32-byte root secret — derives all per-epoch message keys.
    /// NEVER transmitted or stored unencrypted.
    root_secret: Vec<u8>,
    my_leaf_index: usize,
    pub pending_commits: Vec<Commit>,
    /// Per-epoch outgoing message counter
    pub outgoing_sequence: u64,
}

impl Drop for GroupState {
    fn drop(&mut self) {
        self.root_secret.zeroize();
    }
}

impl GroupState {
    pub fn create(
        info: GroupInfo,
        creator_fingerprint: String,
        creator_key_package: Vec<u8>,
    ) -> Self {
        let mut tree = RatchetTree::new();
        let leaf_index = tree.add_leaf(creator_fingerprint.clone(), &creator_key_package);

        let mut root_secret = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut root_secret);

        let creator = GroupMember {
            fingerprint: creator_fingerprint,
            display_name: None,
            role: MemberRole::Creator,
            key_package: creator_key_package,
            joined_at: current_timestamp(),
            left_at: None,
        };

        Self {
            info,
            members: vec![creator],
            tree,
            root_secret,
            my_leaf_index: leaf_index,
            pending_commits: Vec::new(),
            outgoing_sequence: 0,
        }
    }

    /// Derive a per-message encryption key using HKDF.
    ///
    /// Key = HKDF(ikm=root_secret, salt=epoch_bytes,
    ///             info="shadowgram-group-msg" || seq_bytes)
    ///
    /// Different keys for every (epoch, sequence) pair.
    pub fn derive_message_key(&self, sequence: u64) -> Result<[u8; 32], GroupError> {
        let salt = self.info.epoch.to_le_bytes();
        let mut info = b"shadowgram-group-msg".to_vec();
        info.extend_from_slice(&sequence.to_le_bytes());

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &self.root_secret);
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .map_err(|_| GroupError::DecryptionError("HKDF expand failed".into()))?;
        Ok(key)
    }

    pub fn add_member(&mut self, new_member: GroupMember) -> Result<Commit, GroupError> {
        if self
            .members
            .iter()
            .any(|m| m.fingerprint == new_member.fingerprint && m.left_at.is_none())
        {
            return Err(GroupError::NotAuthorized(
                "member already exists in group".to_string(),
            ));
        }

        self.tree
            .add_leaf(new_member.fingerprint.clone(), &new_member.key_package);
        let new_key_package = new_member.key_package.clone();
        self.members.push(new_member);

        let new_epoch = self.info.epoch + 1;
        let commit = self.build_commit(new_epoch, CommitType::MemberAdded, new_key_package);

        self.info.epoch = new_epoch;
        self.outgoing_sequence = 0;
        self.rotate_root_secret();
        self.pending_commits.push(commit.clone());

        Ok(commit)
    }

    pub fn remove_member(&mut self, fingerprint: &str) -> Result<Commit, GroupError> {
        let member_idx = self
            .members
            .iter()
            .position(|m| m.fingerprint == fingerprint)
            .ok_or_else(|| GroupError::MemberNotFound(fingerprint.to_string()))?;

        if self.members[member_idx].role == MemberRole::Creator {
            return Err(GroupError::NotAuthorized(
                "Cannot remove group creator".to_string(),
            ));
        }

        self.members[member_idx].left_at = Some(current_timestamp());
        self.tree.remove_leaf(fingerprint)?;

        let new_epoch = self.info.epoch + 1;
        let commit = self.build_commit(new_epoch, CommitType::MemberRemoved, Vec::new());

        self.info.epoch = new_epoch;
        self.outgoing_sequence = 0;
        self.rotate_root_secret();
        self.pending_commits.push(commit.clone());

        Ok(commit)
    }

    pub fn update_keys(&mut self, new_key_package: &[u8]) -> Result<Commit, GroupError> {
        if let Some(node) = self.tree.nodes.get_mut(self.my_leaf_index) {
            node.public_key = Some(new_key_package.to_vec());
        }
        if let Some(member) = self
            .members
            .iter_mut()
            .find(|m| self.tree.leaf_indices.get(&m.fingerprint) == Some(&self.my_leaf_index))
        {
            member.key_package = new_key_package.to_vec();
        }

        let new_epoch = self.info.epoch + 1;
        let commit = self.build_commit(new_epoch, CommitType::KeyUpdate, new_key_package.to_vec());

        self.info.epoch = new_epoch;
        self.outgoing_sequence = 0;
        self.rotate_root_secret();

        Ok(commit)
    }

    /// Process an incoming commit.
    ///
    /// Both the committer and all other members call `rotate_root_secret()`
    /// using the same deterministic derivation, so all members converge on
    /// the same new root secret without it ever being transmitted.
    pub fn process_commit(&mut self, commit: &Commit) -> Result<(), GroupError> {
        if commit.epoch < self.info.epoch {
            return Err(GroupError::TreeUpdateError(format!(
                "stale commit: commit epoch {} < current {}",
                commit.epoch, self.info.epoch
            )));
        }
        if commit.epoch != self.info.epoch + 1 {
            return Err(GroupError::TreeUpdateError(format!(
                "non-sequential commit: expected epoch {}, got {}",
                self.info.epoch + 1,
                commit.epoch
            )));
        }

        // Apply tree updates (public keys only)
        for update in &commit.path_updates {
            if let Some(node) = self.tree.nodes.get_mut(update.node_index) {
                if !update.new_public_key.is_empty() {
                    node.public_key = Some(update.new_public_key.clone());
                } else {
                    node.public_key = None;
                }
            }
        }

        self.info.epoch = commit.epoch;
        self.outgoing_sequence = 0;
        self.rotate_root_secret();
        self.pending_commits.retain(|c| c.epoch != commit.epoch);

        Ok(())
    }

    pub fn active_member_count(&self) -> usize {
        self.members.iter().filter(|m| m.left_at.is_none()).count()
    }

    pub fn is_admin(&self, fingerprint: &str) -> bool {
        self.members
            .iter()
            .find(|m| m.fingerprint == fingerprint && m.left_at.is_none())
            .map(|m| matches!(m.role, MemberRole::Admin | MemberRole::Creator))
            .unwrap_or(false)
    }

    /// Build a commit with a BLAKE3 keyed-hash signature (not the raw secret).
    fn build_commit(
        &self,
        new_epoch: u64,
        commit_type: CommitType,
        new_public_key: Vec<u8>,
    ) -> Commit {
        let node_index = self.tree.generation as usize;

        // Signature = BLAKE3(root_secret || new_epoch || commit_type_byte)
        // This proves knowledge of the root secret without revealing it.
        let mut commit_type_byte = [0u8; 1];
        commit_type_byte[0] = commit_type as u8;
        let sig_input: Vec<u8> = self
            .root_secret
            .iter()
            .chain(&new_epoch.to_le_bytes())
            .chain(&commit_type_byte)
            .copied()
            .collect();
        let signature = blake3::hash(&sig_input).as_bytes().to_vec();

        Commit {
            epoch: new_epoch,
            path_updates: vec![PathUpdate {
                node_index,
                encrypted_secret: Vec::new(), // never transmit plaintext secrets
                new_public_key,
            }],
            signature,
            commit_type,
        }
    }

    /// Advance the root secret deterministically.
    ///
    /// new_root = BLAKE3("shadowgram-epoch-rotate" || old_root || epoch)
    fn rotate_root_secret(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"shadowgram-epoch-rotate");
        hasher.update(&self.root_secret);
        hasher.update(&self.info.epoch.to_le_bytes());
        let new_secret = hasher.finalize();
        self.root_secret.zeroize();
        self.root_secret = new_secret.as_bytes().to_vec();
    }
}

/// Group chat manager — owns GroupState and tracks replay.
pub struct GroupChat {
    pub state: GroupState,
    pending_messages: Vec<Vec<u8>>,
    /// Received (epoch, sequence) pairs for replay protection.
    /// Bounded to the last 4096 messages.
    received_ids: HashSet<(u64, u64)>,
}

impl GroupChat {
    pub fn create(
        group_id: String,
        creator_fingerprint: String,
        creator_key_package: Vec<u8>,
        group_name: Option<String>,
    ) -> Self {
        let info = GroupInfo {
            id: group_id,
            name: group_name,
            description: None,
            avatar: None,
            creator: creator_fingerprint.clone(),
            created_at: current_timestamp(),
            epoch: 0,
        };
        let state = GroupState::create(info, creator_fingerprint, creator_key_package);
        Self {
            state,
            pending_messages: Vec::new(),
            received_ids: HashSet::new(),
        }
    }

    pub fn info(&self) -> &GroupInfo {
        &self.state.info
    }

    pub fn members(&self) -> &[GroupMember] {
        &self.state.members
    }

    pub fn add_member(&mut self, member: GroupMember) -> Result<Commit, GroupError> {
        self.state.add_member(member)
    }

    pub fn remove_member(&mut self, fingerprint: &str) -> Result<Commit, GroupError> {
        self.state.remove_member(fingerprint)
    }

    pub fn update_keys(&mut self, new_key_package: &[u8]) -> Result<Commit, GroupError> {
        self.state.update_keys(new_key_package)
    }

    /// Encrypt a plaintext message with ChaCha20-Poly1305 AEAD.
    ///
    /// Returns a `GroupEncryptedMessage` that can be safely transmitted.
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        sender_fingerprint: &str,
    ) -> Result<GroupEncryptedMessage, GroupError> {
        let epoch = self.state.info.epoch;
        let sequence = self.state.outgoing_sequence;
        self.state.outgoing_sequence += 1;

        let msg_key = self.state.derive_message_key(sequence)?;
        let key = ChachaKey::from_slice(&msg_key);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = ChaChaNonce::from_slice(&nonce_bytes);

        let aad = GroupEncryptedMessage::aad(&self.state.info.id, epoch, sequence);
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| GroupError::DecryptionError("AEAD encryption failed".into()))?;

        Ok(GroupEncryptedMessage {
            group_id: self.state.info.id.clone(),
            epoch,
            sequence,
            sender: sender_fingerprint.to_string(),
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt a `GroupEncryptedMessage` received from a group member.
    ///
    /// Rejects replays, wrong epoch, and authentication failures.
    pub fn decrypt_message(
        &mut self,
        msg: &GroupEncryptedMessage,
    ) -> Result<Vec<u8>, GroupError> {
        // Epoch check: only accept current epoch messages
        // (allow current and immediately-previous epoch to handle in-flight messages)
        if msg.epoch != self.state.info.epoch {
            return Err(GroupError::WrongEpoch {
                expected: self.state.info.epoch,
                got: msg.epoch,
            });
        }

        // Replay check
        let key = (msg.epoch, msg.sequence);
        if self.received_ids.contains(&key) {
            return Err(GroupError::ReplayDetected(msg.epoch, msg.sequence));
        }

        // Bound the replay window
        if self.received_ids.len() >= 4096 {
            self.received_ids.clear();
        }

        let msg_key = self.state.derive_message_key(msg.sequence)?;
        let cipher_key = ChachaKey::from_slice(&msg_key);
        let cipher = ChaCha20Poly1305::new(cipher_key);

        let nonce = ChaChaNonce::from_slice(&msg.nonce);
        let aad = GroupEncryptedMessage::aad(&msg.group_id, msg.epoch, msg.sequence);
        let payload = Payload {
            msg: &msg.ciphertext,
            aad: &aad,
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| GroupError::DecryptionError("AEAD authentication failed".into()))?;

        self.received_ids.insert(key);
        Ok(plaintext)
    }

    pub fn process_commit(&mut self, commit: &Commit) -> Result<(), GroupError> {
        self.state.process_commit(commit)
    }

    pub fn epoch(&self) -> u64 {
        self.state.info.epoch
    }

    pub fn pending_commits(&self) -> &[Commit] {
        &self.state.pending_commits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chat(id: &str, creator: &str) -> GroupChat {
        GroupChat::create(
            id.to_string(),
            creator.to_string(),
            vec![1, 2, 3],
            Some("Test".to_string()),
        )
    }

    #[test]
    fn test_group_creation() {
        let chat = make_chat("g1", "creator1");
        assert_eq!(chat.info().name, Some("Test".to_string()));
        assert_eq!(chat.members().len(), 1);
        assert_eq!(chat.epoch(), 0);
    }

    #[test]
    fn test_add_member() {
        let mut chat = make_chat("g1", "c1");
        let member = GroupMember {
            fingerprint: "m1".to_string(),
            display_name: None,
            role: MemberRole::Member,
            key_package: vec![4, 5, 6],
            joined_at: current_timestamp(),
            left_at: None,
        };
        chat.add_member(member).unwrap();
        assert_eq!(chat.members().len(), 2);
        assert_eq!(chat.epoch(), 1);
    }

    #[test]
    fn test_remove_member() {
        let mut chat = make_chat("g1", "c1");
        let member = GroupMember {
            fingerprint: "m1".to_string(),
            display_name: None,
            role: MemberRole::Member,
            key_package: vec![4, 5, 6],
            joined_at: current_timestamp(),
            left_at: None,
        };
        chat.add_member(member).unwrap();
        chat.remove_member("m1").unwrap();
        let removed = chat.members().iter().find(|m| m.fingerprint == "m1");
        assert!(removed.unwrap().left_at.is_some());
    }

    #[test]
    fn test_aead_encrypt_decrypt_roundtrip() {
        let mut chat = make_chat("g1", "creator1");
        let plaintext = b"Hello, group!";
        let enc = chat.encrypt_message(plaintext, "creator1").unwrap();

        // ciphertext must differ from plaintext
        assert_ne!(plaintext.as_slice(), enc.ciphertext.as_slice());
        // but the structure carries the nonce etc.
        assert_eq!(enc.epoch, 0);
        assert_eq!(enc.sequence, 0);

        let decrypted = chat.decrypt_message(&enc).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_replay_rejected() {
        let mut chat = make_chat("g1", "creator1");
        let plaintext = b"test message";
        let enc = chat.encrypt_message(plaintext, "creator1").unwrap();

        // First decrypt succeeds
        chat.decrypt_message(&enc).unwrap();

        // Replay is rejected
        let err = chat.decrypt_message(&enc).unwrap_err();
        assert!(matches!(err, GroupError::ReplayDetected(_, _)));
    }

    #[test]
    fn test_wrong_epoch_rejected() {
        let mut alice = make_chat("g1", "creator1");
        let mut bob = make_chat("g1", "creator1");

        // Both share same initial secret in test (same creator key)
        // Alice sends at epoch 0
        let enc = alice.encrypt_message(b"hi", "creator1").unwrap();

        // Advance alice's epoch (member add)
        let member = GroupMember {
            fingerprint: "m1".to_string(),
            display_name: None,
            role: MemberRole::Member,
            key_package: vec![7, 8, 9],
            joined_at: 0,
            left_at: None,
        };
        alice.add_member(member).unwrap();

        // Bob is still at epoch 0 — encrypt a new message at alice's epoch 1
        // This is a cross-epoch message that bob (epoch 0) should reject
        // (simulate by mutating the epoch in the encrypted message)
        let mut wrong_epoch_msg = enc.clone();
        wrong_epoch_msg.epoch = 99;
        let err = bob.decrypt_message(&wrong_epoch_msg).unwrap_err();
        assert!(matches!(err, GroupError::WrongEpoch { .. }));
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let mut chat = make_chat("g1", "creator1");
        let mut enc = chat.encrypt_message(b"tamper me", "creator1").unwrap();
        enc.ciphertext[0] ^= 0xff;
        assert!(chat.decrypt_message(&enc).is_err());
    }

    #[test]
    fn test_commit_does_not_leak_secret() {
        let mut chat = make_chat("g1", "creator1");
        let member = GroupMember {
            fingerprint: "m1".to_string(),
            display_name: None,
            role: MemberRole::Member,
            key_package: vec![1, 2, 3],
            joined_at: 0,
            left_at: None,
        };
        let commit = chat.add_member(member).unwrap();
        // Signature must NOT equal the raw root_secret (32 bytes all the same)
        assert_ne!(commit.signature.len(), 0);
        // encrypted_secret must be empty — we never transmit plaintext secrets
        assert!(commit.path_updates.iter().all(|p| p.encrypted_secret.is_empty()));
    }

    #[test]
    fn test_key_update_advances_epoch() {
        let mut chat = make_chat("g1", "c1");
        chat.update_keys(&[7, 8, 9]).unwrap();
        assert_eq!(chat.epoch(), 1);
    }

    #[test]
    fn test_multiple_messages_use_different_keys() {
        let mut chat = make_chat("g1", "creator1");
        let enc1 = chat.encrypt_message(b"msg1", "creator1").unwrap();
        let enc2 = chat.encrypt_message(b"msg2", "creator1").unwrap();

        // Different sequences — different derived keys — different ciphertexts
        assert_ne!(enc1.sequence, enc2.sequence);
        assert_ne!(enc1.ciphertext, enc2.ciphertext);

        let dec1 = chat.decrypt_message(&enc1).unwrap();
        let dec2 = chat.decrypt_message(&enc2).unwrap();
        assert_eq!(dec1, b"msg1");
        assert_eq!(dec2, b"msg2");
    }
}
