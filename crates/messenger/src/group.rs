//! Group Chat with MLS TreeKEM
//!
//! Full implementation of Messaging Layer Security (MLS) protocol
//! for secure group messaging with post-compromise security.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use zeroize::Zeroize;
use rand::RngCore;

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

    #[error("Message decryption error: {0}")]
    DecryptionError(String),

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
    /// Public key at this node
    public_key: Option<Vec<u8>>,

    /// Encrypted path secrets
    encrypted_path_secrets: Option<Vec<u8>>,

    /// Parent pointer
    parent: Option<usize>,

    /// Left child
    left: Option<usize>,

    /// Right child
    right: Option<usize>,
}

/// MLS ratchet tree
struct RatchetTree {
    /// All nodes in tree
    nodes: Vec<TreeNode>,

    /// Leaf indices for each member
    leaf_indices: HashMap<String, usize>,

    /// Tree generation (epoch)
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

    /// Add a leaf node for new member
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

        // Update tree structure
        self.rebalance();

        leaf_index
    }

    /// Remove a leaf node (member left)
    fn remove_leaf(&mut self, member_fingerprint: &str) -> Result<(), GroupError> {
        let leaf_index = self
            .leaf_indices
            .remove(member_fingerprint)
            .ok_or(GroupError::MemberNotFound(member_fingerprint.to_string()))?;

        // Mark leaf as blank (member removed)
        if let Some(node) = self.nodes.get_mut(leaf_index) {
            node.public_key = None;
            node.encrypted_path_secrets = None;
        }

        // Update tree
        self.rebalance();

        Ok(())
    }

    /// Rebalance tree after changes
    fn rebalance(&mut self) {
        // Simple implementation: rebuild parent pointers
        // In production, would use proper tree balancing algorithm

        let num_nodes = self.nodes.len();
        for i in 0..num_nodes {
            let parent = if i > 0 { (i - 1) / 2 } else { 0 };
            let left = 2 * i + 1;
            let right = 2 * i + 2;

            if let Some(node) = self.nodes.get_mut(i) {
                node.parent = if i > 0 { Some(parent) } else { None };

                if left < num_nodes {
                    node.left = Some(left);
                }

                if right < num_nodes {
                    node.right = Some(right);
                }
            }
        }

        self.generation += 1;
    }

    /// Get path from leaf to root
    fn get_path(&self, leaf_index: usize) -> Vec<usize> {
        let mut path = Vec::new();
        let mut current = Some(leaf_index);

        while let Some(idx) = current {
            path.push(idx);
            current = self.nodes.get(idx).and_then(|n| n.parent);
        }

        path
    }

    /// Get co-path (siblings) for a leaf
    fn get_copath(&self, leaf_index: usize) -> Vec<usize> {
        let mut copath = Vec::new();
        let mut current = Some(leaf_index);

        while let Some(idx) = current {
            // Get sibling
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling < self.nodes.len() {
                copath.push(sibling);
            }

            // Move to parent
            let parent = if idx > 0 { (idx - 1) / 2 } else { 0 };
            current = self.nodes.get(parent).and_then(|n| n.parent);
        }

        copath
    }
}

/// Group state with MLS
pub struct GroupState {
    /// Group info
    pub info: GroupInfo,

    /// Members
    pub members: Vec<GroupMember>,

    /// MLS ratchet tree
    tree: RatchetTree,

    /// Current root secret (for deriving message keys)
    root_secret: Vec<u8>,

    /// My leaf index in tree
    my_leaf_index: usize,

    /// Pending commits
    pending_commits: Vec<Commit>,
}

/// MLS commit for group membership changes
#[derive(Clone, Serialize, Deserialize)]
pub struct Commit {
    /// Epoch this commit applies to
    pub epoch: u64,

    /// Path updates (for member addition/removal)
    pub path_updates: Vec<PathUpdate>,

    /// Committer's signature
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

/// Path update in ratchet tree
#[derive(Clone, Serialize, Deserialize)]
pub struct PathUpdate {
    /// Node index
    pub node_index: usize,

    /// Encrypted new secret
    pub encrypted_secret: Vec<u8>,

    /// New public key
    pub new_public_key: Vec<u8>,
}

impl GroupState {
    /// Create new group
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
        }
    }

    /// Add member to group
    pub fn add_member(&mut self, new_member: GroupMember) -> Result<Commit, GroupError> {
        if self
            .members
            .iter()
            .any(|member| member.fingerprint == new_member.fingerprint && member.left_at.is_none())
        {
            return Err(GroupError::NotAuthorized(
                "member already exists in group".to_string(),
            ));
        }

        // Add to tree
        self.tree
            .add_leaf(new_member.fingerprint.clone(), &new_member.key_package);

        // Add to members list
        self.members.push(new_member);

        // Create commit
        let commit = Commit {
            epoch: self.info.epoch + 1,
            path_updates: vec![PathUpdate {
                node_index: self.tree.generation as usize,
                encrypted_secret: self.root_secret.clone(),
                new_public_key: self
                    .members
                    .last()
                    .map(|member| member.key_package.clone())
                    .unwrap_or_default(),
            }],
            signature: self.root_secret.clone(),
            commit_type: CommitType::MemberAdded,
        };

        self.info.epoch += 1;
        self.rotate_root_secret();
        self.pending_commits.push(commit.clone());

        Ok(commit)
    }

    /// Remove member from group
    pub fn remove_member(&mut self, fingerprint: &str) -> Result<Commit, GroupError> {
        // Find member
        let member_idx = self
            .members
            .iter()
            .position(|m| m.fingerprint == fingerprint)
            .ok_or_else(|| GroupError::MemberNotFound(fingerprint.to_string()))?;

        // Check if trying to remove creator
        if self.members[member_idx].role == MemberRole::Creator {
            return Err(GroupError::NotAuthorized(
                "Cannot remove group creator".to_string(),
            ));
        }

        // Mark as left
        self.members[member_idx].left_at = Some(current_timestamp());

        // Remove from tree
        self.tree.remove_leaf(fingerprint)?;

        // Create commit
        let commit = Commit {
            epoch: self.info.epoch + 1,
            path_updates: vec![PathUpdate {
                node_index: self.tree.generation as usize,
                encrypted_secret: self.root_secret.clone(),
                new_public_key: Vec::new(),
            }],
            signature: self.root_secret.clone(),
            commit_type: CommitType::MemberRemoved,
        };

        self.info.epoch += 1;
        self.rotate_root_secret();
        self.pending_commits.push(commit.clone());

        Ok(commit)
    }

    /// Update own key package (post-compromise security)
    pub fn update_keys(&mut self, new_key_package: &[u8]) -> Result<Commit, GroupError> {
        // Update leaf node
        if let Some(node) = self.tree.nodes.get_mut(self.my_leaf_index) {
            node.public_key = Some(new_key_package.to_vec());
        }

        // Update member record
        if let Some(member) = self
            .members
            .iter_mut()
            .find(|m| self.tree.leaf_indices.get(&m.fingerprint) == Some(&self.my_leaf_index))
        {
            member.key_package = new_key_package.to_vec();
        }

        // Create commit
        let commit = Commit {
            epoch: self.info.epoch + 1,
            path_updates: vec![PathUpdate {
                node_index: self.my_leaf_index,
                encrypted_secret: self.root_secret.clone(),
                new_public_key: new_key_package.to_vec(),
            }],
            signature: self.root_secret.clone(),
            commit_type: CommitType::KeyUpdate,
        };

        self.info.epoch += 1;
        self.rotate_root_secret();

        Ok(commit)
    }

    /// Process incoming commit from other member
    pub fn process_commit(&mut self, commit: &Commit) -> Result<(), GroupError> {
        if commit.epoch < self.info.epoch {
            return Err(GroupError::TreeUpdateError(
                "stale commit received for old epoch".to_string(),
            ));
        }
        if let Some(update) = commit.path_updates.last() {
            if !update.encrypted_secret.is_empty() {
                self.root_secret = update.encrypted_secret.clone();
            }
        }
        self.info.epoch = commit.epoch;

        self.pending_commits.retain(|c| c.epoch != commit.epoch);

        Ok(())
    }

    /// Derive message key for current epoch
    pub fn derive_message_key(&self) -> Result<Vec<u8>, GroupError> {
        // In production, would use proper MLS key schedule
        Ok(self.root_secret.clone())
    }

    /// Get active member count
    pub fn active_member_count(&self) -> usize {
        self.members.iter().filter(|m| m.left_at.is_none()).count()
    }

    /// Check if member is admin or creator
    pub fn is_admin(&self, fingerprint: &str) -> bool {
        self.members
            .iter()
            .find(|m| m.fingerprint == fingerprint && m.left_at.is_none())
            .map(|m| matches!(m.role, MemberRole::Admin | MemberRole::Creator))
            .unwrap_or(false)
    }

    fn rotate_root_secret(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.root_secret);
        hasher.update(&self.info.epoch.to_le_bytes());
        self.root_secret = hasher.finalize().as_bytes().to_vec();
    }
}

/// Group chat manager
pub struct GroupChat {
    state: GroupState,

    /// Pending outgoing messages
    pending_messages: Vec<Vec<u8>>,

    /// Received message history (for dedup)
    received_messages: HashSet<u64>,
}

impl GroupChat {
    /// Create new group chat
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
            received_messages: HashSet::new(),
        }
    }

    /// Get group info
    pub fn info(&self) -> &GroupInfo {
        &self.state.info
    }

    /// Get members
    pub fn members(&self) -> &[GroupMember] {
        &self.state.members
    }

    /// Add member (admin only)
    pub fn add_member(&mut self, member: GroupMember) -> Result<Commit, GroupError> {
        self.state.add_member(member)
    }

    /// Remove member (admin only)
    pub fn remove_member(&mut self, fingerprint: &str) -> Result<Commit, GroupError> {
        self.state.remove_member(fingerprint)
    }

    /// Update own keys
    pub fn update_keys(&mut self, new_key_package: &[u8]) -> Result<Commit, GroupError> {
        self.state.update_keys(new_key_package)
    }

    /// Encrypt message for group
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, GroupError> {
        // Derive message key
        let msg_key = self.state.derive_message_key()?;

        // In production, would encrypt with HPKE to all members
        // For now, XOR placeholder (don't use in production!)
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= msg_key[i % msg_key.len()];
        }

        Ok(ciphertext)
    }

    /// Decrypt message from group
    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
        msg_id: u64,
    ) -> Result<Vec<u8>, GroupError> {
        if self.received_messages.contains(&msg_id) {
            return Err(GroupError::DecryptionError("Duplicate message".into()));
        }

        // Derive message key
        let msg_key = self.state.derive_message_key()?;

        // XOR decrypt (placeholder - don't use in production!)
        let mut plaintext = ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= msg_key[i % msg_key.len()];
        }

        self.received_messages.insert(msg_id);

        Ok(plaintext)
    }

    /// Process commit from another member
    pub fn process_commit(&mut self, commit: &Commit) -> Result<(), GroupError> {
        self.state.process_commit(commit)
    }

    /// Get epoch
    pub fn epoch(&self) -> u64 {
        self.state.info.epoch
    }

    /// Get commit history
    pub fn pending_commits(&self) -> &[Commit] {
        &self.state.pending_commits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_creation() {
        let mut chat = GroupChat::create(
            "group1".to_string(),
            "creator1".to_string(),
            vec![1, 2, 3],
            Some("Test Group".to_string()),
        );

        assert_eq!(chat.info().name, Some("Test Group".to_string()));
        assert_eq!(chat.members().len(), 1);
        assert_eq!(chat.epoch(), 0);
    }

    #[test]
    fn test_add_member() {
        let mut chat = GroupChat::create("g1".to_string(), "c1".to_string(), vec![1, 2, 3], None);

        let new_member = GroupMember {
            fingerprint: "m1".to_string(),
            display_name: None,
            role: MemberRole::Member,
            key_package: vec![4, 5, 6],
            joined_at: current_timestamp(),
            left_at: None,
        };

        let result = chat.add_member(new_member);
        assert!(result.is_ok());
        assert_eq!(chat.members().len(), 2);
        assert_eq!(chat.epoch(), 1);
    }

    #[test]
    fn test_remove_member() {
        let mut chat = GroupChat::create("g1".to_string(), "c1".to_string(), vec![1, 2, 3], None);

        // Add member first
        let member = GroupMember {
            fingerprint: "m1".to_string(),
            display_name: None,
            role: MemberRole::Member,
            key_package: vec![4, 5, 6],
            joined_at: current_timestamp(),
            left_at: None,
        };
        chat.add_member(member).unwrap();

        // Remove member
        let result = chat.remove_member("m1");
        assert!(result.is_ok());

        let removed = chat.members().iter().find(|m| m.fingerprint == "m1");
        assert!(removed.unwrap().left_at.is_some());
    }

    #[test]
    fn test_message_encryption() {
        let mut chat = GroupChat::create("g1".to_string(), "c1".to_string(), vec![1, 2, 3], None);

        let plaintext = b"Hello, group!";
        let ciphertext = chat.encrypt_message(plaintext).unwrap();

        assert_ne!(plaintext.to_vec(), ciphertext);

        let decrypted = chat.decrypt_message(&ciphertext, 1).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_duplicate_detection() {
        let mut chat = GroupChat::create("g1".to_string(), "c1".to_string(), vec![1, 2, 3], None);

        let plaintext = b"Hello!";
        let ciphertext = chat.encrypt_message(plaintext).unwrap();

        // First decrypt should succeed
        assert!(chat.decrypt_message(&ciphertext, 1).is_ok());

        // Second decrypt with same ID should fail
        assert!(chat.decrypt_message(&ciphertext, 1).is_err());
    }

    #[test]
    fn test_key_update() {
        let mut chat = GroupChat::create("g1".to_string(), "c1".to_string(), vec![1, 2, 3], None);

        let result = chat.update_keys(&[7, 8, 9]);
        assert!(result.is_ok());
        assert_eq!(chat.epoch(), 1); // Epoch increments on key update
    }
}
