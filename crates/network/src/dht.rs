//! DHT-based Peer Discovery
//!
//! Kademlia-like distributed hash table for finding peers
//! without a central directory. Identities are looked up
//! by their fingerprint hash.
//!
//! Features:
//! - Decentralized peer discovery
//! - No global contact directory
//! - Nodes can come and go
//! - Replica sets for redundancy

use libp2p::{
    kad::{Event as KademliaEvent, RecordKey},
    multiaddr::{Multiaddr, Protocol},
    PeerId,
};
use std::collections::HashMap;
use thiserror::Error;

/// DHT errors
#[derive(Error, Debug)]
pub enum DhtError {
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Lookup failed: {0}")]
    LookupFailed(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid peer ID: {0}")]
    InvalidPeerId(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// DHT configuration
#[derive(Clone)]
pub struct DhtConfig {
    /// Alpha parameter (parallelism)
    pub alpha: usize,

    /// K value (bucket size)
    pub k_bucket_size: usize,

    /// Record replication factor
    pub replication_factor: usize,

    /// Provider record TTL
    pub provider_ttl: std::time::Duration,

    /// Record TTL
    pub record_ttl: Option<std::time::Duration>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            alpha: 3,              // 3 parallel queries
            k_bucket_size: 20,     // Standard Kademlia K
            replication_factor: 3, // Replicate to 3 closest nodes
            provider_ttl: std::time::Duration::from_secs(3600),
            record_ttl: Some(std::time::Duration::from_secs(86400)), // 24 hours
        }
    }
}

/// DHT node for peer discovery
pub struct DhtNode {
    /// Our peer ID
    peer_id: PeerId,

    /// Kademlia instance (wrapped in Swarm in production)
    config: DhtConfig,

    /// Known peers and their addresses
    known_peers: HashMap<PeerId, Vec<Multiaddr>>,

    /// Pending lookups
    pending_lookups: HashMap<String, tokio::sync::oneshot::Sender<Result<PeerInfo, DhtError>>>,
}

impl DhtNode {
    /// Create new DHT node
    pub fn new(config: DhtConfig) -> Result<Self, DhtError> {
        // Generate random peer ID (in production, derive from identity)
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(local_key.public());

        Ok(Self {
            peer_id,
            config,
            known_peers: HashMap::new(),
            pending_lookups: HashMap::new(),
        })
    }

    /// Get our peer ID
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Add a known peer
    pub fn add_peer(&mut self, peer_id: PeerId, address: Multiaddr) {
        self.known_peers
            .entry(peer_id)
            .or_insert_with(Vec::new)
            .push(address);
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.known_peers.remove(&peer_id);
    }

    /// Get known peers count
    pub fn known_peers_count(&self) -> usize {
        self.known_peers.len()
    }

    /// Lookup a peer by identity fingerprint
    pub async fn lookup_peer(&mut self, fingerprint: &[u8]) -> Result<PeerInfo, DhtError> {
        // Convert fingerprint to record key
        let _key = RecordKey::new(&fingerprint.to_vec());

        // In production, would use the actual Kademlia swarm
        // For now, check known peers

        // Simulate lookup - in production this would query the DHT
        let fake_peer_id = PeerId::from_bytes(fingerprint).unwrap_or(self.peer_id);

        if let Some(addrs) = self.known_peers.get(&fake_peer_id) {
            Ok(PeerInfo {
                peer_id: fake_peer_id,
                addresses: addrs.clone(),
                last_seen: std::time::SystemTime::now(),
            })
        } else {
            Err(DhtError::PeerNotFound(hex::encode(fingerprint)))
        }
    }

    /// Publish our own peer info to DHT
    pub fn publish_self(&mut self, addresses: Vec<Multiaddr>) {
        for addr in addresses {
            self.add_peer(self.peer_id, addr);
        }
        // In production: would actually put record to DHT
    }

    /// Start lookup with callback
    pub fn start_lookup(
        &mut self,
        fingerprint: Vec<u8>,
        callback: tokio::sync::oneshot::Sender<Result<PeerInfo, DhtError>>,
    ) {
        let key = hex::encode(&fingerprint);
        self.pending_lookups.insert(key, callback);

        // In production: initiate actual DHT query
    }

    /// Process DHT events (called by event loop in production)
    pub fn process_event(&mut self, _event: KademliaEvent) {
        // Handle Kademlia events in production
    }

    /// Get routing table statistics
    pub fn routing_table_stats(&self) -> RoutingTableStats {
        let mut bucket_sizes = Vec::new();

        // In production, would get actual bucket sizes
        bucket_sizes.push(self.known_peers.len());

        RoutingTableStats {
            total_peers: self.known_peers.len(),
            bucket_sizes,
            nearest_bucket: 0,
        }
    }
}

/// Peer information stored in DHT
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: PeerId,

    /// Known addresses
    pub addresses: Vec<Multiaddr>,

    /// Last seen timestamp
    pub last_seen: std::time::SystemTime,
}

impl PeerInfo {
    /// Create new peer info
    pub fn new(peer_id: PeerId, addresses: Vec<Multiaddr>) -> Self {
        Self {
            peer_id,
            addresses,
            last_seen: std::time::SystemTime::now(),
        }
    }

    /// Check if peer has onion address
    pub fn has_onion_address(&self) -> bool {
        self.addresses.iter().any(|address| {
            address
                .iter()
                .any(|protocol| matches!(protocol, Protocol::Onion(_, _) | Protocol::Onion3(_)))
                || address.to_string().contains(".onion")
        })
    }

    /// Get first onion address if available
    pub fn onion_address(&self) -> Option<&Multiaddr> {
        self.addresses.iter().find(|address| {
            address
                .iter()
                .any(|protocol| matches!(protocol, Protocol::Onion(_, _) | Protocol::Onion3(_)))
                || address.to_string().contains(".onion")
        })
    }
}

/// Routing table statistics
pub struct RoutingTableStats {
    pub total_peers: usize,
    pub bucket_sizes: Vec<usize>,
    pub nearest_bucket: usize,
}

/// High-level peer discovery interface
pub struct PeerDiscovery {
    dht: DhtNode,

    /// Identity fingerprint for lookups
    our_fingerprint: Vec<u8>,

    /// Discovered peers cache
    discovered_peers: HashMap<String, PeerInfo>,
}

impl PeerDiscovery {
    /// Create new peer discovery
    pub fn new(our_fingerprint: &[u8]) -> Result<Self, DhtError> {
        let dht = DhtNode::new(DhtConfig::default())?;

        Ok(Self {
            dht,
            our_fingerprint: our_fingerprint.to_vec(),
            discovered_peers: HashMap::new(),
        })
    }

    /// Add a discovered peer to cache
    pub fn add_discovered_peer(&mut self, fingerprint: String, info: PeerInfo) {
        self.discovered_peers.insert(fingerprint, info);
    }

    /// Find peer by fingerprint (checks cache first, then DHT)
    pub async fn find_peer(&mut self, fingerprint: &[u8]) -> Result<Option<PeerInfo>, DhtError> {
        let key = hex::encode(fingerprint);

        // Check cache first
        if let Some(info) = self.discovered_peers.get(&key) {
            return Ok(Some(info.clone()));
        }

        // Query DHT
        match self.dht.lookup_peer(fingerprint).await {
            Ok(info) => {
                self.discovered_peers.insert(key, info.clone());
                Ok(Some(info))
            }
            Err(DhtError::PeerNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Publish our presence to DHT
    pub fn announce(&mut self, addresses: Vec<Multiaddr>) {
        self.dht.publish_self(addresses);
    }

    /// Get cache size
    pub fn cache_size(&self) -> usize {
        self.discovered_peers.len()
    }

    /// Clear stale entries from cache
    pub fn prune_cache(&mut self, max_age: std::time::Duration) {
        let _now = std::time::SystemTime::now();

        self.discovered_peers.retain(|_, info| {
            info.last_seen.elapsed().unwrap_or(std::time::Duration::MAX) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_node_creation() {
        let node = DhtNode::new(DhtConfig::default()).unwrap();
        assert!(!node.peer_id().to_bytes().is_empty());
    }

    #[test]
    fn test_peer_lookup_cache() {
        let mut discovery = PeerDiscovery::new(b"test_fingerprint").unwrap();

        // Add peer to cache
        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8080".parse().unwrap();
        let info = PeerInfo::new(peer_id, vec![addr.clone()]);

        discovery.add_discovered_peer("test_key".to_string(), info.clone());

        assert_eq!(discovery.cache_size(), 1);
    }

    #[test]
    fn test_peer_info_onion_check() {
        let peer_id = PeerId::random();

        // Non-onion address
        let addr1: Multiaddr = "/ip4/127.0.0.1/tcp/8080".parse().unwrap();
        let info1 = PeerInfo::new(peer_id, vec![addr1]);
        assert!(!info1.has_onion_address());

        // Onion address
        let addr2: Multiaddr =
            "/onion3/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:8080"
                .parse()
                .unwrap();
        let info2 = PeerInfo::new(peer_id, vec![addr2]);
        assert!(info2.has_onion_address());
    }
}
