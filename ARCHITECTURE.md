# Shadowgram - Ultimate Privacy Messenger

## Architecture Specification & Design Document

**Version:** 0.1.0  
**Status:** Active Development  
**Classification:** Open Source - Security Critical

---

## 1. Executive Summary

Shadowgram is a research-grade privacy messenger designed to minimize trust and metadata exposure. The system targets state-level network adversaries and defends against traffic analysis, metadata collection, and endpoint compromise. It merges ideas from Tor, Signal's Double Ratchet, MLS, SimpleX, Session, Briar, Loopix mixnets, and threshold cryptography.

### Core Principles

1. **No Trust Required** - No phone numbers, emails, or central identity providers
2. **Metadata Minimization** - Hide who talks to whom, when, and how much
3. **Post-Quantum Security** - Hybrid classical + PQ algorithms from day one
4. **Local-First** - All data stored locally, encrypted, with optional multi-device sync
5. **Plausible Deniability** - Deniable authentication, no persistent certificates
6. **Reproducible Builds** - Full audit chain from source to binary

---

## 2. Threat Model

### Primary Adversary: State-Level Network Observer

| Capability | Defense |
|------------|---------|
| Full packet capture at ISP level | Tor onion routing + mixnet layer |
| Traffic analysis (timing, volume) | Constant padding, cover traffic, random delays |
| Global passive adversary (GPA) | Multi-path routing, hidden service rendezvous |
| Compelled service provider logs | No central provider, no logs to compel |
| Quantum computer decryption | ML-KEM-768 hybrid key exchange |

### Secondary Adversary: Targeted Attacker

| Capability | Defense |
|------------|---------|
| Stalking via correlation | Pairwise pseudonyms per contact |
| Identity linkage attacks | Automatic identity rotation |
| Contact list enumeration | Private Set Intersection discovery |
| Metadata from backups | Encrypted local storage, no cloud |

### Tertiary Adversary: Endpoint Compromise

| Capability | Defense |
|------------|---------|
| Memory scraping | Zeroization on drop, arena allocation |
| Key theft | Hardware-backed storage (TPM/Secure Enclave) |
| Malware keylogging | Future: TEE-based key isolation |
| Device seizure | Ephemeral messages, deniable decryption |

### Out of Scope

- Physical coercion (rubber-hose cryptanalysis)
- Compromised build infrastructure (mitigated by reproducible builds)
- Zero-day exploits in dependencies (mitigated by minimal TCB)

---

## 3. System Architecture

### 3.1 High-Level Components

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Tauri Frontend                                │
│                    React + TypeScript + WebAssembly                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐   │
│  │   Chat UI   │ │  Contacts   │ │  Settings   │ │  Security UI    │   │
│  │  Components │ │    QR Scan  │ │   Advanced  │ │  Status/Monitor │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────────┘   │
├─────────────────────────────────────────────────────────────────────────┤
│                              IPC Bridge                                 │
│                    Tauri Commands ↔ Rust Core API                       │
├─────────────────────────────────────────────────────────────────────────┤
│                        Rust Core Library                                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                     Messenger API Layer                          │  │
│  │  Client  │  Chat   │  Group  │  Message  │  Contacts  │  Sync   │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │                     Protocol Stack                               │  │
│  │  Double Ratchet  │  MLS TreeKEM  │  Key Derivation  │  AEAD     │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │                     Identity Layer                               │  │
│  │  Key Generation  │  Rotation  │  Pairwise IDs  │  Threshold     │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │                     Network Layer                                │  │
│  │  Tor (Arti)  │  Mixnet  │  DHT  │  Padding  │  Cover Traffic    │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │                     Storage Layer                                │  │
│  │  SQLCipher  │  Encrypted Cache  │  Zeroization  │  Backup       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Crate Structure

```
shadowgram/
├── Cargo.toml                    # Workspace root
├── ARCHITECTURE.md               # This document
├── SECURITY.md                   # Security policies, audit reports
├── crates/
│   ├── crypto/                   # Phase 1: Cryptographic core
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── key_exchange.rs   # X25519 + ML-KEM-768
│   │       ├── double_ratchet.rs # Signal protocol
│   │       ├── mls.rs            # MLS TreeKEM for groups
│   │       ├── aead.rs           # ChaCha20-Poly1305 / AES-GCM
│   │       ├── kdf.rs            # HKDF, key derivation
│   │       └── keys/             # Key management
│   │           ├── mod.rs
│   │           ├── store.rs
│   │           ├── rotation.rs
│   │           └── zeroize.rs
│   │
│   ├── identity/                 # Phase 2: Identity system
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── identity.rs       # Identity generation, serialization
│   │       ├── pairwise.rs       # Pairwise pseudonyms
│   │       ├── qr.rs             # QR code gen/parse
│   │       ├── threshold.rs      # Shamir Secret Sharing
│   │       └── rotation.rs       # Automatic rotation
│   │
│   ├── network/                  # Phase 3: Anonymous transport
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── tor.rs            # Arti-based Tor client
│   │       ├── mixnet.rs         # Loopix-style mixnet
│   │       ├── dht.rs            # Kademlia DHT
│   │       ├── relay.rs          # Multi-path routing
│   │       ├── padding.rs        # Constant-size packets
│   │       ├── cover_traffic.rs  # Dummy messages
│   │       └── transports/       # Pluggable transports
│   │
│   ├── messenger/                # Phase 4: Messaging protocol
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── client.rs         # Main client API
│   │       ├── chat.rs           # 1-on-1 chat state machine
│   │       ├── group.rs          # MLS group chat
│   │       ├── message.rs        # Message envelopes
│   │       ├── contacts.rs       # Contact discovery, PSI
│   │       └── sync.rs           # Multi-device sync
│   │
│   ├── storage/                  # Phase 5: Secure storage
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── database.rs       # SQLCipher wrapper
│   │       ├── schema.rs         # Database schema
│   │       ├── encrypted_cache.rs
│   │       └── zeroize.rs
│   │
│   └── tauri-backend/            # Phase 6: Tauri integration
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── commands.rs       # IPC handlers
│           └── state.rs          # Tauri app state
│
├── src/                          # React + TypeScript frontend
│   ├── components/
│   ├── hooks/
│   ├── stores/
│   └── App.tsx
│
└── src-tauri/                    # Tauri configuration
    ├── Cargo.toml
    ├── tauri.conf.json
    ├── capabilities/
    └── icons/
```

---

## 4. Protocol Specifications

### 4.1 Identity Layer

#### Identity Generation

```rust
pub struct Identity {
    /// Long-term identity keypair (X25519)
    pub identity_key: Keypair,
    
    /// Signed prekey for initial handshake
    pub signed_prekey: Keypair,
    pub signed_prekey_signature: Signature,
    
    /// One-time prekeys (batch of 100)
    pub one_time_prekeys: Vec<Keypair>,
    
    /// ML-KEM-768 decapsulation keypair
    pub pq_keypair: KyberKeypair,
    
    /// Public identity hash (for QR codes)
    pub public_id: PublicIdentity,
}

pub struct PublicIdentity {
    /// BLAKE3 hash of identity public key
    pub fingerprint: [u8; 32],
    
    /// Human-readable fingerprint (Base64, 8 chars)
    pub display_id: String,
    
    /// Full serialized public identity (for QR)
    pub qr_data: Vec<u8>,
}
```

#### Pairwise Pseudonyms

Each contact sees a different identity:

```rust
/// Derive pairwise pseudonym for a specific contact
pub fn derive_pairwise_id(
    our_identity: &Identity,
    their_public_id: &PublicIdentity
) -> PairwiseIdentity {
    // HKDF-expand with both identities as salt/info
    // Produces unique X25519 keypair per (us, them) pair
}
```

### 4.2 Key Exchange: X25519 + ML-KEM-768 Hybrid

```
Initiator                              Responder
    │                                      │
    │────── X25519 pubkey (ephemeral) ────│
    │────── ML-KEM encapsulation ──────────│
    │         (encapsulates shared secret) │
    │                                      │
    │◄───── X25519 pubkey (ephemeral) ─────│
    │◄───── ML-KEM ciphertext ─────────────│
    │                                      │
    │  Compute shared secret:              │
    │  1. X25519: ECDH(our_priv, their_pub)
    │  2. ML-KEM: Decapsulate their_ciphertext
    │  3. HKDF-SHA256(x25519_ss || kyber_ss || transcript)
    │                                      │
    │         ← Double Ratchet initialized →
```

### 4.3 Double Ratchet

Based on Signal Protocol, with PQ hybrid:

```rust
pub struct DoubleRatchet {
    /// Root chain key (updated each ratchet step)
    root_key: ChainKey,
    
    /// Sending chain (DH ratchet + symmetric chain)
    sending_dh: DhKeyPair,
    sending_chain: SymmetricChain,
    
    /// Receiving chain (from remote's DH public key)
    receiving_dh: PublicKey,
    receiving_chain: SymmetricChain,
    
    /// Message keys buffer (for out-of-order delivery)
    skipped_keys: HashMap<MessageNumber, MessageKey>,
}

impl DoubleRatchet {
    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) 
        -> (MessageHeader, Ciphertext) 
    {
        // 1. Ratchet if needed
        // 2. Derive message key from sending chain
        // 3. Encrypt with ChaCha20-Poly1305
        // 4. Return header + ciphertext
    }
    
    /// Decrypt a message
    pub fn decrypt(&mut self, header: &MessageHeader, ciphertext: &[u8]) 
        -> Result<Vec<u8>> 
    {
        // 1. Perform DH ratchet if sender chain changed
        // 2. Derive/skip message keys as needed
        // 3. Decrypt and verify
        // 4. Zeroize all intermediates
    }
}
```

### 4.4 MLS TreeKEM for Groups

For group chats (3+ participants):

- **Key Encapsulation**: Each member holds leaf node in ratchet tree
- **Update Messages**: Member generates path update, broadcasts
- **Forward Secrecy**: Compromised member excluded → all future keys safe
- **Post-Compromise Security**: One update heals the tree

### 4.5 Message Envelope

```rust
pub struct MessageEnvelope {
    /// Version byte
    pub version: u8,
    
    /// Type: 1=handshake, 2=ratchet, 3=message, 4=control
    pub message_type: u8,
    
    /// Sender's identity (pairwise pseudonym)
    pub sender_id: [u8; 32],
    
    /// Conversation identifier
    pub conversation_id: [u8; 32],
    
    /// Message sequence number
    pub sequence: u64,
    
    /// Ratchet level (for out-of-order handling)
    pub ratchet_level: u32,
    
    /// Encrypted payload
    pub ciphertext: Vec<u8>,
    
    /// Auth tag (Poly1305)
    pub auth_tag: [u8; 16],
    
    /// Padding (to constant size)
    pub padding: Vec<u8>,
}
```

---

## 5. Network Layer

### 5.1 Tor Integration (Arti)

Using Arti (pure Rust Tor implementation):

```rust
use arti_client::{TorClient, TorClientConfig};

pub struct TorTransport {
    client: TorClient,
}

impl TorTransport {
    pub async fn new() -> Result<Self> {
        let config = TorClientConfig::default();
        let client = TorClient::create_bootstrapped(config).await?;
        Ok(Self { client })
    }
    
    pub async fn connect_onion(&self, onion_addr: &str) -> Result<Stream> {
        // Connect to .onion hidden service
        self.client.connect(onion_addr).await
    }
}
```

### 5.2 Mixnet Design (Minimal Loopix)

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│  Entry  │ ──▶ │  Mix    │ ──▶ │  Exit   │
│  Node   │     │  Node   │     │  Node   │
└─────────┘     └─────────┘     └─────────┘
     ▲                                  │
     │                                  ▼
┌─────────┐                       ┌──────────┐
│ Sender  │                       │ Receiver │
└─────────┘                       └──────────┘

Each node:
- Buffer messages in FIFO queue
- Delay each message by random exponential
- Reorder/rerandomize before forwarding
- Add/drop cover traffic
```

### 5.3 DHT for Peer Discovery

Kademlia-like DHT:

```rust
pub struct DhtNode {
    /// Our node ID (SHA256 of public identity)
    node_id: [u8; 32],
    
    /// Routing table (buckets by XOR distance)
    buckets: Vec<KBucket>,
    
    /// Known peers and their onion addresses
    peer_store: HashMap<NodeId, PeerInfo>,
}

pub fn lookup_identity(public_id_hash: [u8; 32]) -> Option<OnionAddress> {
    // Kademlia ITERATIVE_FIND_NODE
    // Returns onion address where this identity can be reached
}
```

### 5.4 Traffic Analysis Defenses

| Technique | Implementation |
|-----------|----------------|
| Constant packet size | Pad all packets to 64KB or drop |
| Cover traffic | Send dummy messages at random intervals |
| Random delays | Exponential delay distribution per-hop |
| Multi-path | Send same message via 2-3 relays |

---

## 6. Storage Layer

### 6.1 Database Schema (SQLCipher)

```sql
-- Identities
CREATE TABLE identities (
    id TEXT PRIMARY KEY,
    private_key_encrypted BLOB NOT NULL,
    public_key BLOB NOT NULL,
    pq_private_encrypted BLOB,
    pq_public BLOB,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER
);

-- Contacts
CREATE TABLE contacts (
    id TEXT PRIMARY KEY,
    alias TEXT,
    public_identity BLOB NOT NULL,
    pairwise_id_ours BLOB,
    trust_level INTEGER DEFAULT 0,
    added_at INTEGER NOT NULL
);

-- Conversations
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    type INTEGER NOT NULL,  -- 1=direct, 2=group
    peer_id TEXT REFERENCES contacts(id),
    our_identity_id TEXT REFERENCES identities(id),
    ratchet_state BLOB,
    last_message_at INTEGER
);

-- Messages (encrypted at application layer)
CREATE TABLE messages (
    conversation_id TEXT REFERENCES conversations(id),
    sequence INTEGER NOT NULL,
    direction INTEGER NOT NULL,  -- 1=incoming, 2=outgoing
    envelope BLOB NOT NULL,
    status INTEGER DEFAULT 0,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (conversation_id, sequence)
);

-- Group membership
CREATE TABLE group_members (
    conversation_id TEXT REFERENCES conversations(id),
    member_identity TEXT NOT NULL,
    role INTEGER DEFAULT 0,  -- 0=member, 1=admin
    PRIMARY KEY (conversation_id, member_identity)
);
```

### 6.2 Per-Chat Encryption

```
Master Key (SQLCipher)
    │
    ├─▶ KDF(contact_id) ──▶ Contact DB encryption
    ├─▶ KDF(conversation_id) ──▶ Message encryption
    └─▶ KDF(identity_id) ──▶ Private key encryption
```

---

## 7. Security Properties

### 7.1 Forward Secrecy

Every message uses fresh keys derived from the ratchet. Compromise of long-term keys does not decrypt past messages.

### 7.2 Post-Compromise Security

After a ratchet step (new DH exchange), even a compromised state cannot decrypt future messages.

### 7.3 Deniable Authentication

The handshake transcript could be simulated by either party. No third party can prove who sent what.

### 7.4 Metadata Protection

| Metadata Element | Protection |
|------------------|------------|
| Sender identity | Pairwise pseudonyms |
| Recipient identity | Hidden service rendezvous |
| Timing | Random delays, cover traffic |
| Message size | Constant padding |
| Online status | Always-on proxy behavior |
| Contact list | No central directory |

---

## 8. Build & Deployment

### 8.1 Reproducible Builds

```bash
# Deterministic Rust build
cargo build --release --locked

# Docker for reproducible environment
docker build -t shadowgram-builder .

# Verify build
sha256sum shadowgram-0.1.0-x86_64.AppImage
```

### 8.2 Dependencies (Cargo.toml)

```toml
[workspace]
members = ["crates/*"]
resolver = "2"

[workspace.dependencies]
# Cryptography
x25519-dalek = "2.0"
kyber = "1.0"
chacha20poly1305 = "0.10"
aes-gcm = "0.10"
hkdf = "0.12"
blake3 = "1.5"

# Zeroization
zeroize = { version = "1.7", features = ["derive"] }

# Tor
arti-client = "0.22"

# DHT
libp2p-kad = "0.46"

# Storage
sqlcipher = "0.8"
rusqlite = "0.31"

# QR codes
qrcode = "0.14"

# Async
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
```

---

## 9. Audit & Verification

### 9.1 Crypto Audit Checklist

- [ ] X25519 uses `curve25519-dalek` (verified, constant-time)
- [ ] ML-KEM uses `kyber` crate (NIST Round 3 reference)
- [ ] ChaCha20-Poly1305 uses `chacha20poly1305` (audited)
- [ ] All key material zeroized on drop
- [ ] No timing side-channels in comparison ops
- [ ] Random number generation uses OS CSPRNG

### 9.2 Fuzz Testing

```bash
# Cargo fuzz on crypto boundaries
cargo fuzz run key_exchange
cargo fuzz run double_ratchet
cargo fuzz run message_parse
```

### 9.3 Integration Tests

```bash
# Two instances exchange messages via Tor
cargo test --package messenger integration

# DHT discovery test
cargo test --package network dht_discovery
```

---

## 10. Roadmap

### Phase 1 (Months 1-2): Crypto Core
- [ ] X25519 key exchange
- [ ] ML-KEM-768 encapsulation
- [ ] Double Ratchet implementation
- [ ] Unit tests + fuzzing

### Phase 2 (Months 3-4): Identity + Protocols
- [ ] Identity generation
- [ ] QR code encoding
- [ ] Pairwise pseudonyms
- [ ] 1-on-1 messaging protocol

### Phase 3 (Months 5-6): Network
- [ ] Arti Tor integration
- [ ] Minimal mixnet
- [ ] DHT peer discovery
- [ ] Padding + cover traffic

### Phase 4 (Months 7-8): Storage + UI
- [ ] SQLCipher integration
- [ ] Tauri frontend
- [ ] Chat UI
- [ ] Settings

### Phase 5 (Months 9-10): Polish
- [ ] Group chat (MLS)
- [ ] Multi-device sync
- [ ] Security audit
- [ ] Public release

---

## 11. References

- Signal Protocol: https://signal.org/docs/
- MLS Protocol: https://messaginglayersecurity.rocks/
- Tor: https://torproject.org/
- Arti: https://gitlab.torproject.org/tpo/core/arti
- Loopix Mixnet: https://arxiv.org/abs/1703.04580
- SimpleX Chat: https://github.com/simplex-chat/simplex-chat
- Briar: https://briarproject.org/

---

## 12. License

MIT License - See LICENSE file for details.

**NO BACKDOORS. NO WARRANTY. USE AT YOUR OWN RISK.**