# Shadowgram - Quick Reference

## Build Commands

```bash
# Build all crates
cargo build --release

# Run all tests
cargo test

# Run specific test
cargo test test_complete_message_flow

# Run with coverage
cargo tarpaulin --out html

# Check lints
cargo clippy --all-targets -- -D warnings

# Format code
cargo fmt

# Generate docs
cargo doc --open

# Run fuzzer
cargo fuzz run message_parse

# Build Tauri app
npm run tauri build
```

## Architecture Quick Reference

### Crypto Core
```
X25519          → Classical key exchange
ML-KEM-768      → Post-quantum encapsulation
Double Ratchet  → Forward secrecy + PCS
ChaCha20-Poly1305 → AEAD encryption
HKDF-SHA256     → Key derivation
```

### Identity
```
No phone/email  → Pure cryptographic IDs
Pairwise IDs    → Per-contact pseudonyms
QR Exchange     → Scan to add contacts
Shamir SS       → 3-of-5 multi-device
```

### Network
```
Tor (Arti)      → Onion routing
Mixnet          → Traffic analysis resistance
DHT (Kademlia)  → Peer discovery
Padding         → Constant message sizes
Cover Traffic   → Dummy messages
```

### Messenger
```
1-on-1 Chat     → Double Ratchet encrypted
Group Chat      → MLS TreeKEM
Contact Discovery → Private Set Intersection
Multi-device    → Threshold sync
```

### Storage
```
SQLCipher       → Encrypted SQLite
Per-entry AES   → Cache encryption
Zeroization     → Secure cleanup
```

## Security Properties

| Threat | Defense |
|--------|---------|
| Network surveillance | Tor + mixnet |
| Traffic analysis | Padding + cover traffic |
| Metadata collection | No server, pairwise IDs |
| Identity correlation | Per-contact pseudonyms |
| Quantum decryption | ML-KEM-768 hybrid |
| Device seizure | SQLCipher + zeroize |
| MITM | QR fingerprint verify |

## File Locations

```
crates/crypto/src/      → Cryptographic core
crates/identity/src/    → Identity management
crates/network/src/     → Network transport
crates/messenger/src/   → Messaging protocol
crates/storage/src/     → Encrypted storage
tests/                  → Integration tests
fuzz/                   → Fuzzing targets
src-tauri/              → Desktop app
src/                    → React frontend
```

## Key Types

### Message Flow
```
1. Key Exchange (Noise IK + Hybrid PQ)
2. Double Ratchet initialized
3. Messages encrypted with per-message keys
4. Ratchet advances after each message
```

### Group Chat Flow
```
1. Creator initializes MLS tree
2. Members added via Commit
3. Epoch tracking for key updates
4. Sender encrypts to group
```

### Contact Discovery
```
1. Hash all local contacts
2. Exchange blinded hashes
3. Find common via PSI
4. Initiate chat with matches
```

## Testing

### Unit Tests
```bash
cargo test --lib          # Library tests
cargo test --bins         # Binary tests
```

### Integration Tests
```bash
cargo test --test integration_tests
```

### Fuzzing
```bash
cargo fuzz run message_parse    # Message parsing
cargo fuzz run key_exchange     # Key exchange
cargo fuzz run ratchet          # Double ratchet
```

## Dependencies

### Crypto
- `x25519-dalek` - X25519 elliptic curve
- `kyber` - ML-KEM-768 (post-quantum)
- `chacha20poly1305` - AEAD cipher
- `hkdf` - Key derivation
- `zeroize` - Secure memory

### Network
- `arti-client` - Tor client (pure Rust)
- `libp2p-kad` - Kademlia DHT

### Storage
- `rusqlite` - SQLite bindings
- `sqlcipher` - Encrypted SQLite

### Utilities
- `serde` - Serialization
- `thiserror` - Error handling
- `parking_lot` - Fast locks

## Common Patterns

### Creating a Client
```rust
use shadowgram_messenger::{Client, ClientConfig};

let config = ClientConfig::default();
let client = Client::new(config)?;
client.start().await?;
```

### Creating Identity
```rust
use shadowgram_identity::Identity;

let identity = Identity::new()?;
let fingerprint = identity.public().fingerprint();
```

### Sending Message
```rust
use shadowgram_messenger::Message;

let msg = Message::text("Hello!".to_string());
let envelope = client.send_message(&fingerprint, msg).await?;
```

### Group Chat
```rust
let group_id = client.create_group("My Group", &identity).await?;
client.add_member_to_group(&group_id, &contact_fp).await?;
```

## Environment Variables

```bash
RUST_LOG=debug    # Enable debug logging
RUST_BACKTRACE=1  # Enable backtraces
```

## Debugging

```bash
# Run with logging
RUST_LOG=shadowgram=debug cargo run

# Get backtraces
RUST_BACKTRACE=1 cargo run

# Profile build
cargo build --release --timings
```

## Resources

- **Architecture:** `ARCHITECTURE.md`
- **Security:** `SECURITY.md`
- ** Getting Started:** `GETTING_STARTED.md`
- **Contributing:** `CONTRIBUTING.md`
- **API Docs:** `cargo doc --open`

---

**NO BACKDOORS. NO COMPROMISES.**