# Shadowgram Test Suite

## Integration Tests

End-to-end tests demonstrating full message round-trip between two clients.

### Running Tests

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_complete_message_flow

# Run integration tests only
cargo test --test integration_tests

# Run with coverage
cargo tarpaulin --out html
```

### Test Coverage

| Test | Description | Status |
|------|-------------|--------|
| `test_complete_message_flow` | Full 1-on-1 chat between Alice and Bob | ✅ |
| `test_double_ratchet_message_ordering` | Out-of-order message handling | ✅ |
| `test_group_chat_message_flow` | MLS group chat messaging | ✅ |
| `test_contact_discovery_psi` | Private Set Intersection | ✅ |
| `test_noise_protocol_handshake` | Noise IK handshake | ✅ |
| `test_multi_device_sync` | Shamir secret sharing | ✅ |
| `test_message_padding_constant_size` | Constant-size padding | ✅ |
| `test_cover_traffic_generation` | Dummy traffic generation | ✅ |

## Unit Tests

Each crate has its own unit tests:

### Crypto (`crates/crypto/`)
- Key exchange serialization/deserialization
- Double ratchet key derivation
- AEAD encryption/decryption
- KDF outputs
- Key zeroization

### Identity (`crates/identity/`)
- Identity key generation
- Pairwise pseudonym derivation
- QR code generation/parsing
- Threshold secret sharing
- Rotation scheduling

### Network (`crates/network/`)
- Tor transport bootstrap
- Mixnet delay/shuffle
- DHT peer lookup
- Padding granularity
- Cover traffic Poisson distribution
- Noise protocol handshake

### Messenger (`crates/messenger/`)
- Client state machine
- Chat session lifecycle
- Message serialization
- Contact management
- Group membership changes
- PSI protocol

### Storage (`crates/storage/`)
- Database CRUD operations
- Schema migrations
- Encrypted cache TTL

## Fuzz Testing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run crypto fuzzer
cargo fuzz run key_exchange

# Run double ratchet fuzzer
cargo fuzz run ratchet

# Run PSI fuzzer
cargo fuzz run psi
```

## Security Properties Verified

- [x] Key exchange produces shared secret
- [x] Double ratchet maintains forward secrecy
- [x] Messages decrypt in correct order despite network reordering
- [x] PSI finds common contacts without revealing full lists
- [x] Noise handshake completes with matching keys
- [x] Threshold sharing reconstructs from m-of-n shares
- [x] Padding achieves constant message sizes
- [x] Cover traffic generates at configured rate

## TODO: Additional Tests

- [ ] Tor connectivity test (requires testnet)
- [ ] Mixnet end-to-end latency measurement
- [ ] Group chat member removal
- [ ] Multi-device sync full flow
- [ ] Database encryption verification
- [ ] Memory zeroization verification
- [ ] Side-channel timing analysis