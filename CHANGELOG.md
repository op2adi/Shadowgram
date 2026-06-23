# CHANGELOG

All notable changes to Shadowgram will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete cryptographic core with X25519 + ML-KEM-768 hybrid key exchange
- Double Ratchet implementation for forward secrecy
- Identity system with pairwise pseudonyms and QR code exchange
- Shamir Secret Sharing for multi-device support (3-of-5 threshold)
- Network layer with Tor (Arti), minimal mixnet, and Kademlia DHT
- Noise Protocol Framework (Noise_IKpsk2) for authenticated handshakes
- MLS TreeKEM group chat implementation
- Private Set Intersection for contact discovery
- Constant-size packet padding for traffic analysis resistance
- Cover traffic generation with Poisson distribution
- SQLCipher encrypted database layer
- Encrypted cache for ephemeral data
- Tauri desktop frontend scaffolding
- React UI components (IdentitySetup, Sidebar, ChatView)
- Integration test suite with 8+ end-to-end tests
- Fuzzing infrastructure with cargo-fuzz
- Comprehensive documentation (README, SECURITY, ARCHITECTURE, etc.)
- Build automation script (build.sh)

### Security
- Memory zeroization for all key material
- Constant-time comparisons via subtle crate
- Per-message key derivation
- Automatic key rotation scheduling

## [0.1.0-alpha] - 2026-06-23

### Initial Alpha Release

Initial implementation complete with:

- **Crypto Core:** X25519, ML-KEM-768, Double Ratchet, ChaCha20-Poly1305, AES-GCM
- **Identity:** Key generation, QR codes, pairwise pseudonyms, threshold sharing
- **Network:** Tor, mixnet, DHT, padding, cover traffic, pluggable transports
- **Messenger:** 1-on-1 chat, group chat (MLS), contacts, multi-device sync
- **Storage:** SQLCipher database, encrypted cache, schema migrations
- **Frontend:** Tauri desktop app with React UI
- **Tests:** Unit tests + integration tests + fuzzing setup

### Known Issues
- No security audit completed
- Tor integration needs real network testing
- MLS uses custom implementation (should use openmls crate)
- Frontend is incomplete (stub components)

---

## Legend
- `Added` - New features
- `Changed` - Changes in existing functionality
- `Deprecated` - Soon-to-be removed features
- `Removed` - Removed features
- `Fixed` - Bug fixes
- `Security` - Security improvements

**NO BACKDOORS. NO COMPROMISES.**