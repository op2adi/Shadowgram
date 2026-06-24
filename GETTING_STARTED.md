# Getting Started with Shadowgram

## Quick Start Guide

This guide will help you get Shadowgram up and running for development.

## Prerequisites

### Required
- **Rust 1.75+** - [Install via rustup](https://rustup.rs/)
- **Node.js 18+** - [Install via nvm](https://github.com/nvm-sh/nvm)

### For Tauri Desktop (Linux)
```bash
apt install libwebkit2gtk-4.0-dev libgtk-3-dev libssl-dev libsoup2.4-dev
```

### For Tauri Desktop (macOS)
```bash
xcode-select --install
```

### For Tauri Desktop (Windows)
- [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/)
- [Visual Studio C++ tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)

## Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/shadowgram/shadowgram.git
cd shadowgram
```

### 2. Build All Crates

```bash
# Build in release mode
cargo build --release

# Or debug mode for development
cargo build
```

### 3. Run Tests

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_complete_message_flow
```

### 4. Run the Application

#### Backend Only (CLI)
```bash
# Run the messenger client
cargo run --bin shadowgram
```

#### Full Desktop App (Tauri)
```bash
# Install frontend dependencies
npm install

# Run in development mode
npm run tauri dev

# Build for production
npm run tauri build
```

## Project Structure Overview

```
shadowgram/
├── crates/           # Rust library crates
│   ├── crypto/       # Cryptographic core
│   ├── identity/     # Identity management
│   ├── network/      # Network transport
│   ├── messenger/    # Messaging protocol
│   └── storage/      # Encrypted storage
├── src-tauri/        # Tauri desktop app
├── src/              # React frontend
└── tests/            # Integration tests
```

## Common Development Tasks

### Check Code Quality
```bash
# Run clippy lints
cargo clippy --all-targets -- -D warnings

# Check formatting
cargo fmt --check

# Apply formatting
cargo fmt
```

### Generate Documentation
```bash
# Generate and open docs
cargo doc --open
```

### Run with Coverage
```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Run with coverage
cargo tarpaulin --out html
```

### Fuzz Testing
```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzzer
cargo fuzz run message_parse
```

## Understanding the Architecture

### Cryptographic Layer (`crates/crypto`)
- X25519 for classical key exchange
- ML-KEM-768 for post-quantum encapsulation
- Double Ratchet for forward secrecy
- ChaCha20-Poly1305 for AEAD encryption

### Identity Layer (`crates/identity`)
- No phone numbers or emails
- Pairwise pseudonyms per contact
- QR code-based identity exchange
- Shamir Secret Sharing for multi-device

### Network Layer (`crates/network`)
- Tor onion routing via Arti
- Minimal mixnet for traffic analysis resistance
- Kademlia DHT for peer discovery
- Constant-size packet padding
- Cover traffic generation

### Messenger Layer (`crates/messenger`)
- 1-on-1 encrypted chats
- MLS TreeKEM group chats
- Private Set Intersection for contact discovery
- Multi-device synchronization

### Storage Layer (`crates/storage`)
- SQLCipher encrypted database
- Per-entry encrypted cache
- Automatic key zeroization

## Troubleshooting

### Build Errors

**Problem:** `cargo: command not found`
- **Solution:** Install Rust from https://rustup.rs/

**Problem:** Tauri build fails on Linux
- **Solution:** Install required dependencies:
  ```bash
  apt install libwebkit2gtk-4.0-dev libgtk-3-dev libssl-dev
  ```

**Problem:** `npm: command not found`
- **Solution:** Install Node.js from https://nodejs.org/

### Test Failures

**Problem:** Tests fail with "connection refused"
- **Solution:** Some tests require network access. Run offline tests only:
  ```bash
  cargo test -- --skip network
  ```

### Runtime Issues

**Problem:** App won't start
- **Solution:** Check logs with:
  ```bash
  RUST_LOG=debug cargo run
  ```

## Next Steps

1. **Read the Architecture** - See `ARCHITECTURE.md` for detailed design
2. **Review Security Model** - See `SECURITY.md` for threat model
3. **Explore the Code** - Start with `crates/messenger/src/client.rs`
4. **Run Integration Tests** - See `tests/README.md`
5. **Contribute** - See `CONTRIBUTING.md` for guidelines

## Getting Help

- **Documentation:** `cargo doc --open`
- **Issues:** https://github.com/shadowgram/shadowgram/issues
- **Discussions:** https://github.com/shadowgram/shadowgram/discussions

---

**NO BACKDOORS. NO COMPROMISES.**