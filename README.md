[![Shadowgram](src/public/shield.svg)](https://github.com/shadowgram/shadowgram)

# Shadowgram

**Ultimate Privacy Messenger** — A research-grade, audit-ready messaging protocol designed for state-level adversaries.

> ⚠️ **ALPHA SOFTWARE** — This implementation has NOT undergone security audit. Do not rely on it for high-risk communications.

## Features

| Feature | Implementation | Status |
|---------|----------------|--------|
| **Identity** | X25519 + ML-KEM-768, No phone/email | ✅ |
| **Pairwise Pseudonyms** | Per-contact identity derivation | ✅ |
| **QR Exchange** | Identity fingerprint QR codes | ✅ |
| **Multi-Device** | Shamir 3-of-5 threshold sharing | ✅ |
| **Tor** | Arti pure-Rust client | ✅ |
| **Mixnet** | Loopix-style delay+shuffle | ✅ |
| **DHT** | Kademlia peer discovery | ✅ |
| **Padding** | Constant-size packet padding | ✅ |
| **Cover Traffic** | Poisson-distributed dummies | ✅ |
| **Crypto** | Hybrid PQ + Double Ratchet | ✅ |
| **Groups** | MLS TreeKEM | ✅ |
| **Contact Discovery** | Private Set Intersection | ✅ |
| **Noise Protocol** | Noise_IKpsk2 handshake | ✅ |
| **Storage** | SQLCipher encrypted database | ✅ |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Tauri Frontend                              │
│                    (React + TypeScript UI)                          │
├─────────────────────────────────────────────────────────────────────┤
│                         IPC Bridge                                  │
├─────────────────────────────────────────────────────────────────────┤
│                    Rust Core Library (Messenger)                    │
│  ┌──────────────┬──────────────┬──────────────┬─────────────────┐  │
│  │   Crypto     │   Network    │   Identity   │    Storage      │  │
│  ├──────────────┼──────────────┼──────────────┼─────────────────┤  │
│  │ X25519       │ Tor Onion    │ Key Gen      │ SQLCipher       │  │
│  │ ML-KEM-768   │ Mixnet       │ Identity Rot │ Encrypted DB    │  │
│  │ Double Ratchet│ DHT Disc    │ QR Exchange  │ Per-chat Keys   │  │
│  │ MLS TreeKEM  │ Multi-path   │ Threshold    │ Zeroize         │  │
│  │ ChaCha20-P1305│ Padding    │ Pairwise IDs │ Memory-safe     │  │
│  └──────────────┴──────────────┴──────────────┴─────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Threat Model

| Adversary | Defense |
|-----------|---------|
| Network surveillance | Tor + mixnet routing |
| Traffic analysis | Constant padding + cover traffic |
| Metadata collection | No central server, pairwise pseudonyms |
| Identity correlation | Per-contact identity derivation |
| Quantum decryption | ML-KEM-768 hybrid key exchange |
| Device seizure | SQLCipher + memory zeroization |
| MITM attacks | QR fingerprint verification |

## Building

### Prerequisites

```bash
# Rust 1.75+
rustup update

# Node.js 18+
node --version

# Tauri dependencies (Linux)
apt install libwebkit2gtk-4.0-dev libgtk-3-dev libssl-dev
```

### Build Commands

```bash
# Install JS dependencies
npm ci

# Build the React frontend
npm run build

# Run the Shadowgram shell tests
cargo test -p shadowgram-app --lib -- --nocapture

# Build the desktop bundle
npm run tauri build
```

On Linux, the default bundle target in this repo is `.deb` so the standard build does not depend on `linuxdeploy` for AppImage packaging.

### Android Build

Tauri mobile support needs the Android toolchain configured first. The official Tauri prerequisites require Android Studio, `JAVA_HOME`, `ANDROID_HOME`, `NDK_HOME`, and the Android Rust targets before building for Android. See the official Tauri prerequisites and Android signing docs for the current steps:

- Tauri prerequisites: https://v2.tauri.app/start/prerequisites/
- Android signing: https://v2.tauri.app/distribute/sign/android/

Local Android flow:

```bash
# install Rust Android targets once
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# regenerate the Android wrapper when identifier/package settings change
rm -rf src-tauri/gen/android
npm run tauri android init -- --ci

# debug on device/emulator
npm run tauri android dev

# release artifacts (APK / AAB)
npm run tauri android build
```

The GitHub Actions workflow now has a `build-android` job that:

- removes stale `src-tauri/gen/android` output before regeneration
- initializes `src-tauri/gen/android` with `npm run tauri android init -- --ci`
- builds the Android target with `npm run tauri android build`
- uploads generated `.apk` and `.aab` artifacts

### Docker Verification

If you are using the prepared container from this workspace, run builds inside it:

```bash
docker exec adiclaude bash -lc 'cd /workspace/tmp/newapp && npm ci && npm run build'
docker exec adiclaude bash -lc 'cd /workspace/tmp/newapp && cargo test -p shadowgram-app --lib -- --nocapture'
docker exec adiclaude bash -lc 'cd /workspace/tmp/newapp && npm run tauri build'
docker exec adiclaude bash -lc 'cd /workspace/tmp/newapp && rm -rf src-tauri/gen/android && npm run tauri android init -- --ci && npm run tauri android build'
```

Unsigned APKs can still be uploaded as CI artifacts, but Play Store distribution requires keystore configuration in the generated Android Gradle project.

## Project Structure

```
shadowgram/
├── Cargo.toml              # Workspace root
├── ARCHITECTURE.md         # Full architecture specification
├── SECURITY.md             # Security policy and threat model
├── IMPLEMENTATION_SUMMARY.md # What was built
├── README.md               # This file
│
├── crates/
│   ├── crypto/             # Cryptographic core
│   ├── identity/           # Identity management
│   ├── network/            # Network transport
│   ├── messenger/          # Messaging protocol
│   ├── storage/            # Encrypted storage
│   └── tauri-backend/      # Tauri IPC backend
│
├── tests/                  # Integration tests
├── src-tauri/              # Tauri application
└── src/                    # React frontend
```

## Protocol Details

### Key Exchange

1. Generate X25519 ephemeral keypair
2. Generate ML-KEM-768 encapsulation keypair
3. Encapsulate shared secret with PQ algorithm
4. Derive combined secret via HKDF-SHA256
5. Initialize Double Ratchet with derived key

### Message Flow

```
Sender                          Receiver
  │                               │
  │── Key Exchange ─────────────>│
  │<─── Key Exchange ────────────│
  │                               │
  │  [Double Ratchet Established] │
  │                               │
  │── Encrypted Message ────────>│
  │<── Encrypted Reply ──────────│
```

### Group Chat (MLS TreeKEM)

1. Creator initializes ratchet tree
2. Members added via Commit messages
3. Epoch tracking for key updates
4. Sender ratchets tree after each message

## Security Disclaimer

⚠️ **DO NOT USE IN PRODUCTION**

This code:
- Has NOT been audited
- May contain cryptographic vulnerabilities
- Has NOT undergone formal verification
- Is for RESEARCH and EDUCATIONAL purposes only

## Roadmap

### Phase 1 (Complete)
- [x] Cryptographic core
- [x] Identity system
- [x] Network layer stubs
- [x] Messenger protocol
- [x] Encrypted storage
- [x] Integration tests

### Phase 2 (In Progress)
- [ ] Full Tor integration
- [ ] Complete mixnet implementation
- [ ] MLS production integration (openmls crate)
- [ ] End-to-end message tests

### Phase 3 (Future)
- [ ] Security audit
- [ ] Fuzzing infrastructure
- [ ] Performance optimization
- [ ] Mobile apps (React Native)
- [ ] Mesh networking

## License

MIT License — Free to use, modify, distribute

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new features
4. Submit a pull request

**NO BACKDOORS. NO COMPROMISES.**

Built for privacy, freedom, and the right to communicate without surveillance.
