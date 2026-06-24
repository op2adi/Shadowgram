# Security Policy

## Reporting a Vulnerability

**DO NOT** report security vulnerabilities via public GitHub issues.

### Secure Reporting

1. **Preferred**: Email security@shadowgram.dev with PGP encryption
2. **Alternative**: Create a draft security advisory on GitHub

### PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF... (key fingerprint sha256: ...)
-----END PGP PUBLIC KEY BLOCK-----
```

### Response Timeline

- **24-48 hours**: Acknowledgment of report
- **7 days**: Initial assessment and severity determination
- **30-90 days**: Fix development and testing
- **Coordinated disclosure**: After fix is available

## Security Scope

### In-Scope Vulnerabilities

- Cryptographic implementation flaws
- Key leakage vulnerabilities
- Authentication bypasses
- Memory safety issues
- Side-channel attacks
- Protocol design flaws
- Traffic analysis attacks

### Out-of-Scope

- Missing platform features
- UI/UX issues
- Feature requests

## Known Limitations

### Current Alpha State

| Component | Status | Notes |
|-----------|--------|-------|
| Crypto Core | Partial | X25519+ML-KEM implemented, needs audit |
| Double Ratchet | Partial | Basic implementation, MLS TODO |
| Tor Integration | Stub | Arti integration incomplete |
| Mixnet | Minimal | Loopix-style, not full protocol |
| DHT | Basic | Libp2p Kademlia stub |
| Storage | Basic | SQLCipher schema defined |

### Known Issues (v0.1.0)

1. **No End-to-End Testing**: Components tested individually but not integrated
2. **Incomplete Error Handling**: Many errors return generic types
3. **No Formal Verification**: Crypto needs formal verification
4. **Memory Safety**: Not audited for side-channels

## Security Architecture

### Cryptographic Choices

| Algorithm | Purpose | Implementation |
|-----------|---------|----------------|
| X25519 | Key exchange | `x25519-dalek` |
| ML-KEM-768 | Post-quantum KEM | `kyber` crate |
| Ed25519 | Signatures | `ed25519-dalek` |
| ChaCha20-Poly1305 | AEAD | `chacha20poly1305` |
| BLAKE3 | Hashing/fingerprints | `blake3` |
| HKDF-SHA256 | Key derivation | `hkdf` + `sha2` |

### Threat Model

**Primary Adversary**: State-level network observer

| Capability | Defense |
|------------|---------|
| Full packet capture | Tor + mixnet routing |
| Traffic analysis | Constant padding, cover traffic |
| Global passive adversary | Multi-path routing, hidden services |
| Compelled service provider | No central provider |
| Quantum computer | ML-KEM-768 hybrid |

**Secondary Adversary**: Targeted attacker

| Capability | Defense |
|------------|---------|
| Identity correlation | Pairwise pseudonyms |
| Contact enumeration | QR exchange, no phone numbers |
| Metadata analysis | No timestamps, constant bandwidth |

**Tertiary Adversary**: Endpoint compromise

| Capability | Defense |
|------------|---------|
| Memory scraping | Zeroization on drop |
| Key theft | Encrypted storage |
| Device seizure | Ephemeral messages |

### Defense in Depth

1. **Cryptographic Layer**: Multiple algorithms, hybrid PQ
2. **Network Layer**: Tor + optional mixnet
3. **Protocol Layer**: Deniable authentication
4. **Storage Layer**: SQLCipher per-page encryption
5. **Memory Layer**: Zeroization, arena allocation

## Audit Status

### Completed Audits

_None yet - alpha stage_

### Planned Audits

1. **Phase 1**: Cryptographic core (Q3 2026)
2. **Phase 2**: Protocol implementation (Q4 2026)
3. **Phase 3**: Full system audit (Q1 2027)

## Bug Bounty

**Status**: No active bounty program (alpha stage)

Once v1.0 is released and audited, a responsible disclosure bug bounty program will be launched.

## Reproducible Builds

### Build Verification

```bash
# Deterministic build
cargo build --release --locked

# Verify hash
sha256sum target/release/shadowgram
```

### Docker Build

```bash
# Reproducible environment
docker build -t shadowgram-builder:latest .
docker run --rm shadowgram-builder:latest cargo build --release
```

## Security Checklist

### For Contributors

- [ ] No hardcoded secrets or keys
- [ ] All sensitive data zeroized on drop
- [ ] No timing-dependent comparisons
- [ ] Error messages don't leak sensitive info
- [ ] Dependencies are from trusted sources

### For Users

- [ ] Verify QR fingerprints in person
- [ ] Use Tor for all connections
- [ ] Enable cover traffic
- [ ] Regular identity rotation
- [ ] Backup recovery phrase securely
- [ ] Don't screenshot conversations

## Compliance

### Export Control

This software uses cryptographic technology. May be subject to export controls.

### Data Protection

No user data is collected by Shadowgram. There is no central server.

---

## Security Contact

- **Email**: security@shadowgram.dev
- **PGP Key**: https://shadowgram.dev/security.asc
- **Response Time**: 24-48 hours