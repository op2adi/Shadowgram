# Repository Audit

Date: 2026-06-23

This audit is based on static inspection only. I did not run `cargo`, `npm`, `vite`, `tauri`, or any test command.

## Executive Summary

The repository contains a real multi-crate architecture and a non-trivial amount of code, but it is not complete in the way the top-level documentation claims.

What is real:
- The repo structure is coherent for a Rust workspace plus a Tauri/React desktop shell.
- Several crates contain substantive prototype code for crypto, identity, network, messaging, and storage.
- There is a migration file and a broad set of tests and docs.

What is not complete:
- The desktop shell was using placeholder Tauri commands and a mostly disconnected frontend.
- Several crate APIs disagree with each other.
- Some docs mark features as complete that are still placeholders or stubs.
- The integration tests appear ahead of the actual library APIs.

## What I Changed

I implemented the desktop integration layer so the shell is no longer purely placeholder-driven.

### Tauri shell

Updated:
- [src-tauri/src/state.rs](/L:/adityau/newapp/src-tauri/src/state.rs)
- [src-tauri/src/commands.rs](/L:/adityau/newapp/src-tauri/src/commands.rs)
- [src-tauri/src/lib.rs](/L:/adityau/newapp/src-tauri/src/lib.rs)

Changes:
- Replaced trivial boolean-only app state with in-memory identity, contacts, chats, and messages.
- Implemented stateful Tauri commands for:
  - `create_identity`
  - `get_identity`
  - `export_identity_qr`
  - `scan_identity_qr`
  - `add_contact`
  - `get_contacts`
  - `create_chat`
  - `get_chats`
  - `send_message`
  - `get_messages`
  - `start_client`
  - `stop_client`
- Added `get_chats` to the Tauri invoke handler.

Important limitation:
- This is an in-memory shell implementation only. It does not claim to integrate the deeper crypto, storage, or network crates.

### React shell

Updated:
- [src/App.tsx](/L:/adityau/newapp/src/App.tsx)
- [src/components/IdentitySetup.tsx](/L:/adityau/newapp/src/components/IdentitySetup.tsx)
- [src/components/Sidebar.tsx](/L:/adityau/newapp/src/components/Sidebar.tsx)
- [src/components/ChatView.tsx](/L:/adityau/newapp/src/components/ChatView.tsx)
- [src/App.css](/L:/adityau/newapp/src/App.css)

Changes:
- Connected app startup to real Tauri commands instead of local placeholder assumptions.
- Fixed identity handling to use the actual response shape.
- Added contact creation and chat creation flows.
- Added active chat selection driven by app state instead of an internal dead-end state.
- Added message loading and sending through Tauri commands.
- Expanded styling for the sidebar, chat view, identity setup, and responsive layout.

## Verified Gaps By Area

### 1. Documentation overstates implementation status

Files:
- [README.md](/L:/adityau/newapp/README.md)
- [IMPLEMENTATION_SUMMARY.md](/L:/adityau/newapp/IMPLEMENTATION_SUMMARY.md)
- [BUILD_STATUS.md](/L:/adityau/newapp/BUILD_STATUS.md)
- [SECURITY.md](/L:/adityau/newapp/SECURITY.md)

Observed issues:
- `README.md` claims many features are complete even where source comments explicitly say placeholder or production TODO.
- `IMPLEMENTATION_SUMMARY.md` marks the React frontend and Tauri backend as complete, but the original code was largely stubbed.
- The implementation summary itself ends with "Next Steps: Fix compilation errors," which contradicts its completion claims.
- `SECURITY.md` is more cautious than the main README and is closer to reality.

Recommendation:
- Rewrite top-level status docs to classify each subsystem as `implemented`, `prototype`, `stub`, or `documentation-only`.

### 2. Tauri and frontend were previously placeholders

Files:
- [src-tauri/src/commands.rs](/L:/adityau/newapp/src-tauri/src/commands.rs)
- [src-tauri/src/state.rs](/L:/adityau/newapp/src-tauri/src/state.rs)
- [src/App.tsx](/L:/adityau/newapp/src/App.tsx)
- [src/components/Sidebar.tsx](/L:/adityau/newapp/src/components/Sidebar.tsx)
- [src/components/ChatView.tsx](/L:/adityau/newapp/src/components/ChatView.tsx)
- [src/components/IdentitySetup.tsx](/L:/adityau/newapp/src/components/IdentitySetup.tsx)

Observed issues before patch:
- `create_identity` returned fixed strings.
- `get_identity` always returned `None`.
- contacts, chats, and messages were not persisted even in memory.
- `ChatView` owned its own `selectedChat` state and there was no UI path to set it.
- QR rendering was a placeholder text block.

Status after patch:
- The shell is now coherent as an in-memory demo.
- It is still not backed by the Rust core protocol implementation.

### 3. Workspace/library API mismatches likely prevent clean compilation

Files:
- [tests/integration_tests.rs](/L:/adityau/newapp/tests/integration_tests.rs)
- [crates/messenger/src/client.rs](/L:/adityau/newapp/crates/messenger/src/client.rs)
- [crates/storage/src/database.rs](/L:/adityau/newapp/crates/storage/src/database.rs)
- [crates/identity/src/identity.rs](/L:/adityau/newapp/crates/identity/src/identity.rs)
- [Cargo.toml](/L:/adityau/newapp/Cargo.toml)
- [crates/identity/Cargo.toml](/L:/adityau/newapp/crates/identity/Cargo.toml)

Observed mismatches:
- `tests/integration_tests.rs` uses API names not present in current library code, including `Identity::new()` and config fields like `enable_cover_traffic`.
- `crates/messenger/src/client.rs` calls storage APIs with signatures that do not match [crates/storage/src/database.rs](/L:/adityau/newapp/crates/storage/src/database.rs).
- `crates/identity/src/identity.rs` imports `kyber::{KemPublicKey, KemSecretKey}`, but the workspace dependency in [Cargo.toml](/L:/adityau/newapp/Cargo.toml) is `ml-kem`, not `kyber`.
- `README.md` says SQLCipher, but storage currently uses bundled `rusqlite` and an in-memory placeholder open path in `Database::new/open`.
- The root workspace does not include `crates/tauri-backend`, while a separate Tauri backend crate exists in the tree.

Recommendation:
- Freeze one canonical API surface and reconcile tests, manifests, and crate imports around it before any new feature work.

### 4. Identity crate is partially real, partially inconsistent

Files:
- [crates/identity/src/identity.rs](/L:/adityau/newapp/crates/identity/src/identity.rs)
- [crates/identity/src/qr.rs](/L:/adityau/newapp/crates/identity/src/qr.rs)

Observed issues:
- Key generation and fingerprint construction are substantial.
- QR generation exists, but QR decoding is explicitly not implemented.
- The file mixes prototype-level code with references to types and APIs that need manifest validation.

Recommendation:
- Split this crate into:
  - a compile-clean MVP identity module
  - optional QR decode support behind a feature flag

### 5. Network crate contains multiple prototypes rather than production-ready implementations

Files:
- [crates/network/src/noise.rs](/L:/adityau/newapp/crates/network/src/noise.rs)
- [crates/network/src/transports.rs](/L:/adityau/newapp/crates/network/src/transports.rs)

Observed issues:
- `noise.rs` contains placeholder handshake logic and zero-derived keys in paths that claim Noise IK behavior.
- `transports.rs` labels obfuscation as a placeholder and does not implement real obfs4-like behavior.
- The network layer docs describe stronger guarantees than these implementations currently support.

Recommendation:
- Mark these modules as prototypes in docs and gate unfinished paths behind explicit `experimental` features.

### 6. Storage crate does not match the "SQLCipher complete" claim

Files:
- [crates/storage/src/database.rs](/L:/adityau/newapp/crates/storage/src/database.rs)
- [crates/storage/src/migrations/001_init.sql](/L:/adityau/newapp/crates/storage/src/migrations/001_init.sql)

Observed issues:
- `Database::open` uses in-memory SQLite and comments describe SQLCipher as future/production behavior.
- The migration file exists and is relatively complete.
- The implementation summary claims this subsystem is complete, which is inaccurate.

Recommendation:
- Either implement actual encrypted-at-rest storage or document this crate as schema-plus-prototype only.

## What Is Still Missing

The following work remains if the goal is a credible end-to-end application:

1. Make the Rust workspace compile cleanly by reconciling crate APIs, dependency names, and tests.
2. Decide whether `src-tauri` or `crates/tauri-backend` is the canonical desktop backend and remove duplication.
3. Replace in-memory shell state with actual persistence and real calls into the messenger/storage crates.
4. Reduce or remove placeholder crypto/network implementations that currently look more complete than they are.
5. Rewrite status documentation to match source reality.
6. Add a verification matrix that distinguishes static review from executed tests.

## Recommended Implementation Order

1. Manifest and API reconciliation
2. Compile-clean core crates
3. Storage integration
4. Identity integration into desktop shell
5. Contact/chat/message persistence
6. Real transport and protocol integration
7. Doc truthfulness pass

## Verification Notes

I verified this audit by reading:
- top-level docs and manifests
- Tauri shell code
- React shell code
- representative files from identity, network, messenger, storage, and tests

I did not verify:
- compilation
- runtime behavior
- cryptographic correctness
- test pass/fail status
- Tauri packaging

## Bottom Line

This repo is best described as a substantial prototype with an ambitious architecture, incomplete integration, and overstated status documentation.

The desktop shell is now materially better than it was at the start of this review, but the repo as a whole still needs a compile-reconciliation phase before it can be considered a coherent implementation.
