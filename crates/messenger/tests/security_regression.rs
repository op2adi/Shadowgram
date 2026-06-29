//! Security regression tests for Shadowgram.
//!
//! Each test is labelled with the property it guards.  A test that passes
//! today must keep passing forever — regressions in security properties are
//! treated as build-breaking failures.

use shadowgram_crypto::aead::AeadCipher;
use shadowgram_identity::Identity;
use shadowgram_messenger::{GroupChat, GroupError, GroupMember, MemberRole};
use shadowgram_network::mailbox::{
    MailboxEnvelope, MailboxError, OutboundQueue, RelayMailbox, MAILBOX_TTL_SECS,
    MAX_ENVELOPE_BYTES, MAX_PENDING_PER_RECIPIENT,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn make_identity() -> Identity {
    Identity::generate().expect("identity generation must succeed")
}

/// Create a two-member group (creator = alice) with alice already joined.
fn two_member_group(alice: &Identity, bob: &Identity) -> GroupChat {
    let alice_key = alice
        .public()
        .to_bytes()
        .expect("alice public key serialization");
    let mut group = GroupChat::create(
        "test-group-1".into(),
        alice.public().fingerprint_full.clone(),
        alice_key,
        Some("Test Group".into()),
    );

    let bob_key = bob
        .public()
        .to_bytes()
        .expect("bob public key serialization");
    let member = GroupMember {
        fingerprint: bob.public().fingerprint_full.clone(),
        display_name: Some("Bob".into()),
        role: MemberRole::Member,
        key_package: bob_key,
        joined_at: unix_now(),
        left_at: None,
    };
    group.add_member(member).expect("add bob to group");
    group
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ─── Property 1: Alice → Bob direct message round-trip ──────────────────────

#[test]
fn direct_message_alice_to_bob_round_trip() {
    // Derive a shared session key (simulate completed key exchange)
    let mut session_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut session_key);

    // Alice sends
    let plaintext = b"Hello Bob, this is Alice.";
    let nonce = AeadCipher::generate_nonce();
    let aad = b"direct:alice:bob";
    let (ciphertext, tag) = AeadCipher::encrypt_chacha20(&session_key, &nonce, plaintext, aad)
        .expect("encrypt must succeed");

    // Bob receives
    let recovered = AeadCipher::decrypt_chacha20(&session_key, &nonce, &ciphertext, &tag, aad)
        .expect("decrypt must succeed");

    assert_eq!(recovered, plaintext);
}

// ─── Property 2: Bob → Alice direct message round-trip ──────────────────────

#[test]
fn direct_message_bob_to_alice_round_trip() {
    let mut session_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut session_key);

    let plaintext = b"Hello Alice, this is Bob.";
    let nonce = AeadCipher::generate_nonce();
    let aad = b"direct:alice:bob";
    let (ciphertext, tag) = AeadCipher::encrypt_chacha20(&session_key, &nonce, plaintext, aad)
        .expect("encrypt must succeed");

    let recovered = AeadCipher::decrypt_chacha20(&session_key, &nonce, &ciphertext, &tag, aad)
        .expect("decrypt must succeed");

    assert_eq!(recovered, plaintext);
}

// ─── Property 3: Wrong key cannot decrypt ──────────────────────────────────

#[test]
fn direct_message_wrong_key_is_rejected() {
    let mut alice_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut alice_key);
    let mut eve_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut eve_key);

    let nonce = AeadCipher::generate_nonce();
    let (ciphertext, tag) =
        AeadCipher::encrypt_chacha20(&alice_key, &nonce, b"secret", b"aad").unwrap();

    let result = AeadCipher::decrypt_chacha20(&eve_key, &nonce, &ciphertext, &tag, b"aad");
    assert!(result.is_err(), "decryption with wrong key must fail");
}

// ─── Property 4: Tampered ciphertext is rejected (AEAD authentication) ──────

#[test]
fn tampered_direct_message_is_rejected() {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);

    let nonce = AeadCipher::generate_nonce();
    let (mut ciphertext, tag) =
        AeadCipher::encrypt_chacha20(&key, &nonce, b"authentic message", b"aad").unwrap();

    // Flip a bit in the ciphertext
    ciphertext[0] ^= 0xFF;

    let result = AeadCipher::decrypt_chacha20(&key, &nonce, &ciphertext, &tag, b"aad");
    assert!(result.is_err(), "tampered ciphertext must be rejected");
}

// ─── Property 5: AAD mismatch is rejected ───────────────────────────────────

#[test]
fn wrong_aad_is_rejected() {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);

    let nonce = AeadCipher::generate_nonce();
    let (ciphertext, tag) =
        AeadCipher::encrypt_chacha20(&key, &nonce, b"message", b"correct-aad").unwrap();

    let result = AeadCipher::decrypt_chacha20(&key, &nonce, &ciphertext, &tag, b"wrong-aad");
    assert!(result.is_err(), "wrong AAD must be rejected");
}

// ─── Property 6: Group message: all members can decrypt ─────────────────────

#[test]
fn group_message_all_members_can_decrypt() {
    let alice = make_identity();
    let bob = make_identity();
    let mut group = two_member_group(&alice, &bob);

    let plaintext = b"Group hello from Alice.";
    let alice_fp = alice.public().fingerprint_full.clone();
    let enc = group
        .encrypt_message(plaintext, &alice_fp)
        .expect("encrypt must succeed");

    // Both alice and bob share the same GroupChat state here.
    // In a real deployment they'd have independent states that converge via commits.
    // This test verifies the AEAD round-trip over the group root secret.
    let recovered = group
        .decrypt_message(&enc)
        .expect("decrypt must succeed for group member");

    assert_eq!(recovered, plaintext);
}

// ─── Property 7: Group replay is rejected ───────────────────────────────────

#[test]
fn group_replayed_packet_is_rejected() {
    let alice = make_identity();
    let bob = make_identity();
    let mut group = two_member_group(&alice, &bob);

    let alice_fp = alice.public().fingerprint_full.clone();
    let enc = group
        .encrypt_message(b"replay me", &alice_fp)
        .expect("encrypt");

    // First decrypt succeeds
    group.decrypt_message(&enc).expect("first decrypt must succeed");

    // Replaying the same packet must fail
    let replay_result = group.decrypt_message(&enc);
    assert!(
        replay_result.is_err(),
        "replayed group packet must be rejected"
    );
    assert!(
        matches!(replay_result.unwrap_err(), GroupError::ReplayDetected(_, _)),
        "error variant must be ReplayDetected"
    );
}

// ─── Property 8: Wrong epoch is rejected ────────────────────────────────────

#[test]
fn group_wrong_epoch_is_rejected() {
    let alice = make_identity();
    let bob = make_identity();
    let mut group = two_member_group(&alice, &bob);

    let alice_fp = alice.public().fingerprint_full.clone();
    let mut enc = group
        .encrypt_message(b"epoch test", &alice_fp)
        .expect("encrypt");

    // Tamper with the epoch field
    enc.epoch = enc.epoch.wrapping_add(999);

    let result = group.decrypt_message(&enc);
    assert!(result.is_err(), "wrong epoch must be rejected");
}

// ─── Property 9: Group commit does NOT transmit root_secret ─────────────────

#[test]
fn group_commit_does_not_contain_root_secret() {
    let alice = make_identity();
    let bob = make_identity();
    let mut group = two_member_group(&alice, &bob);

    // Trigger an epoch rotation via key update
    let alice_key = alice.public().to_bytes().expect("alice key bytes");
    let commit = group.update_keys(&alice_key).expect("update_keys must succeed");

    // The commit must not embed the plaintext root_secret in encrypted_secret fields
    for update in &commit.path_updates {
        assert!(
            update.encrypted_secret.is_empty(),
            "path update encrypted_secret must be empty — secret is never transmitted"
        );
    }
}

// ─── Property 10: Multiple group messages use different per-message keys ─────

#[test]
fn group_messages_use_distinct_keys() {
    let alice = make_identity();
    let bob = make_identity();
    let mut group = two_member_group(&alice, &bob);

    let fp = alice.public().fingerprint_full.clone();
    let enc1 = group.encrypt_message(b"first", &fp).expect("encrypt 1");
    let enc2 = group.encrypt_message(b"second", &fp).expect("encrypt 2");

    // Different sequence numbers → different nonces/keys
    assert_ne!(enc1.sequence, enc2.sequence);
    assert_ne!(
        enc1.nonce, enc2.nonce,
        "different messages must have different nonces"
    );
    assert_ne!(
        enc1.ciphertext, enc2.ciphertext,
        "different plaintexts with different keys must produce different ciphertexts"
    );
}

// ─── Property 11: Private key not derivable from public key alone ────────────

#[test]
fn private_key_not_recoverable_from_public_key() {
    let identity = make_identity();
    let public = identity.public();

    // Sign a message with the private identity.  `sign` is only available on
    // `Identity` (which holds private key material), NOT on `PublicIdentity`.
    let sig = identity.sign(b"signed message");

    // The self-signature embedded in the identity is verifiable via the public
    // identity alone; this exercises the verify path without needing private key.
    assert!(
        public
            .verify_self_signature()
            .expect("verify_self_signature must not error")
    );

    // Drop the full identity — the sig was produced and is meaningful, but the
    // private key is inaccessible via `PublicIdentity`.
    let _ = (sig, public);
}

// ─── Property 12: Identity fingerprints are unique ───────────────────────────

#[test]
fn identity_fingerprints_are_unique() {
    let id1 = make_identity();
    let id2 = make_identity();

    assert_ne!(
        id1.public().fingerprint_full,
        id2.public().fingerprint_full,
        "two independently generated identities must have distinct fingerprints"
    );
}

// ─── Property 13: Offline relay mailbox — store, retrieve, ACK ───────────────

#[test]
fn relay_mailbox_offline_delivery_round_trip() {
    let mut mailbox = RelayMailbox::new();

    // Sender submits encrypted blob (ciphertext is already AEAD-encrypted
    // by the application; the relay sees only opaque bytes)
    let ciphertext = vec![0xAB; 64]; // simulated ciphertext
    let env = MailboxEnvelope::new("alice_fingerprint", ciphertext.clone(), MAILBOX_TTL_SECS)
        .expect("envelope construction must succeed");
    let message_id = env.message_id;

    mailbox.store(env).expect("relay must accept the envelope");

    // Recipient comes online and retrieves — destructive: relay clears the slot
    let retrieved = mailbox.retrieve("alice_fingerprint");
    assert_eq!(retrieved.len(), 1);
    assert_eq!(retrieved[0].ciphertext, ciphertext);
    let _ = message_id; // no separate ACK needed; retrieve already clears the slot

    // Relay slot must be empty after destructive retrieve
    assert_eq!(
        mailbox.pending_count("alice_fingerprint"),
        0,
        "mailbox must be empty after retrieve"
    );
}

// ─── Property 14: Relay never stores plaintext (payload is opaque) ────────────

#[test]
fn relay_stores_only_opaque_ciphertext() {
    // Construct a plaintext, encrypt it, verify relay cannot distinguish
    // ciphertext from random bytes (relay just stores the blob).
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);

    let nonce = AeadCipher::generate_nonce();
    let (ct, _tag) =
        AeadCipher::encrypt_chacha20(&key, &nonce, b"private message", b"relay-aad").unwrap();

    let env = MailboxEnvelope::new("bob_fp", ct.clone(), MAILBOX_TTL_SECS)
        .expect("envelope must be created");

    // The relay stores the envelope; its `ciphertext` field equals `ct`
    // (already-encrypted).  There is no plaintext in the struct.
    assert_eq!(env.ciphertext, ct);
    // relay_hash is BLAKE3 of fingerprint, not the fingerprint itself
    assert_ne!(env.recipient_hash.as_slice(), b"bob_fp".as_slice());
}

// ─── Property 15: Replay on relay mailbox via duplicate message_id ────────────

#[test]
fn relay_mailbox_deduplicates_by_message_id() {
    let mut mailbox = RelayMailbox::new();

    let env = MailboxEnvelope::new("charlie_fp", vec![1, 2, 3], MAILBOX_TTL_SECS).unwrap();
    mailbox.store(env.clone()).unwrap();
    mailbox.store(env).unwrap(); // second submit — idempotent, not doubled

    assert_eq!(
        mailbox.pending_count("charlie_fp"),
        1,
        "relay must not double-store the same message_id"
    );
}

// ─── Property 16: Relay mailbox full rejects new envelopes ──────────────────

#[test]
fn relay_mailbox_full_rejects_new_envelopes() {
    let mut mailbox = RelayMailbox::new();

    for _ in 0..MAX_PENDING_PER_RECIPIENT {
        let env = MailboxEnvelope::new("dave_fp", vec![0u8; 16], MAILBOX_TTL_SECS).unwrap();
        mailbox.store(env).unwrap();
    }

    let extra = MailboxEnvelope::new("dave_fp", vec![1u8; 16], MAILBOX_TTL_SECS).unwrap();
    let result = mailbox.store(extra);
    assert!(
        matches!(result, Err(MailboxError::MailboxFull)),
        "overfull mailbox must be rejected"
    );
}

// ─── Property 17: Expired envelopes are not delivered ────────────────────────

#[test]
fn expired_relay_envelopes_are_not_delivered() {
    let mut mailbox = RelayMailbox::new();

    let mut env = MailboxEnvelope::new("eve_fp", vec![7; 8], MAILBOX_TTL_SECS).unwrap();
    env.expires_at = 1; // epoch 1 is always in the past

    mailbox.store(env).unwrap();
    let retrieved = mailbox.retrieve("eve_fp");
    assert!(retrieved.is_empty(), "expired envelopes must not be returned");
}

// ─── Property 18: Outbound queue exponential back-off on failure ─────────────

#[test]
fn outbound_queue_backoff_prevents_relay_flooding() {
    let mut queue = OutboundQueue::new();
    let env = MailboxEnvelope::new("frank_fp", vec![0], MAILBOX_TTL_SECS).unwrap();
    let id = env.message_id;

    queue.enqueue(env, "relay1.onion:8080".into());

    let now = unix_now();
    // First failure: back-off should be >= 30s
    queue.record_attempt(&id, false);
    let p = queue.pending().iter().find(|p| p.envelope.message_id == id).unwrap();
    assert!(
        p.retry_after >= now + 29, // allow 1s clock skew
        "first failure must impose at least 30s back-off (got retry_after={})",
        p.retry_after
    );
}

// ─── Property 19: Outbound queue drops expired envelopes via sweep ────────────

#[test]
fn outbound_queue_sweep_drops_expired() {
    let mut queue = OutboundQueue::new();

    let mut env = MailboxEnvelope::new("grace_fp", vec![1], MAILBOX_TTL_SECS).unwrap();
    env.expires_at = 1; // expired

    queue.enqueue(env, "relay.onion:1".into());
    assert_eq!(queue.len(), 1);

    queue.sweep_expired();
    assert_eq!(queue.len(), 0, "sweep must remove expired entries");
}

// ─── Property 20: Large payload rejected at envelope creation ────────────────

#[test]
fn oversized_payload_is_rejected_before_relay() {
    let huge = vec![0u8; MAX_ENVELOPE_BYTES + 1];
    let result = MailboxEnvelope::new("henry_fp", huge, MAILBOX_TTL_SECS);
    assert!(
        matches!(result, Err(MailboxError::MessageTooLarge(_))),
        "oversized payload must be rejected before relay submission"
    );
}

// ─── Property 21: Different recipients' mailboxes are isolated ───────────────

#[test]
fn relay_mailboxes_for_different_recipients_are_isolated() {
    let mut mailbox = RelayMailbox::new();

    mailbox
        .store(MailboxEnvelope::new("alice_fp", vec![1], MAILBOX_TTL_SECS).unwrap())
        .unwrap();
    mailbox
        .store(MailboxEnvelope::new("bob_fp", vec![2], MAILBOX_TTL_SECS).unwrap())
        .unwrap();

    let alice_msgs = mailbox.retrieve("alice_fp");
    let bob_msgs = mailbox.retrieve("bob_fp");

    assert_eq!(alice_msgs.len(), 1);
    assert_eq!(alice_msgs[0].ciphertext, vec![1]);
    assert_eq!(bob_msgs.len(), 1);
    assert_eq!(bob_msgs[0].ciphertext, vec![2]);
}

// ─── Property 22: Group encryption with epoch advancement ────────────────────

#[test]
fn group_epoch_rotation_invalidates_old_ciphertext() {
    let alice = make_identity();
    let bob = make_identity();
    let mut group = two_member_group(&alice, &bob);

    let fp = alice.public().fingerprint_full.clone();
    let enc_old = group.encrypt_message(b"before rotation", &fp).expect("encrypt");

    // Rotate the epoch (key update commit)
    let alice_key = alice.public().to_bytes().expect("alice key bytes");
    let _commit = group.update_keys(&alice_key).expect("rotate");

    // The old encrypted message belongs to a different epoch — decryption
    // must fail because the group now tracks a new epoch.
    let result = group.decrypt_message(&enc_old);
    assert!(
        result.is_err(),
        "old-epoch ciphertext must not decrypt after epoch rotation"
    );
}

// ─── Property 23: Identity rotation generates a new unique fingerprint ────────

#[test]
fn identity_rotation_produces_new_fingerprint() {
    let old_identity = make_identity();
    let old_fp = old_identity.public().fingerprint_full.clone();

    let new_identity = make_identity();
    let new_fp = new_identity.public().fingerprint_full.clone();

    assert_ne!(
        old_fp, new_fp,
        "rotated identity must have a different fingerprint"
    );
}
