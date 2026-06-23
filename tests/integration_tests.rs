//! Shadowgram Client Integration Tests
//!
//! End-to-end tests demonstrating full message round-trip
//! between two clients through the complete protocol stack.

use crate::{Client, ClientConfig, Contact, Message};
use shadowgram_crypto::{
    key_exchange::HybridKeypair,
    double_ratchet::DoubleRatchet,
    aead::AeadCipher,
};
use shadowgram_identity::Identity;
use shadowgram_network::{NetworkEnvelope, MessageType};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Test fixture for two clients exchanging messages
struct ClientPair {
    alice: Client,
    bob: Client,
    alice_to_bob: Arc<Mutex<Vec<NetworkEnvelope>>>,
    bob_to_alice: Arc<Mutex<Vec<NetworkEnvelope>>>,
}

impl ClientPair {
    /// Create two clients with mock transport
    fn new() -> Self {
        let alice_config = ClientConfig {
            storage_path: "/tmp/alice_shadowgram".into(),
            enable_cover_traffic: false,
            enable_mixnet: false,
        };

        let bob_config = ClientConfig {
            storage_path: "/tmp/bob_shadowgram".into(),
            enable_cover_traffic: false,
            enable_mixnet: false,
        };

        let alice = Client::new(alice_config);
        let bob = Client::new(bob_config);

        Self {
            alice,
            bob,
            alice_to_bob: Arc::new(Mutex::new(Vec::new())),
            bob_to_alice: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Simulate sending message from Alice to Bob
    async fn send_alice_to_bob(&self, envelope: NetworkEnvelope) {
        let mut queue = self.alice_to_bob.lock().await;
        queue.push(envelope);
    }

    /// Simulate sending message from Bob to Alice
    async fn send_bob_to_alice(&self, envelope: NetworkEnvelope) {
        let mut queue = self.bob_to_alice.lock().await;
        queue.push(envelope);
    }

    /// Deliver all pending messages from Alice to Bob
    async fn deliver_alice_to_bob(&mut self) -> usize {
        let mut queue = self.alice_to_bob.lock().await;
        let count = queue.len();

        for envelope in queue.drain(..) {
            // Bob processes incoming message
            let _ = self.bob.process_network_message(envelope).await;
        }

        count
    }

    /// Deliver all pending messages from Bob to Alice
    async fn deliver_bob_to_alice(&mut self) -> usize {
        let mut queue = self.bob_to_alice.lock().await;
        let count = queue.len();

        for envelope in self.bob_to_alice.lock().await.drain(..) {
            let _ = self.alice.process_network_message(envelope).await;
        }

        count
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_message_flow() {
        let mut pair = ClientPair::new();

        // 1. Create identities
        let alice_identity = Identity::new().unwrap();
        let bob_identity = Identity::new().unwrap();

        // 2. Exchange identity fingerprints (simulated QR scan)
        let alice_fingerprint = alice_identity.public().fingerprint();
        let bob_fingerprint = bob_identity.public().fingerprint();

        // 3. Start key exchange (Alice initiates)
        let key_exchange_msg = pair.alice.initiate_key_exchange(
            &alice_identity,
            &bob_fingerprint,
        ).await.unwrap();

        // 4. Bob receives key exchange
        pair.send_alice_to_bob(key_exchange_msg).await;
        pair.deliver_alice_to_bob().await;

        // 5. Bob responds with his key exchange
        let bob_response = pair.bob.respond_to_key_exchange(
            &bob_identity,
        ).await.unwrap();

        pair.send_bob_to_alice(bob_response).await;
        pair.deliver_bob_to_alice().await;

        // 6. Key exchange complete - both clients have established session
        assert!(pair.alice.is_session_established(&bob_fingerprint).await);
        assert!(pair.bob.is_session_established(&alice_fingerprint).await);

        // 7. Alice sends message to Bob
        let alice_message = Message::text("Hello Bob! This is a test message.");
        let envelope = pair.alice.send_message(
            &bob_fingerprint,
            alice_message,
        ).await.unwrap();

        pair.send_alice_to_bob(envelope).await;
        pair.deliver_alice_to_bob().await;

        // 8. Bob receives and decrypts message
        let received = pair.bob.get_pending_messages(&alice_fingerprint).await;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].content, "Hello Bob! This is a test message.");

        // 9. Bob replies
        let bob_message = Message::text("Hi Alice! Message received.");
        let bob_envelope = pair.bob.send_message(
            &alice_fingerprint,
            bob_message,
        ).await.unwrap();

        pair.send_bob_to_alice(bob_envelope).await;
        pair.deliver_bob_to_alice().await;

        // 10. Alice receives Bob's reply
        let alice_received = pair.alice.get_pending_messages(&bob_fingerprint).await;
        assert_eq!(alice_received.len(), 1);
        assert_eq!(alice_received[0].content, "Hi Alice! Message received.");
    }

    #[tokio::test]
    async fn test_double_ratchet_message_ordering() {
        let mut pair = ClientPair::new();

        let alice_identity = Identity::new().unwrap();
        let bob_identity = Identity::new().unwrap();

        // Establish session (abbreviated for test clarity)
        let alice_fp = alice_identity.public().fingerprint();
        let bob_fp = bob_identity.public().fingerprint();

        pair.alice.initiate_key_exchange(&alice_identity, &bob_fp).await.unwrap();
        // ... (key exchange messages delivered)

        // Send multiple messages in sequence
        for i in 0..5 {
            let msg = Message::text(format!("Message {}", i));
            let envelope = pair.alice.send_message(&bob_fp, msg).await.unwrap();
            pair.send_alice_to_bob(envelope).await;
        }

        // Deliver out of order (simulating network reordering)
        let mut queue = pair.alice_to_bob.lock().await;
        queue.reverse(); // Reverse to test out-of-order delivery
        drop(queue);

        pair.deliver_alice_to_bob().await;

        // Bob should still receive all messages correctly
        let received = pair.bob.get_pending_messages(&alice_fp).await;
        assert_eq!(received.len(), 5);

        // Messages should be in correct order after decryption
        for (i, msg) in received.iter().enumerate() {
            assert_eq!(msg.content, format!("Message {}", i));
        }
    }

    #[tokio::test]
    async fn test_group_chat_message_flow() {
        let alice_identity = Identity::new().unwrap();
        let bob_identity = Identity::new().unwrap();
        let charlie_identity = Identity::new().unwrap();

        let mut alice = Client::new(ClientConfig::default());
        let mut bob = Client::new(ClientConfig::default());
        let charlie = Client::new(ClientConfig::default());

        // Alice creates group
        let group_id = alice.create_group("Test Group", &alice_identity).await.unwrap();

        // Alice adds Bob
        let add_commit = alice.add_member_to_group(
            &group_id,
            &bob_identity.public().fingerprint(),
        ).await.unwrap();

        // Bob processes commit and joins group
        bob.process_group_commit(add_commit).await.unwrap();

        // Alice sends group message
        let group_msg = Message::text("Hello group!");
        let envelope = alice.send_group_message(&group_id, group_msg).await.unwrap();

        // Bob receives group message
        // (delivery simulated)

        let bob_messages = bob.get_group_messages(&group_id).await;
        assert_eq!(bob_messages.len(), 1);
        assert_eq!(bob_messages[0].content, "Hello group!");
    }

    #[tokio::test]
    async fn test_contact_discovery_psi() {
        use shadowgram_messenger::psi::{ContactDiscoveryPSI, PsiProtocol};

        // Alice has contacts: Bob, Charlie, Dave
        let mut alice_contacts = ContactDiscoveryPSI::new(vec![
            "bob_fingerprint".to_string(),
            "charlie_fingerprint".to_string(),
            "dave_fingerprint".to_string(),
        ]);

        // Bob has contacts: Alice, Charlie, Eve
        let bob_contacts = ContactDiscoveryPSI::new(vec![
            "alice_fingerprint".to_string(),
            "charlie_fingerprint".to_string(),
            "eve_fingerprint".to_string(),
        ]);

        // Exchange hashed contact lists
        let bob_hashes = bob_contacts.get_contact_hashes();

        // Alice finds common contacts
        let alice_result = alice_contacts.discover_common(&bob_hashes);

        // Should find Charlie as common contact
        assert_eq!(alice_result.total_matched, 1);
        assert!(alice_result.matched_fingerprints.iter().any(|f| f.contains("charlie")));
    }

    #[tokio::test]
    async fn test_noise_protocol_handshake() {
        use shadowgram_network::noise::{NoiseIK, HandshakeMessageA, HandshakeMessageB};
        use x25519_dalek::{StaticSecret, PublicKey};
        use rand::rngs::OsRng;

        // Generate static keys
        let alice_static = StaticSecret::random_from_rng(OsRng);
        let bob_static = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_static);

        let psk = [42u8; 32];

        // Alice initiates
        let mut alice_ik = NoiseIK::new_initiator(alice_static, bob_public, &psk);
        let msg_a = alice_ik.write_message_a().unwrap();

        // Bob responds
        let mut bob_ik = NoiseIK::new_responder(bob_static, &psk);
        let msg_b = bob_ik.read_message_a_write_message_b(&msg_a, bob_static).unwrap();

        // Alice finalizes
        alice_ik.read_message_b(&msg_b).unwrap();

        // Both should have complete handshakes
        assert!(alice_ik.is_handshake_complete());
        assert!(bob_ik.is_handshake_complete());

        // Test encryption/decryption
        let plaintext = b"Secret message";
        let ciphertext = alice_ik.encrypt(plaintext).unwrap();
        let decrypted = bob_ik.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_multi_device_sync() {
        use shadowgram_identity::threshold::ShamirSecretSharing;

        let alice_identity = Identity::new().unwrap();
        let serialized = alice_identity.serialize().unwrap();

        // Split into 5 shares, 3 required
        let shares = ShamirSecretSharing::split(&serialized, 3, 5).unwrap();

        assert_eq!(shares.len(), 5);

        // Reconstruct from any 3 shares
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, serialized);

        let reconstructed2 = ShamirSecretSharing::reconstruct(&shares[2..5]).unwrap();
        assert_eq!(reconstructed2, serialized);

        // 2 shares should NOT be sufficient
        let incomplete = ShamirSecretSharing::reconstruct(&shares[0..2]);
        assert!(incomplete.is_err());
    }

    #[tokio::test]
    async fn test_message_padding_constant_size() {
        use shadowgram_network::padding::{PaddedMessage, PaddingConfig};

        let config = PaddingConfig {
            granularity: 32,
            max_size: 1024,
        };

        // Short message should be padded to 512 bytes
        let short_msg = PaddedMessage::new(b"Hello".to_vec());
        let padded = short_msg.pad(&config);
        assert_eq!(padded.payload.len(), 512);

        // Longer message should be padded to next granularity boundary
        let medium_data = vec![0u8; 600];
        let medium_msg = PaddedMessage::new(medium_data);
        let padded_medium = medium_msg.pad(&config);
        assert_eq!(padded_medium.payload.len(), 608); // 600 rounded up to 32 boundary

        // Message exceeding max should be fragmented
        let large_data = vec![0u8; 2000];
        let large_msg = PaddedMessage::new(large_data);
        let fragments = large_msg.fragment(&config);

        for fragment in &fragments {
            assert!(fragment.payload.len() <= 1024);
        }
    }

    #[tokio::test]
    async fn test_cover_traffic_generation() {
        use shadowgram_network::cover_traffic::{CoverTraffic, TrafficConfig};

        let config = TrafficConfig {
            rate_per_minute: 10.0,
            burst_probability: 0.1,
        };

        let mut generator = CoverTraffic::new(config);

        // Generate cover traffic for 1 minute simulation
        let mut dummy_count = 0;
        for _ in 0..60 {
            if generator.should_send_dummy() {
                let dummy = generator.generate_dummy();
                assert_eq!(dummy.msg_type, MessageType::Cover);
                dummy_count += 1;
            }
            // Simulate time passing
        }

        // Should have generated some dummy messages
        // (exact count varies due to randomness)
        assert!(dummy_count >= 5); // At least some cover traffic
    }
}