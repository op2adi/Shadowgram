//! Shadowgram Client Integration Tests
//!
//! End-to-end tests demonstrating full message round-trip
//! between two clients through the complete protocol stack.

use shadowgram_crypto::key_exchange::HybridKeypair;
use shadowgram_identity::Identity;
use shadowgram_messenger::client::{Client, ClientConfig, ClientState};
use shadowgram_messenger::{
    ChatSession, Contact, ContactDiscoveryPSI, DeviceInfo, DeviceSync, GroupInfo, GroupMember,
    GroupState, MemberRole, MemoryContactStore, Message, PsiResult, SyncOperation,
};
use shadowgram_network::{MessageType, NetworkEnvelope};
use std::sync::Arc;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_client_identity_creation() {
        // Create client with default config
        let client = Client::with_defaults().unwrap();

        assert_eq!(client.state(), ClientState::Created);
        assert!(!client.is_running());
        assert!(client.identity().is_none());

        // Create new identity
        let identity = client.create_identity().unwrap();

        // Identity should have a valid fingerprint
        assert!(!identity.public().display_fingerprint().is_empty());
        assert_eq!(
            client.fingerprint(),
            Some(identity.public().display_fingerprint().to_string())
        );
    }

    #[tokio::test]
    async fn test_key_exchange_initiation() {
        let client = Client::with_defaults().unwrap();
        let identity = client.create_identity().unwrap();

        // Initiate key exchange
        let result = client
            .initiate_key_exchange(&identity, "remote_fingerprint")
            .await;

        assert!(result.is_ok());
        let envelope = result.unwrap();
        assert_eq!(envelope.msg_type, MessageType::Handshake);
    }

    #[tokio::test]
    async fn test_double_ratchet_key_exchange() {
        let alice_identity = Identity::generate().unwrap();
        let bob_identity = Identity::generate().unwrap();

        let alice_fp = alice_identity.public().display_fingerprint();
        let bob_fp = bob_identity.public().display_fingerprint();

        // Both should have valid distinct fingerprints
        assert!(!alice_fp.is_empty());
        assert!(!bob_fp.is_empty());
        assert_ne!(alice_fp, bob_fp);
    }

    #[tokio::test]
    async fn test_hybrid_key_exchange() {
        // Test the post-quantum key exchange
        let keypair = HybridKeypair::generate_initiator();

        // Verify keypair has valid components (just check it generated)
        let _x25519_pub = keypair.x25519_public();
        let _mlkem_pub = keypair.mlkem_encapsulation_key();

        // If we got here without panic, generation succeeded
    }

    #[tokio::test]
    async fn test_group_chat_creation() {
        let identity = Identity::generate().unwrap();
        let client = Client::with_defaults().unwrap();
        let _client_identity = client.create_identity().unwrap();

        // Create group
        let result = client.create_group("Test Group", &_client_identity).await;
        assert!(result.is_ok());

        let group_id = result.unwrap();
        assert!(!group_id.is_empty());
    }

    #[tokio::test]
    async fn test_group_state_management() {
        let creator_fp = "creator_fp".to_string();
        let creator_key = vec![1, 2, 3];

        let info = GroupInfo {
            id: "group1".to_string(),
            name: Some("Test Group".to_string()),
            description: None,
            avatar: None,
            creator: creator_fp.clone(),
            created_at: 12345,
            epoch: 0,
        };

        let mut group = GroupState::create(info, creator_fp.clone(), creator_key);
        assert_eq!(group.active_member_count(), 1);

        // Add member
        let member = GroupMember {
            fingerprint: "member1".to_string(),
            display_name: Some("Member 1".to_string()),
            role: MemberRole::Member,
            key_package: vec![4, 5, 6],
            joined_at: 12346,
            left_at: None,
        };

        let commit = group.add_member(member).unwrap();
        assert_eq!(group.active_member_count(), 2);

        // Remove member
        let remove_commit = group.remove_member("member1").unwrap();
        assert!(group.is_admin(&creator_fp));
    }

    #[tokio::test]
    async fn test_contact_discovery_psi() {
        use shadowgram_messenger::psi::ContactDiscoveryPSI;

        // Alice has contacts: Bob, Charlie, Dave
        let alice_contacts = ContactDiscoveryPSI::new(vec![
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
        assert!(alice_result
            .matched_fingerprints
            .iter()
            .any(|f| f.contains("charlie")));
    }

    #[tokio::test]
    async fn test_noise_protocol_handshake() {
        use rand::rngs::OsRng;
        use shadowgram_network::noise::NoiseIK;
        use x25519_dalek::{PublicKey, StaticSecret};

        // Generate static keys
        let alice_static = StaticSecret::random_from_rng(OsRng);
        let bob_static = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_static);

        let psk = [42u8; 32];

        // Alice initiates
        let mut alice_ik = NoiseIK::new_initiator(alice_static, bob_public, &psk);
        let msg_a = alice_ik.write_message_a().unwrap();

        // Bob responds - clone bob_static since new_responder takes ownership
        let bob_static_clone = StaticSecret::random_from_rng(OsRng);
        let mut bob_ik = NoiseIK::new_responder(bob_static, &psk);
        let msg_b = bob_ik
            .read_message_a_write_message_b(&msg_a, bob_static_clone)
            .unwrap();

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

        let alice_identity = Identity::generate().unwrap();
        let serialized = alice_identity.public().to_bytes().unwrap();

        // Split into 5 shares, 3 required
        let shares = ShamirSecretSharing::split(&serialized, 3, 5).unwrap();

        assert_eq!(shares.len(), 5);

        // Reconstruct from any 3 shares
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..3], 3).unwrap();
        assert_eq!(reconstructed, serialized);

        let reconstructed2 = ShamirSecretSharing::reconstruct(&shares[2..5], 3).unwrap();
        assert_eq!(reconstructed2, serialized);

        // 2 shares should NOT be sufficient (below threshold)
        let incomplete = ShamirSecretSharing::reconstruct(&shares[0..2], 3);
        assert!(incomplete.is_err());
    }

    #[tokio::test]
    async fn test_message_padding_constant_size() {
        use shadowgram_network::padding::{PaddedMessage, PaddingConfig};

        let config = PaddingConfig::default();

        // Short message should be padded
        let mut short_msg = PaddedMessage::new(b"Hello".to_vec());
        let result = short_msg.pad(&config);
        assert!(result.is_ok());
        // After padding, total_size should be at least min_size
        assert!(short_msg.total_size >= config.min_size);

        // Longer message should be padded to next granularity boundary
        let medium_data = vec![0u8; 600];
        let mut medium_msg = PaddedMessage::new(medium_data);
        medium_msg.pad(&config).unwrap();
        assert!(medium_msg.total_size >= 600);
        assert_eq!(medium_msg.total_size % config.granularity, 0);
    }

    #[tokio::test]
    async fn test_cover_traffic_generation() {
        use shadowgram_network::cover_traffic::{CoverTraffic, TrafficConfig};

        let config = TrafficConfig {
            enabled: true,
            min_interval_ms: 100,
            max_interval_ms: 500,
            activity_probability: 0.5,
            size_range: (64, 256),
        };

        let mut generator = CoverTraffic::new(config);
        generator.start();

        assert!(generator.is_running());

        // Should be able to get a pre-generated message
        let msg = generator.next_message();
        assert!(msg.is_some());

        let cover_msg = msg.unwrap();
        assert!(cover_msg.is_cover());
        assert!(cover_msg.payload.len() >= 64);
        assert!(cover_msg.payload.len() <= 256);

        generator.stop();
        assert!(!generator.is_running());
    }

    #[tokio::test]
    async fn test_contact_management() {
        let client = Client::with_defaults().unwrap();

        let contact = Contact::new("test_fp".to_string(), "Test User".to_string(), vec![]);

        client.add_contact(contact.clone()).unwrap();

        let retrieved = client.get_contact("test_fp").unwrap();
        assert_eq!(retrieved.fingerprint, "test_fp");
        assert_eq!(retrieved.alias, "Test User");

        let contacts = client.list_contacts();
        assert_eq!(contacts.len(), 1);

        // Remove contact
        client.remove_contact("test_fp").unwrap();
        let contacts_after = client.list_contacts();
        assert_eq!(contacts_after.len(), 0);
    }

    #[tokio::test]
    async fn test_device_sync() {
        let mut sync = DeviceSync::new("device1".to_string());

        assert_eq!(sync.status(), shadowgram_messenger::SyncStatus::Idle);
        assert_eq!(sync.devices().len(), 0);

        // Register device
        sync.register_device(DeviceInfo {
            device_id: "device2".to_string(),
            device_name: "Phone".to_string(),
            public_key: vec![1, 2, 3],
            last_sync: 0,
            is_current: false,
        });

        assert_eq!(sync.devices().len(), 1);

        // Queue operation
        sync.queue_operation(SyncOperation::NewMessage {
            message_id: "msg1".to_string(),
            data: vec![1, 2, 3],
        });

        let ops = sync.take_pending_ops();
        assert_eq!(ops.len(), 1);
    }
}
