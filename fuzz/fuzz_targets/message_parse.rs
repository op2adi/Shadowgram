//! Shadowgram Fuzzing Targets
//!
//! Fuzzing tests for cryptographic boundaries and protocol edge cases.
//! Run with: cargo fuzz run <target>

#![no_main]

use libfuzzer_sys::fuzz_target;
use shadowgram_crypto::key_exchange::{HybridKeypair, KeyExchangeMessage};
use shadowgram_crypto::double_ratchet::DoubleRatchet;
use shadowgram_network::NetworkEnvelope;
use shadowgram_messenger::psi::PsiProtocol;

// Fuzz target: Key exchange serialization/deserialization
fuzz_target!(|data: &[u8]| {
    // Test key exchange message parsing
    let _ = KeyExchangeMessage::deserialize(data);

    // Test network envelope parsing
    let _ = NetworkEnvelope::deserialize(data);

    // Test PSI with arbitrary input
    if data.len() > 10 {
        let items: Vec<Vec<u8>> = data
            .chunks(10)
            .map(|chunk| chunk.to_vec())
            .collect();
        let _psi = PsiProtocol::new(items);
    }
});