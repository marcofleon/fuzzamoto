//! Helpers for Erlay (BIP-330) transaction reconciliation.
//!
//! Short transaction ids are link-specific: they are keyed with a salt combined
//! from both peers' `sendtxrcncl` salt contributions. Under the fuzzamoto
//! aggressive-RNG patch (`FUZZAMOTO_FUZZING`), the node's contribution is a
//! compile-time known constant, so short ids can be computed while a program is
//! compiled instead of being captured at runtime. Against unpatched nodes the
//! salt is random and the ids computed here simply won't match, which the node
//! tolerates (unknown short ids are ignored).

use bitcoin::Wtxid;
use bitcoin::hashes::{Hash, sha256};
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

/// Salt the fuzzer contributes in the version handshake (`sendtxrcncl` with
/// salt 0, see `fuzzamoto::connections`).
pub const FUZZER_RECON_SALT: u64 = 0;

/// Salt contributed by a node built with the fuzzamoto aggressive-RNG patch:
/// `TxReconciliationTracker::PreRegisterPeer` draws the salt from a fresh,
/// never-reseeded `FastRandomContext`, i.e. the first 8 bytes of the `ChaCha20`
/// zero-key keystream read as a little-endian u64.
pub const NODE_RECON_SALT: u64 = 0x903d_f1a0_ade0_b876;

/// BIP-330 `ComputeSalt`: tagged hash over both salts in ascending order,
/// yielding the `SipHash` key for short id computation.
#[must_use]
pub fn full_salt(salt1: u64, salt2: u64) -> (u64, u64) {
    let tag_hash = sha256::Hash::hash(b"Tx Relay Salting");
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(tag_hash.as_byte_array());
    data.extend_from_slice(tag_hash.as_byte_array());
    data.extend_from_slice(&salt1.min(salt2).to_le_bytes());
    data.extend_from_slice(&salt1.max(salt2).to_le_bytes());
    let h = sha256::Hash::hash(&data);
    (
        u64::from_le_bytes(h.as_byte_array()[0..8].try_into().unwrap()),
        u64::from_le_bytes(h.as_byte_array()[8..16].try_into().unwrap()),
    )
}

/// BIP-330 short transaction id for `wtxid` on a fuzzer<->node link.
#[must_use]
pub fn short_txid(wtxid: &Wtxid) -> u32 {
    let (k0, k1) = full_salt(NODE_RECON_SALT, FUZZER_RECON_SALT);
    let mut hasher = SipHasher24::new_with_keys(k0, k1);
    hasher.write(&wtxid.to_byte_array());
    // The modulo result is at most 0xFFFF_FFFE, so the +1 cannot overflow
    1 + u32::try_from(hasher.finish() % 0xFFFF_FFFF).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    // Cross-checked against Bitcoin Core's functional test framework
    // (test/functional/test_framework/p2p_txrecon.py: get_short_id with
    // compute_salt, and crypto/siphash.py: siphash256).
    #[test]
    fn short_txid_matches_bitcoin_core() {
        let (k0, k1) = full_salt(NODE_RECON_SALT, FUZZER_RECON_SALT);
        assert_eq!(k0, 0x1343_8c2b_d29e_1761);
        assert_eq!(k1, 0xf986_03d4_d2b5_7654);

        let wtxid = Wtxid::from_byte_array([0x42u8; 32]);
        assert_eq!(short_txid(&wtxid), 4_077_662_624);

        // Hashed as little-endian bytes, i.e. reversed from display order
        let wtxid = Wtxid::from_byte_array([
            0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12,
            0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
            0x03, 0x02, 0x01, 0x00,
        ]);
        assert_eq!(short_txid(&wtxid), 3_491_094_095);
    }
}
