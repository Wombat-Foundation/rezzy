//! Part-B-style responder attestations over an [`UnsignedRoot`].
//!
//! This is deliberately *not* a production attestation-issuing service: no
//! key rotation, no multi-tenant key management, no revocation. It is the
//! minimal thing that turns an [`UnsignedRoot`] -- a locally-computed value
//! nobody has vouched for -- into a signed claim a third party can actually
//! check, scoped to whichever single key the caller hands in. Per MSC4511C
//! ("Relationship to other proposals"), this is the same trust model as
//! archived Part B: the signer is a *responder*, not a room participant
//! whose signature is folded into event identity. "rezzy signed this," not
//! "the room's DAG committed to this."
//!
//! If rezzy grows into something that issues attestations to other servers
//! as a matter of course (not just a CLI/tooling demo), replace this module
//! rather than build on it -- real key management (rotation, multiple
//! concurrent keys, revocation) is a different, larger piece of work than
//! what's here.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde_json::json;

use crate::merkle::UnsignedRoot;

/// A [`UnsignedRoot`] signed by a single responder, plus enough context to
/// verify it: which root, over what kind of structure, how many entries it
/// commits to, and who's vouching.
///
/// The signed envelope is `{"algorithm", "count", "root", "signer"}` as
/// Matrix Canonical JSON -- see [`sign_attestation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttestation {
    /// The attested root.
    pub root: UnsignedRoot,
    /// Free-form label for what kind of root this is, e.g.
    /// `"msc4511c-causal-trie"` or `"msc4511c-state-root"`. Not
    /// standardized; purely so a verifier knows how to interpret `root`.
    pub algorithm: String,
    /// Number of entries (keys/leaves) committed by `root`.
    pub count: u64,
    /// Opaque identifier for whoever signed this (e.g. a server name or
    /// tool identity). Not verified against the key itself -- the caller
    /// supplied both and is asserting they go together.
    pub signer: String,
    /// The Ed25519 signature over the canonical JSON envelope.
    pub signature: [u8; 64],
}

fn envelope_bytes(root: UnsignedRoot, algorithm: &str, count: u64, signer: &str) -> Vec<u8> {
    let value = json!({
        "algorithm": algorithm,
        "count": count,
        "root": URL_SAFE_NO_PAD.encode(root.into_inner()),
        "signer": signer,
    });
    // `algorithm`/`root`/`signer` are always strings, and `count` fits
    // Matrix's canonical-integer range for any trie/state-map size that will
    // ever exist in practice (2^53-1 leaves). If this ever *does* fail
    // (e.g. a caller passes a `count` from a corrupted/adversarial upstream
    // computation rather than an actual trie size), falling back to `b""`
    // would be a real cryptographic hazard, not a graceful degradation:
    // Ed25519 is deterministic, so both `sign_attestation` and
    // `verify_attestation` would silently operate over the same empty
    // message regardless of the real root/count/algorithm/signer, making
    // any two such attestations from the same key interchangeable. Fail
    // loudly instead.
    crate::merkle::canonical_json(&value).expect(
        "attestation envelope is fixed-shape String/u64/base64 fields, always canonicalizable",
    )
}

/// Signs `root` with `key`, producing a [`SignedAttestation`] a holder of
/// the corresponding [`VerifyingKey`] can check with [`verify_attestation`].
///
/// This is the tool (or whichever process holds `key`) vouching for `root`
/// as a responder -- see the module docs for what that guarantees and, more
/// importantly, what it does not.
#[must_use]
pub fn sign_attestation(
    root: UnsignedRoot,
    algorithm: &str,
    count: u64,
    signer: &str,
    key: &SigningKey,
) -> SignedAttestation {
    let message = envelope_bytes(root, algorithm, count, signer);
    let signature = key.sign(&message).to_bytes();
    SignedAttestation {
        root,
        algorithm: algorithm.to_string(),
        count,
        signer: signer.to_string(),
        signature,
    }
}

/// Verifies a [`SignedAttestation`] against the claimed signer's
/// [`VerifyingKey`].
///
/// This only checks the signature is valid over the envelope; it does not
/// (and cannot) check that `attestation.root` is actually correct for
/// whatever `attestation.count` entries it claims to commit -- that's on
/// whoever generated the underlying trie/state map in the first place, the
/// same trust-on-first-use the rest of this crate relies on for cached
/// parent state.
///
/// # Errors
/// Returns `Err` if the signature does not verify over the reconstructed
/// envelope.
pub fn verify_attestation(
    attestation: &SignedAttestation,
    key: &VerifyingKey,
) -> Result<(), String> {
    let message = envelope_bytes(
        attestation.root,
        &attestation.algorithm,
        attestation.count,
        &attestation.signer,
    );
    let signature = Signature::from_bytes(&attestation.signature);
    key.verify_strict(&message, &signature)
        .map_err(|e| alloc::format!("attestation signature verification failed: {e}"))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let sk = SigningKey::from_bytes(&[42_u8; 32]);
        let vk = sk.verifying_key();
        let root = UnsignedRoot([7_u8; 32]);
        let att = sign_attestation(root, "msc4511c-causal-trie", 100, "rezzy-cli", &sk);
        assert_eq!(att.root, root);
        verify_attestation(&att, &vk).expect("valid attestation must verify");
    }

    #[test]
    fn rejects_tampered_root() {
        let sk = SigningKey::from_bytes(&[42_u8; 32]);
        let vk = sk.verifying_key();
        let root = UnsignedRoot([7_u8; 32]);
        let mut att = sign_attestation(root, "msc4511c-causal-trie", 100, "rezzy-cli", &sk);
        att.root = UnsignedRoot([8_u8; 32]);
        verify_attestation(&att, &vk).expect_err("tampered root must not verify");
    }

    #[test]
    fn rejects_tampered_count() {
        let sk = SigningKey::from_bytes(&[42_u8; 32]);
        let vk = sk.verifying_key();
        let root = UnsignedRoot([7_u8; 32]);
        let mut att = sign_attestation(root, "msc4511c-causal-trie", 100, "rezzy-cli", &sk);
        att.count = 101;
        verify_attestation(&att, &vk).expect_err("tampered count must not verify");
    }

    #[test]
    fn rejects_tampered_algorithm() {
        let sk = SigningKey::from_bytes(&[42_u8; 32]);
        let vk = sk.verifying_key();
        let root = UnsignedRoot([7_u8; 32]);
        let mut att = sign_attestation(root, "msc4511c-causal-trie", 100, "rezzy-cli", &sk);
        att.algorithm = "msc4511c-state-root".to_string();
        verify_attestation(&att, &vk).expect_err("tampered algorithm must not verify");
    }

    #[test]
    fn rejects_tampered_signer() {
        let sk = SigningKey::from_bytes(&[42_u8; 32]);
        let vk = sk.verifying_key();
        let root = UnsignedRoot([7_u8; 32]);
        let mut att = sign_attestation(root, "msc4511c-causal-trie", 100, "rezzy-cli", &sk);
        att.signer = "someone-else".to_string();
        verify_attestation(&att, &vk).expect_err("tampered signer must not verify");
    }

    /// Regression test for the `unwrap_or_default()` bug this replaced:
    /// signing over a large-but-in-range `count` must still bind that count
    /// into the signature (not silently collapse to an empty/fixed message
    /// that any other broken attestation from the same key would also
    /// satisfy).
    #[test]
    fn large_count_still_produces_a_root_specific_signature() {
        // Matrix's canonical-integer bound (2^53 - 1) -- the largest count
        // envelope_bytes can actually canonicalize.
        let max_canonical: u64 = (1_u64 << 53) - 1;
        let sk = SigningKey::from_bytes(&[42_u8; 32]);
        let vk = sk.verifying_key();
        let root = UnsignedRoot([7_u8; 32]);
        let att = sign_attestation(
            root,
            "msc4511c-causal-trie",
            max_canonical,
            "rezzy-cli",
            &sk,
        );
        verify_attestation(&att, &vk).expect("max-canonical count must still verify");

        let other_root = UnsignedRoot([9_u8; 32]);
        let other_att = sign_attestation(
            other_root,
            "msc4511c-causal-trie",
            max_canonical,
            "rezzy-cli",
            &sk,
        );
        assert_ne!(
            att.signature, other_att.signature,
            "two distinct roots must not produce the same signature"
        );
    }

    /// A `count` outside Matrix's canonical-integer range must fail loudly
    /// (panic), not silently sign/verify over an empty envelope -- the
    /// exact hazard `unwrap_or_default()` created (see the module's
    /// `envelope_bytes` doc comment). Ed25519 being deterministic means a
    /// silent empty-message fallback would make every such broken
    /// attestation from one key interchangeable with every other.
    #[test]
    #[should_panic(expected = "attestation envelope is fixed-shape")]
    fn out_of_range_count_panics_instead_of_forging() {
        let sk = SigningKey::from_bytes(&[42_u8; 32]);
        let root = UnsignedRoot([7_u8; 32]);
        let _ = sign_attestation(root, "msc4511c-causal-trie", u64::MAX, "rezzy-cli", &sk);
    }

    #[test]
    fn rejects_wrong_key() {
        let sk = SigningKey::from_bytes(&[42_u8; 32]);
        let other_vk = SigningKey::from_bytes(&[43_u8; 32]).verifying_key();
        let root = UnsignedRoot([7_u8; 32]);
        let att = sign_attestation(root, "msc4511c-causal-trie", 100, "rezzy-cli", &sk);
        verify_attestation(&att, &other_vk).expect_err("wrong key must not verify");
    }
}
