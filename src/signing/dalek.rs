//! [`ed25519_dalek`]-backed (RFC 8032 strict) signature verification.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;

use ed25519_dalek::{Signature, VerifyingKey};

use super::SignatureVerifier;

/// Verifies Ed25519 signatures with [`ed25519_dalek`] (RFC 8032 strict).
///
/// Prefer `ConsensusVerifier` (ZIP-215) for federation workloads; this
/// backend is for callers with an existing dalek keyring.
#[derive(Default)]
pub struct DalekVerifier {
    keys: BTreeMap<(String, String), VerifyingKey>,
}

impl DalekVerifier {
    /// Creates an empty verifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a public key for `(server_name, key_id)`.
    pub fn insert(&mut self, server_name: &str, key_id: &str, key: VerifyingKey) -> &mut Self {
        self.keys
            .insert((server_name.to_string(), key_id.to_string()), key);
        self
    }

    /// Registers a raw 32-byte public key for `(server_name, key_id)`.
    ///
    /// # Errors
    /// Returns `Err` if `public_key` is not a valid 32-byte Ed25519 public key.
    pub fn insert_public_key(
        &mut self,
        server_name: &str,
        key_id: &str,
        public_key: &[u8],
    ) -> Result<&mut Self, String> {
        let key = VerifyingKey::try_from(public_key).map_err(|e| alloc::format!("{e}"))?;
        Ok(self.insert(server_name, key_id, key))
    }
}

impl SignatureVerifier for DalekVerifier {
    fn has_key(&self, server_name: &str, key_id: &str) -> bool {
        self.keys
            .contains_key(&(server_name.to_string(), key_id.to_string()))
    }

    fn verify(
        &self,
        server_name: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let key = self
            .keys
            .get(&(server_name.to_string(), key_id.to_string()))
            .ok_or_else(|| alloc::format!("no public key for {server_name}/{key_id}"))?;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| alloc::string::String::from("signature must be 64 bytes"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        key.verify_strict(message, &sig)
            .map_err(|e| alloc::format!("signature verification failed: {e}"))
    }
}
