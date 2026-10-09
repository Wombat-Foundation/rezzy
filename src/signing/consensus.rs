//! [`ed25519_zebra`]-backed (ZIP 215) signature verification.

use std::collections::BTreeMap;
use std::string::String;
use std::string::ToString;

use crate::errors::SignError;
use crate::json::Value;
use ed25519_zebra::{Signature, VerificationKey};

use super::SignatureVerifier;

/// Verifies Ed25519 signatures with [`ed25519_zebra`] (ZIP 215).
///
/// ZIP 215 fixes one acceptance criterion for every signature, so the verdict
/// is identical across implementations, which is what a federation needs.
#[derive(Default)]
pub struct Ed25519ConsensusVerifier {
    keys: BTreeMap<(String, String), VerificationKey>,
}

impl Ed25519ConsensusVerifier {
    /// Creates an empty verifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a public key for `(server_name, key_id)`.
    pub fn insert(&mut self, server_name: &str, key_id: &str, key: VerificationKey) -> &mut Self {
        self.keys
            .insert((server_name.to_ascii_lowercase(), key_id.to_string()), key);
        self
    }

    /// Registers a raw 32-byte public key for `(server_name, key_id)`.
    ///
    /// # Errors
    /// Returns `Err` if `public_key` is not a valid 32-byte Ed25519 public key.
    pub fn insert_public_key<'a>(
        &mut self,
        server_name: &'a str,
        key_id: &str,
        public_key: &[u8],
    ) -> Result<&mut Self, SignError<'a>> {
        let key =
            VerificationKey::try_from(public_key).map_err(SignError::InvalidVerificationKey)?;
        Ok(self.insert(server_name, key_id, key))
    }

    /// Looks up the [`VerificationKey`] for `(server_name, key_id)`.
    #[must_use]
    pub fn get_key(&self, server_name: &str, key_id: &str) -> Option<&VerificationKey> {
        self.keys
            .get(&(server_name.to_ascii_lowercase(), key_id.to_string()))
    }
}

impl SignatureVerifier for Ed25519ConsensusVerifier {
    fn has_key(&self, server_name: &str, key_id: &str) -> bool {
        self.keys
            .contains_key(&(server_name.to_ascii_lowercase(), key_id.to_string()))
    }

    fn verify<'a>(
        &self,
        server_name: &'a str,
        key_id: &'a str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignError<'a>> {
        let key = self
            .keys
            .get(&(server_name.to_ascii_lowercase(), key_id.to_string()))
            .ok_or(SignError::NoPublicKey {
                server_name,
                key_id,
            })?;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| SignError::SignatureLength)?;
        let sig = Signature::from(sig_bytes);
        key.verify(&sig, message)
            .map_err(SignError::SignatureVerifyFailed)
    }
}

/// Verifies every signature on each event in `events` whose key is held by
/// `keys`, one signature at a time via [`VerificationKey::verify`].
///
/// This is a sequential loop, not batch verification. It uses the same ZIP 215
/// criterion as [`Ed25519ConsensusVerifier`], so a lone signature and a signature in a
/// list always get the same verdict. Callers who want batch throughput can use
/// `ed25519_zebra::batch` directly.
///
/// For each event, **all** signatures whose key is held by `keys` are collected
/// and must verify — if any held signature is invalid, the batch fails even if
/// other held signatures for the same event are valid. This matches the
/// behavior of [`super::verify_event_signatures`] applied per event.
///
/// # Errors
/// Returns `Err` if any event has no signature this verifier holds a key for,
/// if a signature is malformed, or if verification fails for any signature.
pub fn verify_sequential<'a>(
    events: &'a [Value],
    room_version: &'a str,
    keys: &Ed25519ConsensusVerifier,
) -> Result<(), SignError<'a>> {
    use base64::Engine as _;

    if crate::basespec::rezzy_types::StateResVersion::from_room_version(room_version).is_none() {
        return Err(SignError::UnsupportedRoomVersion { room_version });
    }

    for value in events {
        let message = super::try_canonical_redacted_json(value, room_version)
            .map_err(SignError::CanonicalRedacted)?
            .into_bytes();
        let Some(sigs_map) = value.get("signatures").and_then(Value::as_object) else {
            return Err(SignError::NoSignaturesObject);
        };

        let Some(origin) = super::expected_event_signer(value, room_version) else {
            return Err(SignError::NoExpectedSigner);
        };
        let mut event_verified_any = false;
        for (server, key_set) in sigs_map {
            if !origin.eq_ignore_ascii_case(server) {
                continue;
            }
            let Some(key_set) = key_set.as_object() else {
                continue;
            };
            for (key_id, sig_val) in key_set {
                let Some(key) = keys.get_key(server, key_id) else {
                    continue;
                };
                let Some(sig_str) = sig_val.as_str() else {
                    return Err(SignError::SignatureNotAString { server, key_id });
                };
                let raw = base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(sig_str)
                    .map_err(|source| SignError::BadSignatureBase64 {
                        server,
                        key_id,
                        source,
                    })?;
                let sig_bytes: [u8; 64] = raw.try_into().map_err(|_| SignError::SignatureLength)?;
                let signature = Signature::from(sig_bytes);
                // Sequential ZIP 215 verification, one signature at a time.
                key.verify(&signature, &message)
                    .map_err(SignError::SignatureVerifyFailed)?;
                event_verified_any = true;
            }
        }

        if !event_verified_any {
            return Err(SignError::NoSupportedSignaturesPresent);
        }
    }

    Ok(())
}
