//! [`ed25519_dalek`]-backed (RFC 8032 strict) signature verification.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

use super::SignatureVerifier;

/// Verifies Ed25519 signatures with [`ed25519_dalek`] (RFC 8032 strict).
///
/// This backend is suitable for callers with an existing dalek keyring.
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
            .insert((server_name.to_ascii_lowercase(), key_id.to_string()), key);
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

    /// Looks up the [`VerifyingKey`] for `(server_name, key_id)`.
    #[must_use]
    pub fn get_key(&self, server_name: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys
            .get(&(server_name.to_ascii_lowercase(), key_id.to_string()))
    }
}

impl SignatureVerifier for DalekVerifier {
    fn has_key(&self, server_name: &str, key_id: &str) -> bool {
        self.keys
            .contains_key(&(server_name.to_ascii_lowercase(), key_id.to_string()))
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
            .get(&(server_name.to_ascii_lowercase(), key_id.to_string()))
            .ok_or_else(|| alloc::format!("no public key for {server_name}/{key_id}"))?;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| alloc::string::String::from("signature must be 64 bytes"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        key.verify_strict(message, &sig)
            .map_err(|e| alloc::format!("signature verification failed: {e}"))
    }
}

/// Verifies every signature on each event in `events` whose key is held by
/// `keys`, one signature at a time via [`VerifyingKey::verify_strict`].
///
/// # Not real batch verification
/// Despite the name this superseded, this is a sequential loop, not
/// [`ed25519_dalek::verify_batch`]. That distinction is load-bearing, not
/// cosmetic: `ed25519_dalek::verify_batch` checks the batched (cofactored)
/// verification equation, which is a *different* acceptance criterion than
/// per-signature RFC 8032 strict verification — the two can disagree on the
/// same input (see Chalkias et al., "Taming the many `EdDSAs`", on
/// batch/single-verification mismatches for non-canonical inputs). Matrix
/// federation signature verification promises strict verification (this
/// backend's rejection of non-canonical `S`/malleable signatures), so
/// silently switching the batch to the non-strict batched equation would
/// change what counts as a valid signature. This function keeps the strict
/// per-signature guarantee and pays for it with `O(n)` scalar
/// multiplications instead of the roughly `O(1)`-amortized cost real batch
/// verification can offer; callers who need actual batch throughput and can
/// accept the batched-equation semantics can build on
/// [`ed25519_dalek::verify_batch`] directly.
///
/// For each event, **all** signatures whose key is held by `keys` are collected
/// and must verify — if any held signature is invalid, the batch fails even if
/// other held signatures for the same event are valid. This matches the
/// behavior of [`super::verify_event_signatures`] applied per event.
///
/// # Errors
/// Returns `Err` if any event has no signature this verifier holds a key for,
/// if a signature is malformed, or if verification fails for any signature.
pub fn verify_sequential_strict(
    events: &[Value],
    room_version: &str,
    keys: &DalekVerifier,
) -> Result<(), String> {
    use base64::Engine as _;

    if crate::basespec::rezzy_types::StateResVersion::from_room_version(room_version).is_none() {
        return Err(alloc::format!(
            "unsupported room version {room_version}: cannot verify signatures over an undefined format"
        ));
    }

    for value in events {
        let message = super::try_canonical_redacted_json(value, room_version)
            .map_err(|e| alloc::format!("failed to compute canonical redacted JSON: {e}"))?
            .into_bytes();
        let Some(sigs_map) = value.get("signatures").and_then(Value::as_object) else {
            return Err(alloc::string::String::from(
                "event has no signatures object",
            ));
        };

        let Some(origin) = super::expected_event_signer(value, room_version) else {
            return Err(alloc::string::String::from(
                "could not derive expected event signer from event_id or sender",
            ));
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
                    return Err(alloc::format!(
                        "signature for {server}/{key_id} is not a string"
                    ));
                };
                let raw = base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(sig_str)
                    .map_err(|e| alloc::format!("bad base64 for {server}/{key_id}: {e}"))?;
                let sig_bytes: [u8; 64] = raw
                    .try_into()
                    .map_err(|_| alloc::string::String::from("signature must be 64 bytes"))?;
                let signature = Signature::from_bytes(&sig_bytes);
                // Sequential strict verification -- see the function doc's
                // "Not real batch verification" section for why this calls
                // `verify_strict` immediately per signature instead of
                // buffering everything for `ed25519_dalek::verify_batch`.
                key.verify_strict(&message, &signature)
                    .map_err(|e| alloc::format!("signature verification failed: {e}"))?;
                event_verified_any = true;
            }
        }

        if !event_verified_any {
            return Err(alloc::string::String::from(
                "no supported signatures present on event",
            ));
        }
    }

    Ok(())
}
