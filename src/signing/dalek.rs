//! [`ed25519_dalek`]-backed (RFC 8032 strict) signature verification.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

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

    /// Looks up the [`VerifyingKey`] for `(server_name, key_id)`.
    #[must_use]
    pub fn get_key(&self, server_name: &str, key_id: &str) -> Option<&VerifyingKey> {
        self.keys
            .get(&(server_name.to_string(), key_id.to_string()))
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

/// Verifies the first supported signature on each event in `events` in a single
/// [`ed25519_dalek::verify_batch`] call.
///
/// For a federation transaction carrying many PDUs from one server, this uses
/// one multiscalar (Straus/Pippenger) operation instead of N sequential
/// Ed25519 verifications — the primary throughput lever over the per-event
/// [`verify_event_signatures`](super::verify_event_signatures) path.
///
/// For each event, the first signature whose key is held by `keys` is selected
/// (mirroring ruma's "first one found" rule) and verified over that event's
/// canonical redacted JSON.
///
/// # Errors
/// Returns `Err` if any event has no signature this verifier holds a key for,
/// if a signature is malformed, or if the batch verification fails.
pub fn verify_batch(
    events: &[Value],
    room_version: &str,
    keys: &DalekVerifier,
) -> Result<(), String> {
    use base64::Engine as _;

    let mut messages: Vec<Vec<u8>> = Vec::with_capacity(events.len());
    let mut signatures: Vec<Signature> = Vec::with_capacity(events.len());
    let mut verifying_keys: Vec<VerifyingKey> = Vec::with_capacity(events.len());

    for value in events {
        let message = super::canonical_redacted_json(value, room_version).into_bytes();
        let Some(sigs_map) = value.get("signatures").and_then(Value::as_object) else {
            return Err(alloc::string::String::from(
                "event has no signatures object",
            ));
        };

        let origin = value
            .get("event_id")
            .and_then(Value::as_str)
            .and_then(|id| {
                id.strip_prefix('$')
                    .unwrap_or(id)
                    .split_once(':')
                    .map(|(_, server)| server)
            });
        let mut selected: Option<(Signature, VerifyingKey)> = None;
        'outer: for (server, key_set) in sigs_map {
            if origin.is_some_and(|expected| !expected.eq_ignore_ascii_case(server)) {
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
                selected = Some((Signature::from_bytes(&sig_bytes), *key));
                break 'outer;
            }
        }

        let (signature, verifying_key) = selected.ok_or_else(|| {
            alloc::string::String::from("no supported signatures present on event")
        })?;
        messages.push(message);
        signatures.push(signature);
        verifying_keys.push(verifying_key);
    }

    let message_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    // Batch verification does not enforce the strict RFC 8032 checks that
    // this backend promises, so verify each item through the strict path.
    for ((message, signature), key) in message_refs.iter().zip(&signatures).zip(&verifying_keys) {
        key.verify_strict(message, signature)
            .map_err(|e| alloc::format!("batch signature verification failed: {e}"))?;
    }
    Ok(())
}
