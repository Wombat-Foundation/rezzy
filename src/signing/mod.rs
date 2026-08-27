//! Event signature verification (Ed25519).
//!
//! rezzy's core stays crypto-free: graph/state resolution carries no key
//! machinery. Enabling the `signing` feature pulls in the Ed25519 backend
//! behind a [`SignatureVerifier`] trait:
//!
//! - `signing` (default) / `signing-dalek` — [`ed25519_dalek`] (RFC 8032
//!   strict). Shares rezzy's `sha2 0.10`, so no duplicate hash crate is
//!   pulled.
//!
//! Both backends verify over the canonical redacted JSON produced by
//! [`crate::basespec::rezzy_types::canonical_redacted_json`] — the same
//! redaction/canonicalization source of truth used for reference hashes and
//! auth, so a redaction-vs-signer mismatch (the MSC4242 `prev_state_events`
//! class of bug) cannot recur.
//!
//! ```
//! # #[cfg(feature = "signing")]
//! # fn example() -> Result<(), String> {
//! use rezzy::signing::{verify_event_signatures, DalekVerifier};
//! use serde_json::json;
//!
//! let mut keys = DalekVerifier::new();
//! keys.insert_public_key("example.com", "ed25519:0", &[0_u8; 32])?;
//!
//! let event = json!({
//!     "type": "m.room.message",
//!     "content": { "body": "hi" },
//!     "signatures": { "example.com": {} },
//! });
//! verify_event_signatures(&event, "10", &keys)
//! # }
//! ```

use alloc::string::String;
use alloc::string::ToString;
use serde_json::Value;

use crate::basespec::rezzy_types::{canonical_redacted_json, EventVerifier};

#[cfg(any(feature = "signing", feature = "signing-dalek"))]
mod dalek;
#[cfg(any(feature = "signing", feature = "signing-dalek"))]
pub use dalek::{verify_batch, DalekVerifier};

/// A backend able to verify one Ed25519 signature over a message.
///
/// Implementations hold a set of `(server_name, key_id)` → public key and
/// check whether they can verify a signature for a given key.
pub trait SignatureVerifier {
    /// Returns `true` if this verifier holds a public key for the signature
    /// key identified by `(server_name, key_id)`.
    #[must_use]
    fn has_key(&self, server_name: &str, key_id: &str) -> bool;

    /// Verifies `signature` over `message` for the key `(server_name, key_id)`.
    ///
    /// # Errors
    /// Returns `Err` when the key is unknown, the signature is malformed, or
    /// the signature does not verify.
    fn verify(
        &self,
        server_name: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;
}

/// Verifies every signature in `value["signatures"][server][key_id]` that
/// `verifier` holds a key for, over the canonical redacted JSON of `value`.
///
/// The signature is computed over [`canonical_redacted_json`] — redacted per
/// room version, with `unsigned`/`signatures` stripped and keys sorted — so
/// this stays consistent with reference hashing and auth.
///
/// # Errors
/// Returns `Err` when the event carries no `signatures` object, when a
/// signature present for a known key fails to verify, or when its base64
/// encoding is malformed.
pub fn verify_event_signatures(
    value: &Value,
    room_version: &str,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    use base64::Engine as _;

    let message = canonical_redacted_json(value, room_version).into_bytes();
    let Some(signatures) = value.get("signatures").and_then(Value::as_object) else {
        return Err(alloc::string::String::from(
            "event has no signatures object",
        ));
    };
    let origin = value
        .get("event_id")
        .and_then(Value::as_str)
        .and_then(|id| id.rsplit_once(':').map(|(_, server)| server));

    let mut verified_any = false;
    for (server, keys) in signatures {
        if origin.is_some_and(|expected| expected != server) {
            continue;
        }
        let Some(keys_obj) = keys.as_object() else {
            continue;
        };
        for (key_id, sig) in keys_obj {
            if !verifier.has_key(server, key_id) {
                continue;
            }
            verified_any = true;
            let Some(sig_str) = sig.as_str() else {
                return Err(alloc::format!(
                    "signature for {server}/{key_id} is not a string"
                ));
            };
            let sig_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(sig_str)
                .map_err(|e| alloc::format!("bad base64 for {server}/{key_id}: {e}"))?;
            verifier.verify(server, key_id, &message, &sig_bytes)?;
        }
    }

    if !verified_any {
        return Err(alloc::string::String::from(
            "no supported signatures present on event",
        ));
    }
    Ok(())
}

/// A [`EventVerifier`] backed by a [`SignatureVerifier`] and an in-memory
/// event store (`Id` → raw PDU [`Value`]), keyed by event ID.
///
/// This adapts the value-level signing engine to the `EventVerifier<Id>` hook
/// used by the auth path, so callers can wire rezzy-native verification into
/// [`crate::auth`] without re-implementing canonicalization/redaction.
pub struct NativeVerifier<Id, K> {
    events: crate::HashMap<Id, Value>,
    room_version: String,
    verifier: K,
}

impl<Id, K: SignatureVerifier> NativeVerifier<Id, K> {
    /// Creates a verifier over `events` (an `Id` → raw PDU map).
    #[must_use]
    pub fn new(events: crate::HashMap<Id, Value>, room_version: &str, verifier: K) -> Self {
        Self {
            events,
            room_version: room_version.to_string(),
            verifier,
        }
    }

    /// The wrapped [`SignatureVerifier`].
    #[must_use]
    pub fn verifier(&self) -> &K {
        &self.verifier
    }
}

impl<Id: core::hash::Hash + Eq + AsRef<str>, K: SignatureVerifier> EventVerifier<Id>
    for NativeVerifier<Id, K>
{
    fn verify_event_id_hash(&self, event_id: &Id) -> Result<(), String> {
        let value = self
            .events
            .get(event_id)
            .ok_or_else(|| alloc::format!("unknown event {}", event_id.as_ref()))?;
        if matches!(self.room_version.as_str(), "1" | "2") {
            Ok(())
        } else {
            let expected = crate::basespec::rezzy_types::reference_hash(value, &self.room_version)?;
            let actual = event_id
                .as_ref()
                .strip_prefix('$')
                .unwrap_or(event_id.as_ref());
            if actual == expected {
                return Ok(());
            }
            Err(alloc::format!(
                "event id hash mismatch for {}: expected {expected}",
                event_id.as_ref()
            ))
        }
    }

    fn verify_signatures(&self, event_id: &Id) -> Result<(), String> {
        let value = self
            .events
            .get(event_id)
            .ok_or_else(|| alloc::format!("unknown event {}", event_id.as_ref()))?;
        verify_event_signatures(value, &self.room_version, &self.verifier)
    }

    fn verify_content_hash(&self, event_id: &Id) -> Result<(), String> {
        let value = self
            .events
            .get(event_id)
            .ok_or_else(|| alloc::format!("unknown event {}", event_id.as_ref()))?;
        crate::basespec::rezzy_types::verify_content_hash(value, &self.room_version)
    }
}

#[cfg(all(test, feature = "signing-dalek"))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod dalek_tests {
    use super::*;
    use alloc::format;
    use alloc::vec::Vec;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;

    fn signed_event(
        mut value: Value,
        room_version: &str,
        server: &str,
        key_id: &str,
        sk: &SigningKey,
    ) -> Value {
        let canonical = canonical_redacted_json(&value, room_version);
        let sig = sk.sign(canonical.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(sig.to_bytes());
        let obj = value.as_object_mut().expect("event is an object");
        obj.entry("signatures")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("signatures is an object")
            .insert(server.to_string(), json!({ key_id: sig_b64 }));
        value
    }

    #[test]
    fn dalek_verifies_round_trip() {
        let sk = SigningKey::from_bytes(&[7_u8; 32]);
        let vk = sk.verifying_key();

        let raw = signed_event(
            json!({
                "type": "m.room.message",
                "room_id": "!r:example.com",
                "sender": "@a:example.com",
                "origin_server_ts": 1,
                "content": { "body": "hi" },
            }),
            "10",
            "example.com",
            "ed25519:0",
            &sk,
        );

        let mut keys = DalekVerifier::new();
        keys.insert_public_key("example.com", "ed25519:0", &vk.to_bytes())
            .unwrap();
        verify_event_signatures(&raw, "10", &keys).unwrap();
    }

    #[test]
    fn dalek_rejects_tampered_preserved_field() {
        let sk = SigningKey::from_bytes(&[8_u8; 32]);
        let vk = sk.verifying_key();

        let mut raw = signed_event(
            json!({
                "type": "m.room.message",
                "room_id": "!r:example.com",
                "sender": "@a:example.com",
                "origin_server_ts": 1,
                "content": { "body": "hi" },
            }),
            "10",
            "example.com",
            "ed25519:0",
            &sk,
        );
        raw["origin_server_ts"] = json!(999);

        let mut keys = DalekVerifier::new();
        keys.insert_public_key("example.com", "ed25519:0", &vk.to_bytes())
            .unwrap();
        assert!(verify_event_signatures(&raw, "10", &keys).is_err());
    }

    #[test]
    fn dalek_batch_verifies_many_events_at_once() {
        let sk = SigningKey::from_bytes(&[9_u8; 32]);
        let vk = sk.verifying_key();
        let mut keys = DalekVerifier::new();
        keys.insert_public_key("example.com", "ed25519:0", &vk.to_bytes())
            .unwrap();

        let events: Vec<Value> = (0..8)
            .map(|i| {
                signed_event(
                    json!({
                        "type": "m.room.message",
                        "room_id": "!r:example.com",
                        "sender": "@a:example.com",
                        "origin_server_ts": i,
                        "content": { "body": format!("msg {i}") },
                    }),
                    "10",
                    "example.com",
                    "ed25519:0",
                    &sk,
                )
            })
            .collect();

        verify_batch(&events, "10", &keys).unwrap();

        // Tampering with one event's preserved field must fail the whole batch.
        let mut tampered = events.clone();
        tampered[3]["origin_server_ts"] = json!(999);
        assert!(verify_batch(&tampered, "10", &keys).is_err());
    }
}
