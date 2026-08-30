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

use crate::basespec::rezzy_types::{try_canonical_redacted_json, EventVerifier};

#[cfg(all(test, feature = "signing-dalek"))]
use crate::basespec::rezzy_types::canonical_redacted_json;

#[cfg(any(feature = "signing", feature = "signing-dalek"))]
mod dalek;
#[cfg(any(feature = "signing", feature = "signing-dalek"))]
pub use dalek::{verify_sequential_strict, DalekVerifier};

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

/// Extracts the expected homeserver domain that should sign `value` in
/// `room_version`.
///
/// For room versions 1 and 2, event IDs have the form `$localpart:domain.com` and
/// the domain is extracted from the event ID. For room versions 3+, event IDs are
/// content hashes, so the signer is the sender's homeserver (extracted from `@user:domain.com`).
#[must_use]
pub(crate) fn expected_event_signer<'a>(value: &'a Value, room_version: &str) -> Option<&'a str> {
    if matches!(room_version, "1" | "2") {
        let event_id = value.get("event_id").and_then(Value::as_str)?;
        if let Some((_, server)) = event_id
            .strip_prefix('$')
            .unwrap_or(event_id)
            .split_once(':')
        {
            return Some(server);
        }
        return None;
    }
    let sender = value.get("sender").and_then(Value::as_str)?;
    sender
        .strip_prefix('@')
        .unwrap_or(sender)
        .split_once(':')
        .map(|(_, server)| server)
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
    if crate::basespec::rezzy_types::StateResVersion::from_room_version(room_version).is_none() {
        return Err(alloc::format!(
            "unsupported room version {room_version}: cannot verify signatures over an undefined format"
        ));
    }

    let Some(origin) = expected_event_signer(value, room_version) else {
        return Err(alloc::string::String::from(
            "could not derive expected event signer from event_id or sender",
        ));
    };
    verify_event_signatures_from_server(value, room_version, origin, verifier)
}

/// Verifies a signature on `value` from one specific server.
///
/// This is used for restricted joins, where Matrix requires a signature from
/// the homeserver of `join_authorised_via_users_server`, not merely the
/// joining event's origin server.
///
/// # Errors
/// Returns `Err` if the expected server has no supported valid signature.
pub fn verify_event_signatures_from_server(
    value: &Value,
    room_version: &str,
    expected_server: &str,
    verifier: &dyn SignatureVerifier,
) -> Result<(), String> {
    use base64::Engine as _;

    let message = try_canonical_redacted_json(value, room_version)
        .map_err(|e| alloc::format!("failed to compute canonical redacted JSON: {e}"))?
        .into_bytes();
    let Some(signatures) = value.get("signatures").and_then(Value::as_object) else {
        return Err(alloc::string::String::from(
            "event has no signatures object",
        ));
    };
    let mut verified_any = false;
    for (server, keys) in signatures {
        if !expected_server.eq_ignore_ascii_case(server) {
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
        return Err(alloc::format!(
            "no supported signature from required server {expected_server}"
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

    fn verify_join_authorised_via_users_server(
        &self,
        event_id: &Id,
        authorising_user: &str,
    ) -> Result<(), String> {
        let server = crate::basespec::rezzy_types::extract_domain(authorising_user)
            .filter(|server| !server.is_empty())
            .ok_or_else(|| alloc::format!("invalid authorising user ID {authorising_user}"))?;
        let value = self
            .events
            .get(event_id)
            .ok_or_else(|| alloc::format!("unknown event {}", event_id.as_ref()))?;
        verify_event_signatures_from_server(value, &self.room_version, server, &self.verifier)
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

        verify_sequential_strict(&events, "10", &keys).unwrap();

        // Tampering with one event's preserved field must fail the whole batch.
        let mut tampered = events.clone();
        tampered[3]["origin_server_ts"] = json!(999);
        assert!(verify_sequential_strict(&tampered, "10", &keys).is_err());
    }

    #[test]
    fn dalek_verifies_case_insensitive_server_name() {
        let sk = SigningKey::from_bytes(&[10_u8; 32]);
        let vk = sk.verifying_key();

        // 1. Signature map has uppercase server, keyring registered lowercase
        let raw_upper_sig = signed_event(
            json!({
                "event_id": "$1:EXAMPLE.COM",
                "type": "m.room.message",
                "room_id": "!r:example.com",
                "sender": "@a:example.com",
                "origin_server_ts": 1,
                "content": { "body": "hi" },
            }),
            "1",
            "EXAMPLE.COM",
            "ed25519:0",
            &sk,
        );

        let mut keys_lower = DalekVerifier::new();
        keys_lower
            .insert_public_key("example.com", "ed25519:0", &vk.to_bytes())
            .unwrap();
        verify_event_signatures(&raw_upper_sig, "1", &keys_lower).unwrap();
        verify_sequential_strict(core::slice::from_ref(&raw_upper_sig), "1", &keys_lower).unwrap();

        // 2. Signature map has lowercase server, keyring registered uppercase
        let raw_lower_sig = signed_event(
            json!({
                "event_id": "$2:example.com",
                "type": "m.room.message",
                "room_id": "!r:example.com",
                "sender": "@a:example.com",
                "origin_server_ts": 1,
                "content": { "body": "hi" },
            }),
            "1",
            "example.com",
            "ed25519:0",
            &sk,
        );

        let mut keys_upper = DalekVerifier::new();
        keys_upper
            .insert_public_key("EXAMPLE.COM", "ed25519:0", &vk.to_bytes())
            .unwrap();
        verify_event_signatures(&raw_lower_sig, "1", &keys_upper).unwrap();
        verify_sequential_strict(&[raw_lower_sig], "1", &keys_upper).unwrap();
    }

    #[test]
    fn dalek_uses_sender_domain_for_v3_and_later() {
        let sender_key = SigningKey::from_bytes(&[12_u8; 32]);
        let attacker_key = SigningKey::from_bytes(&[13_u8; 32]);
        let event = json!({
            // v3+ PDUs do not carry event_id over federation. If an input does
            // include one, it must not change which homeserver is required to
            // sign the event.
            "event_id": "$legacy:attacker.example",
            "type": "m.room.message",
            "room_id": "!r:sender.example",
            "sender": "@a:sender.example",
            "origin_server_ts": 1,
            "content": { "body": "hi" },
        });

        let attacker_signed = signed_event(
            event.clone(),
            "3",
            "attacker.example",
            "ed25519:0",
            &attacker_key,
        );
        let mut attacker_keys = DalekVerifier::new();
        attacker_keys
            .insert_public_key(
                "attacker.example",
                "ed25519:0",
                &attacker_key.verifying_key().to_bytes(),
            )
            .unwrap();
        assert!(verify_event_signatures(&attacker_signed, "3", &attacker_keys).is_err());
        assert!(verify_sequential_strict(&[attacker_signed], "3", &attacker_keys).is_err());

        let sender_signed = signed_event(event, "3", "sender.example", "ed25519:0", &sender_key);
        let mut sender_keys = DalekVerifier::new();
        sender_keys
            .insert_public_key(
                "sender.example",
                "ed25519:0",
                &sender_key.verifying_key().to_bytes(),
            )
            .unwrap();
        verify_event_signatures(&sender_signed, "3", &sender_keys).unwrap();
        verify_sequential_strict(&[sender_signed], "3", &sender_keys).unwrap();
    }

    #[test]
    fn native_verifier_rejects_unsupported_dotted_version() {
        let sk = SigningKey::from_bytes(&[11_u8; 32]);
        let vk = sk.verifying_key();
        let raw = signed_event(
            json!({
                "type": "m.room.message",
                "room_id": "!r:example.com",
                "sender": "@a:example.com",
                "origin_server_ts": 1,
                "content": { "body": "hi" },
            }),
            "2.1",
            "example.com",
            "ed25519:0",
            &sk,
        );
        let mut map = crate::HashMap::new();
        map.insert("$opaque:example.com".to_string(), raw);
        let mut keys = DalekVerifier::new();
        keys.insert_public_key("example.com", "ed25519:0", &vk.to_bytes())
            .unwrap();
        let nv = NativeVerifier::new(map, "2.1", keys);
        assert!(nv
            .verify_event_id_hash(&"$opaque:example.com".to_string())
            .is_err());
    }

    #[test]
    fn dalek_rejects_event_with_invalid_known_signature_alongside_valid() {
        use base64::Engine as _;
        let sk1 = SigningKey::from_bytes(&[1_u8; 32]);
        let vk1 = sk1.verifying_key();
        let sk2 = SigningKey::from_bytes(&[2_u8; 32]);
        let vk2 = sk2.verifying_key();

        let mut event = signed_event(
            json!({
                "event_id": "$1:example.com",
                "type": "m.room.message",
                "room_id": "!r:example.com",
                "sender": "@a:example.com",
                "origin_server_ts": 1,
                "content": { "body": "hi" },
            }),
            "1",
            "example.com",
            "ed25519:1",
            &sk1,
        );

        // Add a second known key on example.com with a corrupted signature
        let corrupt_sig = base64::engine::general_purpose::STANDARD_NO_PAD.encode([99_u8; 64]);
        event["signatures"]["example.com"]["ed25519:2"] = json!(corrupt_sig);

        let mut verifier = DalekVerifier::new();
        verifier
            .insert_public_key("example.com", "ed25519:1", &vk1.to_bytes())
            .unwrap();
        verifier
            .insert_public_key("example.com", "ed25519:2", &vk2.to_bytes())
            .unwrap();

        // Both verify_event_signatures and verify_sequential_strict must reject the event
        assert!(verify_event_signatures(&event, "1", &verifier).is_err());
        assert!(verify_sequential_strict(&[event], "1", &verifier).is_err());
    }
}
