//! State-facing `LtHash` adapters.
//!
//! The accumulator itself is domain-independent and lives in
//! [`crate::incremental::lthash`]. This module adds the MSC4500-shaped
//! pieces that depend on room state or define Matrix-specific encodings:
//! [`LtLattice::from_state`], [`compute_state_hash`], [`RedactionOverlay`],
//! [`ResolutionInputs`], [`PduLtHash`] and [`StateDigest`]. The generic
//! accumulator is not re-exported here; import it from [`crate::incremental`].

use alloc::vec::Vec;

use crate::incremental::lthash::{seed_lattice, truncate_to_u16_limit};
use crate::incremental::{LtHash, LtLattice};

impl<const LANES: usize> LtLattice<LANES> {
    /// Compute the full hash from a state map (non-incremental).
    #[must_use]
    pub fn from_state<Id, K>(state: &super::at::SharedState<Id, K>) -> Self
    where
        Id: crate::basespec::rezzy_types::EventId,
        K: Ord + AsRef<str>,
    {
        let mut hash = Self::ZERO;
        for ((event_type, state_key), event_id) in state {
            let s = Self::seed(event_type.as_str(), state_key.as_ref(), event_id);
            hash.add_seed(&s);
        }
        hash
    }
}

/// A homomorphic digest of the redaction overlay associated with a resolved
/// state.  The overlay is deliberately a separate accumulator from
/// [`LtHash`]: it does not describe another state snapshot.  Each entry names
/// one selected state event that is effectively redacted at the DAG point.
///
/// Callers should insert only selected state events that are effectively
/// redacted by authorized causal redactions at the state point being
/// described.  An empty overlay is a known empty overlay; `None` in
/// [`StateDigest`] means that the sender did not compute one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RedactionOverlay(pub LtHash);

impl Default for RedactionOverlay {
    fn default() -> Self {
        Self::ZERO
    }
}

impl RedactionOverlay {
    /// The identity element (no effectively redacted selected events).
    pub const ZERO: Self = Self(LtHash::ZERO);

    /// Domain separation tag for the overlay accumulator.
    pub const DST: &'static [u8] = b"msc4500:redactions:blake3:v1";

    // The overlay shares `LtHash`'s element encoding, lattice updates, and
    // digest serialization (see the module-level helpers), injecting only its
    // own domain-separation tag. The event ID is appended raw, matching the
    // primary MSC4500 element encoding: it is self-delimiting under Matrix
    // event-ID syntax and must not acquire a second length prefix.
    #[must_use]
    pub fn seed(
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) -> Self {
        Self(LtHash::from_lanes(seed_lattice(
            Self::DST,
            event_type,
            state_key,
            &event_id,
        )))
    }

    /// Adds one effectively redacted selected state event to the overlay.
    ///
    /// The caller must maintain set semantics: inserting the same tuple more
    /// than once intentionally changes the lattice, just as it does for the
    /// primary accumulator.
    pub fn insert(
        &mut self,
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        self.0
            .add_seed(&Self::seed(event_type, state_key, event_id).0);
    }

    /// Removes one overlay entry previously inserted with [`Self::insert`].
    /// Callers must not remove an entry that is absent from the authoritative
    /// overlay set.
    pub fn remove(
        &mut self,
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        self.0
            .sub_seed(&Self::seed(event_type, state_key, event_id).0);
    }

    /// Collapses the overlay lattice to its 32-byte wire digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.0.digest()
    }

    /// Borrows the underlying lattice.
    #[must_use]
    pub fn lattice(&self) -> &LtHash {
        &self.0
    }

    /// Returns the underlying lattice.
    #[must_use]
    pub fn into_inner(self) -> LtHash {
        self.0
    }
}

/// One labelled element of the MSC4500 resolution-input set `I(P)`: an event
/// record together with its outgoing `auth_events` and `prev_state_events`
/// edges. The same event ID with different edges is a distinct element.
#[derive(Clone, Copy)]
pub struct ResolutionInputRecord<'a> {
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub state_key: &'a str,
    pub auth_events: &'a [&'a str],
    /// `prev_state_events` for V2.2; `prev_events` for earlier room versions.
    pub state_predecessors: &'a [&'a str],
}

impl ResolutionInputRecord<'_> {
    /// Serializes the record exactly as specified by MSC4500:
    ///
    /// ```text
    /// len(event_id) || event_id || len(type) || type || len(state_key) || state_key ||
    /// auth_events || state_predecessors
    /// ```
    ///
    /// Each `len` is `uint16le`. An ID list is `uint32le(count)` followed by
    /// its IDs in bytewise ascending order, each as `uint16le(length) || id`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        fn put(out: &mut Vec<u8>, s: &str) {
            let (s, len) = truncate_to_u16_limit(s);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        fn put_ids(out: &mut Vec<u8>, ids: &[&str]) {
            let mut sorted: Vec<&str> = ids.to_vec();
            sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            let count = u32::try_from(sorted.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&count.to_le_bytes());
            for id in sorted {
                put(out, id);
            }
        }

        let mut out = Vec::new();
        put(&mut out, self.event_id);
        put(&mut out, self.event_type);
        put(&mut out, self.state_key);
        put_ids(&mut out, self.auth_events);
        put_ids(&mut out, self.state_predecessors);
        out
    }
}

/// Diagnostic accumulator over the labelled state-resolution input set
/// `I(P)` (MSC4500 `resolution-inputs-blake3-v1`). It is a separate lattice
/// under its own domain-separation tag and never describes a state snapshot.
///
/// Callers must supply a set: each distinct record exactly once, however many
/// paths reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionInputs(pub LtHash);

impl Default for ResolutionInputs {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ResolutionInputs {
    /// The empty input set.
    pub const ZERO: Self = Self(LtHash::ZERO);

    /// Domain separation tag for the resolution-input accumulator.
    pub const DST: &'static [u8] = b"msc4500:resolution_inputs:blake3:v1";

    /// Adds one labelled input record.
    pub fn insert(&mut self, record: &ResolutionInputRecord<'_>) {
        self.0.insert_bytes(Self::DST, &record.encode());
    }

    /// Removes one previously inserted record.
    pub fn remove(&mut self, record: &ResolutionInputRecord<'_>) {
        self.0.remove_bytes(Self::DST, &record.encode());
    }

    /// Collapses the lattice to its 32-byte wire digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.0.digest()
    }

    /// Borrows the underlying lattice.
    #[must_use]
    pub fn lattice(&self) -> &LtHash {
        &self.0
    }
}

/// A field-by-field accumulator for a single protocol data unit (PDU).
///
/// This is the porcelain over [`LtHash`] for callers that hash a structured object one
/// field at a time: the domain tag is bound at construction, so every field goes through
/// [`PduLtHash::insert_field`] without repeating the tag. Two PDUs that carry the same
/// field multiset under the same tag collapse to the same digest regardless of the order
/// the fields were inserted in.
#[derive(Debug, PartialEq, Eq)]
pub struct PduLtHash {
    dst: Vec<u8>,
    inner: LtHash,
}

impl Default for PduLtHash {
    fn default() -> Self {
        Self::new([])
    }
}

impl PduLtHash {
    /// The identity element (a PDU with no fields).
    pub const ZERO: Self = Self {
        dst: Vec::new(),
        inner: LtHash::ZERO,
    };

    /// Binds a domain-separation tag for subsequent field insertions.
    #[must_use]
    pub fn new(dst: impl Into<Vec<u8>>) -> Self {
        Self {
            dst: dst.into(),
            inner: LtHash::ZERO,
        }
    }

    /// Records one field being present with the given value.
    pub fn insert_field(&mut self, key: &str, val: &str) {
        self.inner
            .add_seed(&LtHash::seed_field(&self.dst, key, val));
    }

    /// Records one field being absent with the given value.
    pub fn remove_field(&mut self, key: &str, val: &str) {
        self.inner
            .sub_seed(&LtHash::seed_field(&self.dst, key, val));
    }

    /// Records one field changing value (same key, old value → new value).
    pub fn replace_field(&mut self, key: &str, old_val: &str, new_val: &str) {
        self.inner
            .sub_seed(&LtHash::seed_field(&self.dst, key, old_val));
        self.inner
            .add_seed(&LtHash::seed_field(&self.dst, key, new_val));
    }

    /// Records an opaque byte string being present.
    pub fn insert_bytes(&mut self, bytes: &[u8]) {
        self.inner.add_seed(&LtHash::seed_bytes(&self.dst, bytes));
    }

    /// Records an opaque byte string being absent.
    pub fn remove_bytes(&mut self, bytes: &[u8]) {
        self.inner.sub_seed(&LtHash::seed_bytes(&self.dst, bytes));
    }

    /// Records an opaque byte string being replaced (old → new).
    pub fn replace_bytes(&mut self, old_bytes: &[u8], new_bytes: &[u8]) {
        self.inner
            .sub_seed(&LtHash::seed_bytes(&self.dst, old_bytes));
        self.inner
            .add_seed(&LtHash::seed_bytes(&self.dst, new_bytes));
    }

    /// The domain-separation tag this accumulator is bound to.
    #[must_use]
    pub fn dst(&self) -> &[u8] {
        &self.dst
    }

    /// Whether no field has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner == LtHash::ZERO
    }

    /// Borrows the raw lattice.
    #[must_use]
    pub fn lattice(&self) -> &[u16; 1024] {
        self.inner.lattice()
    }

    /// Finalize into the 32-byte wire digest: `BLAKE3(S)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.inner.digest()
    }

    /// Finalize into both the raw lattice and the 32-byte wire digest.
    #[must_use]
    pub fn finalize_both(&self) -> ([u16; 1024], [u8; 32]) {
        self.inner.finalize_both()
    }

    /// Returns the underlying accumulator and discards the bound tag.
    #[must_use]
    pub fn into_inner(self) -> LtHash {
        self.inner
    }
}

/// The MSC4500 state digest for one DAG point: the primary resolved-state
/// digest and, when supported, its causal redaction overlay digest.
///
/// MSC4500 carries these values as `before` and `after` fields around a state
/// transition (alongside `redactions_before` and `redactions_after`). This
/// type represents one such point; [`StateDigestTransition`] represents the
/// pair. `overlay` is optional for wire compatibility and must never be
/// interpreted as agreement when absent.
#[derive(Clone, Copy)]
pub struct StateDigest {
    pub primary: [u8; 32],
    pub overlay: Option<[u8; 32]>,
}

/// The before/after digest pair carried for one MSC4500 state transition.
#[derive(Clone, Copy)]
pub struct StateDigestTransition {
    pub before: StateDigest,
    pub after: StateDigest,
}

/// Result of comparing two state digest advertisements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAgreement {
    /// The selected `(type, state_key, event_id)` maps differ.
    PrimaryMismatch,
    /// Primary maps agree and both overlay digests agree.
    FullySynchronized,
    /// Primary maps agree but causal redaction overlays differ.
    OverlayMismatch,
    /// Primary maps agree, but at least one side omitted its overlay.
    OverlayUnknown,
}

impl StateDigest {
    /// Compares primary state first, then treats the overlay as a diagnostic.
    #[must_use]
    pub fn compare(self, remote: Self) -> DigestAgreement {
        if self.primary == remote.primary {
            match (self.overlay, remote.overlay) {
                (Some(left), Some(right)) if left == right => DigestAgreement::FullySynchronized,
                (Some(_), Some(_)) => DigestAgreement::OverlayMismatch,
                _ => DigestAgreement::OverlayUnknown,
            }
        } else {
            DigestAgreement::PrimaryMismatch
        }
    }
}

/// Computes a deterministic 256-bit `LtHash` fingerprint of a
/// state map, returned as a 32-byte array.
///
/// This is a convenience wrapper around
/// [`LtHash::from_state`]. Each
/// `(event_type, state_key, event_id)` entry is expanded via
/// the BLAKE3 XOF to a 2048-byte seed, and the state hash is the
/// wrapping addition of all seeds — making it order-independent and
/// incrementally updatable.
#[must_use]
pub fn compute_state_hash<Id: crate::basespec::rezzy_types::EventId, K: Ord + AsRef<str>>(
    state: &crate::state::at::SharedState<Id, K>,
) -> [u8; 32] {
    LtHash::from_state(state).digest()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use core::fmt::Write as _;

    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    #[test]
    fn resolution_input_record_encoding_is_canonical() {
        // Edge lists are sorted bytewise, so caller order is irrelevant.
        let a = ResolutionInputRecord {
            event_id: "$e",
            event_type: "m.room.member",
            state_key: "@a:x",
            auth_events: &["$b", "$a"],
            state_predecessors: &[],
        };
        let b = ResolutionInputRecord {
            auth_events: &["$a", "$b"],
            ..a
        };
        assert_eq!(a.encode(), b.encode());

        let mut expected = Vec::new();
        expected.extend_from_slice(&[2, 0]);
        expected.extend_from_slice(b"$e");
        expected.extend_from_slice(&[13, 0]);
        expected.extend_from_slice(b"m.room.member");
        expected.extend_from_slice(&[4, 0]);
        expected.extend_from_slice(b"@a:x");
        expected.extend_from_slice(&[2, 0, 0, 0, 2, 0]);
        expected.extend_from_slice(b"$a");
        expected.extend_from_slice(&[2, 0]);
        expected.extend_from_slice(b"$b");
        expected.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(a.encode(), expected);
    }

    #[test]
    fn resolution_inputs_distinguish_edges_and_domain() {
        let base = ResolutionInputRecord {
            event_id: "$e",
            event_type: "m.room.name",
            state_key: "",
            auth_events: &["$c"],
            state_predecessors: &[],
        };
        let rewired = ResolutionInputRecord {
            auth_events: &["$d"],
            ..base
        };

        let mut x = ResolutionInputs::ZERO;
        x.insert(&base);
        let mut y = ResolutionInputs::ZERO;
        y.insert(&rewired);
        // Same event ID, different outgoing edges: distinct element.
        assert_ne!(x.digest(), y.digest());

        // Insert/remove round-trips to the empty set.
        x.remove(&base);
        assert_eq!(x, ResolutionInputs::ZERO);

        // Not interchangeable with the redaction overlay's domain.
        let mut overlay = RedactionOverlay::ZERO;
        overlay.insert("m.room.name", "", "$e");
        let mut inputs = ResolutionInputs::ZERO;
        inputs.insert(&ResolutionInputRecord {
            auth_events: &[],
            ..base
        });
        assert_ne!(overlay.digest(), inputs.digest());
    }

    #[test]
    fn resolution_inputs_cross_implementation_vector() {
        let mut x = ResolutionInputs::ZERO;
        x.insert(&ResolutionInputRecord {
            event_id: "$e",
            event_type: "m.room.member",
            state_key: "@a:x",
            auth_events: &["$b", "$a"],
            state_predecessors: &["$p"],
        });
        x.insert(&ResolutionInputRecord {
            event_id: "$a",
            event_type: "m.room.create",
            state_key: "",
            auth_events: &[],
            state_predecessors: &[],
        });
        // Pinned identically in gomatrixcrypto/lthash.
        assert_eq!(
            crate::base64_utils::encode(&URL_SAFE_NO_PAD, &x.digest()),
            "zDnrgYKfPuS6ztctVfakvKVx6rM7l8QVDUuGXcibrnE"
        );
    }

    #[test]
    fn resolution_inputs_proposal_vector() {
        let r = ResolutionInputRecord {
            event_id: "$event_1",
            event_type: "m.room.member",
            state_key: "@alice:example.com",
            auth_events: &[],
            state_predecessors: &[],
        };
        let raw = r.encode().iter().fold(String::new(), |mut raw, byte| {
            write!(raw, "{byte:02x}").expect("writing to String cannot fail");
            raw
        });
        assert_eq!(
            raw,
            "0800246576656e745f310d006d2e726f6f6d2e6d656d626572120040616c6963653a6578616d706c652e636f6d0000000000000000"
        );
        let mut x = ResolutionInputs::ZERO;
        x.insert(&r);
        assert_eq!(
            crate::base64_utils::encode(&URL_SAFE_NO_PAD, &x.digest()),
            "IGytaez3uh-Y5gPuZ7o2bZxlaufNhkXH558n-Unor_Y"
        );
    }

    type StateMap = crate::state::at::SharedState<String, String>;

    /// Builds a `StateMap` from `(event_type, state_key) -> event_id` rows.
    fn state_map(
        rows: impl IntoIterator<Item = ((&'static str, &'static str), &'static str)>,
    ) -> StateMap {
        rows.into_iter()
            .map(|((event_type, state_key), id)| {
                ((event_type.into(), state_key.into()), String::from(id))
            })
            .collect()
    }

    #[test]
    fn test_state_hash_determinism() {
        let state = state_map([
            (("m.room.create", ""), "$1"),
            (("m.room.member", "@alice:example.com"), "$2"),
        ]);

        let h1 = compute_state_hash(&state);
        let h2 = compute_state_hash(&state);
        assert_eq!(h1, h2, "same state must produce same hash");
        assert_eq!(h1.len(), 32, "LtHash final digest should be 32 bytes");
    }

    #[test]
    fn test_state_hash_sensitivity() {
        let state_a = state_map([(("m.room.create", ""), "$1")]);
        let state_b = state_map([(("m.room.create", ""), "$2")]);

        assert_ne!(
            compute_state_hash(&state_a),
            compute_state_hash(&state_b),
            "different states must produce different hashes"
        );
    }

    #[test]
    fn test_lthash_determinism() {
        let state = state_map([
            (("m.room.create", ""), "$1"),
            (("m.room.member", "@a:x"), "$2"),
        ]);
        let h1 = LtHash::from_state(&state);
        let h2 = LtHash::from_state(&state);
        assert_eq!(h1, h2);
        assert_ne!(h1, LtHash::ZERO);
        assert_eq!(h1.digest().len(), 32);
    }

    #[test]
    fn test_lthash_sensitivity() {
        let a = state_map([(("m.room.create", ""), "$1")]);
        let b = state_map([(("m.room.create", ""), "$2")]);
        assert_ne!(LtHash::from_state(&a), LtHash::from_state(&b),);
    }

    #[test]
    fn test_redaction_overlay_is_separate_and_order_independent() {
        let mut left = RedactionOverlay::ZERO;
        left.insert("m.room.member", "@alice:example.org", "$state");

        let mut right = RedactionOverlay::ZERO;
        right.insert("m.room.member", "@alice:example.org", "$other-state");
        assert_ne!(left.digest(), right.digest());

        let mut reordered = RedactionOverlay::ZERO;
        reordered.insert("m.room.member", "@bob:example.org", "$other-state");
        reordered.insert("m.room.member", "@alice:example.org", "$state");
        let mut expected = left;
        expected.insert("m.room.member", "@bob:example.org", "$other-state");
        assert_eq!(reordered, expected);

        reordered.remove("m.room.member", "@bob:example.org", "$other-state");
        assert_eq!(reordered, left);
    }

    #[test]
    fn test_state_digest_comparison_preserves_unknown_overlay_semantics() {
        let primary = [7u8; 32];
        let overlay = [9u8; 32];
        let same = StateDigest {
            primary,
            overlay: Some(overlay),
        };
        assert_eq!(same.compare(same), DigestAgreement::FullySynchronized);
        assert_eq!(
            same.compare(StateDigest {
                primary,
                overlay: Some([8u8; 32]),
            }),
            DigestAgreement::OverlayMismatch
        );
        assert_eq!(
            same.compare(StateDigest {
                primary,
                overlay: None,
            }),
            DigestAgreement::OverlayUnknown
        );
        assert_eq!(
            same.compare(StateDigest {
                primary: [6u8; 32],
                overlay: Some(overlay),
            }),
            DigestAgreement::PrimaryMismatch
        );
    }

    #[test]
    fn test_lthash_incremental_matches_full() {
        let mut state = StateMap::new();
        state.insert(("m.room.create".into(), String::new()), "$c".into());
        state.insert(("m.room.topic".into(), String::new()), "$t".into());

        let full = LtHash::from_state(&state);

        let mut inc = LtHash::ZERO;
        inc.insert("m.room.create", "", "$c");
        inc.insert("m.room.topic", "", "$t");

        assert_eq!(full, inc);
    }

    #[test]
    fn test_lthash_defaults_to_zero() {
        assert_eq!(LtHash::default(), LtHash::ZERO);
        assert_eq!(RedactionOverlay::default(), RedactionOverlay::ZERO);
    }

    #[test]
    fn test_pdu_lthash_field_parity_and_roundtrip() {
        let mut pdu = PduLtHash::new(b"rezzy:test:pdu");
        assert!(pdu.is_empty());
        pdu.insert_field("type", "m.room.message");
        pdu.insert_field("sender", "@alice:example.org");
        assert!(!pdu.is_empty());

        let mut reordered = PduLtHash::new(b"rezzy:test:pdu");
        reordered.insert_field("sender", "@alice:example.org");
        reordered.insert_field("type", "m.room.message");
        assert_eq!(pdu.digest(), reordered.digest());

        // A different tag is a different PDU domain.
        let mut other_tag = PduLtHash::new(b"rezzy:test:pdu:other");
        other_tag.insert_field("type", "m.room.message");
        other_tag.insert_field("sender", "@alice:example.org");
        assert_ne!(pdu.digest(), other_tag.digest());

        pdu.replace_field("sender", "@alice:example.org", "@bob:example.org");
        pdu.remove_field("sender", "@bob:example.org");
        pdu.remove_field("type", "m.room.message");
        assert!(pdu.is_empty());
        assert_eq!(pdu, PduLtHash::new(b"rezzy:test:pdu"));

        let mut bytes = PduLtHash::new(b"rezzy:test:pdu");
        bytes.insert_bytes(b"opaque");
        bytes.replace_bytes(b"opaque", b"other");
        bytes.remove_bytes(b"other");
        assert!(bytes.is_empty());
        assert_eq!(bytes.dst(), b"rezzy:test:pdu");
        assert_eq!(bytes.into_inner(), LtHash::ZERO);
    }

    /// Regression pins for the BLAKE3 instantiation (`msc4500:lthash16:blake3:v1`).
    ///
    /// These are rezzy-derived values, not the published MSC4500 vectors: this module
    /// implements a different expansion and collapse pair, as the module docs explain.
    /// Changing the expansion, the collapse function, the domain tag, or the
    /// length-delimited element encoding changes every value below, so treat this as the
    /// place to re-derive them.
    #[test]
    fn blake3_lthash_vectors() {
        fn hex(bytes: &[u8]) -> String {
            use core::fmt::Write;
            bytes.iter().fold(
                String::with_capacity(bytes.len().wrapping_mul(2)),
                |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                },
            )
        }
        fn b64u(bytes: &[u8]) -> String {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            crate::base64_utils::encode(&URL_SAFE_NO_PAD, bytes)
        }
        fn lanes_hex(hash: &LtHash) -> String {
            hex(&hash.to_bytes()[..16])
        }

        // The empty accumulator still collapses to a real digest rather than a
        // special case, so a state that is empty and one that is merely
        // unresolved stay distinguishable from anything non-empty.
        assert_eq!(
            b64u(&LtHash::ZERO.digest()),
            "viqN49z0bJTOhc3I4HrDCPTYqVSQ2VbDjXgP1hDbCBM"
        );

        let seed1 = LtHash::seed("m.room.member", "@alice:example.com", &"$event_1");
        assert_eq!(hex(&seed1.to_bytes()[..8]), "c3b425b048d36923");
        let mut s1 = LtHash::ZERO;
        s1.add_seed(&seed1);
        assert_eq!(lanes_hex(&s1), "c3b425b048d369230ec3b609c1f0c5a5");
        assert_eq!(
            b64u(&s1.digest()),
            "jkZrUIFtAvB1LEjCV0klBcoslgI_z-fy57tBaYhqy8g"
        );

        let seed2 = LtHash::seed("m.room.name", "", &"$event_2");
        assert_eq!(hex(&seed2.to_bytes()[..8]), "a6f3137486864ae3");
        let mut s2 = s1;
        s2.add_seed(&seed2);
        assert_eq!(lanes_hex(&s2), "69a83824ce59b3064470e993c77e73fe");
        assert_eq!(
            b64u(&s2.digest()),
            "0MOPtd797los_3q4fTJt4bKCjhRFZ12nwPEPshWDcEA"
        );

        // Removing the first seed must land exactly back on the second state.
        let seed3 = LtHash::seed("m.room.member", "@alice:example.com", &"$event_3");
        assert_eq!(hex(&seed3.to_bytes()[..8]), "2092781e84ce05bf");
        let mut s3 = s2;
        s3.sub_seed(&seed1);
        s3.add_seed(&seed3);
        assert_eq!(lanes_hex(&s3), "c6858b920a554fa224e1d928d63eceb7");
        assert_eq!(
            b64u(&s3.digest()),
            "BHYsmq2zHFAQZgQGlXuFqaAG9w9o7vFY7NkRcUL_554"
        );

        let mut back = s3;
        back.sub_seed(&seed3);
        assert_eq!(
            b64u(&back.digest()),
            "yeMXj6Fokw2iYonH8htoklFY5AwtcdDDnRGU_B79_2g"
        );

        let mut overlay = RedactionOverlay::ZERO;
        overlay.insert("m.room.member", "@alice:example.org", "$state");
        assert_eq!(
            hex(&overlay.digest()),
            "c18c12274627af27191a45b13755fff86b2567a871e30453e1bbeeeb436f2159"
        );
        let mut two = RedactionOverlay::ZERO;
        two.insert("m.room.create", "", "$create");
        two.insert("m.room.member", "@alice:example.org", "$state");
        assert_eq!(
            hex(&two.digest()),
            "a572fff7e802aa93492e2c87bb50843b8da33bb29ff88177cda7067d08b0836f"
        );
        let mut custom = RedactionOverlay::ZERO;
        custom.insert("org.example.custom", "key", "$custom");
        assert_eq!(
            hex(&custom.digest()),
            "c2a2306f0728514669fb35e8d96046ab96ca7ed764edcefe6484fa563930019b"
        );

        // Plumbing-only surfaces, pinned so an accidental encoding change is visible.
        assert_eq!(
            b64u(&LtHash::seed_bytes(b"rezzy:test:bytes", b"payload").digest()),
            "A6dOXzQL9dQWi4YN-mX6YChzAVXKdUttuAi6eVbf900"
        );
        assert_eq!(
            b64u(&LtHash::seed_field(b"rezzy:test:field", "sender", "@alice:example.org").digest()),
            "1eXV0G7qmj1EBJiDWnR4ZA0uH3d1cYt_vTnA1I-ucTI"
        );
        assert_eq!(
            b64u(&LtLattice::<8>::seed("m.room.create", "", &"$c").digest()),
            "qbaIieU0BVEcRZLD9O4ArrkTG1qizm8ICv2SE3vl9OE"
        );
    }

    #[test]
    fn test_lthash_differential_random_mutations() {
        struct Lcg(u32);
        impl Lcg {
            fn next(&mut self) -> u32 {
                self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                self.0
            }
            fn next_range(&mut self, min: u32, max: u32) -> u32 {
                min + (self.next() % (max - min + 1))
            }
        }

        let mut rng = Lcg(12345);
        let mut state = StateMap::new();
        let mut running_hash = LtHash::ZERO;

        // Populate state with some initial keys to work with
        let mut keys = Vec::new();
        for i in 0..15 {
            let key = (
                crate::basespec::event_types::EventType::from(alloc::format!("type_{i}")),
                alloc::format!("state_key_{i}"),
            );
            let val = alloc::format!("$initial_event_{i}");
            state.insert(key.clone(), val.clone());
            running_hash.insert(key.0.as_str(), &key.1, &val);
            keys.push(key);
        }

        assert_eq!(running_hash, LtHash::from_state(&state));

        // Let's do 200 mutations
        for step in 0..200 {
            let op = rng.next_range(0, 2); // 0 = insert/overwrite, 1 = remove, 2 = replace
            if op == 0 || keys.is_empty() {
                // Insert a new key or overwrite an existing one
                let key = if !keys.is_empty() && rng.next_range(0, 1) == 1 {
                    // Overwrite an existing key
                    let keys_len = u32::try_from(keys.len()).unwrap();
                    let idx = rng.next_range(0, keys_len - 1) as usize;
                    keys[idx].clone()
                } else {
                    // Create a new key
                    let id = rng.next();
                    let key = (
                        crate::basespec::event_types::EventType::from(alloc::format!("type_{id}")),
                        alloc::format!("state_key_{id}"),
                    );
                    keys.push(key.clone());
                    key
                };

                let new_val = alloc::format!("$event_{}", rng.next());

                // If it existed, we do a replace under the hood, or insert/remove.
                if let Some(old_val) = state.get(&key) {
                    running_hash.replace(key.0.as_str(), &key.1, old_val, &new_val);
                } else {
                    running_hash.insert(key.0.as_str(), &key.1, &new_val);
                }
                state.insert(key, new_val);
            } else if op == 1 && !keys.is_empty() {
                // Remove an existing key
                let keys_len = u32::try_from(keys.len()).unwrap();
                let idx = rng.next_range(0, keys_len - 1) as usize;
                let key = keys.swap_remove(idx);
                if let Some(val) = state.remove(&key) {
                    running_hash.remove(key.0.as_str(), &key.1, &val);
                }
            } else {
                // Replace via explicit .replace API
                let keys_len = u32::try_from(keys.len()).unwrap();
                let idx = rng.next_range(0, keys_len - 1) as usize;
                let key = &keys[idx];
                if let Some(old_val) = state.get(key).cloned() {
                    let new_val = alloc::format!("$replaced_{}", rng.next());
                    running_hash.replace(key.0.as_str(), &key.1, &old_val, &new_val);
                    state.insert(key.clone(), new_val);
                }
            }

            // Verify parity at every single step!
            assert_eq!(
                running_hash,
                LtHash::from_state(&state),
                "Hash mismatch at step {step}"
            );
        }
    }
}
