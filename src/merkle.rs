//! MSC4511 Merkleized event-metadata primitives.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

/// SHA3-256 digest size used by MSC4511.
pub const HASH_SIZE: usize = 32;

const MAX_CANONICAL_INT: i64 = (1_i64 << 53) - 1;
const MIN_CANONICAL_INT: i64 = -MAX_CANONICAL_INT;

const LEAF_DST: &[u8] = b"msc4511:leaf:v1";
const NODE_DST: &[u8] = b"msc4511:node:v1";
const ROOT_DST: &[u8] = b"msc4511:root:v1";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// A SHA3-256 digest.
pub type Hash = [u8; HASH_SIZE];

/// A Merkle root that nobody has signed.
///
/// Some root-computing functions in this crate return this wrapper
/// ([`header_root`], [`CausalSet::unsigned_root`], [`StateMap::unsigned_root`]);
/// others return a bare [`type@Hash`] ([`root`], [`CausalSet::root`],
/// [`StateMap::root`]). The wrapper exists so a caller at a return site that
/// produces `UnsignedRoot` is reminded that the value is only a *proof* of
/// anything when it is either (a) folded into an `event_root` an event's
/// sender actually signed (a true MSC4511C Part C proof), or (b) signed
/// after the fact by whoever computed it, standing behind it as a responder
/// (a Part B attestation -- see `crate::signing::attest` when the
/// `signing-dalek` feature is enabled). Neither case is automatic: this type
/// exists so a caller cannot accidentally hand a bare computed root to code
/// that presents it as authoritative without having gone through one of
/// those two steps.
///
/// A root computed over event IDs from a room that never adopted MSC4511C
/// (any room in existence today) can *never* reach case (a) -- nothing signs
/// a `causal_set`/`state_root` field on those events. It can still reach
/// case (b): sign this value yourself via `crate::signing::attest::sign_attestation`
/// and the result is a real, checkable claim -- just a Part B one, only as
/// trustworthy as that one signer, not a room-participant-committed
/// guarantee.
///
/// Callers who receive a root over federation should prefer
/// [`verify_causal_inclusion`] / [`verify_inclusion`] only after confirming
/// the root's provenance (e.g. extracted from a signature-checked event).
/// A bare `Hash` passed to a verifier proves nothing about who stands
/// behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnsignedRoot(pub Hash);

impl UnsignedRoot {
    /// Unwraps the raw digest.
    #[must_use]
    pub const fn into_inner(self) -> Hash {
        self.0
    }
}

impl From<Hash> for UnsignedRoot {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

/// Errors returned by MSC4511 Merkle and canonical JSON operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    EmptyFieldName,
    InvalidFieldName,
    DuplicateField(String),
    FieldNotFound(String),
    NoLeaves,
    IntegerRange,
    UnsupportedNumber,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFieldName => f.write_str("merkle: empty field name"),
            Self::InvalidFieldName => f.write_str("merkle: invalid field name"),
            Self::DuplicateField(name) => write!(f, "merkle: duplicate field: {name}"),
            Self::FieldNotFound(name) => write!(f, "merkle: field not found: {name}"),
            Self::NoLeaves => f.write_str("merkle: no leaves"),
            Self::IntegerRange => f.write_str("canonical json integer out of range"),
            Self::UnsupportedNumber => f.write_str("unsupported canonical json number"),
        }
    }
}

impl core::error::Error for MerkleError {}

/// One named metadata value. The value is Matrix Canonical JSON encoded before hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: Value,
}

impl Field {
    #[must_use]
    pub fn new(name: impl Into<String>, value: Value) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Fields committed by [`header_root`].
///
/// `sender_localpart` and `sender_domain` are committed as independent leaves
/// (rather than a single combined `sender` leaf) so that a proof can disclose
/// and verify the sending server's identity without disclosing the sender's
/// localpart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub room_id: String,
    pub sender_localpart: String,
    pub sender_domain: String,
    pub event_type: String,
    pub state_key: Option<String>,
    pub redacts: Option<String>,
    pub depth: i64,
    pub origin_server_ts: i64,
}

/// Typed wrapper for the `prev_events` component hash in [`event_root`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrevEventsHash(pub Hash);

/// Typed wrapper for the `auth_events` component hash in [`event_root`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthEventsHash(pub Hash);

/// Typed wrapper for the event header root component in [`event_root`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventHeaderRoot(pub Hash);

/// Typed wrapper for the `content` component hash in [`event_root`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentHash(pub Hash);

/// Typed wrapper for the `other_signed_fields` component hash in [`event_root`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtherSignedFieldsHash(pub Hash);

#[derive(Debug, Clone)]
struct Leaf {
    name: String,
    hash: Hash,
}

/// Matrix Canonical JSON encoding used for MSC4511 leaf values.
///
/// # Errors
///
/// Returns [`MerkleError::IntegerRange`] when an integer is outside Matrix's
/// exactly representable range, or [`MerkleError::UnsupportedNumber`] for
/// non-integer JSON numbers.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, MerkleError> {
    let mut out = Vec::new();
    append_canonical_value(&mut out, value)?;
    Ok(out)
}

/// Computes SHA3-256("msc4511:leaf:v1" || `field_name` || "\x00" ||
/// `canonical_value`).
///
/// # Errors
///
/// Returns [`MerkleError::EmptyFieldName`] if `field_name` is empty, or
/// [`MerkleError::InvalidFieldName`] if it contains invalid bytes (for example a NUL byte).
pub fn leaf_hash(field_name: &str, canonical_value: &[u8]) -> Result<Hash, MerkleError> {
    validate_field_name(field_name)?;
    Ok(leaf_hash_unchecked(field_name.as_bytes(), canonical_value))
}

/// Computes the MSC4511 leaf hash for a field name supplied as raw UTF-8 bytes.
///
/// This is the validation boundary for callers that receive field names before
/// converting them to [`str`] or [`String`].
///
/// # Errors
///
/// Returns [`MerkleError::EmptyFieldName`] when `field_name` is empty, or
/// [`MerkleError::InvalidFieldName`] when it is not valid UTF-8.
pub fn leaf_hash_bytes(field_name: &[u8], canonical_value: &[u8]) -> Result<Hash, MerkleError> {
    validate_field_name_bytes(field_name)?;
    Ok(leaf_hash_unchecked(field_name, canonical_value))
}

/// Computes one top-level event-root component with the standard leaf construction.
///
/// # Errors
///
/// Returns a [`MerkleError`] if the field name is invalid or `value` cannot be
/// encoded as Matrix Canonical JSON.
pub fn component_hash(field_name: &str, value: &Value) -> Result<Hash, MerkleError> {
    validate_field_name(field_name)?;
    let canonical = canonical_json(value)?;
    Ok(leaf_hash_unchecked(field_name.as_bytes(), &canonical))
}

/// Computes the `redacted_content_hash` leaf for MSC4511's `content_hash`
/// split: the leaf hash of the event body fields that survive redaction.
///
/// # Errors
///
/// Returns a [`MerkleError`] if `value` cannot be canonically encoded.
pub fn redacted_content_hash(value: &Value) -> Result<Hash, MerkleError> {
    component_hash("redacted_content", value)
}

/// Computes the `redactable_content_hash` leaf for MSC4511's `content_hash`
/// split: the leaf hash of the event body fields that redaction strips.
///
/// # Errors
///
/// Returns a [`MerkleError`] if `value` cannot be canonically encoded.
pub fn redactable_content_hash(value: &Value) -> Result<Hash, MerkleError> {
    component_hash("redactable_content", value)
}

/// Splits event content using the room-version redaction rules and hashes both
/// halves required by MSC4511's content-hash construction.
///
/// The split itself remains in [`crate::basespec::rezzy_types::split_redaction_content`],
/// where the Matrix redaction tables live; this helper keeps merkle callers
/// from accidentally hashing the unsplit content.  The returned pair is
/// `(redacted_content_hash, redactable_content_hash)`.
///
/// # Errors
///
/// Returns [`MerkleError`] if either split content value cannot be encoded as
/// Matrix Canonical JSON.
pub fn split_content_hashes(
    content: &Value,
    event_type: &str,
    room_version: &str,
) -> Result<(Hash, Hash), MerkleError> {
    let (redacted, redactable) =
        crate::basespec::rezzy_types::split_redaction_content(content, event_type, room_version);
    Ok((
        redacted_content_hash(&redacted)?,
        redactable_content_hash(&redactable)?,
    ))
}

/// Combines `redacted_content_hash` and `redactable_content_hash` into the
/// top-level `content_hash` component, per MSC4511's split-canonicalization
/// redaction fix.
#[must_use]
pub fn content_hash(redacted_content_hash: Hash, redactable_content_hash: Hash) -> ContentHash {
    ContentHash(inner_hash(redacted_content_hash, redactable_content_hash))
}

/// Computes the RFC6962-shaped Merkle root over sorted MSC4511 field leaves.
///
/// # Errors
///
/// Returns a [`MerkleError`] when there are no fields, duplicate field names, an
/// empty field name, or a field value that cannot be canonically encoded.
pub fn root(fields: &[Field]) -> Result<Hash, MerkleError> {
    let leaves = leaves(fields)?;
    root_from_leaves(&leaves)
}

/// Computes `header_root` over `room_id`, `sender_localpart`,
/// `sender_domain`, `type`, `state_key`, `redacts`, `depth`, and
/// `origin_server_ts`. Missing optional fields are encoded as `null`.
///
/// Returns the typed [`EventHeaderRoot`] rather than a bare [`type@Hash`] --
/// this root's only legitimate use is as an [`event_root`] component, so
/// requiring the wrapper at the source keeps a caller from being able to
/// treat it as a proof of anything before it is actually folded into a
/// signed event.
///
/// # Errors
///
/// Returns a [`MerkleError`] if one of the header fields cannot be canonically
/// encoded.
pub fn header_root(header: &Header) -> Result<EventHeaderRoot, MerkleError> {
    root(&[
        Field::new("depth", Value::from(header.depth)),
        Field::new("origin_server_ts", Value::from(header.origin_server_ts)),
        Field::new(
            "redacts",
            header.redacts.clone().map_or(Value::Null, Value::from),
        ),
        Field::new("room_id", Value::from(header.room_id.clone())),
        Field::new("sender_domain", Value::from(header.sender_domain.clone())),
        Field::new(
            "sender_localpart",
            Value::from(header.sender_localpart.clone()),
        ),
        Field::new(
            "state_key",
            header.state_key.clone().map_or(Value::Null, Value::from),
        ),
        Field::new("type", Value::from(header.event_type.clone())),
    ])
    .map(EventHeaderRoot)
}

/// Computes SHA3-256("msc4511:root:v1" || `prev_events_hash` ||
/// `auth_events_hash` || `event_header_root` || `content_hash` ||
/// `other_signed_fields_hash`).
#[must_use]
pub fn event_root(
    prev_events_hash: PrevEventsHash,
    auth_events_hash: AuthEventsHash,
    event_header_root: EventHeaderRoot,
    content_hash: ContentHash,
    other_signed_fields_hash: OtherSignedFieldsHash,
) -> Hash {
    hash_parts(&[
        ROOT_DST,
        &prev_events_hash.0,
        &auth_events_hash.0,
        &event_header_root.0,
        &content_hash.0,
        &other_signed_fields_hash.0,
    ])
}

/// Derives "$" || unpadded base64url(`event_root`).
#[must_use]
pub fn event_id(event_root: Hash) -> String {
    format!("${}", URL_SAFE_NO_PAD.encode(event_root))
}

/// Which side a sibling hash sits on relative to the running hash in a
/// [`ProofStep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// One sibling hash in a header-tree Merkle path, ordered leaf-to-root:
/// applying each step in order (combining the running hash with `hash` on
/// the named `side`) reconstructs the tree root.
#[derive(Debug, Clone, Copy)]
pub struct ProofStep {
    pub side: Side,
    pub hash: Hash,
}

/// Computes the ordered (leaf-to-root) sibling path proving `field_name`'s
/// leaf is included in the RFC 6962-shaped root over `fields`, along with
/// that root. This is the `leaf_paths` construction MSC4511's "Cryptographic
/// proof responses" section describes.
///
/// # Errors
///
/// Returns a [`MerkleError`] if `fields` cannot be canonicalized or contains
/// a duplicate field name, or [`MerkleError::FieldNotFound`] if no field
/// named `field_name` is present.
pub fn leaf_path(
    fields: &[Field],
    field_name: &str,
) -> Result<(Vec<ProofStep>, Hash), MerkleError> {
    let ls = leaves(fields)?;
    let idx = ls
        .iter()
        .position(|l| l.name == field_name)
        .ok_or_else(|| MerkleError::FieldNotFound(field_name.into()))?;
    let hashes = ls.iter().map(|l| l.hash).collect::<Vec<_>>();
    let (root, path) = merkle_root_and_path(&hashes, idx).ok_or(MerkleError::NoLeaves)?;
    Ok((path, root))
}

/// Recomputes the root from `leaf_hash` and `path` (leaf-to-root ordered
/// siblings) and reports whether it matches `root`.
#[must_use]
pub fn verify_leaf_path(leaf_hash: Hash, path: &[ProofStep], root: Hash) -> bool {
    let mut cur = leaf_hash;
    for step in path {
        cur = match step.side {
            Side::Left => inner_hash(step.hash, cur),
            Side::Right => inner_hash(cur, step.hash),
        };
    }
    cur == root
}

/// Computes the RFC 6962 root over `hashes` and the ordered (leaf-to-root)
/// sibling path for `hashes[target]`, mirroring [`merkle_root`]'s
/// largest-power-of-two split so the two stay consistent.
fn merkle_root_and_path(hashes: &[Hash], target: usize) -> Option<(Hash, Vec<ProofStep>)> {
    match hashes.len() {
        0 => None,
        1 => Some((hashes[0], Vec::new())),
        2 => {
            if target == 0 {
                Some((
                    inner_hash(hashes[0], hashes[1]),
                    alloc::vec![ProofStep {
                        side: Side::Right,
                        hash: hashes[1]
                    }],
                ))
            } else {
                Some((
                    inner_hash(hashes[0], hashes[1]),
                    alloc::vec![ProofStep {
                        side: Side::Left,
                        hash: hashes[0]
                    }],
                ))
            }
        }
        len => {
            let k = largest_power_of_two_less_than(len);
            if target < k {
                let (left_root, mut path) = merkle_root_and_path(&hashes[..k], target)?;
                let right_root = merkle_root(&hashes[k..])?;
                path.push(ProofStep {
                    side: Side::Right,
                    hash: right_root,
                });
                Some((inner_hash(left_root, right_root), path))
            } else {
                // `target >= k` here (the `target < k` branch above already
                // handled the other case), so this never saturates.
                let (right_root, mut path) =
                    merkle_root_and_path(&hashes[k..], target.saturating_sub(k))?;
                let left_root = merkle_root(&hashes[..k])?;
                path.push(ProofStep {
                    side: Side::Left,
                    hash: left_root,
                });
                Some((inner_hash(left_root, right_root), path))
            }
        }
    }
}

fn leaves(fields: &[Field]) -> Result<Vec<Leaf>, MerkleError> {
    let mut leaves = fields
        .iter()
        .map(field_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    leaves.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    for pair in leaves.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(MerkleError::DuplicateField(pair[0].name.clone()));
        }
    }
    Ok(leaves)
}

fn field_leaf(field: &Field) -> Result<Leaf, MerkleError> {
    validate_field_name(&field.name)?;
    let canonical = canonical_json(&field.value)?;
    let hash = leaf_hash(&field.name, &canonical)?;
    Ok(Leaf {
        name: field.name.clone(),
        hash,
    })
}

fn root_from_leaves(leaves: &[Leaf]) -> Result<Hash, MerkleError> {
    let hashes = leaves.iter().map(|leaf| leaf.hash).collect::<Vec<_>>();
    merkle_root(&hashes).ok_or(MerkleError::NoLeaves)
}

fn merkle_root(hashes: &[Hash]) -> Option<Hash> {
    match hashes.len() {
        0 => None,
        1 => Some(hashes[0]),
        2 => Some(inner_hash(hashes[0], hashes[1])),
        len => {
            let k = largest_power_of_two_less_than(len);
            let left = merkle_root(&hashes[..k])?;
            let right = merkle_root(&hashes[k..])?;
            Some(inner_hash(left, right))
        }
    }
}

fn largest_power_of_two_less_than(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

fn inner_hash(left: Hash, right: Hash) -> Hash {
    hash_parts(&[NODE_DST, &left, &right])
}

fn validate_field_name(field_name: &str) -> Result<(), MerkleError> {
    if field_name.is_empty() {
        return Err(MerkleError::EmptyFieldName);
    }
    if field_name.as_bytes().contains(&0) {
        return Err(MerkleError::InvalidFieldName);
    }
    Ok(())
}

fn validate_field_name_bytes(field_name: &[u8]) -> Result<(), MerkleError> {
    if field_name.is_empty() {
        return Err(MerkleError::EmptyFieldName);
    }
    if field_name.contains(&0) {
        return Err(MerkleError::InvalidFieldName);
    }
    if core::str::from_utf8(field_name).is_err() {
        return Err(MerkleError::InvalidFieldName);
    }
    Ok(())
}

fn leaf_hash_unchecked(field_name: &[u8], canonical_value: &[u8]) -> Hash {
    hash_parts(&[LEAF_DST, field_name, &[0], canonical_value])
}

fn append_canonical_value(out: &mut Vec<u8>, value: &Value) -> Result<(), MerkleError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => append_number(out, number)?,
        Value::String(string) => append_string(out, string),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                append_canonical_value(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                append_string(out, key);
                out.push(b':');
                append_canonical_value(out, &object[*key])?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn append_number(out: &mut Vec<u8>, number: &serde_json::Number) -> Result<(), MerkleError> {
    if let Some(n) = number.as_i64() {
        if !(MIN_CANONICAL_INT..=MAX_CANONICAL_INT).contains(&n) {
            return Err(MerkleError::IntegerRange);
        }
        out.extend_from_slice(n.to_string().as_bytes());
        return Ok(());
    }

    if number.as_u64().is_some() {
        return Err(MerkleError::IntegerRange);
    }

    Err(MerkleError::UnsupportedNumber)
}

fn append_string(out: &mut Vec<u8>, string: &str) {
    out.push(b'"');
    for ch in string.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br"\\"),
            '\u{08}' => out.extend_from_slice(br"\b"),
            '\u{0c}' => out.extend_from_slice(br"\f"),
            '\n' => out.extend_from_slice(br"\n"),
            '\r' => out.extend_from_slice(br"\r"),
            '\t' => out.extend_from_slice(br"\t"),
            '\u{00}'..='\u{1f}' => {
                let code = ch as usize;
                out.extend_from_slice(b"\\u00");
                out.push(HEX_LOWER[(code >> 4) & 0x0f]);
                out.push(HEX_LOWER[code & 0x0f]);
            }
            _ => {
                let mut buf = [0; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn hash_parts(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// MSC4511's causal sparse Merkle sum trie: a reference 256-level structure
/// committing the set of event IDs in an event's strict causal past.
///
/// This provides a reference implementation matching `gomatrixcrypto`'s `merkle.CausalSet`.
pub mod causal {
    use super::{hash_parts, Hash};
    use alloc::{collections::BTreeMap, collections::BTreeSet, vec::Vec};

    /// The number of bit-levels in the causal sparse Merkle sum trie: one
    /// level per bit of a 32-byte (256-bit) event-ID digest key.
    pub const CAUSAL_DEPTH: usize = 256;

    const CAUSAL_LEAF_DST: &[u8] = b"msc4511:causal-leaf:v1";
    const CAUSAL_NODE_DST: &[u8] = b"msc4511:causal-node:v1";
    const CAUSAL_EMPTY_LEAF_DST: &[u8] = b"msc4511:causal-empty-leaf:v1";

    /// Computes SHA3-256("msc4511:causal-leaf:v1" || `key`).
    fn causal_leaf(key: Hash) -> Hash {
        hash_parts(&[CAUSAL_LEAF_DST, &key])
    }

    /// Computes SHA3-256("msc4511:causal-node:v1" || `u16be(depth)` ||
    /// `left_hash` || `u64be(left_count)` || `right_hash` ||
    /// `u64be(right_count)`).
    fn causal_node(
        depth: u16,
        left_hash: Hash,
        left_count: u64,
        right_hash: Hash,
        right_count: u64,
    ) -> Hash {
        hash_parts(&[
            CAUSAL_NODE_DST,
            &depth.to_be_bytes(),
            &left_hash,
            &left_count.to_be_bytes(),
            &right_hash,
            &right_count.to_be_bytes(),
        ])
    }

    /// Returns the bit of `key` at depth `d` (0 = most significant bit of
    /// byte 0), matching the MSB-to-LSB traversal defined for the causal
    /// trie. `d % 8` is always in `0..=7`, so the subtraction from 7 never
    /// underflows; `saturating_sub` documents that instead of asserting it.
    fn causal_bit(key: &Hash, d: usize) -> u8 {
        let byte_idx = d / 8;
        let bit_idx = 7_usize.saturating_sub(d % 8);
        (key[byte_idx] >> bit_idx) & 1
    }

    /// Converts a trie depth (always `< CAUSAL_DEPTH`, i.e. `<= 255`) to the
    /// `u16` `causal_node` hashes over. `unwrap_or(u16::MAX)` is unreachable
    /// in practice but keeps this a checked, non-panicking conversion rather
    /// than a silent truncating `as` cast.
    fn depth_u16(depth: usize) -> u16 {
        u16::try_from(depth).unwrap_or(u16::MAX)
    }

    /// The canonical empty-subtree hash at every depth in `[0, CAUSAL_DEPTH]`,
    /// indexed by depth. Index `CAUSAL_DEPTH` is the distinguished empty
    /// leaf; every other index is derived from `causal_node` of two empty
    /// children at the next depth.
    ///
    /// Built once per top-level call (see [`empty_table`]) rather than
    /// recomputed recursively per lookup: a naive `empty_hash(depth)` that
    /// recurses to `CAUSAL_DEPTH` on every call is called at nearly every
    /// level of [`subtree_root`]/[`descend`]'s own recursion, which blows up
    /// to roughly `CAUSAL_DEPTH^2` hash calls for one root computation.
    /// Building this table bottom-up costs exactly `CAUSAL_DEPTH` hash calls
    /// total.
    type EmptyTable = [Hash; CAUSAL_DEPTH.saturating_add(1)];

    /// Builds [`EmptyTable`] bottom-up: one pass, `CAUSAL_DEPTH` `causal_node`
    /// calls plus one leaf hash.
    fn build_empty_table() -> EmptyTable {
        let mut table = [[0_u8; super::HASH_SIZE]; CAUSAL_DEPTH.saturating_add(1)];
        table[CAUSAL_DEPTH] = hash_parts(&[CAUSAL_EMPTY_LEAF_DST]);
        let mut depth = CAUSAL_DEPTH;
        while depth > 0 {
            depth = depth.saturating_sub(1);
            let child = table[depth.saturating_add(1)];
            table[depth] = causal_node(depth_u16(depth), child, 0, child, 0);
        }
        table
    }

    #[cfg(feature = "std")]
    fn empty_table() -> EmptyTable {
        static EMPTY_TABLE: std::sync::OnceLock<EmptyTable> = std::sync::OnceLock::new();
        *EMPTY_TABLE.get_or_init(build_empty_table)
    }

    #[cfg(not(feature = "std"))]
    fn empty_table() -> EmptyTable {
        build_empty_table()
    }

    /// The canonical empty causal set root hash (`empty_table()[0]`).
    /// Exposed so tests can assert against the known value without relying
    /// on two freshly-built empty sets comparing equal.
    #[must_use]
    pub fn empty_root() -> super::Hash {
        empty_table()[0]
    }

    /// An in-memory population of event-ID keys committed by an MSC4511
    /// 256-level sparse Merkle sum trie.
    ///
    /// The trie is maintained incrementally: each `insert` / `extend` updates
    /// only the O(256) nodes along the inserted key's path, so `root()`,
    /// `inclusion_proof()`, and `non_inclusion_proof()` are O(1) / O(256)
    /// rather than O(n·256).
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct CausalSet {
        keys: BTreeSet<Hash>,
        /// `(depth, key_prefix) → (hash, count)`. `key_prefix` at depth `d`
        /// is the first `d` bits of a key, stored in the low `d` bits of a
        /// 32-byte array (MSB-first). This is the full node cache: root is
        /// at depth 0, leaves at depth 256.
        nodes: BTreeMap<(u16, [u8; 32]), (Hash, u64)>,
    }

    /// Which side a sibling subtree sits on relative to the running node in
    /// a [`CausalProofStep`].
    ///
    /// This is derived from the key during verification — it is not part of
    /// the wire format. The type exists only for internal use in
    /// [`verify_causal_path`] and [`descend`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CausalSide {
        Left,
        Right,
    }

    /// One sibling in a causal sparse Merkle sum trie path, ordered
    /// leaf-to-root: applying each step in order (combining the running
    /// hash/count with `hash`/`count` on the named side, via
    /// `causal_node`) reconstructs the trie root and count.
    ///
    /// The side (left/right) is not stored here — it is deterministically
    /// derived from the key bit at each depth during verification
    /// ([`verify_causal_path`]). This removes a redundant field from the
    /// wire format and eliminates an entire class of forgery.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CausalProofStep {
        pub hash: Hash,
        pub count: u64,
    }

    impl CausalSet {
        /// Returns the canonical empty causal set: root `empty_hash(0)`,
        /// count 0.
        #[must_use]
        pub fn empty() -> Self {
            Self {
                keys: BTreeSet::new(),
                nodes: BTreeMap::new(),
            }
        }

        /// Inserts a key into `self` in place without cloning.
        ///
        /// Updates the node cache incrementally: walks the path from root to
        /// leaf, creating any missing nodes, then recomputes hashes bottom-up.
        /// O(256) per insert.
        pub fn insert_mut(&mut self, key: Hash) -> bool {
            if !self.keys.insert(key) {
                return false;
            }
            let empty = empty_table();

            // Phase 1: walk down, creating all nodes along the path.
            let mut prefix = [0u8; 32];
            for d in 0..CAUSAL_DEPTH {
                let depth = depth_u16(d);
                self.nodes.entry((depth, prefix)).or_insert((empty[d], 0));
                if causal_bit(&key, d) == 0 {
                    // go left: clear bit d in prefix
                    prefix[d / 8] &= !(1 << (7 - d % 8));
                } else {
                    // go right: set bit d in prefix
                    prefix[d / 8] |= 1 << (7 - d % 8);
                }
            }
            // Leaf at depth 256
            let leaf_depth = depth_u16(CAUSAL_DEPTH);
            self.nodes
                .insert((leaf_depth, prefix), (causal_leaf(key), 1));

            // Phase 2: walk back up, recomputing hashes from cached children.
            // `child_prefix` is maintained to have bits 0..d set from the
            // key and bits d+1..255 = 0 at each iteration. This matches
            // how Phase 1 stored child nodes at depth d+1.
            let mut child_prefix = prefix;
            for d in (0..CAUSAL_DEPTH).rev() {
                let depth = depth_u16(d);
                let child_depth = depth_u16(d + 1);

                // Strip child_prefix to only have bits 0..d set.
                let byte_idx = d / 8;
                let bit_idx = d % 8;
                child_prefix[byte_idx] &= 0xFF << (7 - bit_idx);
                for i in (byte_idx + 1)..32 {
                    child_prefix[i] = 0;
                }

                // Left child prefix: bit d = 0.
                let mut left_prefix = child_prefix;
                left_prefix[byte_idx] &= !(1 << (7 - bit_idx));
                let (left_hash, left_count) = self
                    .nodes
                    .get(&(child_depth, left_prefix))
                    .copied()
                    .unwrap_or((empty[d + 1], 0));

                // Right child prefix: bit d = 1.
                let mut right_prefix = child_prefix;
                right_prefix[byte_idx] |= 1 << (7 - bit_idx);
                let (right_hash, right_count) = self
                    .nodes
                    .get(&(child_depth, right_prefix))
                    .copied()
                    .unwrap_or((empty[d + 1], 0));

                let node = causal_node(depth, left_hash, left_count, right_hash, right_count);
                // Node at depth d is stored with prefix bits 0..d-1 set
                // (= child_prefix with bit d cleared = left_prefix).
                self.nodes.insert(
                    (depth, left_prefix),
                    (node, count_sum(left_count, right_count)),
                );
            }
            true
        }

        /// Extends `self` with keys from an iterator in place.
        pub fn extend<I: IntoIterator<Item = Hash>>(&mut self, iter: I) {
            for key in iter {
                self.insert_mut(key);
            }
        }

        /// Returns a new [`CausalSet`] containing every key in `self` plus
        /// `key`. A no-op (returns an equal set) if `key` is already a
        /// member. The node cache is updated incrementally (O(256)).
        #[must_use]
        pub fn insert(&self, key: Hash) -> Self {
            let mut next = self.clone();
            next.insert_mut(key);
            next
        }

        /// Returns the set union of `self` and `other`, eliminating
        /// duplicates, as required for a multi-predecessor merge event's
        /// `causal_set` transition. The node cache is updated
        /// incrementally.
        #[must_use]
        pub fn union(&self, other: &Self) -> Self {
            let mut next = self.clone();
            for k in &other.keys {
                next.insert_mut(*k);
            }
            next
        }

        /// Reports whether `key` is a member of `self`.
        #[must_use]
        pub fn contains(&self, key: &Hash) -> bool {
            self.keys.contains(key)
        }

        /// Returns the number of distinct keys committed by `self`.
        #[must_use]
        pub fn count(&self) -> u64 {
            self.keys.len() as u64
        }

        /// Computes the canonical sparse Merkle sum trie root for `self`.
        /// O(1) — reads from the maintained node cache.
        #[must_use]
        pub fn root(&self) -> Hash {
            if self.keys.is_empty() {
                return empty_table()[0];
            }
            let root_depth: u16 = 0;
            let root_prefix = [0u8; 32];
            self.nodes
                .get(&(root_depth, root_prefix))
                .map_or_else(|| empty_table()[0], |(h, _)| *h)
        }

        /// Like [`Self::root`], wrapped as an [`super::UnsignedRoot`] -- see
        /// that type's docs for what a caller needs to do before presenting
        /// this value as a proof of anything to someone else. Prefer this
        /// over `root()` at any call site that hands the root outside the
        /// local process.
        #[must_use]
        pub fn unsigned_root(&self) -> super::UnsignedRoot {
            super::UnsignedRoot(self.root())
        }
    }

    /// A single step in a compressed causal-trie proof path.
    ///
    /// Runs of consecutive canonical-empty siblings are collapsed into a
    /// single `EmptyRun` entry; non-empty steps are emitted individually
    /// as `Step`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CompressedCausalStep {
        /// A non-empty sibling step (hash and count are explicit).
        Step(CausalProofStep),
        /// A run of `length` consecutive canonical-empty siblings.
        /// `start_depth` is the sibling depth of the first empty step
        /// in the run (the step at path position 0 has sibling depth `T`
        /// where `T = terminal_depth`).  Expansion proceeds in proof
        /// order: `empty[start_depth]`, `empty[start_depth - 1]`, …,
        /// `empty[start_depth - length + 1]`, each with count 0 and side
        /// derived from `causal_bit(key, sibling_depth - 1)`.
        EmptyRun { start_depth: u16, length: u16 },
    }

    /// Error type for compressed causal-trie proof operations.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CausalProofError {
        /// A compressed step references a sibling depth outside
        /// `1..=CAUSAL_DEPTH`, or `terminal_depth` itself exceeds
        /// `CAUSAL_DEPTH`.
        ///
        /// `EmptyRun` carries no hash or count of its own — it is expanded
        /// directly from `empty_table()` with count 0 — so there is no
        /// attacker-supplied empty-step value to validate; this variant is
        /// the only depth-shaped rejection the format has.
        InvalidDepth(u16),
        /// The decompressed path length does not match `terminal_depth`.
        PathLengthMismatch {
            decompressed: usize,
            expected: usize,
        },
        /// The compressed encoding is truncated (fewer steps than
        /// `terminal_depth`).
        Truncated,
        /// The compressed encoding has data after the complete path.
        ExcessData,
        /// An empty run would extend below sibling depth 1.
        RunBelowRoot,
        /// An empty run's start depth does not match the expected sibling
        /// depth for the current path position (non-contiguous).
        NonContiguousRun {
            expected_sibling_depth: usize,
            actual_start: usize,
        },
        /// Two consecutive `EmptyRun` entries: the second is redundant
        /// because the first could have been extended to cover the same
        /// range. This is a canonicity violation — `compress_causal_path`
        /// never emits adjacent runs.
        NonMaximalRun,
        /// A `Step` entry whose `count == 0` and `hash` equals the
        /// canonical empty subtree at the expected sibling depth. This
        /// should have been collapsed into an `EmptyRun` by the
        /// compressor. Rejecting it enforces the same canonicity rule
        /// that adjacent `EmptyRun` rejection does: every step in a
        /// compressed path is either non-empty or part of a maximal run.
        NonCanonicalStep,
    }

    impl core::fmt::Display for CausalProofError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::InvalidDepth(d) => write!(f, "causal proof: invalid depth {d}"),
                Self::PathLengthMismatch {
                    decompressed,
                    expected,
                } => write!(
                    f,
                    "causal proof: decompressed path length {decompressed} \
                     does not match terminal depth {expected}"
                ),
                Self::Truncated => f.write_str("causal proof: truncated compressed encoding"),
                Self::ExcessData => f.write_str("causal proof: excess data after path"),
                Self::RunBelowRoot => {
                    f.write_str("causal proof: empty run extends below sibling depth 1")
                }
                Self::NonContiguousRun {
                    expected_sibling_depth,
                    actual_start,
                } => write!(
                    f,
                    "causal proof: empty run starts at sibling depth {actual_start}, \
                     expected {expected_sibling_depth}"
                ),
                Self::NonMaximalRun => {
                    f.write_str("causal proof: consecutive empty runs must be merged")
                }
                Self::NonCanonicalStep => f.write_str(
                    "causal proof: step carries canonical-empty value; \
                                 use EmptyRun instead",
                ),
            }
        }
    }

    impl core::error::Error for CausalProofError {}

    /// Compresses a causal-trie proof path by collapsing runs of
    /// consecutive canonical-empty siblings into `EmptyRun` entries.
    ///
    /// Each step at position `i` in `path` is combined at parent depth
    /// `T - 1 - i` (where `T = terminal_depth`); the sibling subtree it
    /// carries is therefore rooted at depth `T - i`, and its canonical-empty
    /// value is `empty_table()[T - i]`. A step is canonical-empty when its
    /// hash equals that value and its count is 0. Consecutive canonical-empty
    /// steps are merged into a single `EmptyRun { start_depth, length }`,
    /// where `start_depth` is the *sibling* depth (`T - i`) of the first
    /// empty step in the run.
    #[must_use]
    pub fn compress_causal_path(
        terminal_depth: usize,
        path: &[CausalProofStep],
    ) -> Vec<CompressedCausalStep> {
        let empty = empty_table();
        let mut out: Vec<CompressedCausalStep> = Vec::new();
        let mut run_start: Option<usize> = None;
        let mut run_len: u16 = 0;

        for (i, step) in path.iter().enumerate() {
            // Sibling depth: one above the parent depth `T - 1 - i`.
            let sibling_depth = terminal_depth.saturating_sub(i);
            let is_empty =
                step.count == 0 && sibling_depth < empty.len() && step.hash == empty[sibling_depth];

            if is_empty {
                if run_start.is_none() {
                    run_start = Some(sibling_depth);
                    run_len = 1;
                } else {
                    run_len = run_len.saturating_add(1);
                }
            } else {
                // Flush any active run (sibling depths decrease as `i`
                // increases, so `start_depth` is the deepest/first point
                // of the run and the run expands toward the root).
                if let Some(start) = run_start.take() {
                    out.push(CompressedCausalStep::EmptyRun {
                        start_depth: depth_u16(start),
                        length: run_len,
                    });
                    run_len = 0;
                }
                out.push(CompressedCausalStep::Step(*step));
            }
        }

        // Flush trailing run.
        if let Some(start) = run_start.take() {
            out.push(CompressedCausalStep::EmptyRun {
                start_depth: depth_u16(start),
                length: run_len,
            });
        }

        out
    }

    /// Decompresses a compressed causal-trie proof path, validating that
    /// every `EmptyRun` expands to the correct canonical empty hashes with
    /// count 0.
    ///
    /// Returns the expanded `Vec<CausalProofStep>` on success, or a
    /// [`CausalProofError`] if the compressed encoding is malformed,
    /// non-canonical, or has the wrong total length.
    ///
    /// # Errors
    ///
    /// Returns [`CausalProofError`] on any validation failure.
    pub fn decompress_causal_path(
        terminal_depth: usize,
        compressed: &[CompressedCausalStep],
    ) -> Result<Vec<CausalProofStep>, CausalProofError> {
        if terminal_depth > CAUSAL_DEPTH {
            return Err(CausalProofError::InvalidDepth(depth_u16(terminal_depth)));
        }
        let empty = empty_table();
        let mut out: Vec<CausalProofStep> = Vec::new();
        let mut prev_was_empty_run = false;

        for step in compressed {
            match step {
                CompressedCausalStep::Step(s) => {
                    if out.len() >= terminal_depth {
                        return Err(CausalProofError::ExcessData);
                    }
                    // Reject a Step that carries a canonical-empty value:
                    // the compressor would have collapsed this into an
                    // EmptyRun, so emitting it as a Step is non-canonical.
                    let sibling_depth = terminal_depth.saturating_sub(out.len());
                    if s.count == 0 && sibling_depth < empty.len() && s.hash == empty[sibling_depth]
                    {
                        return Err(CausalProofError::NonCanonicalStep);
                    }
                    prev_was_empty_run = false;
                    out.push(*s);
                }
                CompressedCausalStep::EmptyRun {
                    start_depth,
                    length,
                } => {
                    // Reject consecutive EmptyRuns: the second should
                    // have been merged into the first by the compressor.
                    if prev_was_empty_run {
                        return Err(CausalProofError::NonMaximalRun);
                    }
                    prev_was_empty_run = true;
                    let start = *start_depth as usize;
                    let len = *length as usize;

                    if len == 0 {
                        return Err(CausalProofError::Truncated);
                    }
                    // Sibling depths only exist in `1..=CAUSAL_DEPTH` (depth
                    // 0 is the root, which has no parent to be a sibling
                    // of), so `start` outside that range is structurally
                    // invalid regardless of where it sits in the path.
                    if start == 0 || start > CAUSAL_DEPTH {
                        return Err(CausalProofError::InvalidDepth(*start_depth));
                    }
                    // The run expands toward the root: sibling depths
                    // `start, start - 1, ..., start - len + 1`, which must
                    // not go below depth 1. Checked before contiguity so a
                    // self-evidently out-of-bounds run is reported as such
                    // even when it's also misaligned with the current
                    // position.
                    if len > start {
                        return Err(CausalProofError::RunBelowRoot);
                    }
                    // `start` is the sibling depth of the first expanded
                    // step, i.e. `terminal_depth - out.len()`. A mismatch
                    // means the encoding's run boundaries don't line up
                    // with its actual position in the path.
                    let expected_start = terminal_depth.saturating_sub(out.len());
                    if start != expected_start {
                        return Err(CausalProofError::NonContiguousRun {
                            expected_sibling_depth: expected_start,
                            actual_start: start,
                        });
                    }
                    for j in 0..len {
                        // `j < len <= start` (checked above) and
                        // `sibling_depth >= 1` (since `len <= start`
                        // guarantees `start - len + 1 >= 1`), so both
                        // subtractions stay in range; `saturating_sub`
                        // avoids the raw `-` clippy flags regardless.
                        let sibling_depth = start.saturating_sub(j);
                        out.push(CausalProofStep {
                            hash: empty[sibling_depth],
                            count: 0,
                        });
                    }
                }
            }
        }

        if out.len() != terminal_depth {
            return Err(CausalProofError::PathLengthMismatch {
                decompressed: out.len(),
                expected: terminal_depth,
            });
        }

        Ok(out)
    }

    /// Verifies an inclusion proof encoded with empty-run compression.
    ///
    /// Decompresses `compressed` and delegates to [`verify_causal_inclusion`].
    ///
    /// # Errors
    ///
    /// Returns [`CausalProofError`] if decompression or validation fails.
    pub fn verify_causal_inclusion_compressed(
        key: &Hash,
        compressed: &[CompressedCausalStep],
        root: Hash,
        count: u64,
    ) -> Result<bool, CausalProofError> {
        let path = decompress_causal_path(CAUSAL_DEPTH, compressed)?;
        Ok(verify_causal_inclusion(key, &path, root, count))
    }

    /// Verifies a non-inclusion proof encoded with empty-run compression.
    ///
    /// Decompresses `compressed` and delegates to
    /// [`verify_causal_non_inclusion`].
    ///
    /// # Errors
    ///
    /// Returns [`CausalProofError`] if decompression or validation fails.
    pub fn verify_causal_non_inclusion_compressed(
        key: &Hash,
        terminal_depth: usize,
        compressed: &[CompressedCausalStep],
        root: Hash,
        count: u64,
    ) -> Result<bool, CausalProofError> {
        let path = decompress_causal_path(terminal_depth, compressed)?;
        Ok(verify_causal_non_inclusion(
            key,
            terminal_depth,
            &path,
            root,
            count,
        ))
    }

    impl CausalSet {
        /// Returns the ordered (leaf-to-root) sibling path proving `key` is a
        /// member of `self`, along with `self`'s root and count. Returns
        /// [`None`] if `key` is not a member; there is no inclusion proof for
        /// a non-member. O(256) — walks the node cache.
        #[must_use]
        pub fn inclusion_proof(&self, key: &Hash) -> Option<(Vec<CausalProofStep>, Hash, u64)> {
            if self.keys.is_empty() || !self.keys.contains(key) {
                return None;
            }
            let empty = empty_table();
            let mut path = Vec::with_capacity(CAUSAL_DEPTH);
            let mut prefix = [0u8; 32];
            for d in 0..CAUSAL_DEPTH {
                let child_depth = depth_u16(d + 1);
                // The sibling is the other child at this depth.
                let (sib_hash, sib_count) = if causal_bit(key, d) == 0 {
                    // key goes left; sibling is right
                    let mut right_prefix = prefix;
                    right_prefix[d / 8] |= 1 << (7 - d % 8);
                    self.nodes
                        .get(&(child_depth, right_prefix))
                        .copied()
                        .unwrap_or((empty[d + 1], 0))
                } else {
                    // key goes right; sibling is left
                    let mut left_prefix = prefix;
                    left_prefix[d / 8] &= !(1 << (7 - d % 8));
                    self.nodes
                        .get(&(child_depth, left_prefix))
                        .copied()
                        .unwrap_or((empty[d + 1], 0))
                };
                path.push(CausalProofStep {
                    hash: sib_hash,
                    count: sib_count,
                });
                if causal_bit(key, d) == 0 {
                    prefix[d / 8] &= !(1 << (7 - d % 8));
                } else {
                    prefix[d / 8] |= 1 << (7 - d % 8);
                }
            }
            let root_hash = self.root();
            let root_count = self.count();
            path.reverse();
            Some((path, root_hash, root_count))
        }

        /// Returns the ordered (leaf-to-root) sibling path proving `key` is
        /// NOT a member of `self` (the key-directed path terminates in a
        /// canonical empty subtree at the returned depth), along with
        /// `self`'s root and count. Returns [`None`] if `key` IS a member; no
        /// non-inclusion proof exists for a member. O(256) — walks the node
        /// cache.
        #[must_use]
        pub fn non_inclusion_proof(
            &self,
            key: &Hash,
        ) -> Option<(Vec<CausalProofStep>, usize, Hash, u64)> {
            let empty = empty_table();
            if self.keys.is_empty() {
                return Some((Vec::new(), 0, empty[0], 0));
            }
            // Walk down the key-directed path, collecting siblings, until we
            // hit an empty node (the key is not in the set).
            let mut path = Vec::new();
            let mut prefix = [0u8; 32];
            for d in 0..CAUSAL_DEPTH {
                let child_depth = depth_u16(d + 1);
                // Collect the sibling at this depth (the other child of
                // the node at depth d).
                let (sib_hash, sib_count) = if causal_bit(key, d) == 0 {
                    let mut right_prefix = prefix;
                    right_prefix[d / 8] |= 1 << (7 - d % 8);
                    self.nodes
                        .get(&(child_depth, right_prefix))
                        .copied()
                        .unwrap_or((empty[d + 1], 0))
                } else {
                    let mut left_prefix = prefix;
                    left_prefix[d / 8] &= !(1 << (7 - d % 8));
                    self.nodes
                        .get(&(child_depth, left_prefix))
                        .copied()
                        .unwrap_or((empty[d + 1], 0))
                };
                path.push(CausalProofStep {
                    hash: sib_hash,
                    count: sib_count,
                });
                // Check if the child node on the key-directed path exists
                // and is non-empty.
                let mut child_prefix = prefix;
                if causal_bit(key, d) == 0 {
                    child_prefix[d / 8] &= !(1 << (7 - d % 8));
                } else {
                    child_prefix[d / 8] |= 1 << (7 - d % 8);
                }
                let child = self.nodes.get(&(child_depth, child_prefix));
                let child_is_empty = child.map_or(true, |(_, c)| *c == 0);
                if child_is_empty {
                    // Found the terminal: an empty subtree at depth d+1.
                    let root_hash = self.root();
                    let root_count = self.count();
                    path.reverse();
                    return Some((path, d + 1, root_hash, root_count));
                }
                prefix = child_prefix;
            }
            // All 256 levels are non-empty and key was found — this is
            // actually an inclusion case, but the caller asked for
            // non_inclusion_proof which returns None for members.
            None
        }
    }

    /// Recomputes `s`'s root from `key`'s `causal_leaf` and `path`
    /// (leaf-to-root ordered siblings) and reports whether it matches `root`
    /// and `count`.
    #[must_use]
    pub fn verify_causal_inclusion(
        key: &Hash,
        path: &[CausalProofStep],
        root: Hash,
        count: u64,
    ) -> bool {
        verify_causal_path(causal_leaf(*key), 1, CAUSAL_DEPTH, key, path, root, count)
    }

    /// Recomputes a root from the canonical empty hash at `terminal_depth`
    /// and `path` (leaf-to-root ordered siblings) and reports whether it
    /// matches `root` and `count`.
    #[must_use]
    pub fn verify_causal_non_inclusion(
        key: &Hash,
        terminal_depth: usize,
        path: &[CausalProofStep],
        root: Hash,
        count: u64,
    ) -> bool {
        if terminal_depth > CAUSAL_DEPTH {
            return false;
        }
        if path.len() != terminal_depth {
            return false;
        }
        // Minimality: if the sibling at the terminal depth were also
        // canonical-empty, the parent at terminal_depth - 1 would have two
        // empty children and so be canonical-empty itself — the descent
        // would have stopped a level higher. Biconditional, so this is
        // exact, not a heuristic.
        if let Some(s0) = path.first() {
            if s0.count == 0 && s0.hash == empty_table()[terminal_depth] {
                return false;
            }
        }
        // Under `std`, `empty_table` is built once and reused by root, proof,
        // and verification operations. The no_std fallback retains allocation-
        // free portability without requiring a synchronization primitive.
        verify_causal_path(
            empty_table()[terminal_depth],
            0,
            terminal_depth,
            key,
            path,
            root,
            count,
        )
    }

    /// Sums two subtree/sibling counts. A locally built causal set's
    /// population is bounded by the number of distinct 32-byte keys held in
    /// memory, so this sum cannot reach `u64::MAX`; `saturating_add` avoids a
    /// panic path without changing any reachable result. Verification of an
    /// untrusted path uses `checked_add` in `verify_causal_path` and rejects
    /// overflow, as the draft's "Room-version validity" section requires.
    fn count_sum(a: u64, b: u64) -> u64 {
        a.saturating_add(b)
    }

    /// Recomputes a causal trie root from a terminal node (either a
    /// `causal_leaf` and count 1, or a canonical empty hash and count 0) by
    /// applying `path`'s siblings from the level just above the terminal
    /// depth up to the root. `path` is ordered leaf-to-root (deepest sibling
    /// first), so `depth` walks downward from `terminal_depth - 1` to 0;
    /// `path.len() == terminal_depth` is checked first, so the decrement
    /// below never underflows past 0.
    ///
    /// The side (left/right) at each level is derived from `causal_bit(key,
    /// depth)`, not stored in the path — this removes a redundant wire field
    /// and eliminates an entire class of forgery.
    fn verify_causal_path(
        terminal_hash: Hash,
        terminal_count: u64,
        terminal_depth: usize,
        key: &Hash,
        path: &[CausalProofStep],
        root: Hash,
        count: u64,
    ) -> bool {
        if path.len() != terminal_depth {
            return false;
        }
        let mut cur_hash = terminal_hash;
        let mut cur_count = terminal_count;
        let mut depth = terminal_depth;
        for step in path {
            depth = depth.saturating_sub(1);
            let side = if causal_bit(key, depth) == 0 {
                CausalSide::Right
            } else {
                CausalSide::Left
            };
            cur_hash = match side {
                CausalSide::Left => {
                    causal_node(depth_u16(depth), step.hash, step.count, cur_hash, cur_count)
                }
                CausalSide::Right => {
                    causal_node(depth_u16(depth), cur_hash, cur_count, step.hash, step.count)
                }
            };
            cur_count = match cur_count.checked_add(step.count) {
                Some(sum) => sum,
                None => return false,
            };
        }
        cur_hash == root && cur_count == count
    }

    #[cfg(all(test, feature = "std"))]
    mod test_oracle {
        use super::*;

        #[derive(PartialEq, Eq)]
        pub(crate) enum TerminalKind {
            Leaf,
            Empty,
        }

        /// `subtree_root`, generalized to accept an empty key set.
        pub(crate) fn subtree_root_or_empty(keys: &[Hash], depth: usize) -> (Hash, u64) {
            if keys.is_empty() {
                (empty_table()[depth], 0)
            } else {
                subtree_root(keys, depth)
            }
        }

        /// Independent recursive computation of the causal trie root for a
        /// given key set. Used as a differential oracle against the
        /// incremental node-cache implementation.
        pub(crate) fn subtree_root(keys: &[Hash], depth: usize) -> (Hash, u64) {
            if depth == CAUSAL_DEPTH {
                return (causal_leaf(keys[0]), 1);
            }
            let mut left = Vec::new();
            let mut right = Vec::new();
            for k in keys {
                if causal_bit(k, depth) == 0 {
                    left.push(*k);
                } else {
                    right.push(*k);
                }
            }
            let next_depth = depth.saturating_add(1);
            let (left_hash, left_count) = subtree_root_or_empty(&left, next_depth);
            let (right_hash, right_count) = subtree_root_or_empty(&right, next_depth);
            (
                causal_node(
                    depth_u16(depth),
                    left_hash,
                    left_count,
                    right_hash,
                    right_count,
                ),
                count_sum(left_count, right_count),
            )
        }

        /// Recursively computes the (hash, count) of the subtree over `keys`
        /// at `depth`, plus the ordered leaf-to-root sibling path along
        /// `target`'s bit-directed descent. Returns the terminal node's kind
        /// and depth.
        pub(crate) fn descend(
            keys: &[Hash],
            depth: usize,
            target: &Hash,
        ) -> (Hash, u64, Vec<CausalProofStep>, TerminalKind, usize) {
            if keys.is_empty() {
                return (
                    empty_table()[depth],
                    0,
                    Vec::new(),
                    TerminalKind::Empty,
                    depth,
                );
            }
            if depth == CAUSAL_DEPTH {
                return (
                    causal_leaf(keys[0]),
                    1,
                    Vec::new(),
                    TerminalKind::Leaf,
                    depth,
                );
            }
            let mut left = Vec::new();
            let mut right = Vec::new();
            for k in keys {
                if causal_bit(k, depth) == 0 {
                    left.push(*k);
                } else {
                    right.push(*k);
                }
            }
            let next_depth = depth.saturating_add(1);
            if causal_bit(target, depth) == 0 {
                let (left_hash, left_count, mut path, kind, term_depth) =
                    descend(&left, next_depth, target);
                let (right_hash, right_count) = subtree_root_or_empty(&right, next_depth);
                let node = causal_node(
                    depth_u16(depth),
                    left_hash,
                    left_count,
                    right_hash,
                    right_count,
                );
                path.push(CausalProofStep {
                    hash: right_hash,
                    count: right_count,
                });
                (
                    node,
                    count_sum(left_count, right_count),
                    path,
                    kind,
                    term_depth,
                )
            } else {
                let (right_hash, right_count, mut path, kind, term_depth) =
                    descend(&right, next_depth, target);
                let (left_hash, left_count) = subtree_root_or_empty(&left, next_depth);
                let node = causal_node(
                    depth_u16(depth),
                    left_hash,
                    left_count,
                    right_hash,
                    right_count,
                );
                path.push(CausalProofStep {
                    hash: left_hash,
                    count: left_count,
                });
                (
                    node,
                    count_sum(left_count, right_count),
                    path,
                    kind,
                    term_depth,
                )
            }
        }
    }

    /// Differential coverage comparing the incremental node-cache
    /// implementation against [`test_oracle`]'s independent recursive
    /// computation.
    ///
    /// This lives here (rather than in `tests/unit/test_causal.rs`) because
    /// `test_oracle` is `pub(crate)` and gated on `#[cfg(test)]`: it is only
    /// compiled in when this crate builds *itself* under test (`cargo test
    /// --lib`), not when an external integration-test binary links this
    /// crate as an ordinary dependency. Only a same-crate `#[cfg(test)]`
    /// module can see it.
    #[cfg(all(test, feature = "std"))]
    mod tests {
        use super::test_oracle::{descend, subtree_root_or_empty, TerminalKind};
        use super::*;

        /// A key with exactly one bit set, at bit index `bit` (MSB-first,
        /// matching [`causal_bit`]).
        ///
        /// Deliberately not `HASH_SIZE`-uniform: a same-byte key such as
        /// `[0xAA; 32]` can't distinguish a correct `byte_idx`/`bit_idx`
        /// split from an off-by-one at a byte boundary, because every bit in
        /// the key is identical either side of the boundary. A single-bit
        /// key makes the boundary observable.
        fn bit_key(bit: usize) -> Hash {
            let mut k = [0u8; 32];
            k[bit / 8] |= 1 << (7 - bit % 8);
            k
        }

        /// Deterministic xorshift64 → 256-bit keys. Every byte of each key
        /// is populated, exercising Phase 2's tail-zeroing loop and
        /// intra-byte mask across all 32 bytes.
        fn dense_keys(seed: u64, count: usize) -> Vec<Hash> {
            let mut state = seed;
            let mut keys = Vec::with_capacity(count);
            for _ in 0..count {
                let mut k = [0u8; 32];
                for chunk in k.chunks_mut(8) {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    chunk.copy_from_slice(&state.to_le_bytes());
                }
                keys.push(k);
            }
            keys
        }

        /// Cross-checks `CausalSet`'s incremental root/proofs against the
        /// recursive oracle for keys that differ only at the byte-boundary
        /// bits (7/8, 15/16) and the final bit (255) — exactly where a strip
        /// or shift bug in `insert_mut`'s bit arithmetic would show up, and
        /// exactly what an all-identical-byte test key (like `key()` in
        /// `tests/unit/test_causal.rs`) cannot exercise.
        #[test]
        fn differential_root_and_proofs_at_boundary_bits() {
            let bits = [7_usize, 8, 15, 16, 255];
            let keys: Vec<Hash> = bits.iter().copied().map(bit_key).collect();

            // descend recurses 256 levels; subtree_root recurses 256 levels
            // for each non-target subtree. Use a larger stack to avoid
            // overflow in the oracle.
            let child = std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    let mut set = CausalSet::empty();
                    for &k in &keys {
                        set.insert_mut(k);
                    }

                    let (ref_root, ref_count) = subtree_root_or_empty(&keys, 0);
                    assert_eq!(
                        set.root(),
                        ref_root,
                        "incremental root diverges from oracle"
                    );
                    assert_eq!(set.count(), ref_count);

                    for &k in &keys {
                        let (path, root, count) = set.inclusion_proof(&k).expect("key is a member");
                        let (oracle_hash, oracle_count, oracle_path, kind, term_depth) =
                            descend(&keys, 0, &k);
                        assert!(matches!(kind, TerminalKind::Leaf));
                        assert_eq!(term_depth, CAUSAL_DEPTH);
                        assert_eq!(oracle_hash, root);
                        assert_eq!(oracle_count, count);
                        assert_eq!(
                            oracle_path, path,
                            "inclusion path diverges from oracle for bit key"
                        );
                        assert!(verify_causal_inclusion(&k, &path, root, count));
                    }

                    // Bit 47 is the reviewer-flagged boundary this test exists
                    // to cover: absent from the member set, it must terminate
                    // in an empty subtree whose depth and path match the
                    // oracle exactly.
                    let absent = bit_key(47);
                    let (oracle_hash, oracle_count, oracle_path, kind, term_depth) =
                        descend(&keys, 0, &absent);
                    assert!(matches!(kind, TerminalKind::Empty));
                    let (path, depth, root, count) = set
                        .non_inclusion_proof(&absent)
                        .expect("key is not a member");
                    assert_eq!(depth, term_depth);
                    // The terminal hash is the hash of the subtree containing
                    // all 5 keys at the terminal depth (the non-empty sibling),
                    // NOT empty[term_depth].
                    assert_eq!(oracle_hash, root);
                    assert_eq!(oracle_count, count);
                    assert_eq!(oracle_path, path, "non-inclusion path diverges from oracle");
                    assert!(verify_causal_non_inclusion(
                        &absent, depth, &path, root, count
                    ));
                })
                .unwrap();
            child.join().unwrap();
        }

        /// Dense pseudorandom keys: exercises the intra-byte mask
        /// (`child_prefix[byte_idx] &= 0xFF << (7 - bit_idx)`) and
        /// tail-zeroing loop (`child_prefix[(byte_idx + 1)..32] = 0`) on
        /// keys where those bytes are non-trivial — the exact gap left by
        /// single-bit keys. Tests n=1, n=2 (trivial degeneracies), and
        /// n=32, n=64 (dense enough that Phase 2 recurses through many
        /// non-trivial prefixes).
        #[test]
        fn differential_root_and_proofs_dense_random() {
            let child = std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    for &n in &[1, 2, 32, 64] {
                        let keys = dense_keys(0xDEAD_BEEF_CAFE_1234, n);

                        let mut set = CausalSet::empty();
                        for &k in &keys {
                            set.insert_mut(k);
                        }

                        let (ref_root, ref_count) = subtree_root_or_empty(&keys, 0);
                        assert_eq!(set.root(), ref_root, "root diverges at n={n}");
                        assert_eq!(set.count(), ref_count, "count diverges at n={n}");

                        for &k in &keys {
                            let (path, root, count) =
                                set.inclusion_proof(&k).expect("key is a member");
                            let (oracle_hash, oracle_count, oracle_path, kind, term_depth) =
                                descend(&keys, 0, &k);
                            assert!(matches!(kind, TerminalKind::Leaf));
                            assert_eq!(term_depth, CAUSAL_DEPTH);
                            assert_eq!(oracle_hash, root, "inclusion hash diverges at n={n}");
                            assert_eq!(oracle_count, count, "inclusion count diverges at n={n}");
                            assert_eq!(oracle_path, path, "inclusion path diverges at n={n}");
                            assert!(verify_causal_inclusion(&k, &path, root, count));
                        }

                        // Non-inclusion: pick a key not in the set.
                        let absent = dense_keys(0xBEEF_CAFE_1234_DEAD, 1)[0];
                        let (oracle_hash, oracle_count, oracle_path, kind, term_depth) =
                            descend(&keys, 0, &absent);
                        assert!(matches!(kind, TerminalKind::Empty));
                        let (path, depth, root, count) = set
                            .non_inclusion_proof(&absent)
                            .expect("key is not a member");
                        assert_eq!(depth, term_depth);
                        assert_eq!(oracle_hash, root);
                        assert_eq!(oracle_count, count);
                        assert_eq!(oracle_path, path, "non-inclusion path diverges at n={n}");
                        assert!(verify_causal_non_inclusion(
                            &absent, depth, &path, root, count
                        ));
                    }
                })
                .unwrap();
            child.join().unwrap();
        }

        /// Same cross-check, insertion-order independence: the oracle takes
        /// a flat key slice, so this also confirms the incremental cache
        /// doesn't depend on the order keys were inserted in. Compares both
        /// roots AND inclusion/non-inclusion proofs — an ordering bug that
        /// produced a correct root with a stale sibling would slip through
        /// root-only comparison.
        #[test]
        fn differential_root_is_order_independent() {
            let bits = [7_usize, 8, 15, 16, 255];
            let bit_keys: Vec<Hash> = bits.iter().copied().map(bit_key).collect();
            let dense = dense_keys(0xCAFE_1234_DEAD_BEEF, 48);

            let child = std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    for (label, keys) in
                        [("bit", &bit_keys as &[Hash]), ("dense", &dense as &[Hash])]
                    {
                        let mut forward = CausalSet::empty();
                        for &k in keys {
                            forward.insert_mut(k);
                        }
                        let mut reverse = CausalSet::empty();
                        for &k in keys.iter().rev() {
                            reverse.insert_mut(k);
                        }

                        let (ref_root, ref_count) = subtree_root_or_empty(keys, 0);
                        assert_eq!(forward.root(), ref_root);
                        assert_eq!(reverse.root(), ref_root);
                        assert_eq!(forward.count(), ref_count);
                        assert_eq!(reverse.count(), ref_count);

                        // Compare inclusion proofs under both orderings.
                        for &k in keys {
                            let (f_path, f_root, f_count) = forward.inclusion_proof(&k).unwrap();
                            let (r_path, r_root, r_count) = reverse.inclusion_proof(&k).unwrap();
                            assert_eq!(f_root, r_root, "{label}: inclusion root diverges");
                            assert_eq!(f_count, r_count, "{label}: inclusion count diverges");
                            assert_eq!(f_path, r_path, "{label}: inclusion path diverges");
                        }

                        // Compare non-inclusion proofs.
                        let absent = dense_keys(0xBEEF_CAFE_1234_DEAD, 1)[0];
                        let (f_path, f_depth, f_root, f_count) =
                            forward.non_inclusion_proof(&absent).unwrap();
                        let (r_path, r_depth, r_root, r_count) =
                            reverse.non_inclusion_proof(&absent).unwrap();
                        assert_eq!(f_root, r_root, "{label}: non-inclusion root diverges");
                        assert_eq!(f_count, r_count, "{label}: non-inclusion count diverges");
                        assert_eq!(f_depth, r_depth, "{label}: non-inclusion depth diverges");
                        assert_eq!(f_path, r_path, "{label}: non-inclusion path diverges");
                    }
                })
                .unwrap();
            child.join().unwrap();
        }

        /// Differential test for `CausalSet::union`: split a dense key set
        /// into halves, build each half with `insert_mut`, then merge with
        /// `union` and verify the result matches the oracle for the full set.
        #[test]
        fn differential_union_matches_oracle() {
            let child = std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    let keys = dense_keys(0xFACE_4321_BEEF_0000, 48);
                    let (left, right) = keys.split_at(24);

                    let mut a = CausalSet::empty();
                    for &k in left {
                        a.insert_mut(k);
                    }
                    let mut b = CausalSet::empty();
                    for &k in right {
                        b.insert_mut(k);
                    }

                    let merged = a.union(&b);
                    let (ref_root, ref_count) = subtree_root_or_empty(&keys, 0);
                    assert_eq!(merged.root(), ref_root, "union root diverges");
                    assert_eq!(merged.count(), ref_count, "union count diverges");

                    for &k in &keys {
                        let (path, root, count) =
                            merged.inclusion_proof(&k).expect("key is a member");
                        assert!(verify_causal_inclusion(&k, &path, root, count));
                    }

                    let absent = dense_keys(0x0000_BEEF_4321_FACE, 1)[0];
                    let (path, depth, root, count) =
                        merged.non_inclusion_proof(&absent).expect("key absent");
                    assert!(verify_causal_non_inclusion(
                        &absent, depth, &path, root, count
                    ));
                })
                .unwrap();
            child.join().unwrap();
        }

        /// Differential test for `CausalSet::extend`: build a set from one
        /// half, extend with the other, and verify root/count/proofs against
        /// the oracle for the full key set.
        #[test]
        fn differential_extend_matches_oracle() {
            let child = std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    let keys = dense_keys(0x1234_5678_9ABC_DEF0, 48);
                    let (left, right) = keys.split_at(24);

                    let mut set = CausalSet::empty();
                    for &k in left {
                        set.insert_mut(k);
                    }
                    set.extend(right.iter().copied());

                    let (ref_root, ref_count) = subtree_root_or_empty(&keys, 0);
                    assert_eq!(set.root(), ref_root, "extend root diverges");
                    assert_eq!(set.count(), ref_count, "extend count diverges");

                    for &k in &keys {
                        let (path, root, count) = set.inclusion_proof(&k).expect("key is a member");
                        assert!(verify_causal_inclusion(&k, &path, root, count));
                    }

                    let absent = dense_keys(0xFEDC_BA98_7654_3210, 1)[0];
                    let (path, depth, root, count) =
                        set.non_inclusion_proof(&absent).expect("key absent");
                    assert!(verify_causal_non_inclusion(
                        &absent, depth, &path, root, count
                    ));
                })
                .unwrap();
            child.join().unwrap();
        }

        /// Regression test for a non-minimality attack on non-inclusion
        /// proofs: prepend an empty-table step and bump `terminal_depth` by 1.
        /// The prepended fold produces empty[terminal_depth-1] by
        /// construction, so the proof is length-consistent and verifies
        /// against the original root. Run BEFORE applying the minimality
        /// fix to confirm the bug exists.
        #[test]
        fn non_minimal_terminal_depth_is_rejected() {
            let (a, b) = (bit_key(7), bit_key(8));
            let absent = bit_key(47);
            let mut set = CausalSet::empty();
            set.insert_mut(a);
            set.insert_mut(b);

            let (path, t, root, count) = set.non_inclusion_proof(&absent).unwrap();
            assert!(verify_causal_non_inclusion(&absent, t, &path, root, count));

            let mut extended = alloc::vec![CausalProofStep {
                hash: empty_table()[t + 1],
                count: 0,
            }];
            extended.extend_from_slice(&path);
            // Pre-fix: this assertion FAILS — the non-minimal proof
            // passes verification. Post-fix: it must pass (reject).
            assert!(!verify_causal_non_inclusion(
                &absent,
                t + 1,
                &extended,
                root,
                count
            ));
        }
    }
}
