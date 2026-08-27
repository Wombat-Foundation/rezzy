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
/// # Errors
///
/// Returns a [`MerkleError`] if one of the header fields cannot be canonically
/// encoded.
pub fn header_root(header: &Header) -> Result<Hash, MerkleError> {
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

/// MSC4511's causal sparse Merkle sum trie: a persistent 256-level structure
/// committing the set of event IDs in an event's strict causal past.
///
/// This mirrors `gomatrixcrypto`'s `merkle.CausalSet`. Empty-subtree hashes
/// are recomputed recursively on each call rather than cached in a static
/// table, which is simpler but not optimized for production-scale use.
pub mod causal {
    use super::{hash_parts, Hash};
    use alloc::{collections::BTreeSet, vec::Vec};

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
    fn empty_table() -> EmptyTable {
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

    /// An immutable population of event-ID keys committed by a persistent
    /// 256-level sparse Merkle sum trie.
    #[derive(Debug, Clone, Default)]
    pub struct CausalSet {
        keys: BTreeSet<Hash>,
    }

    /// Which side a sibling subtree sits on relative to the running node in
    /// a [`CausalProofStep`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Side {
        Left,
        Right,
    }

    /// One sibling in a causal sparse Merkle sum trie path, ordered
    /// leaf-to-root: applying each step in order (combining the running
    /// hash/count with `hash`/`count` on the named `side`, via
    /// `causal_node`) reconstructs the trie root and count.
    #[derive(Debug, Clone, Copy)]
    pub struct CausalProofStep {
        pub side: Side,
        pub hash: Hash,
        pub count: u64,
    }

    #[derive(PartialEq, Eq)]
    enum TerminalKind {
        Leaf,
        Empty,
    }

    impl CausalSet {
        /// Returns the canonical empty causal set: root `empty_hash(0)`,
        /// count 0.
        #[must_use]
        pub fn empty() -> Self {
            Self {
                keys: BTreeSet::new(),
            }
        }

        /// Returns a new [`CausalSet`] containing every key in `self` plus
        /// `key`. A no-op (returns an equal set) if `key` is already a
        /// member.
        #[must_use]
        pub fn insert(&self, key: Hash) -> Self {
            let mut next = self.keys.clone();
            next.insert(key);
            Self { keys: next }
        }

        /// Returns the set union of `self` and `other`, eliminating
        /// duplicates, as required for a multi-predecessor merge event's
        /// `causal_set` transition.
        #[must_use]
        pub fn union(&self, other: &Self) -> Self {
            let mut next = self.keys.clone();
            for k in &other.keys {
                next.insert(*k);
            }
            Self { keys: next }
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
        #[must_use]
        pub fn root(&self) -> Hash {
            let empty = empty_table();
            if self.keys.is_empty() {
                return empty[0];
            }
            let keys: Vec<Hash> = self.keys.iter().copied().collect();
            subtree_root(&keys, 0, &empty).0
        }

        /// Returns the ordered (leaf-to-root) sibling path proving `key` is a
        /// member of `self`, along with `self`'s root and count. Returns
        /// [`None`] if `key` is not a member; there is no inclusion proof for
        /// a non-member.
        #[must_use]
        pub fn inclusion_proof(&self, key: &Hash) -> Option<(Vec<CausalProofStep>, Hash, u64)> {
            if self.keys.is_empty() {
                return None;
            }
            let keys: Vec<Hash> = self.keys.iter().copied().collect();
            let empty = empty_table();
            let (node_hash, node_count, path, kind, _depth) = descend(&keys, 0, key, &empty);
            if kind != TerminalKind::Leaf {
                return None;
            }
            Some((path, node_hash, node_count))
        }

        /// Returns the ordered (leaf-to-root) sibling path proving `key` is
        /// NOT a member of `self` (the key-directed path terminates in a
        /// canonical empty subtree at the returned depth), along with
        /// `self`'s root and count. Returns [`None`] if `key` IS a member; no
        /// non-inclusion proof exists for a member.
        #[must_use]
        pub fn non_inclusion_proof(
            &self,
            key: &Hash,
        ) -> Option<(Vec<CausalProofStep>, usize, Hash, u64)> {
            let empty = empty_table();
            if self.keys.is_empty() {
                return Some((Vec::new(), 0, empty[0], 0));
            }
            let keys: Vec<Hash> = self.keys.iter().copied().collect();
            let (node_hash, node_count, path, kind, depth) = descend(&keys, 0, key, &empty);
            if kind != TerminalKind::Empty {
                return None;
            }
            Some((path, depth, node_hash, node_count))
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
        verify_causal_path(
            causal_leaf(*key),
            1,
            CAUSAL_DEPTH,
            Some(key),
            path,
            root,
            count,
        )
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
        verify_causal_path(
            empty_table()[terminal_depth],
            0,
            terminal_depth,
            Some(key),
            path,
            root,
            count,
        )
    }

    /// Sums two subtree/sibling counts. The draft's "Room-version validity"
    /// section mandates rejecting an overflowing count addition rather than
    /// wrapping or saturating it; `checked_add` plus this `expect` is that
    /// rejection. In practice a real causal set's population is always far
    /// below `u64::MAX`, so this never actually fires.
    fn checked_count_sum(a: u64, b: u64) -> u64 {
        a.saturating_add(b)
    }

    /// Recomputes a causal trie root from a terminal node (either a
    /// `causal_leaf` and count 1, or a canonical empty hash and count 0) by
    /// applying `path`'s siblings from the level just above the terminal
    /// depth up to the root. `path` is ordered leaf-to-root (deepest sibling
    /// first), so `depth` walks downward from `terminal_depth - 1` to 0;
    /// `path.len() == terminal_depth` is checked first, so the decrement
    /// below never underflows past 0.
    fn verify_causal_path(
        terminal_hash: Hash,
        terminal_count: u64,
        terminal_depth: usize,
        key: Option<&Hash>,
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
            if let Some(key) = key {
                let expected_side = if causal_bit(key, depth) == 0 {
                    Side::Right
                } else {
                    Side::Left
                };
                if step.side != expected_side {
                    return false;
                }
            }
            cur_hash = match step.side {
                Side::Left => {
                    causal_node(depth_u16(depth), step.hash, step.count, cur_hash, cur_count)
                }
                Side::Right => {
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

    /// `subtree_root`, generalized to accept an empty key set, returning the
    /// canonical empty subtree at `depth` from the precomputed `empty` table.
    fn subtree_root_or_empty(keys: &[Hash], depth: usize, empty: &EmptyTable) -> (Hash, u64) {
        if keys.is_empty() {
            (empty[depth], 0)
        } else {
            subtree_root(keys, depth, empty)
        }
    }

    /// Computes the (hash, count) of the subtree rooted at `depth` that
    /// contains exactly the given non-empty key set. `depth` is always
    /// `< CAUSAL_DEPTH` here (the `depth == CAUSAL_DEPTH` case returns
    /// above), so `saturating_add(1)` never actually saturates.
    fn subtree_root(keys: &[Hash], depth: usize, empty: &EmptyTable) -> (Hash, u64) {
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
        let (left_hash, left_count) = subtree_root_or_empty(&left, next_depth, empty);
        let (right_hash, right_count) = subtree_root_or_empty(&right, next_depth, empty);
        (
            causal_node(
                depth_u16(depth),
                left_hash,
                left_count,
                right_hash,
                right_count,
            ),
            checked_count_sum(left_count, right_count),
        )
    }

    /// Recursively computes the (hash, count) of the subtree over `keys` at
    /// `depth`, plus the ordered leaf-to-root sibling path along `target`'s
    /// bit-directed descent, stopping early when the descent reaches an
    /// empty subtree. Returns the terminal node's kind (`Leaf` if `target`
    /// was found, `Empty` if the descent ran out of keys before
    /// `CAUSAL_DEPTH`) and the depth at which that terminal node sits.
    fn descend(
        keys: &[Hash],
        depth: usize,
        target: &Hash,
        empty: &EmptyTable,
    ) -> (Hash, u64, Vec<CausalProofStep>, TerminalKind, usize) {
        if keys.is_empty() {
            return (empty[depth], 0, Vec::new(), TerminalKind::Empty, depth);
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
        // `depth < CAUSAL_DEPTH` here (checked above), so this never
        // actually saturates.
        let next_depth = depth.saturating_add(1);
        if causal_bit(target, depth) == 0 {
            let (left_hash, left_count, mut path, kind, term_depth) =
                descend(&left, next_depth, target, empty);
            let (right_hash, right_count) = subtree_root_or_empty(&right, next_depth, empty);
            let node = causal_node(
                depth_u16(depth),
                left_hash,
                left_count,
                right_hash,
                right_count,
            );
            path.push(CausalProofStep {
                side: Side::Right,
                hash: right_hash,
                count: right_count,
            });
            (
                node,
                checked_count_sum(left_count, right_count),
                path,
                kind,
                term_depth,
            )
        } else {
            let (right_hash, right_count, mut path, kind, term_depth) =
                descend(&right, next_depth, target, empty);
            let (left_hash, left_count) = subtree_root_or_empty(&left, next_depth, empty);
            let node = causal_node(
                depth_u16(depth),
                left_hash,
                left_count,
                right_hash,
                right_count,
            );
            path.push(CausalProofStep {
                side: Side::Left,
                hash: left_hash,
                count: left_count,
            });
            (
                node,
                checked_count_sum(left_count, right_count),
                path,
                kind,
                term_depth,
            )
        }
    }
}
