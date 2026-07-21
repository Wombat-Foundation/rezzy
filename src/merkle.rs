//! MSC4511 Merkleized event-metadata primitives.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

/// SHA3-256 digest size used by MSC4511.
pub const HASH_SIZE: usize = 32;

const MAX_CANONICAL_INT: i64 = (1_i64 << 53) - 1;
const MIN_CANONICAL_INT: i64 = -MAX_CANONICAL_INT;

const LEAF_DST: &[u8] = b"msc4511:leaf:v1";
const NODE_DST: &[u8] = b"msc4511:node:v1";
const ROOT_DST: &[u8] = b"msc4511:root:v1";

/// A SHA3-256 digest.
pub type Hash = [u8; HASH_SIZE];

/// Errors returned by MSC4511 Merkle and canonical JSON operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    EmptyFieldName,
    InvalidFieldName,
    DuplicateField(String),
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
            Self::NoLeaves => f.write_str("merkle: no leaves"),
            Self::IntegerRange => f.write_str("canonical json integer out of range"),
            Self::UnsupportedNumber => f.write_str("unsupported canonical json number"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MerkleError {}

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub room_id: String,
    pub sender: String,
    pub event_type: String,
    pub state_key: Option<String>,
    pub redacts: Option<String>,
    pub depth: i64,
    pub origin_server_ts: i64,
}

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
/// Returns [`MerkleError::EmptyFieldName`] if `field_name` is empty.
pub fn leaf_hash(field_name: &str, canonical_value: &[u8]) -> Result<Hash, MerkleError> {
    if field_name.is_empty() {
        return Err(MerkleError::EmptyFieldName);
    }
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

/// Computes `header_root` over `room_id`, `sender`, `type`, `state_key`,
/// `redacts`, `depth`, and `origin_server_ts`. Missing optional fields are
/// encoded as `null`.
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
        Field::new("sender", Value::from(header.sender.clone())),
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
    prev_events_hash: Hash,
    auth_events_hash: Hash,
    event_header_root: Hash,
    content_hash: Hash,
    other_signed_fields_hash: Hash,
) -> Hash {
    hash_parts(&[
        ROOT_DST,
        &prev_events_hash,
        &auth_events_hash,
        &event_header_root,
        &content_hash,
        &other_signed_fields_hash,
    ])
}

/// Derives "$" || unpadded base64url(`event_root`).
#[must_use]
pub fn event_id(event_root: Hash) -> String {
    format!("${}", URL_SAFE_NO_PAD.encode(event_root))
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
    Ok(())
}

fn validate_field_name_bytes(field_name: &[u8]) -> Result<(), MerkleError> {
    if field_name.is_empty() {
        return Err(MerkleError::EmptyFieldName);
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
                let code = ch as u32;
                out.extend_from_slice(format!("\\u{code:04x}").as_bytes());
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
