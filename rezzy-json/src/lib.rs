        if digits > 19
            || digits == 19 && input.get(index.saturating_sub(19)) == Some(&b'-')
        {
            return false;
        }
//!
//! Objects use `BTreeMap` so iteration is deterministic and already suitable
//! for Matrix canonical JSON. Numbers retain their source spelling; canonical
//! validation and writing decide which spellings are acceptable.
//!
//! # Numeric ranges
//!
//! [`Number`] keeps the source spelling, so integers round-trip byte-exactly
//! from [`Value::parse`] through [`write_string_value`] and
//! [`write_raw_canonical_filtered`] all the way up to `u64::MAX`. That is much
//! wider than the range that is safe to sign:
//!
//! - `|n| <= 2^53 - 1` ([`MAX_SAFE_INTEGER`]) is the canonical range.
//!   [`write_raw_canonical_filtered_strict`] accepts it, and so does `ruma`,
//!   whose bound is `js_int::Int`.
//! - `2^53 - 1 < n <= u64::MAX` still round-trips exactly, but is rejected by
//!   [`write_raw_canonical_filtered_strict`] and by `ruma`. Acceptance by the
//!   permissive writer is **not** a signing guarantee.
//! - Integers wider than `u64::MAX` also round-trip exactly. `simd-json` rejects
//!   those outright; keeping them is intentional.
//!
//! [`Number::as_f64`] is lossy from `2^53 + 1` onward, so integer identifiers
//! must be read with [`Number::as_i64`], [`Number::as_u64`], or
//! [`Number::as_str`].
//!
//! Store 64-bit external identifiers such as X/Twitter snowflake ids as JSON
//! strings: that is the only encoding which is canonical, interoperable, and
//! lossless. See `docs/json_numeric_limits.md` for the full matrix.

#![no_std]

extern crate alloc;

use alloc::{
    borrow::Cow,
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt,
    ops::{Index, IndexMut},
};

/// A JSON object, keyed in sorted order.
pub type Object = BTreeMap<String, Value>;

/// Largest integer a JSON number may carry per Matrix canonical JSON (2^53 - 1).
///
/// This bounds canonical output, not parsing: integers above it are still
/// parsed and re-emitted exactly, they just cannot be canonicalized by
/// [`write_raw_canonical_filtered_strict`] or by `ruma`. See the crate-level
/// numeric range docs.
pub const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
/// Smallest integer a JSON number may carry per Matrix canonical JSON (-(2^53 - 1)).
///
/// See [`MAX_SAFE_INTEGER`] for what this does and does not bound.
pub const MIN_SAFE_INTEGER: i64 = -((1_i64 << 53) - 1);

#[must_use]
/// Returns `true` if the value is `canonical_integer_str`.
pub fn is_canonical_integer_str(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty()
        || digits != "0" && digits.starts_with('0')
        || value == "-0"
        || value.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E'))
    {
        return false;
    }
    value.parse::<i64>().is_ok_and(|number| {
        (MIN_SAFE_INTEGER..=i64::try_from(MAX_SAFE_INTEGER).unwrap_or(i64::MAX)).contains(&number)
    }) || value
        .parse::<u64>()
        .is_ok_and(|number| number <= MAX_SAFE_INTEGER)
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
/// An owned JSON value.
pub enum Value {
    #[default]
    /// JSON `null`.
    Null,
    /// A JSON boolean.
    Bool(bool),
    /// A JSON number.
    Number(Number),
    /// A JSON string.
    String(String),
    /// A JSON array.
    Array(Vec<Self>),
    /// A JSON object.
    Object(Object),
}

impl PartialEq<&str> for Value {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Some(*other)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A JSON number, kept as its validated source spelling.
pub struct Number(String);

impl Number {
    fn parse(source: &str) -> Self {
        if source == "-0" {
            return Self("-0.0".to_string());
        }
        let is_float = source.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'));
        if !is_float {
            return Self(source.to_string());
        }
        // Keep the existing canonical rendering for representable values,
        // but retain literals that cannot safely pass through binary float.
        if let Ok(value) = source.parse::<f64>() {
            if value.is_finite() {
                let mut buffer = ryu::Buffer::new();
                return Self(normalize_exponent(buffer.format_finite(value)));
            }
        }
        Self(source.to_string())
    }

    #[must_use]
    /// Builds a number from a float, or `None` if it is not finite.
    pub fn from_f64(value: f64) -> Option<Self> {
        if !value.is_finite() {
            return None;
        }
        let mut buffer = ryu::Buffer::new();
        Some(Self(normalize_exponent(buffer.format_finite(value))))
    }

    #[must_use]
    /// Returns the value as `i64`, or `None` if it is not that type.
    pub fn as_i64(&self) -> Option<i64> {
        self.0.parse().ok()
    }

    #[must_use]
    /// Returns the value as `u64`, or `None` if it is not that type.
    pub fn as_u64(&self) -> Option<u64> {
        self.0.parse().ok()
    }

    #[must_use]
    /// Returns the value as `f64`, or `None` if it is not that type.
    ///
    /// **Lossy from [`MAX_SAFE_INTEGER`] + 1.** `f64` represents every integer
    /// through `2^53` exactly — `2^53` itself is a power of two — but rounds
    /// essentially everything above it, so `2^53 + 1` is the first value that
    /// comes back wrong. A 64-bit identifier read this way is corrupted
    /// (`175928847299117063` yields `175928847299117060`) even though the
    /// canonical spelling was preserved exactly.
    ///
    /// Note this returns `Some(rounded)`, not `None`: `None` appears only when
    /// the literal overflows `f64` entirely, as with `1e400`. It is therefore
    /// not a validity check. Use [`Self::as_i64`], [`Self::as_u64`], or
    /// [`Self::as_str`] for identifiers.
    pub fn as_f64(&self) -> Option<f64> {
        self.0.parse().ok().filter(|value: &f64| value.is_finite())
    }

    #[must_use]
    /// Returns the value as `str`, or `None` if it is not that type.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    /// Returns `true` if the value is `canonical_integer`.
    pub fn is_canonical_integer(&self) -> bool {
        is_canonical_integer_str(self.as_str())
    }
}

fn normalize_exponent(formatted: &str) -> String {
    if let Some(index) = formatted.find('e') {
        let rest = formatted.get(index.saturating_add(1)..).unwrap_or("");
        if !rest.starts_with('-') {
            let head = formatted.get(..index).unwrap_or("");
            return alloc::format!("{head}e+{rest}");
        }
    }
    formatted.to_string()
}

#[cfg(feature = "simd")]
fn simd_safe_for_input(input: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut digits = 0usize;
    let mut index = 0usize;
    while let Some(&byte) = input.get(index) {
        if byte == b'\\' && input.get(index.saturating_add(1)) == Some(&b'u') {
            return false;
        }
        if matches!(byte, b'e' | b'E') {
            let mut exponent_index = index.saturating_add(1);
            if matches!(input.get(exponent_index), Some(b'+' | b'-')) {
                exponent_index = exponent_index.saturating_add(1);
            }
            let mut exponent_digits = 0usize;
            while input
                .get(exponent_index.saturating_add(exponent_digits))
                .is_some_and(u8::is_ascii_digit)
            {
                exponent_digits = exponent_digits.saturating_add(1);
            }
            if exponent_digits >= 3 {
                return false;
            }
        }
        if matches!(byte, b'{' | b'[') {
            depth = depth.saturating_add(1);
            if depth > Tokenizer::MAX_DEPTH {
                return false;
            }
        } else if matches!(byte, b'}' | b']') {
            depth = depth.saturating_sub(1);
        }
        if byte.is_ascii_digit() {
            digits = digits.saturating_add(1);
        } else {
            digits = 0;
        }
        if digits > 19 {
            return false;
        }
        index = index.saturating_add(1);
    }
    true
}

impl From<u64> for Number {
    fn from(v: u64) -> Self {
        Self(v.to_string())
    }
}
impl From<i64> for Number {
    fn from(v: i64) -> Self {
        Self(v.to_string())
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Accessors with identical bodies on `Value` and `ValueRef`.
macro_rules! shared_json_accessors {
    () => {
        #[must_use]
        /// Returns the value as `array`, or `None` if it is not that type.
        pub const fn as_array(&self) -> Option<&Vec<Self>> {
            match self {
                Self::Array(items) => Some(items),
                _ => None,
            }
        }
        #[must_use]
        /// Returns the value as `bool`, or `None` if it is not that type.
        pub const fn as_bool(&self) -> Option<bool> {
            match self {
                Self::Bool(v) => Some(*v),
                _ => None,
            }
        }
    };
}

impl Value {
    #[must_use]
    /// Returns the member named `key` if this is an object that has one.
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(obj) => obj.get(key),
            _ => None,
        }
    }
    /// Mutable variant of [`Self::get`].
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Self> {
        match self {
            Self::Object(obj) => obj.get_mut(key),
            _ => None,
        }
    }
    #[must_use]
    /// Returns the value as `object`, or `None` if it is not that type.
    pub const fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(obj) => Some(obj),
            _ => None,
        }
    }
    /// Returns the value as `object_mut`, or `None` if it is not that type.
    pub fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Self::Object(obj) => Some(obj),
            _ => None,
        }
    }
    shared_json_accessors!();
    #[must_use]
    /// Returns the value as `str`, or `None` if it is not that type.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
    #[must_use]
    /// Returns the value as `i64`, or `None` if it is not that type.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => n.as_i64(),
            _ => None,
        }
    }
    #[must_use]
    /// Returns the value as `u64`, or `None` if it is not that type.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) => n.as_u64(),
            _ => None,
        }
    }
    #[must_use]
    /// Returns the value as `f64`, or `None` if it is not that type.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => n.as_f64(),
            _ => None,
        }
    }
    #[must_use]
    /// Returns `true` if the value is `null`.
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    #[must_use]
    /// Returns `true` if the value is `array`.
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }
    #[must_use]
    /// Returns `true` if the value is `object`.
    pub const fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
    #[must_use]
    /// Returns `true` if the value is `i64`.
    pub fn is_i64(&self) -> bool {
        self.as_i64().is_some()
    }
    #[must_use]
    /// Returns `true` if the value is `u64`.
    pub fn is_u64(&self) -> bool {
        self.as_u64().is_some()
    }
    /// Sets an object member and returns the previous value; `None` if this is not an object.
    pub fn insert(&mut self, key: String, value: Self) -> Option<Self> {
        self.as_object_mut()?.insert(key, value)
    }
    /// Parses a complete JSON document from `input`.
    ///
    /// # Errors
    /// Returns [`Error`] if `input` is not valid JSON or has trailing content.
    pub fn parse(input: &str) -> Result<Self, Error> {
        #[cfg(feature = "simd")]
        return Self::parse_bytes(input.as_bytes());

        #[cfg(not(feature = "simd"))]
        Self::parse_scalar(input.as_bytes())
    }

    fn parse_scalar(input: &[u8]) -> Result<Self, Error> {
        let mut parser = Parser {
            input,
            pos: 0,
            depth: 0,
        };
        let value = parser.value()?;
        parser.ws();
        if parser.pos != parser.input.len() {
            return Err(Error::TrailingCharacters);
        }
        Ok(value)
    }
    /// Parses a complete JSON document from UTF-8 `input` bytes.
    ///
    /// # Errors
    /// Returns [`Error`] if `input` is not valid UTF-8 or not valid JSON.
    pub fn parse_bytes(input: &[u8]) -> Result<Self, Error> {
        #[cfg(feature = "simd")]
        {
            // simd-json parses numbers into machine values and therefore loses
            // the Matrix-significant `-0` spelling. Preserve the scalar path
            // for that rare case.
            if input.windows(2).any(|window| window == b"-0") || !simd_safe_for_input(input) {
                return Self::parse_scalar(input);
            }
            let mut input = input.to_vec();
            simd_json::to_owned_value(&mut input)
                .map(Self::from_simd_value)
                .map_err(|_| Error::InvalidToken)
        }

        #[cfg(not(feature = "simd"))]
        Self::parse_scalar(input)
    }

    #[cfg(feature = "simd")]
    fn from_simd_value(value: simd_json::OwnedValue) -> Self {
        match value {
            simd_json::OwnedValue::Static(value) => match value {
                simd_json::StaticNode::Null => Self::Null,
                simd_json::StaticNode::Bool(value) => Self::Bool(value),
                simd_json::StaticNode::I64(value) => Self::Number(Number(value.to_string())),
                simd_json::StaticNode::U64(value) => Self::Number(Number(value.to_string())),
                simd_json::StaticNode::F64(value) => {
                    let mut buffer = ryu::Buffer::new();
                    Self::Number(Number(normalize_exponent(buffer.format_finite(value))))
                }
            },
            simd_json::OwnedValue::String(value) => Self::String(value),
            simd_json::OwnedValue::Array(values) => {
                Self::Array(values.into_iter().map(Self::from_simd_value).collect())
            }
            simd_json::OwnedValue::Object(values) => Self::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key, Self::from_simd_value(value)))
                    .collect(),
            ),
        }
    }
}

impl Index<&str> for Value {
    type Output = Self;
    fn index(&self, key: &str) -> &Self {
        self.get(key).unwrap_or(&NULL)
    }
}

static NULL: Value = Value::Null;

impl IndexMut<&str> for Value {
    fn index_mut(&mut self, key: &str) -> &mut Self {
        if !self.is_object() {
            *self = Self::Object(Object::new());
        }
        match self {
            Self::Object(obj) => obj.entry(key.to_string()).or_insert(Self::Null),
            _ => unreachable!(),
        }
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}
impl From<&Self> for Value {
    fn from(v: &Self) -> Self {
        v.clone()
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::String(v.to_string())
    }
}
impl From<&String> for Value {
    fn from(v: &String) -> Self {
        Self::String(v.clone())
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::Number(Number(v.to_string()))
    }
}
impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Self::Number(Number(v.to_string()))
    }
}
impl From<u128> for Value {
    fn from(v: u128) -> Self {
        Self::Number(Number(v.to_string()))
    }
}
impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Self::from(i64::from(v))
    }
}
impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Self::from(u64::from(v))
    }
}
impl From<usize> for Value {
    fn from(v: usize) -> Self {
        Self::from(v as u64)
    }
}
impl<T: Into<Self>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Self::Array(v.into_iter().map(Into::into).collect())
    }
}
impl<T: Clone + Into<Self>> From<&Vec<T>> for Value {
    fn from(v: &Vec<T>) -> Self {
        Self::Array(v.iter().cloned().map(Into::into).collect())
    }
}
impl<T: Clone + Into<Self>> From<&[T]> for Value {
    fn from(v: &[T]) -> Self {
        Self::Array(v.iter().cloned().map(Into::into).collect())
    }
}
impl From<Object> for Value {
    fn from(v: Object) -> Self {
        Self::Object(v)
    }
}
impl<T: Into<Self>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Self::Null, Into::into)
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Self {
        let mut number = Number::from_f64(v).expect("JSON numbers must be finite");
        if v == 0.0 && v.is_sign_negative() {
            number.0 = "-0.0".to_string();
        }
        Self::Number(number)
    }
}

#[macro_export]
/// Builds a [`Value`] from JSON-like literal syntax.
macro_rules! json {
    (null) => { $crate::Value::Null };
    ([ $($values:tt)* ]) => {{
        let mut values = $crate::empty_array();
        $crate::json!(@array values; $($values)*);
        $crate::Value::Array(values)
    }};
    ({ $($values:tt)* }) => {{
        let mut object = $crate::empty_object();
        $crate::json!(@object object; $($values)*);
        $crate::Value::Object(object)
    }};
    (@array $values:ident;) => {};
    (@array $values:ident; null $(, $($rest:tt)*)?) => {{
        $values.push($crate::Value::Null);
        $crate::json!(@array $values; $($($rest)*)?);
    }};
    (@array $values:ident; { $($inner:tt)* } $(, $($rest:tt)*)?) => {{
        $values.push($crate::json!({ $($inner)* }));
        $crate::json!(@array $values; $($($rest)*)?);
    }};
    (@array $values:ident; [ $($inner:tt)* ] $(, $($rest:tt)*)?) => {{
        $values.push($crate::json!([ $($inner)* ]));
        $crate::json!(@array $values; $($($rest)*)?);
    }};
    (@array $values:ident; $value:expr, $($rest:tt)*) => {{
        $values.push($crate::to_value($value));
        $crate::json!(@array $values; $($rest)*);
    }};
    (@array $values:ident; $value:expr) => { $values.push($crate::to_value($value)); };
    (@object $object:ident;) => {};
    (@object $object:ident; $key:literal : null $(, $($rest:tt)*)?) => {{
        $object.insert($crate::key($key), $crate::Value::Null);
        $crate::json!(@object $object; $($($rest)*)?);
    }};
    (@object $object:ident; $key:literal : { $($inner:tt)* } $(, $($rest:tt)*)?) => {{
        $object.insert($crate::key($key), $crate::json!({ $($inner)* }));
        $crate::json!(@object $object; $($($rest)*)?);
    }};
    (@object $object:ident; $key:literal : [ $($inner:tt)* ] $(, $($rest:tt)*)?) => {{
        $object.insert($crate::key($key), $crate::json!([ $($inner)* ]));
        $crate::json!(@object $object; $($($rest)*)?);
    }};
    (@object $object:ident; $key:literal : $value:expr, $($rest:tt)*) => {{
        $object.insert($crate::key($key), $crate::to_value($value));
        $crate::json!(@object $object; $($rest)*);
    }};
    (@object $object:ident; $key:literal : $value:expr) => {
        $object.insert($crate::key($key), $crate::to_value($value));
    };
    ($value:expr) => { $crate::to_value($value) };
}

/// Converts anything convertible into a [`Value`].
pub fn to_value(value: impl Into<Value>) -> Value {
    value.into()
}
#[must_use]
/// An empty array body.
pub const fn empty_array() -> Vec<Value> {
    Vec::new()
}
#[must_use]
/// An empty object body.
pub const fn empty_object() -> Object {
    Object::new()
}
#[must_use]
/// Owns a string for use as an object key.
pub fn key(value: &str) -> String {
    value.to_string()
}

/// Character for a single-letter JSON escape (`\n`, `\"`, ...), excluding `\u`.
const fn simple_escape(escape: u8) -> Option<char> {
    Some(match escape {
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        _ => return None,
    })
}

/// Appends the JSON escape for the ASCII byte `byte` to `out`.
///
/// Callers must only pass bytes below `0x20`, `"`, or `\`.
fn push_escape(out: &mut String, byte: u8) {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    match byte {
        b'"' => out.push_str("\\\""),
        b'\\' => out.push_str("\\\\"),
        0x08 => out.push_str("\\b"),
        0x0c => out.push_str("\\f"),
        b'\n' => out.push_str("\\n"),
        b'\r' => out.push_str("\\r"),
        b'\t' => out.push_str("\\t"),
        _ => {
            out.push_str("\\u00");
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

/// Appends `value` to `out` as a quoted, escaped JSON string.
///
/// Scans bytes rather than `char`s so the common escape-free run is copied in
/// one bulk append instead of one push per scalar.
fn write_string_into(out: &mut String, value: &str) {
    out.push('"');
    let bytes = value.as_bytes();
    let mut run = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte >= 0x20 && byte != b'"' && byte != b'\\' {
            // Multi-byte UTF-8 sequences are all >= 0x80, so `index` never lands
            // inside one and the run slice below is always a valid `str`.
            index = index.checked_add(1).expect("JSON string index overflow");
            continue;
        }
        out.push_str(&value[run..index]);
        push_escape(out, byte);
        index = index.checked_add(1).expect("JSON string index overflow");
        run = index;
    }
    out.push_str(&value[run..]);
    out.push('"');
}

/// Appends `value` to `out` as compact canonical JSON.
///
/// Object keys come out sorted because [`Object`] is a [`BTreeMap`].
fn write_value_into(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n.as_str()),
        Value::String(s) => write_string_into(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i != 0 {
                    out.push(',');
                }
                write_value_into(out, item);
            }
            out.push(']');
        }
        Value::Object(obj) => {
            out.push('{');
            for (i, (key, item)) in obj.iter().enumerate() {
                if i != 0 {
                    out.push(',');
                }
                write_string_into(out, key);
                out.push(':');
                write_value_into(out, item);
            }
            out.push('}');
        }
    }
}

/// Writes `value` as compact canonical JSON.
///
/// # Errors
/// Never returns an error; the [`fmt::Error`] return type is kept for
/// compatibility with existing callers.
#[allow(clippy::unnecessary_wraps)]
pub fn write_string_value(value: &Value) -> Result<String, fmt::Error> {
    let mut out = String::new();
    write_value_into(&mut out, value);
    Ok(out)
}

/// Writes canonical JSON while omitting object fields selected by `exclude`.
///
/// The predicate is applied to each object key during the recursive walk. This
/// is intentionally generic; callers can provide Matrix-specific exclusions
/// such as `signatures`, `unsigned`, or `hashes` without coupling this crate to
/// Matrix event semantics.
///
/// # Errors
/// Never returns an error; the [`fmt::Error`] return type is kept for
/// compatibility with existing callers.
#[allow(clippy::unnecessary_wraps)]
pub fn write_string_value_filtered<F>(value: &Value, mut exclude: F) -> Result<String, fmt::Error>
where
    F: FnMut(&str) -> bool,
{
    fn write_value<F>(out: &mut String, value: &Value, exclude: &mut F)
    where
        F: FnMut(&str) -> bool,
    {
        match value {
            Value::Object(object) => {
                out.push('{');
                let mut first = true;
                for (key, item) in object {
                    if exclude(key) {
                        continue;
                    }
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    write_string_into(out, key);
                    out.push(':');
                    write_value(out, item, exclude);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    write_value(out, item, exclude);
                }
                out.push(']');
            }
            // Leaves are written straight into `out`; routing them through
            // `write_string_value` would allocate a `String` per scalar.
            Value::Null => out.push_str("null"),
            Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Value::Number(n) => out.push_str(n.as_str()),
            Value::String(s) => write_string_into(out, s),
        }
    }

    let mut out = String::new();
    write_value(&mut out, value, &mut exclude);
    Ok(out)
}

/// Canonicalizes JSON from validated raw spans, sorting decoded keys and
/// applying last-wins duplicate semantics while omitting selected fields.
///
/// # Errors
/// Returns [`Error`] when `input` is malformed JSON.
fn write_raw_canonical_filtered_internal<F>(
    input: &[u8],
    mut exclude: F,
    strict: bool,
) -> Result<String, Error>
where
    F: FnMut(&str) -> bool,
{
    let mut output = String::with_capacity(input.len());
    emit_raw(input, &mut output, &mut exclude, strict)?;
    Ok(output)
}

fn emit_raw<F>(raw: &[u8], out: &mut String, exclude: &mut F, strict: bool) -> Result<(), Error>
where
    F: FnMut(&str) -> bool,
{
    let mut tokenizer = Tokenizer::new(raw);
    tokenizer.ws();
    match tokenizer.input.get(tokenizer.pos).copied() {
        Some(b'{') => emit_object(&mut tokenizer, raw, out, exclude, strict),
        Some(b'[') => emit_array(&mut tokenizer, raw, out, exclude, strict),
        Some(b'"') => emit_string(&mut tokenizer, raw, out),
        Some(b'n') => emit_literal(&mut tokenizer, raw, out, b"null"),
        Some(b't') => emit_literal(&mut tokenizer, raw, out, b"true"),
        Some(b'f') => emit_literal(&mut tokenizer, raw, out, b"false"),
        Some(b'-' | b'0'..=b'9') => emit_number(&mut tokenizer, raw, out, strict),
        Some(_) => Err(Error::InvalidToken),
        None => Err(Error::UnexpectedEnd),
    }
}

fn finish(tokenizer: &mut Tokenizer<'_>, raw: &[u8]) -> Result<(), Error> {
    tokenizer.ws();
    (tokenizer.pos == raw.len())
        .then_some(())
        .ok_or(Error::TrailingCharacters)
}

fn emit_object<F>(
    tokenizer: &mut Tokenizer<'_>,
    raw: &[u8],
    out: &mut String,
    exclude: &mut F,
    strict: bool,
) -> Result<(), Error>
where
    F: FnMut(&str) -> bool,
{
    let mut members = tokenizer
        .object_members()
        .map_err(|_| Error::InvalidToken)?;
    finish(tokenizer, raw)?;
    members.sort_by(|a, b| a.key.as_ref().cmp(b.key.as_ref()));
    out.push('{');
    let mut first = true;
    for index in 0..members.len() {
        let member = &members[index];
        if members
            .get(index.saturating_add(1))
            .is_some_and(|next| next.key.as_ref() == member.key.as_ref())
            || exclude(member.key.as_ref())
        {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        write_string_into(out, member.key.as_ref());
        out.push(':');
        emit_raw(member.raw_value, out, exclude, strict)?;
    }
    out.push('}');
    Ok(())
}

fn emit_array<F>(
    tokenizer: &mut Tokenizer<'_>,
    raw: &[u8],
    out: &mut String,
    exclude: &mut F,
    strict: bool,
) -> Result<(), Error>
where
    F: FnMut(&str) -> bool,
{
    tokenizer.pos = tokenizer.pos.checked_add(1).ok_or(Error::InvalidToken)?;
    tokenizer.ws();
    out.push('[');
    let mut first = true;
    while tokenizer.input.get(tokenizer.pos) != Some(&b']') {
        let start = tokenizer.pos;
        tokenizer.skip_value().map_err(|_| Error::InvalidToken)?;
        if !first {
            out.push(',');
        }
        first = false;
        emit_raw(&tokenizer.input[start..tokenizer.pos], out, exclude, strict)?;
        tokenizer.ws();
        if tokenizer.input.get(tokenizer.pos) == Some(&b',') {
            tokenizer.pos = tokenizer.pos.checked_add(1).ok_or(Error::InvalidToken)?;
            tokenizer.ws();
            if tokenizer.input.get(tokenizer.pos) == Some(&b']') {
                return Err(Error::InvalidToken);
            }
        } else {
            break;
        }
    }
    if tokenizer.input.get(tokenizer.pos) != Some(&b']') {
        return Err(Error::InvalidToken);
    }
    out.push(']');
    tokenizer.pos = tokenizer.pos.checked_add(1).ok_or(Error::InvalidToken)?;
    finish(tokenizer, raw)
}

fn emit_string(tokenizer: &mut Tokenizer<'_>, raw: &[u8], out: &mut String) -> Result<(), Error> {
    let span = tokenizer.string_raw().map_err(|_| Error::InvalidString)?;
    finish(tokenizer, raw)?;
    out.push('"');
    if span.contains(&b'\\') {
        let mut decoded = String::new();
        unescape_raw_string(span, &mut decoded).map_err(Error::from)?;
        write_string_into(out, &decoded);
    } else {
        out.push_str(core::str::from_utf8(span).map_err(|_| Error::InvalidString)?);
    }
    out.push('"');
    Ok(())
}

fn emit_literal(
    tokenizer: &mut Tokenizer<'_>,
    raw: &[u8],
    out: &mut String,
    literal: &[u8],
) -> Result<(), Error> {
    tokenizer.word(literal).map_err(|_| Error::InvalidToken)?;
    finish(tokenizer, raw)?;
    out.push_str(core::str::from_utf8(literal).expect("JSON literal is UTF-8"));
    Ok(())
}

fn emit_number(
    tokenizer: &mut Tokenizer<'_>,
    raw: &[u8],
    out: &mut String,
    strict: bool,
) -> Result<(), Error> {
    let start = tokenizer.pos;
    tokenizer.skip_number().map_err(|_| Error::InvalidNumber)?;
    let span = raw.get(start..tokenizer.pos).ok_or(Error::InvalidNumber)?;
    finish(tokenizer, raw)?;
    let text = core::str::from_utf8(span).map_err(|_| Error::InvalidNumber)?;
    if strict && !is_canonical_integer_str(text) {
        return Err(Error::InvalidNumber);
    }
    if strict {
        out.push_str(text);
    } else {
        let number = Number::parse(text);
        out.push_str(number.as_str());
    }
    Ok(())
}

/// Canonicalizes JSON from raw spans with caller-supplied field exclusion.
///
/// This is the permissive writer: any well-formed JSON number is accepted and
/// its spelling normalized (`1E1` becomes `10.0`). Use it to read and re-emit
/// content you do not sign. **A successful result here is not a guarantee the
/// value is signable** — integers above [`MAX_SAFE_INTEGER`] are accepted but
/// then rejected by [`write_raw_canonical_filtered_strict`] and by `ruma`.
/// See the crate-level numeric range docs.
///
/// # Errors
/// Returns [`Error`] when the input is malformed JSON or cannot be
/// canonicalized.
pub fn write_raw_canonical_filtered<F>(input: &[u8], exclude: F) -> Result<String, Error>
where
    F: FnMut(&str) -> bool,
{
    write_raw_canonical_filtered_internal(input, exclude, false)
}

/// Canonicalizes JSON after enforcing Matrix's strict canonical-number rules.
///
/// Strict mode accepts only integer spellings without fractions or exponents,
/// and limits values to `[-(2^53 - 1), 2^53 - 1]`, matching `ruma`'s
/// `js_int::Int` bound. Numeric spans are checked directly without constructing
/// a DOM. Anything wider parses, and round-trips exactly, but is rejected here
/// — which is what makes this the signing path. Store 64-bit identifiers as
/// JSON strings.
///
/// # Errors
/// Returns [`Error::InvalidNumber`] when a number violates those rules, or a
/// parsing error for malformed JSON.
pub fn write_raw_canonical_filtered_strict<F>(input: &[u8], exclude: F) -> Result<String, Error>
where
    F: FnMut(&str) -> bool,
{
    write_raw_canonical_filtered_internal(input, exclude, true)
}

/// Writes `value` as indented, human-readable JSON.
///
/// # Errors
/// Returns [`fmt::Error`] if writing to the output string fails.
// `depth` is a nesting counter bounded by the input's nesting depth; the
// increment cannot realistically overflow `usize`.
#[allow(clippy::arithmetic_side_effects)]
fn write_value_pretty(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Array(items) if !items.is_empty() => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i == 0 {
                    out.push('\n');
                } else {
                    out.push_str(",\n");
                }
                indent(out, depth + 1);
                write_value_pretty(out, item, depth + 1);
            }
            out.push('\n');
            indent(out, depth);
            out.push(']');
        }
        Value::Object(obj) if !obj.is_empty() => {
            out.push('{');
            for (i, (key, item)) in obj.iter().enumerate() {
                if i != 0 {
                    out.push(',');
                }
                out.push('\n');
                indent(out, depth + 1);
                write_string_into(out, key);
                out.push_str(": ");
                write_value_pretty(out, item, depth + 1);
            }
            out.push('\n');
            indent(out, depth);
            out.push('}');
        }
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::Number(n) => out.push_str(n.as_str()),
        Value::String(s) => write_string_into(out, s),
        // Empty containers are the fallthrough for the guarded arms above.
        Value::Array(_) => out.push_str("[]"),
        Value::Object(_) => out.push_str("{}"),
    }
}

/// Writes `value` as indented, human-readable JSON.
///
/// The [`fmt::Error`] in the signature is retained for API stability; writing
/// into a [`String`] cannot fail.
///
/// # Errors
/// Never returns an error; the [`fmt::Error`] return type is kept for
/// compatibility with existing callers.
#[allow(clippy::unnecessary_wraps)]
pub fn write_string_pretty(value: &Value) -> Result<String, fmt::Error> {
    let mut out = String::new();
    write_value_pretty(&mut out, value, 0);
    Ok(out)
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// Streaming JSON tokenizer for zero-allocation parsing and subtree skipping.
///
/// This tokenizer operates on raw byte slices (`&'a [u8]`) and produces tokens
/// without any heap allocation. It supports skipping entire JSON values (objects,
/// arrays, strings, numbers) efficiently, making it ideal for selective parsing
/// and high-throughput ingestion pipelines.
#[derive(Clone, Copy, Debug)]
pub struct Tokenizer<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
    /// Stack tracking whether each container in the nesting is an object (true) or array (false).
    is_object: [bool; 128],
    /// Stack tracking whether the next string in an object is a key (true) or value (false).
    expecting_key: [bool; 128],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// One lexical token of a JSON document.
pub enum Token<'a> {
    /// JSON `null`.
    Null,
    /// A JSON boolean.
    Bool(bool),
    /// A JSON number.
    Number(&'a [u8]),
    /// A JSON string.
    String(&'a [u8]),
    /// `[`.
    ArrayStart,
    /// `]`.
    ArrayEnd,
    /// `{`.
    ObjectStart,
    /// `}`.
    ObjectEnd,
    /// An object key; the raw, still-escaped bytes.
    Key(&'a [u8]),
    /// `:`.
    Colon,
    /// `,`.
    Comma,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Why the tokenizer rejected its input.
pub enum TokenizerError {
    /// Input ended inside a value.
    UnexpectedEnd,
    /// A byte that cannot start or continue a JSON token here.
    InvalidToken,
    /// A malformed number literal.
    InvalidNumber,
    /// A string with a raw control character or invalid UTF-8.
    InvalidString,
    /// A string escape that JSON does not define.
    InvalidEscape,
    /// Nesting went deeper than `MAX_DEPTH`.
    DepthLimitExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// The JSON type of a value, without its contents.
pub enum ValueType {
    /// JSON `null`.
    Null,
    /// A JSON boolean.
    Bool,
    /// A JSON number.
    Number,
    /// A JSON string.
    String,
    /// A JSON array.
    Array,
    /// A JSON object.
    Object,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// One object member located in the source bytes.
pub struct MemberSpan<'a> {
    /// The member name, unescaped.
    pub key: Cow<'a, str>,
    /// The member's value exactly as written in the input.
    pub raw_value: &'a [u8],
    /// The JSON type of `raw_value`.
    pub value_type: ValueType,
}

impl fmt::Display for TokenizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tokenizer error: {self:?}")
    }
}

impl<'a> Tokenizer<'a> {
    /// Pushes a container frame and consumes its opening bracket.
    fn open_container(&mut self, is_object: bool) -> Result<(), TokenizerError> {
        if self.depth >= Self::MAX_DEPTH {
            return Err(TokenizerError::DepthLimitExceeded);
        }
        self.is_object[self.depth] = is_object;
        self.expecting_key[self.depth] = is_object;
        self.depth = self.depth.saturating_add(1);
        self.pos = self.pos.saturating_add(1);
        Ok(())
    }

    /// Pops a container frame and consumes its closing bracket.
    fn close_container(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        self.pos = self.pos.saturating_add(1);
    }

    fn advance(&mut self) -> Result<(), TokenizerError> {
        self.pos = self
            .pos
            .checked_add(1)
            .ok_or(TokenizerError::UnexpectedEnd)?;
        Ok(())
    }

    /// Maximum container nesting accepted.
    pub const MAX_DEPTH: usize = 128;

    #[must_use]
    /// Starts tokenizing at the beginning of `input`.
    pub const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
            is_object: [false; 128],
            expecting_key: [false; 128],
        }
    }

    #[must_use]
    /// Byte offset of the next unread input.
    pub const fn position(&self) -> usize {
        self.pos
    }

    #[must_use]
    /// The input not yet consumed.
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.pos..]
    }

    /// Returns validated member spans for the object at the current position.
    /// Duplicate keys are retained in source order for last-wins resolution by
    /// canonical callers.
    ///
    /// # Errors
    /// Returns [`TokenizerError`] if the current value is not a valid object.
    pub fn object_members(&mut self) -> Result<Vec<MemberSpan<'a>>, TokenizerError> {
        self.ws();
        if self.input.get(self.pos) != Some(&b'{') {
            return Err(TokenizerError::InvalidToken);
        }
        self.advance()?;
        self.ws();
        let mut members = Vec::new();
        if self.input.get(self.pos) == Some(&b'}') {
            self.advance()?;
            return Ok(members);
        }
        loop {
            self.ws();
            let key_bytes = self.string_raw()?;
            // Borrow the key straight from `input` when it carries no escapes;
            // only an escaped key needs a decoded copy. Running a full
            // `Value` parse per key would allocate for every member.
            let key = if key_bytes.contains(&b'\\') {
                let mut decoded = String::new();
                unescape_raw_string(key_bytes, &mut decoded)
                    .map_err(|_| TokenizerError::InvalidString)?;
                Cow::Owned(decoded)
            } else {
                Cow::Borrowed(
                    core::str::from_utf8(key_bytes).map_err(|_| TokenizerError::InvalidString)?,
                )
            };
            self.ws();
            if self.input.get(self.pos) != Some(&b':') {
                return Err(TokenizerError::InvalidToken);
            }
            self.advance()?;
            self.ws();
            let value_start = self.pos;
            let value_type = match self.input.get(self.pos).copied() {
                Some(b'n') => ValueType::Null,
                Some(b't' | b'f') => ValueType::Bool,
                Some(b'-' | b'0'..=b'9') => ValueType::Number,
                Some(b'"') => ValueType::String,
                Some(b'[') => ValueType::Array,
                Some(b'{') => ValueType::Object,
                _ => return Err(TokenizerError::InvalidToken),
            };
            self.skip_value()?;
            members.push(MemberSpan {
                key,
                raw_value: &self.input[value_start..self.pos],
                value_type,
            });
            self.ws();
            match self.input.get(self.pos) {
                Some(b',') => {
                    self.advance()?;
                }
                Some(b'}') => {
                    self.advance()?;
                    break;
                }
                _ => return Err(TokenizerError::InvalidToken),
            }
        }
        Ok(members)
    }

    /// Visits object members without allocating a member container.
    ///
    /// If a key contains escape sequences, it is unescaped into `scratch_buf`.
    /// Otherwise, a direct subslice of the input is yielded without touching `scratch_buf`.
    ///
    /// # Errors
    /// Returns [`TokenizerError`] for malformed JSON or invalid escape sequences.
    pub fn for_each_object_member<F>(
        &mut self,
        scratch_buf: &mut String,
        mut callback: F,
    ) -> Result<(), TokenizerError>
    where
        F: FnMut(&str, ValueType, &'a [u8]) -> Result<(), TokenizerError>,
    {
        self.ws();
        if self.input.get(self.pos) != Some(&b'{') {
            return Err(TokenizerError::InvalidToken);
        }
        self.advance()?;
        self.ws();
        if self.input.get(self.pos) == Some(&b'}') {
            self.advance()?;
            return Ok(());
        }
        loop {
            self.ws();
            let key_bytes = self.string_raw()?;
            let key = if key_bytes.contains(&b'\\') {
                unescape_raw_string(key_bytes, scratch_buf)?;
                scratch_buf.as_str()
            } else {
                core::str::from_utf8(key_bytes).map_err(|_| TokenizerError::InvalidString)?
            };
            self.ws();
            if self.input.get(self.pos) != Some(&b':') {
                return Err(TokenizerError::InvalidToken);
            }
            self.advance()?;
            self.ws();
            let start = self.pos;
            let value_type = match self.input.get(self.pos).copied() {
                Some(b'n') => ValueType::Null,
                Some(b't' | b'f') => ValueType::Bool,
                Some(b'-' | b'0'..=b'9') => ValueType::Number,
                Some(b'"') => ValueType::String,
                Some(b'[') => ValueType::Array,
                Some(b'{') => ValueType::Object,
                _ => return Err(TokenizerError::InvalidToken),
            };
            self.skip_value()?;
            callback(key, value_type, &self.input[start..self.pos])?;
            self.ws();
            match self.input.get(self.pos) {
                Some(b',') => {
                    self.advance()?;
                }
                Some(b'}') => {
                    self.advance()?;
                    return Ok(());
                }
                _ => return Err(TokenizerError::InvalidToken),
            }
        }
    }

    fn ws(&mut self) {
        while self
            .input
            .get(self.pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.pos = self.pos.saturating_add(1);
        }
    }

    /// Returns the next token, or `None` if at end of input.
    ///
    /// # Errors
    /// Returns [`TokenizerError`] on invalid JSON.
    pub fn next_token(&mut self) -> Result<Option<Token<'a>>, TokenizerError> {
        self.ws();
        if self.pos >= self.input.len() {
            return Ok(None);
        }
        match self
            .input
            .get(self.pos)
            .copied()
            .ok_or(TokenizerError::UnexpectedEnd)?
        {
            b'n' => {
                self.word(b"null")?;
                Ok(Some(Token::Null))
            }
            b't' => {
                self.word(b"true")?;
                Ok(Some(Token::Bool(true)))
            }
            b'f' => {
                self.word(b"false")?;
                Ok(Some(Token::Bool(false)))
            }
            b'"' => {
                let s = self.string()?;
                if self.depth > 0
                    && self.is_object[self.depth.saturating_sub(1)]
                    && self.expecting_key[self.depth.saturating_sub(1)]
                {
                    self.expecting_key[self.depth.saturating_sub(1)] = false;
                    Ok(Some(Token::Key(s)))
                } else {
                    Ok(Some(Token::String(s)))
                }
            }
            b'[' => {
                self.open_container(false)?;
                Ok(Some(Token::ArrayStart))
            }
            b']' => {
                if self.depth == 0 {
                    return Err(TokenizerError::InvalidToken);
                }
                self.close_container();
                Ok(Some(Token::ArrayEnd))
            }
            b'{' => {
                self.open_container(true)?;
                Ok(Some(Token::ObjectStart))
            }
            b'}' => {
                if self.depth == 0 {
                    return Err(TokenizerError::InvalidToken);
                }
                self.close_container();
                Ok(Some(Token::ObjectEnd))
            }
            b':' => {
                self.pos = self.pos.saturating_add(1);
                Ok(Some(Token::Colon))
            }
            b',' => {
                self.pos = self.pos.saturating_add(1);
                if self.depth > 0 && self.is_object[self.depth.saturating_sub(1)] {
                    self.expecting_key[self.depth.saturating_sub(1)] = true;
                }
                Ok(Some(Token::Comma))
            }
            b'-' | b'0'..=b'9' => Ok(Some(Token::Number(self.number()?))),
            _ => Err(TokenizerError::InvalidToken),
        }
    }

    /// Skips the entire JSON value at the current position without allocation.
    ///
    /// This advances `pos` past the complete value (object, array, string, number,
    /// null, true, false) and returns the byte slice of the skipped value.
    /// Use this for high-speed subtree skipping in selective parsing.
    ///
    /// # Errors
    /// Returns [`TokenizerError`] on invalid JSON.
    pub fn skip_value(&mut self) -> Result<&'a [u8], TokenizerError> {
        self.ws();
        let start = self.pos;
        match self
            .input
            .get(self.pos)
            .copied()
            .ok_or(TokenizerError::UnexpectedEnd)?
        {
            b'n' => {
                self.word(b"null")?;
            }
            b't' => {
                self.word(b"true")?;
            }
            b'f' => {
                self.word(b"false")?;
            }
            b'"' => {
                self.string_raw()?;
            }
            b'[' => self.skip_array()?,
            b'{' => self.skip_object()?,
            b'-' | b'0'..=b'9' => self.skip_number()?,
            _ => return Err(TokenizerError::InvalidToken),
        }
        Ok(&self.input[start..self.pos])
    }

    /// Skips a JSON object and returns its raw byte slice.
    fn skip_object(&mut self) -> Result<(), TokenizerError> {
        self.open_container(true)?;
        self.ws();
        if self.input.get(self.pos) == Some(&b'}') {
            self.close_container();
            return Ok(());
        }
        loop {
            self.ws();
            if self.input.get(self.pos) != Some(&b'"') {
                return Err(TokenizerError::InvalidToken);
            }
            self.string_raw()?;
            self.ws();
            if self.input.get(self.pos) != Some(&b':') {
                return Err(TokenizerError::InvalidToken);
            }
            self.pos = self.pos.saturating_add(1);
            self.skip_value()?;
            self.ws();
            match self.input.get(self.pos) {
                Some(b',') => self.pos = self.pos.saturating_add(1),
                Some(b'}') => {
                    self.close_container();
                    break;
                }
                _ => return Err(TokenizerError::InvalidToken),
            }
        }
        Ok(())
    }

    /// Skips a JSON array and returns its raw byte slice.
    fn skip_array(&mut self) -> Result<(), TokenizerError> {
        self.open_container(false)?;
        self.ws();
        if self.input.get(self.pos) == Some(&b']') {
            self.close_container();
            return Ok(());
        }
        loop {
            self.skip_value()?;
            self.ws();
            match self.input.get(self.pos) {
                Some(b',') => self.pos = self.pos.saturating_add(1),
                Some(b']') => {
                    self.close_container();
                    break;
                }
                _ => return Err(TokenizerError::InvalidToken),
            }
        }
        Ok(())
    }

    /// Parses a string without unescaping, returning the raw content slice.
    /// Validates escape sequences per JSON spec.
    fn string_raw(&mut self) -> Result<&'a [u8], TokenizerError> {
        self.pos = self.pos.saturating_add(1); // skip opening quote
        let start = self.pos;
        loop {
            let b = *self
                .input
                .get(self.pos)
                .ok_or(TokenizerError::UnexpectedEnd)?;
            match b {
                b'"' => {
                    let slice = &self.input[start..self.pos];
                    self.pos = self.pos.saturating_add(1);
                    return Ok(slice);
                }
                b'\\' => {
                    self.pos = self.pos.saturating_add(1);
                    let esc = *self
                        .input
                        .get(self.pos)
                        .ok_or(TokenizerError::UnexpectedEnd)?;
                    // Validate escape sequence per RFC 8259
                    match esc {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                            self.pos = self.pos.saturating_add(1);
                        }
                        b'u' => {
                            self.pos = self.pos.saturating_add(1);
                            // Validate 4 hex digits
                            for _ in 0..4 {
                                let hex_digit = *self
                                    .input
                                    .get(self.pos)
                                    .ok_or(TokenizerError::UnexpectedEnd)?;
                                if !hex_digit.is_ascii_hexdigit() {
                                    return Err(TokenizerError::InvalidEscape);
                                }
                                self.pos = self.pos.saturating_add(1);
                            }
                        }
                        _ => return Err(TokenizerError::InvalidEscape),
                    }
                }
                0..=0x1f => return Err(TokenizerError::InvalidString),
                _ => self.pos = self.pos.saturating_add(1),
            }
        }
    }

    /// Parses a string, returning its raw escaped content bytes.
    fn string(&mut self) -> Result<&'a [u8], TokenizerError> {
        self.string_raw()
    }

    fn skip_number(&mut self) -> Result<(), TokenizerError> {
        let start = self.pos;
        let mut saw_digit = false;

        // Optional minus sign
        if self.input.get(self.pos) == Some(&b'-') {
            self.pos = self.pos.saturating_add(1);
        }

        // JSON forbids leading zeros: `0` may only be followed by `.`, `e`/`E`, or the end.
        if self.input.get(self.pos) == Some(&b'0')
            && self
                .input
                .get(self.pos.saturating_add(1))
                .is_some_and(u8::is_ascii_digit)
        {
            return Err(TokenizerError::InvalidNumber);
        }

        // Integer part (must have at least one digit)
        while let Some(b) = self.input.get(self.pos) {
            if b.is_ascii_digit() {
                saw_digit = true;
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
        if !saw_digit {
            return Err(TokenizerError::InvalidNumber);
        }

        // Fractional part
        if self.input.get(self.pos) == Some(&b'.') {
            self.pos = self.pos.saturating_add(1);
            let mut frac_digits = false;
            while let Some(b) = self.input.get(self.pos) {
                if b.is_ascii_digit() {
                    frac_digits = true;
                    self.pos = self.pos.saturating_add(1);
                } else {
                    break;
                }
            }
            if !frac_digits {
                return Err(TokenizerError::InvalidNumber);
            }
        }

        // Exponent part
        if let Some(b) = self.input.get(self.pos) {
            if matches!(b, b'e' | b'E') {
                self.pos = self.pos.saturating_add(1);
                // Optional sign
                if matches!(self.input.get(self.pos), Some(b'+' | b'-')) {
                    self.pos = self.pos.saturating_add(1);
                }
                let mut exp_digits = false;
                while let Some(b) = self.input.get(self.pos) {
                    if b.is_ascii_digit() {
                        exp_digits = true;
                        self.pos = self.pos.saturating_add(1);
                    } else {
                        break;
                    }
                }
                if !exp_digits {
                    return Err(TokenizerError::InvalidNumber);
                }
            }
        }

        // Ensure we consumed something that looks like a number
        if self.pos == start {
            return Err(TokenizerError::InvalidNumber);
        }
        Ok(())
    }

    fn number(&mut self) -> Result<&'a [u8], TokenizerError> {
        let start = self.pos;
        self.skip_number()?;
        Ok(&self.input[start..self.pos])
    }

    fn word(&mut self, expected: &[u8]) -> Result<(), TokenizerError> {
        let Some(end) = self.pos.checked_add(expected.len()) else {
            return Err(TokenizerError::UnexpectedEnd);
        };
        if self.input.get(self.pos..end) == Some(expected) {
            self.pos = end;
            Ok(())
        } else {
            Err(TokenizerError::InvalidToken)
        }
    }
}

fn hex4(input: &[u8], pos: &mut usize) -> Result<u16, TokenizerError> {
    let mut n = 0u16;
    for _ in 0..4 {
        let b = *input.get(*pos).ok_or(TokenizerError::UnexpectedEnd)?;
        *pos = pos.checked_add(1).ok_or(TokenizerError::UnexpectedEnd)?;
        let digit = (b as char)
            .to_digit(16)
            .ok_or(TokenizerError::InvalidEscape)?;
        let digit = u8::try_from(digit).map_err(|_| TokenizerError::InvalidEscape)?;
        n = (n << 4) | u16::from(digit);
    }
    Ok(n)
}

fn decode_unicode_escape(input: &[u8], pos: &mut usize) -> Result<char, TokenizerError> {
    let high = hex4(input, pos)?;
    let scalar = if (0xd800..=0xdbff).contains(&high) {
        if input.get(*pos..pos.saturating_add(2)) != Some(b"\\u") {
            return Err(TokenizerError::InvalidEscape);
        }
        *pos = pos.checked_add(2).ok_or(TokenizerError::UnexpectedEnd)?;
        let low = hex4(input, pos)?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return Err(TokenizerError::InvalidEscape);
        }
        0x10000_u32
            .saturating_add((u32::from(high).saturating_sub(0xd800)) << 10)
            .saturating_add(u32::from(low).saturating_sub(0xdc00))
    } else {
        u32::from(high)
    };
    char::from_u32(scalar).ok_or(TokenizerError::InvalidEscape)
}

/// Decodes JSON escape sequences from `input` into `out`.
///
/// # Errors
/// Returns [`TokenizerError`] on malformed UTF-8 or invalid escape sequences.
pub fn unescape_raw_string(input: &[u8], out: &mut String) -> Result<(), TokenizerError> {
    out.clear();
    let mut pos = 0;
    let mut start = 0;
    while pos < input.len() {
        if input[pos] == b'\\' {
            let seg = core::str::from_utf8(&input[start..pos])
                .map_err(|_| TokenizerError::InvalidString)?;
            out.push_str(seg);
            pos = pos.checked_add(1).ok_or(TokenizerError::UnexpectedEnd)?;
            let esc = *input.get(pos).ok_or(TokenizerError::UnexpectedEnd)?;
            pos = pos.checked_add(1).ok_or(TokenizerError::UnexpectedEnd)?;
            match esc {
                b'u' => {
                    let c = decode_unicode_escape(input, &mut pos)?;
                    out.push(c);
                }
                _ => out.push(simple_escape(esc).ok_or(TokenizerError::InvalidEscape)?),
            }
            start = pos;
        } else {
            pos = pos.checked_add(1).ok_or(TokenizerError::UnexpectedEnd)?;
        }
    }
    if start < input.len() {
        let seg =
            core::str::from_utf8(&input[start..pos]).map_err(|_| TokenizerError::InvalidString)?;
        out.push_str(seg);
    }
    Ok(())
}

/// A field mask for selective parsing - specifies which JSON paths to extract.
#[derive(Clone, Debug, Default)]
pub struct FieldMask<'a> {
    /// Dot-separated paths to keep; an empty list selects everything.
    pub paths: &'a [&'a str],
}

impl FieldMask<'_> {
    #[must_use]
    /// Whether `prefix` is, or lies on the way to, a selected path.
    pub fn allows_prefix(&self, prefix: &str) -> bool {
        if self.paths.is_empty() {
            return true;
        }
        self.paths.iter().any(|p| {
            *p == prefix
                || p.strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('.'))
                || prefix
                    .strip_prefix(p)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
    }

    #[must_use]
    /// Whether the path made of `segments` is selected.
    pub fn matches_segments(&self, segments: &[&str]) -> bool {
        self.matches_path(segments)
    }

    fn matches_path<S: AsRef<str>>(&self, segments: &[S]) -> bool {
        if self.paths.is_empty() || segments.is_empty() {
            return true;
        }
        self.paths.iter().any(|path| {
            segments
                .iter()
                .zip(path.split('.'))
                .all(|(segment, part)| segment.as_ref() == part)
        })
    }
}

/// Decodes a raw (still escaped) object key; borrows when it has no escapes.
fn decode_key(raw: &str) -> Result<Cow<'_, str>, TokenizerError> {
    if !raw.contains('\\') {
        return Ok(Cow::Borrowed(raw));
    }
    match Value::parse_bytes(alloc::format!("\"{raw}\"").as_bytes()) {
        Ok(Value::String(decoded)) => Ok(Cow::Owned(decoded)),
        _ => Err(TokenizerError::InvalidString),
    }
}

/// Whether the raw object key `raw` decodes to `key`.
fn raw_key_eq(raw: &str, key: &str) -> bool {
    decode_key(raw).is_ok_and(|decoded| decoded == key)
}

/// Zero-copy borrowed JSON value for selective parsing.
///
/// Unlike `Value` which owns all data, `ValueRef` borrows from the original
/// input slice. Unselected fields are skipped entirely without allocation.
#[derive(Clone, Debug, PartialEq)]
pub enum ValueRef<'a> {
    /// JSON `null`.
    Null,
    /// A JSON boolean.
    Bool(bool),
    /// A JSON number.
    Number(&'a str),
    /// A JSON string.
    String(&'a str),
    /// A JSON array.
    Array(Vec<Self>),
    /// A JSON object.
    Object(Vec<(&'a str, Self)>),
}

impl<'a> ValueRef<'a> {
    /// Parses only keys matching the mask, skipping over unselected subtrees
    /// without allocations.
    ///
    /// # Errors
    /// Returns [`TokenizerError`] if the input is not valid JSON or the mask
    /// paths are invalid.
    pub fn parse_masked(input: &'a [u8], mask: &FieldMask<'_>) -> Result<Self, TokenizerError> {
        let mut tokenizer = Tokenizer::new(input);
        let mut segments: Vec<Cow<'a, str>> = Vec::new();
        let value = Self::parse_masked_value(&mut tokenizer, mask, &mut segments)?;
        tokenizer.ws();
        if tokenizer.position() != tokenizer.input.len() {
            return Err(TokenizerError::InvalidToken);
        }
        Ok(value)
    }

    fn parse_masked_value(
        tokenizer: &mut Tokenizer<'a>,
        mask: &FieldMask<'_>,
        segments: &mut Vec<Cow<'a, str>>,
    ) -> Result<Self, TokenizerError> {
        tokenizer.ws();
        match tokenizer
            .input
            .get(tokenizer.pos)
            .copied()
            .ok_or(TokenizerError::UnexpectedEnd)?
        {
            b'n' => {
                tokenizer.word(b"null")?;
                Ok(Self::Null)
            }
            b't' => {
                tokenizer.word(b"true")?;
                Ok(Self::Bool(true))
            }
            b'f' => {
                tokenizer.word(b"false")?;
                Ok(Self::Bool(false))
            }
            b'"' => {
                let s = tokenizer.string()?;
                let s = core::str::from_utf8(s).map_err(|_| TokenizerError::InvalidString)?;
                Ok(Self::String(s))
            }
            b'[' => Self::parse_masked_array(tokenizer, mask, segments),
            b'{' => Self::parse_masked_object(tokenizer, mask, segments),
            b'-' | b'0'..=b'9' => {
                let n = tokenizer.number()?;
                let n = core::str::from_utf8(n).map_err(|_| TokenizerError::InvalidNumber)?;
                Ok(Self::Number(n))
            }
            _ => Err(TokenizerError::InvalidToken),
        }
    }

    fn parse_masked_array(
        tokenizer: &mut Tokenizer<'a>,
        mask: &FieldMask<'_>,
        segments: &mut Vec<Cow<'a, str>>,
    ) -> Result<Self, TokenizerError> {
        if tokenizer.depth >= Tokenizer::MAX_DEPTH {
            return Err(TokenizerError::DepthLimitExceeded);
        }
        tokenizer.depth = tokenizer.depth.saturating_add(1);
        tokenizer.pos = tokenizer.pos.saturating_add(1);
        tokenizer.ws();
        let mut items = Vec::new();
        if tokenizer.input.get(tokenizer.pos) == Some(&b']') {
            tokenizer.pos = tokenizer.pos.saturating_add(1);
            tokenizer.depth = tokenizer.depth.saturating_sub(1);
            return Ok(Self::Array(items));
        }
        loop {
            items.push(Self::parse_masked_value(tokenizer, mask, segments)?);
            tokenizer.ws();
            match tokenizer.input.get(tokenizer.pos) {
                Some(b',') => tokenizer.pos = tokenizer.pos.saturating_add(1),
                Some(b']') => {
                    tokenizer.pos = tokenizer.pos.saturating_add(1);
                    tokenizer.depth = tokenizer.depth.saturating_sub(1);
                    break;
                }
                _ => return Err(TokenizerError::InvalidToken),
            }
        }
        Ok(Self::Array(items))
    }

    fn parse_masked_object(
        tokenizer: &mut Tokenizer<'a>,
        mask: &FieldMask<'_>,
        segments: &mut Vec<Cow<'a, str>>,
    ) -> Result<Self, TokenizerError> {
        if tokenizer.depth >= Tokenizer::MAX_DEPTH {
            return Err(TokenizerError::DepthLimitExceeded);
        }
        tokenizer.depth = tokenizer.depth.saturating_add(1);
        tokenizer.pos = tokenizer.pos.saturating_add(1);
        tokenizer.ws();
        let mut fields = Vec::new();
        if tokenizer.input.get(tokenizer.pos) == Some(&b'}') {
            tokenizer.pos = tokenizer.pos.saturating_add(1);
            tokenizer.depth = tokenizer.depth.saturating_sub(1);
            return Ok(Self::Object(fields));
        }
        loop {
            tokenizer.ws();
            if tokenizer.input.get(tokenizer.pos) != Some(&b'"') {
                return Err(TokenizerError::InvalidToken);
            }
            let key_bytes = tokenizer.string_raw()?;
            let key = core::str::from_utf8(key_bytes).map_err(|_| TokenizerError::InvalidString)?;

            segments.push(decode_key(key)?);
            let should_extract = mask.matches_path(segments);

            tokenizer.ws();
            if tokenizer.input.get(tokenizer.pos) != Some(&b':') {
                return Err(TokenizerError::InvalidToken);
            }
            tokenizer.pos = tokenizer.pos.saturating_add(1);

            if should_extract {
                let value = Self::parse_masked_value(tokenizer, mask, segments)?;
                fields.push((key, value));
            } else {
                tokenizer.skip_value()?;
            }
            let _ = segments.pop();

            tokenizer.ws();
            match tokenizer.input.get(tokenizer.pos) {
                Some(b',') => tokenizer.pos = tokenizer.pos.saturating_add(1),
                Some(b'}') => {
                    tokenizer.pos = tokenizer.pos.saturating_add(1);
                    tokenizer.depth = tokenizer.depth.saturating_sub(1);
                    break;
                }
                _ => return Err(TokenizerError::InvalidToken),
            }
        }
        Ok(Self::Object(fields))
    }
}

impl<'a> ValueRef<'a> {
    shared_json_accessors!();
    #[must_use]
    /// Returns the member named `key` if this is an object that has one.
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(obj) => obj
                .iter()
                .rev()
                .find(|(k, _)| raw_key_eq(k, key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
    #[must_use]
    /// Returns the value as `number`, or `None` if it is not that type.
    pub const fn as_number(&self) -> Option<&'a str> {
        match self {
            Self::Number(n) => Some(n),
            _ => None,
        }
    }
    #[must_use]
    /// Returns the value as `str`, or `None` if it is not that type.
    pub const fn as_str(&self) -> Option<&'a str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
    #[must_use]
    /// Returns `true` if the value is `null`.
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Why parsing a JSON document failed.
pub enum Error {
    /// Input ended inside a value.
    UnexpectedEnd,
    /// A byte that cannot start or continue a JSON token here.
    InvalidToken,
    /// A malformed number literal.
    InvalidNumber,
    /// A string with a raw control character or invalid UTF-8.
    InvalidString,
    /// A string escape that JSON does not define.
    InvalidEscape,
    /// Non-whitespace input followed the top-level value.
    TrailingCharacters,
    /// Nesting went deeper than `MAX_DEPTH`.
    DepthLimitExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON: {self:?}")
    }
}

impl From<TokenizerError> for Error {
    fn from(err: TokenizerError) -> Self {
        match err {
            TokenizerError::UnexpectedEnd => Self::UnexpectedEnd,
            TokenizerError::InvalidToken => Self::InvalidToken,
            TokenizerError::InvalidNumber => Self::InvalidNumber,
            TokenizerError::InvalidString => Self::InvalidString,
            TokenizerError::InvalidEscape => Self::InvalidEscape,
            TokenizerError::DepthLimitExceeded => Self::DepthLimitExceeded,
        }
    }
}

/// Maximum container nesting accepted.
pub const MAX_DEPTH: usize = 128;

// Parser cursor arithmetic is on `usize` offsets bounded by `input.len()`; each
// increment is preceded by a `.get()` bounds check, so the operations cannot
// overflow or wrap in practice.
struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
}

// Parser cursor arithmetic is on `usize` offsets bounded by `input.len()`; each
// increment is preceded by a `.get()` bounds check, so the operations cannot
// overflow or wrap in practice.
#[allow(clippy::arithmetic_side_effects)]
impl Parser<'_> {
    fn ws(&mut self) {
        while self
            .input
            .get(self.pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.pos += 1;
        }
    }
    fn value(&mut self) -> Result<Value, Error> {
        self.ws();
        match self
            .input
            .get(self.pos)
            .copied()
            .ok_or(Error::UnexpectedEnd)?
        {
            b'n' => {
                self.word(b"null")?;
                Ok(Value::Null)
            }
            b't' => {
                self.word(b"true")?;
                Ok(Value::Bool(true))
            }
            b'f' => {
                self.word(b"false")?;
                Ok(Value::Bool(false))
            }
            b'"' => self.string().map(Value::String),
            b'[' => {
                if self.depth >= MAX_DEPTH {
                    return Err(Error::DepthLimitExceeded);
                }
                self.depth += 1;
                let res = self.array();
                self.depth -= 1;
                res
            }
            b'{' => {
                if self.depth >= MAX_DEPTH {
                    return Err(Error::DepthLimitExceeded);
                }
                self.depth += 1;
                let res = self.object();
                self.depth -= 1;
                res
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(Error::InvalidToken),
        }
    }
    fn word(&mut self, expected: &[u8]) -> Result<(), Error> {
        if self.input.get(self.pos..self.pos + expected.len()) == Some(expected) {
            self.pos += expected.len();
            Ok(())
        } else {
            Err(Error::InvalidToken)
        }
    }
    /// Appends the unescaped run `self.input[start..self.pos]` to `out` and
    /// advances past the current byte.
    fn push_segment(&mut self, out: &mut String, start: usize) -> Result<(), Error> {
        let part =
            core::str::from_utf8(&self.input[start..self.pos]).map_err(|_| Error::InvalidString)?;
        out.push_str(part);
        self.pos += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String, Error> {
        self.pos += 1;
        let start = self.pos;
        // Escape-free strings are the overwhelmingly common case and need one
        // slice plus one copy instead of a segment-by-segment append.
        let mut scan = start;
        loop {
            match self.input.get(scan) {
                Some(b'"') => {
                    let text = core::str::from_utf8(&self.input[start..scan])
                        .map_err(|_| Error::InvalidString)?;
                    self.pos = scan + 1;
                    return Ok(String::from(text));
                }
                Some(b'\\' | 0..=0x1f) => break,
                Some(_) => scan += 1,
                None => return Err(Error::UnexpectedEnd),
            }
        }
        let mut out = String::from(
            core::str::from_utf8(&self.input[start..scan]).map_err(|_| Error::InvalidString)?,
        );
        self.pos = scan;
        let mut run = self.pos;
        loop {
            let b = *self.input.get(self.pos).ok_or(Error::UnexpectedEnd)?;
            match b {
                b'"' => {
                    self.push_segment(&mut out, run)?;
                    return Ok(out);
                }
                b'\\' => {
                    self.push_segment(&mut out, run)?;
                    let escaped = *self.input.get(self.pos).ok_or(Error::UnexpectedEnd)?;
                    self.pos += 1;
                    match escaped {
                        b'u' => out.push(self.unicode_escape()?),
                        _ => out.push(simple_escape(escaped).ok_or(Error::InvalidEscape)?),
                    }
                    run = self.pos;
                }
                0..=0x1f => return Err(Error::InvalidString),
                _ => self.pos += 1,
            }
        }
    }
    fn unicode_escape(&mut self) -> Result<char, Error> {
        let high = self.hex4()?;
        let scalar = if (0xd800..=0xdbff).contains(&high) {
            if self.input.get(self.pos..self.pos + 2) != Some(b"\\u") {
                return Err(Error::InvalidEscape);
            }
            self.pos += 2;
            let low = self.hex4()?;
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err(Error::InvalidEscape);
            }
            0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00)
        } else {
            u32::from(high)
        };
        char::from_u32(scalar).ok_or(Error::InvalidEscape)
    }
    fn hex4(&mut self) -> Result<u16, Error> {
        let mut n = 0u16;
        for _ in 0..4 {
            let b = *self.input.get(self.pos).ok_or(Error::UnexpectedEnd)?;
            self.pos += 1;
            let digit = (b as char).to_digit(16).ok_or(Error::InvalidEscape)?;
            let digit = u8::try_from(digit).map_err(|_| Error::InvalidEscape)?;
            n = (n << 4) | u16::from(digit);
        }
        Ok(n)
    }
    fn number(&mut self) -> Result<Value, Error> {
        let start = self.pos;
        while self
            .input
            .get(self.pos)
            .is_some_and(|b| matches!(b, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
        {
            self.pos += 1;
        }
        let s =
            core::str::from_utf8(&self.input[start..self.pos]).map_err(|_| Error::InvalidNumber)?;
        if !valid_number(s) {
            return Err(Error::InvalidNumber);
        }
        Ok(Value::Number(Number::parse(s)))
    }
    fn array(&mut self) -> Result<Value, Error> {
        self.pos += 1;
        self.ws();
        let mut values = Vec::new();
        if self.input.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.ws();
            match self.input.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(Error::InvalidToken),
            }
        }
        Ok(Value::Array(values))
    }
    fn object(&mut self) -> Result<Value, Error> {
        self.pos += 1;
        self.ws();
        let mut values = Object::new();
        if self.input.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Value::Object(values));
        }
        loop {
            self.ws();
            if self.input.get(self.pos) != Some(&b'"') {
                return Err(Error::InvalidToken);
            }
            let key = self.string()?;
            self.ws();
            if self.input.get(self.pos) != Some(&b':') {
                return Err(Error::InvalidToken);
            }
            self.pos += 1;
            let value = self.value()?;
            values.insert(key, value);
            self.ws();
            match self.input.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(Error::InvalidToken),
            }
        }
        Ok(Value::Object(values))
    }
}

// Index arithmetic is bounded by `s.len()` via the surrounding `.get()` checks.
#[allow(clippy::arithmetic_side_effects)]
fn valid_number(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            i += 1;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return false,
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    i == b.len()
}

#[cfg(test)]
mod tests {
    use super::{
        write_raw_canonical_filtered, write_raw_canonical_filtered_strict, write_string_pretty,
        write_string_value, write_string_value_filtered, Error, Value,
    };
    use crate::{FieldMask, ValueRef};
    use alloc::{
        format,
        string::{String, ToString},
    };

    #[test]
    fn parses_nested_values_and_sorts_object_keys() {
        let value = Value::parse(r#"{"z":[true,null],"a":{"n":-12}}"#).unwrap();
        assert_eq!(
            write_string_value(&value).unwrap(),
            r#"{"a":{"n":-12},"z":[true,null]}"#
        );
    }

    #[test]
    fn decodes_unicode_escapes_and_surrogate_pairs() {
        let value = Value::parse(r#"["\u0061","\ud83d\ude00"]"#).unwrap();
        assert_eq!(value.as_array().unwrap()[0].as_str(), Some("a"));
        assert_eq!(value.as_array().unwrap()[1].as_str(), Some("😀"));
    }

    #[test]
    fn duplicate_keys_use_last_value() {
        let value = Value::parse(r#"{"x":1,"x":2}"#).unwrap();
        assert_eq!(value["x"].as_u64(), Some(2));
    }

    #[test]
    fn rejects_invalid_number_forms_and_surrogates() {
        for input in ["01", "1.", "1e", "--1", r#""\ud800""#] {
            assert!(Value::parse(input).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn compact_and_pretty_writers_escape_and_indent() {
        let value = Value::parse(r#"{"a":[1,{"b":"x\n"}],"z":true}"#).unwrap();
        assert_eq!(
            write_string_value(&value).unwrap(),
            r#"{"a":[1,{"b":"x\n"}],"z":true}"#
        );
        assert_eq!(
            write_string_pretty(&value).unwrap(),
            "{\n  \"a\": [\n    1,\n    {\n      \"b\": \"x\\n\"\n    }\n  ],\n  \"z\": true\n}"
        );
    }

    #[test]
    fn filtered_writer_matches_canonical_output_after_exclusion() {
        let value =
            Value::parse(r#"{"z":1,"unsigned":{"age":3},"a":{"signatures":{},"x":"y"}}"#).unwrap();
        assert_eq!(
            write_string_value_filtered(&value, |key| matches!(key, "unsigned" | "signatures"))
                .unwrap(),
            r#"{"a":{"x":"y"},"z":1}"#
        );
        assert_eq!(
            write_string_value_filtered(&value, |_| false).unwrap(),
            write_string_value(&value).unwrap()
        );
    }

    #[test]
    fn raw_canonical_writer_sorts_deduplicates_and_normalizes() {
        let input = br#"{"z":1E1,"a":1,"a":-0,"skip":{"x":1},"\u0062":[{"z":2,"a":3}]}"#;
        assert_eq!(
            write_raw_canonical_filtered(input, |key| key == "skip").unwrap(),
            r#"{"a":-0.0,"b":[{"a":3,"z":2}],"z":10.0}"#
        );
    }

    #[test]
    fn strict_raw_writer_enforces_safe_integer_bounds_and_spelling() {
        assert_eq!(
            write_raw_canonical_filtered_strict(
                br#"{"min":-9007199254740991,"max":9007199254740991}"#,
                |_| false,
            )
            .unwrap(),
            r#"{"max":9007199254740991,"min":-9007199254740991}"#
        );
        for input in [
            br"9007199254740992".as_slice(),
            br"-9007199254740992".as_slice(),
            br"-0".as_slice(),
            br#"{"nested":[0,9007199254740992]}"#.as_slice(),
        ] {
            assert_eq!(
                write_raw_canonical_filtered_strict(input, |_| false),
                Err(Error::InvalidNumber),
                "accepted non-canonical number: {}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn rejects_deeply_nested_json() {
        let nested_array = "[".repeat(200) + &"]".repeat(200);
        assert_eq!(
            Value::parse(&nested_array),
            Err(super::Error::DepthLimitExceeded)
        );

        let nested_obj = "{\"a\":".repeat(200) + "1" + &"}".repeat(200);
        assert_eq!(
            Value::parse(&nested_obj),
            Err(super::Error::DepthLimitExceeded)
        );
    }

    /// The parser must accept every valid JSON document, including the empty
    /// object. State resolution consumes untrusted federation content, so a
    /// rejected-but-valid document is a correctness bug: callers that map a
    /// parse failure onto empty content would silently drop it.
    #[test]
    fn accepts_valid_documents() {
        let valid = [
            "null",
            "true",
            "false",
            "0",
            "-0",
            "-0.0",
            "123",
            "-42",
            "1.5",
            "1e2",
            "1E+2",
            "1e-2",
            "0.0001",
            "18446744073709551616",
            "\"string\"",
            r#""\/""#,
            r#""\u0061\u00e9\uD83D\uDE00""#,
            r#""a\tb\nc\u0000d""#,
            "[]",
            "{}",
            "[ ]",
            "{ }",
            "[1,2,3]",
            r#"{"a":1,"b":2}"#,
            r#"{"a":{"b":[true,null,1.5]}}"#,
            r#"{"x":1,"x":2}"#,
            "  {\n  \"a\" : [ 1 , 2 ]  }  ",
        ];
        for input in valid {
            assert!(
                Value::parse(input).is_ok(),
                "rejected valid JSON: {input:?}"
            );
        }
    }

    /// Counterpart corpus: malformed documents must not be accepted.
    #[test]
    fn rejects_malformed_documents() {
        let invalid = [
            "",
            " ",
            "[",
            "{",
            "[1,]",
            r#"{"a":1,}"#,
            concat!("{", "1:2}"),
            "{'a':1}",
            r#"{"a" 1}"#,
            r#"{"a":}"#,
            r#""unterminated"#,
            "01",
            "1.",
            ".5",
            "1e",
            "1e+",
            "+1",
            "--1",
            "nan",
            "Infinity",
            "tru",
            "nulll",
            r#""\ud800""#,
            r#""\x41""#,
            "\"raw\ncontrol\"",
            "1 2",
            "{} extra",
        ];
        for input in invalid {
            assert!(
                Value::parse(input).is_err(),
                "accepted invalid JSON: {input:?}"
            );
        }
    }

    #[test]
    fn tokenizer_basic_tokens() {
        use super::{Token, Tokenizer};
        let input = br#"{"a":1,"b":[true,null],"c":"hello"}"#;
        let mut t = Tokenizer::new(input);
        assert_eq!(t.next_token(), Ok(Some(Token::ObjectStart)));
        assert_eq!(t.next_token(), Ok(Some(Token::Key(b"a"))));
        assert_eq!(t.next_token(), Ok(Some(Token::Colon)));
        assert_eq!(t.next_token(), Ok(Some(Token::Number(b"1"))));
        assert_eq!(t.next_token(), Ok(Some(Token::Comma)));
        assert_eq!(t.next_token(), Ok(Some(Token::Key(b"b"))));
        assert_eq!(t.next_token(), Ok(Some(Token::Colon)));
        assert_eq!(t.next_token(), Ok(Some(Token::ArrayStart)));
        assert_eq!(t.next_token(), Ok(Some(Token::Bool(true))));
        assert_eq!(t.next_token(), Ok(Some(Token::Comma)));
        assert_eq!(t.next_token(), Ok(Some(Token::Null)));
        assert_eq!(t.next_token(), Ok(Some(Token::ArrayEnd)));
        assert_eq!(t.next_token(), Ok(Some(Token::Comma)));
        assert_eq!(t.next_token(), Ok(Some(Token::Key(b"c"))));
        assert_eq!(t.next_token(), Ok(Some(Token::Colon)));
        assert_eq!(t.next_token(), Ok(Some(Token::String(b"hello"))));
        assert_eq!(t.next_token(), Ok(Some(Token::ObjectEnd)));
        assert_eq!(t.next_token(), Ok(None));
    }

    #[test]
    fn tokenizer_skip_value_object() {
        use super::Tokenizer;
        let input = br#"{"skip":"this entire object","keep":42}"#;
        let mut t = Tokenizer::new(input);
        t.next_token().unwrap(); // ObjectStart
        t.next_token().unwrap(); // Key "skip"
        t.next_token().unwrap(); // Colon
        let skipped = t.skip_value().unwrap();
        assert_eq!(skipped, br#""this entire object""#);
        t.next_token().unwrap(); // Comma
        t.next_token().unwrap(); // Key "keep"
        t.next_token().unwrap(); // Colon
        let kept = t.skip_value().unwrap();
        assert_eq!(kept, b"42");
    }

    #[test]
    fn tokenizer_skip_value_array() {
        use super::Tokenizer;
        let input = br#"[1,2,{"nested":true},3]"#;
        let mut t = Tokenizer::new(input);
        t.next_token().unwrap(); // ArrayStart
        t.skip_value().unwrap(); // skip 1
        t.next_token().unwrap(); // Comma
        t.skip_value().unwrap(); // skip 2
        t.next_token().unwrap(); // Comma
        let skipped = t.skip_value().unwrap(); // skip entire object
        assert_eq!(skipped, br#"{"nested":true}"#);
        t.next_token().unwrap(); // Comma
        let kept = t.skip_value().unwrap(); // keep 3
        assert_eq!(kept, b"3");
    }

    #[test]
    fn parse_masked_matches_escaped_keys_with_last_wins() {
        use super::{FieldMask, ValueRef};
        let mask = FieldMask {
            paths: &["event_id", "content.body"],
        };
        let input =
            br#"{"event_id":"first","event\u005fid":"second","content":{"bo\u0064y":"hi"}}"#;
        let result = ValueRef::parse_masked(input, &mask).unwrap();
        assert_eq!(
            result.get("event_id").and_then(ValueRef::as_str),
            Some("second")
        );
        assert_eq!(
            result
                .get("content")
                .and_then(|content| content.get("body"))
                .and_then(ValueRef::as_str),
            Some("hi")
        );
    }

    #[test]
    fn parse_masked_extracts_selected_fields() {
        use super::{FieldMask, ValueRef};
        let input = br#"{"room_id":"!abc:domain","event_id":"$xyz:domain","content":{"msgtype":"m.text","body":"hello","huge_field":[1,2,3,4,5]},"unsigned":{"age":1000}}"#;
        let mask = FieldMask {
            paths: &["room_id", "event_id", "content.msgtype"],
        };
        let result = ValueRef::parse_masked(input, &mask).unwrap();

        assert_eq!(
            result.get("room_id").and_then(super::ValueRef::as_str),
            Some("!abc:domain")
        );
        assert_eq!(
            result.get("event_id").and_then(super::ValueRef::as_str),
            Some("$xyz:domain")
        );

        let content = result.get("content").unwrap();
        assert_eq!(
            content.get("msgtype").and_then(super::ValueRef::as_str),
            Some("m.text")
        );
        assert!(content.get("body").is_none());
        assert!(content.get("huge_field").is_none());

        assert!(result.get("unsigned").is_none());
    }

    #[test]
    fn parse_masked_nested_prefix() {
        use super::{FieldMask, ValueRef};
        let input = br#"{"a":{"b":{"c":1,"d":2},"e":3},"f":4}"#;
        let mask = FieldMask { paths: &["a.b"] };
        let result = ValueRef::parse_masked(input, &mask).unwrap();

        let a = result.get("a").unwrap();
        let b = a.get("b").unwrap();
        assert!(b.get("c").is_some());
        assert!(b.get("d").is_some());
        assert!(a.get("e").is_none());
        assert!(result.get("f").is_none());
    }

    #[test]
    fn parse_masked_array() {
        use super::{FieldMask, ValueRef};
        let input = br#"[{"id":1,"data":"large"},{"id":2,"data":"also large"}]"#;
        let mask = FieldMask { paths: &["id"] };
        let result = ValueRef::parse_masked(input, &mask).unwrap();

        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0].get("id").and_then(super::ValueRef::as_number),
            Some("1")
        );
        assert_eq!(
            arr[1].get("id").and_then(super::ValueRef::as_number),
            Some("2")
        );
        assert!(arr[0].get("data").is_none());
    }

    #[test]
    fn tokenizer_depth_limit() {
        use super::{Tokenizer, TokenizerError};
        let nested = "[".repeat(200) + &"]".repeat(200);
        let mut t = Tokenizer::new(nested.as_bytes());
        let mut hit_depth_limit = false;
        for _ in 0..150 {
            if t.next_token() == Err(TokenizerError::DepthLimitExceeded) {
                hit_depth_limit = true;
                break;
            }
        }
        assert!(hit_depth_limit);
    }

    #[test]
    fn masked_parse_rejects_leading_zero_numbers() {
        let mask = FieldMask::default();
        for bad in ["01", "-01", "[00]", "{\"a\":01}"] {
            assert!(
                ValueRef::parse_masked(bad.as_bytes(), &mask).is_err(),
                "{bad}"
            );
        }
        for good in ["0", "-0", "0.5", "0e1", "10"] {
            assert!(
                ValueRef::parse_masked(good.as_bytes(), &mask).is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn number_as_f64_is_finite_only() {
        let value = Value::parse("1e400").unwrap();
        assert_eq!(value.as_f64(), None);
    }

    /// The boundary values that separate the three numeric ranges.
    ///
    /// A golden corpus of realistic events cannot catch drift here: real
    /// payloads carry no exponent-notation floats, no identifiers past
    /// `u64::MAX`, and no lone surrogates. These cases must stay pinned.
    #[test]
    fn numeric_range_boundaries_are_pinned() {
        use crate::{
            write_raw_canonical_filtered, write_raw_canonical_filtered_strict, MAX_SAFE_INTEGER,
        };

        // Canonical range: exact everywhere, including through `f64`.
        for exact in [
            MAX_SAFE_INTEGER.to_string(),
            format!("-{MAX_SAFE_INTEGER}"),
            "0".to_string(),
            "42".to_string(),
        ] {
            let parsed = Value::parse(&exact).unwrap();
            assert_eq!(write_string_value(&parsed).unwrap(), exact, "{exact}");
            assert_eq!(
                parsed.as_f64().map(|f| f.to_string()),
                Some(exact.clone()),
                "canonical range must survive f64: {exact}"
            );
            assert_eq!(
                write_raw_canonical_filtered_strict(exact.as_bytes(), |_| false).unwrap(),
                exact
            );
        }

        // Wide but non-canonical: parses and round-trips exactly, yet is
        // rejected by the signing path and is lossy through `f64`. Acceptance by
        // the permissive writer is not a signing guarantee.
        for wide in [
            "9007199254740992",
            "175928847299117063",
            "9223372036854775807",
            "18446744073709551615",
        ] {
            let parsed = Value::parse(wide).unwrap();
            assert_eq!(write_string_value(&parsed).unwrap(), wide, "{wide}");
            assert_eq!(
                write_raw_canonical_filtered(wide.as_bytes(), |_| false).unwrap(),
                wide
            );
            assert!(
                write_raw_canonical_filtered_strict(wide.as_bytes(), |_| false).is_err(),
                "strict mode must reject {wide}"
            );
            let Value::Number(number) = &parsed else {
                panic!("expected a number");
            };
            assert_eq!(number.as_str(), wide, "source spelling must be kept");
        }

        // `f64` is exact through 2^53 inclusive -- 2^53 itself is a power of
        // two -- and lossy for essentially everything above it, including
        // 2^53 + 1. So reading an identifier through `as_f64` is unsafe from
        // the very first integer past the canonical bound.
        assert_eq!(
            Value::parse("9007199254740992")
                .unwrap()
                .as_f64()
                .map(|f| f.to_string()),
            Some("9007199254740992".to_string()),
            "2^53 is a power of two and stays exact"
        );
        for lossy in [
            "9007199254740993",
            "175928847299117063",
            "9223372036854775807",
            "18446744073709551615",
        ] {
            assert_ne!(
                Value::parse(lossy).unwrap().as_f64().map(|f| f.to_string()),
                Some(lossy.to_string()),
                "past 2^53, f64 must not be lossless: {lossy}"
            );
        }

        // `as_f64` is lossy past 2^53, so identifiers must not be read through it.
        let snowflake = Value::parse("175928847299117063").unwrap();
        assert_eq!(snowflake.as_i64(), Some(175_928_847_299_117_063));
        let Value::Number(number) = &snowflake else {
            panic!("expected a number");
        };
        assert_eq!(number.as_str(), "175928847299117063");
        assert_ne!(
            snowflake.as_f64().map(|f| f.to_string()).as_deref(),
            Some("175928847299117063")
        );

        // A 64-bit identifier survives strict canonicalization as a string.
        assert_eq!(
            write_raw_canonical_filtered_strict(br#"{"id":"175928847299117063"}"#, |_| false)
                .unwrap(),
            r#"{"id":"175928847299117063"}"#
        );
    }
}
