//! Small `alloc`-only JSON value and parser used by the no-std core.
//!
//! Objects use `BTreeMap` so iteration is deterministic and already suitable
//! for Matrix canonical JSON. Numbers retain their source spelling; canonical
//! validation and writing decide which spellings are acceptable.

#![no_std]

extern crate alloc;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt,
    ops::{Index, IndexMut},
};

pub type Object = BTreeMap<String, Value>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Object),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Number(String);

impl Number {
    fn parse(source: &str) -> Option<Self> {
        if source == "-0" {
            return Some(Self("-0.0".to_string()));
        }
        let is_float = source.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'));
        if !is_float && (source.parse::<i64>().is_ok() || source.parse::<u64>().is_ok()) {
            return Some(Self(source.to_string()));
        }
        let value = source.parse::<f64>().ok()?;
        if !value.is_finite() {
            return None;
        }
        let mut buffer = ryu::Buffer::new();
        Some(Self(normalize_exponent(buffer.format_finite(value))))
    }

    pub fn from_f64(value: f64) -> Option<Self> {
        if !value.is_finite() {
            return None;
        }
        let mut buffer = ryu::Buffer::new();
        Some(Self(normalize_exponent(buffer.format_finite(value))))
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.0.parse().ok()
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.0.parse().ok()
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.0.parse().ok()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn normalize_exponent(formatted: &str) -> String {
    if let Some(index) = formatted.find('e') {
        if !formatted[index + 1..].starts_with('-') {
            return alloc::format!("{}e+{}", &formatted[..index], &formatted[index + 1..]);
        }
    }
    formatted.to_string()
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

impl Default for Value {
    fn default() -> Self {
        Self::Null
    }
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(obj) => obj.get(key),
            _ => None,
        }
    }
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Self> {
        match self {
            Self::Object(obj) => obj.get_mut(key),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(obj) => Some(obj),
            _ => None,
        }
    }
    pub fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Self::Object(obj) => Some(obj),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Self>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => n.as_i64(),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) => n.as_u64(),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => n.as_f64(),
            _ => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
    pub fn is_i64(&self) -> bool {
        self.as_i64().is_some()
    }
    pub fn is_u64(&self) -> bool {
        self.as_u64().is_some()
    }
    pub fn insert(&mut self, key: String, value: Self) -> Option<Self> {
        self.as_object_mut()?.insert(key, value)
    }
    pub fn parse(input: &str) -> Result<Self, Error> {
        let mut parser = Parser {
            input: input.as_bytes(),
            pos: 0,
        };
        let value = parser.value()?;
        parser.ws();
        if parser.pos != parser.input.len() {
            return Err(Error::TrailingCharacters);
        }
        Ok(value)
    }
    pub fn parse_bytes(input: &[u8]) -> Result<Self, Error> {
        let text = core::str::from_utf8(input).map_err(|_| Error::InvalidString)?;
        Self::parse(text)
    }
}

impl Index<&str> for Value {
    type Output = Value;
    fn index(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&NULL)
    }
}

static NULL: Value = Value::Null;

impl IndexMut<&str> for Value {
    fn index_mut(&mut self, key: &str) -> &mut Value {
        if !self.is_object() {
            *self = Value::Object(Object::new());
        }
        match self {
            Value::Object(obj) => obj.entry(key.to_string()).or_insert(Value::Null),
            _ => unreachable!(),
        }
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}
impl From<&Value> for Value {
    fn from(v: &Value) -> Self {
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
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Self::Array(v.into_iter().map(Into::into).collect())
    }
}
impl<T: Clone + Into<Value>> From<&Vec<T>> for Value {
    fn from(v: &Vec<T>) -> Self {
        Self::Array(v.iter().cloned().map(Into::into).collect())
    }
}
impl<T: Clone + Into<Value>> From<&[T]> for Value {
    fn from(v: &[T]) -> Self {
        Self::Array(v.iter().cloned().map(Into::into).collect())
    }
}
impl From<Object> for Value {
    fn from(v: Object) -> Self {
        Self::Object(v)
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
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

pub fn to_value(value: impl Into<Value>) -> Value {
    value.into()
}
pub fn empty_array() -> Vec<Value> {
    Vec::new()
}
pub fn empty_object() -> Object {
    Object::new()
}
pub fn key(value: &str) -> String {
    value.to_string()
}

pub fn write_string_value(value: &Value) -> Result<String, fmt::Error> {
    use fmt::Write as _;
    fn write_value(out: &mut String, value: &Value) -> fmt::Result {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Value::Number(n) => out.push_str(n.as_str()),
            Value::String(s) => write_string(out, s)?,
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    write_value(out, item)?;
                }
                out.push(']');
            }
            Value::Object(obj) => {
                out.push('{');
                for (i, (key, item)) in obj.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    write_string(out, key)?;
                    out.push(':');
                    write_value(out, item)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
    fn write_string(out: &mut String, value: &str) -> fmt::Result {
        out.push('"');
        for ch in value.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c <= '\u{1f}' => write!(out, "\\u{:04x}", c as u32)?,
                c => out.push(c),
            }
        }
        out.push('"');
        Ok(())
    }
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

pub fn write_string_pretty(value: &Value) -> Result<String, fmt::Error> {
    fn write_value(out: &mut String, value: &Value, depth: usize) -> fmt::Result {
        match value {
            Value::Array(items) if !items.is_empty() => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i == 0 {
                        out.push('\n');
                    } else {
                        out.push_str(",\n");
                    }
                    indent(out, depth + 1)?;
                    write_value(out, item, depth + 1)?;
                }
                out.push('\n');
                indent(out, depth)?;
                out.push(']');
            }
            Value::Object(obj) if !obj.is_empty() => {
                out.push('{');
                for (i, (key, item)) in obj.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    out.push('\n');
                    indent(out, depth + 1)?;
                    write_quoted(out, key)?;
                    out.push_str(": ");
                    write_value(out, item, depth + 1)?;
                }
                out.push('\n');
                indent(out, depth)?;
                out.push('}');
            }
            Value::Array(_) | Value::Object(_) => out.push_str(&write_string_value(value)?),
            _ => out.push_str(&write_string_value(value)?),
        }
        Ok(())
    }
    fn indent(out: &mut String, depth: usize) -> fmt::Result {
        for _ in 0..depth {
            out.push_str("  ");
        }
        Ok(())
    }
    fn write_quoted(out: &mut String, value: &str) -> fmt::Result {
        let quoted = write_string_value(&Value::String(value.to_string()))?;
        out.push_str(&quoted);
        Ok(())
    }
    let mut out = String::new();
    write_value(&mut out, value, 0)?;
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnexpectedEnd,
    InvalidToken,
    InvalidNumber,
    InvalidString,
    InvalidEscape,
    TrailingCharacters,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON: {self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::{write_string_pretty, write_string_value, Value};

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
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

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
            b'[' => self.array(),
            b'{' => self.object(),
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
    fn string(&mut self) -> Result<String, Error> {
        self.pos += 1;
        let mut out = String::new();
        let mut start = self.pos;
        loop {
            let b = *self.input.get(self.pos).ok_or(Error::UnexpectedEnd)?;
            match b {
                b'"' => {
                    let part = core::str::from_utf8(&self.input[start..self.pos])
                        .map_err(|_| Error::InvalidString)?;
                    out.push_str(part);
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    let part = core::str::from_utf8(&self.input[start..self.pos])
                        .map_err(|_| Error::InvalidString)?;
                    out.push_str(part);
                    self.pos += 1;
                    let escaped = *self.input.get(self.pos).ok_or(Error::UnexpectedEnd)?;
                    self.pos += 1;
                    match escaped {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(Error::InvalidEscape),
                    }
                    start = self.pos;
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
            n = (n << 4) | u16::from((b as char).to_digit(16).ok_or(Error::InvalidEscape)? as u8);
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
        Ok(Value::Number(Number::parse(s).ok_or(Error::InvalidNumber)?))
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
