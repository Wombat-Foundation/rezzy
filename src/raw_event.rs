// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Raw event spans and selective field extraction primitives for high-throughput
//! JSON ingestion and Matrix DAG processing without full DOM allocation.

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use rezzy_json::{FieldMask, Token, Tokenizer, TokenizerError, Value as JsonValue, ValueType};

/// Byte slice range representing a raw event in an input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawEventSpan {
    pub start: usize,
    pub end: usize,
}

/// Field mask selecting only the fields required for adjacency, typing, and DAG traversal.
pub const ADJACENCY_MASK: FieldMask<'static> = FieldMask {
    paths: &[
        "room_id",
        "event_id",
        "prev_events",
        "auth_events",
        "type",
        "state_key",
        "content",
        "content.room_version",
        "content.m.relates_to",
        "content.m.relates_to.rel_type",
        "content.m.relates_to.event_id",
    ],
};

/// Reusable caller-supplied scratch buffers to eliminate per-event heap allocations.
#[derive(Clone, Debug, Default)]
pub struct MatrixEventScratch<'a> {
    pub prev_events: Vec<&'a str>,
    pub auth_events: Vec<&'a str>,
    pub key_buffer: String,
    pub event_id_buf: String,
    pub room_id_buf: String,
    pub event_type_buf: String,
    pub state_key_buf: String,
    pub room_version_buf: String,
    pub rel_type_buf: String,
    pub rel_event_id_buf: String,
}

impl MatrixEventScratch<'_> {
    /// Creates an empty scratch buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a scratch buffer with pre-allocated capacities.
    #[must_use]
    pub fn with_capacity(prev_cap: usize, auth_cap: usize, key_cap: usize) -> Self {
        Self {
            prev_events: Vec::with_capacity(prev_cap),
            auth_events: Vec::with_capacity(auth_cap),
            key_buffer: String::with_capacity(key_cap),
            event_id_buf: String::with_capacity(key_cap),
            room_id_buf: String::with_capacity(key_cap),
            event_type_buf: String::with_capacity(key_cap),
            state_key_buf: String::with_capacity(key_cap),
            room_version_buf: String::with_capacity(key_cap),
            rel_type_buf: String::with_capacity(key_cap),
            rel_event_id_buf: String::with_capacity(key_cap),
        }
    }

    /// Clears the buffers while retaining allocated capacity.
    pub fn clear(&mut self) {
        self.prev_events.clear();
        self.auth_events.clear();
        self.key_buffer.clear();
        self.event_id_buf.clear();
        self.room_id_buf.clear();
        self.event_type_buf.clear();
        self.state_key_buf.clear();
        self.room_version_buf.clear();
        self.rel_type_buf.clear();
        self.rel_event_id_buf.clear();
    }
}

/// A zero-allocation borrowed view of structural Matrix event fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatrixEventView<'buf, 'a> {
    pub event_id: Option<&'buf str>,
    pub room_id: Option<&'buf str>,
    pub event_type: Option<&'buf str>,
    pub state_key: Option<&'buf str>,
    pub prev_events: &'buf [&'a str],
    pub auth_events: &'buf [&'a str],
    pub room_version: Option<&'buf str>,
    pub relates_to: Option<(&'buf str, &'buf str)>,
    pub(crate) _marker: core::marker::PhantomData<&'a ()>,
}

type RelationView<'a> = Option<(&'a str, &'a str)>;
type ContentRelationResult<'a> = (Option<&'a str>, RelationView<'a>);

impl MatrixEventView<'_, '_> {
    /// Converts this borrowed view into owned [`MatrixEventFields`].
    #[must_use]
    pub fn to_owned(&self) -> MatrixEventFields {
        MatrixEventFields {
            event_id: self.event_id.map(ToOwned::to_owned),
            room_id: self.room_id.map(ToOwned::to_owned),
            event_type: self.event_type.map(ToOwned::to_owned),
            state_key: self.state_key.map(ToOwned::to_owned),
            prev_events: self
                .prev_events
                .iter()
                .copied()
                .map(ToOwned::to_owned)
                .collect(),
            auth_events: self
                .auth_events
                .iter()
                .copied()
                .map(ToOwned::to_owned)
                .collect(),
            room_version: self.room_version.map(ToOwned::to_owned),
            relates_to: self
                .relates_to
                .map(|(rel, id)| (rel.to_owned(), id.to_owned())),
        }
    }
}

/// Key structural fields extracted from a raw Matrix event via selective parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixEventFields {
    pub event_id: Option<String>,
    pub room_id: Option<String>,
    pub event_type: Option<String>,
    pub state_key: Option<String>,
    pub prev_events: Vec<String>,
    pub auth_events: Vec<String>,
    pub room_version: Option<String>,
    pub relates_to: Option<(String, String)>,
}

/// Borrowed structural fields extracted from a raw Matrix event.
///
/// Note: Scalar string fields borrow directly from the input buffer without allocation.
/// `prev_events` and `auth_events` allocate vectors of borrowed `&str` references per event.
/// For strictly zero-allocation extraction into reusable caller buffers, use [`extract_matrix_event_into`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixEventFieldsRef<'a> {
    pub event_id: Option<&'a str>,
    pub room_id: Option<&'a str>,
    pub event_type: Option<&'a str>,
    pub state_key: Option<&'a str>,
    pub prev_events: Vec<&'a str>,
    pub auth_events: Vec<&'a str>,
    pub room_version: Option<&'a str>,
    pub relates_to: Option<(&'a str, &'a str)>,
}

impl MatrixEventFieldsRef<'_> {
    /// Converts this borrowed structure into owned [`MatrixEventFields`].
    #[must_use]
    pub fn to_owned(&self) -> MatrixEventFields {
        MatrixEventFields {
            event_id: self.event_id.map(ToOwned::to_owned),
            room_id: self.room_id.map(ToOwned::to_owned),
            event_type: self.event_type.map(ToOwned::to_owned),
            state_key: self.state_key.map(ToOwned::to_owned),
            prev_events: self
                .prev_events
                .iter()
                .copied()
                .map(ToOwned::to_owned)
                .collect(),
            auth_events: self
                .auth_events
                .iter()
                .copied()
                .map(ToOwned::to_owned)
                .collect(),
            room_version: self.room_version.map(ToOwned::to_owned),
            relates_to: self
                .relates_to
                .map(|(rel, id)| (rel.to_owned(), id.to_owned())),
        }
    }
}

/// Spans of `pdus` and `auth_chain` arrays discovered within a federation transaction payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FederationSpans {
    pub pdus: Vec<RawEventSpan>,
    pub auth_chain: Vec<RawEventSpan>,
}

/// Spans of `events` and extracted `heads` discovered within an envelope object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvelopeSpans {
    pub events: Vec<RawEventSpan>,
    pub heads: Vec<String>,
}

/// Computes byte spans for non-empty lines in a JSONL buffer.
#[must_use]
pub fn discover_jsonl_spans(input: &[u8]) -> Vec<RawEventSpan> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (index, byte) in input.iter().copied().enumerate() {
        if byte == b'\n' {
            if input[start..index].iter().any(|b| !b.is_ascii_whitespace()) {
                spans.push(RawEventSpan { start, end: index });
            }
            start = index.saturating_add(1);
        }
    }
    if start < input.len() && input[start..].iter().any(|b| !b.is_ascii_whitespace()) {
        spans.push(RawEventSpan {
            start,
            end: input.len(),
        });
    }
    spans
}

/// Discovers element spans inside a top-level JSON array without full DOM allocation.
///
/// # Errors
/// Returns [`TokenizerError`] if the slice is not a valid JSON array.
pub fn discover_array_spans(input: &[u8]) -> Result<Vec<RawEventSpan>, TokenizerError> {
    let mut tokenizer = Tokenizer::new(input);
    if tokenizer.next_token()? != Some(Token::ArrayStart) {
        return Err(TokenizerError::InvalidToken);
    }
    let mut spans = Vec::new();
    let base_ptr = input.as_ptr() as usize;
    loop {
        let mut peek = tokenizer;
        match peek.next_token()? {
            Some(Token::ArrayEnd) => {
                let _ = tokenizer.next_token()?;
                break;
            }
            Some(_) => {}
            None => return Err(TokenizerError::UnexpectedEnd),
        }
        let raw = tokenizer.skip_value()?;
        let start = (raw.as_ptr() as usize).saturating_sub(base_ptr);
        let end = start.saturating_add(raw.len());
        spans.push(RawEventSpan { start, end });
        match tokenizer.next_token()? {
            Some(Token::Comma) => {}
            Some(Token::ArrayEnd) => break,
            _ => return Err(TokenizerError::InvalidToken),
        }
    }
    if tokenizer.next_token()?.is_some() {
        return Err(TokenizerError::InvalidToken);
    }
    Ok(spans)
}

/// Discovers `pdus` and `auth_chain` event spans from a federation transaction payload.
///
/// # Errors
/// Returns [`TokenizerError`] if the input cannot be tokenized as a JSON object.
pub fn discover_federation_spans(input: &[u8]) -> Result<FederationSpans, TokenizerError> {
    let mut tokenizer = Tokenizer::new(input);
    let mut key_buf = String::new();
    let mut result = FederationSpans::default();
    let base_ptr = input.as_ptr() as usize;
    tokenizer.for_each_object_member(&mut key_buf, |key, value_type, raw_value| {
        if key == "pdus" && value_type == ValueType::Array {
            let pdu_spans = discover_array_spans(raw_value)?;
            let offset = (raw_value.as_ptr() as usize).saturating_sub(base_ptr);
            result
                .pdus
                .extend(pdu_spans.into_iter().map(|s| RawEventSpan {
                    start: s.start.saturating_add(offset),
                    end: s.end.saturating_add(offset),
                }));
        } else if key == "auth_chain" && value_type == ValueType::Array {
            let auth_spans = discover_array_spans(raw_value)?;
            let offset = (raw_value.as_ptr() as usize).saturating_sub(base_ptr);
            result
                .auth_chain
                .extend(auth_spans.into_iter().map(|s| RawEventSpan {
                    start: s.start.saturating_add(offset),
                    end: s.end.saturating_add(offset),
                }));
        }
        Ok(())
    })?;
    Ok(result)
}

/// Discovers `events` spans and extracts `heads` from an envelope object.
///
/// # Errors
/// Returns [`TokenizerError`] if the input cannot be tokenized as a JSON object.
pub fn discover_envelope_spans(input: &[u8]) -> Result<EnvelopeSpans, TokenizerError> {
    let mut tokenizer = Tokenizer::new(input);
    let mut key_buf = String::new();
    let mut result = EnvelopeSpans::default();
    let base_ptr = input.as_ptr() as usize;
    tokenizer.for_each_object_member(&mut key_buf, |key, value_type, raw_value| {
        if key == "events" && value_type == ValueType::Array {
            let event_spans = discover_array_spans(raw_value)?;
            let offset = (raw_value.as_ptr() as usize).saturating_sub(base_ptr);
            result
                .events
                .extend(event_spans.into_iter().map(|s| RawEventSpan {
                    start: s.start.saturating_add(offset),
                    end: s.end.saturating_add(offset),
                }));
        } else if key == "heads" && value_type == ValueType::Array {
            let head_spans = discover_array_spans(raw_value)?;
            for span in head_spans {
                let raw_item = &raw_value[span.start..span.end];
                if let Ok(JsonValue::String(s)) = JsonValue::parse_bytes(raw_item) {
                    result.heads.push(s);
                }
            }
        }
        Ok(())
    })?;
    Ok(result)
}

fn fill_id_array<'a>(raw: &'a [u8], out: &mut Vec<&'a str>) -> Result<(), TokenizerError> {
    let mut tokenizer = Tokenizer::new(raw);
    if tokenizer.next_token()? != Some(Token::ArrayStart) {
        return Err(TokenizerError::InvalidToken);
    }
    loop {
        let token = match tokenizer.next_token()? {
            Some(Token::ArrayEnd) => break,
            Some(Token::Comma) => continue,
            Some(t) => t,
            None => return Err(TokenizerError::UnexpectedEnd),
        };
        match token {
            Token::String(s) => {
                if s.contains(&b'\\') {
                    return Err(TokenizerError::InvalidString);
                }
                let id_str = core::str::from_utf8(s).map_err(|_| TokenizerError::InvalidString)?;
                out.push(id_str);
            }
            Token::ArrayStart => {
                let Some(Token::String(s)) = tokenizer.next_token()? else {
                    return Err(TokenizerError::InvalidString);
                };
                if s.contains(&b'\\') {
                    return Err(TokenizerError::InvalidString);
                }
                let id_str = core::str::from_utf8(s).map_err(|_| TokenizerError::InvalidString)?;
                out.push(id_str);
                if tokenizer.next_token()? != Some(Token::Comma) {
                    return Err(TokenizerError::InvalidToken);
                }
                tokenizer.skip_value()?;
                if tokenizer.next_token()? != Some(Token::ArrayEnd) {
                    return Err(TokenizerError::InvalidToken);
                }
            }
            _ => {
                tokenizer.skip_value()?;
            }
        }
    }
    Ok(())
}

fn parse_scalar_str<'buf, 'a>(
    raw: &'a [u8],
    buf: &'buf mut String,
) -> Result<Option<&'buf str>, TokenizerError>
where
    'a: 'buf,
{
    if raw.len() >= 2 && raw.first() == Some(&b'"') && raw.last() == Some(&b'"') {
        let inner = &raw[1..raw.len().saturating_sub(1)];
        if !inner.contains(&b'\\') {
            return Ok(core::str::from_utf8(inner).ok());
        }
        buf.clear();
        rezzy_json::unescape_raw_string(inner, buf)?;
        return Ok(Some(buf.as_str()));
    }
    Ok(None)
}

fn extract_content_and_relations<'buf, 'a>(
    raw_content: &'a [u8],
    key_buffer: &mut String,
    room_version_buf: &'buf mut String,
    rel_type_buf: &'buf mut String,
    rel_event_id_buf: &'buf mut String,
) -> Result<ContentRelationResult<'buf>, TokenizerError>
where
    'a: 'buf,
{
    let mut content_tok = Tokenizer::new(raw_content);
    let mut room_version_raw = None;
    let mut relates_to_raw = None;

    content_tok.for_each_object_member(key_buffer, |key, value_type, raw_val| {
        match key {
            "room_version" if value_type == ValueType::String => {
                room_version_raw = Some(raw_val);
            }
            "m.relates_to" if value_type == ValueType::Object => {
                relates_to_raw = Some(raw_val);
            }
            _ => {}
        }
        Ok(())
    })?;

    let room_version = match room_version_raw {
        Some(r_ver) => parse_scalar_str(r_ver, room_version_buf)?,
        None => None,
    };

    let mut relates_to = None;
    if let Some(raw_rel) = relates_to_raw {
        let mut rel_tok = Tokenizer::new(raw_rel);
        let mut rel_type_raw = None;
        let mut rel_event_id_raw = None;
        rel_tok.for_each_object_member(key_buffer, |key, value_type, raw_val| {
            match key {
                "rel_type" if value_type == ValueType::String => {
                    rel_type_raw = Some(raw_val);
                }
                "event_id" if value_type == ValueType::String => {
                    rel_event_id_raw = Some(raw_val);
                }
                _ => {}
            }
            Ok(())
        })?;
        let rel_type = match rel_type_raw {
            Some(r) => parse_scalar_str(r, rel_type_buf)?,
            None => None,
        };
        let rel_event_id = match rel_event_id_raw {
            Some(r) => parse_scalar_str(r, rel_event_id_buf)?,
            None => None,
        };
        if let (Some(r), Some(id)) = (rel_type, rel_event_id) {
            relates_to = Some((r, id));
        }
    }

    Ok((room_version, relates_to))
}

/// Extracts Matrix event fields into a zero-allocation [`MatrixEventView`] using caller-supplied buffer storage.
///
/// This tokenizer-driven extraction performs zero heap allocations when reusing `scratch`.
///
/// # Errors
/// Returns [`TokenizerError`] if the span is not valid JSON.
pub fn extract_matrix_event_view<'buf, 'a>(
    raw: &'a [u8],
    scratch: &'buf mut MatrixEventScratch<'a>,
) -> Result<MatrixEventView<'buf, 'a>, TokenizerError>
where
    'a: 'buf,
{
    scratch.clear();
    let mut tokenizer = Tokenizer::new(raw);

    let mut event_id_raw = None;
    let mut room_id_raw = None;
    let mut event_type_raw = None;
    let mut state_key_raw = None;
    let mut prev_raw = None;
    let mut auth_raw = None;
    let mut content_raw = None;

    tokenizer.for_each_object_member(&mut scratch.key_buffer, |key, value_type, raw_val| {
        match key {
            "event_id" if value_type == ValueType::String => {
                event_id_raw = Some(raw_val);
            }
            "room_id" if value_type == ValueType::String => {
                room_id_raw = Some(raw_val);
            }
            "type" if value_type == ValueType::String => {
                event_type_raw = Some(raw_val);
            }
            "state_key" if value_type == ValueType::String => {
                state_key_raw = Some(raw_val);
            }
            "prev_events" if value_type == ValueType::Array => {
                prev_raw = Some(raw_val);
            }
            "auth_events" if value_type == ValueType::Array => {
                auth_raw = Some(raw_val);
            }
            "content" if value_type == ValueType::Object => {
                content_raw = Some(raw_val);
            }
            _ => {}
        }
        Ok(())
    })?;

    let event_id = match event_id_raw {
        Some(r) => parse_scalar_str(r, &mut scratch.event_id_buf)?,
        None => None,
    };
    let room_id = match room_id_raw {
        Some(r) => parse_scalar_str(r, &mut scratch.room_id_buf)?,
        None => None,
    };
    let event_type = match event_type_raw {
        Some(r) => parse_scalar_str(r, &mut scratch.event_type_buf)?,
        None => None,
    };
    let state_key = match state_key_raw {
        Some(r) => parse_scalar_str(r, &mut scratch.state_key_buf)?,
        None => None,
    };

    if let Some(raw_prev) = prev_raw {
        fill_id_array(raw_prev, &mut scratch.prev_events)?;
    }
    if let Some(raw_auth) = auth_raw {
        fill_id_array(raw_auth, &mut scratch.auth_events)?;
    }

    let (room_version, relates_to) = match content_raw {
        Some(raw_c) => extract_content_and_relations(
            raw_c,
            &mut scratch.key_buffer,
            &mut scratch.room_version_buf,
            &mut scratch.rel_type_buf,
            &mut scratch.rel_event_id_buf,
        )?,
        None => (None, None),
    };

    Ok(MatrixEventView {
        event_id,
        room_id,
        event_type,
        state_key,
        prev_events: &scratch.prev_events,
        auth_events: &scratch.auth_events,
        room_version,
        relates_to,
        _marker: core::marker::PhantomData,
    })
}

/// Extracts Matrix event fields into a caller-supplied scratch buffer without any heap allocations.
///
/// # Errors
/// Returns [`TokenizerError`] if the byte span is not valid JSON.
pub fn extract_matrix_event_into<'buf, 'a>(
    raw: &'a [u8],
    scratch: &'buf mut MatrixEventScratch<'a>,
) -> Result<MatrixEventView<'buf, 'a>, TokenizerError>
where
    'a: 'buf,
{
    extract_matrix_event_view(raw, scratch)
}

fn parse_unquoted_str_borrowed(raw: Option<&[u8]>) -> Option<&str> {
    let raw = raw?;
    if raw.len() >= 2 && raw.first() == Some(&b'"') && raw.last() == Some(&b'"') {
        let inner = &raw[1..raw.len().saturating_sub(1)];
        if !inner.contains(&b'\\') {
            return core::str::from_utf8(inner).ok();
        }
    }
    None
}

/// Extracts adjacency fields while retaining references into `raw`.
///
/// Note: Scalar string fields borrow directly from `raw` without allocation.
/// `prev_events` and `auth_events` allocate vectors of borrowed `&str` references per event.
/// For strictly zero-allocation extraction into reusable caller buffers, use [`extract_matrix_event_into`].
///
/// # Errors
/// Returns [`TokenizerError`] if the span is not valid JSON.
pub fn extract_matrix_event_fields_ref(
    raw: &[u8],
) -> Result<MatrixEventFieldsRef<'_>, TokenizerError> {
    let mut key_buf = String::new();
    let mut tokenizer = Tokenizer::new(raw);

    let mut event_id_raw = None;
    let mut room_id_raw = None;
    let mut event_type_raw = None;
    let mut state_key_raw = None;
    let mut prev_raw = None;
    let mut auth_raw = None;
    let mut content_raw = None;

    tokenizer.for_each_object_member(&mut key_buf, |key, value_type, raw_val| {
        match key {
            "event_id" if value_type == ValueType::String => {
                event_id_raw = Some(raw_val);
            }
            "room_id" if value_type == ValueType::String => {
                room_id_raw = Some(raw_val);
            }
            "type" if value_type == ValueType::String => {
                event_type_raw = Some(raw_val);
            }
            "state_key" if value_type == ValueType::String => {
                state_key_raw = Some(raw_val);
            }
            "prev_events" if value_type == ValueType::Array => {
                prev_raw = Some(raw_val);
            }
            "auth_events" if value_type == ValueType::Array => {
                auth_raw = Some(raw_val);
            }
            "content" if value_type == ValueType::Object => {
                content_raw = Some(raw_val);
            }
            _ => {}
        }
        Ok(())
    })?;

    let event_id = parse_unquoted_str_borrowed(event_id_raw);
    let room_id = parse_unquoted_str_borrowed(room_id_raw);
    let event_type = parse_unquoted_str_borrowed(event_type_raw);
    let state_key = parse_unquoted_str_borrowed(state_key_raw);

    let mut prev_events = Vec::new();
    let mut auth_events = Vec::new();

    if let Some(raw_prev) = prev_raw {
        fill_id_array(raw_prev, &mut prev_events)?;
    }
    if let Some(raw_auth) = auth_raw {
        fill_id_array(raw_auth, &mut auth_events)?;
    }

    let mut room_version = None;
    let mut relates_to = None;

    if let Some(raw_content) = content_raw {
        let mut content_tok = Tokenizer::new(raw_content);
        let mut room_version_raw = None;
        let mut relates_to_raw = None;

        content_tok.for_each_object_member(&mut key_buf, |key, value_type, raw_val| {
            match key {
                "room_version" if value_type == ValueType::String => {
                    room_version_raw = Some(raw_val);
                }
                "m.relates_to" if value_type == ValueType::Object => {
                    relates_to_raw = Some(raw_val);
                }
                _ => {}
            }
            Ok(())
        })?;

        room_version = parse_unquoted_str_borrowed(room_version_raw);

        if let Some(raw_rel) = relates_to_raw {
            let mut rel_tok = Tokenizer::new(raw_rel);
            let mut rel_type_raw = None;
            let mut rel_event_id_raw = None;
            rel_tok.for_each_object_member(&mut key_buf, |key, value_type, raw_val| {
                match key {
                    "rel_type" if value_type == ValueType::String => {
                        rel_type_raw = Some(raw_val);
                    }
                    "event_id" if value_type == ValueType::String => {
                        rel_event_id_raw = Some(raw_val);
                    }
                    _ => {}
                }
                Ok(())
            })?;
            let rel_type = parse_unquoted_str_borrowed(rel_type_raw);
            let rel_event_id = parse_unquoted_str_borrowed(rel_event_id_raw);
            if let (Some(r), Some(id)) = (rel_type, rel_event_id) {
                relates_to = Some((r, id));
            }
        }
    }

    Ok(MatrixEventFieldsRef {
        event_id,
        room_id,
        event_type,
        state_key,
        prev_events,
        auth_events,
        room_version,
        relates_to,
    })
}

/// Extracts adjacency fields from one raw event span into an owned structure.
///
/// # Errors
/// Returns [`TokenizerError`] if the span is not valid JSON or cannot be selectively parsed.
pub fn extract_matrix_event_fields(raw: &[u8]) -> Result<MatrixEventFields, TokenizerError> {
    let mut scratch = MatrixEventScratch::new();
    let view = extract_matrix_event_view(raw, &mut scratch)?;
    Ok(view.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn raw_jsonl_spans_skip_blank_lines() {
        let input = b"\n {\"event_id\":\"$a\"}\n\n{\"event_id\":\"$b\"}";
        let spans = discover_jsonl_spans(input);
        assert_eq!(spans.len(), 2);
        assert_eq!(
            &input[spans[0].start..spans[0].end],
            b" {\"event_id\":\"$a\"}"
        );
        assert_eq!(
            &input[spans[1].start..spans[1].end],
            b"{\"event_id\":\"$b\"}"
        );
    }

    #[test]
    fn masked_matrix_fields_extract_adjacency_without_full_dom() {
        let raw = br#"{"event_id":"$e","room_id":"!r:x","type":"m.room.message","state_key":"","prev_events":["$p"],"auth_events":[["$a",{}]],"content":{"room_version":"10","m.relates_to":{"rel_type":"m.thread","event_id":"$root"},"ignored":{"large":[1,2,3]}}}"#;
        let mut scratch = MatrixEventScratch::new();
        let view = extract_matrix_event_view(raw, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$e"));
        assert_eq!(view.room_id, Some("!r:x"));
        assert_eq!(view.event_type, Some("m.room.message"));
        assert_eq!(view.state_key, Some(""));
        assert_eq!(view.prev_events, &["$p"]);
        assert_eq!(view.auth_events, &["$a"]);
        assert_eq!(view.room_version, Some("10"));
        assert_eq!(view.relates_to, Some(("m.thread", "$root")));

        let fields = extract_matrix_event_fields(raw).unwrap();
        assert_eq!(fields.event_id.as_deref(), Some("$e"));
        assert_eq!(fields.prev_events, vec!["$p"]);
        assert_eq!(fields.auth_events, vec!["$a"]);
        assert_eq!(fields.room_version.as_deref(), Some("10"));
        assert_eq!(
            fields.relates_to,
            Some(("m.thread".to_owned(), "$root".to_owned()))
        );

        let fields_ref = extract_matrix_event_fields_ref(raw).unwrap();
        assert_eq!(fields_ref.event_id, Some("$e"));
        assert_eq!(fields_ref.room_id, Some("!r:x"));
        assert_eq!(fields_ref.event_type, Some("m.room.message"));
        assert_eq!(fields_ref.state_key, Some(""));
        assert_eq!(fields_ref.prev_events, vec!["$p"]);
        assert_eq!(fields_ref.auth_events, vec!["$a"]);
        assert_eq!(fields_ref.room_version, Some("10"));
        assert_eq!(fields_ref.relates_to, Some(("m.thread", "$root")));
    }

    #[test]
    fn discover_array_and_envelope_and_federation_spans() {
        let arr = br#"[ {"event_id":"$1"}, {"event_id":"$2"} ]"#;
        let spans = discover_array_spans(arr).unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(&arr[spans[0].start..spans[0].end], br#"{"event_id":"$1"}"#);
        assert_eq!(&arr[spans[1].start..spans[1].end], br#"{"event_id":"$2"}"#);

        let env = br#"{"heads":["$h1","$h2"],"events":[{"event_id":"$1"}]}"#;
        let env_spans = discover_envelope_spans(env).unwrap();
        assert_eq!(env_spans.heads, vec!["$h1", "$h2"]);
        assert_eq!(env_spans.events.len(), 1);
        assert_eq!(
            &env[env_spans.events[0].start..env_spans.events[0].end],
            br#"{"event_id":"$1"}"#
        );

        let fed = br#"{"pdus":[{"event_id":"$p1"}],"auth_chain":[{"event_id":"$a1"}]}"#;
        let fed_spans = discover_federation_spans(fed).unwrap();
        assert_eq!(fed_spans.pdus.len(), 1);
        assert_eq!(fed_spans.auth_chain.len(), 1);
        assert_eq!(
            &fed[fed_spans.pdus[0].start..fed_spans.pdus[0].end],
            br#"{"event_id":"$p1"}"#
        );
        assert_eq!(
            &fed[fed_spans.auth_chain[0].start..fed_spans.auth_chain[0].end],
            br#"{"event_id":"$a1"}"#
        );
    }

    #[test]
    fn escaped_matrix_fields_extract_adjacency() {
        let raw = br#"{"\u0065vent_id":"$e","\u0072oom_id":"!r:x","\u0074ype":"m.room.message","\u0073tate_key":"","\u0070rev_events":["$p"],"\u0061uth_events":[["$a",{}]],"content":{"\u0072oom_version":"10","\u006d.relates_to":{"\u0072el_type":"m.thread","\u0065vent_id":"$root"}}}"#;
        let mut scratch = MatrixEventScratch::with_capacity(8, 8, 32);
        let view = extract_matrix_event_view(raw, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$e"));
        assert_eq!(view.room_id, Some("!r:x"));
        assert_eq!(view.event_type, Some("m.room.message"));
        assert_eq!(view.state_key, Some(""));
        assert_eq!(view.prev_events, &["$p"]);
        assert_eq!(view.auth_events, &["$a"]);
        assert_eq!(view.room_version, Some("10"));
        assert_eq!(view.relates_to, Some(("m.thread", "$root")));
    }

    #[test]
    fn escaped_selected_value_is_decoded_without_being_dropped() {
        let raw = br#"{"event_id":"\u0024event:example.com"}"#;
        let mut scratch = MatrixEventScratch::with_capacity(2, 2, 32);
        let view = extract_matrix_event_into(raw, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$event:example.com"));
    }

    #[test]
    fn escaped_reference_id_is_rejected_instead_of_dropped() {
        let raw = br#"{"prev_events":["\u0024parent"]}"#;
        let mut scratch = MatrixEventScratch::with_capacity(2, 2, 32);
        assert_eq!(
            extract_matrix_event_into(raw, &mut scratch),
            Err(TokenizerError::InvalidString)
        );
    }

    #[test]
    fn nested_and_mixed_format_auth_and_prev_events() {
        let raw = br#"{
            "event_id": "$nested",
            "room_id": "!room:example.com",
            "type": "m.room.member",
            "state_key": "@alice:example.com",
            "prev_events": [["$p1", {"hash": "sha256"}], ["$p2", {"extra": [1, 2, 3]}]],
            "auth_events": [["$a1", {}], "$a2", ["$a3", {"deep": {"nested": true}}]],
            "content": {
                "membership": "join",
                "room_version": "1",
                "m.relates_to": {
                    "rel_type": "m.replace",
                    "event_id": "$target"
                }
            }
        }"#;

        let mut scratch = MatrixEventScratch::with_capacity(16, 16, 64);
        let view = extract_matrix_event_view(raw, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$nested"));
        assert_eq!(view.room_id, Some("!room:example.com"));
        assert_eq!(view.event_type, Some("m.room.member"));
        assert_eq!(view.state_key, Some("@alice:example.com"));
        assert_eq!(view.prev_events, &["$p1", "$p2"]);
        assert_eq!(view.auth_events, &["$a1", "$a2", "$a3"]);
        assert_eq!(view.room_version, Some("1"));
        assert_eq!(view.relates_to, Some(("m.replace", "$target")));
    }
}
