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

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use rezzy_json::{FieldMask, Token, Tokenizer, TokenizerError, Value as JsonValue, ValueType};

/// Byte slice range representing a raw event in an input buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
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

/// Reusable caller-supplied scratch storage for zero-heap-allocation Matrix event extraction.
///
/// # Lifetime
///
/// `MatrixEventScratch<'a>` is parameterized on the lifetime of the **input byte buffer**
/// that raw event strings are borrowed from.  One scratch instance is intended to be
/// associated with **one input buffer** (e.g., a memory-mapped file or a read buffer)
/// and reused across every event in that buffer:
///
/// ```text
/// let content = fs::read("events.jsonl")?;          // 'a lives here
/// let mut scratch = MatrixEventScratch::with_capacity(16, 16, 64);
/// for span in spans {
///     let view = extract_matrix_event_into(&content[span.start..span.end], &mut scratch)?;
///     // view borrows from both `content` ('a) and `scratch` ('buf ≤ 'a)
/// }
/// ```
///
/// Reusing the same scratch across **independently owned** buffers (e.g., alternating
/// between two separately allocated `Vec<u8>`) requires starting a fresh
/// `MatrixEventScratch` for each buffer, because the `&'a str` references stored in
/// `prev_events` and `auth_events` must not outlive their source buffer.
///
/// # Zero-allocation contract
///
/// `extract_matrix_event_into` performs **zero heap allocations** when the scratch
/// buffers already have sufficient capacity for the current event:
///
/// - `prev_events` and `auth_events` are cleared (O(1)) and refilled without
///   reallocating as long as the new event has ≤ the previously seen maximum
///   number of parent references.
///   An oversized `prev_events` or `auth_events` array grows its corresponding
///   `Vec`; callers requiring a strict zero-allocation pass must provision
///   capacities for the largest expected arrays.
/// - Reference IDs in `prev_events` and `auth_events` must use unescaped JSON
///   strings. Escaped reference IDs are rejected regardless of available
///   capacity; they are not part of the zero-allocation extraction contract.
/// - Each `*_buf` `String` is cleared and written in-place as long as the decoded
///   value fits within the existing allocated capacity.
///
/// The first call after `MatrixEventScratch::new()` (zero capacity) allocates.
/// Use [`MatrixEventScratch::with_capacity`] to pre-size the buffers, or run a
/// warm-up pass over a representative event before entering the steady-state loop.
/// After the scratch has been sized to the widest event in the stream, subsequent
/// calls operate at 0 bytes allocated per event.
#[derive(Default)]
pub struct MatrixEventScratch<'a> {
    /// Decoded `prev_events` IDs, borrowing from the input buffer `'a`.
    pub prev_events: Vec<&'a str>,
    /// Decoded `auth_events` IDs, borrowing from the input buffer `'a`.
    pub auth_events: Vec<&'a str>,
    /// Scratch for JSON key decoding (escape sequences in object keys).
    pub key_buffer: String,
    /// Decode buffer for `event_id` values that contain escape sequences.
    pub event_id_buf: String,
    /// Decode buffer for `room_id` values that contain escape sequences.
    pub room_id_buf: String,
    /// Decode buffer for `type` values that contain escape sequences.
    pub event_type_buf: String,
    /// Decode buffer for `state_key` values that contain escape sequences.
    pub state_key_buf: String,
    /// Decode buffer for `content.room_version` values that contain escape sequences.
    pub room_version_buf: String,
    /// Decode buffer for `content.m.relates_to.rel_type` values.
    pub rel_type_buf: String,
    /// Decode buffer for `content.m.relates_to.event_id` values.
    pub rel_event_id_buf: String,
}

impl MatrixEventScratch<'_> {
    /// Creates an empty scratch buffer with no pre-allocated capacity.
    ///
    /// The first [`extract_matrix_event_into`] call will allocate. Use
    /// [`with_capacity`](Self::with_capacity) or a warm-up pass to achieve the
    /// zero-allocation steady state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a scratch buffer with pre-allocated capacities.
    ///
    /// - `prev_cap` — expected maximum number of `prev_events` references per event.
    /// - `auth_cap` — expected maximum number of `auth_events` references per event.
    /// - `key_cap` — expected maximum byte length of any decoded scalar field (event ID,
    ///   room ID, type, state key, room version, relation fields).
    ///
    /// Over-estimating is safe (wastes a little memory). Under-estimating triggers a
    /// single reallocation per underestimated field, after which steady-state zero
    /// allocations resume.
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

    /// Clears all buffers while retaining their allocated capacity.
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
///
/// Scalar string fields (`event_id`, `room_id`, `event_type`, `state_key`,
/// `room_version`, `relates_to`) borrow either directly from the raw input bytes
/// (`'a`) when the value contains no escape sequences, or from the corresponding
/// `*_buf` field of the [`MatrixEventScratch`] (`'buf`) when decoding was required.
///
/// `prev_events` and `auth_events` borrow from the scratch's `Vec` storage.
/// Escaped IDs in reference arrays are rejected explicitly, regardless of
/// scratch capacity.
///
/// The view is valid for the shorter of `'buf` and `'a`.
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

/// Owned Matrix event fields for batch processing.
///
/// Unlike `MatrixEventView`, this type owns all its data and has no lifetime
/// dependency on a reusable scratch buffer. Suitable for collecting multiple
/// events into a batch before processing (e.g., adjacency recording).
#[derive(PartialEq, Eq)]
pub struct OwnedMatrixEvent {
    pub event_id: Option<String>,
    pub room_id: Option<String>,
    pub event_type: Option<String>,
    pub state_key: Option<String>,
    pub prev_events: Vec<String>,
    pub auth_events: Vec<String>,
    pub room_version: Option<String>,
    pub relates_to: Option<(String, String)>,
}

impl<'buf, 'a> From<MatrixEventView<'buf, 'a>> for OwnedMatrixEvent {
    fn from(view: MatrixEventView<'buf, 'a>) -> Self {
        Self {
            event_id: view.event_id.map(ToString::to_string),
            room_id: view.room_id.map(ToString::to_string),
            event_type: view.event_type.map(ToString::to_string),
            state_key: view.state_key.map(ToString::to_string),
            prev_events: view.prev_events.iter().map(|s| (*s).to_string()).collect(),
            auth_events: view.auth_events.iter().map(|s| (*s).to_string()).collect(),
            room_version: view.room_version.map(ToString::to_string),
            relates_to: view
                .relates_to
                .map(|(r, id)| (r.to_string(), id.to_string())),
        }
    }
}

impl OwnedMatrixEvent {
    /// Extracts a batch of Matrix events directly into owned representations.
    ///
    /// This is the batch-safe entry point: it internally uses a single
    /// `MatrixEventScratch` for zero-allocation extraction of each event,
    /// then converts each `MatrixEventView` into an `OwnedMatrixEvent` before
    /// the scratch is reused for the next event.
    ///
    /// # Errors
    /// Returns [`TokenizerError`] if any input is not a valid JSON object.
    pub fn extract_batch(raw_events: &[&[u8]]) -> Result<Vec<Self>, TokenizerError> {
        let mut scratch = MatrixEventScratch::new();
        let mut results = Vec::with_capacity(raw_events.len());
        for raw in raw_events {
            let view = extract_matrix_event_view(raw, &mut scratch)?;
            results.push(view.into());
        }
        Ok(results)
    }
}

type RelationView<'a> = Option<(&'a str, &'a str)>;
type ContentRelationResult<'a> = (Option<&'a str>, RelationView<'a>);

/// Spans of `pdus` and `auth_chain` arrays discovered within a federation transaction payload.
#[derive(Default, PartialEq, Eq)]
pub struct FederationSpans {
    pub pdus: Vec<RawEventSpan>,
    pub auth_chain: Vec<RawEventSpan>,
}

/// Spans of `events` and extracted `heads` discovered within an envelope object.
#[derive(Default, PartialEq, Eq)]
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

/// Fills `out` with the event-ID strings from a raw JSON `prev_events` or `auth_events`
/// array, supporting both bare strings and room-version-1/2 `[event_id, hashes]` tuples.
///
/// Escape-encoded IDs are rejected rather than silently dropped, because a single
/// reusable buffer cannot safely back multiple returned `&str` values.
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
                out.push(core::str::from_utf8(s).map_err(|_| TokenizerError::InvalidString)?);
            }
            Token::ArrayStart => {
                // Room-version 1/2: ["$event_id", {"sha256": "..."}]
                let Some(Token::String(s)) = tokenizer.next_token()? else {
                    return Err(TokenizerError::InvalidString);
                };
                if s.contains(&b'\\') {
                    return Err(TokenizerError::InvalidString);
                }
                out.push(core::str::from_utf8(s).map_err(|_| TokenizerError::InvalidString)?);
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

/// Decodes a raw JSON string token (without surrounding quotes) into a `&str`.
///
/// If the bytes contain no backslash the result borrows directly from `raw_inner` (`'a`).
/// If escape sequences are present the decoded value is appended to `buf` followed by
/// a NUL separator, and the result borrows from `buf` — which must also carry lifetime `'a`.
#[cfg(any())]
fn decode_id_str<'a>(raw_inner: &'a [u8], buf: &'a mut String) -> Result<&'a str, TokenizerError> {
    if !raw_inner.contains(&b'\\') {
        return core::str::from_utf8(raw_inner).map_err(|_| TokenizerError::InvalidString);
    }
    // Append decoded bytes, then a NUL separator so multiple decoded IDs can
    // coexist in the same buffer without overwriting each other.
    let start = buf.len();
    rezzy_json::unescape_raw_string(raw_inner, buf)?;
    let end = buf.len();
    // Push NUL sentinel so next decoded ID starts cleanly.
    buf.push('\0');
    // SAFETY: `unescape_raw_string` writes valid UTF-8 into `buf`.
    // We return the slice `[start..end]` which was just written.
    Ok(&buf[start..end])
}

/// Decodes a raw JSON string value (with surrounding `"` quotes) into a `&'buf str`.
///
/// Returns `None` if the raw bytes are not a quoted JSON string.
/// Plain strings (no backslash) borrow from the `'a` input.
/// Escaped strings are decoded into `buf` and borrow from `'buf`.
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

fn extract_matrix_event_view<'buf, 'a>(
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

/// Extracts Matrix event fields into a caller-supplied [`MatrixEventScratch`] with zero heap
/// allocations in the steady state.
///
/// All scalar fields are decoded from `raw` without allocating: plain values borrow directly
/// from the input; escape-encoded values are decoded into the corresponding `*_buf` field of
/// `scratch`.  `prev_events` and `auth_events` are filled into the scratch's `Vec` storage;
/// Escape-encoded IDs in those arrays are rejected explicitly.
///
/// # Zero-allocation contract
///
/// Zero allocations occur when every buffer in `scratch` already has sufficient capacity for
/// the current event (see [`MatrixEventScratch`] for the full contract).  Use
/// [`MatrixEventScratch::with_capacity`] to pre-size, or warm up with one representative
/// event before entering the steady-state loop.
///
/// # Errors
/// Returns [`TokenizerError`] if `raw` is not a valid JSON object.
pub fn extract_matrix_event_into<'buf, 'a>(
    raw: &'a [u8],
    scratch: &'buf mut MatrixEventScratch<'a>,
) -> Result<MatrixEventView<'buf, 'a>, TokenizerError>
where
    'a: 'buf,
{
    extract_matrix_event_view(raw, scratch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::ToOwned;
    use alloc::vec;

    /// Asserts the adjacency, version and thread relation shared by the
    /// thread-reply extraction fixtures.
    fn assert_thread_adjacency(view: &MatrixEventView<'_, '_>) {
        assert_eq!(view.prev_events, &["$p"]);
        assert_eq!(view.auth_events, &["$a"]);
        assert_eq!(view.room_version, Some("10"));
        assert_eq!(view.relates_to, Some(("m.thread", "$root")));
    }

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
        assert_thread_adjacency(&view);
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
        assert_eq!(env_spans.events.len(), 1);
        assert_eq!(env_spans.heads, vec!["$h1".to_owned(), "$h2".to_owned()]);

        let fed = br#"{"pdus":[{"event_id":"$pdu1"}],"auth_chain":[{"event_id":"$ac1"}]}"#;
        let fed_spans = discover_federation_spans(fed).unwrap();
        assert_eq!(fed_spans.pdus.len(), 1);
        assert_eq!(fed_spans.auth_chain.len(), 1);
    }

    #[test]
    fn nested_and_mixed_format_auth_and_prev_events() {
        // v1/v2 tuple auth_events mixed with a bare-string prev_events entry
        let raw = br#"{"event_id":"$e","room_id":"!r:x","type":"m.room.message","prev_events":["$p1"],"auth_events":[["$a1",{"sha256":"abc"}],["$a2",{"sha256":"xyz"}]]}"#;
        let mut scratch = MatrixEventScratch::new();
        let view = extract_matrix_event_view(raw, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$e"));
        assert_eq!(view.prev_events, &["$p1"]);
        assert_eq!(view.auth_events, &["$a1", "$a2"]);
    }

    #[test]
    fn escaped_scalar_values_are_decoded() {
        // \u0024 = '$', \u0021 = '!'
        let raw = br#"{"event_id":"\u0024event:example.com","room_id":"\u0021room:example.com","type":"m.room.message","prev_events":["$p"],"auth_events":["$a"]}"#;
        let mut scratch = MatrixEventScratch::new();
        let view = extract_matrix_event_view(raw, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$event:example.com"));
        assert_eq!(view.room_id, Some("!room:example.com"));
    }

    /// Escaped IDs inside `prev_events` are rejected rather than dropped.
    #[test]
    fn escaped_prev_event_ids_are_rejected() {
        // \u0024 = '$' — ID has an escape sequence
        let raw = br#"{"event_id":"$e","room_id":"!r:x","type":"m.room.message","prev_events":["\u0024escaped:server","$plain"],"auth_events":["$a"]}"#;
        let mut scratch = MatrixEventScratch::new();
        assert_eq!(
            extract_matrix_event_view(raw, &mut scratch),
            Err(TokenizerError::InvalidString)
        );
    }

    /// Escaped IDs inside `auth_events` are rejected rather than dropped.
    #[test]
    fn escaped_auth_event_ids_are_rejected() {
        // bare escaped string + v1/v2 tuple with escaped first element
        let raw = br#"{"event_id":"$e","room_id":"!r:x","type":"m.room.message","prev_events":["$p"],"auth_events":["\u0024bare:escaped",["\u0024tuple:escaped",{"sha256":"abc"}]]}"#;
        let mut scratch = MatrixEventScratch::new();
        assert_eq!(
            extract_matrix_event_view(raw, &mut scratch),
            Err(TokenizerError::InvalidString)
        );
    }

    /// Multiple escaped IDs across both arrays are rejected safely.
    #[test]
    fn multiple_escaped_ids_in_both_arrays_are_rejected() {
        let raw = br#"{"event_id":"$e","room_id":"!r:x","type":"m.room.message","prev_events":["\u0024p1:s","\u0024p2:s"],"auth_events":["\u0024a1:s",["\u0024a2:s",{}]]}"#;
        let mut scratch = MatrixEventScratch::new();
        assert_eq!(
            extract_matrix_event_view(raw, &mut scratch),
            Err(TokenizerError::InvalidString)
        );
    }

    #[test]
    fn masked_matrix_fields_extract_adjacency_without_full_dom_2() {
        // Retained for regression: the exact shape from the original test
        let raw = br#"{"event_id":"$e","room_id":"!r:x","type":"m.room.message","state_key":"","prev_events":["$p"],"auth_events":[["$a",{}]],"content":{"room_version":"10","m.relates_to":{"rel_type":"m.thread","event_id":"$root"},"ignored":{"large":[1,2,3]}}}"#;
        let mut scratch = MatrixEventScratch::with_capacity(4, 4, 64);
        let view = extract_matrix_event_into(raw, &mut scratch).unwrap();
        assert_eq!(view.event_id, Some("$e"));
        assert_thread_adjacency(&view);
    }

    #[test]
    fn owned_matrix_event_batch_extraction() {
        let raw1 = br#"{"event_id":"$e1","room_id":"!r1:x","type":"m.room.message","prev_events":["$p1"],"auth_events":["$a1"]}"#;
        let raw2 = br#"{"event_id":"$e2","room_id":"!r2:x","type":"m.room.encrypted","prev_events":["$p2"],"auth_events":["$a2","$a3"]}"#;
        let batch = OwnedMatrixEvent::extract_batch(&[raw1, raw2]).unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].event_id.as_deref(), Some("$e1"));
        assert_eq!(batch[0].room_id.as_deref(), Some("!r1:x"));
        assert_eq!(batch[0].event_type.as_deref(), Some("m.room.message"));
        assert_eq!(batch[0].prev_events, vec!["$p1"]);
        assert_eq!(batch[0].auth_events, vec!["$a1"]);
        assert_eq!(batch[1].event_id.as_deref(), Some("$e2"));
        assert_eq!(batch[1].room_id.as_deref(), Some("!r2:x"));
        assert_eq!(batch[1].event_type.as_deref(), Some("m.room.encrypted"));
        assert_eq!(batch[1].prev_events, vec!["$p2"]);
        assert_eq!(batch[1].auth_events, vec!["$a2", "$a3"]);
    }

    #[test]
    fn owned_matrix_event_from_view_conversion() {
        let raw = br#"{"event_id":"$e","room_id":"!r:x","type":"m.room.message","prev_events":["$p1","$p2"],"auth_events":["$a1"]}"#;
        let mut scratch = MatrixEventScratch::new();
        let view = extract_matrix_event_view(raw, &mut scratch).unwrap();
        let owned: OwnedMatrixEvent = view.into();
        assert_eq!(owned.event_id.as_deref(), Some("$e"));
        assert_eq!(owned.room_id.as_deref(), Some("!r:x"));
        assert_eq!(owned.prev_events, vec!["$p1", "$p2"]);
        assert_eq!(owned.auth_events, vec!["$a1"]);
    }
}
