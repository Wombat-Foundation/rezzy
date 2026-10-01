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
use rezzy_json::{
    FieldMask, Token, Tokenizer, TokenizerError, Value as JsonValue, ValueRef, ValueType,
};

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
    let members = tokenizer.object_members()?;
    let mut result = FederationSpans::default();
    let base_ptr = input.as_ptr() as usize;
    for member in members {
        if member.key == "pdus" && member.value_type == ValueType::Array {
            let pdu_spans = discover_array_spans(member.raw_value)?;
            let offset = (member.raw_value.as_ptr() as usize).saturating_sub(base_ptr);
            result
                .pdus
                .extend(pdu_spans.into_iter().map(|s| RawEventSpan {
                    start: s.start.saturating_add(offset),
                    end: s.end.saturating_add(offset),
                }));
        } else if member.key == "auth_chain" && member.value_type == ValueType::Array {
            let auth_spans = discover_array_spans(member.raw_value)?;
            let offset = (member.raw_value.as_ptr() as usize).saturating_sub(base_ptr);
            result
                .auth_chain
                .extend(auth_spans.into_iter().map(|s| RawEventSpan {
                    start: s.start.saturating_add(offset),
                    end: s.end.saturating_add(offset),
                }));
        }
    }
    Ok(result)
}

/// Discovers `events` spans and extracts `heads` from an envelope object.
///
/// # Errors
/// Returns [`TokenizerError`] if the input cannot be tokenized as a JSON object.
pub fn discover_envelope_spans(input: &[u8]) -> Result<EnvelopeSpans, TokenizerError> {
    let mut tokenizer = Tokenizer::new(input);
    let members = tokenizer.object_members()?;
    let mut result = EnvelopeSpans::default();
    let base_ptr = input.as_ptr() as usize;
    for member in members {
        if member.key == "events" && member.value_type == ValueType::Array {
            let event_spans = discover_array_spans(member.raw_value)?;
            let offset = (member.raw_value.as_ptr() as usize).saturating_sub(base_ptr);
            result
                .events
                .extend(event_spans.into_iter().map(|s| RawEventSpan {
                    start: s.start.saturating_add(offset),
                    end: s.end.saturating_add(offset),
                }));
        } else if member.key == "heads" && member.value_type == ValueType::Array {
            let head_spans = discover_array_spans(member.raw_value)?;
            for span in head_spans {
                let raw_item = &member.raw_value[span.start..span.end];
                if let Ok(JsonValue::String(s)) = JsonValue::parse_bytes(raw_item) {
                    result.heads.push(s);
                }
            }
        }
    }
    Ok(result)
}

fn string_field(value: &ValueRef<'_>, key: &str) -> Option<String> {
    value.get(key).and_then(ValueRef::as_str).map(str::to_owned)
}

fn id_array(value: &ValueRef<'_>, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(ValueRef::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            item.as_str().or_else(|| {
                item.as_array()
                    .and_then(|pair| pair.first())
                    .and_then(ValueRef::as_str)
            })
        })
        .map(str::to_owned)
        .collect()
}

/// Extracts adjacency fields from one raw event span using the selective JSON API.
///
/// # Errors
/// Returns [`TokenizerError`] if the span is not valid JSON or cannot be selectively parsed.
pub fn extract_matrix_event_fields(raw: &[u8]) -> Result<MatrixEventFields, TokenizerError> {
    let value = ValueRef::parse_masked(raw, &ADJACENCY_MASK)?;
    let content = value.get("content");
    let relates = content.and_then(|c| c.get("m.relates_to"));
    Ok(MatrixEventFields {
        event_id: string_field(&value, "event_id"),
        room_id: string_field(&value, "room_id"),
        event_type: string_field(&value, "type"),
        state_key: string_field(&value, "state_key"),
        prev_events: id_array(&value, "prev_events"),
        auth_events: id_array(&value, "auth_events"),
        room_version: content.and_then(|c| string_field(c, "room_version")),
        relates_to: relates
            .and_then(|r| Some((string_field(r, "rel_type")?, string_field(r, "event_id")?))),
    })
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
        let fields = extract_matrix_event_fields(raw).unwrap();
        assert_eq!(fields.event_id.as_deref(), Some("$e"));
        assert_eq!(fields.prev_events, vec!["$p"]);
        assert_eq!(fields.auth_events, vec!["$a"]);
        assert_eq!(fields.room_version.as_deref(), Some("10"));
        assert_eq!(
            fields.relates_to,
            Some(("m.thread".to_owned(), "$root".to_owned()))
        );
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
}
