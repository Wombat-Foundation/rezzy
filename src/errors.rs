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

//! Typed zero-heap errors for the hash and canonicalization layer.
//!
//! [`HashError`] replaces the `String` error payloads previously returned by
//! the reference-hash, content-hash, and canonical-redaction functions. Every
//! variant carries only borrowed or inline data, so constructing and
//! rendering an error never allocates. Display rendering is byte-compatible
//! with the old `format!` messages.

use base64::EncodeSliceError;
use core::fmt;
use std::string::String;
use std::string::ToString;

use crate::basespec::rezzy_types::{CanonicalizationError, HASH_B64_MAX_LEN};

/// The computed half of a content-hash mismatch: a base64 digest stored in a
/// fixed inline buffer so the error can escape the local buffer it was
/// encoded into inside `verify_content_hash`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComputedHash {
    buf: [u8; HASH_B64_MAX_LEN],
    len: usize,
}

impl ComputedHash {
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Bytes are copied from a `&str` on a char boundary.
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl From<&str> for ComputedHash {
    fn from(s: &str) -> Self {
        let mut len = s.len().min(HASH_B64_MAX_LEN);
        while !s.is_char_boundary(len) {
            len = len.saturating_sub(1);
        }
        let mut buf = [0u8; HASH_B64_MAX_LEN];
        buf[..len].copy_from_slice(&s.as_bytes()[..len]);
        Self { buf, len }
    }
}

impl fmt::Debug for ComputedHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.as_str(), f)
    }
}

/// Errors returned by the reference-hash, content-hash, and canonical-JSON
/// functions.
///
/// Payloads are borrowed (`&'a str` from the caller's `Value` or room
/// version) or inline ([`ComputedHash`], [`CanonicalizationError`],
/// [`EncodeSliceError`]), so building and displaying an error performs no
/// allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashError<'a> {
    /// The room version is v1/v2: event IDs are opaque assigned strings.
    ReferenceHashV1V2 {
        /// The rejected room version.
        room_version: &'a str,
    },
    /// The room version is unknown to the reference-hash rules.
    UnsupportedReferenceHash {
        /// The rejected room version.
        room_version: &'a str,
    },
    /// The room version is unknown to the content-hash rules.
    UnsupportedContentHash {
        /// The rejected room version.
        room_version: &'a str,
    },
    /// The room version is unknown to the canonical-redaction rules.
    UnsupportedCanonical {
        /// The rejected room version.
        room_version: &'a str,
    },
    /// The canonical JSON writer failed (strict-number validation or sink I/O).
    CanonicalWrite(CanonicalizationError),
    /// Base64 encoding of a hash digest failed (output slice too small).
    Encode(EncodeSliceError),
    /// The caller-supplied output buffer is shorter than 43 bytes.
    EncodeBufferTooSmall,
    /// `hashes.sha256` is missing or not a string.
    MissingContentHash,
    /// The recomputed content hash does not match `hashes.sha256`.
    ContentHashMismatch {
        /// The declared `hashes.sha256` value.
        expected: &'a str,
        /// The recomputed digest, stored inline.
        computed: ComputedHash,
    },
}

impl fmt::Display for HashError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReferenceHashV1V2 { room_version } => write!(
                f,
                "no reference hash for room version {room_version}: v1/v2 event IDs are opaque server-assigned strings, not hashes"
            ),
            Self::UnsupportedReferenceHash { room_version } => write!(
                f,
                "no reference hash for unsupported room version {room_version}: its event ID hash rules are undefined"
            ),
            Self::UnsupportedContentHash { room_version } => write!(
                f,
                "no content hash for unsupported room version {room_version}: its canonical JSON rules are undefined"
            ),
            Self::UnsupportedCanonical { room_version } => write!(
                f,
                "no canonical redacted JSON for unsupported room version {room_version}"
            ),
            Self::CanonicalWrite(err) => {
                write!(f, "failed to write canonical JSON: {err}")
            }
            Self::Encode(err) => write!(f, "failed to encode hash: {err}"),
            Self::EncodeBufferTooSmall => {
                f.write_str("encode_hash_slice: output buffer shorter than 43 bytes")
            }
            Self::MissingContentHash => f.write_str("hashes.sha256 is missing or not a string"),
            Self::ContentHashMismatch { expected, computed } => write!(
                f,
                "content hash mismatch: hashes.sha256={expected}, computed={}",
                computed.as_str()
            ),
        }
    }
}

/// Transitional bridge: boundary traits (such as the signing
/// `EventVerifier` impls) still spell their errors `String`. They are
/// converted to structured error types in a later phase.
impl From<HashError<'_>> for String {
    fn from(err: HashError<'_>) -> Self {
        err.to_string()
    }
}
