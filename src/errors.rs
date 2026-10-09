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

//! Typed zero-heap errors for the hash, canonicalization, and signature
//! verification layers.
//!
//! [`HashError`] replaces the `String` error payloads previously returned by
//! the reference-hash, content-hash, and canonical-redaction functions, and
//! [`SignError`] those of signature verification. Every variant carries only
//! borrowed or inline data, so constructing and rendering an error never
//! allocates. Display rendering is byte-compatible with the old `format!`
//! messages.

use base64::EncodeSliceError;
use core::fmt;
use std::string::String;
use std::string::ToString;

use crate::basespec::rezzy_types::{CanonicalizationError, HASH_B64_MAX_LEN};

/// The computed or expected half of a hash mismatch: a base64 digest stored
/// in a fixed inline buffer so the error can escape the local buffer it was
/// encoded into (e.g. inside `verify_content_hash`).
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

/// Errors returned by signature verification and key provisioning.
///
/// Like [`HashError`], payloads are borrowed (`&'a str` from the caller's
/// server/key/room-version strings) or inline (embedded
/// [`HashError`]/[`base64::DecodeError`]/`ed25519_zebra::Error` values), so
/// building and displaying an error performs no allocation.
#[derive(Debug, PartialEq, Eq)]
pub enum SignError<'a> {
    /// The room version has no defined signature format.
    UnsupportedRoomVersion {
        /// The rejected room version.
        room_version: &'a str,
    },
    /// The event's expected signer could not be derived from `event_id`/`sender`.
    NoExpectedSigner,
    /// Canonical redaction of the signing envelope failed.
    CanonicalRedacted(HashError<'a>),
    /// The event carries no `signatures` object.
    NoSignaturesObject,
    /// A signature value is not a string.
    SignatureNotAString {
        /// The server the signature is claimed from.
        server: &'a str,
        /// The claimed key ID.
        key_id: &'a str,
    },
    /// A signature is not valid base64.
    BadSignatureBase64 {
        /// The server the signature is claimed from.
        server: &'a str,
        /// The claimed key ID.
        key_id: &'a str,
        /// The base64 decode failure.
        source: base64::DecodeError,
    },
    /// No supported signature from the required server.
    NoSupportedSignature {
        /// The server whose signature was required.
        server: &'a str,
    },
    /// The event carries no signature this verifier holds a key for.
    NoSupportedSignaturesPresent,
    /// The raw public key bytes are not a valid Ed25519 key.
    #[cfg(feature = "signing-consensus")]
    InvalidVerificationKey(ed25519_zebra::Error),
    /// The verifier holds no key for this `(server_name, key_id)`.
    NoPublicKey {
        /// The server whose key was requested.
        server_name: &'a str,
        /// The requested key ID.
        key_id: &'a str,
    },
    /// A signature was not exactly 64 bytes.
    SignatureLength,
    /// Ed25519 signature verification failed.
    #[cfg(feature = "signing-consensus")]
    SignatureVerifyFailed(ed25519_zebra::Error),
}

impl fmt::Display for SignError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRoomVersion { room_version } => write!(
                f,
                "unsupported room version {room_version}: cannot verify signatures over an undefined format"
            ),
            Self::NoExpectedSigner => {
                f.write_str("could not derive expected event signer from event_id or sender")
            }
            Self::CanonicalRedacted(err) => {
                write!(f, "failed to compute canonical redacted JSON: {err}")
            }
            Self::NoSignaturesObject => f.write_str("event has no signatures object"),
            Self::SignatureNotAString { server, key_id } => {
                write!(f, "signature for {server}/{key_id} is not a string")
            }
            Self::BadSignatureBase64 {
                server,
                key_id,
                source,
            } => write!(f, "bad base64 for {server}/{key_id}: {source}"),
            Self::NoSupportedSignature { server } => {
                write!(f, "no supported signature from required server {server}")
            }
            Self::NoSupportedSignaturesPresent => {
                f.write_str("no supported signatures present on event")
            }
            #[cfg(feature = "signing-consensus")]
            Self::InvalidVerificationKey(err) => write!(f, "{err:?}"),
            Self::NoPublicKey { server_name, key_id } => {
                write!(f, "no public key for {server_name}/{key_id}")
            }
            Self::SignatureLength => f.write_str("signature must be 64 bytes"),
            #[cfg(feature = "signing-consensus")]
            Self::SignatureVerifyFailed(err) => write!(f, "signature verification failed: {err:?}"),
        }
    }
}

/// Transitional bridge: the signing `EventVerifier` impls still spell their
/// errors `String` until the `VerifyError` trait conversion.
impl From<SignError<'_>> for String {
    fn from(err: SignError<'_>) -> Self {
        err.to_string()
    }
}

/// Errors returned by the [`EventVerifier`](crate::EventVerifier) pipeline.
///
/// Payloads are borrowed or inline, so building and displaying an error
/// performs no allocation. [`VerifyError::Reason`] lets custom verifier
/// implementations carry their own borrowed rejection reason; the built-in
/// `NativeVerifier` paths report structured variants.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError<'a> {
    /// A caller-supplied rejection reason from a custom verifier impl.
    Reason(&'a str),
    /// The verifier holds no stored event for this ID.
    UnknownEvent {
        /// The unresolvable event ID.
        event_id: &'a str,
    },
    /// The event ID does not match the reference hash of the event body.
    EventIdHashMismatch {
        /// The event ID that failed to match.
        event_id: &'a str,
        /// The recomputed reference hash (base64, no `$` prefix).
        expected: ComputedHash,
    },
    /// The authorising user ID yields no usable server domain.
    InvalidAuthorisingUser {
        /// The rejected authorising user ID.
        authorising_user: &'a str,
    },
    /// Signature verification failed.
    Sign(SignError<'a>),
    /// Hashing or canonicalization of the event failed.
    Hash(HashError<'a>),
}

impl fmt::Display for VerifyError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reason(reason) => f.write_str(reason),
            Self::UnknownEvent { event_id } => write!(f, "unknown event {event_id}"),
            Self::EventIdHashMismatch { event_id, expected } => write!(
                f,
                "event id hash mismatch for {event_id}: expected {}",
                expected.as_str()
            ),
            Self::InvalidAuthorisingUser { authorising_user } => {
                write!(f, "invalid authorising user ID {authorising_user}")
            }
            Self::Sign(err) => fmt::Display::fmt(err, f),
            Self::Hash(err) => fmt::Display::fmt(err, f),
        }
    }
}

/// Transitional bridge: `AuthError::InvalidSyntax` still holds a formatted
/// `String` until the structured `AuthError` conversion.
impl From<VerifyError<'_>> for String {
    fn from(err: VerifyError<'_>) -> Self {
        err.to_string()
    }
}
