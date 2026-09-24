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

//! Structured error codes for CLI fatal errors.
//!
//! Every [`ErrorCode`] has a stable, version-independent code string
//! (e.g. `E001_NO_CREATE_EVENT`) suitable for programmatic matching and
//! logging. The format mirrors the existing [`rz_core::Warning::code()`]
//! convention (`W001_`, `W002_`, …).

use std::fmt;

/// A stable, programmatic error code for a fatal CLI condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// No `m.room.create` event found — cannot detect room version.
    NoCreateEvent,
    /// `event_type` cannot be missing or empty.
    EmptyEventType,
    /// No input data provided (empty file).
    EmptyInput,
    /// Neither `--input` nor `--room` was provided.
    MissingInputFlag,
    /// `--homeserver` is required when using `--room`.
    MissingHomeserver,
    /// JSON parse failure.
    MalformedJson,
    /// Input files describe disjoint DAGs with no shared history.
    DisjointDags,
    /// I/O error reading input file(s).
    IoError,
    /// Unsupported or unrecognised room version string.
    UnsupportedVersion,
    /// Top-level JSON object has an unrecognised structure.
    UnrecognisedStructure,
    /// Unexpected JSON format (not object or array).
    UnexpectedFormat,
    /// The `events` field is not a JSON array.
    EventsNotArray,
    /// Each element of `heads` must be a string.
    InvalidHeadType,
    /// Network / HTTP error when fetching room state.
    NetworkError,
    /// An aggregate does not match its raw inputs or manifest.
    AggregateStale,
    /// Raw inputs contain different payloads for one event ID.
    AggregateConflict,
}

impl ErrorCode {
    /// A short, stable code for this error, safe to match on or log
    /// across rezzy versions independent of the variant's exact fields.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoCreateEvent => "E001_NO_CREATE_EVENT",
            Self::EmptyEventType => "E002_EMPTY_EVENT_TYPE",
            Self::EmptyInput => "E003_EMPTY_INPUT",
            Self::MissingInputFlag => "E004_MISSING_INPUT_FLAG",
            Self::MissingHomeserver => "E005_MISSING_HOMESERVER",
            Self::MalformedJson => "E006_MALFORMED_JSON",
            Self::DisjointDags => "E007_DISJOINT_DAGS",
            Self::IoError => "E008_IO_ERROR",
            Self::UnsupportedVersion => "E009_UNSUPPORTED_VERSION",
            Self::UnrecognisedStructure => "E010_UNRECOGNISED_STRUCTURE",
            Self::UnexpectedFormat => "E011_UNEXPECTED_FORMAT",
            Self::EventsNotArray => "E012_EVENTS_NOT_ARRAY",
            Self::InvalidHeadType => "E013_INVALID_HEAD_TYPE",
            Self::NetworkError => "E014_NETWORK_ERROR",
            Self::AggregateStale => "E015_AGGREGATE_STALE",
            Self::AggregateConflict => "E016_AGGREGATE_CONFLICT",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// A structured application error pairing an [`ErrorCode`] with a
/// human-readable message.
#[derive(Debug)]
pub struct AppError {
    code: ErrorCode,
    message: String,
}

impl AppError {
    /// Create a new error with the given code and message.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code.code(), self.message)
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorCode::IoError, e.to_string())
    }
}

impl From<rz_core::JsonError> for AppError {
    fn from(e: rz_core::JsonError) -> Self {
        Self::new(ErrorCode::MalformedJson, e.to_string())
    }
}

/// Bail with an [`ErrorCode`] and formatted message.
///
/// # Examples
///
/// ```ignore
/// bail_code!(ErrorCode::NoCreateEvent, "No m.room.create event found");
/// ```
macro_rules! bail_code {
    ($code:expr, $msg:expr $(, $arg:expr)*) => {{
        return Err($crate::error::AppError::new($code, format!($msg $(, $arg)*)));
    }};
}

/// Build an [`AppError`] with an [`ErrorCode`] and formatted message.
macro_rules! err {
    ($code:expr, $msg:expr $(, $arg:expr)*) => {{
        $crate::error::AppError::new($code, format!($msg $(, $arg)*))
    }};
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{AppError, ErrorCode};

    #[test]
    fn test_error_codes_are_stable() {
        assert_eq!(ErrorCode::NoCreateEvent.code(), "E001_NO_CREATE_EVENT");
        assert_eq!(ErrorCode::EmptyEventType.code(), "E002_EMPTY_EVENT_TYPE");
        assert_eq!(ErrorCode::EmptyInput.code(), "E003_EMPTY_INPUT");
        assert_eq!(
            ErrorCode::MissingInputFlag.code(),
            "E004_MISSING_INPUT_FLAG"
        );
        assert_eq!(
            ErrorCode::MissingHomeserver.code(),
            "E005_MISSING_HOMESERVER"
        );
        assert_eq!(ErrorCode::MalformedJson.code(), "E006_MALFORMED_JSON");
        assert_eq!(ErrorCode::DisjointDags.code(), "E007_DISJOINT_DAGS");
        assert_eq!(ErrorCode::IoError.code(), "E008_IO_ERROR");
        assert_eq!(
            ErrorCode::UnsupportedVersion.code(),
            "E009_UNSUPPORTED_VERSION"
        );
        assert_eq!(
            ErrorCode::UnrecognisedStructure.code(),
            "E010_UNRECOGNISED_STRUCTURE"
        );
        assert_eq!(ErrorCode::UnexpectedFormat.code(), "E011_UNEXPECTED_FORMAT");
        assert_eq!(ErrorCode::EventsNotArray.code(), "E012_EVENTS_NOT_ARRAY");
        assert_eq!(ErrorCode::InvalidHeadType.code(), "E013_INVALID_HEAD_TYPE");
        assert_eq!(ErrorCode::NetworkError.code(), "E014_NETWORK_ERROR");
        assert_eq!(ErrorCode::AggregateStale.code(), "E015_AGGREGATE_STALE");
    }

    #[test]
    fn test_error_code_display() {
        let code = ErrorCode::NoCreateEvent;
        assert_eq!(code.to_string(), "E001_NO_CREATE_EVENT");
    }

    #[test]
    fn test_app_error_display() {
        let err = AppError::new(ErrorCode::NoCreateEvent, "test message");
        assert_eq!(err.to_string(), "[E001_NO_CREATE_EVENT] test message");
        assert_eq!(err.code(), ErrorCode::NoCreateEvent);
    }

    #[test]
    fn test_app_error_is_std_error() {
        let err = AppError::new(ErrorCode::EmptyInput, "empty");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_io_errors_have_the_io_error_code() {
        let err = AppError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "input does not exist",
        ));
        assert_eq!(err.code(), ErrorCode::IoError);
    }

    #[test]
    fn test_bail_code_macro() {
        fn do_thing() -> Result<(), AppError> {
            bail_code!(ErrorCode::EmptyInput, "no data in file");
        }
        let err = do_thing().unwrap_err();
        assert_eq!(err.code(), ErrorCode::EmptyInput);
        assert_eq!(err.to_string(), "[E003_EMPTY_INPUT] no data in file");
    }

    #[test]
    fn test_err_macro() {
        let err = err!(ErrorCode::MalformedJson, "line {} col {}", 1, 5);
        assert_eq!(err.code(), ErrorCode::MalformedJson);
        assert_eq!(err.to_string(), "[E006_MALFORMED_JSON] line 1 col 5");
    }
}
