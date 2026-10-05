//! Direct inspection of the BLAKE3 LtHash lattice.
//!
//! `rezzy hash lthash` is a workbench for the accumulator, not another state
//! resolution path: it shows the lattice and the collapsed digest for a set of
//! elements so the homomorphic properties can be checked by hand.

use crate::error::{AppError, ErrorCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Arg, ArgAction, ArgMatches, Command};
use rezzy::state::lthash::LtLattice;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Lane counts `--lanes` accepts.
///
/// Each count is a separate monomorphization of [`LtLattice`], so this is an
/// explicit allowlist rather than an arbitrary runtime width.
const SUPPORTED_LANES: [usize; 5] = [8, 64, 256, 1024, 2048];

/// Which representations of the accumulator to print.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    /// The 32-byte collapsed digest only.
    Digest,
    /// The raw lattice bytes only.
    Lattice,
    /// Both, which is the default so a single run shows the whole picture.
    Both,
}

impl OutputMode {
    /// Parses a `--output` value.
    fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "digest" => Ok(Self::Digest),
            "lattice" => Ok(Self::Lattice),
            "both" => Ok(Self::Both),
            other => Err(AppError::new(
                ErrorCode::UnrecognisedStructure,
                format!("--output must be digest, lattice, or both (got {other})"),
            )),
        }
    }

    /// Whether the collapsed digest belongs in the report.
    const fn wants_digest(self) -> bool {
        matches!(self, Self::Digest | Self::Both)
    }

    /// Whether the raw lattice belongs in the report.
    const fn wants_lattice(self) -> bool {
        matches!(self, Self::Lattice | Self::Both)
    }
}

/// One state element supplied on the command line or in a batch file.
#[derive(Debug)]
struct Element {
    /// The Matrix event type.
    event_type: String,
    /// The state key, which is empty for events without one.
    state_key: String,
    /// The event ID that resolved the state key.
    event_id: String,
}

/// Everything needed to build one accumulator.
struct Plan {
    /// Domain separation tag for every element in this run.
    dst: Vec<u8>,
    /// The state entries read from `--input`, if any.
    state: Vec<Element>,
    /// Ad-hoc state elements from `--event`.
    events: Vec<Element>,
    /// `key=value` field elements from `--field`.
    fields: Vec<(String, String)>,
    /// Raw byte elements from `--raw-bytes`, already decoded.
    raw: Vec<Vec<u8>>,
    /// The requested lane count.
    lanes: usize,
    /// Which representations to print.
    output: OutputMode,
}

impl Plan {
    /// The number of elements that will be summed into the lattice.
    const fn element_count(&self) -> usize {
        self.state
            .len()
            .saturating_add(self.events.len())
            .saturating_add(self.fields.len())
            .saturating_add(self.raw.len())
    }

    /// Whether the run requested any work at all.
    const fn is_empty(&self) -> bool {
        self.state.is_empty()
            && self.events.is_empty()
            && self.fields.is_empty()
            && self.raw.is_empty()
    }
}

/// Builds the `hash` subcommand tree.
#[must_use]
pub fn command() -> Command {
    Command::new("hash")
        .about("Inspect rezzy hashes directly")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("lthash")
                .about("Build a BLAKE3 LtHash lattice and show its digest and raw lanes")
                .arg(
                    Arg::new("input")
                        .long("input")
                        .short('i')
                        .value_parser(clap::value_parser!(PathBuf))
                        .help(
                            "JSON holding state entries: a bare array, {\"resolved_state\": [...]} \
                             as produced by `rezzy -f resolve-state`, or a nested \
                             {\"type\": {\"state_key\": \"$event\"}} state map. '-' reads stdin",
                        ),
                )
                .arg(
                    Arg::new("dst")
                        .long("dst")
                        .value_parser(clap::value_parser!(String))
                        .help(
                            "Override the domain separation tag. Prefix with 'hex:' for raw bytes, \
                             or 'utf-8:' for an explicit UTF-8 tag. Defaults to the state DST",
                        ),
                )
                .arg(
                    Arg::new("event")
                        .long("event")
                        .value_name("TYPE,STATE_KEY,EVENT_ID")
                        .action(ArgAction::Append)
                        .help("Add a state element as CSV; repeat for more"),
                )
                .arg(
                    Arg::new("field")
                        .long("field")
                        .value_name("KEY=VALUE")
                        .action(ArgAction::Append)
                        .help("Add a length-delimited field element; repeat for more"),
                )
                .arg(
                    Arg::new("raw-bytes")
                        .long("raw-bytes")
                        .value_name("HEX")
                        .action(ArgAction::Append)
                        .help("Add a raw byte element as hex; repeat for more"),
                )
                .arg(
                    Arg::new("batch")
                        .long("batch")
                        .value_name("PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("TSV file of type/state_key/event_id rows; '-' reads stdin"),
                )
                .arg(
                    Arg::new("lanes")
                        .long("lanes")
                        .value_parser(clap::value_parser!(usize))
                        .default_value("1024")
                        .help("Lattice width in u16 lanes; one of 8, 64, 256, 1024, 2048"),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('O')
                        .value_parser(clap::value_parser!(String))
                        .default_value("both")
                        .help("What to print: digest, lattice, or both"),
                ),
        )
}

/// Runs the selected hash subcommand.
///
/// # Errors
///
/// Returns an error for an unknown subcommand, a malformed element or state
/// entry, an unreadable input, an unsupported lane count, or a `--dst`/`--output`
/// value that cannot be interpreted.
pub fn run_from_matches(matches: &ArgMatches) -> Result<rezzy::JsonValue, AppError> {
    match matches.subcommand() {
        Some(("lthash", m)) => run_lthash(m),
        _ => Err(AppError::new(
            ErrorCode::MissingInputFlag,
            "choose `lthash`",
        )),
    }
}

fn run_lthash(matches: &ArgMatches) -> Result<rezzy::JsonValue, AppError> {
    let plan = build_plan(matches)?;
    if plan.is_empty() {
        return Err(AppError::new(
            ErrorCode::MissingInputFlag,
            "supply --input, --event, --field, --raw-bytes, or --batch",
        ));
    }

    // Every lane count is a distinct monomorphization, so the width is chosen
    // by expansion rather than passed as a runtime value.
    macro_rules! dispatch {
        ($($lanes:literal),* $(,)?) => {
            match plan.lanes {
                $(
                    $lanes => {
                        let mut hash = LtLattice::<$lanes>::ZERO;
                        hash.insert_batch_with_dst(&plan.dst, plan.state.iter().map(element_triple));
                        for element in &plan.events {
                            hash.add_seed(&LtLattice::<$lanes>::seed_with_dst(
                                &plan.dst,
                                &element.event_type,
                                &element.state_key,
                                &element.event_id,
                            ));
                        }
                        for (key, val) in &plan.fields {
                            hash.add_seed(&LtLattice::<$lanes>::seed_field(
                                &plan.dst,
                                key,
                                val,
                            ));
                        }
                        for bytes in &plan.raw {
                            hash.add_seed(&LtLattice::<$lanes>::seed_bytes(&plan.dst, bytes));
                        }
                        return Ok(report(&hash, &plan));
                    }
                )*
                other => {
                    return Err(AppError::new(
                        ErrorCode::UnrecognisedStructure,
                        format!(
                            "--lanes {other} is not supported; choose one of {}",
                            SUPPORTED_LANES
                                .iter()
                                .map(usize::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }
        };
    }
    dispatch!(8, 64, 256, 1024, 2048);
}

/// Renders a finished accumulator as the requested JSON report.
fn report<const LANES: usize>(hash: &LtLattice<LANES>, plan: &Plan) -> rezzy::JsonValue {
    let mut out = rezzy::json!({
        "dst": String::from_utf8_lossy(&plan.dst).into_owned(),
        "dst_hex": hex(&plan.dst),
        "lanes": LANES,
        "byte_len": LANES.wrapping_mul(2),
        "elements": plan.element_count(),
    });

    if plan.output.wants_digest() {
        let digest = URL_SAFE_NO_PAD.encode(hash.digest());
        let _ = out.insert("digest".to_owned(), rezzy::json!(digest));
    }
    if plan.output.wants_lattice() {
        let _ = out.insert("lattice".to_owned(), rezzy::json!(hex(&hash.to_bytes())));
    }
    out
}

/// The `(event_type, state_key, event_id)` view `insert_batch_with_dst` expects.
const fn element_triple(element: &Element) -> (&str, &str, &str) {
    (
        element.event_type.as_str(),
        element.state_key.as_str(),
        element.event_id.as_str(),
    )
}

fn build_plan(matches: &ArgMatches) -> Result<Plan, AppError> {
    let lanes = *matches.get_one::<usize>("lanes").expect("has a default");
    let output = OutputMode::parse(matches.get_one::<String>("output").expect("has a default"))?;

    let mut state = Vec::new();
    if let Some(path) = matches.get_one::<PathBuf>("input") {
        let text = read_input(path)?;
        state.extend(parse_state(&text)?);
    }
    if let Some(path) = matches.get_one::<PathBuf>("batch") {
        state.extend(read_batch(path)?);
    }

    let mut events = Vec::new();
    if let Some(raw_events) = matches.get_many::<String>("event") {
        for spec in raw_events {
            events.push(parse_event_spec(spec)?);
        }
    }

    let mut fields = Vec::new();
    if let Some(raw_fields) = matches.get_many::<String>("field") {
        for spec in raw_fields {
            let (key, val) = spec.split_once('=').ok_or_else(|| {
                AppError::new(
                    ErrorCode::UnrecognisedStructure,
                    format!("--field {spec} must be KEY=VALUE"),
                )
            })?;
            if key.is_empty() {
                return Err(AppError::new(
                    ErrorCode::EmptyEventType,
                    "--field key must not be empty",
                ));
            }
            fields.push((key.to_owned(), val.to_owned()));
        }
    }

    let mut raw = Vec::new();
    if let Some(raw_hex) = matches.get_many::<String>("raw-bytes") {
        for spec in raw_hex {
            raw.push(decode_hex(spec)?);
        }
    }

    let dst = match matches.get_one::<String>("dst") {
        Some(spec) => parse_dst(spec)?,
        None => rezzy::state::lthash::LtHash::DST.to_vec(),
    };

    Ok(Plan {
        dst,
        state,
        events,
        fields,
        raw,
        lanes,
        output,
    })
}

/// Reads a path, treating `-` as stdin.
fn read_input(path: &Path) -> Result<String, AppError> {
    if path == Path::new("-") {
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        return Ok(buffer);
    }
    std::fs::read_to_string(path).map_err(Into::into)
}

/// Parses a domain separation tag, honouring an explicit encoding prefix.
fn parse_dst(spec: &str) -> Result<Vec<u8>, AppError> {
    if let Some(hex) = spec.strip_prefix("hex:") {
        return decode_hex(hex);
    }
    if let Some(text) = spec.strip_prefix("utf-8:") {
        return Ok(text.as_bytes().to_vec());
    }
    if spec.is_empty() {
        return Err(AppError::new(
            ErrorCode::EmptyEventType,
            "--dst must not be empty",
        ));
    }
    Ok(spec.as_bytes().to_vec())
}

/// Decodes an even-length hex string.
fn decode_hex(spec: &str) -> Result<Vec<u8>, AppError> {
    let cleaned: String = spec.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(AppError::new(
            ErrorCode::UnrecognisedStructure,
            format!("hex input {spec} must have an even number of digits"),
        ));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, AppError> {
    match byte {
        b'0'..=b'9' => Ok(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(byte.wrapping_sub(b'A').wrapping_add(10)),
        other => Err(AppError::new(
            ErrorCode::UnrecognisedStructure,
            format!("{} is not a hex digit", char::from(other)),
        )),
    }
}

/// Renders bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    bytes.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

/// Parses a `TYPE,STATE_KEY,EVENT_ID` element specification.
fn parse_event_spec(spec: &str) -> Result<Element, AppError> {
    let mut parts = spec.splitn(3, ',');
    let event_type = parts.next().unwrap_or_default();
    let state_key = parts.next().ok_or_else(|| {
        AppError::new(
            ErrorCode::UnrecognisedStructure,
            format!("--event {spec} must be TYPE,STATE_KEY,EVENT_ID"),
        )
    })?;
    let event_id = parts.next().ok_or_else(|| {
        AppError::new(
            ErrorCode::UnrecognisedStructure,
            format!("--event {spec} must be TYPE,STATE_KEY,EVENT_ID"),
        )
    })?;
    if event_type.is_empty() {
        return Err(AppError::new(
            ErrorCode::EmptyEventType,
            "--event type must not be empty",
        ));
    }
    Ok(Element {
        event_type: event_type.to_owned(),
        state_key: state_key.to_owned(),
        event_id: event_id.to_owned(),
    })
}

/// Reads a TSV batch file of `type<TAB>state_key<TAB>event_id` rows.
///
/// Blank lines and `#` comments are skipped so hand-written batches stay
/// readable.
fn read_batch(path: &Path) -> Result<Vec<Element>, AppError> {
    let text = read_input(path)?;
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let mut parts = line.split('\t');
        let event_type = parts.next().unwrap_or_default().trim();
        let state_key = parts.next().ok_or_else(|| {
            AppError::new(
                ErrorCode::UnrecognisedStructure,
                format!(
                    "batch line {} needs type, state_key, event_id",
                    index.saturating_add(1)
                ),
            )
        })?;
        let event_id = parts.next().ok_or_else(|| {
            AppError::new(
                ErrorCode::UnrecognisedStructure,
                format!(
                    "batch line {} needs type, state_key, event_id",
                    index.saturating_add(1)
                ),
            )
        })?;
        if parts.next().is_some() {
            return Err(AppError::new(
                ErrorCode::UnrecognisedStructure,
                format!(
                    "batch line {} has more than type, state_key, event_id",
                    index.saturating_add(1)
                ),
            ));
        }
        if event_type.is_empty() {
            return Err(AppError::new(
                ErrorCode::EmptyEventType,
                format!(
                    "batch line {} has an empty event type",
                    index.saturating_add(1)
                ),
            ));
        }
        out.push(Element {
            event_type: event_type.to_owned(),
            state_key: state_key.to_owned(),
            event_id: event_id.to_owned(),
        });
    }
    Ok(out)
}

/// Parses the supported state-entry document shapes into elements.
///
/// Accepted shapes:
/// - `[{"type": ..., "state_key": ..., "event_id": ...}, ...]`
/// - `{"resolved_state": [ ...same entries... ]}` as printed by `rezzy -f resolve-state`
/// - `{"m.room.member": {"@alice:x": "$event"}}`
fn parse_state(text: &str) -> Result<Vec<Element>, AppError> {
    let value = rezzy::JsonValue::parse(text)
        .map_err(|e| AppError::new(ErrorCode::MalformedJson, format!("state input: {e}")))?;

    let entries = match &value {
        rezzy::JsonValue::Array(items) => items.clone(),
        rezzy::JsonValue::Object(obj) => match obj.get("resolved_state") {
            Some(rezzy::JsonValue::Array(items)) => items.clone(),
            _ => return nested_state_map(&value),
        },
        other => {
            return Err(AppError::new(
                ErrorCode::UnexpectedFormat,
                format!(
                    "state input must be an array or object, got {}",
                    kind(other)
                ),
            ));
        }
    };

    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| entry_to_element(entry, index))
        .collect()
}

/// Extracts `type`/`state_key`/`event_id` from one state entry.
fn entry_to_element(entry: &rezzy::JsonValue, index: usize) -> Result<Element, AppError> {
    let event_type = entry["type"]
        .as_str()
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::UnrecognisedStructure,
                format!("state entry {index} needs a string \"type\""),
            )
        })?
        .to_owned();
    if event_type.is_empty() {
        return Err(AppError::new(
            ErrorCode::EmptyEventType,
            format!("state entry {index} has an empty type"),
        ));
    }
    let state_key = entry["state_key"].as_str().unwrap_or_default().to_owned();
    let event_id = entry["event_id"]
        .as_str()
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::UnrecognisedStructure,
                format!("state entry {index} needs a string \"event_id\""),
            )
        })?
        .to_owned();
    Ok(Element {
        event_type,
        state_key,
        event_id,
    })
}

/// Reads the `{"type": {"state_key": "$event"}}` shape, rejecting any entry
/// that does not fit it rather than hashing a partial state.
fn nested_state_map(value: &rezzy::JsonValue) -> Result<Vec<Element>, AppError> {
    let mut out = Vec::new();
    let rezzy::JsonValue::Object(map) = value else {
        return Ok(out);
    };
    for (event_type, inner) in map {
        if event_type.is_empty() {
            return Err(AppError::new(
                ErrorCode::EmptyEventType,
                "state input has an empty event type",
            ));
        }
        let rezzy::JsonValue::Object(entries) = inner else {
            return Err(AppError::new(
                ErrorCode::UnrecognisedStructure,
                format!(
                    "state input \"{event_type}\" must map state keys to event IDs, got {}",
                    kind(inner)
                ),
            ));
        };
        for (state_key, event_id) in entries {
            let Some(event_id) = event_id.as_str() else {
                return Err(AppError::new(
                    ErrorCode::UnrecognisedStructure,
                    format!("state input \"{event_type}\"/\"{state_key}\" needs a string event ID"),
                ));
            };
            out.push(Element {
                event_type: event_type.clone(),
                state_key: state_key.clone(),
                event_id: event_id.to_owned(),
            });
        }
    }
    // `OrdMap` is `BTreeMap`-ordered, so this is already deterministic; the
    // explicit sort keeps that guarantee independent of the input order.
    out.sort_by(|a, b| {
        a.event_type
            .cmp(&b.event_type)
            .then_with(|| a.state_key.cmp(&b.state_key))
    });
    Ok(out)
}

/// The JSON type name of a value, for error messages.
const fn kind(value: &rezzy::JsonValue) -> &'static str {
    match value {
        rezzy::JsonValue::Null => "null",
        rezzy::JsonValue::Bool(_) => "a boolean",
        rezzy::JsonValue::Number(_) => "a number",
        rezzy::JsonValue::String(_) => "a string",
        rezzy::JsonValue::Array(_) => "an array",
        rezzy::JsonValue::Object(_) => "an object",
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{decode_hex, hex, parse_dst, parse_event_spec, parse_state, read_batch};
    use crate::error::ErrorCode;
    use crate::hash::{build_plan, command, run_from_matches, OutputMode};
    use rezzy::state::lthash::LtHash;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A temp directory removed when the guard drops.
    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(name: &str) -> TempDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rezzy-hash-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    /// Parses the `hash` command, keeping the `lthash` subcommand level.
    fn hash_matches(args: &[&str]) -> clap::ArgMatches {
        let mut full = vec!["hash", "lthash"];
        full.extend_from_slice(args);
        command()
            .try_get_matches_from(full)
            .unwrap_or_else(|e| panic!("args should parse: {}", e.kind()))
    }

    /// Parses straight to the `lthash` argument level.
    fn lthash_matches(args: &[&str]) -> clap::ArgMatches {
        hash_matches(args)
            .subcommand()
            .expect("lthash subcommand")
            .1
            .clone()
    }

    fn run(args: &[&str]) -> rezzy::JsonValue {
        run_from_matches(&hash_matches(args)).expect("lthash should succeed")
    }

    fn run_err(args: &[&str]) -> crate::error::AppError {
        run_from_matches(&hash_matches(args)).expect_err("lthash should fail")
    }

    #[test]
    fn empty_accumulator_still_reports_a_digest() {
        let out = run(&["--event", "m.room.create,,"]);
        assert_eq!(out["elements"], rezzy::json!(1));
        assert_eq!(out["lanes"], rezzy::json!(1024));
        assert!(out["digest"].as_str().is_some_and(|d| d.len() == 43));
        // `--output digest` omits the raw lanes entirely.
        let digest_only = run(&["--event", "m.room.create,,", "--output", "digest"]);
        assert!(digest_only["lattice"].is_null());
    }

    #[test]
    fn elements_are_order_independent_and_sum_additively() {
        let a = "--event";
        let first = run(&[a, "m.room.member,@alice:x,$one", a, "m.room.name,,$two"]);
        let second = run(&[a, "m.room.name,,$two", a, "m.room.member,@alice:x,$one"]);
        assert_eq!(first["digest"], second["digest"]);
        assert_eq!(first["lattice"], second["lattice"]);

        // One run of both elements equals the lattice sum of the two runs.
        let one = run(&[a, "m.room.member,@alice:x,$one", "-O", "lattice"]);
        let two = run(&[a, "m.room.name,,$two", "-O", "lattice"]);
        let mut summed = LtHash::ZERO;
        summed.add_seed(&LtHash::seed("m.room.member", "@alice:x", &"$one"));
        summed.add_seed(&LtHash::seed("m.room.name", "", &"$two"));
        assert_eq!(first["lattice"], rezzy::json!(hex(&summed.to_bytes())));
        assert_ne!(one["lattice"].as_str(), two["lattice"].as_str());
    }

    #[test]
    fn dst_changes_the_digest() {
        let base = run(&["--event", "m.room.member,@alice:x,$one"]);
        let tagged = run(&[
            "--event",
            "m.room.member,@alice:x,$one",
            "--dst",
            "utf-8:example.test/v1",
        ]);
        let hexed = run(&[
            "--event",
            "m.room.member,@alice:x,$one",
            "--dst",
            "hex:6578616d706c652e746573742f7631",
        ]);
        assert_ne!(base["digest"], tagged["digest"]);
        // The hex and utf-8 spellings of the same tag must agree.
        assert_eq!(tagged["digest"], hexed["digest"]);
        assert_eq!(tagged["dst"], rezzy::json!("example.test/v1"));
    }

    #[test]
    fn lane_count_changes_the_width_but_not_the_element_count() {
        let out = run(&["--event", "m.room.create,,$c", "--lanes", "8"]);
        assert_eq!(out["lanes"], rezzy::json!(8));
        assert_eq!(out["byte_len"], rezzy::json!(16));
        let wide = run(&["--event", "m.room.create,,$c"]);
        assert_ne!(out["digest"], wide["digest"]);
    }

    #[test]
    fn unsupported_lane_count_is_rejected_with_the_allowed_set() {
        let error = run_err(&["--lanes", "7", "--event", "a,,"]);
        assert!(error.to_string().contains("8, 64, 256, 1024, 2048"));
    }

    #[test]
    fn rejects_a_run_with_no_elements() {
        let error = run_err(&[]);
        assert_eq!(error.code(), ErrorCode::MissingInputFlag);
    }

    #[test]
    fn rejects_malformed_elements() {
        let missing = run_err(&["--event", "m.room.member"]);
        assert_eq!(missing.code(), ErrorCode::UnrecognisedStructure);

        let empty_type = run_err(&["--event", ",,x"]);
        assert_eq!(empty_type.code(), ErrorCode::EmptyEventType);

        let no_equals = run_err(&["--field", "sender"]);
        assert_eq!(no_equals.code(), ErrorCode::UnrecognisedStructure);

        let odd_hex = run_err(&["--raw-bytes", "abc"]);
        assert_eq!(odd_hex.code(), ErrorCode::UnrecognisedStructure);

        let bad_hex = run_err(&["--raw-bytes", "zz"]);
        assert_eq!(bad_hex.code(), ErrorCode::UnrecognisedStructure);
    }

    #[test]
    fn rejects_an_unknown_output_mode() {
        let error = run_err(&["--output", "everything", "--event", "a,,"]);
        assert_eq!(error.code(), ErrorCode::UnrecognisedStructure);
        assert!(OutputMode::parse("digest").is_ok());
        assert!(OutputMode::parse("lattice").is_ok());
        assert!(OutputMode::parse("both").is_ok());
    }

    #[test]
    fn field_and_raw_byte_elements_are_length_delimited() {
        let split = run(&["--field", "ab=c", "--field", "a=bc"]);
        let joined = run(&["--field", "ab=c"]);
        assert_ne!(split["digest"], joined["digest"]);

        // `ab`+`c` must not collide with `a`+`bc`, and the same bytes under a
        // different tag must not collide either.
        let bytes = run(&["--raw-bytes", "0102"]);
        let other_tag = run(&["--raw-bytes", "0102", "--dst", "utf-8:other"]);
        assert_ne!(bytes["digest"], other_tag["digest"]);
        assert_eq!(bytes["elements"], rezzy::json!(1));
    }

    #[test]
    fn field_and_raw_bytes_match_the_library_encodings() {
        let out = run(&["--field", "sender=@alice:example.org"]);
        let expected = LtHash::seed_field(LtHash::DST, "sender", "@alice:example.org");
        assert_eq!(out["digest"], rezzy::json!(b64(&expected.digest())));

        let out = run(&["--raw-bytes", "deadbeef"]);
        let expected = LtHash::seed_bytes(LtHash::DST, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(out["digest"], rezzy::json!(b64(&expected.digest())));
    }

    #[test]
    fn batch_rows_are_summed_like_repeated_events() {
        let dir = temp_dir("batch");
        let path = dir.0.join("rows.tsv");
        std::fs::write(
            &path,
            "# a comment\n\nm.room.member\t@alice:x\t$one\nm.room.name\t\t$two\n",
        )
        .expect("write batch");

        let batched = run(&["--batch", path.to_str().expect("utf-8 path")]);
        let listed = run(&[
            "--event",
            "m.room.member,@alice:x,$one",
            "--event",
            "m.room.name,,$two",
        ]);
        assert_eq!(batched["digest"], listed["digest"]);
        assert_eq!(batched["elements"], rezzy::json!(2));

        let error = read_batch(&dir.0.join("missing.tsv")).expect_err("missing batch should fail");
        assert_eq!(error.code(), ErrorCode::IoError);
    }

    #[test]
    fn reads_every_supported_state_document_shape() {
        let entries = r#"[{"type":"m.room.member","state_key":"@alice:x","event_id":"$one"}]"#;
        let wrapped = r#"{"resolved_state":[{"type":"m.room.member","state_key":"@alice:x","event_id":"$one"}]}"#;
        let nested = r#"{"m.room.member":{"@alice:x":"$one"}}"#;

        let mut digests = Vec::new();
        for text in [entries, wrapped, nested] {
            let dir = temp_dir("state");
            let path = dir.0.join("state.json");
            std::fs::write(&path, text).expect("write state file");
            let out = run(&["--input", path.to_str().expect("utf-8 path")]);
            assert_eq!(out["elements"], rezzy::json!(1));
            digests.push(out["digest"].clone());
        }
        assert_eq!(digests[0], digests[1]);
        assert_eq!(digests[0], digests[2]);

        // A missing state_key defaults to empty rather than failing.
        let no_key = parse_state(r#"[{"type":"m.room.name","event_id":"$n"}]"#)
            .expect("state_key is optional");
        assert_eq!(no_key[0].state_key, "");
        assert!(parse_state("42").is_err());
    }

    #[test]
    fn plan_records_the_requested_shape() {
        let matches = lthash_matches(&[
            "--event",
            "m.room.member,@alice:x,$one",
            "--field",
            "a=b",
            "--raw-bytes",
            "00",
            "--lanes",
            "64",
        ]);
        let plan = build_plan(&matches).expect("plan builds");
        assert_eq!(plan.element_count(), 3);
        assert_eq!(plan.lanes, 64);
        assert_eq!(plan.dst, LtHash::DST);
        assert!(!plan.is_empty());
    }

    #[test]
    fn unit_helpers_handle_encoding_edges() {
        assert_eq!(
            decode_hex("00 ff\n10").expect("whitespace ok"),
            vec![0, 255, 16]
        );
        assert_eq!(
            decode_hex("DEADbeef").expect("case ok"),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(parse_dst("plain").expect("plain tag"), b"plain".to_vec());
        assert_eq!(parse_dst("hex:00ff").expect("hex tag"), vec![0, 255]);
        assert_eq!(parse_dst("utf-8:tag").expect("utf-8 tag"), b"tag".to_vec());
        assert!(parse_dst("").is_err());
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");

        let spec = parse_event_spec("m.room.member,@alice:x,$one").expect("csv spec");
        assert_eq!(spec.event_type, "m.room.member");
        assert_eq!(spec.state_key, "@alice:x");
        assert_eq!(spec.event_id, "$one");

        // A spec may itself contain commas; only the first two split.
        let comma = parse_event_spec("m.room.message,a,b,$ev").expect("extra comma");
        assert_eq!(comma.state_key, "a");
        assert_eq!(comma.event_id, "b,$ev");
    }

    fn b64(bytes: &[u8; 32]) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.encode(bytes)
    }
}
