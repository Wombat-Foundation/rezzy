//! Signed Matrix server-server requests and the remote DAG crawler.

use crate::error::{AppError, ErrorCode};
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use clap::{Arg, ArgAction, ArgMatches, Command};
use ed25519_dalek::{Signer, SigningKey};
use rezzy::JsonValue;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Connect timeout for outbound federation requests, so a flapping or
/// unreachable destination fails fast instead of hanging in `SYN-SENT`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall timeout for outbound federation requests (connect + transfer).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Process-wide `ureq` agent with the federation timeouts applied.
///
/// Request-level `.timeout_connect()` is ignored by `ureq`'s global agent, so
/// the timeouts must be configured on an explicit agent.
fn federation_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
    })
}

#[must_use]
/// Builds the federation subcommand-line interface.
pub fn command() -> Command {
    Command::new("federation")
        .about("Make signed Matrix server-server requests")
        .subcommand(
            Command::new("request")
                .about("Send one generic signed federation request")
                .arg(origin_arg())
                .arg(Arg::new("destination").long("destination").required(true))
                .arg(Arg::new("method").long("method").default_value("GET"))
                .arg(Arg::new("path").long("path").required(true))
                .arg(
                    Arg::new("body")
                        .long("body")
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .args(signing_key_args()),
        )
        .subcommand(
            Command::new("get-remote-dag")
                .about("Crawl a remote room DAG over federation")
                .arg(origin_arg())
                .arg(Arg::new("destination").long("destination").required(true))
                .arg(Arg::new("room").long("room").required(true))
                .arg(
                    Arg::new("from")
                        .long("from")
                        .action(ArgAction::Append)
                        .help("Starting event ID; repeatable"),
                )
                .arg(
                    Arg::new("from-file")
                        .long("from-file")
                        .action(ArgAction::Append)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("File of newline-delimited seed event IDs; '-' reads stdin"),
                )
                .arg(
                    Arg::new("emit-missing")
                        .long("emit-missing")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Write the unresolved frontier event IDs, one per line; '-' writes stdout"),
                )
                .arg(
                    Arg::new("room-version")
                        .long("room-version")
                        .default_value("12"),
                )
                .arg(
                    Arg::new("limit")
                        .long("limit")
                        .default_value("-1")
                        .allow_negative_numbers(true)
                        .value_parser(clap::value_parser!(i64)),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .default_value("remote-dag.jsonl")
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .args(signing_key_args())
                .arg(
                    Arg::new("no-fallback")
                        .long("no-fallback")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("gap-fill")
                .about("Fetch missing room DAG and authentication events in bounded rounds")
                .arg(
                    Arg::new("input")
                        .long("input")
                        .short('i')
                        .required(true)
                        .num_args(1..)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(Arg::new("destination").long("destination").required(true))
                .arg(Arg::new("room").long("room").required(true))
                .arg(
                    Arg::new("output-dir")
                        .long("output-dir")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg(Arg::new("origin").long("origin").env("MATRIX_ORIGIN").default_value("matrix.org"))
                .arg(Arg::new("room-version").long("room-version").default_value("12"))
                .arg(
                    Arg::new("rounds")
                        .long("rounds")
                        .default_value("5")
                        .value_parser(clap::value_parser!(u32))
                        .help("Maximum fetch rounds; 0 means continue until closed or no progress"),
                )
                .args(signing_key_args())
                .arg(Arg::new("no-fallback").long("no-fallback").action(ArgAction::SetTrue)),
        )
}

fn origin_arg() -> Arg {
    Arg::new("origin")
        .long("origin")
        .env("MATRIX_ORIGIN")
        .default_value("matrix.org")
}

fn signing_key_args() -> [Arg; 2] {
    [
        Arg::new("signing-key")
            .long("signing-key")
            .value_parser(clap::value_parser!(PathBuf)),
        Arg::new("signing-key-keyring").long("signing-key-keyring"),
    ]
}

/// Runs the selected federation subcommand.
///
/// # Errors
/// Returns an error when arguments, credentials, or the remote request are invalid.
///
/// # Panics
/// Panics if a required default argument is absent from a parsed subcommand.
pub fn run_from_matches(matches: &ArgMatches) -> Result<JsonValue, AppError> {
    if let Some(("request" | "get-remote-dag" | "gap-fill", m)) = matches.subcommand() {
        let origin = m.get_one::<String>("origin").expect("default");
        load_signing_key(
            origin,
            m.get_one::<PathBuf>("signing-key").map(PathBuf::as_path),
            m.get_one::<String>("signing-key-keyring")
                .map(String::as_str),
        )?;
    }
    match matches.subcommand() {
        Some(("request", m)) => {
            let body = if let Some(path) = m.get_one::<PathBuf>("body") {
                JsonValue::parse_bytes(&fs::read(path)?)?
            } else {
                rezzy::json!({})
            };
            request(
                m.get_one::<String>("origin").expect("default"),
                m.get_one::<String>("destination").expect("required"),
                m.get_one::<String>("method").expect("default"),
                m.get_one::<String>("path").expect("required"),
                &body,
                m.get_one::<PathBuf>("signing-key").map(PathBuf::as_path),
                m.get_one::<String>("signing-key-keyring")
                    .map(String::as_str),
            )
        }
        Some(("get-remote-dag", m)) => {
            let mut starts = m
                .get_many::<String>("from")
                .map(|ids| ids.cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            if let Some(files) = m.get_many::<PathBuf>("from-file") {
                for path in files {
                    starts.extend(crate::repair::read_event_ids(path)?);
                }
            }
            get_remote_dag(
                m.get_one::<String>("origin").expect("default"),
                m.get_one::<String>("destination").expect("required"),
                m.get_one::<String>("room").expect("required"),
                &starts,
                m.get_one::<String>("room-version").expect("default"),
                *m.get_one::<i64>("limit").expect("default"),
                m.get_one::<PathBuf>("output").expect("default"),
                m.get_one::<PathBuf>("signing-key").map(PathBuf::as_path),
                m.get_one::<String>("signing-key-keyring")
                    .map(String::as_str),
                m.get_flag("no-fallback"),
                m.get_one::<PathBuf>("emit-missing").map(PathBuf::as_path),
            )
        }
        Some(("gap-fill", m)) => {
            let inputs = m
                .get_many::<PathBuf>("input")
                .expect("required")
                .cloned()
                .collect::<Vec<_>>();
            gap_fill(
                &inputs,
                m.get_one::<String>("origin").expect("default"),
                m.get_one::<String>("destination").expect("required"),
                m.get_one::<String>("room").expect("required"),
                m.get_one::<String>("room-version").expect("default"),
                *m.get_one::<u32>("rounds").expect("default"),
                m.get_one::<PathBuf>("output-dir").expect("required"),
                m.get_one::<PathBuf>("signing-key").map(PathBuf::as_path),
                m.get_one::<String>("signing-key-keyring")
                    .map(String::as_str),
                m.get_flag("no-fallback"),
            )
        }
        _ => Err(AppError::new(
            ErrorCode::MissingInputFlag,
            "choose `request`, `get-remote-dag`, or `gap-fill`",
        )),
    }
}

/// Credentials used to authenticate federation requests.
#[derive(Debug, Clone)]
pub struct SigningKeySpec {
    /// The key identifier used for signing.
    pub key_id: String,
    /// The parsed signing key.
    pub key: SigningKey,
}

fn domain_env_suffix(domain: &str) -> String {
    let domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(domain)
        .split(':')
        .next()
        .unwrap_or(domain);
    domain.to_ascii_uppercase().replace(['.', '-'], "_")
}

/// Resolve and parse a Matrix server signing key from the OS keyring.
///
/// Private key files and `MATRIX_SERVER_SIGNING_KEY` are intentionally not
/// accepted: federation credentials must be stored through the OS keyring.
///
/// # Errors
/// Returns an error when no usable key is configured or the configured key is invalid.
pub fn load_signing_key(
    origin: &str,
    explicit: Option<&Path>,
    keyring_account: Option<&str>,
) -> Result<SigningKeySpec, AppError> {
    let keyring_account = keyring_account
        .map(str::to_owned)
        .or_else(|| {
            std::env::var(format!(
                "MATRIX_SERVER_SIGNING_KEY_KEYRING_{}",
                domain_env_suffix(origin)
            ))
            .ok()
        })
        .or_else(|| std::env::var("MATRIX_SERVER_SIGNING_KEY_KEYRING").ok());
    if let Some(account) = keyring_account {
        let cache_key = (origin.to_owned(), account.clone());
        if let Ok(cache) = signing_key_cache().lock() {
            if let Some(spec) = cache.get(&cache_key) {
                return Ok(spec.clone());
            }
        }
        let entry = keyring::Entry::new("rezzy", &account).map_err(|e| {
            AppError::new(
                ErrorCode::SigningKey,
                format!("failed to open OS keyring entry rezzy/{account}: {e}"),
            )
        })?;
        let text = entry.get_password().map_err(|e| {
            AppError::new(
                ErrorCode::SigningKey,
                format!("failed to read OS keyring entry rezzy/{account}: {e}"),
            )
        })?;
        let spec = parse_signing_key(&text).map_err(|message| {
            AppError::new(
                ErrorCode::SigningKey,
                format!("OS keyring entry rezzy/{account}: {message}"),
            )
        })?;
        if let Ok(mut cache) = signing_key_cache().lock() {
            cache.insert(cache_key, spec.clone());
        }
        return Ok(spec);
    }

    let legacy_file_configured = explicit.is_some()
        || std::env::var(format!(
            "MATRIX_SERVER_SIGNING_KEY_{}",
            domain_env_suffix(origin)
        ))
        .is_ok()
        || std::env::var("MATRIX_SERVER_SIGNING_KEY").is_ok();
    let detail = if legacy_file_configured {
        "plaintext signing-key files and MATRIX_SERVER_SIGNING_KEY are not accepted"
    } else {
        "no OS keyring account configured"
    };
    Err(AppError::new(
        ErrorCode::SigningKey,
        format!(
            "{detail}; set MATRIX_SERVER_SIGNING_KEY_KEYRING_{} or MATRIX_SERVER_SIGNING_KEY_KEYRING",
            domain_env_suffix(origin)
        ),
    ))
}

fn parse_signing_key(text: &str) -> Result<SigningKeySpec, String> {
    let mut fields = text.split_whitespace().filter(|s| !s.starts_with('#'));
    let first = fields.next().ok_or("signing key file is empty")?;
    let (key_id, encoded) = if first.starts_with("ed25519:") {
        (
            first.to_owned(),
            fields.next().ok_or("missing private key")?,
        )
    } else if first == "ed25519" {
        (
            format!("ed25519:{}", fields.next().ok_or("missing key ID")?),
            fields.next().ok_or("missing private key")?,
        )
    } else {
        ("ed25519:0".to_owned(), first)
    };
    let bytes = STANDARD_NO_PAD
        .decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|e| format!("invalid base64 private key: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "private key must decode to 32 bytes".to_owned())?;
    Ok(SigningKeySpec {
        key_id,
        key: SigningKey::from_bytes(&bytes),
    })
}

fn canonical_request(
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    body: &JsonValue,
) -> Result<Vec<u8>, AppError> {
    let mut value =
        rezzy::json!({"method": method, "uri": uri, "origin": origin, "destination": destination});
    if !(method.eq_ignore_ascii_case("GET") && matches!(body, JsonValue::Object(o) if o.is_empty()))
    {
        let _ = value.insert("content".to_owned(), body.clone());
    }
    rezzy::json::write_string_value(&value)
        .map(std::string::String::into_bytes)
        .map_err(|e| AppError::new(ErrorCode::NetworkError, e.to_string()))
}

/// Cache of logical server name -> resolved `https://host[:port]` endpoint.
fn delegation_cache() -> &'static Mutex<BTreeMap<String, String>> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Process-wide cache of parsed signing keys, keyed by `(origin, account)`.
///
/// Each `(origin, account)` keyring value is read once per process. Changes to
/// the keyring take effect after restarting the CLI.
fn signing_key_cache() -> &'static Mutex<BTreeMap<(String, String), SigningKeySpec>> {
    static CACHE: OnceLock<Mutex<BTreeMap<(String, String), SigningKeySpec>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Resolve a Matrix server name to its federation endpoint, honoring
/// server-server delegation: `/.well-known/matrix/server` first, then DNS SRV
/// (`_matrix-fed._tcp`, then the legacy `_matrix._tcp`).
///
/// Returns `None` when delegation does not apply (explicit scheme/port) or no
/// delegation record is found, in which case callers fall back to the literal
/// host on port 8448.
fn resolve_delegation(destination: &str) -> Option<String> {
    if destination.contains(':') {
        return None;
    }
    if let Ok(cache) = delegation_cache().lock() {
        if let Some(cached) = cache.get(destination) {
            return Some(cached.clone());
        }
    }
    let resolved = well_known_lookup(destination).or_else(|| srv_lookup(destination));
    if let Some(ref endpoint) = resolved {
        eprintln!("[info] federation delegation: {destination} -> {endpoint}");
        if let Ok(mut cache) = delegation_cache().lock() {
            cache.insert(destination.to_owned(), endpoint.clone());
        }
    }
    resolved
}

/// Query `_matrix-fed._tcp` / `_matrix._tcp` SRV records via the system
/// resolver (`dig`). Best effort: absent `dig` or no record yields `None`.
fn srv_lookup(destination: &str) -> Option<String> {
    for service in ["_matrix-fed._tcp", "_matrix._tcp"] {
        let name = format!("{service}.{destination}");
        if let Some((target, port)) = dig_srv(&name) {
            return Some(format!("https://{target}:{port}"));
        }
    }
    None
}

fn dig_srv(name: &str) -> Option<(String, u16)> {
    let output = std::process::Command::new("dig")
        .args(["+short", "SRV", name])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut best: Option<(u16, String, u16)> = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(priority), Some(_weight), Some(port), Some(target)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(priority), Ok(port)) = (priority.parse::<u16>(), port.parse::<u16>()) else {
            continue;
        };
        if best
            .as_ref()
            .map_or(true, |(best_priority, _, _)| priority < *best_priority)
        {
            best = Some((priority, target.trim_end_matches('.').to_owned(), port));
        }
    }
    best.map(|(_, target, port)| (target, port))
}

/// Fetch `https://<destination>/.well-known/matrix/server` and use `m.server`.
fn well_known_lookup(destination: &str) -> Option<String> {
    let url = format!("https://{destination}/.well-known/matrix/server");
    let response = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .call()
        .ok()?;
    let body = response.into_string().ok()?;
    let value = JsonValue::parse(&body).ok()?;
    let delegated = value.get("m.server")?.as_str()?;
    if delegated.is_empty() {
        return None;
    }
    if delegated.contains(':') {
        Some(format!("https://{delegated}"))
    } else {
        // Per the spec, `m.server` without a port defaults to 8448.
        Some(format!("https://{delegated}:8448"))
    }
}

fn base_url(destination: &str) -> String {
    if destination.starts_with("http://") || destination.starts_with("https://") {
        destination.trim_end_matches('/').to_owned()
    } else if let Some(endpoint) = resolve_delegation(destination) {
        endpoint
    } else {
        format!("https://{destination}:8448")
    }
}

/// Send one signed federation request. Keyring values are cached per process.
///
/// # Errors
/// Returns an error if credentials cannot be loaded or the signed request fails.
pub fn request(
    origin: &str,
    destination: &str,
    method: &str,
    uri: &str,
    body: &JsonValue,
    key_path: Option<&Path>,
    keyring_account: Option<&str>,
) -> Result<JsonValue, AppError> {
    let key = load_signing_key(origin, key_path, keyring_account)?;
    let canonical = canonical_request(method, uri, origin, destination, body)?;
    let sig = STANDARD_NO_PAD.encode(key.key.sign(&canonical).to_bytes());
    let auth = format!(
        "X-Matrix origin=\"{origin}\",destination=\"{destination}\",key=\"{}\",sig=\"{sig}\"",
        key.key_id
    );
    let url = format!("{}{uri}", base_url(destination));
    #[cfg(not(feature = "tls"))]
    if url.starts_with("https://") {
        return Err(AppError::new(
            ErrorCode::NetworkError,
            "HTTPS request requires the `tls` feature; rebuild rezzy-cli with `--features tls` or use http://",
        ));
    }
    let agent = federation_agent();
    let mut req = match method.to_ascii_uppercase().as_str() {
        "GET" => agent.get(&url),
        "POST" => agent.post(&url),
        "PUT" => agent.put(&url),
        "DELETE" => agent.delete(&url),
        other => {
            return Err(AppError::new(
                ErrorCode::NetworkError,
                format!("unsupported HTTP method {other}"),
            ))
        }
    };
    req = req
        .set("Authorization", &auth)
        .set("User-Agent", crate::USER_AGENT)
        .set("Content-Type", "application/json");
    let result = if method.eq_ignore_ascii_case("GET")
        && matches!(body, JsonValue::Object(o) if o.is_empty())
    {
        req.call()
    } else {
        let body_text = rezzy::json::write_string_value(body)
            .map_err(|e| AppError::new(ErrorCode::NetworkError, e.to_string()))?;
        req.send_string(&body_text)
    };
    let response = match result {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let detail = r.into_string().unwrap_or_default();
            return Err(AppError::new(
                ErrorCode::NetworkError,
                format!("HTTP {code} from {destination}: {detail}"),
            ));
        }
        Err(e) => return Err(AppError::new(ErrorCode::RemoteUnavailable, e.to_string())),
    };
    let text = response
        .into_string()
        .map_err(|e| AppError::new(ErrorCode::NetworkError, e.to_string()))?;
    JsonValue::parse(&text).map_err(|e| {
        AppError::new(
            ErrorCode::NetworkError,
            format!("invalid JSON response: {e}"),
        )
    })
}

fn quote(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Open `output` for writing, creating its parent directory when needed.
fn open_output_writer(output: &Path) -> Result<BufWriter<fs::File>, AppError> {
    if let Some(parent) = output.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    Ok(BufWriter::new(fs::File::create(output)?))
}

/// Whether `err` means the destination never answered (connect/DNS/TLS/
/// timeout) as opposed to an HTTP status it actively returned.
fn is_unreachable(err: &AppError) -> bool {
    err.code() == ErrorCode::RemoteUnavailable
}

/// Crawl a remote room DAG by repeatedly fetching frontier `prev_events`.
///
/// When `emit_missing` is set the unresolved frontier is written there as one
/// event ID per line, so a later crawl can resume with `--from-file`.
///
/// # Errors
/// Returns an error if inputs cannot be read, requests fail, or outputs cannot be written.
pub fn get_remote_dag(
    origin: &str,
    destination: &str,
    room_id: &str,
    starts: &[String],
    room_version: &str,
    limit: i64,
    output: &Path,
    key_path: Option<&Path>,
    keyring_account: Option<&str>,
    no_fallback: bool,
    emit_missing: Option<&Path>,
) -> Result<JsonValue, AppError> {
    if starts.is_empty() {
        return Err(AppError::new(
            ErrorCode::MissingInputFlag,
            "get-remote-dag needs at least one --from <event-id> or --from-file <path> (the CLI has no local timeline to infer a starting event)",
        ));
    }
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    for id in starts {
        if queued.insert(id.clone()) {
            queue.push_back(id.clone());
        }
    }
    let mut seen = HashSet::new();
    let mut output_writer = open_output_writer(output)?;
    let mut event_count = 0_usize;
    let mut failures = FetchFailures::default();
    let mut unresolved = Vec::new();
    let max = if limit < 0 {
        usize::MAX
    } else {
        usize::try_from(limit).unwrap_or(usize::MAX)
    };
    while !queue.is_empty() && seen.len() < max {
        let mut ids = Vec::new();
        while ids.len() < 50 {
            if let Some(id) = queue.pop_front() {
                if !seen.contains(&id) {
                    ids.push(id);
                }
            } else {
                break;
            }
        }
        if ids.is_empty() {
            continue;
        }
        let uri = format!(
            "/_matrix/federation/v1/backfill/{}?{}&limit=500",
            quote(room_id),
            ids.iter()
                .map(|id| format!("v={}", quote(id)))
                .collect::<Vec<_>>()
                .join("&")
        );
        let response = request(
            origin,
            destination,
            "GET",
            &uri,
            &rezzy::json!({}),
            key_path,
            keyring_account,
        );
        let mut value = match response {
            Ok(v) => v,
            // The destination never answered: per-event fallback cannot help,
            // and retrying thousands of IDs just turns a fast failure into a
            // multi-hour hang. Abort the whole crawl immediately.
            Err(e) if is_unreachable(&e) => return Err(e),
            Err(e) if !no_fallback => {
                failures.record(&e);
                unresolved.extend(ids.iter().cloned());
                let Some(id) = queue.pop_front() else {
                    continue;
                };
                let event_uri = format!("/_matrix/federation/v1/event/{}", quote(&id));
                match request(
                    origin,
                    destination,
                    "GET",
                    &event_uri,
                    &rezzy::json!({}),
                    key_path,
                    keyring_account,
                ) {
                    Ok(v) => {
                        let pdu = v.get("pdu").cloned().unwrap_or(v);
                        rezzy::json!({"pdus":[pdu]})
                    }
                    Err(e) if is_unreachable(&e) => return Err(e),
                    Err(e) => {
                        failures.record(&e);
                        continue;
                    }
                }
            }
            Err(e) => return Err(e),
        };
        let empty_backfill = value
            .get("pdus")
            .and_then(JsonValue::as_array)
            .map_or(true, Vec::is_empty);
        if empty_backfill && no_fallback {
            unresolved.extend(ids.iter().cloned());
            break;
        }
        if empty_backfill {
            unresolved.extend(ids.iter().cloned());
            if let Some(id) = queue.pop_front() {
                let event_uri = format!("/_matrix/federation/v1/event/{}", quote(&id));
                match request(
                    origin,
                    destination,
                    "GET",
                    &event_uri,
                    &rezzy::json!({}),
                    key_path,
                    keyring_account,
                ) {
                    Ok(event) => {
                        let pdu = event.get("pdu").cloned().unwrap_or(event);
                        value = rezzy::json!({"pdus":[pdu]});
                    }
                    Err(e) if is_unreachable(&e) => return Err(e),
                    Err(e) => {
                        failures.record(&e);
                        unresolved.push(id);
                    }
                }
            }
        }
        let Some(pdus) = value.get("pdus").and_then(JsonValue::as_array) else {
            continue;
        };
        for pdu in pdus {
            let Some(object) = pdu.as_object() else {
                continue;
            };
            let event_id = object
                .get("event_id")
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    rezzy::reference_hash(pdu, room_version)
                        .ok()
                        .map(|h| format!("${h}"))
                });
            let Some(event_id) = event_id else { continue };
            if !seen.insert(event_id.clone()) {
                continue;
            }
            let mut line = pdu.clone();
            if let Some(obj) = line.as_object_mut() {
                obj.insert("event_id".to_owned(), JsonValue::String(event_id));
            }
            if let Some(prev) = line.get("prev_events").and_then(JsonValue::as_array) {
                for item in prev {
                    let id = item.as_str().or_else(|| {
                        item.as_array()
                            .and_then(|a| a.first())
                            .and_then(JsonValue::as_str)
                    });
                    if let Some(id) = id {
                        if !seen.contains(id) && queued.insert(id.to_owned()) {
                            queue.push_back(id.to_owned());
                        }
                    }
                }
            }
            let encoded = rezzy::json::write_string_value(&line)
                .map_err(|e| AppError::new(ErrorCode::MalformedJson, e.to_string()))?;
            writeln!(output_writer, "{encoded}")?;
            event_count = event_count.saturating_add(1);
            if seen.len() >= max {
                break;
            }
        }

        // Make the fetched events durable before advancing the checkpoint.
        // If interrupted after this point, re-fetching the checkpointed
        // frontier is safe because aggregate deduplicates event IDs.
        output_writer.flush()?;
        let frontier = queue
            .iter()
            .filter(|id| !seen.contains(*id))
            .cloned()
            .chain(unresolved.iter().filter(|id| !seen.contains(*id)).cloned())
            .collect::<Vec<_>>();
        if let Some(path) = emit_missing.filter(|path| *path != Path::new("-")) {
            write_frontier_checkpoint(path, &frontier)?;
        }
    }
    output_writer.flush()?;
    if event_count == 0 && !failures.is_empty() {
        return Err(AppError::new(
            ErrorCode::NetworkError,
            format!(
                "no events fetched from {destination} for {room_id}: {}",
                failures.summary()
            ),
        ));
    }
    let remaining_frontier = queue
        .into_iter()
        .chain(unresolved)
        .filter(|id| !seen.contains(id))
        .collect::<Vec<_>>();
    if let Some(path) = emit_missing {
        crate::repair::write_event_ids(path, &remaining_frontier)?;
    }
    let mut result = rezzy::json!({
        "count": event_count,
        "output": output.display().to_string(),
        "remaining_frontier": remaining_frontier,
    });
    if !failures.is_empty() {
        let _ = result.insert(
            String::from("failed_requests"),
            rezzy::json!(failures.total() as u64),
        );
        let _ = result.insert(String::from("failures"), rezzy::json!(failures.summary()));
    }
    if let Some(path) = emit_missing {
        let _ = result.insert(
            String::from("missing_output"),
            rezzy::json!(path.to_string_lossy().to_string()),
        );
    }
    Ok(result)
}

/// Fetch missing timeline and authentication references for a bounded number
/// of rounds. This intentionally writes fetched batches separately; callers
/// can inspect or aggregate them without mutating the original input.
fn gap_fill(
    inputs: &[PathBuf],
    origin: &str,
    destination: &str,
    room_id: &str,
    room_version: &str,
    rounds: u32,
    output_dir: &Path,
    key_path: Option<&Path>,
    keyring_account: Option<&str>,
    no_fallback: bool,
) -> Result<JsonValue, AppError> {
    fs::create_dir_all(output_dir)?;
    let mut events = Vec::new();
    for input in inputs {
        events.extend(crate::repair::read_jsonl_events(input)?);
    }

    let mut fetched = Vec::new();
    let mut completed_rounds = 0_u32;
    let mut failed_requests = 0_usize;
    let mut closed = false;
    let mut round = 0_u32;
    loop {
        if rounds != 0 && round >= rounds {
            break;
        }
        let report = crate::repair::scan_gaps(&events);
        if report.is_closed() {
            closed = true;
            break;
        }
        let before = report.present.len();
        let round_dir = output_dir.join(format!("round-{round:03}"));
        fs::create_dir_all(&round_dir)?;

        if !report.missing_prev.is_empty() {
            let path = round_dir.join("backfill.jsonl");
            let starts = report.missing_prev.iter().cloned().collect::<Vec<_>>();
            let summary = get_remote_dag(
                origin,
                destination,
                room_id,
                &starts,
                room_version,
                -1,
                &path,
                key_path,
                keyring_account,
                no_fallback,
                None,
            )?;
            if let Some(n) = summary.get("failed_requests").and_then(JsonValue::as_u64) {
                failed_requests =
                    failed_requests.saturating_add(usize::try_from(n).unwrap_or(usize::MAX));
                if let Some(detail) = summary.get("failures").and_then(JsonValue::as_str) {
                    eprintln!("[warn] round {round}: {n} backfill request(s) failed: {detail}");
                }
            }
            let backfilled = summary
                .get("count")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0);
            if backfilled > 0 {
                fetched.push(path.clone());
                events.extend(crate::repair::read_jsonl_events(&path)?);
            }
        }

        let report = crate::repair::scan_gaps(&events);
        if !report.missing_auth.is_empty() {
            let path = round_dir.join("auth.jsonl");
            let (count, failures) = fetch_auth_batches(
                origin,
                destination,
                room_id,
                &report,
                &path,
                key_path,
                keyring_account,
            )?;
            if !failures.is_empty() {
                failed_requests = failed_requests.saturating_add(failures.total());
                eprintln!(
                    "[warn] round {round}: {} auth-chain request(s) failed: {}",
                    failures.total(),
                    failures.summary()
                );
            }
            if count > 0 {
                fetched.push(path.clone());
                events.extend(crate::repair::read_jsonl_events(&path)?);
            }
        }

        let after = crate::repair::scan_gaps(&events).present.len();
        round = round.saturating_add(1);
        completed_rounds = round;
        if after <= before {
            break;
        }
    }
    let final_report = crate::repair::scan_gaps(&events);
    if final_report.is_closed() {
        closed = true;
    }
    Ok(rezzy::json!({
        "status": if closed { "closed" } else { "incomplete" },
        "rounds": completed_rounds,
        "events": final_report.present.len(),
        "missing_prev_events": final_report.missing_prev.iter().cloned().collect::<Vec<_>>(),
        "missing_auth_events": final_report.missing_auth.iter().cloned().collect::<Vec<_>>(),
        "failed_requests": failed_requests,
        "fetched": fetched.iter().map(|path| path.to_string_lossy().to_string()).collect::<Vec<_>>(),
    }))
}

/// Aggregated federation request failures, grouped by stable error code.
///
/// One round can fail many requests for the same reason (for example an
/// untrusted origin), so failures are folded into a single summary instead of
/// one warning per request. The first full message is retained as context.
#[derive(Debug, Default, PartialEq, Eq)]
struct FetchFailures {
    by_code: BTreeMap<&'static str, usize>,
    first: Option<String>,
}

impl FetchFailures {
    fn record(&mut self, error: &AppError) {
        let count = self.by_code.entry(error.code().code()).or_default();
        *count = count.saturating_add(1);
        if self.first.is_none() {
            self.first = Some(error.to_string());
        }
    }

    fn total(&self) -> usize {
        self.by_code.values().sum()
    }

    fn is_empty(&self) -> bool {
        self.by_code.is_empty()
    }

    fn summary(&self) -> String {
        let mut parts = self
            .by_code
            .iter()
            .map(|(code, count)| format!("{count} x {code}"))
            .collect::<Vec<_>>();
        parts.sort();
        let detail = self.first.as_deref().unwrap_or("unknown error");
        format!("{} (first: {detail})", parts.join(", "))
    }
}

fn fetch_auth_batches(
    origin: &str,
    destination: &str,
    room_id: &str,
    report: &crate::repair::GapReport,
    output: &Path,
    key_path: Option<&Path>,
    keyring_account: Option<&str>,
) -> Result<(usize, FetchFailures), AppError> {
    let mut referencing = std::collections::BTreeSet::new();
    for reference in &report.references {
        if reference.kind == crate::repair::ReferenceKind::AuthEvents {
            referencing.insert(reference.event_id.clone());
        }
    }
    let mut output_writer = open_output_writer(output)?;
    let mut seen = HashSet::new();
    let mut failures = FetchFailures::default();
    let mut written = 0_usize;
    for event_id in referencing {
        let uri = format!(
            "/_matrix/federation/v1/event_auth/{}/{}",
            quote(room_id),
            quote(&event_id)
        );
        let value = match request(
            origin,
            destination,
            "GET",
            &uri,
            &rezzy::json!({}),
            key_path,
            keyring_account,
        ) {
            Ok(value) => value,
            Err(error) => {
                failures.record(&error);
                continue;
            }
        };
        for field in ["auth_chain", "pdus"] {
            let Some(items) = value.get(field).and_then(JsonValue::as_array) else {
                continue;
            };
            for item in items {
                let Some(id) = crate::repair::event_id_of(item) else {
                    continue;
                };
                if seen.insert(id) {
                    let encoded = rezzy::json::write_string_value(item)
                        .map_err(|e| AppError::new(ErrorCode::MalformedJson, e.to_string()))?;
                    writeln!(output_writer, "{encoded}")?;
                    written = written.saturating_add(1);
                }
            }
        }
        // Flush after every response so an interrupted crawl keeps the auth
        // chains it already fetched.
        output_writer.flush()?;
    }
    output_writer.flush()?;
    Ok((written, failures))
}

/// Atomically replace the crawl frontier checkpoint.
///
/// The checkpoint is written to a sibling temp file and renamed into place, so
/// a crash never leaves a truncated checkpoint that a resume would trust. It is
/// only advanced after the corresponding backfill events have been flushed.
fn write_frontier_checkpoint(path: &Path, frontier: &[String]) -> Result<(), AppError> {
    let mut text = String::new();
    for id in frontier {
        text.push_str(id);
        text.push('\n');
    }
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    fs::write(&temp, text)?;
    fs::rename(&temp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{domain_env_suffix, parse_signing_key, AppError, ErrorCode, FetchFailures};

    #[test]
    fn domain_environment_names_match_token_convention() {
        assert_eq!(
            domain_env_suffix("https://matrix.example:8448"),
            "MATRIX_EXAMPLE"
        );
        assert_eq!(domain_env_suffix("unredacted.org"), "UNREDACTED_ORG");
    }

    #[test]
    fn parses_common_matrix_key_file_format() {
        let key =
            parse_signing_key("ed25519:7 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(key.key_id, "ed25519:7");
    }

    #[test]
    fn fetch_failures_collapse_repeated_errors_into_one_summary() {
        let mut failures = FetchFailures::default();
        for _ in 0..5 {
            failures.record(&AppError::new(ErrorCode::NetworkError, "HTTP 401"));
        }
        failures.record(&AppError::new(ErrorCode::SigningKey, "no key"));

        assert_eq!(failures.total(), 6);
        assert!(!failures.is_empty());
        let summary = failures.summary();
        assert!(summary.contains("5 x E014_NETWORK_ERROR"), "{summary}");
        assert!(summary.contains("1 x E017_SIGNING_KEY"), "{summary}");
        assert!(
            summary.contains("first: [E014_NETWORK_ERROR] HTTP 401"),
            "{summary}"
        );
    }

    #[test]
    fn fetch_failures_default_is_empty() {
        assert!(FetchFailures::default().is_empty());
        assert_eq!(FetchFailures::default().total(), 0);
    }

    #[test]
    fn frontier_checkpoint_replaces_prior_contents_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join("rezzy-frontier-checkpoint-test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("frontier.jsonl");
        super::write_frontier_checkpoint(&path, &["$first".to_string(), "$second".to_string()])
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "$first\n$second\n");
        super::write_frontier_checkpoint(&path, &["$only".to_string()]).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "$only\n");
        assert!(!dir.join("frontier.jsonl.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
