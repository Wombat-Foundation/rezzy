//! Signed Matrix server-server requests and the remote DAG crawler.

use crate::error::{AppError, ErrorCode};
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use clap::{Arg, ArgAction, ArgMatches, Command};
use ed25519_zebra::SigningKey;
use rezzy::JsonValue;
mod state_diff;

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Connect timeout for outbound federation requests, so a flapping or
/// unreachable destination fails fast instead of hanging in `SYN-SENT`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall timeout for outbound federation requests (connect + transfer).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Environment variable that permits credential-bearing requests over plaintext
/// `http://`. Meant for local development against a test homeserver only.
const ALLOW_INSECURE_HTTP_ENV: &str = "REZZY_ALLOW_INSECURE_HTTP";

/// SRV-delegated connection targets, keyed by the `host:port` the request URL
/// names (`<logical server>:443`) and valued by the `host:port` to dial.
///
/// Matrix requires the TLS handshake and `Host` header to keep the *logical*
/// server name even when SRV points at another machine, so the URL is never
/// rewritten; only the address the connection is made to is.
fn srv_targets() -> &'static Mutex<BTreeMap<String, String>> {
    static TARGETS: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
    TARGETS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Resolver that dials an SRV target while the URL keeps the logical host.
#[derive(Debug)]
struct SrvResolver;

impl ureq::unversioned::resolver::Resolver for SrvResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        use std::net::ToSocketAddrs;
        let host = uri.host().ok_or(ureq::Error::HostNotFound)?;
        let port = uri.port_u16().unwrap_or_else(|| {
            if uri.scheme_str() == Some("http") {
                80
            } else {
                443
            }
        });
        let netloc = format!("{host}:{port}");
        let target = srv_targets()
            .lock()
            .ok()
            .and_then(|targets| targets.get(&netloc).cloned());
        let mut resolved = self.empty();
        let addrs = target
            .as_deref()
            .unwrap_or(&netloc)
            .to_socket_addrs()
            .map_err(ureq::Error::Io)?;
        // `ArrayVec` holds at most 16 addresses; `push` panics past that.
        for addr in addrs.take(16) {
            resolved.push(addr);
        }
        if resolved.is_empty() {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(resolved)
    }
}

/// Process-wide `ureq` agent with the federation timeouts applied.
///
/// HTTP error statuses are returned as responses (not `Err`) so callers can
/// read the error body.
fn federation_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .build();
        ureq::Agent::with_parts(
            config,
            ureq::unversioned::transport::DefaultConnector::default(),
            SrvResolver,
        )
    })
}

/// The `--signing-key` encrypted key-file path, when given.
fn signing_key_path(m: &ArgMatches) -> Option<&Path> {
    m.get_one::<PathBuf>("signing-key").map(PathBuf::as_path)
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
                .arg(known_events_arg())
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
                )
                .args(crawl_args()),
        )
        .subcommand(encrypt_key_command())
        .subcommand(gap_fill_command())
        .subcommand(state_diff::command())
}

/// Builds the gap-fill arguments, including resume and retry controls.
fn gap_fill_command() -> Command {
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
        .arg(
            Arg::new("origin")
                .long("origin")
                .env("MATRIX_ORIGIN")
                .default_value("matrix.org"),
        )
        .arg(
            Arg::new("room-version")
                .long("room-version")
                .default_value("12"),
        )
        .arg(
            Arg::new("rounds")
                .long("rounds")
                .default_value("5")
                .value_parser(clap::value_parser!(u32))
                .help("Maximum fetch rounds; 0 means continue until closed or no progress"),
        )
        .arg(
            Arg::new("skip-tried")
                .long("skip-tried")
                .action(ArgAction::SetTrue)
                .help(
                    "Do not ask again for IDs already requested (listed in tried.txt or auth-tried.txt). \
                     Off by default: failures here can be transient, so later rounds retry them",
                ),
        )
        .arg(
            Arg::new("resume")
                .long("resume")
                .action(ArgAction::SetTrue)
                .help(
                    "Continue in an --output-dir that already has round-NNN folders: \
                             reload them and number new rounds after them; previously requested IDs are \
                             asked again unless --skip-tried is also set",
                ),
        )
        .args(signing_key_args())
        .arg(
            Arg::new("no-fallback")
                .long("no-fallback")
                .action(ArgAction::SetTrue),
        )
        .args(crawl_args())
}

/// Builds the shared backfill toggle and inclusive event-depth cap arguments.
fn crawl_args() -> [Arg; 2] {
    [
        Arg::new("no-backfill")
            .long("no-backfill")
            .action(ArgAction::SetTrue)
            .conflicts_with("no-fallback")
            .help("Never call /backfill; fetch every event with /event/{id}"),
        Arg::new("max-depth")
            .long("max-depth")
            .value_parser(clap::value_parser!(u64))
            .help(
                "Ignore events deeper than N and do not follow their parents. \
                 An event's ancestors are always shallower, so a cap at the deepest \
                 wanted event loses nothing needed to close it",
            ),
    ]
}

/// Builds the key-encryption arguments, including optional passphrase origin.
fn encrypt_key_command() -> Command {
    Command::new("encrypt-key")
        .about("Encrypt a plaintext signing key into a passphrase-protected file")
        .arg(
            Arg::new("origin")
                .long("origin")
                .env("MATRIX_ORIGIN")
                .help("Origin server, used to select REZZY_KEY_PASSPHRASE_<DOMAIN>"),
        )
        .arg(
            Arg::new("input")
                .long("input")
                .short('i')
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
}

fn origin_arg() -> Arg {
    Arg::new("origin")
        .long("origin")
        .env("MATRIX_ORIGIN")
        .default_value("matrix.org")
}

fn signing_key_args() -> [Arg; 1] {
    [Arg::new("signing-key")
        .long("signing-key")
        .help("Passphrase-encrypted signing key (see `federation encrypt-key`)")
        .value_parser(clap::value_parser!(PathBuf))]
}

/// Builds the repeatable argument for locally held event files.
fn known_events_arg() -> Arg {
    Arg::new("known")
        .long("known")
        .action(ArgAction::Append)
        .value_parser(clap::value_parser!(PathBuf))
        .help("JSONL file of events already held locally; repeatable")
}

/// A room ID must start with the `!` sigil. A shell can silently rewrite it:
/// in an interactive bash, `"!$R"` is history expansion (the previous
/// command's last word followed by `R`), which then reaches the server as a
/// room it is not in and fails with `403 Host not in room`.
fn validate_room_id(room: &str) -> Result<(), AppError> {
    if room.len() > 1 && room.starts_with('!') && !room.contains(char::is_whitespace) {
        return Ok(());
    }
    Err(AppError::new(
        ErrorCode::MissingInputFlag,
        format!(
            "--room must be a Matrix room ID starting with '!', got {room:?}. \
             In an interactive bash, \"!$VAR\" is rewritten by history expansion; \
             use single quotes ('!room') or ROOM='!'\"$VAR\""
        ),
    ))
}

/// Checks and process-wide switches shared by `get-remote-dag` and `gap-fill`.
fn prepare_crawl(m: &ArgMatches) -> Result<(), AppError> {
    validate_room_id(m.get_one::<String>("room").expect("required"))?;
    NO_BACKFILL.store(m.get_flag("no-backfill"), Ordering::Relaxed);
    let max_depth = m.get_one::<u64>("max-depth").copied().unwrap_or(u64::MAX);
    MAX_DEPTH.store(max_depth, Ordering::Relaxed);
    Ok(())
}

/// Event IDs from the repeatable `--known` JSONL files: events the caller
/// already holds, which the crawl stops at.
fn load_known_ids(
    m: &ArgMatches,
    output: &Path,
    emit_missing: Option<&Path>,
    room_version: &str,
) -> Result<HashSet<String>, AppError> {
    let mut known = HashSet::new();
    for path in m.get_many::<PathBuf>("known").into_iter().flatten() {
        crate::repair::ensure_paths_distinct(path, output)?;
        if let Some(missing) = emit_missing {
            crate::repair::ensure_paths_distinct(path, missing)?;
        }
        for event in crate::repair::read_jsonl_events(path)? {
            let id = crate::repair::event_id_of(&event).or_else(|| {
                rezzy::reference_hash(&event, room_version)
                    .ok()
                    .map(|hash| format!("${hash}"))
            });
            known.extend(id);
        }
    }
    Ok(known)
}

/// Runs the selected federation subcommand.
///
/// # Errors
/// Returns an error when arguments, credentials, or the remote request are invalid.
///
/// # Panics
/// Panics if a required default argument is absent from a parsed subcommand.
pub fn run_from_matches(matches: &ArgMatches) -> Result<JsonValue, AppError> {
    if let Some(("request" | "get-remote-dag" | "gap-fill" | "state-diff", m)) =
        matches.subcommand()
    {
        let origin = m.get_one::<String>("origin").expect("default");
        load_signing_key(origin, signing_key_path(m))?;
    }
    if let Some(("get-remote-dag" | "gap-fill", m)) = matches.subcommand() {
        prepare_crawl(m)?;
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
                signing_key_path(m),
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
            let output = m.get_one::<PathBuf>("output").expect("default");
            let emit_missing = m.get_one::<PathBuf>("emit-missing").map(PathBuf::as_path);
            let room_version = m.get_one::<String>("room-version").expect("default");
            let known = load_known_ids(m, output, emit_missing, room_version)?;
            let request = DagRequest {
                origin: m.get_one::<String>("origin").expect("default"),
                destination: m.get_one::<String>("destination").expect("required"),
                room_id: m.get_one::<String>("room").expect("required"),
                starts: &starts,
                room_version,
                limit: *m.get_one::<i64>("limit").expect("default"),
                output,
                key_path: signing_key_path(m),
                no_fallback: m.get_flag("no-fallback"),
                emit_missing,
            };
            get_remote_dag_with_known(&request, (!known.is_empty()).then_some(&known))
        }
        Some(("encrypt-key", m)) => {
            let out = m.get_one::<PathBuf>("output").expect("required");
            encrypt_key_file_with_origin(
                m.get_one::<PathBuf>("input").expect("required"),
                out,
                m.get_one::<String>("origin").map(String::as_str),
            )?;
            Ok(rezzy::json!({ "written": out.display().to_string() }))
        }
        Some(("gap-fill", m)) => {
            let inputs = m
                .get_many::<PathBuf>("input")
                .expect("required")
                .cloned()
                .collect::<Vec<_>>();
            gap_fill(&GapFillRequest {
                inputs: &inputs,
                origin: m.get_one::<String>("origin").expect("default"),
                destination: m.get_one::<String>("destination").expect("required"),
                room_id: m.get_one::<String>("room").expect("required"),
                room_version: m.get_one::<String>("room-version").expect("default"),
                rounds: *m.get_one::<u32>("rounds").expect("default"),
                output_dir: m.get_one::<PathBuf>("output-dir").expect("required"),
                key_path: signing_key_path(m),
                no_fallback: m.get_flag("no-fallback"),
                resume: m.get_flag("resume"),
                skip_tried: m.get_flag("skip-tried"),
            })
        }
        Some(("state-diff", m)) => state_diff::run(m),
        _ => Err(AppError::new(
            ErrorCode::MissingInputFlag,
            "choose `request`, `get-remote-dag`, `gap-fill`, or `state-diff`",
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

/// Returns the passphrase variable name for the origin, ignoring scheme, port,
/// and path and replacing dots and hyphens with underscores.
fn scoped_passphrase_env_name(origin: &str) -> String {
    format!("REZZY_KEY_PASSPHRASE_{}", domain_env_suffix(origin))
}

/// Resolve the passphrase for `origin`, falling back to the legacy global
/// variable. Environment variables are visible to processes that can inspect
/// this process.
fn configured_passphrase(origin: Option<&str>) -> Option<String> {
    origin
        .map(scoped_passphrase_env_name)
        .and_then(|name| std::env::var(name).ok())
        .or_else(|| std::env::var("REZZY_KEY_PASSPHRASE").ok())
}

/// Read a key-file passphrase from the domain-scoped or legacy global
/// environment variable, or prompt on the terminal.
fn read_passphrase(path: &Path, origin: Option<&str>) -> Result<String, AppError> {
    if let Some(pw) = configured_passphrase(origin) {
        return Ok(pw);
    }
    rpassword::prompt_password(format!("Passphrase for {}: ", path.display())).map_err(|e| {
        AppError::new(
            ErrorCode::SigningKey,
            format!("could not read passphrase (set REZZY_KEY_PASSPHRASE_<DOMAIN> or REZZY_KEY_PASSPHRASE for unattended use): {e}"),
        )
    })
}

/// Resolve, decrypt and parse a Matrix server signing key.
///
/// The key must be a passphrase-encrypted file (see `federation encrypt-key`),
/// given by `--signing-key`, `MATRIX_SERVER_SIGNING_KEY_<DOMAIN>` or
/// `MATRIX_SERVER_SIGNING_KEY`. Plaintext key files are not accepted. The
/// passphrase comes from `REZZY_KEY_PASSPHRASE_<DOMAIN>`, then
/// `REZZY_KEY_PASSPHRASE`, or a terminal prompt. Parsed keys are cached by
/// origin and path, so later file or passphrase changes require a new process.
///
/// # Errors
/// Returns an error when no usable key is configured, the key file cannot be
/// read or decrypted, its contents are invalid, or prompting for a passphrase fails.
pub fn load_signing_key(origin: &str, explicit: Option<&Path>) -> Result<SigningKeySpec, AppError> {
    let suffix = domain_env_suffix(origin);
    let path = explicit.map(Path::to_path_buf).or_else(|| {
        std::env::var_os(format!("MATRIX_SERVER_SIGNING_KEY_{suffix}"))
            .or_else(|| std::env::var_os("MATRIX_SERVER_SIGNING_KEY"))
            .map(PathBuf::from)
    });
    let Some(path) = path else {
        return Err(AppError::new(
            ErrorCode::SigningKey,
            format!(
                "no encrypted signing key configured; pass --signing-key or set \
                 MATRIX_SERVER_SIGNING_KEY_{suffix} / MATRIX_SERVER_SIGNING_KEY to a file made \
                 by `federation encrypt-key`"
            ),
        ));
    };
    let cache_key = (origin.to_owned(), path.clone());
    if let Ok(cache) = signing_key_cache().lock() {
        if let Some(spec) = cache.get(&cache_key) {
            return Ok(spec.clone());
        }
    }
    let err = |message: String| {
        AppError::new(
            ErrorCode::SigningKey,
            format!("signing key {}: {message}", path.display()),
        )
    };
    let file = fs::read(&path).map_err(|e| err(e.to_string()))?;
    let passphrase = read_passphrase(&path, Some(origin))?;
    let plain = crate::keyfile::open(&file, passphrase.as_bytes()).map_err(err)?;
    let text = String::from_utf8(plain).map_err(|_| err("decrypted key is not UTF-8".into()))?;
    let spec = parse_signing_key(&text).map_err(err)?;
    if let Ok(mut cache) = signing_key_cache().lock() {
        cache.insert(cache_key, spec.clone());
    }
    Ok(spec)
}

/// Encrypt a plaintext signing key (read from `input`) into `output`, prompting for a
/// passphrase twice (or using `REZZY_KEY_PASSPHRASE`). The CLI command also
/// supports domain-scoped passphrases when `--origin` is supplied.
///
/// # Errors
/// Returns an error on I/O failure, mismatched passphrases, or an invalid key.
pub fn encrypt_key_file(input: &Path, output: &Path) -> Result<(), AppError> {
    encrypt_key_file_with_origin(input, output, None)
}

/// Encrypts a validated plaintext signing key, replacing `output`. Uses the
/// origin-scoped passphrase with global fallback, or prompts twice. On Unix,
/// sets output permissions to 0600. Returns errors for key parsing, empty or
/// mismatched passphrases, encryption, prompting, and file I/O.
fn encrypt_key_file_with_origin(
    input: &Path,
    output: &Path,
    origin: Option<&str>,
) -> Result<(), AppError> {
    let err = |m: String| AppError::new(ErrorCode::SigningKey, m);
    let plain = fs::read_to_string(input)?;
    parse_signing_key(&plain).map_err(|m| err(format!("{}: {m}", input.display())))?;
    let pw = if let Some(pw) = configured_passphrase(origin) {
        pw
    } else {
        let a = rpassword::prompt_password("New passphrase: ")?;
        let b = rpassword::prompt_password("Repeat passphrase: ")?;
        if a != b {
            return Err(err("passphrases do not match".into()));
        }
        a
    };
    if pw.is_empty() {
        return Err(err("empty passphrase".into()));
    }
    let sealed = crate::keyfile::seal(plain.as_bytes(), pw.as_bytes()).map_err(err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(output)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&sealed)?;
    }
    #[cfg(not(unix))]
    fs::write(output, sealed)?;
    Ok(())
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
        key: SigningKey::from(bytes),
    })
}

fn canonical_request(
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    body: &JsonValue,
) -> Result<Vec<u8>, AppError> {
    let method_upper = method.to_ascii_uppercase();
    let mut value = rezzy::json!({
        "method": &method_upper,
        "uri": uri,
        "origin": origin,
        "destination": destination
    });
    if !(method_upper == "GET" && matches!(body, JsonValue::Object(o) if o.is_empty())) {
        let _ = value.insert("content".to_owned(), body.clone());
    }
    rezzy::json::write_string_value(&value)
        .map(std::string::String::into_bytes)
        .map_err(|e| AppError::new(ErrorCode::NetworkError, e.to_string()))
}

/// Cache of logical server name -> resolved `https://host[:port]` endpoint, or
/// `None` when no delegation record exists (so misses are not re-queried).
fn delegation_cache() -> &'static Mutex<BTreeMap<String, Option<String>>> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Process-wide cache of parsed signing keys, keyed by `(origin, key file)`.
///
/// Each `(origin, key file)` is decrypted once per process; key-file changes
/// take effect after restarting the CLI.
fn signing_key_cache() -> &'static Mutex<BTreeMap<(String, PathBuf), SigningKeySpec>> {
    static CACHE: OnceLock<Mutex<BTreeMap<(String, PathBuf), SigningKeySpec>>> = OnceLock::new();
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
            return cached.clone();
        }
    }
    // `Err` marks a transient failure (network, missing `dig`): the answer is
    // still unknown, so it must not be cached as "no delegation".
    let (resolved, definitive) = match well_known_lookup(destination) {
        Ok(Some(endpoint)) => (Some(endpoint), true),
        well_known => {
            let (found, srv_definitive) = srv_lookup(destination);
            (found, srv_definitive && well_known.is_ok())
        }
    };
    if let Some(ref endpoint) = resolved {
        eprintln!("[info] federation delegation: {destination} -> {endpoint}");
    }
    if definitive {
        if let Ok(mut cache) = delegation_cache().lock() {
            cache.insert(destination.to_owned(), resolved.clone());
        }
    }
    resolved
}

/// Query `_matrix-fed._tcp` / `_matrix._tcp` SRV records via the system
/// resolver (`dig`).
///
/// Returns the endpoint found, if any, and whether that answer is definitive.
/// A failed `_matrix-fed._tcp` lookup makes the answer non-definitive even
/// when the legacy `_matrix._tcp` record is found, since the preferred record
/// might exist once the resolver recovers.
fn srv_lookup(destination: &str) -> (Option<String>, bool) {
    let mut failed = false;
    for service in ["_matrix-fed._tcp", "_matrix._tcp"] {
        let name = format!("{service}.{destination}");
        let found = dig_srv(&name).unwrap_or_else(|()| {
            failed = true;
            None
        });
        if let Some((target, port)) = found {
            if let Ok(mut targets) = srv_targets().lock() {
                targets.insert(format!("{destination}:443"), format!("{target}:{port}"));
            }
            // Keep the logical name in the URL so `Host` and the certificate
            // check use it; `SrvResolver` supplies the SRV target's address.
            return (Some(format!("https://{destination}")), !failed);
        }
    }
    (None, !failed)
}

fn dig_srv(name: &str) -> Result<Option<(String, u16)>, ()> {
    let output = std::process::Command::new("dig")
        .args(["+short", "SRV", name])
        .output()
        .map_err(|_| ())?;
    if !output.status.success() {
        return Err(());
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
            .is_none_or(|(best_priority, _, _)| priority < *best_priority)
        {
            best = Some((priority, target.trim_end_matches('.').to_owned(), port));
        }
    }
    Ok(best.map(|(_, target, port)| (target, port)))
}

/// Fetch `https://<destination>/.well-known/matrix/server` and use `m.server`.
///
/// `Ok(None)` means the server answered without usable delegation; `Err` means
/// the request failed transiently (transport error, 5xx, 408 or 429).
fn well_known_lookup(destination: &str) -> Result<Option<String>, ()> {
    let url = format!("https://{destination}/.well-known/matrix/server");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(5)))
        .http_status_as_error(false)
        .build()
        .into();
    let Ok(mut response) = agent.get(&url).call() else {
        return Err(());
    };
    let code = response.status().as_u16();
    // 408 and 429 are retryable, not a statement that no delegation exists.
    if code >= 400 {
        return if code < 500 && code != 408 && code != 429 {
            Ok(None)
        } else {
            Err(())
        };
    }
    let Ok(body) = response.body_mut().read_to_string() else {
        return Err(());
    };
    let delegated = JsonValue::parse(&body)
        .ok()
        .and_then(|value| value.get("m.server")?.as_str().map(str::to_owned))
        .filter(|delegated| !delegated.is_empty());
    Ok(delegated.map(|delegated| {
        if delegated.contains(':') {
            format!("https://{delegated}")
        } else {
            // Per the spec, `m.server` without a port defaults to 8448.
            format!("https://{delegated}:8448")
        }
    }))
}

fn base_url(destination: &str) -> String {
    if destination.starts_with("http://") || destination.starts_with("https://") {
        destination.trim_end_matches('/').to_owned()
    } else if destination.contains(':') {
        // An explicit port is used as given; no delegation applies.
        format!("https://{destination}")
    } else if let Some(endpoint) = resolve_delegation(destination) {
        endpoint
    } else {
        format!("https://{destination}:8448")
    }
}

/// Send one signed federation request using a passphrase-encrypted signing key
/// file. The key file is resolved from `key_path` or the
/// `MATRIX_SERVER_SIGNING_KEY_<DOMAIN>` / `MATRIX_SERVER_SIGNING_KEY`
/// environment variables and cached per process.
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
) -> Result<JsonValue, AppError> {
    let key = load_signing_key(origin, key_path)?;
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
            "HTTPS request requires the `tls` feature; rebuild rezzy-cli with `--features tls` (plaintext http:// also needs REZZY_ALLOW_INSECURE_HTTP=1)",
        ));
    }
    if url.starts_with("http://") && std::env::var(ALLOW_INSECURE_HTTP_ENV).as_deref() != Ok("1") {
        return Err(AppError::new(
            ErrorCode::NetworkError,
            format!(
                "refusing to send a signed request over plaintext HTTP to {destination}; \
                 use https, or set {ALLOW_INSECURE_HTTP_ENV}=1 for local development"
            ),
        ));
    }
    let agent = federation_agent();
    let method_upper = method.to_ascii_uppercase();
    if !matches!(method_upper.as_str(), "GET" | "POST" | "PUT" | "DELETE") {
        return Err(AppError::new(
            ErrorCode::NetworkError,
            format!("unsupported HTTP method {method_upper}"),
        ));
    }
    let builder = ureq::http::Request::builder()
        .method(method_upper.as_str())
        .uri(&url)
        .header("Authorization", &auth)
        .header("User-Agent", crate::USER_AGENT)
        .header("Content-Type", "application/json");
    let bad_request = |e: ureq::http::Error| AppError::new(ErrorCode::NetworkError, e.to_string());
    let result = if method_upper == "GET" && matches!(body, JsonValue::Object(o) if o.is_empty()) {
        agent.run(builder.body(()).map_err(bad_request)?)
    } else {
        let body_text = rezzy::json::write_string_value(body)
            .map_err(|e| AppError::new(ErrorCode::NetworkError, e.to_string()))?;
        agent.run(builder.body(body_text).map_err(bad_request)?)
    };
    let mut response =
        result.map_err(|e| AppError::new(ErrorCode::RemoteUnavailable, e.to_string()))?;
    let code = response.status().as_u16();
    let text = response
        .body_mut()
        .read_to_string()
        .map_err(|e| AppError::new(ErrorCode::NetworkError, e.to_string()))?;
    if code >= 400 {
        return Err(AppError::new(
            ErrorCode::NetworkError,
            format!("HTTP {code} from {destination}: {text}"),
        ));
    }
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
pub struct DagRequest<'a> {
    /// Origin server name used for signing.
    pub origin: &'a str,
    /// Destination server name.
    pub destination: &'a str,
    /// Room being crawled.
    pub room_id: &'a str,
    /// Initial event frontier.
    pub starts: &'a [String],
    /// Room version used for event hashing.
    pub room_version: &'a str,
    /// Maximum number of events to fetch.
    pub limit: i64,
    /// JSONL output path.
    pub output: &'a Path,
    /// Optional signing-key file.
    pub key_path: Option<&'a Path>,
    /// Disable per-event fallback requests.
    pub no_fallback: bool,
    /// Optional unresolved-frontier output path.
    pub emit_missing: Option<&'a Path>,
}

static DEBUG: AtomicBool = AtomicBool::new(false);

/// Enable the debug-only per-request log (`requests.jsonl`); set from `--debug`.
pub fn set_debug(on: bool) {
    DEBUG.store(on, Ordering::Relaxed);
}

/// Returns whether per-request debug logging is enabled process-wide.
fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

static FORBIDDEN_HINT_SHOWN: AtomicBool = AtomicBool::new(false);

/// `403 Host not in room` from `/backfill` usually means the room ID sent was
/// not the room meant (see `validate_room_id`); say so once.
fn hint_if_not_in_room(result: &Result<JsonValue, AppError>, room_id: &str) {
    let refused = result.as_ref().err().is_some_and(|e| {
        let text = e.to_string();
        http_status_of(&text) == Some(403) && text.contains("Host not in room")
    });
    if refused && !FORBIDDEN_HINT_SHOWN.swap(true, Ordering::Relaxed) {
        eprintln!(
            "[hint] /backfill answered 403 \"Host not in room\" for room {room_id:?}. \
             Check --room is exactly the room ID (a shell can rewrite \"!$VAR\"); \
             events requested by ID may still work, since /event/{{id}} does not use it"
        );
    }
}

/// Set by `--no-backfill`: never call `/backfill`.
static NO_BACKFILL: AtomicBool = AtomicBool::new(false);

/// Set by `--max-depth`: events deeper than this are skipped, not followed.
static MAX_DEPTH: AtomicU64 = AtomicU64::new(u64::MAX);

/// Returns whether the process-wide crawl settings permit backfill requests.
fn backfill_allowed() -> bool {
    !NO_BACKFILL.load(Ordering::Relaxed)
}

/// One request made during a fetch, kept for the debug-only `requests.jsonl`.
struct Attempt {
    event_id: Option<String>,
    endpoint: &'static str,
    outcome: &'static str,
    status: Option<u16>,
    errcode: Option<String>,
    message: String,
    millis: u64,
}

/// Extracts the first status number following `HTTP `, or returns `None`.
fn http_status_of(text: &str) -> Option<u16> {
    text.split("HTTP ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Extracts a quoted `errcode` from error text, or returns `None` if absent
/// or not in the expected format.
fn errcode_of(text: &str) -> Option<String> {
    let rest = text.split("\"errcode\"").nth(1)?;
    let rest = rest.trim_start_matches([':', ' ']).strip_prefix('"')?;
    Some(rest.split('"').next()?.to_owned())
}

/// Summarizes a request result and elapsed milliseconds. Successful requests
/// are labeled with status 200; error text is limited to 200 characters.
fn attempt_of(
    event_id: Option<&str>,
    endpoint: &'static str,
    result: &Result<JsonValue, AppError>,
    started: Instant,
) -> Attempt {
    let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let event_id = event_id.map(str::to_owned);
    match result {
        Ok(_) => Attempt {
            event_id,
            endpoint,
            outcome: "ok",
            status: Some(200),
            errcode: None,
            message: String::new(),
            millis,
        },
        Err(error) => {
            let text = error.to_string();
            let status = http_status_of(&text);
            Attempt {
                event_id,
                endpoint,
                outcome: if status.is_some() {
                    "http_error"
                } else {
                    "network_error"
                },
                status,
                errcode: errcode_of(&text),
                message: text.chars().take(200).collect(),
                millis,
            }
        }
    }
}

/// `event:404`, `backfill:403`, `event:5xx`, `event:network`, ...
fn stat_label(attempt: &Attempt) -> String {
    let status = match attempt.status {
        Some(500..=599) => "5xx".to_owned(),
        Some(code) => code.to_string(),
        None => "network".to_owned(),
    };
    format!("{}:{status}", attempt.endpoint)
}

/// Converts an absent string to JSON null.
fn opt_str(value: Option<&str>) -> JsonValue {
    value.map_or(JsonValue::Null, |s| JsonValue::String(s.to_owned()))
}

/// Append one JSON line per attempt. Only error text and statuses are logged,
/// never signing keys or the `Authorization` header.
fn append_attempts(
    path: &Path,
    round: u32,
    tried: &HashSet<String>,
    dag_request: &DagRequest<'_>,
    attempts: &[Attempt],
) -> Result<(), AppError> {
    if attempts.is_empty() {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let when = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    for a in attempts {
        let line = attempt_record(
            when,
            round,
            dag_request.room_id,
            dag_request.origin,
            dag_request.destination,
            tried,
            a,
        );
        let text = rezzy::json::write_string_value(&line)
            .map_err(|e| AppError::new(ErrorCode::MalformedJson, e.to_string()))?;
        writeln!(file, "{text}")?;
    }
    Ok(())
}

/// Per-batch progress record for `gap-fill`.
struct Checkpoint<'a> {
    tried: &'a mut HashSet<String>,
    tried_path: &'a Path,
    requests_path: Option<&'a Path>,
    round: u32,
    /// Do not queue IDs already in `tried`, including parents found mid-crawl.
    skip_tried: bool,
}

/// Records the supplied IDs as tried and persists the checkpoint, optionally
/// adding them to the crawl exclusion set. Propagates log and checkpoint I/O
/// or serialization errors.
fn checkpoint_batch(
    checkpoint: &mut Checkpoint<'_>,
    dag_request: &DagRequest<'_>,
    state: &mut DagWalkState,
    ids: Vec<String>,
) -> Result<(), AppError> {
    if let Some(path) = checkpoint.requests_path {
        append_attempts(
            path,
            checkpoint.round,
            checkpoint.tried,
            dag_request,
            &state.attempts,
        )?;
    }
    state.attempts.clear();
    state.requested.clear();
    for id in ids {
        checkpoint.tried.insert(id.clone());
        if checkpoint.skip_tried {
            state.skip.insert(id);
        }
    }
    write_tried_file(checkpoint.tried_path, checkpoint.tried)
}

/// Formats request counts in sorted label order, separated by spaces.
fn summarize_stats(stats: &BTreeMap<String, usize>) -> String {
    stats
        .iter()
        .map(|(label, count)| format!("{label}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Mutable state accumulated while walking a remote DAG.
struct DagWalkState {
    queue: VecDeque<String>,
    queued: HashSet<String>,
    seen: HashSet<String>,
    unresolved: Vec<String>,
    failures: FetchFailures,
    unreachable: Option<AppError>,
    output_writer: BufWriter<fs::File>,
    event_count: usize,
    /// Events the caller already has and the crawl should stop at.
    known: HashSet<String>,
    /// Counts of request outcomes by `endpoint:status`.
    stats: BTreeMap<String, usize>,
    /// Requests made since the last checkpoint, kept only when logging them.
    attempts: Vec<Attempt>,
    log_attempts: bool,
    /// Event IDs requested since the last checkpoint, in request order.
    requested: Vec<String>,
    track_requested: bool,
    /// Events dropped by `--max-depth`.
    skipped_deep: usize,
    /// Whether fetched events' `prev_events` should be queued for crawling.
    follow_prev_events: bool,
    /// IDs a resumed gap-fill run was told not to ask for again.
    skip: HashSet<String>,
}

impl DagWalkState {
    /// Counts the outcome and retains its event ID for checkpointing; retains
    /// the full attempt only when request logging is enabled.
    fn record(&mut self, attempt: Attempt) {
        let count = self.stats.entry(stat_label(&attempt)).or_insert(0);
        *count = count.saturating_add(1);
        if self.track_requested {
            if let Some(id) = &attempt.event_id {
                self.requested.push(id.clone());
            }
        }
        if self.log_attempts {
            self.attempts.push(attempt);
        }
    }
}

/// Creates or truncates the event output and queues unique seeds not in `known`.
/// A negative event limit is unlimited. Returns an error for empty seeds,
/// conflicting output paths, or output I/O failure.
fn initialize_dag(
    request: &DagRequest<'_>,
    known: Option<&HashSet<String>>,
) -> Result<(DagWalkState, usize), AppError> {
    if request.starts.is_empty() {
        return Err(AppError::new(
            ErrorCode::MissingInputFlag,
            "get-remote-dag needs at least one --from <event-id> or --from-file <path> (the CLI has no local timeline to infer a starting event)",
        ));
    }
    if let Some(missing) = request.emit_missing {
        crate::repair::ensure_paths_distinct(request.output, missing)?;
    }
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    for id in request.starts {
        // Events the caller already holds need no request, even as seeds.
        if known.is_some_and(|held| held.contains(id)) {
            continue;
        }
        if queued.insert(id.clone()) {
            queue.push_back(id.clone());
        }
    }
    let output_writer = open_output_writer(request.output)?;
    if let Some(missing) = request.emit_missing.filter(|path| *path != Path::new("-")) {
        // The output exists now, so a symlink or relative alias resolves.
        if crate::repair::ensure_distinct_paths(request.output, missing).is_err() {
            return Err(AppError::new(
                ErrorCode::IoError,
                "--output and --emit-missing must be different files",
            ));
        }
    }
    let max = if request.limit < 0 {
        usize::MAX
    } else {
        usize::try_from(request.limit).unwrap_or(usize::MAX)
    };
    Ok((
        DagWalkState {
            queue,
            queued,
            seen: HashSet::new(),
            unresolved: Vec::new(),
            failures: FetchFailures::default(),
            unreachable: None,
            output_writer,
            event_count: 0,
            known: known.cloned().unwrap_or_default(),
            stats: BTreeMap::new(),
            attempts: Vec::new(),
            log_attempts: false,
            requested: Vec::new(),
            track_requested: false,
            skipped_deep: 0,
            follow_prev_events: true,
            skip: HashSet::new(),
        },
        max,
    ))
}

/// Flushes events and returns counts, request statistics, and unresolved IDs,
/// optionally writing the frontier. Returns an error on output failure or if
/// requests failed and no events were written; partial fetches carry failures
/// in the returned summary.
fn finalize_dag(mut state: DagWalkState, request: &DagRequest<'_>) -> Result<JsonValue, AppError> {
    state.output_writer.flush()?;
    let mut request_stats = rezzy::json!({});
    for (label, count) in &state.stats {
        let count = u64::try_from(*count).unwrap_or(u64::MAX);
        let _ = request_stats.insert(label.clone(), rezzy::json!(count));
    }
    if state.event_count == 0 && !state.failures.is_empty() {
        return Err(AppError::new(
            ErrorCode::NetworkError,
            format!(
                "no events fetched from {} for {}: {}",
                request.destination,
                request.room_id,
                state.failures.summary()
            ),
        ));
    }
    let remaining_frontier = state
        .queue
        .into_iter()
        .chain(state.unresolved)
        .filter(|id| !state.seen.contains(id))
        .collect::<Vec<_>>();
    if let Some(path) = request.emit_missing {
        crate::repair::write_event_ids(path, &remaining_frontier)?;
    }
    let mut result = rezzy::json!({
        "count": state.event_count,
        "output": request.output.display().to_string(),
        "remaining_frontier": remaining_frontier,
    });
    let _ = result.insert(String::from("request_stats"), request_stats);
    let skipped = u64::try_from(state.skipped_deep).unwrap_or(u64::MAX);
    let _ = result.insert(String::from("skipped_too_deep"), rezzy::json!(skipped));
    if !state.failures.is_empty() {
        let _ = result.insert(
            String::from("failed_requests"),
            rezzy::json!(state.failures.total() as u64),
        );
        let _ = result.insert(
            String::from("failures"),
            rezzy::json!(state.failures.summary()),
        );
    }
    if let Some(path) = request.emit_missing {
        let _ = result.insert(
            String::from("missing_output"),
            rezzy::json!(path.to_string_lossy().to_string()),
        );
    }
    Ok(result)
}

/// Write one fetched PDU. Returns `false` only once the event limit is reached;
/// skipped (invalid, duplicate, known, or too deep) PDUs return `true` so the
/// batch continues. A finite depth cap also skips missing or nonnumeric depths.
/// Kept events queue unknown parents when traversal is enabled. Serialization
/// and output errors propagate.
fn write_dag_event(
    pdu: &JsonValue,
    room_version: &str,
    max: usize,
    state: &mut DagWalkState,
) -> Result<bool, AppError> {
    let Some(object) = pdu.as_object() else {
        return Ok(true);
    };
    let max_depth = MAX_DEPTH.load(Ordering::Relaxed);
    // With a finite limit, a missing/non-numeric depth is malformed and must not slip past it.
    let too_deep = object
        .get("depth")
        .and_then(JsonValue::as_u64)
        .map_or(max_depth != u64::MAX, |depth| depth > max_depth);
    if too_deep {
        state.skipped_deep = state.skipped_deep.saturating_add(1);
        return Ok(true);
    }
    let event_id = object
        .get("event_id")
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .or_else(|| {
            rezzy::reference_hash(pdu, room_version)
                .ok()
                .map(|h| format!("${h}"))
        });
    let Some(event_id) = event_id else {
        return Ok(true);
    };
    if state.known.contains(&event_id) || !state.seen.insert(event_id.clone()) {
        return Ok(true);
    }
    let mut line = pdu.clone();
    if let Some(obj) = line.as_object_mut() {
        obj.insert("event_id".to_owned(), JsonValue::String(event_id));
    }
    let prev = line
        .get("prev_events")
        .and_then(JsonValue::as_array)
        .filter(|_| state.follow_prev_events);
    if let Some(prev) = prev {
        for item in prev {
            let id = item.as_str().or_else(|| {
                item.as_array()
                    .and_then(|a| a.first())
                    .and_then(JsonValue::as_str)
            });
            if let Some(id) = id {
                if !state.known.contains(id)
                    && !state.skip.contains(id)
                    && !state.seen.contains(id)
                    && state.queued.insert(id.to_owned())
                {
                    state.queue.push_back(id.to_owned());
                }
            }
        }
    }
    let encoded = rezzy::json::write_string_value(&line)
        .map_err(|e| AppError::new(ErrorCode::MalformedJson, e.to_string()))?;
    writeln!(state.output_writer, "{encoded}")?;
    state.event_count = state.event_count.saturating_add(1);
    Ok(state.seen.len() < max)
}

enum DagBatch {
    Events(JsonValue),
    Stop,
}

/// Fetch each of `ids` with a single-event request, returning the PDUs found.
///
/// Per-event failures are recorded and the ID is left for the caller to mark
/// unresolved; only an unreachable destination aborts.
fn fetch_events_individually(
    dag_request: &DagRequest<'_>,
    ids: &[String],
    state: &mut DagWalkState,
) -> Vec<JsonValue> {
    let mut pdus = Vec::new();
    for id in ids {
        let event_uri = format!("/_matrix/federation/v1/event/{}", quote(id));
        let started = Instant::now();
        let result = request(
            dag_request.origin,
            dag_request.destination,
            "GET",
            &event_uri,
            &rezzy::json!({}),
            dag_request.key_path,
        );
        state.record(attempt_of(Some(id), "event", &result, started));
        match result {
            Ok(v) => pdus.extend(event_pdus_from_response(v)),
            Err(e) if is_unreachable(&e) => {
                state.failures.record(&e);
                state
                    .unresolved
                    .extend(ids.iter().skip_while(|candidate| *candidate != id).cloned());
                state.unreachable = Some(e);
                return pdus;
            }
            Err(e) => state.failures.record(&e),
        }
    }
    pdus
}

/// Extract event objects from the common federation event response shapes.
/// Matrix servers may return a single `pdu` or a `pdus` array; older/custom
/// endpoints can return the PDU object directly.
fn event_pdus_from_response(response: JsonValue) -> Vec<JsonValue> {
    if let Some(pdu) = response.get("pdu") {
        return vec![pdu.clone()];
    }
    if let Some(pdus) = response.get("pdus").and_then(JsonValue::as_array) {
        return pdus.clone();
    }
    vec![response]
}

/// Fetches a frontier batch through backfill, falling back to individual
/// requests when permitted and backfill fails or returns no PDUs.
/// Unreachable backfill requests and failures with fallback disabled propagate;
/// individual request failures are retained in the walk state.
fn fetch_dag_batch(
    dag_request: &DagRequest<'_>,
    ids: &[String],
    state: &mut DagWalkState,
) -> Result<DagBatch, AppError> {
    if !backfill_allowed() {
        let value = rezzy::json!({"pdus": fetch_events_individually(dag_request, ids, state)});
        return Ok(finish_batch(value, ids, state));
    }
    let uri = format!(
        "/_matrix/federation/v1/backfill/{}?{}&limit=500",
        quote(dag_request.room_id),
        ids.iter()
            .map(|id| format!("v={}", quote(id)))
            .collect::<Vec<_>>()
            .join("&")
    );
    let started = Instant::now();
    let response = request(
        dag_request.origin,
        dag_request.destination,
        "GET",
        &uri,
        &rezzy::json!({}),
        dag_request.key_path,
    );
    state.record(attempt_of(None, "backfill", &response, started));
    hint_if_not_in_room(&response, dag_request.room_id);
    let mut fell_back = false;
    let mut value = match response {
        Ok(v) => v,
        Err(e) if is_unreachable(&e) => return Err(e),
        Err(e) if !dag_request.no_fallback => {
            state.failures.record(&e);
            fell_back = true;
            rezzy::json!({"pdus": fetch_events_individually(dag_request, ids, state)})
        }
        Err(e) => return Err(e),
    };
    let empty = value
        .get("pdus")
        .and_then(JsonValue::as_array)
        .is_none_or(Vec::is_empty);
    if empty && dag_request.no_fallback {
        state.unresolved.extend(ids.iter().cloned());
        return Ok(DagBatch::Stop);
    }
    // Skip the retry when the error branch already fetched each ID once.
    if empty && !fell_back {
        value = rezzy::json!({"pdus": fetch_events_individually(dag_request, ids, state)});
    }
    Ok(finish_batch(value, ids, state))
}

/// Record which requested IDs the response actually returned.
fn finish_batch(value: JsonValue, ids: &[String], state: &mut DagWalkState) -> DagBatch {
    let returned_ids: HashSet<String> = value
        .get("pdus")
        .and_then(JsonValue::as_array)
        .map(|pdus| pdus.iter().filter_map(crate::repair::event_id_of).collect())
        .unwrap_or_default();
    // Any requested ID not in returned_ids is unresolved.
    for id in ids {
        if !returned_ids.contains(id) {
            state.unresolved.push(id.clone());
        }
    }
    DagBatch::Events(value)
}

/// Fetches a remote timeline DAG into the output file, following `prev_events`.
/// Returns event counts, request statistics, and the unresolved frontier.
/// The output is replaced; a negative limit allows an unbounded crawl.
///
/// # Errors
/// Returns an error for empty seeds, conflicting output paths, output failures,
/// an unreachable destination, or a backfill error with fallback disabled.
/// Individual request failures are reported in the summary unless no events
/// were written, in which case the fetch fails.
pub fn get_remote_dag(dag_request: &DagRequest<'_>) -> Result<JsonValue, AppError> {
    get_remote_dag_with_known(dag_request, None)
}

/// Crawls the remote DAG, stopping at IDs in `known` without fetching them.
/// Returns the crawl summary or propagates initialization, fetch, and output errors.
fn get_remote_dag_with_known(
    dag_request: &DagRequest<'_>,
    known: Option<&HashSet<String>>,
) -> Result<JsonValue, AppError> {
    get_remote_dag_with_known_and_checkpoint(dag_request, known, None)
}

/// Fetches only the requested IDs, without crawling their `prev_events`.
///
/// # Errors
/// Returns an error for empty seeds, conflicting output paths, serialization or
/// output failures, or request failures when no events were written. After
/// partial success, an unreachable destination stops fetching and the summary
/// includes failures and unresolved IDs. Known IDs are skipped.
pub(super) fn get_remote_events_by_id(
    dag_request: &DagRequest<'_>,
    known: Option<&HashSet<String>>,
) -> Result<JsonValue, AppError> {
    let (mut state, max) = initialize_dag(dag_request, known)?;
    state.follow_prev_events = false;
    // One ID at a time, writing as we go, so an unreachable server late in the
    // list does not discard what was already fetched.
    'ids: for (index, id) in dag_request.starts.iter().enumerate() {
        if known.is_some_and(|held| held.contains(id)) {
            continue;
        }
        let pdus = fetch_events_individually(dag_request, std::slice::from_ref(id), &mut state);
        let found = pdus.iter().any(|pdu| {
            crate::repair::event_id_of(pdu)
                .or_else(|| {
                    rezzy::reference_hash(pdu, dag_request.room_version)
                        .ok()
                        .map(|hash| format!("${hash}"))
                })
                .is_some_and(|returned| returned == *id)
        });
        // An unreachable server already put this ID in `unresolved`.
        if !found && state.unreachable.is_none() {
            state.unresolved.push(id.clone());
        }
        for pdu in pdus {
            if !write_dag_event(&pdu, dag_request.room_version, max, &mut state)? {
                state.unresolved.extend(
                    dag_request
                        .starts
                        .iter()
                        .skip(index.saturating_add(1))
                        .filter(|remaining| !known.is_some_and(|held| held.contains(*remaining)))
                        .cloned(),
                );
                break 'ids;
            }
        }
        state.output_writer.flush()?;
        if let Some(error) = state.unreachable.take() {
            state.unresolved.extend(
                dag_request
                    .starts
                    .iter()
                    .skip(index.saturating_add(1))
                    .filter(|remaining| !known.is_some_and(|held| held.contains(*remaining)))
                    .cloned(),
            );
            if state.event_count == 0 {
                return Err(error);
            }
            break;
        }
    }
    finalize_dag(state, dag_request)
}

/// Crawls the frontier while excluding known events and optionally persisting
/// tried IDs after each batch. With `skip_tried`, excludes prior requests and
/// discovered parents in that set. Propagates initialization, fetch, write,
/// and checkpoint errors; a failed-batch checkpoint error does not replace
/// the fetch error.
fn get_remote_dag_with_known_and_checkpoint(
    dag_request: &DagRequest<'_>,
    known: Option<&HashSet<String>>,
    tried_checkpoint: Option<Checkpoint<'_>>,
) -> Result<JsonValue, AppError> {
    let room_version = dag_request.room_version;
    let (mut state, max) = initialize_dag(dag_request, known)?;
    let mut tried_checkpoint = tried_checkpoint;
    state.track_requested = tried_checkpoint.is_some();
    state.log_attempts = tried_checkpoint
        .as_ref()
        .is_some_and(|cp| cp.requests_path.is_some());
    if let Some(cp) = tried_checkpoint.as_ref().filter(|cp| cp.skip_tried) {
        state.skip.clone_from(cp.tried);
        state.queue.retain(|id| !state.skip.contains(id));
        state.queued.retain(|id| !state.skip.contains(id));
    }
    while !state.queue.is_empty() && state.seen.len() < max {
        let mut ids = Vec::new();
        while ids.len() < 50 {
            if let Some(id) = state.queue.pop_front() {
                if !state.seen.contains(&id) {
                    ids.push(id);
                }
            } else {
                break;
            }
        }
        if ids.is_empty() {
            continue;
        }
        let value = match fetch_dag_batch(dag_request, &ids, &mut state) {
            Err(error) => {
                state.output_writer.flush()?;
                if let Some(cp) = tried_checkpoint.as_mut() {
                    // For requests that reached the destination, persist their
                    // IDs before returning so --resume --skip-tried does not
                    // send the same failed batch again.
                    // An unreachable destination never received the batch, so
                    // checkpoint no IDs and leave them retryable on resume.
                    // A checkpoint write failure must not mask the real error.
                    let checkpoint_ids = if is_unreachable(&error) {
                        Vec::new()
                    } else {
                        ids
                    };
                    if let Err(write_error) =
                        checkpoint_batch(cp, dag_request, &mut state, checkpoint_ids)
                    {
                        eprintln!("[warn] could not checkpoint failed batch: {write_error}");
                    }
                }
                return Err(error);
            }
            Ok(DagBatch::Events(value)) => value,
            Ok(DagBatch::Stop) => {
                if let Some(cp) = tried_checkpoint.as_mut() {
                    checkpoint_batch(cp, dag_request, &mut state, ids)?;
                }
                break;
            }
        };
        let Some(pdus) = value.get("pdus").and_then(JsonValue::as_array) else {
            continue;
        };
        for pdu in pdus {
            if !write_dag_event(pdu, room_version, max, &mut state)? {
                break;
            }
        }

        if let Some(error) = finish_dag_batch(&mut state, dag_request, &mut tried_checkpoint, ids)?
        {
            return Err(error);
        }
    }
    if let Some(cp) = tried_checkpoint.as_ref() {
        eprintln!(
            "[info] round {}: requests {}",
            cp.round,
            summarize_stats(&state.stats)
        );
    }
    if state.skipped_deep > 0 {
        eprintln!(
            "[info] skipped {} event(s) deeper than --max-depth {}",
            state.skipped_deep,
            MAX_DEPTH.load(Ordering::Relaxed)
        );
    }
    finalize_dag(state, dag_request)
}

/// Flushes fetched events before saving tried IDs and the unresolved frontier.
/// Returns a pending unreachable-server error inside `Ok`, leaving the failing
/// and unattempted IDs out of the tried checkpoint. Output and checkpoint
/// errors propagate as `Err`.
fn finish_dag_batch(
    state: &mut DagWalkState,
    dag_request: &DagRequest<'_>,
    checkpoint: &mut Option<Checkpoint<'_>>,
    ids: Vec<String>,
) -> Result<Option<AppError>, AppError> {
    // Flush fetched events before advancing the checkpoint.
    state.output_writer.flush()?;
    if let Some(error) = state.unreachable.take() {
        if let Some(cp) = checkpoint.as_mut() {
            // Only IDs actually requested count as tried; the fetch that hit the
            // unreachable server and everything after it must be retried.
            let failing = state.requested.last().cloned();
            let attempted: HashSet<&str> = state.requested.iter().map(String::as_str).collect();
            let requested: Vec<String> = ids
                .into_iter()
                .filter(|id| attempted.contains(id.as_str()) && failing.as_ref() != Some(id))
                .collect();
            checkpoint_batch(cp, dag_request, state, requested)?;
        }
        return Ok(Some(error));
    }
    if let Some(cp) = checkpoint.as_mut() {
        checkpoint_batch(cp, dag_request, state, ids)?;
    }
    eprintln!(
        "[progress] fetched {} event(s), {} queued",
        state.event_count,
        state.queue.len()
    );
    let frontier = state
        .queue
        .iter()
        .filter(|id| !state.seen.contains(*id))
        .cloned()
        .chain(
            state
                .unresolved
                .iter()
                .filter(|id| !state.seen.contains(*id))
                .cloned(),
        )
        .collect::<Vec<_>>();
    if let Some(path) = dag_request
        .emit_missing
        .filter(|path| *path != Path::new("-"))
    {
        write_frontier_checkpoint(path, &frontier)?;
    }
    Ok(None)
}

/// Parameters for filling missing references from a remote server.
struct GapFillRequest<'a> {
    inputs: &'a [PathBuf],
    origin: &'a str,
    destination: &'a str,
    room_id: &'a str,
    room_version: &'a str,
    rounds: u32,
    output_dir: &'a Path,
    key_path: Option<&'a Path>,
    no_fallback: bool,
    resume: bool,
    skip_tried: bool,
}

/// IDs already requested from the destination, kept so later rounds and
/// resumed runs do not ask again for events the server has already refused.
const TRIED_FILE: &str = "tried.txt";
const AUTH_TRIED_FILE: &str = "auth-tried.txt";

/// Debug-only log of every request in a round. It is not event data, so it must
/// never be reloaded as events when resuming.
const REQUESTS_FILE: &str = "requests.jsonl";

/// `round-NNN` folders already in `output_dir`, in round order.
fn existing_rounds(output_dir: &Path) -> Result<Vec<(u32, PathBuf)>, AppError> {
    let mut found = Vec::new();
    for entry in fs::read_dir(output_dir)? {
        let path = entry?.path();
        let number = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("round-"))
            .and_then(|digits| digits.parse::<u32>().ok());
        if let Some(number) = number.filter(|_| path.is_dir()) {
            found.push((number, path));
        }
    }
    found.sort();
    Ok(found)
}

/// Events from every `*.jsonl` in a round folder. An interrupted run can leave
/// the last line of a file cut short; a malformed final nonblank line is skipped.
/// Excludes `requests.jsonl`. Earlier malformed lines and file I/O errors propagate.
fn read_round_events(dir: &Path) -> Result<Vec<JsonValue>, AppError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let is_events = path.extension().is_some_and(|ext| ext == "jsonl")
            && path.file_name().is_some_and(|name| name != REQUESTS_FILE);
        if is_events {
            files.push(path);
        }
    }
    files.sort();
    let mut events = Vec::new();
    for path in files {
        let text = String::from_utf8_lossy(&fs::read(&path)?).into_owned();
        let lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            match JsonValue::parse(line) {
                Ok(event) => events.push(event),
                Err(_) if index.saturating_add(1) == lines.len() => {
                    eprintln!("[warn] {}: skipping a truncated last line", path.display());
                }
                Err(e) => {
                    return Err(AppError::new(
                        ErrorCode::MalformedJson,
                        format!("{}:{}: {e}", path.display(), index.saturating_add(1)),
                    ));
                }
            }
        }
    }
    Ok(events)
}

/// Reads timeline request IDs from the output directory checkpoint; a missing
/// file is an empty set and other read errors propagate.
fn read_tried(output_dir: &Path) -> Result<HashSet<String>, AppError> {
    read_tried_file(&output_dir.join(TRIED_FILE))
}

/// Reads unique, trimmed, nonblank request IDs. A missing file is an empty
/// set; other I/O and invalid UTF-8 errors propagate.
fn read_tried_file(path: &Path) -> Result<HashSet<String>, AppError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(HashSet::new()),
        Err(error) => Err(error.into()),
    }
}

/// Replaces the timeline request checkpoint with sorted tried IDs,
/// propagating checkpoint I/O errors.
fn write_tried(output_dir: &Path, tried: &HashSet<String>) -> Result<(), AppError> {
    write_tried_file(&output_dir.join(TRIED_FILE), tried)
}

/// Replaces a checkpoint with sorted tried IDs, propagating I/O errors.
fn write_tried_file(path: &Path, tried: &HashSet<String>) -> Result<(), AppError> {
    let mut ids = tried.iter().cloned().collect::<Vec<_>>();
    ids.sort();
    write_frontier_checkpoint(path, &ids)
}

fn gap_fill_result(
    events: &[rezzy::JsonValue],
    fetched: &[PathBuf],
    completed_rounds: u32,
    failed_requests: usize,
    closed: bool,
) -> JsonValue {
    let final_report = crate::repair::scan_gaps(events);
    rezzy::json!({
        "status": if closed || final_report.is_closed() { "closed" } else { "incomplete" },
        "rounds": completed_rounds,
        "events": final_report.present.len(),
        "missing_prev_events": final_report.missing_prev.iter().cloned().collect::<Vec<_>>(),
        "missing_auth_events": final_report.missing_auth.iter().cloned().collect::<Vec<_>>(),
        "failed_requests": failed_requests,
        "fetched": fetched.iter().map(|path| path.to_string_lossy().to_string()).collect::<Vec<_>>(),
    })
}

/// Fetches missing timeline events and then auth chains, extending `events`.
/// Returns unique event counts before and after, fetched file paths, and the
/// failed request count. Unreachable destinations and auth-fetch or reload
/// errors propagate; other timeline crawl errors count as failed requests.
fn fetch_gap_round(
    request: &GapFillRequest<'_>,
    events: &mut Vec<JsonValue>,
    round_dir: &Path,
    round: u32,
    tried: &mut HashSet<String>,
    auth_tried: &mut HashSet<String>,
) -> Result<(usize, usize, Vec<PathBuf>, usize), AppError> {
    let before = crate::repair::scan_gaps(events).present.len();
    let report = crate::repair::scan_gaps(events);
    let mut fetched = Vec::new();
    let mut failed_requests = 0_usize;
    let requests_path = debug_enabled().then(|| round_dir.join(REQUESTS_FILE));
    let starts = report
        .missing_prev
        .iter()
        .filter(|id| !request.skip_tried || !tried.contains(*id))
        .cloned()
        .collect::<Vec<_>>();
    if !starts.is_empty() {
        let path = round_dir.join("backfill.jsonl");
        let known = events
            .iter()
            .filter_map(crate::repair::event_id_of)
            .collect::<HashSet<_>>();
        eprintln!(
            "[info] round {round}: fetching {} missing prev event(s) from {}",
            starts.len(),
            request.destination
        );
        let dag_request = DagRequest {
            origin: request.origin,
            destination: request.destination,
            room_id: request.room_id,
            starts: &starts,
            room_version: request.room_version,
            limit: -1,
            output: &path,
            key_path: request.key_path,
            no_fallback: request.no_fallback,
            emit_missing: None,
        };
        let tried_path = request.output_dir.join(TRIED_FILE);
        let result = get_remote_dag_with_known_and_checkpoint(
            &dag_request,
            Some(&known),
            Some(Checkpoint {
                tried,
                tried_path: &tried_path,
                requests_path: requests_path.as_deref(),
                round,
                skip_tried: request.skip_tried,
            }),
        );
        let summary = match result {
            Ok(summary) => summary,
            Err(error) if is_unreachable(&error) => return Err(error),
            Err(error) => {
                failed_requests = failed_requests.saturating_add(1);
                eprintln!("[warn] round {round}: backfill failed: {error}");
                rezzy::json!({})
            }
        };
        if let Some(n) = summary.get("failed_requests").and_then(JsonValue::as_u64) {
            failed_requests = usize::try_from(n).unwrap_or(usize::MAX);
            if let Some(detail) = summary.get("failures").and_then(JsonValue::as_str) {
                eprintln!("[warn] round {round}: {n} backfill request(s) failed: {detail}");
            }
        }
        if summary
            .get("count")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0)
            > 0
        {
            fetched.push(path.clone());
            events.extend(crate::repair::read_jsonl_events(&path)?);
        }
    }
    let (auth_path, auth_failures) = fetch_auth_for_round(
        request,
        events,
        round_dir,
        round,
        auth_tried,
        requests_path.as_deref(),
    )?;
    if let Some(path) = auth_path {
        fetched.push(path);
    }
    failed_requests = failed_requests.saturating_add(auth_failures);
    let after = crate::repair::scan_gaps(events).present.len();
    Ok((before, after, fetched, failed_requests))
}

/// Fetch missing timeline and authentication references for a bounded number
/// of rounds. This intentionally writes fetched batches separately; callers
/// can inspect or aggregate them without mutating the original input.
/// Zero rounds means continue until closed or no new events are added; on
/// resume, the limit counts newly run rounds. Earlier round events and tried
/// checkpoints are reloaded, and new round numbers follow the existing ones.
/// Requests are retried in later rounds unless `skip_tried` is set. Returns
/// closure status, missing references, fetched paths, and failure counts.
///
/// # Errors
/// Returns an error for existing round directories without resume, input or
/// checkpoint I/O failures, malformed resumed data, or an unreachable server.
fn gap_fill(request: &GapFillRequest<'_>) -> Result<JsonValue, AppError> {
    let GapFillRequest {
        inputs,
        rounds,
        output_dir,
        ..
    } = *request;
    fs::create_dir_all(output_dir)?;
    let earlier = existing_rounds(output_dir)?;
    if !earlier.is_empty() && !request.resume {
        return Err(AppError::new(
            ErrorCode::IoError,
            format!(
                "{} already has {} round folder(s); pass --resume to continue after them, \
                 or use a different --output-dir (a plain run would overwrite them)",
                output_dir.display(),
                earlier.len()
            ),
        ));
    }
    let mut events = Vec::new();
    for input in inputs {
        events.extend(crate::repair::read_jsonl_events(input)?);
    }
    let mut tried = HashSet::new();
    let mut auth_tried = HashSet::new();
    let mut round = 0_u32;
    if request.resume {
        for (number, dir) in &earlier {
            events.extend(read_round_events(dir)?);
            round = round.max(number.saturating_add(1));
        }
        tried = read_tried(output_dir)?;
        auth_tried = read_tried_file(&output_dir.join(AUTH_TRIED_FILE))?;
        eprintln!(
            "[info] resuming at round {round}: {} earlier round(s) reloaded, {} ID(s) requested before (re-asked unless --skip-tried)",
            earlier.len(),
            tried.len().saturating_add(auth_tried.len())
        );
    }

    let mut fetched = Vec::new();
    let mut completed_rounds = round;
    let mut failed_requests = 0_usize;
    let mut closed = false;
    let mut ran = 0_u32;
    loop {
        if rounds != 0 && ran >= rounds {
            break;
        }
        if crate::repair::scan_gaps(&events).is_closed() {
            closed = true;
            break;
        }
        let round_dir = output_dir.join(format!("round-{round:03}"));
        fs::create_dir_all(&round_dir)?;
        let (before, after, round_fetched, round_failures) = fetch_gap_round(
            request,
            &mut events,
            &round_dir,
            round,
            &mut tried,
            &mut auth_tried,
        )?;
        write_tried(output_dir, &tried)?;
        ran = ran.saturating_add(1);
        fetched.extend(round_fetched);
        failed_requests = failed_requests.saturating_add(round_failures);
        round = round.saturating_add(1);
        completed_rounds = round;
        if after <= before {
            break;
        }
    }
    Ok(gap_fill_result(
        &events,
        &fetched,
        completed_rounds,
        failed_requests,
        closed,
    ))
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

struct AuthFetchContext<'a> {
    origin: &'a str,
    destination: &'a str,
    room_id: &'a str,
    output: &'a Path,
    key_path: Option<&'a Path>,
    auth_tried: &'a mut HashSet<String>,
    auth_tried_path: &'a Path,
    requests_path: Option<&'a Path>,
    round: u32,
    skip_tried: bool,
}

/// Fetches auth chains for events citing missing auth references and writes
/// events with distinct IDs. Returns the written count and collected request
/// failures. Successful responses are flushed before marking requests tried;
/// unreachable destinations, serialization, and I/O errors propagate.
fn fetch_auth_batches(
    report: &crate::repair::GapReport,
    context: AuthFetchContext<'_>,
) -> Result<(usize, FetchFailures), AppError> {
    let AuthFetchContext {
        origin,
        destination,
        room_id,
        output,
        key_path,
        auth_tried,
        auth_tried_path,
        requests_path,
        round,
        skip_tried,
    } = context;
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
        if skip_tried && auth_tried.contains(&event_id) {
            continue;
        }
        let uri = format!(
            "/_matrix/federation/v1/event_auth/{}/{}",
            quote(room_id),
            quote(&event_id)
        );
        let started = Instant::now();
        let result = request(
            origin,
            destination,
            "GET",
            &uri,
            &rezzy::json!({}),
            key_path,
        );
        let attempt = attempt_of(Some(&event_id), "event_auth", &result, started);
        if let Some(path) = requests_path {
            append_auth_attempt(
                path,
                round,
                origin,
                destination,
                room_id,
                auth_tried,
                &attempt,
            )?;
        }
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                if is_unreachable(&error) {
                    return Err(error);
                }
                record_auth_tried(auth_tried_path, auth_tried, &event_id)?;
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
        // Record the request only once its events are flushed, so a resumed
        // run never skips an ID whose auth events were not saved.
        record_auth_tried(auth_tried_path, auth_tried, &event_id)?;
    }
    output_writer.flush()?;
    Ok((written, failures))
}

/// Fetches and reloads missing auth chains into `events`, returning the
/// nonempty output path and failed request count. Returns no path when nothing
/// is written; fetch and reload errors propagate.
fn fetch_auth_for_round(
    request: &GapFillRequest<'_>,
    events: &mut Vec<JsonValue>,
    round_dir: &Path,
    round: u32,
    auth_tried: &mut HashSet<String>,
    requests_path: Option<&Path>,
) -> Result<(Option<PathBuf>, usize), AppError> {
    let report = crate::repair::scan_gaps(events);
    if report.missing_auth.is_empty() {
        return Ok((None, 0));
    }
    let path = round_dir.join("auth.jsonl");
    let (count, failures) = fetch_auth_batches(
        &report,
        AuthFetchContext {
            origin: request.origin,
            destination: request.destination,
            room_id: request.room_id,
            output: &path,
            key_path: request.key_path,
            auth_tried,
            auth_tried_path: &request.output_dir.join(AUTH_TRIED_FILE),
            requests_path,
            round,
            skip_tried: request.skip_tried,
        },
    )?;
    if !failures.is_empty() {
        eprintln!(
            "[warn] round {round}: {} auth-chain request(s) failed: {}",
            failures.total(),
            failures.summary()
        );
    }
    if count > 0 {
        events.extend(crate::repair::read_jsonl_events(&path)?);
        Ok((Some(path), failures.total()))
    } else {
        Ok((None, failures.total()))
    }
}

/// Appends one authentication request record with a timestamp in Unix seconds.
/// Serialization and file I/O errors propagate.
fn append_auth_attempt(
    path: &Path,
    round: u32,
    origin: &str,
    destination: &str,
    room_id: &str,
    auth_tried: &HashSet<String>,
    attempt: &Attempt,
) -> Result<(), AppError> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let when = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let line = attempt_record(
        when,
        round,
        room_id,
        origin,
        destination,
        auth_tried,
        attempt,
    );
    let encoded = rezzy::json::write_string_value(&line)
        .map_err(|error| AppError::new(ErrorCode::MalformedJson, error.to_string()))?;
    writeln!(file, "{encoded}")?;
    Ok(())
}

/// Builds a request record with `when` in Unix seconds and duration in
/// milliseconds. An event request is a retry if its ID is in `tried`.
fn attempt_record(
    when: u64,
    round: u32,
    room_id: &str,
    origin: &str,
    destination: &str,
    tried: &HashSet<String>,
    attempt: &Attempt,
) -> JsonValue {
    rezzy::json!({
        "time": when,
        "round": u64::from(round),
        "event_id": opt_str(attempt.event_id.as_deref()),
        "room_id": room_id,
        "origin": origin,
        "destination": destination,
        "endpoint": attempt.endpoint,
        "outcome": attempt.outcome,
        "status": attempt.status.map(u64::from),
        "errcode": opt_str(attempt.errcode.as_deref()),
        "message": attempt.message.clone(),
        "millis": attempt.millis,
        "retry": attempt.event_id.as_ref().is_some_and(|id| tried.contains(id)),
    })
}

/// Adds a newly tried auth request ID to memory and appends it to the checkpoint.
/// File I/O errors propagate; an ID already in memory is not written again.
fn record_auth_tried(
    path: &Path,
    auth_tried: &mut HashSet<String>,
    event_id: &str,
) -> Result<(), AppError> {
    if auth_tried.insert(event_id.to_owned()) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{event_id}")?;
        file.flush()?;
    }
    Ok(())
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
    fn crawl_skips_known_events_and_does_not_requeue_their_ids() {
        use std::collections::HashSet;
        let dir = std::env::temp_dir().join(format!("rezzy-known-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("dag.jsonl");
        let starts = vec!["$new".to_owned()];
        let known: HashSet<String> = HashSet::from(["$have".to_owned()]);
        let request = super::DagRequest {
            origin: "o",
            destination: "d",
            room_id: "!r",
            starts: &starts,
            room_version: "12",
            limit: -1,
            output: &out,
            key_path: None,
            no_fallback: false,
            emit_missing: None,
        };
        let (mut state, max) = super::initialize_dag(&request, Some(&known)).unwrap();
        // A fetched event whose parents are one we hold and one we do not.
        let fetched = rezzy::json!({"event_id": "$new", "prev_events": ["$have", "$gap"]});
        assert!(super::write_dag_event(&fetched, "12", max, &mut state).unwrap());
        let queued: Vec<String> = state.queue.iter().cloned().collect();
        assert_eq!(queued, vec!["$new".to_owned(), "$gap".to_owned()]);
        // An event we already hold is neither written nor crawled through.
        let held = rezzy::json!({"event_id": "$have", "prev_events": ["$deeper"]});
        assert!(super::write_dag_event(&held, "12", max, &mut state).unwrap());
        assert_eq!(state.event_count, 1);
        assert!(!state.queue.iter().any(|id| id == "$deeper"));
        let _ = std::fs::remove_dir_all(&dir);
    }

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
    fn crawl_rejects_emit_missing_aliasing_output() {
        let dir = std::env::temp_dir().join(format!("rezzy-dag-alias-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("dag.jsonl");
        let starts = vec!["$a".to_owned()];
        let alias = dir.join(".").join("dag.jsonl");
        let request = super::DagRequest {
            origin: "o",
            destination: "d",
            room_id: "!r",
            starts: &starts,
            room_version: "12",
            limit: -1,
            output: &out,
            key_path: None,
            no_fallback: false,
            emit_missing: Some(&alias),
        };
        assert!(super::initialize_dag(&request, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
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
