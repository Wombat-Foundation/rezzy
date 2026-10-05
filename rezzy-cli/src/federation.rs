//! Signed Matrix server-server requests and the remote DAG crawler.

use crate::error::{AppError, ErrorCode};
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use clap::{Arg, ArgAction, ArgMatches, Command};
use ed25519_zebra::SigningKey;
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
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("http") {
                80
            } else {
                443
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
        .subcommand(encrypt_key_command())
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

fn encrypt_key_command() -> Command {
    Command::new("encrypt-key")
        .about("Encrypt a plaintext signing key into a passphrase-protected file")
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
        load_signing_key(origin, signing_key_path(m))?;
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
            get_remote_dag(&DagRequest {
                origin: m.get_one::<String>("origin").expect("default"),
                destination: m.get_one::<String>("destination").expect("required"),
                room_id: m.get_one::<String>("room").expect("required"),
                starts: &starts,
                room_version: m.get_one::<String>("room-version").expect("default"),
                limit: *m.get_one::<i64>("limit").expect("default"),
                output: m.get_one::<PathBuf>("output").expect("default"),
                key_path: signing_key_path(m),
                no_fallback: m.get_flag("no-fallback"),
                emit_missing: m.get_one::<PathBuf>("emit-missing").map(PathBuf::as_path),
            })
        }
        Some(("encrypt-key", m)) => {
            let out = m.get_one::<PathBuf>("output").expect("required");
            encrypt_key_file(m.get_one::<PathBuf>("input").expect("required"), out)?;
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
            })
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

/// Read the key-file passphrase from `REZZY_KEY_PASSPHRASE` (unattended use,
/// weaker: visible to the process environment) or prompt on the terminal.
fn read_passphrase(path: &Path) -> Result<String, AppError> {
    if let Ok(pw) = std::env::var("REZZY_KEY_PASSPHRASE") {
        return Ok(pw);
    }
    rpassword::prompt_password(format!("Passphrase for {}: ", path.display())).map_err(|e| {
        AppError::new(
            ErrorCode::SigningKey,
            format!("could not read passphrase (set REZZY_KEY_PASSPHRASE for unattended use): {e}"),
        )
    })
}

/// Resolve, decrypt and parse a Matrix server signing key.
///
/// The key must be a passphrase-encrypted file (see `federation encrypt-key`),
/// given by `--signing-key`, `MATRIX_SERVER_SIGNING_KEY_<DOMAIN>` or
/// `MATRIX_SERVER_SIGNING_KEY`. Plaintext key files are not accepted.
///
/// # Errors
/// Returns an error when no usable key is configured or the configured key is invalid.
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
    let passphrase = read_passphrase(&path)?;
    let plain = crate::keyfile::open(&file, passphrase.as_bytes()).map_err(err)?;
    let text = String::from_utf8(plain).map_err(|_| err("decrypted key is not UTF-8".into()))?;
    let spec = parse_signing_key(&text).map_err(err)?;
    if let Ok(mut cache) = signing_key_cache().lock() {
        cache.insert(cache_key, spec.clone());
    }
    Ok(spec)
}

/// Encrypt a plaintext signing key (read from `input`) into `output`, prompting for a
/// passphrase twice (or using `REZZY_KEY_PASSPHRASE`).
///
/// # Errors
/// Returns an error on I/O failure, mismatched passphrases, or an invalid key.
pub fn encrypt_key_file(input: &Path, output: &Path) -> Result<(), AppError> {
    let err = |m: String| AppError::new(ErrorCode::SigningKey, m);
    let plain = fs::read_to_string(input)?;
    parse_signing_key(&plain).map_err(|m| err(format!("{}: {m}", input.display())))?;
    let pw = if let Ok(pw) = std::env::var("REZZY_KEY_PASSPHRASE") {
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
        let found = match dig_srv(&name) {
            Ok(found) => found,
            Err(()) => {
                failed = true;
                None
            }
        };
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
            .map_or(true, |(best_priority, _, _)| priority < *best_priority)
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

/// Mutable state accumulated while walking a remote DAG.
struct DagWalkState {
    queue: VecDeque<String>,
    queued: HashSet<String>,
    seen: HashSet<String>,
    unresolved: Vec<String>,
    failures: FetchFailures,
    output_writer: BufWriter<fs::File>,
    event_count: usize,
}

fn initialize_dag(request: &DagRequest<'_>) -> Result<(DagWalkState, usize), AppError> {
    if request.starts.is_empty() {
        return Err(AppError::new(
            ErrorCode::MissingInputFlag,
            "get-remote-dag needs at least one --from <event-id> or --from-file <path> (the CLI has no local timeline to infer a starting event)",
        ));
    }
    let mut queue = VecDeque::new();
    let mut queued = HashSet::new();
    for id in request.starts {
        if queued.insert(id.clone()) {
            queue.push_back(id.clone());
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
            output_writer: open_output_writer(request.output)?,
            event_count: 0,
        },
        max,
    ))
}

fn finalize_dag(mut state: DagWalkState, request: &DagRequest<'_>) -> Result<JsonValue, AppError> {
    state.output_writer.flush()?;
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
/// skipped (invalid or duplicate) PDUs return `true` so the batch continues.
fn write_dag_event(
    pdu: &JsonValue,
    room_version: &str,
    max: usize,
    state: &mut DagWalkState,
) -> Result<bool, AppError> {
    let Some(object) = pdu.as_object() else {
        return Ok(true);
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
    let Some(event_id) = event_id else {
        return Ok(true);
    };
    if !state.seen.insert(event_id.clone()) {
        return Ok(true);
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
                if !state.seen.contains(id) && state.queued.insert(id.to_owned()) {
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
    Events(JsonValue, Vec<String>), // value, returned_ids
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
) -> Result<Vec<JsonValue>, AppError> {
    let mut pdus = Vec::new();
    for id in ids {
        let event_uri = format!("/_matrix/federation/v1/event/{}", quote(id));
        match request(
            dag_request.origin,
            dag_request.destination,
            "GET",
            &event_uri,
            &rezzy::json!({}),
            dag_request.key_path,
        ) {
            Ok(v) => pdus.push(v.get("pdu").cloned().unwrap_or(v)),
            Err(e) if is_unreachable(&e) => return Err(e),
            Err(e) => state.failures.record(&e),
        }
    }
    Ok(pdus)
}

fn fetch_dag_batch(
    dag_request: &DagRequest<'_>,
    ids: &[String],
    state: &mut DagWalkState,
) -> Result<DagBatch, AppError> {
    let uri = format!(
        "/_matrix/federation/v1/backfill/{}?{}&limit=500",
        quote(dag_request.room_id),
        ids.iter()
            .map(|id| format!("v={}", quote(id)))
            .collect::<Vec<_>>()
            .join("&")
    );
    let response = request(
        dag_request.origin,
        dag_request.destination,
        "GET",
        &uri,
        &rezzy::json!({}),
        dag_request.key_path,
    );
    let mut fell_back = false;
    let mut value = match response {
        Ok(v) => v,
        Err(e) if is_unreachable(&e) => return Err(e),
        Err(e) if !dag_request.no_fallback => {
            state.failures.record(&e);
            fell_back = true;
            rezzy::json!({"pdus": fetch_events_individually(dag_request, ids, state)?})
        }
        Err(e) => return Err(e),
    };
    let empty = value
        .get("pdus")
        .and_then(JsonValue::as_array)
        .map_or(true, Vec::is_empty);
    if empty && dag_request.no_fallback {
        state.unresolved.extend(ids.iter().cloned());
        return Ok(DagBatch::Stop);
    }
    // Skip the retry when the error branch already fetched each ID once.
    if empty && !fell_back {
        value = rezzy::json!({"pdus": fetch_events_individually(dag_request, ids, state)?});
    }
    // Track which requested IDs were actually returned in the response.
    let returned_ids: Vec<String> = value
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
    Ok(DagBatch::Events(value, returned_ids))
}

///
/// # Errors
/// Returns an error if fetching, parsing, or writing the crawl fails.
pub fn get_remote_dag(dag_request: &DagRequest<'_>) -> Result<JsonValue, AppError> {
    let room_version = dag_request.room_version;
    let (mut state, max) = initialize_dag(dag_request)?;
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
        let (value, _returned_ids) = match fetch_dag_batch(dag_request, &ids, &mut state)? {
            DagBatch::Events(value, returned_ids) => (value, returned_ids),
            DagBatch::Stop => break,
        };
        let Some(pdus) = value.get("pdus").and_then(JsonValue::as_array) else {
            continue;
        };
        for pdu in pdus {
            if !write_dag_event(pdu, room_version, max, &mut state)? {
                break;
            }
        }

        // Make the fetched events durable before advancing the checkpoint.
        // If interrupted after this point, re-fetching the checkpointed
        // frontier is safe because aggregate deduplicates event IDs.
        state.output_writer.flush()?;
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
    }
    finalize_dag(state, dag_request)
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

fn fetch_gap_round(
    request: &GapFillRequest<'_>,
    events: &mut Vec<JsonValue>,
    round_dir: &Path,
    round: u32,
) -> Result<(usize, usize, Vec<PathBuf>, usize), AppError> {
    let before = crate::repair::scan_gaps(events).present.len();
    let report = crate::repair::scan_gaps(events);
    let mut fetched = Vec::new();
    let mut failed_requests = 0_usize;
    if !report.missing_prev.is_empty() {
        let path = round_dir.join("backfill.jsonl");
        let starts = report.missing_prev.iter().cloned().collect::<Vec<_>>();
        let result = get_remote_dag(&DagRequest {
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
        });
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
    let report = crate::repair::scan_gaps(events);
    if !report.missing_auth.is_empty() {
        let path = round_dir.join("auth.jsonl");
        let (count, failures) = fetch_auth_batches(
            request.origin,
            request.destination,
            request.room_id,
            &report,
            &path,
            request.key_path,
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
    let after = crate::repair::scan_gaps(events).present.len();
    Ok((before, after, fetched, failed_requests))
}

/// Fetch missing timeline and authentication references for a bounded number
/// of rounds. This intentionally writes fetched batches separately; callers
/// can inspect or aggregate them without mutating the original input.
fn gap_fill(request: &GapFillRequest<'_>) -> Result<JsonValue, AppError> {
    let GapFillRequest {
        inputs,
        rounds,
        output_dir,
        ..
    } = *request;
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
        if crate::repair::scan_gaps(&events).is_closed() {
            closed = true;
            break;
        }
        let round_dir = output_dir.join(format!("round-{round:03}"));
        fs::create_dir_all(&round_dir)?;
        let (before, after, round_fetched, round_failures) =
            fetch_gap_round(request, &mut events, &round_dir, round)?;
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

fn fetch_auth_batches(
    origin: &str,
    destination: &str,
    room_id: &str,
    report: &crate::repair::GapReport,
    output: &Path,
    key_path: Option<&Path>,
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
        ) {
            Ok(value) => value,
            Err(error) => {
                if is_unreachable(&error) {
                    return Err(error);
                }
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
