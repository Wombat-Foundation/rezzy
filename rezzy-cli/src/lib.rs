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

#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]
//! Command-line utilities for working with Rezzy state data.

#[macro_use]
pub mod error;
pub mod aggregate;
#[cfg(feature = "tls")]
pub mod federation;
/// Output formats for resolved state, events, HAMT data, and timelines.
pub mod format;
/// The `hash` subcommand: direct LtHash accumulator inspection.
pub mod hash;
pub mod inspect;
/// Merging several JSONL event files into one deduplicated set.
pub mod jsonl_merge;
/// Fetching room state from a homeserver.
pub mod network;
pub mod provenance;
pub mod repair;
/// Timeline orderings and the Kahn topological sort behind them.
pub mod timeline_order;
/// Shared helpers for loading events and resolving state.
pub mod utils;

/// HTTP client identity sent by Rezzy's outbound requests.
pub const USER_AGENT: &str = concat!("rezzy/", env!("CARGO_PKG_VERSION"));

use crate::timeline_order::{OrderKey, TimelineOrder};
use format::{format_cli_output, FormattingContext};
use rezzy::OutputFormat;
use rezzy::{LeanEvent, StateResVersion};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;
use utils::{
    apply_global_power_levels, compute_state_maps, detect_version, load_or_fetch_input_value,
    parse_and_extract_heads, partition_and_resolve_state,
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
/// Parsed command-line arguments for the default state-resolution command.
pub struct Args {
    /// JSONL event files to read.
    pub input: Vec<PathBuf>,

    /// Room to fetch from `--homeserver`.
    pub room: Option<String>,

    /// Homeserver to fetch room events from instead of reading files.
    pub homeserver: Option<String>,

    /// Matrix access token. Falls back to per-domain env var (e.g. `MTOKEN_MATRIX_UNREDACTED_ORG`)
    pub token: Option<String>,

    /// File to write output to instead of stdout.
    pub output: Option<PathBuf>,

    /// State resolution version; inferred from the room version when unset.
    pub state_res: Option<StateResVersion>,

    /// Output format.
    pub format: OutputFormat,

    /// Print diagnostic detail.
    pub debug: bool,

    /// Suppress informational and warning messages.
    pub quiet: bool,

    /// Validate input only; suppress state output and exit.
    pub check: bool,

    /// Server name embedded as the origin in `-f federation` output.
    pub origin: String,

    /// Ordering for `-f timeline`.
    pub timeline_order: TimelineOrder,

    /// Ready-queue key order for `-f timeline --timeline-order causal`.
    pub tie_break: Vec<OrderKey>,

    /// Whether `--timeline-order` was passed on the command line.
    pub timeline_order_explicit: bool,

    /// Explicit provenance sidecar for stream-order lookups.
    pub metadata: Option<PathBuf>,
}

impl Args {
    /// Parse the process arguments.
    ///
    /// # Panics
    ///
    /// Panics if the command line cannot be parsed (clap prints usage and exits).
    #[must_use]
    pub fn parse() -> Self {
        let matches = cli_command().get_matches();
        if let Some(name) = matches.subcommand_name() {
            cli_command()
                .error(
                    clap::error::ErrorKind::InvalidSubcommand,
                    format!("subcommand {name} must be handled by rezzy's command dispatcher"),
                )
                .exit();
        }
        Self::from_matches(&matches)
    }

    fn from_matches(matches: &clap::ArgMatches) -> Self {
        let input = matches
            .get_many::<PathBuf>("input")
            .map(|values| values.cloned().collect())
            .unwrap_or_default();

        Self {
            input,
            room: matches.get_one::<String>("room").cloned(),
            homeserver: matches.get_one::<String>("homeserver").cloned(),
            token: matches.get_one::<String>("token").cloned(),
            output: matches.get_one::<PathBuf>("output").cloned(),
            state_res: matches.get_one::<StateResVersion>("state_res").copied(),
            format: matches
                .get_one::<OutputFormat>("format")
                .copied()
                .unwrap_or_default(),
            debug: matches.get_flag("debug"),
            quiet: matches.get_flag("quiet"),
            check: matches.get_flag("check"),
            origin: matches
                .get_one::<String>("origin")
                .cloned()
                .unwrap_or_else(|| String::from("matrix.org")),
            timeline_order: *matches
                .get_one::<TimelineOrder>("timeline-order")
                .expect("timeline-order has a default"),
            tie_break: matches
                .get_many::<OrderKey>("tie-break")
                .map(|values| values.copied().collect())
                .unwrap_or_default(),
            timeline_order_explicit: matches.value_source("timeline-order")
                == Some(clap::parser::ValueSource::CommandLine),
            metadata: matches.get_one::<PathBuf>("metadata").cloned(),
        }
    }
}

/// Build the top-level CLI parser, including subcommands.
#[must_use]
pub fn cli_command() -> clap::Command {
    let command = clap::Command::new("rezzy")
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            clap::Arg::new("input")
                .short('i')
                .long("input")
                .num_args(1..)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(clap::Arg::new("room").short('r').long("room"))
        .arg(
            clap::Arg::new("homeserver")
                .long("homeserver")
                .env("MATRIX_HOMESERVER"),
        )
        .arg(
            clap::Arg::new("token")
                .long("token")
                .env("MATRIX_TOKEN")
                .hide_env_values(true),
        )
        .arg(
            clap::Arg::new("output")
                .short('o')
                .long("output")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::Arg::new("state_res")
                .short('s')
                .long("state-res")
                .value_parser(clap::builder::EnumValueParser::<StateResVersion>::new()),
        )
        .arg(
            clap::Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(clap::builder::EnumValueParser::<OutputFormat>::new())
                .default_value("default"),
        )
        .arg(
            clap::Arg::new("debug")
                .long("debug")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            clap::Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            clap::Arg::new("check")
                .short('c')
                .long("check")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            clap::Arg::new("origin")
                .long("origin")
                .default_value("matrix.org"),
        )
        .arg(
            clap::Arg::new("timeline-order")
                .long("timeline-order")
                .value_parser(clap::builder::EnumValueParser::<TimelineOrder>::new())
                .default_value("causal")
                .help("Ordering for -f timeline: causal (Kahn) or synapse (depth + sidecar stream order)"),
        )
        .arg(
            clap::Arg::new("tie-break")
                .long("tie-break")
                .value_delimiter(',')
                .value_parser(clap::builder::EnumValueParser::<OrderKey>::new())
                .help("Tie-break order for simultaneously eligible events in causal mode. Parent-before-child ordering always wins. Portable keys (server-agnostic): origin_server_ts,matrix_depth,event_id. Server-local keys (need --metadata): stream_ordering,pdu_count."),
        )
        .arg(
            clap::Arg::new("metadata")
                .long("metadata")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Explicit provenance sidecar for stream-order lookups"),
        )
        .subcommand(aggregate::command());
    #[cfg(feature = "tls")]
    let command = command.subcommand(federation::command());
    command
        .subcommand(hash::command())
        .subcommand(inspect::command())
        .subcommand(repair::command())
        .subcommand(
            clap::Command::new("completions")
                .about("Print a shell completion script to stdout")
                .arg(
                    clap::Arg::new("shell")
                        .required(true)
                        .value_parser(clap::value_parser!(clap_complete::Shell)),
                ),
        )
}

fn misplaced_top_level_argument(matches: &clap::ArgMatches) -> Option<String> {
    cli_command().get_arguments().find_map(|arg| {
        let id = arg.get_id().as_str();
        (matches.value_source(id) == Some(clap::parser::ValueSource::CommandLine))
            .then(|| id.to_owned())
    })
}

/// Reject ordering flags used with a format they do not apply to.
///
/// # Errors
/// Returns [`error::ErrorCode::UnexpectedFormat`] for an incompatible
/// combination of `-f` and the timeline ordering flags.
fn validate_timeline_args(args: &Args) -> Result<(), error::AppError> {
    let timeline = matches!(args.format, OutputFormat::Timeline);
    let used_ordering_flags =
        args.timeline_order_explicit || !args.tie_break.is_empty() || args.metadata.is_some();
    if !timeline {
        if used_ordering_flags {
            return Err(error::AppError::new(
                error::ErrorCode::UnexpectedFormat,
                format!(
                    "timeline ordering flags (--timeline-order/--tie-break/--metadata) require -f timeline, not -f {}",
                    format_name(args.format)
                ),
            ));
        }
        return Ok(());
    }
    if args.timeline_order != TimelineOrder::Causal && !args.tie_break.is_empty() {
        return Err(error::AppError::new(
            error::ErrorCode::UnexpectedFormat,
            String::from("--tie-break only applies to --timeline-order causal"),
        ));
    }
    if args.metadata.is_some() && !format::needs_stream_order(args) {
        return Err(error::AppError::new(
            error::ErrorCode::UnexpectedFormat,
            String::from(
                "--metadata requires --timeline-order synapse or a stream_ordering/pdu_count tie-break key",
            ),
        ));
    }
    Ok(())
}

const fn format_name(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Events => "events",
        OutputFormat::Default => "default",
        OutputFormat::Deltas => "deltas",
        OutputFormat::Federation => "federation",
        OutputFormat::Summary => "summary",
        OutputFormat::Timeline => "timeline",
        OutputFormat::TimelineChronological => "timeline-chronological",
        OutputFormat::ResolveState => "resolve-state",
        OutputFormat::Hamt => "hamt",
    }
}

/// Run the CLI application.
///
/// # Errors
///
/// Returns an error when input loading, parsing, or state resolution fails.
///
/// # Panics
///
/// Panics if an auth-chain index produced by the graph cannot be looked up in
/// that same graph's index.
#[allow(clippy::too_many_lines)]
pub fn run_cli(args: &Args) -> Result<rezzy::JsonValue, error::AppError> {
    validate_timeline_args(args)?;
    let input_val = load_or_fetch_input_value(args)?;
    let (raw_events, heads) = parse_and_extract_heads(&input_val, args.debug)?;

    // --check mode: validate input only, suppress state output
    if args.check {
        return Ok(rezzy::json!({ "status": "ok" }));
    }

    let event_count = raw_events.len();
    let mut room_version: Option<String> = None;
    let version = match args.state_res {
        Some(v) => v,
        None => detect_version(&raw_events, args.debug)?,
    };
    // Needed up front (not discovered mid-loop below, since `raw_events`
    // isn't guaranteed to have `m.room.create` first) for
    // `validate_syntactic`'s version-string-sensitive checks. Absent
    // room_version defaults to "1" per spec.
    let syntactic_room_version =
        utils::detect_room_version_string(&raw_events).unwrap_or_else(|| "1".to_string());

    let mut raw_map = HashMap::with_capacity(event_count);
    let mut events_map = HashMap::with_capacity(event_count);
    let mut creator_user_id = String::new();
    let mut syntactically_rejected: usize = 0;
    let mut parsed: usize = 0;
    let progress_interval = if args.debug { 10_000 } else { 50_000 };
    // A non-compliant MXID recurs on every event its user authors, so collect
    // them by (field, MXID) and summarize once instead of emitting a warning
    // per event.
    let mut compatibility_mxids: BTreeMap<(&'static str, String), usize> = BTreeMap::new();

    for val in raw_events {
        match LeanEvent::from_value(&val, Some(syntactic_room_version.as_str())) {
            Ok(ev) => {
                // A syntactically-invalid-but-parseable event (e.g. a
                // malformed sender MXID a lenient origin server already
                // accepted into a real room's history) is treated as
                // rejected -- like an auth failure -- not a fatal CLI error:
                // real DAGs pulled from the wild contain events no current
                // homeserver would author but that already exist, and this
                // is a diagnostic tool for exactly that data, not a strict
                // federation-grade validator (see the startup WARNING).
                // Excluding it here (never inserted into raw_map/events_map)
                // keeps it out of state resolution the same way an
                // AuthError-rejected event would be.
                match ev.validate_syntactic(&syntactic_room_version) {
                    Ok(outcome) => {
                        if args.debug && !rezzy::basespec::rezzy_types::is_valid_mxid(&ev.sender) {
                            eprintln!(
                                "[DEBUG] event {} sender '{}' uses the compatibility MXID grammar",
                                ev.event_id, ev.sender
                            );
                        }
                        if !args.quiet {
                            for warning in outcome.warnings {
                                match &warning {
                                    rezzy::Warning::CompatibilityMxid { field, mxid, .. } => {
                                        let count = compatibility_mxids
                                            .entry((*field, mxid.clone()))
                                            .or_insert(0_usize);
                                        *count = count.saturating_add(1);
                                        if args.debug {
                                            eprintln!("[WARN] {warning}");
                                        }
                                    }
                                    _ => eprintln!("[WARN] {warning}"),
                                }
                            }
                        }
                    }
                    Err(reason) => {
                        syntactically_rejected = syntactically_rejected.saturating_add(1);
                        if reason.starts_with("sender must be a valid MXID") {
                            eprintln!(
                                "[REJECTED] event {} sender {} not a valid MXID: '@', ':', domain, and localpart a-z, 0-9, '.', '_', '=', '-', '/', '+'",
                                ev.event_id, ev.sender
                            );
                        } else {
                            eprintln!(
                                "[REJECTED] event {} failed syntactic validation, excluded from resolution: {reason}",
                                ev.event_id
                            );
                        }
                        continue;
                    }
                }
                if ev.event_type == "m.room.create" {
                    creator_user_id.clone_from(&ev.sender);
                    room_version = ev
                        .content
                        .get("room_version")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                }
                raw_map.insert(ev.event_id.clone(), val);
                events_map.insert(ev.event_id.clone(), ev);
            }
            Err(e) => {
                if args.debug {
                    eprintln!("[DEBUG] Failed to parse event: {val:?}. Error: {e}");
                }
                let msg = e;
                let code = if msg.contains("event_type") {
                    error::ErrorCode::EmptyEventType
                } else {
                    error::ErrorCode::MalformedJson
                };
                return Err(error::AppError::new(code, msg));
            }
        }
        parsed = parsed.saturating_add(1);
        if !args.quiet && parsed.checked_rem(progress_interval) == Some(0) {
            eprintln!("[progress] parsed {parsed}/{event_count} events, {} in graph, {syntactically_rejected} rejected", events_map.len());
        }
    }

    let heads = if heads.is_empty() {
        let all_ids: std::collections::HashSet<String> = events_map.keys().cloned().collect();
        let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
        for ev in events_map.values() {
            for pe in &ev.prev_events {
                referenced.insert(pe.clone());
            }
        }
        let mut auto_heads: Vec<String> = all_ids.difference(&referenced).cloned().collect();
        auto_heads.sort();
        if args.debug {
            eprintln!(
                "[DEBUG] Auto-computed {} heads: {:?}",
                auto_heads.len(),
                auto_heads
            );
        }
        auto_heads
    } else {
        heads
    };

    if !args.quiet {
        let room_label = args.room.as_deref().unwrap_or("<local-input>");
        let room_version_label = room_version.as_deref().unwrap_or("1");
        eprintln!(
            "INFO rezzy: room={room_label} room_version={room_version_label} state_res_version={version:?}"
        );
        eprintln!(
            "WARNING rezzy is a diagnostic tool: it does not perform federation-grade PDU validation (signatures, required hashes). Structural/syntactic invariants (validate_syntactic) are enforced during ingestion."
        );
        if syntactically_rejected > 0 {
            eprintln!(
                "[WARN] {syntactically_rejected} event(s) excluded from resolution for failing syntactic validation (see [REJECTED] lines above)"
            );
        }
    }

    if !args.quiet {
        // No external event store is available; every referenced-but-absent event is a gap.
        let (backward, missing_auth) = utils::report_gaps(&events_map, |_| false);
        let describe = |id: &str| -> String {
            events_map.get(id).map_or_else(
                || String::from("<?>"),
                |ev| format!("{} {} ts={}", ev.event_type, ev.sender, ev.origin_server_ts),
            )
        };
        if !missing_auth.is_empty() {
            eprintln!(
                "[WARN] {} event(s) reference auth_events absent from local set (auth cannot be fully verified):",
                missing_auth.len()
            );
            for gap in missing_auth.iter().take(20) {
                eprintln!(
                    "    {} ({}) -> missing auth {}",
                    gap.event_id,
                    describe(&gap.event_id),
                    gap.missing_auth_events.join(", ")
                );
            }
        }
        if !backward.is_empty() {
            eprintln!(
                "[WARN] {} event(s) reference prev_events absent from local set (backfill/backward extremity):",
                backward.len()
            );
            for gap in backward.iter().take(20) {
                eprintln!(
                    "    {} ({}) -> missing prev {}",
                    gap.event_id,
                    describe(&gap.event_id),
                    gap.missing_prev_events.join(", ")
                );
            }
        }
        if !compatibility_mxids.is_empty() {
            let total: usize = compatibility_mxids.values().copied().sum();
            eprintln!(
                "[WARN] {total} event(s) from {} non-compliant MXID(s) accepted for compatibility with \
                 historical user IDs (MSC4303 is proposed; no current room version enforces it):",
                compatibility_mxids.len()
            );
            for ((_field, mxid), count) in &compatibility_mxids {
                eprintln!("    '{mxid}' ×{count}");
            }
        }
    }

    let state_maps = {
        if !args.quiet {
            eprintln!("[progress] building state maps...");
        }
        let t = Instant::now();
        let m = compute_state_maps(&heads, &events_map, &raw_map, args.debug);
        if !args.quiet {
            eprintln!("[progress] state maps built in {:.2?}", t.elapsed());
        }
        m
    };

    if version != rezzy::StateResVersion::V2_1 && version != rezzy::StateResVersion::V2_1_1 {
        apply_global_power_levels(&mut events_map, &creator_user_id, version);
    }

    let auth_graph = {
        if !args.quiet {
            eprintln!("[progress] building auth graph...");
        }
        let t = Instant::now();
        let g = rezzy::auth::roaring::AuthGraph::build(&events_map);
        if !args.quiet {
            eprintln!("[progress] auth graph built in {:.2?}", t.elapsed());
        }
        g
    };

    let (final_state_map, duration) = {
        if !args.quiet {
            eprintln!("[progress] resolving state...");
        }
        let t = Instant::now();
        let r = partition_and_resolve_state(&heads, &events_map, &state_maps, version, &auth_graph);
        if !args.quiet {
            eprintln!(
                "[progress] state resolved in {:?} (wall {:?})",
                r.1,
                t.elapsed()
            );
        }
        r
    };

    let resolved_state_list: Vec<String> = final_state_map.values().cloned().collect();
    let mut auth_chain_bitmap = roaring::RoaringBitmap::new();
    for id in &resolved_state_list {
        if let Some(idx) = auth_graph.index.index_of(id) {
            auth_chain_bitmap |= &auth_graph.auth_bitmaps[idx as usize];
        }
    }
    let auth_chain_ids: Vec<String> = auth_chain_bitmap
        .into_iter()
        .map(|idx| {
            auth_graph
                .index
                .item_at(idx as usize)
                .cloned()
                .expect("auth-chain index came from this graph")
        })
        .collect();

    let stream_order = if format::needs_stream_order(args) {
        format::load_stream_order(args, &events_map, &raw_map, room_version.as_deref())?
    } else {
        None
    };

    let ctx = FormattingContext {
        args,
        events_map: &events_map,
        raw_map: &raw_map,
        heads: &heads,
        final_state_map: &final_state_map,
        resolved_state_list: &resolved_state_list,
        auth_chain_ids: &auth_chain_ids,
        auth_graph: &auth_graph,
        version,
        room_version: room_version.as_deref(),
        duration,
        event_count,
        stream_order: stream_order.as_ref(),
    };

    Ok(format_cli_output(&ctx))
}

/// Run the command-line entry point and write its JSON output.
///
/// # Panics
///
/// Panics if the output file cannot be created or written, or if the JSON
/// output cannot be formatted.
fn open_output(path: Option<PathBuf>) -> Box<dyn Write> {
    let Some(path) = path else {
        return Box::new(BufWriter::new(io::stdout()));
    };
    Box::new(BufWriter::new(
        File::create(path).expect("Failed to create output file"),
    ))
}

pub fn main_entry() {
    let mut command = cli_command();
    let matches = command.get_matches_mut();
    if let Some(("completions", sub)) = matches.subcommand() {
        let shell = *sub
            .get_one::<clap_complete::Shell>("shell")
            .expect("shell is required");
        let name = command.get_name().to_owned();
        clap_complete::generate(shell, &mut command, name, &mut io::stdout());
        return;
    }
    if let Some(("aggregate", aggregate_matches)) = matches.subcommand() {
        if let Some(id) = misplaced_top_level_argument(&matches) {
            eprintln!(
                "Error: --{id} belongs after the aggregate subcommand; use `rezzy aggregate --help`"
            );
            std::process::exit(2);
        }
        match aggregate::run_from_matches(aggregate_matches) {
            Ok(outcome) => {
                let output = match &outcome {
                    aggregate::AggregateOutcome::Complete(output)
                    | aggregate::AggregateOutcome::Partial(output) => output,
                };
                let pretty = rezzy::json::write_string_pretty(output)
                    .expect("JSON formatting is infallible");
                println!("{pretty}");
                if let aggregate::AggregateOutcome::Partial(report) = &outcome {
                    if !aggregate_matches.get_flag("quiet") {
                        let failed = report["failed"].as_u64().unwrap_or(0);
                        eprintln!("Error: {failed} room(s) failed; see the JSON report");
                    }
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    #[cfg(feature = "tls")]
    if let Some(("federation", federation_matches)) = matches.subcommand() {
        print_json_command_result(federation::run_from_matches(federation_matches));
    }
    if let Some(("inspect", inspect_matches)) = matches.subcommand() {
        match inspect::run_from_matches(inspect_matches) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(("hash", hash_matches)) = matches.subcommand() {
        print_json_command_result(hash::run_from_matches(hash_matches));
    }
    if let Some(("repair-ids", repair_matches)) = matches.subcommand() {
        print_json_command_result(repair::run_from_matches(repair_matches));
    }
    let args = Args::from_matches(&matches);
    match run_cli(&args) {
        Ok(output) => {
            let mut buffered_out = open_output(args.output);
            let pretty =
                rezzy::json::write_string_pretty(&output).expect("JSON formatting is infallible");
            buffered_out
                .write_all(pretty.as_bytes())
                .expect("Failed to write output");
            if let Err(e) = writeln!(buffered_out) {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    return;
                }
                panic!("Failed to write trailing newline: {e}");
            }
            buffered_out.flush().expect("Failed to flush output buffer");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            let err_json = rezzy::json!({
                "status": "error",
                "code": e.code().code(),
                "error": e.to_string()
            });
            if let Ok(pretty) = rezzy::json::write_string_pretty(&err_json) {
                let _ = io::stderr().write_all(pretty.as_bytes());
            }
            eprintln!();
            std::process::exit(1);
        }
    }
}

fn print_json_command_result(result: Result<rezzy::JsonValue, error::AppError>) -> ! {
    match result {
        Ok(output) => println!(
            "{}",
            rezzy::json::write_string_pretty(&output).expect("JSON formatting is infallible")
        ),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
    std::process::exit(0);
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{run_cli, Args};
    use crate::error::ErrorCode;
    use rezzy::OutputFormat;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempFixture {
        path: PathBuf,
    }

    impl Drop for TempFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn args_without_input() -> Args {
        Args {
            input: Vec::new(),
            room: None,
            homeserver: None,
            token: None,
            output: None,
            state_res: None,
            format: OutputFormat::Default,
            debug: false,
            quiet: true,
            check: true,
            origin: String::from("matrix.org"),
            timeline_order: crate::timeline_order::TimelineOrder::default(),
            tie_break: Vec::new(),
            timeline_order_explicit: false,
            metadata: None,
        }
    }

    fn args_for_input(path: PathBuf) -> Args {
        let mut args = args_without_input();
        args.input = vec![path];
        args
    }

    fn write_fixture(contents: &str) -> TempFixture {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rezzy-cli-test-{}-{}.json",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("write CLI test fixture");
        TempFixture { path }
    }

    #[test]
    fn check_mode_validates_a_file_without_resolving_it() {
        let fixture = write_fixture(r#"{"event_id":"$event","type":"m.room.message"}"#);
        let result = run_cli(&args_for_input(fixture.path.clone())).expect("check mode succeeds");

        assert_eq!(result, rezzy::json!({ "status": "ok" }));
    }

    #[test]
    fn malformed_file_returns_malformed_json_error() {
        let fixture = write_fixture("not JSON");
        let error =
            run_cli(&args_for_input(fixture.path.clone())).expect_err("malformed input fails");

        assert_eq!(error.code(), ErrorCode::MalformedJson);
    }

    #[test]
    fn missing_input_returns_missing_input_error() {
        let args = args_without_input();

        let error = run_cli(&args).expect_err("missing input fails");

        assert_eq!(error.code(), ErrorCode::MissingInputFlag);
    }

    #[test]
    fn room_input_requires_a_homeserver() {
        let mut args = args_without_input();
        args.room = Some(String::from("!room:example.org"));

        let error = run_cli(&args).expect_err("missing homeserver fails");

        assert_eq!(error.code(), ErrorCode::MissingHomeserver);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cli_tests {
    use super::*;
    use crate::error::ErrorCode;
    use crate::timeline_order::{OrderKey, TimelineOrder};

    #[test]
    fn aggregate_rejects_top_level_command_line_flags() {
        let matches = cli_command()
            .try_get_matches_from([
                "rezzy",
                "--quiet",
                "aggregate",
                "--room",
                "room",
                "--output",
                "out.jsonl",
            ])
            .unwrap();
        assert_eq!(
            misplaced_top_level_argument(&matches).as_deref(),
            Some("quiet")
        );
    }

    #[test]
    fn completions_subcommand_parses_a_shell() {
        let matches = cli_command()
            .try_get_matches_from(["rezzy", "completions", "bash"])
            .expect("completions should accept a shell");
        let Some(("completions", sub)) = matches.subcommand() else {
            panic!("completions subcommand missing");
        };
        assert_eq!(
            sub.get_one::<clap_complete::Shell>("shell").copied(),
            Some(clap_complete::Shell::Bash)
        );
    }

    #[test]
    fn completions_generate_a_bash_script() {
        let mut command = cli_command();
        let name = command.get_name().to_owned();
        let mut buffer = Vec::new();
        clap_complete::generate(clap_complete::Shell::Bash, &mut command, name, &mut buffer);
        let script = String::from_utf8(buffer).expect("completion output is UTF-8");
        assert_ne!(script.len(), 0);
        assert!(script.contains("rezzy"));
    }

    #[test]
    fn aggregate_rejects_output_and_output_dir_together() {
        let error = cli_command()
            .try_get_matches_from([
                "rezzy",
                "aggregate",
                "--room",
                "room",
                "--output",
                "out.jsonl",
                "--output-dir",
                "merged",
            ])
            .expect_err("--output and --output-dir should conflict");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    fn timeline_args(extra: &[&str]) -> Args {
        let mut args = vec!["rezzy", "-i", "room.jsonl", "-f", "timeline"];
        args.extend_from_slice(extra);
        let matches = cli_command()
            .try_get_matches_from(args)
            .expect("timeline args should parse");
        Args::from_matches(&matches)
    }

    #[test]
    fn timeline_tie_break_parses_the_key_list() {
        let args = timeline_args(&[
            "--timeline-order",
            "causal",
            "--tie-break",
            "origin_server_ts,matrix_depth,event_id",
        ]);
        assert_eq!(args.timeline_order, TimelineOrder::Causal);
        assert!(args.timeline_order_explicit);
        assert_eq!(
            args.tie_break,
            vec![
                OrderKey::OriginServerTs,
                OrderKey::MatrixDepth,
                OrderKey::EventId
            ]
        );
        validate_timeline_args(&args).expect("causal tie-break is valid");
    }

    #[test]
    fn timeline_ordering_flags_reject_incompatible_formats() {
        let args = timeline_args(&["--timeline-order", "synapse"]);
        let mut chronological = args;
        chronological.format = OutputFormat::TimelineChronological;
        let error =
            validate_timeline_args(&chronological).expect_err("chronological is not timeline");
        assert_eq!(error.code(), ErrorCode::UnexpectedFormat);
        assert!(error.to_string().contains("require -f timeline"));
    }

    #[test]
    fn synapse_rejects_a_tie_break() {
        let args = timeline_args(&[
            "--timeline-order",
            "synapse",
            "--tie-break",
            "origin_server_ts",
        ]);
        let error = validate_timeline_args(&args).expect_err("synapse has no tie-break");
        assert_eq!(error.code(), ErrorCode::UnexpectedFormat);
    }

    #[test]
    fn metadata_requires_stream_order() {
        let args = timeline_args(&["--metadata", "other.rezzy-meta.jsonl"]);
        let error = validate_timeline_args(&args).expect_err("metadata without stream order");
        assert_eq!(error.code(), ErrorCode::UnexpectedFormat);
    }
}
