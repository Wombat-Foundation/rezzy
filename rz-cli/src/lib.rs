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

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

#[macro_use]
pub mod error;
pub mod format;
pub mod jsonl_merge;
pub mod network;
pub mod utils;

use format::{format_cli_output, FormattingContext};
use rz_core::OutputFormat;
use rz_core::{LeanEvent, StateResVersion};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;
use utils::{
    apply_global_power_levels, compute_state_maps, detect_version, load_or_fetch_input_value,
    parse_and_extract_heads, partition_and_resolve_state,
};

#[derive(Debug)]
pub struct Args {
    pub input: Vec<PathBuf>,

    pub room: Option<String>,

    pub homeserver: Option<String>,

    /// Matrix access token. Falls back to per-domain env var (e.g. `MTOKEN_MATRIX_UNREDACTED_ORG`)
    pub token: Option<String>,

    pub output: Option<PathBuf>,

    pub state_res: Option<StateResVersion>,

    pub format: OutputFormat,

    pub debug: bool,

    pub quiet: bool,

    /// Validate input only; suppress state output and exit.
    pub check: bool,

    pub origin: String,
}

impl Args {
    /// Parse the process arguments.
    ///
    /// # Panics
    ///
    /// Panics if the command line cannot be parsed (clap prints usage and exits).
    #[must_use]
    pub fn parse() -> Self {
        let matches = clap::Command::new("rezzy")
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
            .get_matches();

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
        }
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
pub fn run_cli(args: &Args) -> Result<rz_core::JsonValue, error::AppError> {
    let input_val = load_or_fetch_input_value(args)?;
    let (raw_events, heads) = parse_and_extract_heads(&input_val, args.debug)?;

    // --check mode: validate input only, suppress state output
    if args.check {
        return Ok(rz_core::json!({ "status": "ok" }));
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

    for val in raw_events {
        match LeanEvent::from_value(&val, None) {
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
                        if !args.quiet {
                            for warning in outcome.warnings {
                                eprintln!("[WARN] {warning}");
                            }
                        }
                    }
                    Err(reason) => {
                        syntactically_rejected = syntactically_rejected.saturating_add(1);
                        eprintln!(
                            "[REJECTED] event {} failed syntactic validation, excluded from resolution: {reason}",
                            ev.event_id
                        );
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
                let msg = e.clone();
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
            match events_map.get(id) {
                Some(ev) => {
                    format!("{} {} ts={}", ev.event_type, ev.sender, ev.origin_server_ts)
                }
                None => String::from("<?>"),
            }
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

    if version != rz_core::StateResVersion::V2_1 && version != rz_core::StateResVersion::V2_1_1 {
        apply_global_power_levels(&mut events_map, &creator_user_id, version);
    }

    let auth_graph = {
        if !args.quiet {
            eprintln!("[progress] building auth graph...");
        }
        let t = Instant::now();
        let g = rz_core::auth::roaring::AuthGraph::build(&events_map);
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
    };

    Ok(format_cli_output(&ctx))
}

/// Run the command-line entry point and write its JSON output.
///
/// # Panics
///
/// Panics if the output file cannot be created or written, or if the JSON
/// output cannot be formatted.
pub fn main_entry() {
    let args = Args::parse();
    match run_cli(&args) {
        Ok(output) => {
            let output_writer: Box<dyn Write> = match args.output {
                Some(path) => Box::new(BufWriter::new(
                    File::create(path).expect("Failed to create output file"),
                )),
                None => Box::new(BufWriter::new(io::stdout())),
            };
            let mut buffered_out = output_writer;
            let pretty =
                rz_core::json::write_string_pretty(&output).expect("JSON formatting is infallible");
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
            let err_json = rz_core::json!({
                "status": "error",
                "code": e.code().code(),
                "error": e.to_string()
            });
            if let Ok(pretty) = rz_core::json::write_string_pretty(&err_json) {
                let _ = io::stderr().write_all(pretty.as_bytes());
            }
            eprintln!();
            std::process::exit(1);
        }
    }
}
