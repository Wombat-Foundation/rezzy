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

mod format;
mod network;
mod utils;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::{Parser, ValueEnum};
use format::{format_cli_output, FormattingContext};
use rezzy::{LeanEvent, StateResVersion};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use utils::{
    apply_global_power_levels, compute_state_maps, detect_version, load_or_fetch_input_value,
    parse_and_extract_heads, partition_and_resolve_state,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long, num_args(1..))]
    pub input: Vec<PathBuf>,

    #[arg(short, long)]
    pub room: Option<String>,

    #[arg(long, env = "MATRIX_HOMESERVER")]
    pub homeserver: Option<String>,

    /// Matrix access token. Falls back to per-domain env var (e.g. `MTOKEN_MATRIX_UNREDACTED_ORG`)
    #[arg(long, env = "MATRIX_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    #[arg(short, long)]
    pub output: Option<PathBuf>,

    #[arg(short, long, value_enum)]
    pub state_res: Option<StateResVersion>,

    #[arg(short, long, value_enum, default_value = "default")]
    pub format: OutputFormat,

    #[arg(long)]
    pub debug: bool,

    #[arg(short, long)]
    pub quiet: bool,

    #[arg(long, default_value = "matrix.org")]
    pub origin: String,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Events,
    Default,
    Deltas,
    Federation,
    Summary,
    Timeline,
}

fn run_cli(args: &Args) -> anyhow::Result<serde_json::Value> {
    let input_val = load_or_fetch_input_value(args)?;
    let (raw_events, heads) = parse_and_extract_heads(&input_val)?;

    let event_count = raw_events.len();
    let version = match args.state_res {
        Some(v) => v,
        None => detect_version(&raw_events, args.debug)?,
    };

    let mut raw_map = HashMap::with_capacity(event_count);
    let mut events_map = HashMap::with_capacity(event_count);
    let mut creator_user_id = String::new();

    for val in raw_events {
        match serde_json::from_value::<LeanEvent>(val.clone()) {
            Ok(ev) => {
                if ev.event_type == "m.room.create" {
                    creator_user_id.clone_from(&ev.sender);
                }
                raw_map.insert(ev.event_id.clone(), val);
                events_map.insert(ev.event_id.clone(), ev);
            }
            Err(e) => {
                if args.debug {
                    eprintln!("[DEBUG] Failed to parse event: {val:?}. Error: {e}");
                }
                let _ = serde_json::from_value::<LeanEvent>(val)?;
            }
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

    let state_maps = compute_state_maps(&heads, &events_map, &raw_map);

    if version != rezzy::StateResVersion::V2_1 && version != rezzy::StateResVersion::V2_1_1 {
        apply_global_power_levels(&mut events_map, &creator_user_id, version);
    }

    let auth_graph = rezzy::auth::roaring::AuthGraph::build(&events_map);

    let (final_state_map, duration) =
        partition_and_resolve_state(&heads, &events_map, &state_maps, version, &auth_graph);

    let resolved_state_list: Vec<String> = final_state_map.values().cloned().collect();
    let mut auth_chain_bitmap = roaring::RoaringBitmap::new();
    for id in &resolved_state_list {
        if let Some(&idx) = auth_graph.id_to_index.get(id) {
            auth_chain_bitmap |= &auth_graph.auth_bitmaps[idx as usize];
        }
    }
    let auth_chain_ids: Vec<String> = auth_chain_bitmap
        .into_iter()
        .map(|idx| auth_graph.index_to_id[idx as usize].clone())
        .collect();

    let ctx = FormattingContext {
        args,
        events_map: &events_map,
        raw_map: &raw_map,
        heads: &heads,
        final_state_map: &final_state_map,
        resolved_state_list: &resolved_state_list,
        auth_chain_ids: &auth_chain_ids,
        version,
        duration,
        event_count,
    };

    Ok(format_cli_output(&ctx))
}

fn main() {
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
            serde_json::to_writer_pretty(&mut buffered_out, &output)
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
            let err_json = serde_json::json!({
                "status": "error",
                "error": e.to_string()
            });
            serde_json::to_writer_pretty(io::stderr(), &err_json).ok();
            eprintln!();
            std::process::exit(1);
        }
    }
}
