//! Merged benchmark runner for rezzy.
//!
//! Run all benchmarks:
//!   cargo bench --bench rezzy
//!
//! Run specific benchmarks (substring filter):
//!   cargo bench --bench rezzy -- lthash
//!   cargo bench --bench rezzy -- resolve
//!   cargo bench --bench rezzy -- state
//!
//! List available benchmarks:
//!   cargo bench --bench rezzy -- --list
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown,
    clippy::redundant_closure_for_method_calls
)]

#[path = "../common/mod.rs"]
mod common;

mod cumulative_rebuild;
mod hamt_audit_bitmap;
mod interned_key;
mod interned_lookup;
mod lthash;
mod mainline_cache;
mod persistence;
mod reconcile;
mod resolve;
mod state_backend;
mod state_groups;

struct BenchmarkEntry {
    name: &'static str,
    description: &'static str,
    run_fn: fn(),
}

const BENCHMARKS: &[BenchmarkEntry] = &[
    BenchmarkEntry {
        name: "cumulative_rebuild",
        description: "Step-by-step state rebuild simulation (HAMT vs sorted vs XOR-fold)",
        run_fn: cumulative_rebuild::run,
    },
    BenchmarkEntry {
        name: "hamt_audit_bitmap",
        description: "HAMT node reachability audit bitmap operations",
        run_fn: hamt_audit_bitmap::run,
    },
    BenchmarkEntry {
        name: "interned_key",
        description: "State resolution with interned string keys vs String keys",
        run_fn: interned_key::run,
    },
    BenchmarkEntry {
        name: "interned_lookup",
        description: "Micro-bench of event state lookups across multiple event types",
        run_fn: interned_lookup::run,
    },
    BenchmarkEntry {
        name: "lthash",
        description: "MSC4500 LtHash incremental state hash vs non-homomorphic baselines",
        run_fn: lthash::run,
    },
    BenchmarkEntry {
        name: "mainline_cache",
        description: "Mainline power-level search and ordering cache performance",
        run_fn: mainline_cache::run,
    },
    BenchmarkEntry {
        name: "persistence",
        description: "HAMT path-copying persistence vs full snapshot serialization",
        run_fn: persistence::run,
    },
    BenchmarkEntry {
        name: "reconcile",
        description: "Set reconciliation (PinSketch/Minisketch) encoding & decoding",
        run_fn: reconcile::run,
    },
    BenchmarkEntry {
        name: "resolve",
        description: "State resolution v1, v2, v2.1 benchmark matrix",
        run_fn: resolve::run,
    },
    BenchmarkEntry {
        name: "state_backend",
        description: "Persistent HAMT state backend vs im::OrdMap operations",
        run_fn: state_backend::run,
    },
    BenchmarkEntry {
        name: "state_groups",
        description: "HAMT content-addressed state groups vs delta-chain storage",
        run_fn: state_groups::run,
    },
];

fn print_list() {
    println!("Available benchmarks in rezzy:");
    for b in BENCHMARKS {
        println!("  {:<20} - {}", b.name, b.description);
    }
}

fn print_help() {
    println!("rezzy benchmark runner\n");
    println!("Usage:");
    println!("  cargo bench --bench rezzy                 Run all benchmarks");
    println!("  cargo bench --bench rezzy -- <FILTER>     Run matching benchmarks");
    println!("  cargo bench --bench rezzy -- --list       List available benchmarks\n");
    print_list();
}

fn is_cargo_harness_flag(arg: &str) -> bool {
    matches!(
        arg,
        "--bench"
            | "--test"
            | "--nocapture"
            | "--exact"
            | "--quiet"
            | "-q"
            | "--profile"
            | "release"
    ) || arg.starts_with("--color")
        || arg.starts_with("--format")
}

fn main() {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    // Check for help/list flags first
    for arg in &raw_args {
        if arg == "--list" || arg == "-l" {
            print_list();
            return;
        }
        if arg == "--help" || arg == "-h" {
            print_help();
            return;
        }
    }

    // Filter out standard cargo harness flags
    let filters: Vec<&str> = raw_args
        .iter()
        .map(String::as_str)
        .filter(|arg| !is_cargo_harness_flag(arg))
        .collect();

    let is_all = filters.is_empty() || filters.iter().any(|&f| f == "all");

    let mut matched_any = false;
    for b in BENCHMARKS {
        let should_run = is_all
            || filters
                .iter()
                .any(|&f| b.name.eq_ignore_ascii_case(f) || b.name.contains(f));

        if should_run {
            matched_any = true;
            println!("============================================================");
            println!(" BENCHMARK: {}", b.name);
            println!("============================================================");
            (b.run_fn)();
            println!();
        }
    }

    if !matched_any {
        eprintln!("No benchmarks matched filter: {:?}", filters);
        eprintln!();
        print_list();
        std::process::exit(1);
    }
}
