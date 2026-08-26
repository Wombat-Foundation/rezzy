//! Merged benchmark runner for rezzy.
//!
//! Organized by domain:
//!   - `state`: Matrix state resolution & DAG traversal
//!   - `db`: HAMT persistent state & delta storage
//!   - `math`: Homomorphic hashing & set reconciliation
//!
//! Run all benchmarks:
//!   cargo bench --bench rezzy
//!
//! Run a domain group:
//!   cargo bench --bench rezzy -- state
//!   cargo bench --bench rezzy -- db
//!   cargo bench --bench rezzy -- math
//!
//! Run a specific benchmark:
//!   cargo bench --bench rezzy -- lthash
//!   cargo bench --bench rezzy -- resolve
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

mod common;
mod db;
mod math;
mod state;

struct BenchmarkEntry {
    domain: &'static str,
    name: &'static str,
    description: &'static str,
    run_fn: fn(),
}

const BENCHMARKS: &[BenchmarkEntry] = &[
    // --- state (Matrix State Resolution & Traversal) ---
    BenchmarkEntry {
        domain: "state",
        name: "resolve",
        description: "State resolution v1, v2, v2.1 benchmark matrix",
        run_fn: state::resolve::run,
    },
    BenchmarkEntry {
        domain: "state",
        name: "mainline_cache",
        description: "Mainline power-level search and ordering cache performance",
        run_fn: state::mainline_cache::run,
    },
    BenchmarkEntry {
        domain: "state",
        name: "interned_key",
        description: "State resolution with interned string keys vs String keys",
        run_fn: state::interned_key::run,
    },
    BenchmarkEntry {
        domain: "state",
        name: "interned_lookup",
        description: "Micro-bench of event state lookups across multiple event types",
        run_fn: state::interned_lookup::run,
    },
    // --- db (HAMT Storage & Persistence) ---
    BenchmarkEntry {
        domain: "db",
        name: "state_backend",
        description: "Persistent HAMT state backend vs im::OrdMap operations",
        run_fn: db::state_backend::run,
    },
    BenchmarkEntry {
        domain: "db",
        name: "state_groups",
        description: "HAMT content-addressed state groups vs delta-chain storage",
        run_fn: db::state_groups::run,
    },
    BenchmarkEntry {
        domain: "db",
        name: "persistence",
        description: "HAMT path-copying persistence vs full snapshot serialization",
        run_fn: db::persistence::run,
    },
    BenchmarkEntry {
        domain: "db",
        name: "cumulative_rebuild",
        description: "Step-by-step state rebuild simulation (HAMT vs sorted vs XOR-fold)",
        run_fn: db::cumulative_rebuild::run,
    },
    BenchmarkEntry {
        domain: "db",
        name: "hamt_audit_bitmap",
        description: "HAMT node reachability audit bitmap operations",
        run_fn: db::hamt_audit_bitmap::run,
    },
    // --- math (Algebraic Structures & Set Reconciliation) ---
    BenchmarkEntry {
        domain: "math",
        name: "lthash",
        description: "MSC4500 LtHash incremental state hash vs non-homomorphic baselines",
        run_fn: math::lthash::run,
    },
    BenchmarkEntry {
        domain: "math",
        name: "reconcile",
        description: "Set reconciliation (PinSketch/Minisketch) encoding & decoding",
        run_fn: math::reconcile::run,
    },
];

fn print_list() {
    println!("Available benchmarks in rezzy:\n");
    let domains = ["state", "db", "math"];
    for domain in domains {
        let title = match domain {
            "state" => "State Resolution & Traversal (`state`)",
            "db" => "HAMT Storage & Persistence (`db`)",
            "math" => "Algebraic Data Structures & Reconciliation (`math`)",
            _ => domain,
        };
        println!("  [{domain}] {title}:");
        for b in BENCHMARKS.iter().filter(|b| b.domain == domain) {
            println!("    {:<20} - {}", b.name, b.description);
        }
        println!();
    }
}

fn print_help() {
    println!("rezzy benchmark suite\n");
    println!("Usage:");
    println!("  cargo bench --bench rezzy                 Run all benchmarks");
    println!(
        "  cargo bench --bench rezzy -- <DOMAIN>     Run benchmarks in domain (state, db, math)"
    );
    println!("  cargo bench --bench rezzy -- <NAME>       Run specific benchmark by name");
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

    let filters: Vec<&str> = raw_args
        .iter()
        .map(String::as_str)
        .filter(|arg| !is_cargo_harness_flag(arg))
        .collect();

    let is_all = filters.is_empty() || filters.contains(&"all");

    let mut matched_any = false;
    for b in BENCHMARKS {
        let should_run = is_all
            || filters.iter().any(|&f| {
                b.domain.eq_ignore_ascii_case(f)
                    || b.name.eq_ignore_ascii_case(f)
                    || b.name.contains(f)
            });

        if should_run {
            matched_any = true;
            println!("============================================================");
            println!(" [{}] BENCHMARK: {}", b.domain, b.name);
            println!("============================================================");
            (b.run_fn)();
            println!();
        }
    }

    if !matched_any {
        eprintln!("No benchmarks matched filter: {filters:?}");
        eprintln!();
        print_list();
        std::process::exit(1);
    }
}
