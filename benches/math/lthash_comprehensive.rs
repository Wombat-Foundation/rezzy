//! Comprehensive LtHash benchmarks: incremental, single, multi, and batch operations
//! across different input sizes and expansion backends.
//!
//! Run with: `cargo bench --bench rezzy -- lthash_comprehensive`
//!
//! Covers:
//! - Single operations: insert, remove, replace, seed
//! - Multi operations: batch insert/remove (varying batch sizes)
//! - Large batch operations: bulk state construction
//! - Input size variations: small (minimal), medium (typical), large (max event IDs)
//! - Expansion cost: the BLAKE3 XOF that seeds a lane, and the BLAKE3 collapse
//! - Lattice arithmetic

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use rezzy::state::LtHash;

use crate::common::{generate_unique_entries, Xorshift128};

type StateKey = (String, String);

/// Largest state size run with `InputSize::Large` (~64 MiB of event IDs).
const MAX_LARGE_STATE: usize = 1024;

/// Input size categories for testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputSize {
    Small,   // Minimal event IDs like "$a"
    Medium,  // Typical event IDs like "$event123:example.org"
    Large,   // Max-length event IDs (65535 bytes)
}

impl InputSize {
    fn name(&self) -> &'static str {
        match self {
            InputSize::Small => "small",
            InputSize::Medium => "medium",
            InputSize::Large => "large",
        }
    }

    fn generate_event_id(&self, rng: &mut Xorshift128, idx: usize) -> String {
        match self {
            InputSize::Small => format!("${idx}"),
            InputSize::Medium => format!("$event{idx}:example.org"),
            InputSize::Large => {
                // Generate a ~65KB event ID (truncated to u16::MAX)
                let len = 65535;
                let mut s = String::with_capacity(len + 2);
                s.push('$');
                for i in 0..len {
                    let c = ((rng.next_u64() >> (i % 8)) & 0xFF) as u8;
                    if c.is_ascii_alphanumeric() {
                        s.push(c as char);
                    } else {
                        s.push('a');
                    }
                }
                s
            }
        }
    }
}

/// Generate entries with configurable input size
fn make_entries_with_size(n: usize, seed: u64, size: InputSize) -> Vec<(StateKey, String)> {
    generate_unique_entries(
        n,
        seed,
        |rng| {
            let uid = rng.next_u64() % 1_000_000;
            (
                "m.room.member".to_string(),
                format!("@user{uid}:example.org"),
            )
        },
        |rng| {
            let index = rng.next_u64() as usize;
            size.generate_event_id(rng, index)
        },
    )
}

/// Benchmark a single operation type
fn bench_single_op<F>(iterations: u32, mut op: F) -> Duration
where
    F: FnMut(),
{
    let start = Instant::now();
    for _ in 0..iterations {
        op();
    }
    start.elapsed()
}

/// Format duration as ns/op
fn format_ns_per_op(elapsed: Duration, ops: u32) -> String {
    let ns_per_op = elapsed.as_nanos() as f64 / f64::from(ops);
    if ns_per_op >= 1_000_000.0 {
        format!("{:.2} ms/op", ns_per_op / 1_000_000.0)
    } else if ns_per_op >= 1_000.0 {
        format!("{:.2} μs/op", ns_per_op / 1_000.0)
    } else {
        format!("{:.1} ns/op", ns_per_op)
    }
}

/// Run single-operation benchmarks
fn bench_single_operations(size: InputSize) {
    println!("\n=== Single Operations (input size: {}) ===", size.name());

    // Seed generation (the dominant cost)
    let mut rng = Xorshift128::new(0x5EED_0001);
    let event_type = "m.room.member";
    let state_key = "@alice:example.org";
    let event_id = size.generate_event_id(&mut rng, 0);

    let iterations = 10_000;

    // Benchmark seed() - the expansion function
    let elapsed = bench_single_op(iterations, || {
        black_box(LtHash::seed(event_type, state_key, &event_id));
    });
    println!("  seed()            : {}", format_ns_per_op(elapsed, iterations));

    // Benchmark insert (seed + add)
    let mut lt = LtHash::ZERO;
    let elapsed = bench_single_op(iterations, || {
        lt.insert(event_type, state_key, &event_id);
        black_box(&lt);
    });
    println!("  insert()          : {}", format_ns_per_op(elapsed, iterations));

    // Benchmark remove (seed + sub)
    let seed = LtHash::seed(event_type, state_key, &event_id);
    let mut lt = LtHash::ZERO;
    lt.add_seed(&seed);
    let elapsed = bench_single_op(iterations, || {
        lt.remove(event_type, state_key, &event_id);
        black_box(&lt);
    });
    println!("  remove()          : {}", format_ns_per_op(elapsed, iterations));

    // Benchmark replace (2 seeds + add + sub)
    let event_id2 = size.generate_event_id(&mut rng, 1);
    let mut lt = LtHash::ZERO;
    lt.insert(event_type, state_key, &event_id);
    let elapsed = bench_single_op(iterations, || {
        lt.replace(event_type, state_key, &event_id, &event_id2);
        lt.replace(event_type, state_key, &event_id2, &event_id);
        black_box(&lt);
    });
    println!("  replace (x2)      : {}", format_ns_per_op(elapsed, iterations));

    // Benchmark lattice add (just the arithmetic, no expansion)
    let seed1 = LtHash::seed(event_type, state_key, &event_id);
    let seed2 = LtHash::seed(event_type, state_key, &event_id2);
    let mut lt = LtHash::ZERO;
    let elapsed = bench_single_op(iterations * 10, || {
        lt.add_seed(&seed1);
        lt.add_seed(&seed2);
        black_box(&lt);
    });
    println!("  add_lattice (x2)  : {}", format_ns_per_op(elapsed, iterations * 10));

    // Benchmark lattice sub (just the arithmetic, no expansion)
    let mut lt = seed1;
    let elapsed = bench_single_op(iterations * 10, || {
        lt.sub_seed(&seed2);
        lt.add_seed(&seed2);
        black_box(&lt);
    });
    println!("  sub_lattice (x2)  : {}", format_ns_per_op(elapsed, iterations * 10));

    // Benchmark digest (BLAKE3 collapse)
    let mut lt = LtHash::ZERO;
    for i in 0..100 {
        let id = size.generate_event_id(&mut rng, i);
        lt.insert(event_type, state_key, &id);
    }
    let elapsed = bench_single_op(iterations, || {
        black_box(lt.digest());
    });
    println!("  digest()          : {}", format_ns_per_op(elapsed, iterations));
}

/// Run multi/batch operation benchmarks
fn bench_batch_operations(size: InputSize) {
    println!("\n=== Batch Operations (input size: {}) ===", size.name());

    let batch_sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

    for &batch_size in &batch_sizes {
        if batch_size > 1024 {
            continue;
        }

        let mut rng = Xorshift128::new(0xBA7C_0000 + batch_size as u64);
        let event_type = "m.room.member";
        let state_key = "@alice:example.org";

        // Pre-generate seeds for this batch size
        let mut seeds = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let event_id = size.generate_event_id(&mut rng, i);
            seeds.push(LtHash::seed(event_type, state_key, &event_id));
        }

        // Benchmark batch insert (accumulate multiple seeds)
        let iterations = (10_000 / batch_size.max(1)) as u32;
        let mut lt = LtHash::ZERO;

        let elapsed = bench_single_op(
            iterations,
            || {
                for seed in &seeds {
                    lt.add_seed(seed);
                }
                black_box(&lt);
            },
        );
        println!(
            "  batch insert [{:>4}]: {} ({} seeds = {} total ops)",
            batch_size,
            format_ns_per_op(elapsed, iterations),
            batch_size,
            batch_size * iterations as usize
        );

        // Benchmark batch remove
        let mut lt = LtHash::ZERO;
        for seed in &seeds {
            lt.add_seed(seed);
        }

        let elapsed = bench_single_op(
            iterations,
            || {
                for seed in &seeds {
                    lt.sub_seed(seed);
                }
                black_box(&lt);
            },
        );
        println!(
            "  batch remove [{:>4}]: {} ({} seeds = {} total ops)",
            batch_size,
            format_ns_per_op(elapsed, iterations),
            batch_size,
            batch_size * iterations as usize
        );
    }
}

/// Run large batch / bulk state construction benchmarks
fn bench_bulk_construction(size: InputSize) {
    println!("\n=== Bulk State Construction (input size: {}) ===", size.name());

    let state_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384];

    for &state_size in &state_sizes {
        // Large event IDs are ~64 KiB each; cap the fixture to keep memory bounded.
        if size == InputSize::Large && state_size > MAX_LARGE_STATE {
            continue;
        }

        let entries = make_entries_with_size(state_size, 0xB01C_0000 + state_size as u64, size);
        let iterations = ((1000 / (state_size / 16).max(1)) as u32).max(1);

        // Benchmark from_state (full state hashing)
        let elapsed = bench_single_op(
            iterations,
            || {
                black_box(LtHash::from_state_map(&entries));
            },
        );
        println!(
            "  from_state [{:>5}]: {} ({} entries × {} iters = {} total)",
            state_size,
            format_ns_per_op(elapsed, iterations),
            state_size,
            iterations,
            state_size * iterations as usize
        );

        // Benchmark incremental build (insert one by one)
        let elapsed = bench_single_op(
            iterations,
            || {
                let mut lt = LtHash::ZERO;
                for ((event_type, state_key), event_id) in &entries {
                    lt.insert(event_type, state_key, event_id);
                }
                black_box(lt);
            },
        );
        println!(
            "  incremental   [{:>5}]: {} ({} entries × {} iters = {} total)",
            state_size,
            format_ns_per_op(elapsed, iterations),
            state_size,
            iterations,
            state_size * iterations as usize
        );
    }
}

/// Run incremental mutation benchmarks (the original benchmark style)
fn bench_incremental_mutations(size: InputSize) {
    println!("\n=== Incremental Mutations (input size: {}) ===", size.name());

    let state_sizes = [16, 64, 256, 1024, 4096, 16384, 65536];
    let steps = 300;

    for &n in &state_sizes {
        if size == InputSize::Large && n > MAX_LARGE_STATE {
            continue;
        }
        let base_entries = make_entries_with_size(n, 0x5EED_0000 + n as u64, size);
        let mut state: HashMap<StateKey, String> = base_entries.into_iter().collect();

        let mut lt = LtHash::ZERO;
        for ((event_type, state_key), event_id) in &state {
            lt.insert(event_type, state_key, event_id);
        }

        let mut rng = Xorshift128::new(0xBEEF);
        let existing_keys: Vec<StateKey> = state.keys().cloned().collect();

        enum Op {
            Insert(StateKey, String),
            Overwrite(StateKey, String),
            Remove(StateKey),
        }
        let mut ops = Vec::with_capacity(steps);
        for _ in 0..steps {
            let roll = rng.next_u64() % 10;
            if roll < 6 {
                let key = (
                    "m.room.member".to_string(),
                    format!("@user{}:example.org", rng.next_u64()),
                );
                ops.push(Op::Insert(
                    key,
                    format!("$event{}:example.org", rng.next_u64()),
                ));
            } else if roll < 9 {
                let key = existing_keys[(rng.next_u64() as usize) % existing_keys.len()].clone();
                ops.push(Op::Overwrite(
                    key,
                    format!("$event{}:example.org", rng.next_u64()),
                ));
            } else {
                let key = existing_keys[(rng.next_u64() as usize) % existing_keys.len()].clone();
                ops.push(Op::Remove(key));
            }
        }

        // LtHash incremental
        let lt_start = Instant::now();
        for op in &ops {
            match op {
                Op::Insert(k, v) | Op::Overwrite(k, v) => {
                    if let Some(old) = state.insert(k.clone(), v.clone()) {
                        lt.replace(&k.0, &k.1, &old, v);
                    } else {
                        lt.insert(&k.0, &k.1, v);
                    }
                }
                Op::Remove(k) => {
                    if let Some(old) = state.remove(k) {
                        lt.remove(&k.0, &k.1, &old);
                    }
                }
            }
            black_box(lt.digest());
        }
        let lt_elapsed = lt_start.elapsed();

        let op_count = ops.len() as u32;
        println!(
            "  n={:>6}: LtHash incremental = {}",
            n,
            format_ns_per_op(lt_elapsed, op_count)
        );
    }
}

/// Run lattice arithmetic benchmarks
fn bench_lattice_arithmetic() {
    println!("\n=== Lattice Arithmetic ===");

    let event_type = "m.room.member";
    let state_key = "@alice:example.org";

    // Generate test seeds
    let mut seeds = Vec::with_capacity(1000);
    for i in 0..1000 {
        let event_id = format!("$event{i}:example.org");
        seeds.push(LtHash::seed(event_type, state_key, &event_id));
    }

    let iterations = 100_000;

    // Add
    let mut lt = LtHash::ZERO;
    let elapsed = bench_single_op(iterations, || {
        for seed in &seeds {
            lt.add_seed(seed);
        }
        black_box(&lt);
    });
    println!(
        "  add_lattice (1000 seeds): {}",
        format_ns_per_op(elapsed, iterations)
    );

    // Sub
    let mut lt = seeds[0];
    let elapsed = bench_single_op(iterations, || {
        for seed in &seeds[1..] {
            lt.sub_seed(seed);
        }
        black_box(&lt);
    });
    println!(
        "  sub_lattice (999 seeds): {}",
        format_ns_per_op(elapsed, iterations)
    );

    // Add + sub alternating
    let mut lt = LtHash::ZERO;
    let elapsed = bench_single_op(iterations, || {
        for (i, seed) in seeds.iter().enumerate() {
            if i % 2 == 0 {
                lt.add_seed(seed);
            } else {
                lt.sub_seed(seed);
            }
        }
        black_box(&lt);
    });
    println!(
        "  add/sub (1000 seeds): {}",
        format_ns_per_op(elapsed, iterations)
    );
}

/// Benchmark the two BLAKE3 halves of the engine: XOF expansion and collapse.
///
/// Expansion dominates `insert`/`remove`, and collapse dominates `digest`, so
/// these two numbers explain nearly all of the per-element cost above. The
/// pre-migration SHAKE256 backend is deliberately absent: it is no longer a
/// code path, and keeping it here would only measure dead work.
fn bench_expansion_backends(size: InputSize) {
    println!("\n=== BLAKE3 Expansion and Collapse (input size: {}) ===", size.name());

    let mut rng = Xorshift128::new(0x5EED);
    let event_type = "m.room.member";
    let state_key = "@alice:example.org";
    let event_id = size.generate_event_id(&mut rng, 0);

    let iterations = 10_000;

    // The XOF half: hashing one encoded element and squeezing 2 * LANES bytes.
    let elapsed = bench_single_op(iterations, || {
        let mut hasher = blake3::Hasher::new();
        hasher.update(LtHash::DST);
        hasher.update(&(event_type.len() as u16).to_le_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(&(state_key.len() as u16).to_le_bytes());
        hasher.update(state_key.as_bytes());
        hasher.update(event_id.as_bytes());
        let mut buf = [0u8; 2048];
        hasher.finalize_xof().fill(&mut buf);
        black_box(buf);
    });
    println!("  XOF expansion     : {}", format_ns_per_op(elapsed, iterations));

    // The collapse half: one 2 KiB lattice in, 32 bytes out.
    let mut lattice = LtHash::ZERO;
    for i in 0..100 {
        let id = size.generate_event_id(&mut rng, i);
        lattice.insert(event_type, state_key, &id);
    }
    let lattice_bytes = lattice.to_bytes();
    let elapsed = bench_single_op(iterations, || {
        black_box(blake3::Hasher::new().update(&lattice_bytes).finalize());
    });
    println!("  collapse          : {}", format_ns_per_op(elapsed, iterations));
}

/// Benchmark trait for extension - allows testing custom LtHash implementations
trait LtHashExt {
    fn from_state_map(entries: &[(StateKey, String)]) -> Self;
}

impl LtHashExt for LtHash {
    fn from_state_map(entries: &[(StateKey, String)]) -> Self {
        let mut hash = Self::ZERO;
        for ((event_type, state_key), event_id) in entries {
            let s = Self::seed(event_type, state_key, event_id);
            hash.add_seed(&s);
        }
        hash
    }
}

/// Run all benchmarks
pub fn run() {
    println!("============================================================");
    println!(" COMPREHENSIVE LTHASH BENCHMARK SUITE");
    println!("============================================================");
    println!("Testing: single ops, batch ops, bulk construction, incremental");
    println!("Input sizes: small, medium, large");

    // Single operations for each input size
    for size in [InputSize::Small, InputSize::Medium, InputSize::Large] {
        bench_single_operations(size);
        bench_batch_operations(size);
        bench_bulk_construction(size);
        bench_incremental_mutations(size);
        bench_expansion_backends(size);
    }

    // Lattice arithmetic (independent of input size)
    bench_lattice_arithmetic();

    println!("\n============================================================");
    println!(" BENCHMARK SUITE COMPLETE");
    println!("============================================================");
}
