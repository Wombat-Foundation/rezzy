//! Benchmark: filter spillover vs sketch splitting for bucket overflow.
//!
//! Compares three strategies when a pinsketch bucket exceeds its decode budget:
//!
//! 1. **Sketch splitting**: retry at larger capacity or split into children,
//!    each costing a full network round trip.
//! 2. **Filter spillover**: encode overflow elements in a compact filter,
//!    exchange in one trip, receiver probes for membership.
//! 3. **Hybrid**: filter first for small overflows, sketch splitting as fallback.
//!
//! Simulates realistic network latency (20–40 ms per round trip).

use std::hint::black_box;
use std::time::{Duration, Instant};

use rezzy::{
    build_bucket_sketches, estimate_strata, triage::MAX_BUCKET_SKETCH_CAPACITY, BucketDecodeBatch,
    BucketDecodeSuccess, BucketExchange, ClientAction, ElementHash, H64Index, ReconciliationClient,
    RemoteDigest, ResidentKernel, SyndromeSketch, MAX_BUCKETED_SKETCH_CAPACITY,
    MAX_BUCKETS_PER_ROUND, MAX_SKETCH_CAPACITY,
};

use super::filters::{CountingQuotientFilter, CuckooFilter};

// ---------------------------------------------------------------------------
// Deterministic PRNG
// ---------------------------------------------------------------------------

struct Xorshift128 {
    state: [u64; 2],
}

impl Xorshift128 {
    fn new(seed: u64) -> Self {
        Self {
            state: [seed, seed ^ 0x9e37_79b9_7f4a_7c15],
        }
    }

    fn next(&mut self) -> u64 {
        let mut value = self.state[0];
        let other = self.state[1];
        value ^= value << 23;
        value ^= value >> 17;
        value ^= other ^ (other >> 26);
        self.state = [other, value];
        value
    }

    fn hash(&mut self) -> ElementHash {
        let high = self.next();
        let low = self.next();
        let h64 = self.next() | 1;
        ElementHash {
            h128: u128::from(high) << 64 | u128::from(low),
            h64,
        }
    }
}

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------

fn measure(iterations: u32, mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    start.elapsed()
}

fn report(name: &str, iterations: u32, elapsed: Duration) {
    let millis = elapsed.as_secs_f64() * 1e3 / f64::from(iterations);
    println!("{name}: {millis:.6} ms/op ({iterations} iterations)");
}

// ---------------------------------------------------------------------------
// Sorted-merge set difference (O(n) instead of O(n²))
// ---------------------------------------------------------------------------

fn sorted_difference(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut result = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => {
                result.push(a[i]);
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    result.extend_from_slice(&a[i..]);
    result
}

// ---------------------------------------------------------------------------
// Strategy results
// ---------------------------------------------------------------------------

struct StrategyResult {
    wall_ms: f64,
    cpu_ms: f64,
    rounds: usize,
    wire_bytes: usize,
    resolved: bool,
}

// ---------------------------------------------------------------------------
// Input generation
// ---------------------------------------------------------------------------

/// Best case: Δ elements spread across distinct buckets, no overflow.
fn generate_best_case(base: &[ElementHash], delta: usize) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let mut gen = Xorshift128::new(0xBE57_CA5E);
    let mut remote: Vec<ElementHash> = base.to_vec();

    let high_shift: u32 = 40;
    let low_mask: u64 = u64::MAX >> 24;
    for i in 0..delta {
        let prefix = 0x00_20_00_u64 + (i as u64);
        let suffix = (gen.next() ^ (i as u64).wrapping_mul(0x10000)) & low_mask;
        let h64 = (prefix << high_shift) | suffix | 1;
        remote.push(ElementHash {
            h128: u128::from(gen.next()) << 64 | u128::from(h64 ^ 0x5555),
            h64,
        });
    }
    (base.to_vec(), remote)
}

/// Average case: Δ elements uniformly random in hash space.
fn generate_average_case(
    base: &[ElementHash],
    delta: usize,
) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let mut gen = Xorshift128::new(0xA7E7_A6E0);
    let mut remote: Vec<ElementHash> = base.to_vec();
    for _ in 0..delta {
        remote.push(gen.hash());
    }
    (base.to_vec(), remote)
}

/// Worst case: all Δ elements concentrated in one bucket (depth 8, prefix 0).
fn generate_worst_case(base: &[ElementHash], delta: usize) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let mut gen = Xorshift128::new(0xF007_CAFE);
    let mut remote: Vec<ElementHash> = base.to_vec();

    let high_shift: u32 = 56;
    let low_mask: u64 = u64::MAX >> 8;
    for i in 0..delta {
        let suffix = (gen.next() ^ (i as u64).wrapping_mul(0x10000)) & low_mask;
        let h64 = (0_u64 << high_shift) | suffix | 1;
        remote.push(ElementHash {
            h128: u128::from(gen.next()) << 64 | u128::from(h64 ^ 0xAAAA),
            h64,
        });
    }
    (base.to_vec(), remote)
}

// ---------------------------------------------------------------------------
// End-to-end reconciliation simulation (per-strategy)
// ---------------------------------------------------------------------------

fn simulate_strategy(
    local_hashes: &[ElementHash],
    remote_hashes: &[ElementHash],
    strategy: &str,
    network_latency_ms: u64,
    decode_budget: usize,
    filter_fpr: f64,
) -> StrategyResult {
    let mut local = ResidentKernel::new();
    let mut remote = ResidentKernel::new();
    let mut local_h64: Vec<u64> = Vec::with_capacity(local_hashes.len());
    let mut remote_h64: Vec<u64> = Vec::with_capacity(remote_hashes.len());

    for hash in local_hashes {
        local.insert(*hash).expect("valid hash");
        local_h64.push(hash.h64);
    }
    for hash in remote_hashes {
        remote.insert(*hash).expect("valid hash");
        remote_h64.push(hash.h64);
    }
    local_h64.sort_unstable();
    remote_h64.sort_unstable();

    let client = ReconciliationClient::default().allow_unlimited_delta();
    let remote_digest = RemoteDigest {
        digest: remote.accumulator().digest(),
        known_event_count: remote.accumulator().known_event_count(),
        strata: *remote.strata(),
        frame_matches: true,
        has_unknown_extremity: false,
    };

    let estimated_delta = estimate_strata(local.strata(), remote.strata())
        .map_or(500, |est| est.delta.max(1));

    let initial_action = client.select_action(&local, remote_digest, 0);

    let ClientAction::BucketSketches {
        requests: mut current_requests,
        accumulated_roots,
    } = initial_action
    else {
        return StrategyResult {
            wall_ms: 0.0,
            cpu_ms: 0.0,
            rounds: 0,
            wire_bytes: 0,
            resolved: matches!(initial_action, ClientAction::Synchronized),
        };
    };

    let mut exchange = BucketExchange::new(
        accumulated_roots,
        rezzy::client::MAX_RECONCILIATION_ROUNDS,
        MAX_BUCKETS_PER_ROUND,
        MAX_BUCKETED_SKETCH_CAPACITY,
    );

    let mut total_wall = Duration::ZERO;
    let mut total_cpu = Duration::ZERO;
    let mut total_wire = 0_usize;
    let mut rounds = 0_usize;
    let mut resolved = false;

    // Pre-build H64Index once for the entire simulation.
    let local_index = H64Index::new(&local_h64);
    let remote_index = H64Index::new(&remote_h64);

    loop {
        rounds += 1;
        let round_cpu_start = Instant::now();

        let remote_sketches = build_bucket_sketches(&remote_h64, &current_requests).unwrap();
        let local_sketches = build_bucket_sketches(&local_h64, &current_requests).unwrap();

        let mut batch = BucketDecodeBatch {
            successful_buckets: Vec::with_capacity(current_requests.len()),
            failed_buckets: Vec::new(),
        };

        match strategy {
            "sketch_split" => {
                for ((mut remote_sketch, local_sketch), request) in remote_sketches
                    .into_iter()
                    .zip(local_sketches)
                    .zip(current_requests.iter())
                {
                    total_wire += request.capacity * 8 * 2;
                    remote_sketch.xor(&local_sketch).unwrap();
                    match remote_sketch.decode_elements(request.capacity) {
                        Ok(roots) => {
                            batch.successful_buckets.push(BucketDecodeSuccess {
                                depth: request.depth,
                                prefix: request.prefix,
                                roots,
                            });
                        }
                        Err(_) => {
                            batch.failed_buckets.push((request.depth, request.prefix));
                        }
                    }
                }
            }

            "filter_spillover" => {
                for ((remote_sketch, local_sketch), request) in remote_sketches
                    .into_iter()
                    .zip(local_sketches)
                    .zip(current_requests.iter())
                {
                    let mut rs = remote_sketch.clone();
                    rs.xor(&local_sketch).unwrap();
                    if let Ok(roots) = rs.decode_elements_with_budget(request.capacity, decode_budget) {
                        total_wire += request.capacity * 8 * 2;
                        batch.successful_buckets.push(BucketDecodeSuccess {
                            depth: request.depth,
                            prefix: request.prefix,
                            roots,
                        });
                    } else {
                        // Overflow: build filter of remote-only elements in bucket.
                        let remote_slice =
                            &remote_h64[remote_index.bucket_range(request).unwrap()];
                        let local_slice =
                            &local_h64[local_index.bucket_range(request).unwrap()];
                        let remote_only = sorted_difference(remote_slice, local_slice);
                        let mut filter =
                            CuckooFilter::with_fpr(remote_only.len().max(1), filter_fpr);
                        for &val in &remote_only {
                            filter.insert(&val);
                        }
                        total_wire += filter.byte_len();
                        batch.successful_buckets.push(BucketDecodeSuccess {
                            depth: request.depth,
                            prefix: request.prefix,
                            roots: remote_only,
                        });
                    }
                }
            }

            "hybrid" => {
                for ((remote_sketch, local_sketch), request) in remote_sketches
                    .into_iter()
                    .zip(local_sketches)
                    .zip(current_requests.iter())
                {
                    let mut rs = remote_sketch.clone();
                    rs.xor(&local_sketch).unwrap();
                    if let Ok(roots) = rs.decode_elements_with_budget(request.capacity, decode_budget) {
                        total_wire += request.capacity * 8 * 2;
                        batch.successful_buckets.push(BucketDecodeSuccess {
                            depth: request.depth,
                            prefix: request.prefix,
                            roots,
                        });
                    } else {
                        let remote_slice =
                            &remote_h64[remote_index.bucket_range(request).unwrap()];
                        let local_slice =
                            &local_h64[local_index.bucket_range(request).unwrap()];
                        let remote_only = sorted_difference(remote_slice, local_slice);
                        if remote_only.len() <= MAX_BUCKET_SKETCH_CAPACITY * 2 {
                            let mut filter =
                                CuckooFilter::with_fpr(remote_only.len().max(1), filter_fpr);
                            for &val in &remote_only {
                                filter.insert(&val);
                            }
                            total_wire += filter.byte_len();
                            batch.successful_buckets.push(BucketDecodeSuccess {
                                depth: request.depth,
                                prefix: request.prefix,
                                roots: remote_only,
                            });
                        } else {
                            batch.failed_buckets.push((request.depth, request.prefix));
                        }
                    }
                }
            }

            _ => unreachable!("unknown strategy: {strategy}"),
        }

        let round_cpu = round_cpu_start.elapsed();
        total_cpu += round_cpu;

        match exchange.advance(batch, &current_requests, Some(estimated_delta)) {
            ClientAction::BucketSketches {
                requests,
                accumulated_roots: _,
            } => {
                current_requests = requests;
                if network_latency_ms > 0 {
                    std::thread::sleep(Duration::from_millis(network_latency_ms));
                }
                total_wall += round_cpu + Duration::from_millis(network_latency_ms);
            }
            ClientAction::ResolveRoots { roots } => {
                resolved = true;
                total_wall += round_cpu;
                black_box(roots);
                break;
            }
            ClientAction::ExtremityDiff | ClientAction::Synchronized => {
                total_wall += round_cpu;
                break;
            }
        }
    }

    StrategyResult {
        wall_ms: total_wall.as_secs_f64() * 1e3,
        cpu_ms: total_cpu.as_secs_f64() * 1e3,
        rounds,
        wire_bytes: total_wire,
        resolved,
    }
}

// ---------------------------------------------------------------------------
// Comparison table printer
// ---------------------------------------------------------------------------

fn print_comparison(
    case_name: &str,
    delta: usize,
    latency_ms: u64,
    budget: usize,
    sketch: &StrategyResult,
    filter: &StrategyResult,
    hybrid: &StrategyResult,
) {
    let winner = if filter.wall_ms < sketch.wall_ms && filter.wall_ms < hybrid.wall_ms {
        "FILTER"
    } else if hybrid.wall_ms < sketch.wall_ms {
        "HYBRID"
    } else {
        "SKETCH"
    };

    let sk_status = if sketch.resolved { "ok" } else { "FALL" };
    let fl_status = if filter.resolved { "ok" } else { "FALL" };
    let hy_status = if hybrid.resolved { "ok" } else { "FALL" };

    println!(
        "  [{case_name:<7}] Δ={delta:>6} lat={latency_ms:>2}ms budget={budget:>8} | \
         sketch {sk_status:>4} {sk_wall:>8.1}ms/{sk_cpu:>7.1}ms r{sk_rounds:<2} {sk_wire:>7}B | \
         filter {fl_status:>4} {fl_wall:>8.1}ms/{fl_cpu:>7.1}ms r{fl_rounds:<2} {fl_wire:>7}B | \
         hybrid {hy_status:>4} {hy_wall:>8.1}ms/{hy_cpu:>7.1}ms r{hy_rounds:<2} {hy_wire:>7}B | \
         => {winner}",
        sk_wall = sketch.wall_ms,
        sk_cpu = sketch.cpu_ms,
        sk_rounds = sketch.rounds,
        sk_wire = sketch.wire_bytes,
        fl_wall = filter.wall_ms,
        fl_cpu = filter.cpu_ms,
        fl_rounds = filter.rounds,
        fl_wire = filter.wire_bytes,
        hy_wall = hybrid.wall_ms,
        hy_cpu = hybrid.cpu_ms,
        hy_rounds = hybrid.rounds,
        hy_wire = hybrid.wire_bytes,
    );
}

// ---------------------------------------------------------------------------
// Layer 1: Microbenchmarks
// ---------------------------------------------------------------------------

fn microbenchmarks() {
    println!("\n=== Layer 1: Filter microbenchmarks ===\n");

    for capacity in [1_000, 10_000, 100_000] {
        // Cuckoo insert
        let elapsed = measure(10, || {
            let mut filter = CuckooFilter::with_fpr(capacity, 0.001);
            let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
            for _ in 0..capacity {
                filter.insert(&(gen.next() | 1));
            }
            black_box(&filter);
        });
        report(&format!("cuckoo/insert/{capacity}"), 10, elapsed);

        // Cuckoo probe
        let mut filter = CuckooFilter::with_fpr(capacity, 0.001);
        let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
        let probe_values: Vec<u64> = (0..capacity.min(10_000)).map(|_| gen.next() | 1).collect();
        for val in &probe_values {
            filter.insert(val);
        }
        let elapsed = measure(100, || {
            for val in &probe_values {
                black_box(filter.contains(val));
            }
        });
        report(&format!("cuckoo/probe/{capacity}"), 100, elapsed);

        println!(
            "  cuckoo byte_len({capacity}): {} bytes ({:.1} B/elem)",
            filter.byte_len(),
            filter.byte_len() as f64 / capacity as f64,
        );

        // CQF insert
        let elapsed = measure(10, || {
            let mut filter = CountingQuotientFilter::with_remainder_bits(capacity, 10);
            let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
            for _ in 0..capacity {
                filter.insert(&(gen.next() | 1));
            }
            black_box(&filter);
        });
        report(&format!("cqf/insert/{capacity}"), 10, elapsed);

        // CQF probe
        let mut filter = CountingQuotientFilter::with_remainder_bits(capacity, 10);
        let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
        let probe_values: Vec<u64> = (0..capacity.min(10_000)).map(|_| gen.next() | 1).collect();
        for val in &probe_values {
            filter.insert(val);
        }
        let elapsed = measure(100, || {
            for val in &probe_values {
                black_box(filter.contains(val));
            }
        });
        report(&format!("cqf/probe/{capacity}"), 100, elapsed);

        println!(
            "  cqf byte_len({capacity}): {} bytes ({:.1} B/elem)",
            filter.byte_len(),
            filter.byte_len() as f64 / capacity as f64,
        );

        println!();
    }

    // Pinsketch decode at various budgets
    println!("--- pinsketch decode at various budgets (cap=32) ---");
    for budget in [1_000_000_usize, 2_000_000, 4_000_000, 8_000_000, 16_000_000] {
        let elapsed = measure(10, || {
            let mut sketch = SyndromeSketch::new(MAX_SKETCH_CAPACITY).unwrap();
            let mut gen = Xorshift128::new(0xDEAD_BEEF + budget as u64);
            for _ in 0..MAX_SKETCH_CAPACITY {
                sketch.toggle(gen.next() | 1).unwrap();
            }
            let _ = black_box(sketch.decode_elements_with_budget(MAX_SKETCH_CAPACITY, budget));
        });
        report(&format!("pinsketch/decode/budget={budget}"), 10, elapsed);
    }
}

// ---------------------------------------------------------------------------
// Layer 2: End-to-end simulation
// ---------------------------------------------------------------------------

fn e2e_simulation() {
    println!("\n=== Layer 2: End-to-end reconciliation simulation ===\n");

    // Generate base set (1M elements — enough to exercise real behavior
    // without making binary searches dominate).
    let base_count: usize = 1_000_000;
    let mut gen = Xorshift128::new(0x243f_6a88_85a3_08d3);
    let base: Vec<ElementHash> = (0..base_count).map(|_| gen.hash()).collect();

    for &network_latency_ms in &[0_u64, 20, 30, 40] {
        for &decode_budget in &[1_000_000_usize, 4_000_000, 8_000_000, 16_000_000] {
            println!("\n--- network={network_latency_ms}ms, budget={decode_budget} ---");

            for &delta in &[1_000_usize, 5_000, 10_000, 25_000, 50_000, 100_000] {
                let generators: &[(
                    &str,
                    fn(&[ElementHash], usize) -> (Vec<ElementHash>, Vec<ElementHash>),
                )] = &[
                    ("best", generate_best_case),
                    ("average", generate_average_case),
                    ("worst", generate_worst_case),
                ];

                for &(case_name, gen_fn) in generators {
                    let (local, remote) = gen_fn(&base, delta);

                    let sketch = simulate_strategy(
                        &local,
                        &remote,
                        "sketch_split",
                        network_latency_ms,
                        decode_budget,
                        0.001,
                    );
                    let filter = simulate_strategy(
                        &local,
                        &remote,
                        "filter_spillover",
                        network_latency_ms,
                        decode_budget,
                        0.001,
                    );
                    let hybrid = simulate_strategy(
                        &local,
                        &remote,
                        "hybrid",
                        network_latency_ms,
                        decode_budget,
                        0.001,
                    );

                    print_comparison(
                        case_name,
                        delta,
                        network_latency_ms,
                        decode_budget,
                        &sketch,
                        &filter,
                        &hybrid,
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-over summary
// ---------------------------------------------------------------------------

fn cross_over_summary() {
    println!("\n\n=== Cross-over summary ===\n");
    println!("Δ where filter_spillover first beats sketch_split (average case):\n");

    let base_count: usize = 1_000_000;
    let mut gen = Xorshift128::new(0x243f_6a88_85a3_08d3);
    let base: Vec<ElementHash> = (0..base_count).map(|_| gen.hash()).collect();

    println!(
        "\n  {:>8} {:>10} {:>14} {:>10} {:>10}",
        "latency", "budget", "cross-over Δ", "sketch ms", "filter ms"
    );
    println!(
        "  {:->8} {:->10} {:->14} {:->10} {:->10}",
        "", "", "", "", ""
    );

    for &latency in &[0_u64, 20, 30, 40] {
        for &budget in &[1_000_000_usize, 4_000_000, 8_000_000, 16_000_000] {
            let mut cross_over_delta = None;
            let mut co_sketch_ms = 0.0;
            let mut co_filter_ms = 0.0;
            for &delta in &[1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
                let (local, remote) = generate_average_case(&base, delta);
                let sketch =
                    simulate_strategy(&local, &remote, "sketch_split", latency, budget, 0.001);
                let filter =
                    simulate_strategy(&local, &remote, "filter_spillover", latency, budget, 0.001);
                if filter.wall_ms < sketch.wall_ms && cross_over_delta.is_none() {
                    cross_over_delta = Some(delta);
                    co_sketch_ms = sketch.wall_ms;
                    co_filter_ms = filter.wall_ms;
                }
            }
            if let Some(d) = cross_over_delta { println!(
                "  {latency:>6}ms {budget:>10} {d:>14} {co_sketch_ms:>10.1} {co_filter_ms:>10.1}"
            ) } else {
                let never = "never";
                println!(
                    "  {latency:>6}ms {budget:>10} {never:>14}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run() {
    microbenchmarks();
    e2e_simulation();
    cross_over_summary();
}
