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
//!
//! Run:
//!   cargo bench --bench rezzy -- filter_spillover

use std::hint::black_box;
use std::time::{Duration, Instant};

use rezzy::{
    build_bucket_sketches, estimate_strata, triage::MAX_BUCKET_SKETCH_CAPACITY, BucketDecodeBatch,
    BucketDecodeSuccess, BucketExchange, BucketRequest, ClientAction, ElementHash, H64Index,
    ReconciliationClient, RemoteDigest, ResidentKernel, SyndromeSketch,
    MAX_BUCKETED_SKETCH_CAPACITY, MAX_BUCKETS_PER_ROUND, MAX_SKETCH_CAPACITY,
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
// Hash pool (pre-generated for scale benchmarks)
// ---------------------------------------------------------------------------

struct HashPool {
    base: Vec<ElementHash>,
    local_extra: Vec<ElementHash>,
    remote_extra: Vec<ElementHash>,
}

impl HashPool {
    fn new(max_base: usize, max_local_extra: usize, max_remote_extra: usize) -> Self {
        let mut generator = Xorshift128::new(0x243f_6a88_85a3_08d3);
        let base = (0..max_base).map(|_| generator.hash()).collect();
        let local_extra = (0..max_local_extra).map(|_| generator.hash()).collect();
        let remote_extra = (0..max_remote_extra).map(|_| generator.hash()).collect();
        Self {
            base,
            local_extra,
            remote_extra,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-bucket element extraction (for filter spillover)
// ---------------------------------------------------------------------------

fn extract_bucket_elements(sorted_h64: &[u64], request: &BucketRequest) -> Vec<u64> {
    let index = H64Index::new(sorted_h64);
    let range = index.bucket_range(request).expect("valid request");
    sorted_h64[range].to_vec()
}

fn bucket_would_overflow(
    sorted_h64: &[u64],
    request: &BucketRequest,
    decode_budget: usize,
) -> bool {
    let index = H64Index::new(sorted_h64);
    let range = index.bucket_range(request).expect("valid request");
    let slice = &sorted_h64[range];
    if slice.len() <= request.capacity {
        return false;
    }
    let mut sketch = SyndromeSketch::new(request.capacity).unwrap();
    for &h64 in slice {
        sketch.toggle(h64).unwrap();
    }
    sketch
        .decode_elements_with_budget(request.capacity, decode_budget)
        .is_err()
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
// Input generation strategies
// ---------------------------------------------------------------------------

/// Best case: Δ elements uniformly spread, each bucket gets ≤ capacity.
fn generate_best_case(
    pool: &HashPool,
    base_count: usize,
    delta: usize,
) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let mut gen = Xorshift128::new(0xBE57_CA5E);
    let local: Vec<ElementHash> = pool.base[..base_count].to_vec();
    let mut remote = local.clone();

    // Plant Δ elements each in their own distinct bucket (depth 24, unique prefix)
    let high_shift: u32 = 40;
    let low_mask: u64 = u64::MAX >> 24;
    for i in 0..delta {
        let prefix = 0x00_20_00_u64 + (i as u64);
        let suffix = (gen.next() ^ (i as u64).wrapping_mul(0x10000)) & low_mask;
        let h64 = (prefix << high_shift) | suffix | 1;
        let hash = ElementHash {
            h128: u128::from(gen.next()) << 64 | u128::from(h64 ^ 0x5555),
            h64,
        };
        remote.push(hash);
    }
    (local, remote)
}

/// Average case: Δ elements uniformly random in hash space.
fn generate_average_case(
    pool: &HashPool,
    base_count: usize,
    delta: usize,
) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let local: Vec<ElementHash> = pool.base[..base_count].to_vec();
    let mut remote = local.clone();
    let remote_extra = &pool.remote_extra[..delta];
    remote.extend_from_slice(remote_extra);
    (local, remote)
}

/// Worst case: all Δ elements in one bucket (depth 0, prefix 0).
fn generate_worst_case(
    pool: &HashPool,
    base_count: usize,
    delta: usize,
) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let mut gen = Xorshift128::new(0xF007_CAFE);
    let local: Vec<ElementHash> = pool.base[..base_count].to_vec();
    let mut remote = local.clone();

    let high_shift: u32 = 56;
    let low_mask: u64 = u64::MAX >> 8;
    for i in 0..delta {
        let suffix = (gen.next() ^ (i as u64).wrapping_mul(0x10000)) & low_mask;
        let h64 = (0_u64 << high_shift) | suffix | 1;
        let hash = ElementHash {
            h128: u128::from(gen.next()) << 64 | u128::from(h64 ^ 0xAAAA),
            h64,
        };
        remote.push(hash);
    }
    (local, remote)
}

// ---------------------------------------------------------------------------
// End-to-end simulation
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

    let estimated_delta =
        estimate_strata(local.strata(), remote.strata()).map_or(500, |est| est.delta.max(1));

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
                // Standard behavior: decode, track failures for splitting.
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
                // When a bucket overflows, build a filter of its remote-only
                // elements and count it as wire cost.
                for ((remote_sketch, local_sketch), request) in remote_sketches
                    .into_iter()
                    .zip(local_sketches)
                    .zip(current_requests.iter())
                {
                    let remote_elements = extract_bucket_elements(&remote_h64, request);
                    let local_elements = extract_bucket_elements(&local_h64, request);
                    let _diff_count = remote_elements.len().saturating_sub(local_elements.len());

                    // Try sketch decode first.
                    let mut rs = remote_sketch.clone();
                    rs.xor(&local_sketch).unwrap();
                    if let Ok(roots) =
                        rs.decode_elements_with_budget(request.capacity, decode_budget)
                    {
                        total_wire += request.capacity * 8 * 2;
                        batch.successful_buckets.push(BucketDecodeSuccess {
                            depth: request.depth,
                            prefix: request.prefix,
                            roots,
                        });
                    } else {
                        // Overflow: build filter of remote-only elements.
                        let remote_only: Vec<u64> = remote_elements
                            .iter()
                            .filter(|h| !local_elements.contains(h))
                            .copied()
                            .collect();
                        let mut filter =
                            CuckooFilter::with_fpr(remote_only.len().max(1), filter_fpr);
                        for &val in &remote_only {
                            filter.insert(&val);
                        }
                        total_wire += filter.byte_len();
                        // Treat filter-encoded buckets as resolved (receiver
                        // can probe). No further splitting needed.
                        batch.successful_buckets.push(BucketDecodeSuccess {
                            depth: request.depth,
                            prefix: request.prefix,
                            roots: remote_only,
                        });
                    }
                }
            }

            "hybrid" => {
                // Filter for small overflows, split for large ones.
                for ((remote_sketch, local_sketch), request) in remote_sketches
                    .into_iter()
                    .zip(local_sketches)
                    .zip(current_requests.iter())
                {
                    let remote_elements = extract_bucket_elements(&remote_h64, request);
                    let local_elements = extract_bucket_elements(&local_h64, request);

                    let mut rs = remote_sketch.clone();
                    rs.xor(&local_sketch).unwrap();
                    if let Ok(roots) =
                        rs.decode_elements_with_budget(request.capacity, decode_budget)
                    {
                        total_wire += request.capacity * 8 * 2;
                        batch.successful_buckets.push(BucketDecodeSuccess {
                            depth: request.depth,
                            prefix: request.prefix,
                            roots,
                        });
                    } else {
                        let remote_only: Vec<u64> = remote_elements
                            .iter()
                            .filter(|h| !local_elements.contains(h))
                            .copied()
                            .collect();
                        // Use filter if the overflow fits comfortably;
                        // otherwise split (push to failed_buckets).
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
                // Simulate network round trip.
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

fn print_comparison_table(
    _label: &str,
    delta: usize,
    latency_ms: u64,
    budget: usize,
    results: &[(&str, StrategyResult)],
) {
    println!("  Δ={delta:>7} | latency={latency_ms:>2}ms | budget={budget:>8}");
    for (name, r) in results {
        let resolved_str = if r.resolved { "ok" } else { "FALLBACK" };
        println!(
            "    {name:<16} | wall {:>8.1}ms | cpu {:>7.1}ms | rounds {:>2} | wire {:>7.1}KB | {resolved_str}",
            r.wall_ms,
            r.cpu_ms,
            r.rounds,
            r.wire_bytes as f64 / 1024.0,
        );
    }
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

        // Cuckoo serialize
        let elapsed = measure(10, || {
            black_box(filter.encode());
        });
        report(&format!("cuckoo/serialize/{capacity}"), 10, elapsed);

        println!(
            "  cuckoo byte_len({capacity}): {} bytes ({:.1} bytes/elem)",
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
            "  cqf byte_len({capacity}): {} bytes ({:.1} bytes/elem)",
            filter.byte_len(),
            filter.byte_len() as f64 / capacity as f64,
        );
    }

    // Pinsketch decode at various budgets for comparison
    println!("\n--- pinsketch decode at various budgets ---");
    for budget in [1_000_000, 2_000_000, 4_000_000, 8_000_000, 16_000_000] {
        let elapsed = measure(10, || {
            let mut sketch = SyndromeSketch::new(MAX_SKETCH_CAPACITY).unwrap();
            let mut gen = Xorshift128::new(0xDEAD_BEEF + budget as u64);
            for _ in 0..MAX_SKETCH_CAPACITY {
                sketch.toggle(gen.next() | 1).unwrap();
            }
            black_box(sketch.decode_elements_with_budget(MAX_SKETCH_CAPACITY, budget));
        });
        report(
            &format!("pinsketch/decode/cap=32/budget={budget}"),
            10,
            elapsed,
        );
    }
}

// ---------------------------------------------------------------------------
// Layer 2: End-to-end simulation
// ---------------------------------------------------------------------------

fn e2e_simulation() {
    println!("\n=== Layer 2: End-to-end reconciliation simulation ===\n");

    let pool = HashPool::new(10_000_000, 500_000, 500_000);
    let base_count = 10_000_000;

    for &network_latency_ms in &[0, 20, 30, 40] {
        for &decode_budget in &[1_000_000, 4_000_000, 8_000_000, 16_000_000] {
            println!(
                "\n--- network_latency={network_latency_ms}ms, decode_budget={decode_budget} ---"
            );

            for &delta in &[1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
                for &(case_name, gen_fn) in &[
                    (
                        "best",
                        generate_best_case
                            as fn(&HashPool, usize, usize) -> (Vec<ElementHash>, Vec<ElementHash>),
                    ),
                    (
                        "average",
                        generate_average_case
                            as fn(&HashPool, usize, usize) -> (Vec<ElementHash>, Vec<ElementHash>),
                    ),
                    (
                        "worst",
                        generate_worst_case
                            as fn(&HashPool, usize, usize) -> (Vec<ElementHash>, Vec<ElementHash>),
                    ),
                ] {
                    let (local, remote) = gen_fn(&pool, base_count, delta);

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

                    let results = [
                        ("sketch_split", sketch),
                        ("filter_spillover", filter),
                        ("hybrid", hybrid),
                    ];

                    println!("  [{case_name}]");
                    print_comparison_table(
                        case_name,
                        delta,
                        network_latency_ms,
                        decode_budget,
                        &results,
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
    println!("\n=== Cross-over summary ===\n");
    println!(
        "For each (latency, budget), the Δ where filter_spillover first beats sketch_split:\n"
    );

    let pool = HashPool::new(10_000_000, 500_000, 500_000);
    let base_count = 10_000_000;

    for &network_latency_ms in &[0, 20, 30, 40] {
        for &decode_budget in &[1_000_000, 4_000_000, 8_000_000, 16_000_000] {
            let mut cross_over = None;
            for &delta in &[1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
                let (local, remote) = generate_average_case(&pool, base_count, delta);
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
                if filter.wall_ms < sketch.wall_ms && cross_over.is_none() {
                    cross_over = Some(delta);
                }
            }
            let co_str = cross_over.map_or_else(
                || "never (sketch always wins)".to_string(),
                |d| format!("Δ={d}"),
            );
            println!("  latency={network_latency_ms:>2}ms, budget={decode_budget:>8}: cross-over at {co_str}");
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
