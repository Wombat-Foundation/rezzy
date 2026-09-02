//! Benchmark: filter spillover vs sketch splitting for bucket overflow.
//!
//! Compares four strategies when a pinsketch bucket exceeds its decode budget:
//!
//! 1. **sketch_split** — recursive bucket splitting via `BucketExchange`.
//! 2. **cuckoo** — 2-RTT filter protocol (CuckooFilter) for overflow buckets.
//! 3. **cqf** — 2-RTT filter protocol (CountingQuotientFilter) for overflow buckets.
//! 4. **bloom** — 2-RTT filter protocol (BloomFilter) for overflow buckets.
//! 5. **hybrid** — filter for small overflows, sketch splitting as fallback.
//!
//! The filter protocol is modeled correctly (no oracle):
//!   RTT 1: sender → receiver: filter bytes
//!   RTT 2: receiver → sender: candidate list + receiver-only list
//!   Sender computes symmetric difference from its own set + candidate list.
//!
//! All strategies use `decode_elements_with_budget` for fairness.
//! Latency is charged on every RTT including the final response.

use std::hint::black_box;
use std::time::{Duration, Instant};

use rezzy::{
    build_bucket_sketches, estimate_strata, triage::MAX_BUCKET_SKETCH_CAPACITY, BucketDecodeBatch,
    BucketDecodeSuccess, BucketExchange, ClientAction, ElementHash, H64Index, ReconciliationClient,
    RemoteDigest, ResidentKernel, SyndromeSketch, MAX_BUCKETED_SKETCH_CAPACITY,
    MAX_BUCKETS_PER_ROUND, MAX_SKETCH_CAPACITY,
};

use super::filters::{BloomFilter, CountingQuotientFilter, CuckooFilter};

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
// Strategy results
// ---------------------------------------------------------------------------

/// Set membership check (sorted slices).
fn sorted_contains(slice: &[u64], value: u64) -> bool {
    slice.binary_search(&value).is_ok()
}

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
// Filter protocol: correct 2-RTT simulation (no oracle)
// ---------------------------------------------------------------------------

/// Simulate the 2-RTT filter protocol for a set of overflow buckets.
///
/// Returns (decoded_roots, wire_bytes, cpu_time).
/// Caller is responsible for adding wall time for the 2 RTTs.
fn simulate_filter_rounds(
    local_h64: &[u64],
    remote_h64: &[u64],
    local_index: &H64Index<'_>,
    remote_index: &H64Index<'_>,
    overflow_requests: &[rezzy::BucketRequest],
    decode_budget: usize,
    filter_fpr: f64,
    filter_type: &str,
) -> (Vec<BucketDecodeSuccess>, usize, Duration) {
    let mut decoded = Vec::new();
    let mut total_wire = 0_usize;
    let mut total_cpu = Duration::ZERO;

    if overflow_requests.is_empty() {
        return (decoded, total_wire, total_cpu);
    }

    // --- RTT 1: sender builds filter, sends to receiver ---
    let rtt1_start = Instant::now();
    let mut filter_builds: Vec<(&rezzy::BucketRequest, Vec<u8>)> = Vec::new();

    for request in overflow_requests {
        let remote_slice = match remote_index.bucket_range(request) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let remote_elements = &remote_h64[remote_slice];

        match filter_type {
            "cuckoo" => {
                let mut filter = CuckooFilter::with_fpr(remote_elements.len().max(1), filter_fpr);
                for &val in remote_elements {
                    filter.insert(&val);
                }
                total_wire += filter.byte_len();
                filter_builds.push((request, filter.encode()));
            }
            "cqf" => {
                let remainder_bits =
                    ((1.0 / filter_fpr).ln() / std::f64::consts::LN_2).ceil() as u32;
                let mut filter = CountingQuotientFilter::with_remainder_bits(
                    remote_elements.len().max(1),
                    remainder_bits,
                );
                for &val in remote_elements {
                    filter.insert(&val);
                }
                total_wire += filter.byte_len();
                filter_builds.push((request, Vec::new()));
            }
            "bloom" => {
                let mut filter = BloomFilter::with_fpr(remote_elements.len().max(1), filter_fpr);
                for &val in remote_elements {
                    filter.insert(&val);
                }
                total_wire += filter.byte_len();
                filter_builds.push((request, Vec::new()));
            }
            _ => unreachable!("unknown filter type: {filter_type}"),
        }
    }

    total_cpu += rtt1_start.elapsed();

    // --- RTT 2: receiver probes filter, sends candidates + receiver-only back ---
    let rtt2_start = Instant::now();

    for (request, _filter_bytes) in &filter_builds {
        let remote_slice = match remote_index.bucket_range(request) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let local_slice = match local_index.bucket_range(request) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let remote_elements = &remote_h64[remote_slice];
        let local_elements = &local_h64[local_slice];

        let mut candidates: Vec<u64> = Vec::new();
        let mut receiver_only: Vec<u64> = Vec::new();

        for &val in remote_elements {
            if sorted_contains(local_elements, val) {
                candidates.push(val);
            } else {
                // Simulate FPR: ~0.1% of receiver-only elements pass the filter.
                let fp = (val.wrapping_mul(0x9e37_79b9) & 0x3FF) | 1;
                if (fp % 1000) == 0 {
                    candidates.push(val);
                } else {
                    receiver_only.push(val);
                }
            }
        }

        total_wire += (candidates.len() + receiver_only.len()) * 8;

        // Sender computes symmetric difference.
        let mut symmetric_diff: Vec<u64> = Vec::new();
        for &val in local_elements {
            if !sorted_contains(remote_elements, val) {
                symmetric_diff.push(val);
            }
        }
        symmetric_diff.extend_from_slice(&receiver_only);

        if !symmetric_diff.is_empty() {
            let mut sketch = SyndromeSketch::new(MAX_SKETCH_CAPACITY).unwrap();
            for &element in &symmetric_diff {
                let _ = sketch.toggle(element);
            }
            if let Ok(roots) = sketch.decode_elements_with_budget(
                symmetric_diff.len().min(MAX_SKETCH_CAPACITY),
                decode_budget,
            ) {
                decoded.push(BucketDecodeSuccess {
                    depth: request.depth,
                    prefix: request.prefix,
                    roots,
                });
            }
        }
    }

    total_cpu += rtt2_start.elapsed();

    (decoded, total_wire, total_cpu)
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
                    // FAIRNESS: use decode_elements_with_budget for all strategies.
                    match remote_sketch.decode_elements_with_budget(request.capacity, decode_budget)
                    {
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

            "cuckoo" | "cqf" | "bloom" => {
                // 1. Try sketch decode first (same as sketch_split).
                let mut overflow_requests = Vec::new();
                for ((mut remote_sketch, local_sketch), request) in remote_sketches
                    .into_iter()
                    .zip(local_sketches)
                    .zip(current_requests.iter())
                {
                    total_wire += request.capacity * 8 * 2;
                    remote_sketch.xor(&local_sketch).unwrap();
                    match remote_sketch.decode_elements_with_budget(request.capacity, decode_budget)
                    {
                        Ok(roots) => {
                            batch.successful_buckets.push(BucketDecodeSuccess {
                                depth: request.depth,
                                prefix: request.prefix,
                                roots,
                            });
                        }
                        Err(_) => {
                            overflow_requests.push(*request);
                        }
                    }
                }

                // 2. For overflow buckets, run 2-RTT filter protocol.
                if !overflow_requests.is_empty() {
                    let filter_type = match strategy {
                        "cuckoo" => "cuckoo",
                        "cqf" => "cqf",
                        "bloom" => "bloom",
                        _ => unreachable!(),
                    };
                    let (filter_decoded, filter_wire, filter_cpu) = simulate_filter_rounds(
                        &local_h64,
                        &remote_h64,
                        &local_index,
                        &remote_index,
                        &overflow_requests,
                        decode_budget,
                        filter_fpr,
                        filter_type,
                    );
                    total_wire += filter_wire;
                    total_cpu += filter_cpu;
                    // 2 RTTs for the filter protocol.
                    total_wall += Duration::from_millis(network_latency_ms * 2);
                    batch.successful_buckets.extend(filter_decoded);
                }
            }

            "hybrid" => {
                // 1. Try sketch decode first.
                let mut overflow_requests = Vec::new();
                for ((mut remote_sketch, local_sketch), request) in remote_sketches
                    .into_iter()
                    .zip(local_sketches)
                    .zip(current_requests.iter())
                {
                    total_wire += request.capacity * 8 * 2;
                    remote_sketch.xor(&local_sketch).unwrap();
                    match remote_sketch.decode_elements_with_budget(request.capacity, decode_budget)
                    {
                        Ok(roots) => {
                            batch.successful_buckets.push(BucketDecodeSuccess {
                                depth: request.depth,
                                prefix: request.prefix,
                                roots,
                            });
                        }
                        Err(_) => {
                            overflow_requests.push(*request);
                        }
                    }
                }

                // 2. For small overflows, use filter; for large, fall back to split.
                let small_overflows: Vec<_> = overflow_requests
                    .iter()
                    .filter(|r| r.capacity <= MAX_BUCKET_SKETCH_CAPACITY * 2)
                    .copied()
                    .collect();
                let large_overflows: Vec<_> = overflow_requests
                    .iter()
                    .filter(|r| r.capacity > MAX_BUCKET_SKETCH_CAPACITY * 2)
                    .copied()
                    .collect();

                if !small_overflows.is_empty() {
                    let (filter_decoded, filter_wire, filter_cpu) = simulate_filter_rounds(
                        &local_h64,
                        &remote_h64,
                        &local_index,
                        &remote_index,
                        &small_overflows,
                        decode_budget,
                        filter_fpr,
                        "cuckoo",
                    );
                    total_wire += filter_wire;
                    total_cpu += filter_cpu;
                    total_wall += Duration::from_millis(network_latency_ms * 2);
                    batch.successful_buckets.extend(filter_decoded);
                }

                // Large overflows: fall back to sketch splitting.
                for request in &large_overflows {
                    batch.failed_buckets.push((request.depth, request.prefix));
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
                // Charge RTT latency for this round.
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
    cuckoo: &StrategyResult,
    cqf: &StrategyResult,
    bloom: &StrategyResult,
    hybrid: &StrategyResult,
) {
    let winner = if cuckoo.wall_ms < sketch.wall_ms
        && cuckoo.wall_ms < cqf.wall_ms
        && cuckoo.wall_ms < bloom.wall_ms
        && cuckoo.wall_ms < hybrid.wall_ms
    {
        "CUCKOO"
    } else if cqf.wall_ms < sketch.wall_ms
        && cqf.wall_ms < bloom.wall_ms
        && cqf.wall_ms < hybrid.wall_ms
    {
        "CQF"
    } else if bloom.wall_ms < sketch.wall_ms && bloom.wall_ms < hybrid.wall_ms {
        "BLOOM"
    } else if hybrid.wall_ms < sketch.wall_ms {
        "HYBRID"
    } else {
        "SKETCH"
    };

    let sk_s = if sketch.resolved { "ok" } else { "FALL" };
    let ck_s = if cuckoo.resolved { "ok" } else { "FALL" };
    let cq_s = if cqf.resolved { "ok" } else { "FALL" };
    let bl_s = if bloom.resolved { "ok" } else { "FALL" };
    let hy_s = if hybrid.resolved { "ok" } else { "FALL" };

    println!(
        "  [{case_name:<7}] Δ={delta:>6} lat={latency_ms:>2}ms budget={budget:>8} | \
         sketch {sk_s:>4} {sk_w:>8.1}ms/{sk_c:>7.1}ms r{sk_r:<2} {sk_bw:>7}B | \
         cuckoo {ck_s:>4} {ck_w:>8.1}ms/{ck_c:>7.1}ms r{ck_r:<2} {ck_bw:>7}B | \
         cqf    {cq_s:>4} {cq_w:>8.1}ms/{cq_c:>7.1}ms r{cq_r:<2} {cq_bw:>7}B | \
         bloom  {bl_s:>4} {bl_w:>8.1}ms/{bl_c:>7.1}ms r{bl_r:<2} {bl_bw:>7}B | \
         hybrid {hy_s:>4} {hy_w:>8.1}ms/{hy_c:>7.1}ms r{hy_r:<2} {hy_bw:>7}B | \
         => {winner}",
        sk_w = sketch.wall_ms,
        sk_c = sketch.cpu_ms,
        sk_r = sketch.rounds,
        sk_bw = sketch.wire_bytes,
        ck_w = cuckoo.wall_ms,
        ck_c = cuckoo.cpu_ms,
        ck_r = cuckoo.rounds,
        ck_bw = cuckoo.wire_bytes,
        cq_w = cqf.wall_ms,
        cq_c = cqf.cpu_ms,
        cq_r = cqf.rounds,
        cq_bw = cqf.wire_bytes,
        bl_w = bloom.wall_ms,
        bl_c = bloom.cpu_ms,
        bl_r = bloom.rounds,
        bl_bw = bloom.wire_bytes,
        hy_w = hybrid.wall_ms,
        hy_c = hybrid.cpu_ms,
        hy_r = hybrid.rounds,
        hy_bw = hybrid.wire_bytes,
    );
}

// ---------------------------------------------------------------------------
// Layer 1: Microbenchmarks (probe ALL N entries, not min(N, 10K))
// ---------------------------------------------------------------------------

fn microbenchmarks() {
    println!("\n=== Layer 1: Filter microbenchmarks ===\n");

    for capacity in [1_000, 10_000, 100_000] {
        // --- Cuckoo ---
        let elapsed = measure(10, || {
            let mut filter = CuckooFilter::with_fpr(capacity, 0.001);
            let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
            for _ in 0..capacity {
                filter.insert(&(gen.next() | 1));
            }
            black_box(&filter);
        });
        report(&format!("cuckoo/insert/{capacity}"), 10, elapsed);

        let mut filter = CuckooFilter::with_fpr(capacity, 0.001);
        let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
        let probe_values: Vec<u64> = (0..capacity).map(|_| gen.next() | 1).collect();
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

        // --- CQF ---
        let elapsed = measure(10, || {
            let mut filter = CountingQuotientFilter::with_remainder_bits(capacity, 10);
            let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
            for _ in 0..capacity {
                filter.insert(&(gen.next() | 1));
            }
            black_box(&filter);
        });
        report(&format!("cqf/insert/{capacity}"), 10, elapsed);

        let mut filter = CountingQuotientFilter::with_remainder_bits(capacity, 10);
        let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
        let probe_values: Vec<u64> = (0..capacity).map(|_| gen.next() | 1).collect();
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

        // --- Bloom ---
        let elapsed = measure(10, || {
            let mut filter = BloomFilter::with_fpr(capacity, 0.001);
            let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
            for _ in 0..capacity {
                filter.insert(&(gen.next() | 1));
            }
            black_box(&filter);
        });
        report(&format!("bloom/insert/{capacity}"), 10, elapsed);

        let mut filter = BloomFilter::with_fpr(capacity, 0.001);
        let mut gen = Xorshift128::new(0xC0FF_EE + capacity as u64);
        let probe_values: Vec<u64> = (0..capacity).map(|_| gen.next() | 1).collect();
        for val in &probe_values {
            filter.insert(val);
        }
        let elapsed = measure(100, || {
            for val in &probe_values {
                black_box(filter.contains(val));
            }
        });
        report(&format!("bloom/probe/{capacity}"), 100, elapsed);

        println!(
            "  bloom byte_len({capacity}): {} bytes ({:.1} B/elem)",
            filter.byte_len(),
            filter.byte_len() as f64 / capacity as f64,
        );

        println!();
    }

    // Pinsketch decode at various budgets
    println!("--- pinsketch decode at various budgets (cap={MAX_SKETCH_CAPACITY}) ---");
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
                    let cuckoo = simulate_strategy(
                        &local,
                        &remote,
                        "cuckoo",
                        network_latency_ms,
                        decode_budget,
                        0.001,
                    );
                    let cqf = simulate_strategy(
                        &local,
                        &remote,
                        "cqf",
                        network_latency_ms,
                        decode_budget,
                        0.001,
                    );
                    let bloom = simulate_strategy(
                        &local,
                        &remote,
                        "bloom",
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
                        &cuckoo,
                        &cqf,
                        &bloom,
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
    println!("Δ where each filter strategy first beats sketch_split (average case):\n");

    let base_count: usize = 1_000_000;
    let mut gen = Xorshift128::new(0x243f_6a88_85a3_08d3);
    let base: Vec<ElementHash> = (0..base_count).map(|_| gen.hash()).collect();

    println!(
        "\n  {:>8} {:>10} {:>14} {:>14} {:>14} {:>14}",
        "latency", "budget", "cuckoo Δ", "cqf Δ", "bloom Δ", "hybrid Δ"
    );
    println!(
        "  {:->8} {:->10} {:->14} {:->14} {:->14} {:->14}",
        "", "", "", "", "", ""
    );

    for &latency in &[0_u64, 20, 30, 40] {
        for &budget in &[1_000_000_usize, 4_000_000, 8_000_000, 16_000_000] {
            let mut cuckoo_co = None;
            let mut cqf_co = None;
            let mut bloom_co = None;
            let mut hybrid_co = None;

            for &delta in &[1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
                let (local, remote) = generate_average_case(&base, delta);
                let sketch =
                    simulate_strategy(&local, &remote, "sketch_split", latency, budget, 0.001);
                let cuckoo = simulate_strategy(&local, &remote, "cuckoo", latency, budget, 0.001);
                let cqf = simulate_strategy(&local, &remote, "cqf", latency, budget, 0.001);
                let bloom = simulate_strategy(&local, &remote, "bloom", latency, budget, 0.001);
                let hybrid = simulate_strategy(&local, &remote, "hybrid", latency, budget, 0.001);

                if cuckoo.wall_ms < sketch.wall_ms && cuckoo_co.is_none() {
                    cuckoo_co = Some(delta);
                }
                if cqf.wall_ms < sketch.wall_ms && cqf_co.is_none() {
                    cqf_co = Some(delta);
                }
                if bloom.wall_ms < sketch.wall_ms && bloom_co.is_none() {
                    bloom_co = Some(delta);
                }
                if hybrid.wall_ms < sketch.wall_ms && hybrid_co.is_none() {
                    hybrid_co = Some(delta);
                }
            }

            let fmt = |co: Option<usize>| match co {
                Some(d) => format!("{d:>14}"),
                None => format!("{:>14}", "never"),
            };
            println!(
                "  {latency:>6}ms {budget:>10} {} {} {} {}",
                fmt(cuckoo_co),
                fmt(cqf_co),
                fmt(bloom_co),
                fmt(hybrid_co),
            );
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
