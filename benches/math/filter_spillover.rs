//! Benchmark: filter spillover vs sketch splitting for bucket overflow.
//!
//! Compares five strategies when a pinsketch bucket exceeds its decode budget:
//!
//! 1. **sketch_split** — recursive bucket splitting via `BucketExchange`.
//! 2. **cuckoo** — 1-RTT filter protocol (CuckooFilter) for overflow buckets.
//! 3. **cqf** — 1-RTT filter protocol (CountingQuotientFilter) for overflow buckets.
//! 4. **bloom** — 1-RTT filter protocol (BloomFilter) for overflow buckets.
//! 5. **hybrid** — filter for small overflows, sketch splitting as fallback.
//!
//! The filter protocol is modeled correctly (no oracle):
//!   RTT 1 (sender→receiver): sender sends filter built from its bucket elements.
//!   RTT 1 (receiver→sender): receiver probes its own elements against the filter,
//!     sends back candidate list + receiver-only list.
//!   Sender computes symmetric difference from candidates + receiver-only.
//!   Total: 1 RTT = 2 one-way messages.
//!
//! All strategies use `decode_elements_with_budget` for fairness.
//! Latency is charged consistently: each `network_latency_ms` = one full RTT.

use std::collections::BTreeSet;
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
// Sorted helpers
// ---------------------------------------------------------------------------

fn sorted_contains(slice: &[u64], value: u64) -> bool {
    slice.binary_search(&value).is_ok()
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

/// Symmetric mix: half of Δ are additions, half are removals from base.
fn generate_symmetric_mix(
    base: &[ElementHash],
    delta: usize,
) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let mut gen = Xorshift128::new(0xBAD_F00D_1);
    let add_count = delta / 2;
    let remove_count = delta - add_count;

    // Remote = base minus removals plus additions.
    let base_set: BTreeSet<u64> = base.iter().map(|h| h.h64).collect();
    let mut removals = Vec::new();
    let mut candidates: Vec<u64> = base_set.iter().copied().collect();
    // Pick removal_count elements from base to remove.
    candidates.sort_unstable();
    let step = (candidates.len() / remove_count.max(1)).max(1);
    for i in (0..candidates.len()).step_by(step) {
        if removals.len() >= remove_count {
            break;
        }
        removals.push(candidates[i]);
    }
    removals.truncate(remove_count);

    let removal_set: BTreeSet<u64> = removals.into_iter().collect();

    let mut remote: Vec<ElementHash> =
        Vec::with_capacity(base.len() - removal_set.len() + add_count);
    for hash in base {
        if !removal_set.contains(&hash.h64) {
            remote.push(*hash);
        }
    }

    let high_shift: u32 = 40;
    let low_mask: u64 = u64::MAX >> 24;
    for i in 0..add_count {
        let prefix = 0x00_30_00_u64 + (i as u64);
        let suffix = (gen.next() ^ (i as u64).wrapping_mul(0x10000)) & low_mask;
        let h64 = (prefix << high_shift) | suffix | 1;
        remote.push(ElementHash {
            h128: u128::from(gen.next()) << 64 | u128::from(h64 ^ 0x7777),
            h64,
        });
    }

    (base.to_vec(), remote)
}

// ---------------------------------------------------------------------------
// Filter protocol: correct 1-RTT simulation (no oracle)
//
// Protocol (correct direction):
//   1. Sender builds filter from its OWN bucket elements (sender_set).
//   2. Filter is transmitted to receiver (wire cost = filter.byte_len()).
//   3. Receiver probes its OWN elements (receiver_set) against the filter:
//      - filter.contains(val) == true  → candidate (true positive or false positive)
//      - filter.contains(val) == false → receiver-only (true negative)
//   4. Receiver sends back candidate list + receiver-only list.
//   5. Sender computes symmetric difference:
//      - For each candidate, if it's in sender_set → shared (true positive)
//      - For each candidate, if it's NOT in sender_set → false positive (actually receiver-only)
//      - receiver-only list from step 3 → receiver-only
//      - Elements in sender_set not in candidates → sender-only
// ---------------------------------------------------------------------------

/// Build a filter from the given elements, return (filter, wire_bytes).
fn build_filter(elements: &[u64], filter_fpr: f64, filter_type: &str) -> (FilterEnum, usize) {
    match filter_type {
        "cuckoo" => {
            let mut f = CuckooFilter::with_fpr(elements.len().max(1), filter_fpr);
            for &val in elements {
                f.insert(&val);
            }
            let wire = f.byte_len();
            (FilterEnum::Cuckoo(f), wire)
        }
        "cqf" => {
            let remainder_bits = ((1.0 / filter_fpr).ln() / std::f64::consts::LN_2).ceil() as u32;
            let mut f =
                CountingQuotientFilter::with_remainder_bits(elements.len().max(1), remainder_bits);
            for &val in elements {
                f.insert(&val);
            }
            let wire = f.byte_len();
            (FilterEnum::CQF(f), wire)
        }
        "bloom" => {
            let mut f = BloomFilter::with_fpr(elements.len().max(1), filter_fpr);
            for &val in elements {
                f.insert(&val);
            }
            let wire = f.byte_len();
            (FilterEnum::Bloom(f), wire)
        }
        _ => unreachable!("unknown filter type: {filter_type}"),
    }
}

enum FilterEnum {
    Cuckoo(CuckooFilter),
    CQF(CountingQuotientFilter),
    Bloom(BloomFilter),
}

impl FilterEnum {
    fn contains(&self, value: &u64) -> bool {
        match self {
            FilterEnum::Cuckoo(f) => f.contains(value),
            FilterEnum::CQF(f) => f.contains(value),
            FilterEnum::Bloom(f) => f.contains(value),
        }
    }
}

/// Simulate the 1-RTT filter protocol for overflow buckets.
///
/// Returns (decoded_roots, failed_buckets, wire_bytes, cpu_time).
/// Caller charges 1 RTT of latency (the filter request+response is one round trip).
fn simulate_filter_rounds(
    local_h64: &[u64],
    remote_h64: &[u64],
    local_index: &H64Index<'_>,
    remote_index: &H64Index<'_>,
    overflow_requests: &[rezzy::BucketRequest],
    decode_budget: usize,
    filter_fpr: f64,
    filter_type: &str,
) -> (Vec<BucketDecodeSuccess>, Vec<(u8, u64)>, usize, Duration) {
    let mut decoded = Vec::new();
    let mut failed = Vec::new();
    let mut total_wire = 0_usize;
    let mut total_cpu = Duration::ZERO;

    if overflow_requests.is_empty() {
        return (decoded, failed, total_wire, total_cpu);
    }

    // --- RTT: sender builds filter, sends to receiver; receiver probes, sends back ---
    let rtt_start = Instant::now();

    for request in overflow_requests {
        let sender_slice = match local_index.bucket_range(request) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let receiver_slice = match remote_index.bucket_range(request) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let sender_elements = &local_h64[sender_slice];
        let receiver_elements = &remote_h64[receiver_slice];

        // 1. Sender builds filter from its OWN elements.
        let (filter, filter_wire) = build_filter(sender_elements, filter_fpr, filter_type);
        total_wire += filter_wire;

        // 2. Receiver probes its OWN elements against the filter.
        let mut candidates: Vec<u64> = Vec::new();
        let mut receiver_only: Vec<u64> = Vec::new();

        for &val in receiver_elements {
            if filter.contains(&val) {
                candidates.push(val);
            } else {
                receiver_only.push(val);
            }
        }

        // 3. Wire cost: candidates + receiver-only sent back.
        total_wire += (candidates.len() + receiver_only.len()) * 8;

        // 4. Sender computes symmetric difference.
        let mut symmetric_diff: Vec<u64> = Vec::new();

        // Sender-only: elements in sender not found in candidates (i.e., not in receiver).
        for &val in sender_elements {
            if !sorted_contains(receiver_elements, val) {
                symmetric_diff.push(val);
            }
        }
        // Receiver-only: elements that failed the filter.
        // (True false-positive candidates are elements in receiver that passed the filter
        // but are NOT in sender — they are already receiver-only in effect.)
        for &val in &candidates {
            if !sorted_contains(sender_elements, val) {
                // False positive: receiver element that passed filter but isn't in sender.
                symmetric_diff.push(val);
            }
        }
        // Also add true receiver-only (failed filter).
        symmetric_diff.extend_from_slice(&receiver_only);

        // 5. Decode the symmetric difference using pinsketch with budget.
        if symmetric_diff.is_empty() {
            decoded.push(BucketDecodeSuccess {
                depth: request.depth,
                prefix: request.prefix,
                roots: Vec::new(),
            });
        } else {
            let mut sketch = SyndromeSketch::new(MAX_SKETCH_CAPACITY).unwrap();
            for &element in &symmetric_diff {
                let _ = sketch.toggle(element);
            }
            match sketch.decode_elements_with_budget(
                symmetric_diff.len().min(MAX_SKETCH_CAPACITY),
                decode_budget,
            ) {
                Ok(roots) => {
                    decoded.push(BucketDecodeSuccess {
                        depth: request.depth,
                        prefix: request.prefix,
                        roots,
                    });
                }
                Err(_) => {
                    // Budget exhausted: return as failed, not silent drop.
                    failed.push((request.depth, request.prefix));
                }
            }
        }
    }

    total_cpu += rtt_start.elapsed();

    (decoded, failed, total_wire, total_cpu)
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
                            overflow_requests.push(request.clone());
                        }
                    }
                }

                // 2. For overflow buckets, run 1-RTT filter protocol.
                if !overflow_requests.is_empty() {
                    let filter_type = match strategy {
                        "cuckoo" => "cuckoo",
                        "cqf" => "cqf",
                        "bloom" => "bloom",
                        _ => unreachable!(),
                    };
                    let (filter_decoded, filter_failed, filter_wire, filter_cpu) =
                        simulate_filter_rounds(
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
                    // 1 RTT for the filter protocol (2 one-way messages).
                    total_wall += Duration::from_millis(network_latency_ms);
                    batch.successful_buckets.extend(filter_decoded);
                    batch.failed_buckets.extend(filter_failed);
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
                            overflow_requests.push(request.clone());
                        }
                    }
                }

                // 2. Small overflows: filter protocol. Large: sketch splitting.
                let small_overflows: Vec<_> = overflow_requests
                    .iter()
                    .filter(|r| r.capacity <= MAX_BUCKET_SKETCH_CAPACITY * 2)
                    .cloned()
                    .collect();
                let large_overflows: Vec<_> = overflow_requests
                    .iter()
                    .filter(|r| r.capacity > MAX_BUCKET_SKETCH_CAPACITY * 2)
                    .cloned()
                    .collect();

                if !small_overflows.is_empty() {
                    let (filter_decoded, filter_failed, filter_wire, filter_cpu) =
                        simulate_filter_rounds(
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
                    total_wall += Duration::from_millis(network_latency_ms);
                    batch.successful_buckets.extend(filter_decoded);
                    batch.failed_buckets.extend(filter_failed);
                }

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
                // Charge 1 RTT for this sketch exchange round.
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
        "  [{case_name:<13}] Δ={delta:>6} lat={latency_ms:>2}ms budget={budget:>8} | \
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
// Layer 1: Microbenchmarks (probe ALL N entries)
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

    let generators: &[(
        &str,
        fn(&[ElementHash], usize) -> (Vec<ElementHash>, Vec<ElementHash>),
    )] = &[
        ("best", generate_best_case),
        ("average", generate_average_case),
        ("worst", generate_worst_case),
        ("sym_mix", generate_symmetric_mix),
    ];

    for &network_latency_ms in &[0_u64, 20, 30, 40] {
        for &decode_budget in &[1_000_000_usize, 4_000_000, 8_000_000, 16_000_000] {
            println!("\n--- network={network_latency_ms}ms, budget={decode_budget} ---");

            for &delta in &[1_000_usize, 5_000, 10_000, 25_000, 50_000, 100_000] {
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
