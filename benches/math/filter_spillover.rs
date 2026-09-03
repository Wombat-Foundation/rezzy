#![allow(
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::type_complexity,
    clippy::unusual_byte_groupings,
    clippy::manual_let_else
)]

//! Benchmark: filter spillover vs sketch splitting for bucket overflow.
//!
//! Compares five strategies when a pinsketch bucket exceeds its decode budget:
//!
//! 1. **sketch_split** — recursive bucket splitting via `BucketExchange`.
//! 2. **cuckoo** — filter protocol (CuckooFilter) for overflow buckets.
//! 3. **remainder_probe** — naive linear-probe remainder table for overflow
//!    buckets. This is explicitly not a quotient filter.
//! 4. **cqf** — counting quotient filter for overflow buckets.
//! 5. **bloom** — filter protocol (BloomFilter) for overflow buckets.
//! 6. **hybrid** — filter for small overflows, sketch splitting as fallback.
//!
//! The filter protocol is modeled correctly (no oracle):
//!   RTT 1: sender→receiver: sender sends filter built from its bucket elements.
//!   RTT 1: receiver→sender: receiver probes its own elements against the filter,
//!     sends back candidate list + receiver-only list.
//!   Sender computes symmetric difference from candidates + receiver-only.
//!   Total: 1 additional RTT per overflow bucket group (beyond the sketch exchange).
//!
//! Wire cost note: the filter protocol does NOT reduce response wire cost.
//! Candidates + receiver_only partition every receiver element, so the full
//! receiver set is always sent back as u64 values regardless of filter type
//! or FPR. The filter's benefit is avoiding recursive bucket-splitting rounds,
//! not reducing per-round wire.
//!
//! All strategies use `decode_elements_with_budget` for fairness.
//! Latency is charged consistently: each `network_latency_ms` = one full RTT.
//! Overflow buckets cost 2 RTTs total (sketch exchange + filter exchange).

use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

use rezzy::{
    build_bucket_sketches, estimate_strata, triage::MAX_BUCKET_SKETCH_CAPACITY, BucketDecodeBatch,
    BucketDecodeSuccess, BucketExchange, ClientAction, ElementHash, H64Index, ReconciliationClient,
    RemoteDigest, ResidentKernel, SyndromeSketch, MAX_BUCKETED_SKETCH_CAPACITY,
    MAX_BUCKETS_PER_ROUND, MAX_SKETCH_CAPACITY,
};

use super::filters::{
    quotient_remainder_bits_for_fpr, remainder_probe_bits_for_fpr, BloomFilter,
    CountingQuotientFilter, CuckooFilter, RemainderProbeFilter,
};

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
    let millis = millis_per_operation(elapsed, iterations);
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

#[derive(Clone)]
struct StrategyResult {
    wall_ms: f64,
    cpu_ms: f64,
    rounds: usize,
    wire_bytes: usize,
    resolved: bool,
}

struct MicrobenchmarkRow {
    capacity: usize,
    cuckoo_insert: Duration,
    cuckoo_probe: Duration,
    cuckoo_bytes: usize,
    cqf_insert: Duration,
    cqf_probe: Duration,
    cqf_bytes: usize,
    bloom_insert: Duration,
    bloom_probe: Duration,
    bloom_bytes: usize,
}

struct ReconciliationSummaryRow {
    case_name: &'static str,
    delta: usize,
    sketch: StrategyResult,
    cuckoo: StrategyResult,
    cqf: StrategyResult,
    bloom: StrategyResult,
}

/// Shared, immutable state for one local/remote population pair.
///
/// Preparing this once prevents each strategy from independently rebuilding
/// the resident kernels and resorting one million short identifiers.
struct PreparedInput {
    local: ResidentKernel,
    local_h64: Vec<u64>,
    remote_h64: Vec<u64>,
    remote_digest: RemoteDigest,
    estimated_delta: u64,
}

fn prepare_input(local_hashes: &[ElementHash], remote_hashes: &[ElementHash]) -> PreparedInput {
    let mut local = ResidentKernel::new();
    let mut remote = ResidentKernel::new();
    let mut local_h64 = Vec::with_capacity(local_hashes.len());
    let mut remote_h64 = Vec::with_capacity(remote_hashes.len());

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

    let remote_digest = RemoteDigest {
        digest: remote.accumulator().digest(),
        known_event_count: remote.accumulator().known_event_count(),
        strata: *remote.strata(),
        frame_matches: true,
        has_unknown_extremity: false,
    };
    let estimated_delta = estimate_strata(local.strata(), remote.strata())
        .map_or(500, |estimate| estimate.delta.max(1));

    PreparedInput {
        local,
        local_h64,
        remote_h64,
        remote_digest,
        estimated_delta,
    }
}

fn millis_per_operation(elapsed: Duration, iterations: u32) -> f64 {
    elapsed.as_secs_f64() * 1e3 / f64::from(iterations)
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
    let mut gen = Xorshift128::new(0xBAD_F00D1);
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
        "remainder_probe" => {
            let remainder_bits = remainder_probe_bits_for_fpr(filter_fpr);
            let mut f =
                RemainderProbeFilter::with_remainder_bits(elements.len().max(1), remainder_bits);
            for &val in elements {
                f.insert(&val);
            }
            let wire = f.byte_len();
            (FilterEnum::RemainderProbe(f), wire)
        }
        "cqf" => {
            let remainder_bits = quotient_remainder_bits_for_fpr(filter_fpr);
            let mut f =
                CountingQuotientFilter::with_remainder_bits(elements.len().max(1), remainder_bits);
            for &value in elements {
                assert!(f.insert(&value), "CQF insertion failed");
            }
            let wire = f.byte_len();
            (FilterEnum::Cqf(f), wire)
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
    RemainderProbe(RemainderProbeFilter),
    Cqf(CountingQuotientFilter),
    Bloom(BloomFilter),
}

impl FilterEnum {
    fn contains(&self, value: &u64) -> bool {
        match self {
            FilterEnum::Cuckoo(f) => f.contains(value),
            FilterEnum::RemainderProbe(f) => f.contains(value),
            FilterEnum::Cqf(f) => f.contains(value),
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
    input: &PreparedInput,
    strategy: &str,
    network_latency_ms: u64,
    decode_budget: usize,
    filter_fpr: f64,
) -> StrategyResult {
    let client = ReconciliationClient::default().allow_unlimited_delta();
    let initial_action = client.select_action(&input.local, input.remote_digest, 0);

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

    let local_index = H64Index::new(&input.local_h64);
    let remote_index = H64Index::new(&input.remote_h64);

    loop {
        rounds += 1;
        let round_cpu_start = Instant::now();

        let remote_sketches = build_bucket_sketches(&input.remote_h64, &current_requests).unwrap();
        let local_sketches = build_bucket_sketches(&input.local_h64, &current_requests).unwrap();

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

            "cuckoo" | "remainder_probe" | "cqf" | "bloom" => {
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

                // 2. For overflow buckets, run 1-RTT filter protocol.
                if !overflow_requests.is_empty() {
                    let filter_type = match strategy {
                        "cuckoo" => "cuckoo",
                        "remainder_probe" => "remainder_probe",
                        "cqf" => "cqf",
                        "bloom" => "bloom",
                        _ => unreachable!(),
                    };
                    let (filter_decoded, filter_failed, filter_wire, filter_cpu) =
                        simulate_filter_rounds(
                            &input.local_h64,
                            &input.remote_h64,
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
                            overflow_requests.push(*request);
                        }
                    }
                }

                // 2. Small overflows: filter protocol. Large: sketch splitting.
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
                    let (filter_decoded, filter_failed, filter_wire, filter_cpu) =
                        simulate_filter_rounds(
                            &input.local_h64,
                            &input.remote_h64,
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

        match exchange.advance(batch, &current_requests, Some(input.estimated_delta)) {
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
                // Charge 1 RTT for the sketch exchange that discovered resolution.
                if network_latency_ms > 0 {
                    std::thread::sleep(Duration::from_millis(network_latency_ms));
                }
                total_wall += round_cpu + Duration::from_millis(network_latency_ms);
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

fn fastest_resolved<'a>(strategies: &[(&'a str, &'a StrategyResult)]) -> &'a str {
    strategies
        .iter()
        .filter(|(_, result)| result.resolved)
        .min_by(|(_, left), (_, right)| left.wall_ms.total_cmp(&right.wall_ms))
        .map_or("none", |(name, _)| name)
}

fn print_comparison(
    case_name: &str,
    delta: usize,
    latency_ms: u64,
    budget: usize,
    sketch: &StrategyResult,
    cuckoo: &StrategyResult,
    remainder_probe: &StrategyResult,
    cqf: &StrategyResult,
    bloom: &StrategyResult,
    hybrid: &StrategyResult,
) {
    let winner = fastest_resolved(&[
        ("SKETCH", sketch),
        ("CUCKOO", cuckoo),
        ("REMAINDER", remainder_probe),
        ("CQF", cqf),
        ("BLOOM", bloom),
        ("HYBRID", hybrid),
    ]);

    let sk_s = if sketch.resolved { "ok" } else { "FALL" };
    let ck_s = if cuckoo.resolved { "ok" } else { "FALL" };
    let rp_s = if remainder_probe.resolved {
        "ok"
    } else {
        "FALL"
    };
    let cq_s = if cqf.resolved { "ok" } else { "FALL" };
    let bl_s = if bloom.resolved { "ok" } else { "FALL" };
    let hy_s = if hybrid.resolved { "ok" } else { "FALL" };

    println!(
        "  [{case_name:<13}] Δ={delta:>6} lat={latency_ms:>2}ms budget={budget:>8} | \
         sketch {sk_s:>4} {sk_w:>8.1}ms/{sk_c:>7.1}ms r{sk_r:<2} {sk_bw:>7}B | \
         cuckoo {ck_s:>4} {ck_w:>8.1}ms/{ck_c:>7.1}ms r{ck_r:<2} {ck_bw:>7}B | \
         rem-pr {rp_s:>4} {rp_w:>8.1}ms/{rp_c:>7.1}ms r{rp_r:<2} {rp_bw:>7}B | \
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
        rp_w = remainder_probe.wall_ms,
        rp_c = remainder_probe.cpu_ms,
        rp_r = remainder_probe.rounds,
        rp_bw = remainder_probe.wire_bytes,
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

fn print_reconciliation_summary(rows: &[ReconciliationSummaryRow], base_count: usize) {
    println!("\n=== Reconciliation summary ({base_count} elements, 0ms, budget=8M) ===\n");
    println!(
        "  {:<9} {:>7} {:>19} {:>19} {:>19} {:>19} {:>9}",
        "case", "delta", "sketch split", "cuckoo", "cqf", "bloom", "winner"
    );
    println!(
        "  {:->9} {:->7} {:->19} {:->19} {:->19} {:->19} {:->9}",
        "", "", "", "", "", "", ""
    );
    for row in rows {
        let format_result = |result: &StrategyResult| {
            let status = if result.resolved { "ok" } else { "FALL" };
            format!("{:.1}ms r{} {status}", result.wall_ms, result.rounds)
        };
        let winner = fastest_resolved(&[
            ("sketch", &row.sketch),
            ("cuckoo", &row.cuckoo),
            ("cqf", &row.cqf),
            ("bloom", &row.bloom),
        ]);
        println!(
            "  {:<9} {:>7} {:>19} {:>19} {:>19} {:>19} {:>9}",
            row.case_name,
            row.delta,
            format_result(&row.sketch),
            format_result(&row.cuckoo),
            format_result(&row.cqf),
            format_result(&row.bloom),
            winner,
        );
    }
    println!("  Times are modeled wall time; `FALL` is not eligible to win.\n");

    println!("  Cumulative wire bytes (including work before a fallback):");
    println!(
        "  {:<9} {:>7} {:>14} {:>14} {:>14} {:>14}",
        "case", "delta", "sketch split", "cuckoo", "cqf", "bloom"
    );
    println!(
        "  {:->9} {:->7} {:->14} {:->14} {:->14} {:->14}",
        "", "", "", "", "", ""
    );
    for row in rows {
        let format_wire = |bytes: usize| {
            if bytes < 1_024 {
                format!("{bytes} B")
            } else {
                format!("{:.1} KiB", bytes as f64 / 1_024.0)
            }
        };
        println!(
            "  {:<9} {:>7} {:>14} {:>14} {:>14} {:>14}",
            row.case_name,
            row.delta,
            format_wire(row.sketch.wire_bytes),
            format_wire(row.cuckoo.wire_bytes),
            format_wire(row.cqf.wire_bytes),
            format_wire(row.bloom.wire_bytes),
        );
    }
    println!();

    println!("  Crossover against sketch split (average case; tested deltas only):");
    println!(
        "  {:<10} {:>26} {:>26}",
        "strategy", "first faster wall time", "first higher wire"
    );
    println!("  {:->10} {:->26} {:->26}", "", "", "");
    type StrategySelector = for<'a> fn(&'a ReconciliationSummaryRow) -> &'a StrategyResult;
    let strategies: [(&str, StrategySelector); 3] = [
        ("cuckoo", |row: &ReconciliationSummaryRow| &row.cuckoo),
        ("cqf", |row: &ReconciliationSummaryRow| &row.cqf),
        ("bloom", |row: &ReconciliationSummaryRow| &row.bloom),
    ];
    for (name, select) in strategies {
        let first_faster = rows.iter().find(|row| {
            row.case_name == "average"
                && row.sketch.resolved
                && select(row).resolved
                && select(row).wall_ms < row.sketch.wall_ms
        });
        let first_higher_wire = rows.iter().find(|row| {
            row.case_name == "average" && select(row).wire_bytes > row.sketch.wire_bytes
        });
        let faster = first_faster.map_or_else(
            || "not observed".to_owned(),
            |row| {
                format!(
                    "Δ={} ({:.2}x)",
                    row.delta,
                    row.sketch.wall_ms / select(row).wall_ms
                )
            },
        );
        let higher_wire = first_higher_wire.map_or_else(
            || "not observed".to_owned(),
            |row| {
                format!(
                    "Δ={} ({:.1}x)",
                    row.delta,
                    select(row).wire_bytes as f64 / row.sketch.wire_bytes as f64
                )
            },
        );
        println!("  {name:<10} {faster:>26} {higher_wire:>26}");
    }
    println!();
}

// ---------------------------------------------------------------------------
// Layer 1: Microbenchmarks (probe ALL N entries)
// ---------------------------------------------------------------------------

/// Bench binaries use a custom `harness = false`, so ordinary `#[test]` items
/// in this tree do not run here. Keep a small deterministic CQF integrity
/// check outside the timed measurements.
fn assert_cqf_integrity() {
    let mut filter = CountingQuotientFilter::with_remainder_bits(10_000, 12);
    let inserted: Vec<u64> = (0..10_000_u64)
        .map(|value| value.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .collect();
    for &value in &inserted {
        assert!(filter.insert(&value), "CQF insert failed for {value}");
        assert!(filter.contains(&value), "CQF lost {value} immediately");
    }
    for &value in &inserted {
        assert!(
            filter.contains(&value),
            "CQF missing inserted value {value}"
        );
    }

    let entries_before_duplicate = filter.len();
    assert!(entries_before_duplicate <= inserted.len());
    assert!(filter.insert(&inserted[123]));
    assert!(filter.insert(&inserted[123]));
    assert_eq!(filter.len(), entries_before_duplicate);
    assert!(filter.count(&inserted[123]) >= 3);

    let false_positives = (10_000_u64..110_000)
        .filter(|value| filter.contains(&value.wrapping_mul(0xd6e8_feb8_6659_fd93)))
        .count();
    assert!(
        false_positives <= 100,
        "CQF FPR too high: {false_positives}/100000"
    );
}

fn print_microbenchmark_summary(rows: &[MicrobenchmarkRow]) {
    println!("\n=== Microbenchmark summary (0.1% target FPR) ===\n");
    println!(
        "  {:<16} {:>12} {:>12} {:>12}",
        "operation", "cuckoo", "cqf", "bloom"
    );
    println!("  {:->16} {:->12} {:->12} {:->12}", "", "", "", "");
    for row in rows {
        let size = format!("{}K", row.capacity / 1_000);
        println!(
            "  {:<16} {:>9.3}ms {:>9.3}ms {:>9.3}ms",
            format!("insert {size}"),
            millis_per_operation(row.cuckoo_insert, 10),
            millis_per_operation(row.cqf_insert, 10),
            millis_per_operation(row.bloom_insert, 10),
        );
        println!(
            "  {:<16} {:>9.3}ms {:>9.3}ms {:>9.3}ms",
            format!("probe {size}"),
            millis_per_operation(row.cuckoo_probe, 100),
            millis_per_operation(row.cqf_probe, 100),
            millis_per_operation(row.bloom_probe, 100),
        );
    }
    let last = rows.last().expect("microbenchmark table has rows");
    println!(
        "  {:<16} {:>9.1} B {:>9.1} B {:>9.1} B",
        "wire @ 100K",
        last.cuckoo_bytes as f64 / last.capacity as f64,
        last.cqf_bytes as f64 / last.capacity as f64,
        last.bloom_bytes as f64 / last.capacity as f64,
    );
    println!("  Note: remainder_probe is intentionally omitted; it is not a CQF.\n");
}

fn microbenchmarks() {
    println!("\n=== Layer 1: Filter microbenchmarks ===\n");
    assert_cqf_integrity();
    let mut summary_rows = Vec::new();

    for capacity in [1_000, 10_000, 100_000] {
        // --- Cuckoo ---
        let cuckoo_insert = measure(10, || {
            let mut filter = CuckooFilter::with_fpr(capacity, 0.001);
            let mut gen = Xorshift128::new(0x00C0_FFEE + capacity as u64);
            for _ in 0..capacity {
                filter.insert(&(gen.next() | 1));
            }
            black_box(&filter);
        });
        report(&format!("cuckoo/insert/{capacity}"), 10, cuckoo_insert);

        let mut filter = CuckooFilter::with_fpr(capacity, 0.001);
        let mut gen = Xorshift128::new(0x00C0_FFEE + capacity as u64);
        let probe_values: Vec<u64> = (0..capacity).map(|_| gen.next() | 1).collect();
        for val in &probe_values {
            filter.insert(val);
        }
        let cuckoo_probe = measure(100, || {
            for val in &probe_values {
                black_box(filter.contains(val));
            }
        });
        report(&format!("cuckoo/probe/{capacity}"), 100, cuckoo_probe);

        let cuckoo_bytes = filter.byte_len();

        println!(
            "  cuckoo byte_len({capacity}): {} bytes ({:.1} B/elem)",
            cuckoo_bytes,
            cuckoo_bytes as f64 / capacity as f64,
        );

        // --- Naive linear-probe remainder table (not a quotient filter) ---
        let elapsed = measure(10, || {
            let mut filter = RemainderProbeFilter::with_remainder_bits(capacity, 10);
            let mut gen = Xorshift128::new(0x00C0_FFEE + capacity as u64);
            for _ in 0..capacity {
                filter.insert(&(gen.next() | 1));
            }
            black_box(&filter);
        });
        report(&format!("remainder_probe/insert/{capacity}"), 10, elapsed);

        let mut filter = RemainderProbeFilter::with_remainder_bits(capacity, 10);
        let mut gen = Xorshift128::new(0x00C0_FFEE + capacity as u64);
        let probe_values: Vec<u64> = (0..capacity).map(|_| gen.next() | 1).collect();
        for val in &probe_values {
            filter.insert(val);
        }
        let elapsed = measure(100, || {
            for val in &probe_values {
                black_box(filter.contains(val));
            }
        });
        report(&format!("remainder_probe/probe/{capacity}"), 100, elapsed);

        println!(
            "  remainder-probe byte_len({capacity}): {} bytes ({:.1} B/elem)",
            filter.byte_len(),
            filter.byte_len() as f64 / capacity as f64,
        );

        // --- Counting quotient filter ---
        let cqf_insert = measure(10, || {
            let mut filter = CountingQuotientFilter::with_remainder_bits(capacity, 10);
            let mut gen = Xorshift128::new(0x00C0_FFEE + capacity as u64);
            for _ in 0..capacity {
                assert!(filter.insert(&(gen.next() | 1)));
            }
            black_box(&filter);
        });
        report(&format!("cqf/insert/{capacity}"), 10, cqf_insert);

        let mut filter = CountingQuotientFilter::with_remainder_bits(capacity, 10);
        let mut gen = Xorshift128::new(0x00C0_FFEE + capacity as u64);
        let probe_values: Vec<u64> = (0..capacity).map(|_| gen.next() | 1).collect();
        for value in &probe_values {
            assert!(filter.insert(value));
        }
        black_box(filter.len());
        black_box(filter.count(&probe_values[0]));
        for value in &probe_values {
            assert!(filter.contains(value), "CQF missing inserted probe value");
        }
        let cqf_probe = measure(100, || {
            for value in &probe_values {
                black_box(filter.contains(value));
            }
        });
        report(&format!("cqf/probe/{capacity}"), 100, cqf_probe);
        let cqf_bytes = filter.byte_len();
        println!(
            "  cqf byte_len({capacity}): {} bytes ({:.1} B/elem)",
            cqf_bytes,
            cqf_bytes as f64 / capacity as f64,
        );

        // --- Bloom ---
        let bloom_insert = measure(10, || {
            let mut filter = BloomFilter::with_fpr(capacity, 0.001);
            let mut gen = Xorshift128::new(0x00C0_FFEE + capacity as u64);
            for _ in 0..capacity {
                filter.insert(&(gen.next() | 1));
            }
            black_box(&filter);
        });
        report(&format!("bloom/insert/{capacity}"), 10, bloom_insert);

        let mut filter = BloomFilter::with_fpr(capacity, 0.001);
        let mut gen = Xorshift128::new(0x00C0_FFEE + capacity as u64);
        let probe_values: Vec<u64> = (0..capacity).map(|_| gen.next() | 1).collect();
        for val in &probe_values {
            filter.insert(val);
        }
        let bloom_probe = measure(100, || {
            for val in &probe_values {
                black_box(filter.contains(val));
            }
        });
        report(&format!("bloom/probe/{capacity}"), 100, bloom_probe);
        let bloom_bytes = filter.byte_len();

        println!(
            "  bloom byte_len({capacity}): {} bytes ({:.1} B/elem)",
            bloom_bytes,
            bloom_bytes as f64 / capacity as f64,
        );

        summary_rows.push(MicrobenchmarkRow {
            capacity,
            cuckoo_insert,
            cuckoo_probe,
            cuckoo_bytes,
            cqf_insert,
            cqf_probe,
            cqf_bytes,
            bloom_insert,
            bloom_probe,
            bloom_bytes,
        });

        println!();
    }

    print_microbenchmark_summary(&summary_rows);

    print_pinsketch_decode_matrix();
}

fn pinsketch_decode_case(capacity: usize, elements: usize, budget: usize) -> (f64, bool) {
    let iterations = if capacity <= 64 { 10 } else { 3 };
    let mut decoded_ok = false;
    let elapsed = measure(iterations, || {
        let mut sketch = if capacity <= MAX_SKETCH_CAPACITY {
            SyndromeSketch::new(capacity).expect("standard capacity is valid")
        } else {
            SyndromeSketch::new_overflow(capacity).expect("overflow capacity is valid")
        };

        for element in 1..=elements {
            // Nonzero, distinct u64s: exactly the residual cardinality labelled
            // by this case, without PRNG collisions changing the result.
            sketch
                .toggle((u64::try_from(element).expect("usize fits u64") << 1) | 1)
                .expect("nonzero element");
        }

        let result = if capacity <= MAX_SKETCH_CAPACITY {
            sketch.decode_elements_with_budget(capacity, budget)
        } else {
            sketch.decode_elements_overflow_budget(capacity, budget)
        };
        decoded_ok = result.is_ok();
        let _ = black_box(result);
    });
    (millis_per_operation(elapsed, iterations), decoded_ok)
}

fn print_pinsketch_decode_matrix() {
    const DECODE_BUDGET: usize = 8_000_000;
    let capacities = [32_usize, 64, 128, 256];

    println!("--- PinSketch decode cost (budget=8M) ---");
    println!("  Each cell is one complete residual decode: time plus outcome.");
    println!(
        "  {:>8} {:>14} {:>14} {:>14} {:>14} {:>14}",
        "capacity", "Δ=1", "Δ=cap/4", "Δ=cap/2", "Δ=cap", "Δ=cap+1"
    );
    println!(
        "  {:->8} {:->14} {:->14} {:->14} {:->14} {:->14}",
        "", "", "", "", "", ""
    );

    for capacity in capacities {
        let residuals = [1, capacity / 4, capacity / 2, capacity, capacity + 1];
        let cells = residuals.map(|elements| {
            let (millis, ok) = pinsketch_decode_case(capacity, elements, DECODE_BUDGET);
            format!("{millis:.3}ms {}", if ok { "ok" } else { "FAIL" })
        });
        println!(
            "  {capacity:>8} {:>14} {:>14} {:>14} {:>14} {:>14}",
            cells[0], cells[1], cells[2], cells[3], cells[4]
        );
    }

    println!("\n  Sketch payload wire cost (request headers excluded):");
    println!(
        "  {:>8} {:>14} {:>20}",
        "capacity", "one sketch", "two-peer exchange"
    );
    println!("  {:->8} {:->14} {:->20}", "", "", "");
    for capacity in capacities {
        println!(
            "  {capacity:>8} {:>11} B {:>17} B",
            capacity * 8,
            capacity * 8 * 2
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// Layer 2: End-to-end simulation
// ---------------------------------------------------------------------------

fn e2e_simulation() {
    println!("\n=== Layer 2: End-to-end reconciliation simulation ===\n");
    let full_sweep = std::env::var_os("REZZY_FILTER_FULL_SWEEP").is_some();
    let base_count = std::env::var("REZZY_FILTER_ELEMENTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(if full_sweep { 1_000_000 } else { 10_000 });
    if full_sweep {
        println!("Full sweep enabled by REZZY_FILTER_FULL_SWEEP.\n");
    } else {
        println!(
            "Quick baseline: {base_count} elements, 0ms / 8M, average + worst. \
             Set REZZY_FILTER_ELEMENTS=1000000 for the 1M baseline or \
             REZZY_FILTER_FULL_SWEEP=1 for the exhaustive matrix.\n"
        );
    }

    let mut gen = Xorshift128::new(0x243f_6a88_85a3_08d3);
    let base: Vec<ElementHash> = (0..base_count).map(|_| gen.hash()).collect();
    let mut summary_rows = Vec::new();

    let full_generators: &[(
        &str,
        fn(&[ElementHash], usize) -> (Vec<ElementHash>, Vec<ElementHash>),
    )] = &[
        ("best", generate_best_case),
        ("average", generate_average_case),
        ("worst", generate_worst_case),
        ("sym_mix", generate_symmetric_mix),
    ];
    let baseline_generators: &[(
        &str,
        fn(&[ElementHash], usize) -> (Vec<ElementHash>, Vec<ElementHash>),
    )] = &[
        ("average", generate_average_case),
        ("worst", generate_worst_case),
    ];
    let generators = if full_sweep {
        full_generators
    } else {
        baseline_generators
    };
    let latencies: &[u64] = if full_sweep { &[0, 20, 30, 40] } else { &[0] };
    let budgets: &[usize] = if full_sweep {
        &[1_000_000, 4_000_000, 8_000_000, 16_000_000]
    } else {
        &[8_000_000]
    };
    let deltas: &[usize] = if full_sweep {
        &[1_000, 5_000, 10_000, 25_000, 50_000, 100_000]
    } else if base_count <= 10_000 {
        &[100, 1_000]
    } else {
        &[1_000, 5_000, 10_000]
    };

    for &network_latency_ms in latencies {
        for &decode_budget in budgets {
            if full_sweep {
                println!("\n--- network={network_latency_ms}ms, budget={decode_budget} ---");
            }

            for &delta in deltas {
                for &(case_name, gen_fn) in generators {
                    if !full_sweep {
                        println!("  running {case_name:<7} Δ={delta:>6} ...");
                    }
                    let (local, remote) = gen_fn(&base, delta);
                    let input = prepare_input(&local, &remote);

                    let sketch = simulate_strategy(
                        &input,
                        "sketch_split",
                        network_latency_ms,
                        decode_budget,
                        0.001,
                    );
                    let cuckoo = simulate_strategy(
                        &input,
                        "cuckoo",
                        network_latency_ms,
                        decode_budget,
                        0.001,
                    );
                    let cqf =
                        simulate_strategy(&input, "cqf", network_latency_ms, decode_budget, 0.001);
                    let bloom = simulate_strategy(
                        &input,
                        "bloom",
                        network_latency_ms,
                        decode_budget,
                        0.001,
                    );
                    if full_sweep {
                        let remainder_probe = simulate_strategy(
                            &input,
                            "remainder_probe",
                            network_latency_ms,
                            decode_budget,
                            0.001,
                        );
                        let hybrid = simulate_strategy(
                            &input,
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
                            &remainder_probe,
                            &cqf,
                            &bloom,
                            &hybrid,
                        );
                    }

                    if network_latency_ms == 0
                        && decode_budget == 8_000_000
                        && matches!(case_name, "average" | "worst")
                    {
                        summary_rows.push(ReconciliationSummaryRow {
                            case_name,
                            delta,
                            sketch,
                            cuckoo,
                            cqf,
                            bloom,
                        });
                    }
                }
            }
        }
    }

    print_reconciliation_summary(&summary_rows, base_count);
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
        "\n  {:>8} {:>10} {:>14} {:>14} {:>14} {:>14} {:>14} {:>14}",
        "latency",
        "budget",
        "sketch Δ=100K",
        "cuckoo Δ",
        "remainder-probe Δ",
        "cqf Δ",
        "bloom Δ",
        "hybrid Δ"
    );
    println!(
        "  {:->8} {:->10} {:->14} {:->14} {:->14} {:->14} {:->14} {:->14}",
        "", "", "", "", "", "", "", ""
    );

    for &latency in &[0_u64, 20, 30, 40] {
        for &budget in &[1_000_000_usize, 4_000_000, 8_000_000, 16_000_000] {
            let mut cuckoo_co = None;
            let mut remainder_probe_co = None;
            let mut cqf_co = None;
            let mut bloom_co = None;
            let mut hybrid_co = None;
            let mut sketch_ref = None;

            for &delta in &[1_000, 5_000, 10_000, 25_000, 50_000, 100_000] {
                let (local, remote) = generate_average_case(&base, delta);
                let input = prepare_input(&local, &remote);
                let sketch = simulate_strategy(&input, "sketch_split", latency, budget, 0.001);
                let cuckoo = simulate_strategy(&input, "cuckoo", latency, budget, 0.001);
                let remainder_probe =
                    simulate_strategy(&input, "remainder_probe", latency, budget, 0.001);
                let cqf = simulate_strategy(&input, "cqf", latency, budget, 0.001);
                let bloom = simulate_strategy(&input, "bloom", latency, budget, 0.001);
                let hybrid = simulate_strategy(&input, "hybrid", latency, budget, 0.001);

                if cuckoo.wall_ms < sketch.wall_ms && cuckoo_co.is_none() {
                    cuckoo_co = Some(delta);
                }
                if remainder_probe.wall_ms < sketch.wall_ms && remainder_probe_co.is_none() {
                    remainder_probe_co = Some(delta);
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
                if delta == 100_000 {
                    sketch_ref = Some(sketch);
                }
            }

            let fmt = |co: Option<usize>| match co {
                Some(d) => format!("{d:>14}"),
                None => format!("{:>14}", "never"),
            };
            let sketch_col = match sketch_ref {
                Some(s) => format!("{:>8.1}ms r{}", s.wall_ms, s.rounds),
                None => format!("{:>14}", "n/a"),
            };
            println!(
                "  {latency:>6}ms {budget:>10} {sketch_col} {} {} {} {} {}",
                fmt(cuckoo_co),
                fmt(remainder_probe_co),
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
    if std::env::var_os("REZZY_FILTER_FULL_SWEEP").is_some() {
        cross_over_summary();
    }
}
