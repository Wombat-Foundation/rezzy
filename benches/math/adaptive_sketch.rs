//! Adaptive overflow sketches versus recursive splitting and exact transfer.
//!
//! This benchmark starts with the production [`ReconciliationClient`] request
//! selection and [`BucketExchange`] state machine. Overflow choices use only a
//! failed request and the remote bucket's advertised element count. Exact
//! transfer is modeled as a length-prefixed list of the same `u64` short IDs
//! used for sketch roots; it is not a production event-wire encoding.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use rezzy::{
    build_bucket_sketches, estimate_strata, validate_overflow_bucket_requests, BucketDecodeBatch,
    BucketDecodeSuccess, BucketExchange, BucketRequest, ClientAction, ElementHash, H64Index,
    ReconciliationClient, RemoteDigest, ResidentKernel, SyndromeSketch,
    MAX_BUCKETED_SKETCH_CAPACITY, MAX_BUCKETS_PER_ROUND, MAX_RECONCILIATION_ROUNDS,
};

const EXACT_ELEM_BYTES: usize = std::mem::size_of::<u64>();
const EXACT_LIST_OVERHEAD: usize = std::mem::size_of::<u64>();
const REMOTE_COUNT_BYTES: usize = std::mem::size_of::<u64>();

#[derive(Clone, Copy)]
enum Strategy {
    RecursiveSplit,
    Adaptive(usize),
    ImmediateExact,
}

struct StrategyResult {
    wall_ms: f64,
    cpu_ms: f64,
    rounds: usize,
    wire_bytes: usize,
    resolved: bool,
}

type InputGenerator = fn(&[ElementHash], usize) -> (Vec<ElementHash>, Vec<ElementHash>);

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
        ElementHash {
            h128: u128::from(high) << 64 | u128::from(low),
            h64: self.next() | 1,
        }
    }
}

fn symmetric_difference(left: &[u64], right: &[u64]) -> Vec<u64> {
    let mut result = Vec::new();
    let mut left_index = 0;
    let mut right_index = 0;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => {
                result.push(left[left_index]);
                left_index += 1;
            }
            std::cmp::Ordering::Greater => {
                result.push(right[right_index]);
                right_index += 1;
            }
            std::cmp::Ordering::Equal => {
                left_index += 1;
                right_index += 1;
            }
        }
    }
    result.extend_from_slice(&left[left_index..]);
    result.extend_from_slice(&right[right_index..]);
    result
}

fn expected_difference(local: &[ElementHash], remote: &[ElementHash]) -> BTreeSet<u64> {
    let mut local_h64: Vec<_> = local.iter().map(|hash| hash.h64).collect();
    let mut remote_h64: Vec<_> = remote.iter().map(|hash| hash.h64).collect();
    local_h64.sort_unstable();
    remote_h64.sort_unstable();
    symmetric_difference(&local_h64, &remote_h64)
        .into_iter()
        .collect()
}

fn overflow_sketch(elements: &[u64], capacity: usize) -> SyndromeSketch {
    let mut sketch = SyndromeSketch::new_overflow(capacity).expect("overflow capacity is valid");
    for element in elements {
        sketch.toggle(*element).expect("benchmark IDs are nonzero");
    }
    sketch
}

fn exact_roots(local: &[u64], remote: &[u64]) -> Vec<u64> {
    symmetric_difference(local, remote)
}

fn result(
    wall: Duration,
    cpu: Duration,
    rounds: usize,
    wire_bytes: usize,
    resolved: bool,
) -> StrategyResult {
    StrategyResult {
        wall_ms: wall.as_secs_f64() * 1e3,
        cpu_ms: cpu.as_secs_f64() * 1e3,
        rounds,
        wire_bytes,
        resolved,
    }
}

#[allow(clippy::too_many_lines)]
fn simulate_strategy(
    local_hashes: &[ElementHash],
    remote_hashes: &[ElementHash],
    strategy: Strategy,
    latency_ms: u64,
    decode_budget: usize,
) -> StrategyResult {
    let expected = expected_difference(local_hashes, remote_hashes);
    let mut local = ResidentKernel::new();
    let mut remote = ResidentKernel::new();
    let mut local_h64 = Vec::with_capacity(local_hashes.len());
    let mut remote_h64 = Vec::with_capacity(remote_hashes.len());
    for hash in local_hashes {
        local.insert(*hash).expect("unique benchmark hash");
        local_h64.push(hash.h64);
    }
    for hash in remote_hashes {
        remote.insert(*hash).expect("unique benchmark hash");
        remote_h64.push(hash.h64);
    }
    local_h64.sort_unstable();
    remote_h64.sort_unstable();
    let local_index = H64Index::new(&local_h64);
    let remote_index = H64Index::new(&remote_h64);

    let remote_digest = RemoteDigest {
        digest: remote.accumulator().digest(),
        known_event_count: remote.accumulator().known_event_count(),
        strata: *remote.strata(),
        frame_matches: true,
        has_unknown_extremity: false,
    };
    let client = ReconciliationClient::default().allow_unlimited_delta();
    let initial = client.select_action(&local, remote_digest, 0);
    let ClientAction::BucketSketches {
        mut requests,
        accumulated_roots,
    } = initial
    else {
        return result(Duration::ZERO, Duration::ZERO, 0, 0, false);
    };
    let estimate = estimate_strata(local.strata(), remote.strata())
        .ok()
        .map(|value| value.delta);
    let mut exchange = BucketExchange::new(
        accumulated_roots,
        MAX_RECONCILIATION_ROUNDS,
        MAX_BUCKETS_PER_ROUND,
        MAX_BUCKETED_SKETCH_CAPACITY,
    );
    let mut wall = Duration::ZERO;
    let mut cpu = Duration::ZERO;
    let mut wire_bytes = 0;
    let mut rounds = 0;

    loop {
        rounds += 1;
        let round_start = Instant::now();
        let remote_sketches =
            build_bucket_sketches(&remote_h64, &requests).expect("valid requests");
        let local_sketches = build_bucket_sketches(&local_h64, &requests).expect("valid requests");
        let mut batch = BucketDecodeBatch {
            successful_buckets: Vec::new(),
            failed_buckets: Vec::new(),
        };
        let mut failures = Vec::new();

        for ((mut remote_sketch, local_sketch), request) in remote_sketches
            .into_iter()
            .zip(local_sketches)
            .zip(&requests)
        {
            // The remote response carries one sketch and an advertised bucket count.
            wire_bytes += request.capacity * 8 + REMOTE_COUNT_BYTES;
            remote_sketch
                .xor(&local_sketch)
                .expect("matching capacities");
            if let Ok(roots) =
                remote_sketch.decode_elements_with_budget(request.capacity, decode_budget)
            {
                batch.successful_buckets.push(BucketDecodeSuccess {
                    depth: request.depth,
                    prefix: request.prefix,
                    roots,
                });
            } else {
                let remote_count = remote_index
                    .bucket_slice(request)
                    .expect("validated request")
                    .len();
                failures.push((*request, remote_count));
            }
        }
        let round_cpu = round_start.elapsed();
        cpu += round_cpu;
        wall += round_cpu + Duration::from_millis(latency_ms);

        if failures.is_empty() || matches!(strategy, Strategy::RecursiveSplit) {
            batch.failed_buckets.extend(
                failures
                    .into_iter()
                    .map(|(request, _)| (request.depth, request.prefix)),
            );
        } else {
            // One additional request/response resolves every failed bucket by an
            // adaptive sketch or exact list. This is the only overflow RTT.
            rounds += 1;
            let fallback_start = Instant::now();
            for (request, remote_count) in failures {
                let local_slice = local_index.bucket_slice(&request).expect("valid request");
                let remote_slice = remote_index.bucket_slice(&request).expect("valid request");
                let exact_wire = EXACT_LIST_OVERHEAD + remote_count * EXACT_ELEM_BYTES;
                let roots = match strategy {
                    Strategy::ImmediateExact => {
                        wire_bytes += exact_wire;
                        exact_roots(local_slice, remote_slice)
                    }
                    Strategy::Adaptive(capacity) => {
                        let overflow_request =
                            BucketRequest::with_overflow(request.depth, request.prefix, capacity);
                        validate_overflow_bucket_requests(&[overflow_request])
                            .expect("benchmark overflow request is within local policy");
                        let sketch_wire = capacity * 8;
                        if exact_wire <= sketch_wire {
                            wire_bytes += exact_wire;
                            exact_roots(local_slice, remote_slice)
                        } else {
                            wire_bytes += sketch_wire;
                            let mut remote_overflow = overflow_sketch(remote_slice, capacity);
                            let local_overflow = overflow_sketch(local_slice, capacity);
                            remote_overflow
                                .xor(&local_overflow)
                                .expect("matching capacities");
                            if let Ok(roots) = remote_overflow
                                .decode_elements_overflow_budget(capacity, decode_budget)
                            {
                                roots
                            } else {
                                wire_bytes += exact_wire;
                                exact_roots(local_slice, remote_slice)
                            }
                        }
                    }
                    Strategy::RecursiveSplit => unreachable!(),
                };
                batch.successful_buckets.push(BucketDecodeSuccess {
                    depth: request.depth,
                    prefix: request.prefix,
                    roots,
                });
            }
            let fallback_cpu = fallback_start.elapsed();
            cpu += fallback_cpu;
            wall += fallback_cpu + Duration::from_millis(latency_ms);
        }

        match exchange.advance(batch, &requests, estimate) {
            ClientAction::BucketSketches {
                requests: next_requests,
                accumulated_roots: _,
            } => requests = next_requests,
            ClientAction::ResolveRoots { roots } => {
                assert_eq!(
                    BTreeSet::from_iter(roots),
                    expected,
                    "reconciliation mismatch"
                );
                return result(wall, cpu, rounds, wire_bytes, true);
            }
            ClientAction::ExtremityDiff | ClientAction::Synchronized => {
                return result(wall, cpu, rounds, wire_bytes, false);
            }
        }
    }
}

fn generate_uniform(base: &[ElementHash], delta: usize) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let mut generator = Xorshift128::new(0x1111_2222);
    let mut remote = base.to_vec();
    remote.extend((0..delta).map(|_| generator.hash()));
    (base.to_vec(), remote)
}

fn generate_concentrated(
    base: &[ElementHash],
    delta: usize,
) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let mut generator = Xorshift128::new(0x3333_4444);
    let mut remote = base.to_vec();
    for index in 0..delta {
        let h64 = (generator.next() ^ (index as u64).wrapping_mul(0x1_0000)) | 1;
        remote.push(ElementHash {
            h128: u128::from(generator.next()) << 64 | u128::from(h64),
            h64,
        });
    }
    (base.to_vec(), remote)
}

fn generate_symmetric_mix(
    base: &[ElementHash],
    delta: usize,
) -> (Vec<ElementHash>, Vec<ElementHash>) {
    let mut generator = Xorshift128::new(0x5555_6666);
    let removals = delta / 2;
    let additions = delta - removals;
    let mut remote = base[removals..].to_vec();
    remote.extend((0..additions).map(|_| generator.hash()));
    (base.to_vec(), remote)
}

pub fn run() {
    println!("\n=== Adaptive overflow sketches ===\n");
    let mut generator = Xorshift128::new(0x243f_6a88_85a3_08d3);
    let base: Vec<_> = (0..100_000).map(|_| generator.hash()).collect();
    let generators: &[(&str, InputGenerator)] = &[
        ("uniform", generate_uniform),
        ("concentrated", generate_concentrated),
        ("symmetric", generate_symmetric_mix),
    ];

    for &latency_ms in &[20, 40] {
        for &delta in &[100, 500, 1_000, 5_000] {
            for &(name, generate) in generators {
                let (local, remote) = generate(&base, delta);
                let split = simulate_strategy(
                    &local,
                    &remote,
                    Strategy::RecursiveSplit,
                    latency_ms,
                    8_000_000,
                );
                let exact = simulate_strategy(
                    &local,
                    &remote,
                    Strategy::ImmediateExact,
                    latency_ms,
                    8_000_000,
                );
                let adaptive: Vec<_> = [64, 128, 256]
                    .map(|capacity| {
                        simulate_strategy(
                            &local,
                            &remote,
                            Strategy::Adaptive(capacity),
                            latency_ms,
                            8_000_000,
                        )
                    })
                    .into();
                println!(
                    "[{name:>12}] delta={delta:>5} latency={latency_ms:>2}ms | \
                     split {:>7.1}/{:>6.1}ms r{:<2} {:>6}B {} | \
                     exact {:>7.1}/{:>6.1}ms r{:<2} {:>6}B {} | \
                     a64 {:>7.1}/{:>6.1}ms {:>6}B | \
                     a128 {:>7.1}/{:>6.1}ms {:>6}B | \
                     a256 {:>7.1}/{:>6.1}ms {:>6}B",
                    split.wall_ms,
                    split.cpu_ms,
                    split.rounds,
                    split.wire_bytes,
                    if split.resolved { "ok" } else { "fall" },
                    exact.wall_ms,
                    exact.cpu_ms,
                    exact.rounds,
                    exact.wire_bytes,
                    if exact.resolved { "ok" } else { "fall" },
                    adaptive[0].wall_ms,
                    adaptive[0].cpu_ms,
                    adaptive[0].wire_bytes,
                    adaptive[1].wall_ms,
                    adaptive[1].cpu_ms,
                    adaptive[1].wire_bytes,
                    adaptive[2].wall_ms,
                    adaptive[2].cpu_ms,
                    adaptive[2].wire_bytes,
                );
            }
        }
    }
}
