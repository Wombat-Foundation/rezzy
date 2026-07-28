use std::hint::black_box;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use rezzy::{
    build_bucket_sketches, decode_bucket_sketches, estimate_delta, gf64_mul, BucketDecodeBatch,
    BucketDecodeSuccess, BucketRequest, ElementHash, ReconciliationClient, RemoteDigest,
    ResidentKernel, SyndromeSketch,
};

fn hash(index: u64) -> ElementHash {
    let h64 = index.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17) | 1;
    ElementHash {
        h128: u128::from(h64) << 64 | u128::from(index),
        h64,
    }
}

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

fn report_split(name: &str, setup: Duration, algo: Duration) {
    println!(
        "{name}: (setup: {:.6} ms, algo: {:.6} ms)",
        setup.as_secs_f64() * 1e3,
        algo.as_secs_f64() * 1e3
    );
}

fn benchmark_pinsketch_toggle(capacity: usize, element_count: usize) {
    let mut generator = Xorshift128::new(0x7f4a_7c15_9e37_79b9);
    let values: Vec<u64> = (0..element_count).map(|_| generator.next() | 1).collect();
    let elapsed = measure(10, || {
        let mut sketch = SyndromeSketch::new(capacity).expect("benchmark capacity is valid");
        for value in &values {
            sketch
                .toggle(*value)
                .expect("benchmark identifiers are valid");
        }
        black_box(sketch);
    });
    report(
        &format!("algebraic/toggle/{capacity}x{element_count}"),
        10,
        elapsed,
    );
}

fn benchmark_pinsketch_subtract(capacity: usize, element_count: usize) {
    let mut generator = Xorshift128::new(0x1357_9bdf_2468_ace0);
    let left_values: Vec<u64> = (0..element_count).map(|_| generator.next() | 1).collect();
    let right_values: Vec<u64> = (0..element_count).map(|_| generator.next() | 1).collect();
    let mut left = SyndromeSketch::new(capacity).expect("benchmark capacity is valid");
    let mut right = SyndromeSketch::new(capacity).expect("benchmark capacity is valid");
    for value in &left_values {
        left.toggle(*value)
            .expect("benchmark identifiers are valid");
    }
    for value in &right_values {
        right
            .toggle(*value)
            .expect("benchmark identifiers are valid");
    }
    let elapsed = measure(100, || {
        let residual = left.subtract(&right).expect("benchmark capacities match");
        black_box(residual);
    });
    report(
        &format!("algebraic/subtract/{capacity}x{element_count}"),
        100,
        elapsed,
    );
}

fn benchmark_pinsketch_decode(capacity: usize, element_count: usize) {
    let mut generator = Xorshift128::new(0x0ddc_0ffe_e15e_d00d);
    let mut sketch = SyndromeSketch::new(capacity).expect("benchmark capacity is valid");
    for _ in 0..element_count {
        sketch
            .toggle(generator.next() | 1)
            .expect("benchmark identifiers are valid");
    }
    let encoded = sketch.encode();
    let elapsed = measure(100, || {
        let decoded =
            SyndromeSketch::decode(capacity, &encoded).expect("benchmark decode is valid");
        let _ = black_box(decoded.decode_elements(element_count.min(capacity)));
    });
    report(
        &format!("algebraic/decode/{capacity}x{element_count}"),
        100,
        elapsed,
    );
}

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

fn benchmark_scale_from_pool(
    pool: &HashPool,
    base_count: usize,
    local_extra_count: usize,
    remote_extra_count: usize,
) -> (Duration, Duration) {
    let setup_start = Instant::now();
    let base_slice = &pool.base[..base_count];
    let local_extra_slice = &pool.local_extra[..local_extra_count];
    let remote_extra_slice = &pool.remote_extra[..remote_extra_count];

    let mut local = ResidentKernel::new();
    let mut remote = ResidentKernel::new();
    for event in base_slice {
        local.insert(*event).expect("benchmark hashes are valid");
        remote.insert(*event).expect("benchmark hashes are valid");
    }
    for event in local_extra_slice {
        local.insert(*event).expect("benchmark hashes are valid");
    }
    for event in remote_extra_slice {
        remote.insert(*event).expect("benchmark hashes are valid");
    }

    let setup_elapsed = setup_start.elapsed();

    let client = ReconciliationClient::default().allow_unlimited_delta();
    let remote_digest = RemoteDigest {
        digest: remote.accumulator().digest(),
        known_event_count: remote.accumulator().known_event_count(),
        strata: *remote.strata(),
        frame_matches: true,
        has_unknown_extremity: false,
    };

    let algo_start = Instant::now();
    let action = client.select_action(&local, remote_digest, 0);
    black_box(action);
    let algo_elapsed = algo_start.elapsed();

    (setup_elapsed, algo_elapsed)
}

#[allow(clippy::too_many_lines)]
fn main() {
    let elapsed = measure(1_000_000, || {
        black_box(gf64_mul(
            black_box(0x0123_4567_89ab_cdef),
            black_box(0xfedc_ba98_7654_3211),
        ));
    });
    report("gf64 multiply", 1_000_000, elapsed);

    benchmark_pinsketch_toggle(8, 4);
    benchmark_pinsketch_toggle(32, 16);
    benchmark_pinsketch_toggle(64, 32);

    benchmark_pinsketch_subtract(8, 4);
    benchmark_pinsketch_subtract(32, 16);
    benchmark_pinsketch_subtract(64, 32);

    benchmark_pinsketch_decode(8, 4);
    benchmark_pinsketch_decode(32, 16);
    benchmark_pinsketch_decode(64, 32);

    for count in [100, 1_000, 10_000] {
        let elapsed = measure(10, || {
            let mut resident = ResidentKernel::new();
            for index in 1..=count {
                resident
                    .insert(hash(index))
                    .expect("benchmark hashes are valid");
            }
            black_box(resident);
        });
        report(&format!("resident insert/{count}"), 10, elapsed);
    }

    for capacity in [1, 4, 8, 16, 32, 64] {
        let mut sketch = SyndromeSketch::new(capacity).expect("benchmark capacity is valid");
        for index in 1..=capacity {
            let value = u64::try_from(index)
                .expect("benchmark capacity fits u64")
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .expect("benchmark identifier arithmetic fits");
            sketch
                .toggle(value)
                .expect("benchmark identifiers are nonzero");
        }
        let iterations = if capacity <= 8 { 100 } else { 10 };
        let elapsed = measure(iterations, || {
            let _ = black_box(sketch.decode_elements(sketch.capacity()));
        });
        report(&format!("pinsketch decode/{capacity}"), iterations, elapsed);
    }

    let local = ResidentKernel::new();
    for count in [0, 4, 100] {
        let mut remote = ResidentKernel::new();
        for index in 1..=count {
            remote
                .insert(hash(index))
                .expect("benchmark hashes are valid");
        }
        let iterations = if count == 100 { 10 } else { 100 };
        let elapsed = measure(iterations, || {
            let _ = black_box(estimate_delta(local.strata(), remote.strata()));
        });
        report(
            &format!("triage/estimate strata/{count}"),
            iterations,
            elapsed,
        );
    }

    let requests = [BucketRequest {
        depth: 8,
        prefix: 0,
        capacity: 8,
    }];
    let encoded = [0_u8; 64];
    let elapsed = measure(1_000, || {
        let _ = black_box(decode_bucket_sketches(&encoded, &requests));
    });
    report("triage/parse bucket sketch", 1_000, elapsed);

    let batch = BucketDecodeBatch {
        successful_buckets: vec![BucketDecodeSuccess {
            depth: 8,
            prefix: 0,
            roots: vec![101, 102],
        }],
        failed_buckets: vec![(8, 1)],
    };
    let previous = [
        BucketRequest {
            depth: 8,
            prefix: 0,
            capacity: 8,
        },
        BucketRequest {
            depth: 8,
            prefix: 1,
            capacity: 64,
        },
    ];
    let mut batches = vec![batch; 10_000];
    let elapsed = measure(10_000, || {
        let _ = black_box(ReconciliationClient::transition_bucket_batch(
            black_box(batches.pop().unwrap()),
            black_box(&previous),
            black_box(vec![]),
            black_box(Some(100)),
            black_box(4096),
        ));
    });
    report("triage/transition_bucket_batch split", 10_000, elapsed);

    println!("\n--- scale workload triage (plucking from pre-generated HashPool) ---");
    let pool = HashPool::new(10_000_000, 5_000_000, 5_000_000);

    // Test 1: Medium Sized Room
    let (setup_elapsed, algo_elapsed) = benchmark_scale_from_pool(&pool, 50_000, 2_100, 1_900);
    report_split("scale/50000 +2100/-1900", setup_elapsed, algo_elapsed);

    // Test 2: Large Room
    let (setup_elapsed, algo_elapsed) = benchmark_scale_from_pool(&pool, 100_000, 5_000, 4_000);
    report_split("scale/100000 +5000/-4000", setup_elapsed, algo_elapsed);

    // Test 3: Huge Rooms
    let (setup_elapsed, algo_elapsed) = benchmark_scale_from_pool(&pool, 1_000_000, 10_000, 9_000);
    report_split("scale/1000000 +10000/-9000", setup_elapsed, algo_elapsed);
    let (setup_elapsed, algo_elapsed) =
        benchmark_scale_from_pool(&pool, 10_000_000, 500_000, 400_000);
    report_split(
        "scale/10000000 +500000/-400000",
        setup_elapsed,
        algo_elapsed,
    );

    // Test 4: Near-total disagreement (high desync) on 1M and 10M element sets
    let (setup_elapsed, algo_elapsed) = benchmark_scale_from_pool(&pool, 10_000, 500_000, 490_000);
    report_split(
        "scale/1000000 near-total desync (+500000/-490000)",
        setup_elapsed,
        algo_elapsed,
    );
    let (setup_elapsed, algo_elapsed) =
        benchmark_scale_from_pool(&pool, 100_000, 5_000_000, 4_900_000);
    report_split(
        "scale/10000000 near-total desync (+5000000/-4900000)",
        setup_elapsed,
        algo_elapsed,
    );

    // -------------------------------------------------------------------------
    // Extraction sweep: confirms O(log N + Δ) scaling of build_bucket_sketches.
    //
    // Plants exactly BUCKET_CAP (64) elements in each of n_buckets depth-24
    // prefixes. With N=10M background, ~0.6 background elements land in any
    // given prefix on average (10M / 2^24), so each bucket extract touches
    // ~BUCKET_CAP planted elements — isolating cost to Δ, not N.
    //
    // Capacities are capped at 32 per bucket (MAX_BUCKET_SKETCH_CAPACITY).
    // Multiple buckets are used for larger Δ to stay within the limit.
    // -------------------------------------------------------------------------
    println!("\n--- build_bucket_sketches extraction sweep (N=10M, varying Δ) ---");
    {
        const DEPTH: u8 = 24;
        // 64 − DEPTH; the prefix occupies the top DEPTH bits of h64.
        const HIGH_SHIFT: u32 = 40_u32;
        // Bottom HIGH_SHIFT bits mask — avoids `(1_u64 << 40) - 1` form.
        const LOW_MASK: u64 = u64::MAX >> 24_u32;
        const BUCKET_CAP: usize = 32; // MAX_BUCKET_SKETCH_CAPACITY per bucket
        const BASE_PREFIX: u32 = 0x00_10_00; // arbitrary 24-bit starting prefix

        let n: usize = 10_000_000;

        let mut gen = Xorshift128::new(0xdead_beef_cafe_babe);

        // 2, 16, 128 buckets → Δ ≈ 64, 512, 4096 extracted elements.
        // Aggregate capacity: n_buckets × 32 ≤ 4096 = MAX_BUCKETED_SKETCH_CAPACITY.
        for n_buckets in [2_usize, 16, 128] {
            let delta = n_buckets.saturating_mul(BUCKET_CAP);
            // Consecutive depth-24 prefixes: each covers a disjoint h64 range.
            let prefixes: Vec<u32> = (0..n_buckets)
                .map(|i| {
                    BASE_PREFIX.saturating_add(u32::try_from(i).expect("n_buckets always fits u32"))
                })
                .collect();

            let mut h64_index: Vec<u64> = Vec::with_capacity(n);

            // Plant BUCKET_CAP odd-h64 elements in each prefix range.
            for (&prefix, bucket_i) in prefixes.iter().zip(0_u64..) {
                for j in 0_u64..BUCKET_CAP as u64 {
                    let suffix = (gen.next() ^ (bucket_i << 16) ^ j) & LOW_MASK;
                    h64_index.push((u64::from(prefix) << HIGH_SHIFT) | suffix | 1);
                }
            }
            // Uniform background noise filling the rest of the index.
            for _ in delta..n {
                h64_index.push(gen.next() | 1);
            }
            h64_index.sort_unstable();

            // One request per bucket, all valid (capacity ≤ 64, aggregate ≤ 4096).
            let requests: Vec<BucketRequest> = prefixes
                .iter()
                .map(|&prefix| BucketRequest {
                    depth: DEPTH,
                    prefix,
                    capacity: BUCKET_CAP,
                })
                .collect();

            let iterations: u32 = if n_buckets == 1 { 1000 } else { 100 };
            let elapsed = measure(iterations, || {
                let _ = black_box(build_bucket_sketches(black_box(&h64_index), &requests));
            });
            report(&format!("extract/N=10M Δ≈{delta}"), iterations, elapsed);
        }
    }

    // -------------------------------------------------------------------------
    // Extraction + decode (triage pre-computed).
    //
    // `select_action` (which includes strata estimation) is called ONCE outside
    // the timed loop so that only `build_bucket_sketches` + XOR + `decode` are
    // measured. This isolates server-side extraction and client-side decode from
    // the strata-estimation cost already benchmarked above.
    // -------------------------------------------------------------------------
    println!("\n--- extract + decode (triage pre-computed, N varies) ---");
    // -------------------------------------------------------------------------
    // Extraction + decode (triage pre-computed, populated bucket measurement).
    //
    // Measures build_bucket_sketches + XOR + SyndromeSketch::decode_elements
    // over populated prefix buckets (isolating extraction and decode scaling).
    // -------------------------------------------------------------------------
    println!("\n--- extract + decode (populated buckets, N varies) ---");
    {
        const DEPTH: u8 = 24;
        const HIGH_SHIFT: u32 = 40_u32;
        const LOW_MASK: u64 = u64::MAX >> 24_u32;
        const BUCKET_CAP: usize = 32;
        const BASE_PREFIX: u32 = 0x00_10_00;

        for (n, n_buckets) in [
            (10_000_usize, 2_usize),
            (100_000, 16),
            (1_000_000, 128),
            (10_000_000, 128),
            (10_000_000, 3124),
        ] {
            let delta = n_buckets.saturating_mul(BUCKET_CAP);
            let mut gen = Xorshift128::new(0x1234_5678_abcd_ef00 ^ delta as u64);

            let prefixes: Vec<u32> = (0..n_buckets)
                .map(|i| BASE_PREFIX.saturating_add(u32::try_from(i).unwrap()))
                .collect();

            let mut local_sorted: Vec<u64> = Vec::with_capacity(n);
            let mut remote_sorted: Vec<u64> = Vec::with_capacity(n.saturating_add(delta));

            // Plant BUCKET_CAP elements per bucket in remote index (local gets background)
            for (&prefix, bucket_i) in prefixes.iter().zip(0_u64..) {
                for j in 0_u64..BUCKET_CAP as u64 {
                    let suffix = (gen.next() ^ (bucket_i << 16) ^ j) & LOW_MASK;
                    let val = (u64::from(prefix) << HIGH_SHIFT) | suffix | 1;
                    local_sorted.push(val);
                    // Remote has extra elements in each bucket to create delta
                    remote_sorted.push(val);
                    let diff_suffix =
                        (gen.next() ^ (bucket_i << 16) ^ j.saturating_add(100)) & LOW_MASK;
                    remote_sorted.push((u64::from(prefix) << HIGH_SHIFT) | diff_suffix | 1);
                }
            }

            for _ in delta..n {
                let val = gen.next() | 1;
                local_sorted.push(val);
                remote_sorted.push(val);
            }

            local_sorted.sort_unstable();
            remote_sorted.sort_unstable();

            let requests: Vec<BucketRequest> = prefixes
                .iter()
                .map(|&prefix| BucketRequest {
                    depth: DEPTH,
                    prefix,
                    capacity: BUCKET_CAP,
                })
                .collect();

            let total_cap: usize = requests.iter().map(|r| r.capacity).sum();
            println!(
                "  [populated] N={n} Δ≈{delta}: {} requests, aggregate_cap={total_cap}",
                requests.len(),
            );

            let iterations: u32 = match n_buckets {
                1..=8 => 30,
                9..=64 => 3,
                _ => 1,
            };

            let elapsed = measure(iterations, || {
                let mut all_remote_sk = Vec::with_capacity(requests.len());
                let mut all_local_sk = Vec::with_capacity(requests.len());

                for chunk in requests.chunks(64) {
                    all_remote_sk
                        .extend(build_bucket_sketches(black_box(&remote_sorted), chunk).unwrap());
                    all_local_sk
                        .extend(build_bucket_sketches(black_box(&local_sorted), chunk).unwrap());
                }

                let recovered: usize = all_remote_sk
                    .into_par_iter()
                    .zip(all_local_sk.into_par_iter())
                    .map(|(mut rs, ls)| {
                        rs.xor(&ls).unwrap();
                        match rs.decode_elements(rs.capacity()) {
                            Ok(roots) => roots.len(),
                            Err(_) => 0,
                        }
                    })
                    .sum();
                black_box(recovered);
            });
            report(
                &format!("extract+decode/N={n} Δ≈{delta}"),
                iterations,
                elapsed,
            );
        }
    }
}
