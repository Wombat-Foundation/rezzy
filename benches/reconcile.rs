use std::collections::HashSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

use rezzy::{
    build_bucket_sketches, decode_bucket_sketches, estimate_delta, gf64_mul, BucketRequest,
    ClientAction, ElementHash, ReconciliationClient, RemoteDigest, ResidentKernel, SyndromeSketch,
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

fn benchmark_scale_workload(
    base_count: usize,
    local_extra_count: usize,
    remote_extra_count: usize,
) {
    let mut generator = Xorshift128::new(0x243f_6a88_85a3_08d3);
    let base: Vec<_> = (0..base_count).map(|_| generator.hash()).collect();
    let local_extra: Vec<_> = (0..local_extra_count).map(|_| generator.hash()).collect();
    let remote_extra: Vec<_> = (0..remote_extra_count).map(|_| generator.hash()).collect();
    let mut identities = HashSet::with_capacity(
        base_count
            .saturating_add(local_extra_count)
            .saturating_add(remote_extra_count),
    );
    for event in base.iter().chain(&local_extra).chain(&remote_extra) {
        assert!(identities.insert((event.h128, event.h64)));
    }
    let mut local = ResidentKernel::new();
    let mut remote = ResidentKernel::new();
    for event in &base {
        local.insert(*event).expect("benchmark hashes are valid");
        remote.insert(*event).expect("benchmark hashes are valid");
    }
    for event in &local_extra {
        local.insert(*event).expect("benchmark hashes are valid");
    }
    for event in &remote_extra {
        remote.insert(*event).expect("benchmark hashes are valid");
    }
    assert_eq!(
        local.accumulator().known_event_count(),
        u64::try_from(base_count.saturating_add(local_extra_count)).unwrap()
    );
    assert_eq!(
        remote.accumulator().known_event_count(),
        u64::try_from(base_count.saturating_add(remote_extra_count)).unwrap()
    );
    assert_eq!(
        local
            .accumulator()
            .known_event_count()
            .checked_sub(remote.accumulator().known_event_count())
            .expect("local fixture is larger"),
        local_extra_count.checked_sub(remote_extra_count).unwrap() as u64
    );
    let expected_residual = local_extra
        .iter()
        .chain(&remote_extra)
        .fold(0, |residual, event| residual ^ event.h128);
    assert_eq!(
        local.accumulator().residual(remote.accumulator()),
        expected_residual
    );
    black_box((local, remote));
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

    // Test 1: Medium Sized Room
    let elapsed = measure(1, || benchmark_scale_workload(50_000, 2_100, 1_900));
    report("scale/50000 +2100/-1900", 1, elapsed);

    // Test 2: Large Room
    let elapsed = measure(1, || benchmark_scale_workload(100_000, 5_000, 4_000));
    report("scale/100000 +5000/-4000", 1, elapsed);

    // Test 3: Huge Room
    let elapsed = measure(1, || benchmark_scale_workload(10_000_000, 500_000, 400_000));
    report("scale/10000000 +500000/-400000", 1, elapsed);

    // -------------------------------------------------------------------------
    // Extraction sweep: confirms O(log N + Δ) scaling of build_bucket_sketches.
    //
    // Plants exactly BUCKET_CAP (64) elements in each of n_buckets depth-24
    // prefixes. With N=10M background, ~0.6 background elements land in any
    // given prefix on average (10M / 2^24), so each bucket extract touches
    // ~BUCKET_CAP planted elements — isolating cost to Δ, not N.
    //
    // Capacities are capped at 64 per bucket (MAX_BUCKET_SKETCH_CAPACITY).
    // Multiple buckets are used for larger Δ to stay within the limit.
    // -------------------------------------------------------------------------
    println!("\n--- build_bucket_sketches extraction sweep (N=10M, varying Δ) ---");
    {
        const DEPTH: u8 = 24;
        // 64 − DEPTH; the prefix occupies the top DEPTH bits of h64.
        const HIGH_SHIFT: u32 = 40_u32;
        // Bottom HIGH_SHIFT bits mask — avoids `(1_u64 << 40) - 1` form.
        const LOW_MASK: u64 = u64::MAX >> 24_u32;
        const BUCKET_CAP: usize = 64; // MAX_BUCKET_SKETCH_CAPACITY per bucket
        const BASE_PREFIX: u32 = 0x00_10_00; // arbitrary 24-bit starting prefix

        let n: usize = 10_000_000;

        let mut gen = Xorshift128::new(0xdead_beef_cafe_babe);

        // 1, 8, 64 buckets → Δ ≈ 64, 512, 4096 extracted elements.
        // Aggregate capacity: n_buckets × 64 ≤ 4096 = MAX_BUCKETED_SKETCH_CAPACITY.
        for n_buckets in [1_usize, 8, 64] {
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
    for (n, delta) in [
        (10_000_usize, 100_usize),
        (100_000, 1_000),
        (1_000_000, 10_000),
        (10_000_000, 100_000),
    ] {
        let mut gen = Xorshift128::new(0x1234_5678_abcd_ef00 ^ delta as u64);
        let base: Vec<ElementHash> = (0..n).map(|_| gen.hash()).collect();
        let remote_extra: Vec<ElementHash> = (0..delta).map(|_| gen.hash()).collect();

        let mut local_kernel = ResidentKernel::new();
        let mut remote_kernel = ResidentKernel::new();
        for h in &base {
            local_kernel.insert(*h).unwrap();
            remote_kernel.insert(*h).unwrap();
        }
        for h in &remote_extra {
            remote_kernel.insert(*h).unwrap();
        }

        // Pre-sort both sides' h64 indices (in production this is maintained)
        let mut local_sorted: Vec<u64> = base.iter().map(|h| h.h64).collect();
        local_sorted.sort_unstable();
        let mut remote_sorted: Vec<u64> = base.iter().chain(&remote_extra).map(|h| h.h64).collect();
        remote_sorted.sort_unstable();

        let remote_digest = RemoteDigest {
            digest: remote_kernel.accumulator().digest(),
            known_event_count: remote_kernel.accumulator().known_event_count(),
            strata: *remote_kernel.strata(),
            frame_matches: true,
            has_unknown_extremity: false,
        };

        // Triage runs once outside the timed loop — cost not included.
        let client = ReconciliationClient::default();
        let action = client.select_action(&local_kernel, remote_digest, 0);
        let ClientAction::BucketSketches { requests, .. } = action else {
            // Δ exceeds gate_threshold (MAX_RECONCILIATION_ROUNDS × MAX_BUCKETED_SKETCH_CAPACITY
            // = 20 × 4096 = 81920): select_action returns ExtremityDiff, not BucketSketches.
            println!("extract+decode/N={n} Δ={delta}: gated to ExtremityDiff (Δ > 81920)");
            continue;
        };

        let total_cap: usize = requests.iter().map(|r| r.capacity).sum();
        println!(
            "  [triage] N={n} Δ={delta}: {} requests, aggregate_cap={total_cap}",
            requests.len(),
        );

        // Scale iterations down for expensive cases so total bench time stays reasonable.
        // Target: ~3-5 seconds per (N, Δ) pair.
        let iterations: u32 = match n {
            0..=10_000 => 30,
            10_001..=100_000 => 10,
            100_001..=1_000_000 => 3,
            _ => 1,
        };

        let elapsed = measure(iterations, || {
            let remote_sk = build_bucket_sketches(black_box(&remote_sorted), &requests).unwrap();
            let local_sk = build_bucket_sketches(black_box(&local_sorted), &requests).unwrap();
            let mut recovered = 0usize;
            for (mut rs, ls) in remote_sk.into_iter().zip(local_sk) {
                rs.xor(&ls).unwrap();
                if let Ok(roots) = rs.decode_elements(rs.capacity()) {
                    recovered = recovered.saturating_add(roots.len());
                }
            }
            black_box(recovered);
        });
        report(
            &format!("extract+decode/N={n} Δ={delta}"),
            iterations,
            elapsed,
        );
    }
}
