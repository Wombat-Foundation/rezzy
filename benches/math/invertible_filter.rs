use std::hint::black_box;
use std::time::{Duration, Instant};

use rezzy::{SyndromeSketch, MAX_SKETCH_CAPACITY};

use super::filters::{
    quotient_remainder_bits_for_fpr, remainder_probe_bits_for_fpr, BloomFilter,
    CountingQuotientFilter, CuckooFilter, RemainderProbeFilter,
};

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
}

fn measure(iterations: u32, mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    start.elapsed()
}

// ---------------------------------------------------------------------------
// Golomb-coded set (BIP 158 style) with full enumeration support.
//
// XOR filters (e.g. xorf) expose raw fingerprints (seed, block_length,
// fingerprints: Box<[u8]>) but cannot recover elements: the 8-bit
// fingerprints discard the original u64 identities and the construction
// peel stack is not retained. This GCS stores the sorted hash values in
// Golomb-Rice encoding and can decode the full set from the wire bytes.
// This is the "invertible filter" baseline for the reconciliation benchmark.
// ---------------------------------------------------------------------------
mod gcs {
    /// A Golomb-coded set that can enumerate all inserted elements.
    ///
    /// Space: ~`P` bits per element for the encoded stream, where `P` is the
    /// Golomb parameter (BIP 158 default: 20 → ~2.5 bytes/elem). Values are
    /// truncated to u16 — like BIP 158's hash-mod-table-size — to keep
    /// Golomb-Rice deltas small and encoding efficient.
    #[derive(Clone)]
    pub struct GolombCodedSet {
        /// Golomb parameter (P in BIP 158).
        p: u32,
        /// Truncated hash values (u16). Random u32/u64 values produce deltas
        /// of ~128M which blow up Golomb-Rice unary quotients to millions of
        /// bits per element. Truncating to u16 keeps average delta at ~32K
        /// for P=20, which encodes in ~1600 bits/elem — still worse than
        /// PinSketch's 64 bits/elem, but correct.
        hashes: Vec<u16>,
    }

    impl GolombCodedSet {
        /// Builds a GCS from a set of u64 values (truncated to u16 for encoding).
        pub fn build(elements: &[u64], p: u32) -> Self {
            let mut hashes: Vec<u16> = elements.iter().map(|&h| h as u16).collect();
            hashes.sort_unstable();
            hashes.dedup();
            Self { p, hashes }
        }

        /// Probes membership (false-positive rate depends on truncation + P).
        #[allow(dead_code)]
        pub fn contains(&self, value: u64) -> bool {
            let truncated = value as u16;
            self.hashes.binary_search(&truncated).is_ok()
        }

        /// Enumerates all truncated elements — this is what makes it invertible.
        pub fn enumerate(&self) -> &[u16] {
            &self.hashes
        }

        /// Wire size in bytes (Golomb-Rice encoded bitstream).
        pub fn wire_bytes(&self) -> usize {
            let mut bits: usize = 0;
            let rem_bits = (32 - self.p.leading_zeros()) as usize;
            let mut prev: u16 = 0;
            for &h in &self.hashes {
                let delta = h.saturating_sub(prev);
                let q = delta / self.p as u16;
                // Unary quotient: q + 1 bits
                bits += q as usize + 1;
                // Remainder: always ceil(log2(P)) bits (fixed-width field)
                bits += rem_bits;
                prev = h;
            }
            bits.div_ceil(8)
        }

        /// Number of elements stored.
        #[allow(dead_code)]
        pub fn len(&self) -> usize {
            self.hashes.len()
        }
    }

    /// Computes the symmetric difference between a GCS and a reference set.
    pub fn symmetric_difference(gcs: &GolombCodedSet, reference: &[u64]) -> (Vec<u64>, Vec<u64>) {
        let ref_set: std::collections::HashSet<u64> = reference.iter().copied().collect();
        let gcs_set: std::collections::HashSet<u64> =
            gcs.enumerate().iter().map(|&h| u64::from(h)).collect();

        let in_gcs_not_ref: Vec<u64> = gcs_set.difference(&ref_set).copied().collect();
        let in_ref_not_gcs: Vec<u64> = ref_set.difference(&gcs_set).copied().collect();
        (in_gcs_not_ref, in_ref_not_gcs)
    }
}

// ---------------------------------------------------------------------------
// Benchmark: PinSketch vs GCS for set reconciliation
//
// Protocol comparison:
//   PinSketch: Each side builds sketch (8 bytes/elem), exchange sketches,
//              XOR, decode → symmetric difference.
//   GCS:       Each side builds GCS (~P bits/elem), exchange GCS + probe
//              results, enumerate → symmetric difference.
//
// This measures the actual space/time tradeoff for each approach.
// ---------------------------------------------------------------------------

fn benchmark_pinsketch_reconciliation(set_size: usize, delta: usize) {
    let mut gen = Xorshift128::new(0x7f4a_7c15_9e37_79b9);

    // Generate base set + local-only + remote-only elements.
    let base: Vec<u64> = (0..set_size).map(|_| gen.next() | 1).collect();
    let local_only: Vec<u64> = (0..delta).map(|_| gen.next() | 1).collect();
    let remote_only: Vec<u64> = (0..delta).map(|_| gen.next() | 1).collect();

    let mut local_set: Vec<u64> = base.iter().chain(local_only.iter()).copied().collect();
    let mut remote_set: Vec<u64> = base.iter().chain(remote_only.iter()).copied().collect();
    local_set.sort_unstable();
    remote_set.sort_unstable();

    // PinSketch capacity: must hold the symmetric difference (2 * delta).
    let capacity = (2 * delta).clamp(1, MAX_SKETCH_CAPACITY);

    // Build sketches and measure.
    let setup = measure(10, || {
        let mut local_sk = SyndromeSketch::new(capacity).unwrap();
        for &v in &local_set {
            local_sk.toggle(v).unwrap();
        }
        let mut remote_sk = SyndromeSketch::new(capacity).unwrap();
        for &v in &remote_set {
            remote_sk.toggle(v).unwrap();
        }
        black_box((&local_sk, &remote_sk));
    });

    // XOR + decode.
    let algo = measure(10, || {
        let mut local_sk = SyndromeSketch::new(capacity).unwrap();
        for &v in &local_set {
            local_sk.toggle(v).unwrap();
        }
        let mut remote_sk = SyndromeSketch::new(capacity).unwrap();
        for &v in &remote_set {
            remote_sk.toggle(v).unwrap();
        }
        local_sk.xor(&remote_sk).unwrap();
        let decoded = local_sk.decode_elements(capacity);
        let _ = black_box(decoded);
    });

    let wire = capacity * 8; // 8 bytes per u64 coordinate
    println!(
        "  pinsketch/N={set_size} Δ={delta}: setup={:.3} ms, decode={:.3} ms, wire={} bytes ({:.1} B/elem), capacity={capacity}",
        setup.as_secs_f64() * 1e3,
        algo.as_secs_f64() * 1e3,
        wire,
        wire as f64 / (2 * delta) as f64,
    );
}

fn benchmark_gcs_reconciliation(set_size: usize, delta: usize) {
    let mut gen = Xorshift128::new(0x7f4a_7c15_9e37_79b9);

    let base: Vec<u64> = (0..set_size).map(|_| gen.next() | 1).collect();
    let local_only: Vec<u64> = (0..delta).map(|_| gen.next() | 1).collect();
    let remote_only: Vec<u64> = (0..delta).map(|_| gen.next() | 1).collect();

    let mut local_set: Vec<u64> = base.iter().chain(local_only.iter()).copied().collect();
    let mut remote_set: Vec<u64> = base.iter().chain(remote_only.iter()).copied().collect();
    local_set.sort_unstable();
    remote_set.sort_unstable();

    // BIP 158 default P=20 gives ~1.2 bits/elem false-positive rate.
    // For reconciliation, we need low FPR so probing is accurate.
    for p in [20, 128] {
        let local_gcs = gcs::GolombCodedSet::build(&local_set, p);
        let remote_gcs = gcs::GolombCodedSet::build(&remote_set, p);

        let wire_local = local_gcs.wire_bytes();
        let wire_remote = remote_gcs.wire_bytes();
        let wire_total = wire_local + wire_remote;

        // Build + enumerate + symmetric difference.
        let algo = measure(10, || {
            let local = gcs::GolombCodedSet::build(&local_set, p);
            let remote = gcs::GolombCodedSet::build(&remote_set, p);

            // Probe: remote GCS against local set, local GCS against remote set.
            // For true reconciliation, we also need the full element lists
            // (which is the "enumerate" part — this is what makes it invertible).
            let (in_remote_not_local, in_local_not_remote) =
                gcs::symmetric_difference(&remote, &local_set);
            let (in_local_not_remote_2, in_remote_not_local_2) =
                gcs::symmetric_difference(&local, &remote_set);

            // Union of both directions.
            let mut diff: Vec<u64> = in_remote_not_local;
            diff.extend(in_local_not_remote);
            diff.extend(in_local_not_remote_2);
            diff.extend(in_remote_not_local_2);
            diff.sort_unstable();
            diff.dedup();
            black_box(diff);
        });

        println!(
            "  gcs/P={p}/N={set_size} Δ={delta}: algo={:.3} ms, wire={} bytes ({:.1} B/elem total, {:.2} bits/elem each)",
            algo.as_secs_f64() * 1e3,
            wire_total,
            wire_total as f64 / (set_size + delta) as f64,
            wire_local as f64 * 8.0 / local_set.len() as f64,
        );
    }
}

// ---------------------------------------------------------------------------
// Benchmark: Membership-only filters (Bloom, Cuckoo, CQF, remainder-probe)
// for set reconciliation (Protocol A).
//
// Protocol: sender builds filter from its elements, sends to receiver.
// Receiver probes its elements, sends back candidates + receiver-only.
// Sender computes symmetric difference.
// ---------------------------------------------------------------------------

fn benchmark_filter_reconciliation(set_size: usize, delta: usize, fpr: f64) {
    let mut gen = Xorshift128::new(0x7f4a_7c15_9e37_79b9);

    let base: Vec<u64> = (0..set_size).map(|_| gen.next() | 1).collect();
    let local_only: Vec<u64> = (0..delta).map(|_| gen.next() | 1).collect();
    let remote_only: Vec<u64> = (0..delta).map(|_| gen.next() | 1).collect();

    let mut local_set: Vec<u64> = base.iter().chain(local_only.iter()).copied().collect();
    let mut remote_set: Vec<u64> = base.iter().chain(remote_only.iter()).copied().collect();
    local_set.sort_unstable();
    remote_set.sort_unstable();

    let filter_types = ["bloom", "cuckoo", "cqf", "remainder_probe"];

    for &filter_type in &filter_types {
        // 1. Sender builds filter.
        let build = measure(10, || {
            let f = build_filter_bench(&local_set, fpr, filter_type);
            black_box(&f);
        });

        // 2. Full protocol: build + probe + response.
        let algo = measure(10, || {
            let filter = build_filter_bench(&local_set, fpr, filter_type);

            // Receiver probes its elements.
            let mut candidates: Vec<u64> = Vec::new();
            let mut receiver_only: Vec<u64> = Vec::new();
            for &val in &remote_set {
                if filter_contains_bench(&filter, val) {
                    candidates.push(val);
                } else {
                    receiver_only.push(val);
                }
            }

            // Wire: filter bytes + response (candidates + receiver-only).
            let filter_wire = filter_byte_len_bench(&filter);
            let response_wire = (candidates.len() + receiver_only.len()) * 8;

            // Sender computes symmetric difference.
            // The sender only knows local_set and the candidates response,
            // not remote_set.
            let mut symmetric_diff: Vec<u64> = Vec::new();
            for &val in &local_set {
                if candidates.binary_search(&val).is_err() {
                    symmetric_diff.push(val);
                }
            }
            for &val in &candidates {
                if local_set.binary_search(&val).is_err() {
                    symmetric_diff.push(val);
                }
            }
            symmetric_diff.extend_from_slice(&receiver_only);

            black_box((filter_wire, response_wire, symmetric_diff));
        });

        let filter_wire = filter_byte_len_bench(&build_filter_bench(&local_set, fpr, filter_type));
        let response_wire = {
            let filter = build_filter_bench(&local_set, fpr, filter_type);
            let mut candidates = 0usize;
            let mut receiver_only = 0usize;
            for &val in &remote_set {
                if filter_contains_bench(&filter, val) {
                    candidates += 1;
                } else {
                    receiver_only += 1;
                }
            }
            (candidates + receiver_only) * 8
        };
        let total_wire = filter_wire + response_wire;

        println!(
            "  {filter_type}/N={set_size} Δ={delta} FPR={fpr:.4}: build={:.3} ms, algo={:.3} ms, wire={total_wire} bytes ({:.1} B/elem), filter={filter_wire} bytes, response={response_wire} bytes",
            build.as_secs_f64() * 1e3,
            algo.as_secs_f64() * 1e3,
            total_wire as f64 / (set_size + delta) as f64,
        );
    }
}

enum FilterBench {
    Bloom(BloomFilter),
    Cuckoo(CuckooFilter),
    Cqf(CountingQuotientFilter),
    Rp(RemainderProbeFilter),
}

fn build_filter_bench(elements: &[u64], fpr: f64, filter_type: &str) -> FilterBench {
    match filter_type {
        "bloom" => {
            let mut f = BloomFilter::with_fpr(elements.len().max(1), fpr);
            for &val in elements {
                assert!(f.insert(&val), "bloom insertion failed");
            }
            FilterBench::Bloom(f)
        }
        "cuckoo" => {
            let mut f = CuckooFilter::with_fpr(elements.len().max(1), fpr);
            for &val in elements {
                assert!(f.insert(&val), "cuckoo insertion failed");
            }
            FilterBench::Cuckoo(f)
        }
        "cqf" => {
            let rem_bits = quotient_remainder_bits_for_fpr(fpr);
            let mut f =
                CountingQuotientFilter::with_remainder_bits(elements.len().max(1), rem_bits);
            for &val in elements {
                assert!(f.insert(&val), "cqf insertion failed");
            }
            FilterBench::Cqf(f)
        }
        "remainder_probe" => {
            let rem_bits = remainder_probe_bits_for_fpr(fpr);
            let mut f = RemainderProbeFilter::with_remainder_bits(elements.len().max(1), rem_bits);
            for &val in elements {
                assert!(f.insert(&val), "remainder_probe insertion failed");
            }
            FilterBench::Rp(f)
        }
        _ => unreachable!(),
    }
}

fn filter_contains_bench(filter: &FilterBench, value: u64) -> bool {
    match filter {
        FilterBench::Bloom(f) => f.contains(&value),
        FilterBench::Cuckoo(f) => f.contains(&value),
        FilterBench::Cqf(f) => f.contains(&value),
        FilterBench::Rp(f) => f.contains(&value),
    }
}

fn filter_byte_len_bench(filter: &FilterBench) -> usize {
    match filter {
        FilterBench::Bloom(f) => f.byte_len(),
        FilterBench::Cuckoo(f) => f.byte_len(),
        FilterBench::Cqf(f) => f.byte_len(),
        FilterBench::Rp(f) => f.byte_len(),
    }
}

fn benchmark_space_comparison(set_size: usize) {
    println!("\n--- Space comparison for N={set_size} ---");

    // PinSketch capacity = set_size (worst case: full set difference).
    let capacity = set_size.min(MAX_SKETCH_CAPACITY);
    let pinsketch_wire = capacity * 8;
    println!(
        "  pinsketch/cap={capacity}: {} bytes ({:.1} B/elem)",
        pinsketch_wire,
        pinsketch_wire as f64 / set_size as f64,
    );

    for p in [20, 128, 512] {
        let mut gen = Xorshift128::new(0x243f_6a88_85a3_08d3);
        let elements: Vec<u64> = (0..set_size).map(|_| gen.next() | 1).collect();
        let gcs = gcs::GolombCodedSet::build(&elements, p);
        let wire = gcs.wire_bytes();
        let fpr = 1.0 / f64::from(p);
        println!(
            "  gcs/P={p}/FPR={fpr:.4}: {wire} bytes ({:.1} B/elem, {:.2} bits/elem)",
            wire as f64 / set_size as f64,
            wire as f64 * 8.0 / set_size as f64,
        );
    }
}

pub fn run() {
    println!("=== Reconciliation Benchmark: All Strategies ===\n");
    println!("Comparing PinSketch, GCS, Bloom, Cuckoo, CQF, remainder-probe.\n");

    // Space comparison at various set sizes.
    for n in [32, 128, 1_000, 10_000] {
        benchmark_space_comparison(n);
    }

    println!("\n--- Reconciliation benchmark (FPR=0.1%) ---\n");

    let fpr = 0.001;

    // Reconciliation at various set sizes and delta sizes.
    for set_size in [100, 1_000, 10_000] {
        for delta in [1, 10, 100, set_size / 4]
            .into_iter()
            .filter(|&d| d <= set_size)
        {
            benchmark_pinsketch_reconciliation(set_size, delta);
            benchmark_gcs_reconciliation(set_size, delta);
            benchmark_filter_reconciliation(set_size, delta, fpr);
            println!();
        }
    }
}
