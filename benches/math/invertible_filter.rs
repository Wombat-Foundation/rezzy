use std::hint::black_box;
use std::time::{Duration, Instant};

use rezzy::{SyndromeSketch, MAX_SKETCH_CAPACITY};

fn hash(index: u64) -> u64 {
    index.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17) | 1
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

// ---------------------------------------------------------------------------
// Golomb-coded set (BIP 158 style) with full enumeration support.
//
// Unlike xorf (lossy, membership-only), this stores the sorted hash values
// in Golomb-Rice encoding and can decode the full set from the wire bytes.
// This is the "invertible filter" baseline for the reconciliation benchmark.
// ---------------------------------------------------------------------------
mod gcs {
    /// A Golomb-coded set that can enumerate all inserted elements.
    ///
    /// Space: ~`P` bits per element for the encoded stream, where `P` is the
    /// Golomb parameter (BIP 158 default: 20 → ~2.5 bytes/elem). The sorted
    /// hash array is stored implicitly via the Golomb-Rice prefix codes.
    #[derive(Clone)]
    pub struct GolombCodedSet {
        /// Golomb parameter (P in BIP 158).
        p: u32,
        /// Truncated hash values (low 32 bits) for practical Golomb-Rice encoding.
        /// Full u64 deltas are too large for efficient Rice coding.
        hashes: Vec<u32>,
    }

    impl GolombCodedSet {
        /// Builds a GCS from a set of u64 values (truncated to u32 for encoding).
        pub fn build(elements: &[u64], p: u32) -> Self {
            let mut hashes: Vec<u32> = elements.iter().map(|&h| h as u32).collect();
            hashes.sort_unstable();
            hashes.dedup();
            Self { p, hashes }
        }

        /// Probes membership (false-positive rate ≈ 1/P).
        pub fn contains(&self, value: u64) -> bool {
            let truncated = value as u32;
            self.hashes.binary_search(&truncated).is_ok()
        }

        /// Enumerates all truncated elements — this is what makes it invertible.
        pub fn enumerate(&self) -> &[u32] {
            &self.hashes
        }

        /// Wire size in bytes (Golomb-Rice encoded bitstream).
        pub fn wire_bytes(&self) -> usize {
            let mut bits: usize = 0;
            let rem_bits = f64::from(self.p).log2().ceil() as usize;
            let mut prev: u32 = 0;
            for &h in &self.hashes {
                let delta = h.saturating_sub(prev);
                let q = delta / self.p;
                let _r = delta % self.p;
                // Unary quotient: q + 1 bits
                bits += q as usize + 1;
                // Remainder: rem_bits bits
                bits += rem_bits;
                prev = h;
            }
            bits.div_ceil(8)
        }

        /// Number of elements stored.
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
        black_box(decoded);
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
    println!("=== Invertible Filter vs Sketch Reconciliation Benchmark ===\n");
    println!("Comparing PinSketch (algebraic, 8 B/elem) against");
    println!("Golomb-coded set (invertible filter, ~P bits/elem).\n");

    // Space comparison at various set sizes.
    for n in [32, 128, 1_000, 10_000] {
        benchmark_space_comparison(n);
    }

    println!("\n--- Reconciliation benchmark ---\n");

    // Reconciliation at various set sizes and delta sizes.
    for set_size in [100, 1_000, 10_000] {
        for delta in [1, 10, 100, set_size / 4]
            .into_iter()
            .filter(|&d| d <= set_size)
        {
            benchmark_pinsketch_reconciliation(set_size, delta);
            benchmark_gcs_reconciliation(set_size, delta);
            println!();
        }
    }
}
