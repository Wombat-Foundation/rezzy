//! Shared reconciliation fixtures and deterministic helpers for tests/benches.

use rezzy_recon::{
    build_bucket_sketches, BucketDecodeBatch, BucketDecodeSuccess, BucketRequest, ElementHash,
    RemoteDigest, ResidentKernel, SyndromeSketch,
};

/// Deterministic xorshift PRNG used by the reconciliation test and benchmark
/// harnesses. Seed initialization is kept stable so fixtures reproduce.
pub struct Xorshift128Hash {
    state: [u64; 2],
}

impl Xorshift128Hash {
    pub fn new(seed: u64) -> Self {
        Self {
            state: [seed, seed ^ 0x9e37_79b9_7f4a_7c15],
        }
    }

    pub fn next(&mut self) -> u64 {
        let mut value = self.state[0];
        let other = self.state[1];
        value ^= value << 23;
        value ^= value >> 17;
        value ^= other ^ (other >> 26);
        self.state = [other, value];
        value
    }

    pub fn hash(&mut self) -> ElementHash {
        let high = self.next();
        let low = self.next();
        let h64 = self.next() | 1;
        ElementHash {
            h128: (u128::from(high) << 64) | u128::from(low),
            h64,
        }
    }
}

/// The remote-side protocol digest used in reconciliation round fixtures.
pub fn build_remote_digest(remote: &ResidentKernel) -> RemoteDigest {
    RemoteDigest {
        digest: remote.accumulator().digest(),
        known_event_count: remote.accumulator().known_event_count(),
        strata: *remote.strata(),
        frame_matches: true,
        has_unknown_extremity: false,
    }
}

/// Creates an empty round result with room for its expected successful buckets.
pub fn empty_decode_batch(capacity: usize) -> BucketDecodeBatch {
    BucketDecodeBatch {
        successful_buckets: Vec::with_capacity(capacity),
        failed_buckets: Vec::new(),
    }
}

/// XORs paired remote/local sketches and decodes each requested bucket.
/// Decode failures are recorded for the exchange retry path.
fn decode_round_batch(
    remote_sketches: Vec<SyndromeSketch>,
    local_sketches: Vec<SyndromeSketch>,
    requests: &[BucketRequest],
) -> BucketDecodeBatch {
    let mut batch = empty_decode_batch(requests.len());
    for ((mut remote_sketch, local_sketch), request) in remote_sketches
        .into_iter()
        .zip(local_sketches)
        .zip(requests.iter())
    {
        remote_sketch.xor(&local_sketch).unwrap();
        match remote_sketch.decode_elements(request.capacity) {
            Ok(roots) => batch.successful_buckets.push(BucketDecodeSuccess {
                depth: request.depth,
                prefix: request.prefix,
                roots,
            }),
            Err(_) => batch.failed_buckets.push((request.depth, request.prefix)),
        }
    }
    batch
}

/// Builds both sides' sketches and decodes their XOR for a reconciliation
/// round. Shared by the end-to-end test and timing harness.
pub fn build_decode_round_batch(
    local_h64: &[u64],
    remote_h64: &[u64],
    requests: &[BucketRequest],
) -> BucketDecodeBatch {
    let remote_sketches = build_bucket_sketches(remote_h64, requests).unwrap();
    let local_sketches = build_bucket_sketches(local_h64, requests).unwrap();
    decode_round_batch(remote_sketches, local_sketches, requests)
}
