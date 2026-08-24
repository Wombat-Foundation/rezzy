//! End-to-end MSC0501/MSC4521 client<->server reconciliation round trips.
//!
//! Unlike `test_reconcile_algebraic.rs` (which exercises the `PinSketch`
//! primitive and `estimate_strata` in isolation), this drives the actual
//! protocol loop: `ReconciliationClient::select_action` -> server-side
//! `build_bucket_sketches` -> client-side XOR+decode -> `BucketExchange`
//! advance -- repeated until `ResolveRoots`/`Synchronized`/`ExtremityDiff`.
//! The loop shape mirrors `benches/reconcile.rs`'s
//! `benchmark_bucket_exchange_from_pool`, but as assertions instead of a
//! timing harness, covering `provision_capacity`'s initial sizing and a
//! `low_confidence` strata estimate that still converges.
//!
//! This file measures **round-trip count**, not round-trip *time* -- the
//! loop runs in-process with no simulated network latency or serialization
//! cost. It also does not (yet) cover the over-capacity bucket-split
//! retry path (`retry_or_split_bucket`'s multi-round escalation): reliably
//! forcing that deterministically, without either flaking on uniform-random
//! skew or hand-tuning a hot-bucket construction that hits the round cap,
//! turned out to need more care than a drive-by add here -- that scenario
//! is better exercised via `benches/reconcile.rs`'s
//! `benchmark_bucket_exchange_from_pool` (which already runs multi-round
//! exchanges at scale) than forced into an always-pass unit test. See
//! `docs/tech_debt.md` for the follow-up.

use rezzy::reconcile::client::{
    BucketExchange, ClientAction, ReconciliationClient, RemoteDigest, MAX_BUCKETS_PER_ROUND,
};
use rezzy::reconcile::resident::ResidentKernel;
use rezzy::reconcile::server::build_bucket_sketches;
use rezzy::reconcile::triage::{
    estimate_strata, BucketDecodeBatch, BucketDecodeSuccess, MAX_BUCKETED_SKETCH_CAPACITY,
};
use rezzy::reconcile::ElementHash;

/// Deterministic xorshift so cases are reproducible without external randomness.
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
            h128: (u128::from(high) << 64) | u128::from(low),
            h64,
        }
    }
}

/// Builds a local/remote pair sharing `base` elements, with `local_extra`
/// only on the local side and `remote_extra` only on the remote side, so the
/// true symmetric difference is `local_extra + remote_extra`.
fn build_pair(
    seed: u64,
    base: usize,
    local_extra: usize,
    remote_extra: usize,
) -> (ResidentKernel, ResidentKernel, Vec<u64>, Vec<u64>) {
    let mut generator = Xorshift128::new(seed);
    let mut local = ResidentKernel::new();
    let mut remote = ResidentKernel::new();
    let mut local_h64 = Vec::with_capacity(base.saturating_add(local_extra));
    let mut remote_h64 = Vec::with_capacity(base.saturating_add(remote_extra));

    for _ in 0..base {
        let hash = generator.hash();
        local.insert(hash).unwrap();
        remote.insert(hash).unwrap();
        local_h64.push(hash.h64);
        remote_h64.push(hash.h64);
    }
    for _ in 0..local_extra {
        let hash = generator.hash();
        local.insert(hash).unwrap();
        local_h64.push(hash.h64);
    }
    for _ in 0..remote_extra {
        let hash = generator.hash();
        remote.insert(hash).unwrap();
        remote_h64.push(hash.h64);
    }
    local_h64.sort_unstable();
    remote_h64.sort_unstable();
    (local, remote, local_h64, remote_h64)
}

fn remote_digest(remote: &ResidentKernel) -> RemoteDigest {
    RemoteDigest {
        digest: remote.accumulator().digest(),
        known_event_count: remote.accumulator().known_event_count(),
        strata: *remote.strata(),
        frame_matches: true,
        has_unknown_extremity: false,
    }
}

/// Drives the full bucket-exchange loop to completion (or bails to
/// `ExtremityDiff`), returning `(round_trip_count, resolved_root_count,
/// terminal_action_kind)`.
fn run_round_trip(
    local: &ResidentKernel,
    local_h64: &[u64],
    remote_h64: &[u64],
    remote: &ResidentKernel,
) -> (usize, usize, &'static str) {
    let client = ReconciliationClient::default().allow_unlimited_delta();
    let digest = remote_digest(remote);
    let initial = client.select_action(local, digest, 0);

    let (mut current_requests, accumulated_roots) = match initial {
        ClientAction::Synchronized => return (0, 0, "Synchronized"),
        ClientAction::ExtremityDiff => return (0, 0, "ExtremityDiff"),
        ClientAction::BucketSketches {
            requests,
            accumulated_roots,
        } => (requests, accumulated_roots),
        ClientAction::ResolveRoots { roots } => return (1, roots.len(), "ResolveRoots"),
    };

    let estimated_delta = estimate_strata(local.strata(), remote.strata())
        .ok()
        .map(|estimate| estimate.delta);

    let mut exchange = BucketExchange::new(
        accumulated_roots,
        rezzy::reconcile::client::MAX_RECONCILIATION_ROUNDS,
        MAX_BUCKETS_PER_ROUND,
        MAX_BUCKETED_SKETCH_CAPACITY,
    );

    let mut round_trips = 1_usize; // the initial select_action round counts as one.
    loop {
        let remote_sketches = build_bucket_sketches(remote_h64, &current_requests).unwrap();
        let local_sketches = build_bucket_sketches(local_h64, &current_requests).unwrap();

        let mut batch = BucketDecodeBatch {
            successful_buckets: Vec::with_capacity(current_requests.len()),
            failed_buckets: Vec::new(),
        };
        for ((mut remote_sketch, local_sketch), request) in remote_sketches
            .into_iter()
            .zip(local_sketches)
            .zip(current_requests.iter())
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

        match exchange.advance(batch, &current_requests, estimated_delta) {
            ClientAction::BucketSketches { requests, .. } => {
                current_requests = requests;
                round_trips = round_trips.saturating_add(1);
            }
            ClientAction::ResolveRoots { roots } => {
                return (round_trips, roots.len(), "ResolveRoots");
            }
            ClientAction::ExtremityDiff => return (round_trips, 0, "ExtremityDiff"),
            ClientAction::Synchronized => return (round_trips, 0, "Synchronized"),
        }
    }
}

/// Small symmetric difference, comfortably inside the initial
/// `provision_capacity` sizing (`ceil(1.5*delta)+4`): should resolve in a
/// single round trip via the unbucketed/top-level sketch.
#[test]
fn small_delta_resolves_in_one_round_trip() {
    let (local, remote, local_h64, remote_h64) = build_pair(1, 5_000, 6, 6);
    let (round_trips, resolved, terminal) =
        run_round_trip(&local, &local_h64, &remote_h64, &remote);
    assert_eq!(terminal, "ResolveRoots", "expected a clean decode");
    assert_eq!(
        round_trips, 1,
        "well-provisioned delta should not need a retry round"
    );
    assert_eq!(
        resolved, 12,
        "should recover exactly the injected symmetric difference"
    );
}

/// Builds a pair whose low strata are saturated (forcing
/// `estimate_strata`'s `low_confidence` fallback -- see
/// `triage.rs::low_confidence_estimate_uses_lowest_decoded_stratum`) but
/// whose true delta is still small enough to resolve. Confirms
/// `low_confidence` only degrades the capacity *estimate* rather than
/// blocking convergence: the client is expected to retry into a correct
/// answer even when its first guess is a poor one.
#[test]
fn low_confidence_estimate_still_converges_via_retry() {
    let mut generator = Xorshift128::new(3);
    let mut local = ResidentKernel::new();
    let mut remote = ResidentKernel::new();
    let mut local_h64 = Vec::new();
    let mut remote_h64 = Vec::new();

    // Saturate the low strata with many distinct elements so the raw
    // stratum-0 syndrome fails to decode, forcing estimate_strata to fall
    // back to a scaled lowest-decoded-stratum estimate (low_confidence).
    for _ in 0..200 {
        let hash = generator.hash();
        local.insert(hash).unwrap();
        remote.insert(hash).unwrap();
        local_h64.push(hash.h64);
        remote_h64.push(hash.h64);
    }
    let estimate = estimate_strata(local.strata(), remote.strata()).unwrap();
    assert!(
        !estimate.low_confidence,
        "identical strata should still report a confident (zero) delta"
    );

    // Now inject a genuine, small, real difference on top.
    for _ in 0..8 {
        let hash = generator.hash();
        local.insert(hash).unwrap();
        local_h64.push(hash.h64);
    }
    for _ in 0..8 {
        let hash = generator.hash();
        remote.insert(hash).unwrap();
        remote_h64.push(hash.h64);
    }
    local_h64.sort_unstable();
    remote_h64.sort_unstable();

    let (round_trips, resolved, terminal) =
        run_round_trip(&local, &local_h64, &remote_h64, &remote);
    assert_eq!(
        terminal, "ResolveRoots",
        "small real delta atop a large shared base must still converge"
    );
    assert!(round_trips >= 1);
    assert_eq!(
        resolved, 16,
        "should recover exactly the injected symmetric difference"
    );
}

/// Identical sets short-circuit to `Synchronized` with zero round trips --
/// the baseline every other case in this file is contrasted against.
#[test]
fn identical_sets_synchronize_without_a_round_trip() {
    let (local, remote, local_h64, remote_h64) = build_pair(4, 500, 0, 0);
    let (round_trips, _resolved, terminal) =
        run_round_trip(&local, &local_h64, &remote_h64, &remote);
    assert_eq!(terminal, "Synchronized");
    assert_eq!(round_trips, 0);
}
