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
    BucketExchange, ClientAction, ReconciliationClient, MAX_BUCKETS_PER_ROUND,
};
use rezzy::reconcile::resident::ResidentKernel;
use rezzy::reconcile::triage::{
    estimate_strata, MAX_BUCKETED_SKETCH_CAPACITY, MAX_STRATA_FACTOR_WORK,
};
#[path = "../../support/reconciliation.rs"]
mod reconciliation_support;
use reconciliation_support::{
    build_decode_round_batch, build_remote_digest as remote_digest, Xorshift128Hash as Xorshift128,
};

/// Inserts `count` elements shared by both sides, recording each hash on both
/// sides so the identical base cancels out of reconciliation.
fn insert_shared_base(
    generator: &mut Xorshift128,
    local: &mut ResidentKernel,
    remote: &mut ResidentKernel,
    local_h64: &mut Vec<u64>,
    remote_h64: &mut Vec<u64>,
    count: usize,
) {
    for _ in 0..count {
        let hash = generator.hash();
        local.insert(hash).unwrap();
        remote.insert(hash).unwrap();
        local_h64.push(hash.h64);
        remote_h64.push(hash.h64);
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

    insert_shared_base(
        &mut generator,
        &mut local,
        &mut remote,
        &mut local_h64,
        &mut remote_h64,
        base,
    );
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

/// The sorted symmetric difference of two sorted `h64` lists.
fn symmetric_difference(local: &[u64], remote: &[u64]) -> Vec<u64> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < local.len() || j < remote.len() {
        match (local.get(i), remote.get(j)) {
            (Some(x), Some(y)) => match x.cmp(y) {
                core::cmp::Ordering::Equal => {
                    i = i.saturating_add(1);
                    j = j.saturating_add(1);
                }
                core::cmp::Ordering::Less => {
                    out.push(*x);
                    i = i.saturating_add(1);
                }
                core::cmp::Ordering::Greater => {
                    out.push(*y);
                    j = j.saturating_add(1);
                }
            },
            (Some(x), None) => {
                out.push(*x);
                i = i.saturating_add(1);
            }
            (None, Some(y)) => {
                out.push(*y);
                j = j.saturating_add(1);
            }
            (None, None) => break,
        }
    }
    out
}

/// Drives the full bucket-exchange loop to completion (or bails to
/// `ExtremityDiff`), returning `(round_trip_count, resolved_roots,
/// terminal_action_kind)`. Resolved roots carry the actual identities, so
/// callers can assert them against the true symmetric difference rather than
/// trusting only a count.
fn run_round_trip(
    local: &ResidentKernel,
    local_h64: &[u64],
    remote_h64: &[u64],
    remote: &ResidentKernel,
) -> (usize, Vec<u64>, &'static str) {
    let client = ReconciliationClient::default().allow_unlimited_delta();
    let digest = remote_digest(remote);
    let initial = client.select_action(local, digest, 0);

    let (mut current_requests, accumulated_roots) = match initial {
        ClientAction::Synchronized => return (0, Vec::new(), "Synchronized"),
        ClientAction::ExtremityDiff => return (0, Vec::new(), "ExtremityDiff"),
        ClientAction::BucketSketches {
            requests,
            accumulated_roots,
        } => (requests, accumulated_roots),
        ClientAction::ResolveRoots { roots } => return (1, roots, "ResolveRoots"),
    };

    let estimated_delta = estimate_strata(local.strata(), remote.strata(), MAX_STRATA_FACTOR_WORK)
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
        let batch = build_decode_round_batch(local_h64, remote_h64, &current_requests);

        match exchange.advance(batch, &current_requests, estimated_delta) {
            ClientAction::BucketSketches { requests, .. } => {
                current_requests = requests;
                round_trips = round_trips.saturating_add(1);
            }
            ClientAction::ResolveRoots { roots } => {
                return (round_trips, roots, "ResolveRoots");
            }
            ClientAction::ExtremityDiff => return (round_trips, Vec::new(), "ExtremityDiff"),
            ClientAction::Synchronized => return (round_trips, Vec::new(), "Synchronized"),
        }
    }
}

/// Small symmetric difference, comfortably inside the initial
/// `provision_capacity` sizing (`ceil(1.5*delta)+4`): should resolve in a
/// single round trip via the unbucketed/top-level sketch.
#[test]
fn small_delta_resolves_in_one_round_trip() {
    let (local, remote, local_h64, remote_h64) = build_pair(1, 5_000, 6, 6);
    let (round_trips, roots, terminal) = run_round_trip(&local, &local_h64, &remote_h64, &remote);
    assert_eq!(terminal, "ResolveRoots", "expected a clean decode");
    assert_eq!(
        round_trips, 1,
        "well-provisioned delta should not need a retry round"
    );
    assert_eq!(
        roots.len(),
        12,
        "should recover exactly the injected symmetric difference"
    );
    let mut resolved = roots;
    resolved.sort_unstable();
    assert_eq!(
        resolved,
        symmetric_difference(&local_h64, &remote_h64),
        "resolved roots must be exactly the symmetric difference, not just the right count"
    );
}
/// Builds a pair with a large identical shared base plus a small, real
/// difference. The shared base cancels out of `estimate_strata`'s per-stratum
/// residuals entirely; the injected differences concentrate in the low strata
/// (a hash's stratum is the trailing-zero count of its `h128`, so most hashes
/// land in stratum 0), which overflows a stratum and forces the
/// `low_confidence` fallback. Confirms `low_confidence` only degrades the
/// capacity *estimate* rather than blocking convergence: even with a poor
/// first guess the small delta still resolves in a single round (the
/// provisioned buckets hold it), so no escalation round is needed here.
///
/// Genuinely forcing the multi-round `retry_or_split_bucket` escalation (a
/// difference large enough to overflow the *provisioned* capacity, not just a
/// stratum) is deferred to `benches/reconcile.rs` -- see the module docs.
#[test]
fn low_confidence_estimate_still_converges() {
    let mut generator = Xorshift128::new(3);
    let mut local = ResidentKernel::new();
    let mut remote = ResidentKernel::new();
    let mut local_h64 = Vec::new();
    let mut remote_h64 = Vec::new();

    // A large shared base, identical on both sides. These never contribute to
    // the strata residual (they XOR to zero), so they neither saturate a
    // stratum nor distort the estimate -- the estimate sees only the genuine
    // differences injected below.
    insert_shared_base(
        &mut generator,
        &mut local,
        &mut remote,
        &mut local_h64,
        &mut remote_h64,
        200,
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

    // The injected differences cluster in the low strata (stratum == trailing
    // zeros of h128), overflowing one and forcing the low_confidence fallback.
    let estimate =
        estimate_strata(local.strata(), remote.strata(), MAX_STRATA_FACTOR_WORK).unwrap();
    assert!(
        estimate.low_confidence,
        "a genuine per-stratum difference must force the low_confidence fallback"
    );

    let (round_trips, roots, terminal) = run_round_trip(&local, &local_h64, &remote_h64, &remote);
    assert_eq!(
        terminal, "ResolveRoots",
        "a low-confidence first guess must still converge to the correct roots"
    );
    assert_eq!(
        round_trips, 1,
        "the provisioned buckets hold the small delta, so low_confidence does not force a retry round"
    );
    assert_eq!(
        roots.len(),
        16,
        "should recover exactly the injected symmetric difference"
    );
    let mut resolved = roots;
    resolved.sort_unstable();
    assert_eq!(
        resolved,
        symmetric_difference(&local_h64, &remote_h64),
        "resolved roots must be exactly the symmetric difference, not just the right count"
    );
}

/// Identical sets short-circuit to `Synchronized` with zero round trips --
/// the baseline every other case in this file is contrasted against.
#[test]
fn identical_sets_synchronize_without_a_round_trip() {
    let (local, remote, local_h64, remote_h64) = build_pair(4, 500, 0, 0);
    let (round_trips, roots, terminal) = run_round_trip(&local, &local_h64, &remote_h64, &remote);
    assert_eq!(terminal, "Synchronized");
    assert_eq!(round_trips, 0);
    assert!(roots.is_empty(), "identical sets resolve no roots");
}
