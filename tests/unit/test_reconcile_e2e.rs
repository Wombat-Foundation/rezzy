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

use rezzy_recon::client::{
    BucketExchange, ClientAction, ReconciliationClient, MAX_BUCKETS_PER_ROUND,
};
use rezzy_recon::resident::ResidentKernel;
use rezzy_recon::triage::{estimate_strata, MAX_BUCKETED_SKETCH_CAPACITY, MAX_STRATA_FACTOR_WORK};
use rezzy_recon::{
    build_bucket_nodes, verify_follow_up, BucketDecodeBatch, BucketDecodeSuccess, BucketRequest,
    ElementHash, NodeSummary, SortedPopulation,
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
        ClientAction::ResolveRoots { roots, .. } => return (1, roots, "ResolveRoots"),
    };

    let estimated_delta = estimate_strata(local.strata(), remote.strata(), MAX_STRATA_FACTOR_WORK)
        .ok()
        .map(|estimate| estimate.delta);

    let mut exchange = BucketExchange::new(
        accumulated_roots,
        rezzy_recon::client::MAX_RECONCILIATION_ROUNDS,
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
            ClientAction::ResolveRoots { roots, .. } => {
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
/// (a hash's stratum is the trailing-zero count of its `h64`, so most hashes
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
    // zeros of h64), overflowing one and forcing the low_confidence fallback.
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

/// One side's population: the resident kernel plus the sorted index.
struct Side {
    kernel: ResidentKernel,
    population: SortedPopulation,
}

impl Side {
    fn new(elements: Vec<ElementHash>) -> Self {
        let mut kernel = ResidentKernel::new();
        for element in &elements {
            kernel.insert(*element).unwrap();
        }
        Self {
            kernel,
            population: SortedPopulation::new(elements),
        }
    }

    /// The multi-valued `h64 -> h128` map.
    fn candidates(&self, root: u64) -> Vec<u128> {
        self.population.candidates(root).to_vec()
    }
}

/// A canonical digest whose derived `h64`/`h128` are exactly the element's.
fn digest_of(element: ElementHash) -> [u8; 32] {
    let mut digest = [0_u8; 32];
    digest[..8].copy_from_slice(&element.h64.to_be_bytes());
    digest[16..].copy_from_slice(&element.h128.to_be_bytes());
    digest
}

/// Drives the verified exchange. Returns the terminal action and the exchange.
fn run_verified(local: &Side, remote: &Side) -> (ClientAction, BucketExchange) {
    let client = ReconciliationClient::default().allow_unlimited_delta();
    let initial = client.select_action(&local.kernel, remote_digest(&remote.kernel), 0);
    let ClientAction::BucketSketches {
        mut requests,
        accumulated_roots,
    } = initial
    else {
        return (initial, BucketExchange::new(Vec::new(), 1, 1, 1));
    };
    let estimate = estimate_strata(
        local.kernel.strata(),
        remote.kernel.strata(),
        MAX_STRATA_FACTOR_WORK,
    )
    .ok()
    .map(|e| e.delta);
    let mut exchange = BucketExchange::new(
        accumulated_roots,
        rezzy_recon::client::MAX_RECONCILIATION_ROUNDS,
        MAX_BUCKETS_PER_ROUND,
        MAX_BUCKETED_SKETCH_CAPACITY,
    );
    loop {
        let remote_nodes = build_bucket_nodes(&remote.population, &requests).unwrap();
        let local_nodes = build_bucket_nodes(&local.population, &requests).unwrap();
        let mut batch = BucketDecodeBatch {
            successful_buckets: Vec::new(),
            failed_buckets: Vec::new(),
        };
        for ((request, (remote_sketch, _)), (local_sketch, _)) in
            requests.iter().zip(&remote_nodes).zip(&local_nodes)
        {
            let mut xored = remote_sketch.clone();
            xored.xor(local_sketch).unwrap();
            match xored.decode_elements(request.capacity) {
                Ok(roots) => batch.successful_buckets.push(BucketDecodeSuccess {
                    depth: request.depth,
                    prefix: request.prefix,
                    roots,
                }),
                Err(_) => batch.failed_buckets.push((request.depth, request.prefix)),
            }
        }
        let local_summaries: Vec<NodeSummary> = local_nodes.iter().map(|n| n.1).collect();
        let remote_summaries: Vec<NodeSummary> = remote_nodes.iter().map(|n| n.1).collect();
        let action = exchange
            .advance_verified(
                batch,
                &requests,
                &local_summaries,
                &remote_summaries,
                estimate,
                |root| local.candidates(root),
            )
            .unwrap();
        match action {
            ClientAction::BucketSketches { requests: next, .. } => requests = next,
            terminal => return (terminal, exchange),
        }
    }
}

#[test]
fn verified_exchange_resolves_and_passes_phase_two() {
    let mut generator = Xorshift128::new(11);
    let shared: Vec<ElementHash> = (0..300).map(|_| generator.hash()).collect();
    let local_only: Vec<ElementHash> = (0..5).map(|_| generator.hash()).collect();
    let remote_only: Vec<ElementHash> = (0..7).map(|_| generator.hash()).collect();
    let local = Side::new([shared.clone(), local_only.clone()].concat());
    let remote = Side::new([shared, remote_only.clone()].concat());

    let (action, exchange) = run_verified(&local, &remote);
    let ClientAction::ResolveRoots { mut roots, .. } = action else {
        panic!("expected a clean resolve, got {action:?}");
    };
    roots.sort_unstable();
    let mut expected: Vec<u64> = local_only
        .iter()
        .chain(&remote_only)
        .map(|e| e.h64)
        .collect();
    expected.sort_unstable();
    assert_eq!(roots, expected);

    // Phase 2, per node: the peer returns the identifiers for that node's M.
    let mut covered = 0;
    for classified in exchange.classified() {
        let (depth, prefix) = classified.node();
        let request = BucketRequest::new(depth, prefix, 8);
        let returned: Vec<[u8; 32]> = remote_only
            .iter()
            .filter(|e| classified.m_roots().contains(&e.h64))
            .map(|e| digest_of(*e))
            .collect();
        covered += returned.len();
        assert_eq!(verify_follow_up(classified, &request, &returned), Ok(()));
    }
    assert_eq!(covered, remote_only.len());
}

/// A shared element whose `h64` collides with a remote-only one (mocked, since
/// no real event ID can be ground to this). The root survives the sketch on
/// the wrong side and the node fails its count identity. The same restricted
/// root set comes back under a bigger capacity, so the exchange classifies a
/// collision after two attempts, never admits the node, and reports the prefix
/// as ladder-failed instead of climbing every step to the baseline.
#[test]
fn colliding_h64_is_ladder_failed_after_two_attempts() {
    let mut generator = Xorshift128::new(12);
    let shared: Vec<ElementHash> = (0..200).map(|_| generator.hash()).collect();
    let collided = shared[17];
    let twin = ElementHash {
        h128: collided.h128 ^ 0xdead_beef,
        h64: collided.h64,
    };
    let extra = generator.hash();
    let local = Side::new(shared.clone());
    let remote = Side::new([shared, vec![twin, extra]].concat());

    let (action, exchange) = run_verified(&local, &remote);
    let ClientAction::ResolveRoots {
        roots,
        ladder_failed,
    } = action
    else {
        panic!("expected a partial resolve, got {action:?}");
    };
    assert!(
        roots.is_empty(),
        "the failed node's roots must not be admitted"
    );
    assert_eq!(ladder_failed, vec![(0, 0)]);
    assert_eq!(exchange.ladder_failed(), ladder_failed.as_slice());
    assert!(exchange.classified().is_empty());
    assert!(
        exchange.rounds_emitted() <= 2,
        "two attempts, not the whole ladder: {}",
        exchange.rounds_emitted()
    );
}

/// With several buckets, only the bucket holding the collision is given up on;
/// every sibling still resolves and verifies.
#[test]
fn collision_in_one_bucket_leaves_siblings_resolved() {
    let mut generator = Xorshift128::new(14);
    let shared: Vec<ElementHash> = (0..200).map(|_| generator.hash()).collect();
    let local_extra: Vec<ElementHash> = (0..22).map(|_| generator.hash()).collect();
    let remote_extra: Vec<ElementHash> = (0..22).map(|_| generator.hash()).collect();
    let collided = shared[3];
    let twin = ElementHash {
        h128: collided.h128 ^ 0xdead_beef,
        h64: collided.h64,
    };
    let local = Side::new([shared.clone(), local_extra.clone()].concat());
    let remote = Side::new([shared, remote_extra.clone(), vec![twin]].concat());

    let (action, exchange) = run_verified(&local, &remote);
    let ClientAction::ResolveRoots {
        roots,
        ladder_failed,
    } = action
    else {
        panic!("expected a partial resolve, got {action:?}");
    };
    assert_eq!(ladder_failed.len(), 1);
    assert!(in_node(collided.h64, ladder_failed[0]));

    // Every honest root outside the failed prefix was resolved.
    let honest: Vec<u64> = local_extra
        .iter()
        .chain(&remote_extra)
        .map(|e| e.h64)
        .filter(|&h| !in_node(h, ladder_failed[0]))
        .collect();
    assert!(!honest.is_empty(), "siblings must hold honest roots");
    for root in &honest {
        assert!(roots.contains(root), "sibling root {root:#x} lost");
    }
    assert!(roots.iter().all(|&r| !in_node(r, ladder_failed[0])));
    assert!(!exchange.classified().is_empty());
}

/// Whether `h64` falls in the node `(depth, prefix)`.
fn in_node(h64: u64, (depth, prefix): (u8, u64)) -> bool {
    depth == 0 || h64.checked_shr(64_u32.saturating_sub(u32::from(depth))) == Some(prefix)
}

/// The opposite-sides collision: X is held only locally, Y only remotely, and
/// they share an `h64` (mocked). The pair cancels in the sketch, the counts
/// balance, and an honest remote-only element in the same node keeps the early
/// residual check from running, so phase 1 admits the node. Only phase 2 can
/// catch it -- after the exchange has ended with `ResolveRoots` -- and that
/// failure is the caller's per-prefix fallback, not something the exchange can
/// split or retry. Every other node still verifies.
#[test]
fn split_pair_collision_is_admitted_by_phase_one_and_caught_by_phase_two() {
    let mut generator = Xorshift128::new(13);
    let shared: Vec<ElementHash> = (0..200).map(|_| generator.hash()).collect();
    // Enough honest differences to force several buckets, so siblings exist.
    let local_extra: Vec<ElementHash> = (0..22).map(|_| generator.hash()).collect();
    let mut remote_extra: Vec<ElementHash> = (0..22).map(|_| generator.hash()).collect();

    let x = generator.hash();
    let y = ElementHash {
        h128: x.h128 ^ 0xfeed_face,
        h64: x.h64,
    };
    // An honest remote-only element in the same node as the colliding pair.
    let z = ElementHash {
        h128: generator.hash().h128,
        h64: x.h64 ^ 1,
    };
    remote_extra.push(z);

    let local = Side::new([shared.clone(), local_extra, vec![x]].concat());
    let remote = Side::new([shared, remote_extra.clone(), vec![y]].concat());

    let (action, exchange) = run_verified(&local, &remote);
    let ClientAction::ResolveRoots { roots, .. } = action else {
        panic!("phase 1 must admit the split pair, got {action:?}");
    };
    assert!(
        !roots.contains(&x.h64),
        "the pair cancelled, so no root may carry its h64"
    );
    assert!(exchange.classified().len() > 1, "need sibling nodes");

    let mut rejected = Vec::new();
    for classified in exchange.classified() {
        let (depth, prefix) = classified.node();
        let request = BucketRequest::new(depth, prefix, 8);
        let returned: Vec<[u8; 32]> = remote_extra
            .iter()
            .filter(|e| classified.m_roots().contains(&e.h64))
            .map(|e| digest_of(*e))
            .collect();
        if verify_follow_up(classified, &request, &returned).is_err() {
            rejected.push(classified.node());
        }
    }
    assert_eq!(
        rejected.len(),
        1,
        "only the colliding node may fail phase 2"
    );
    assert!(in_node(x.h64, rejected[0]));
}
