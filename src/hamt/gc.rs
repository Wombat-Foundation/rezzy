//! Incremental, refcount-based garbage collection bookkeeping for
//! content-addressed HAMT storage.
//!
//! This is an experimental alternative to a periodic full-universe
//! reachability sweep (see [`super::audit`]) for integrations that can prove
//! every retired root has exactly one live successor. It is not sound for
//! general branching state-group lifetimes; normal callers should use a
//! reachability sweep or retain nodes until explicit room purge.
//!
//! Under that strict-linear precondition, [`RefcountTable`] is fed directly
//! from the [`NodeHashDelta`](super::delta::NodeHashDelta) each mutation
//! already produces, and does `O(|delta|)` work per state transition rather
//! than `O(|universe|)` per sweep.
//!
//! Prefer [`LinearRootChain`] over raw `RefcountTable` — it enforces the
//! linear-root lifecycle at the API level and catches ordering mistakes
//! (wrong call order, missing decrement, double decrement) at runtime.
//!
//! # Why it can avoid periodic sweeping on a linear history
//!
//! A batch sweep run on a fixed wall-clock cadence while the universe keeps
//! growing accumulates *quadratic* total cost over the system's lifetime:
//! with audits every period `P` and growth rate `r`, the `k`-th audit costs
//! `O(r·k·P)`, and summing that over `m = T/P` audits by elapsed time `T`
//! gives `Θ(n²)` in the eventual size `n = r·T` — not `O(n)` per call as a
//! "cheaper index" framing might suggest. This is true regardless of which
//! structure backs a periodic audit (exact `HashSet`, `RoaringBitmap`, a
//! probabilistic filter); the problem is the fixed-cadence-while-growing
//! architecture, not the index type. A `RefcountTable` sidesteps this
//! entirely by never re-deriving anything: each transition's cost is bounded
//! by the size of *that transition's* delta (typically `O(log32 N)`, the
//! spine [`diff_node_hashes`](super::delta::diff_node_hashes) touches for an
//! adjacent-root diff), independent of how large the universe has grown or
//! how long the system has been running.
//!
//! # Timing contract (matches `diff_node_hashes`'s doc exactly)
//!
//! - [`RefcountTable::apply_new`] for `new_node_hashes` — safe to call
//!   immediately once the new root is persisted.
//! - [`RefcountTable::apply_superseded`] for `superseded_node_hashes` —
//!   call only once the *old* root is actually retired, never in the same
//!   batch as the matching `apply_new` for the same transition. The old
//!   root is typically still a live, independently-referenced root at
//!   persist time (that's the entire reason path copying returns a new root
//!   instead of mutating in place).
//! - [`RefcountTable::bootstrap`] seeds absolute counts from a one-time full
//!   reachability walk (see [`reachable_node_hashes`](super::delta::reachable_node_hashes))
//!   over every currently-live root. Needed once, when a store already has
//!   content before this table starts tracking it — the table only ever
//!   sees *deltas* otherwise, never absolute state.
//!
//! # Branching hazard (matches `diff_node_hashes`'s doc exactly)
//!
//! `apply_superseded` is only safe as the *sole* source of decrements when
//! the delta's `root_b` was `root_a`'s **one and only** live successor. If
//! `root_a` has more than one live descendant at retirement time (a forked
//! resolution branch, an unconverged forward-extremity), decrementing on a
//! single pairwise diff's basis can zero out and delete data a different
//! still-live descendant needs. This module cannot detect that case; it's
//! the caller's responsibility to only retire a root through this path when
//! retirement is a strict linear chain.
//!
//! A full structural fix would add per-root reference tracking to
//! `RefcountTable`. This would require:
//! 1. Adding a `root_reach: HashMap<StructuralHash, Vec<StructuralHash>>` field
//! 2. Modifying `bootstrap`, `apply_new`, and `apply_superseded` to track which
//!    hashes belong to which root
//! 3. In `apply_superseded`, checking that no other live root references a node
//!    before reporting it as zeroed
//!
//! That's a real refcounting redesign, out of scope here. Short of it,
//! [`RefcountTable::debug_assert_zeroed_not_reachable_elsewhere`] gives
//! callers a cheap way to *catch* a violation in tests/debug builds: hand it
//! the hashes [`apply_superseded`](RefcountTable::apply_superseded) just
//! reported as zeroed, plus a reachability set walked from every other
//! currently-live root, and it asserts the two don't intersect. It is
//! `debug_assert!`-gated (a no-op in release builds) because computing that
//! reachability set is an `O(|universe|)` walk — exactly the per-call cost
//! this module exists to avoid paying in production; it's affordable only
//! as a debug/test-time correctness check, not on the hot path.

use alloc::vec::Vec;
use core::fmt;

use crate::{HashMap, HashSet};

use super::StructuralHash;

/// A wrapper around [`RefcountTable`] that enforces the linear-root lifecycle
/// at the API level.
///
/// This prevents the most common misuse patterns:
/// - Calling `apply_new` and `apply_superseded` in the wrong order
/// - Forgetting to decrement the old root
/// - Double-decrementing the same transition
///
/// The caller still holds the invariant that no branching occurs (multiple
/// live roots), but the wrapper makes the *protocol* explicit and catches
/// ordering mistakes at runtime.
///
/// # Example
/// ```ignore
/// let mut chain = LinearRootChain::bootstrap(
///     reachable_hashes,
///     root_a_hash,
/// );
/// // When root_b supersedes root_a:
/// let zeroed = chain.advance(&delta_b, root_b_hash)?;
/// // `zeroed` contains hashes safe to delete (subject to branching check).
/// ```
#[derive(Debug, Clone)]
pub struct LinearRootChain {
    table: RefcountTable,
    /// The currently live root's hash. `None` before bootstrap.
    current_root: Option<StructuralHash>,
    /// Hashes from the previous root that need decrementing.
    /// `Some(vec![])` means "previous root existed but had no superseded hashes."
    /// `None` means "no pending retirement."
    pending_retirement: Option<Vec<StructuralHash>>,
}

impl LinearRootChain {
    /// Seeds from a full reachability walk and sets the initial live root.
    ///
    /// `hashes` should be the raw output of `reachable_node_hashes` or
    /// `walk_reachable_node_hashes` over the current live root — **not**
    /// deduplicated, so shared subtrees are counted once per root.
    #[must_use]
    pub fn bootstrap(
        hashes: impl IntoIterator<Item = StructuralHash>,
        current_root: StructuralHash,
    ) -> Self {
        let mut table = RefcountTable::new();
        table.bootstrap(hashes);
        Self {
            table,
            current_root: Some(current_root),
            pending_retirement: None,
        }
    }

    /// Transitions to a new root: increments for `delta.new_node_hashes`
    /// and queues the old root's superseded hashes for retirement.
    ///
    /// `new_root` is the structural hash of the replacement root; it becomes
    /// the tracked live root after this call.
    ///
    /// Returns `Ok(())` on success. The previous root's superseded hashes
    /// are now pending — call [`retire_previous`](Self::retire_previous)
    /// when the old root is actually retired, or use [`advance`](Self::advance)
    /// for the common one-step case.
    ///
    /// # Errors
    /// Returns [`RefcountUnderflow`] if `new_node_hashes` contains a hash
    /// whose count cannot absorb the increment (should not happen for
    /// well-formed deltas).
    ///
    /// # Panics
    /// Panics if a retirement is already pending from a prior `transition`
    /// (caller must complete it via `retire_previous` first).
    pub fn transition(
        &mut self,
        delta: &super::NodeHashDelta,
        new_root: StructuralHash,
    ) -> Result<(), RefcountUnderflow> {
        assert!(
            self.pending_retirement.is_none(),
            "transition called while a retirement is pending; call retire_previous first"
        );
        // Increment new hashes immediately.
        self.table.apply_new(&delta.new_node_hashes);
        // Queue old root's superseded hashes for later decrement.
        self.pending_retirement = Some(delta.superseded_node_hashes.clone());
        self.current_root = Some(new_root);
        Ok(())
    }

    /// Retires the previous root: decrements its superseded hashes.
    ///
    /// Must be called after [`transition`](Self::transition) once the old
    /// root is actually retired (not in the same batch as `transition`).
    ///
    /// # Errors
    /// Returns [`RefcountUnderflow`] if the decrement would go below zero —
    /// a caller bookkeeping bug (missing prior increment, double decrement,
    /// or wrong call order).
    ///
    /// # Panics
    /// Panics if no retirement is pending (i.e. `transition` was not called,
    /// or `retire_previous` was already called for this transition).
    pub fn retire_previous(&mut self) -> Result<Vec<StructuralHash>, RefcountUnderflow> {
        let pending = self
            .pending_retirement
            .take()
            .expect("retire_previous called without a pending transition; call transition first");
        self.table.apply_superseded(&pending)
    }

    /// One-step transition: increment new, decrement old, return zeroed hashes.
    ///
    /// This is the common case when the old root is retired immediately.
    /// If you need to delay retirement (old root still live), use
    /// [`transition`](Self::transition) + [`retire_previous`](Self::retire_previous).
    ///
    /// # Errors
    /// Returns [`RefcountUnderflow`] on decrement failure.
    ///
    /// # Panics
    /// Panics if a retirement is already pending from a prior `transition`
    /// (caller must complete it via `retire_previous` first).
    pub fn advance(
        &mut self,
        delta: &super::NodeHashDelta,
        new_root: StructuralHash,
    ) -> Result<Vec<StructuralHash>, RefcountUnderflow> {
        assert!(
            self.pending_retirement.is_none(),
            "advance called while a retirement is pending; call retire_previous first"
        );
        self.table.apply_new(&delta.new_node_hashes);
        let zeroed = self.table.apply_superseded(&delta.superseded_node_hashes)?;
        self.current_root = Some(new_root);
        Ok(zeroed)
    }

    /// Returns the current live root hash, if bootstrapped.
    #[must_use]
    pub fn current_root(&self) -> Option<StructuralHash> {
        self.current_root
    }

    /// Returns true if a retirement is pending (between `transition` and
    /// `retire_previous`).
    #[must_use]
    pub fn has_pending_retirement(&self) -> bool {
        self.pending_retirement.is_some()
    }

    /// Debug-only branching check. Same semantics as
    /// [`RefcountTable::debug_assert_zeroed_not_reachable_elsewhere`]
    /// but uses the tracked `current_root` for context.
    pub fn debug_assert_no_branching(
        &self,
        zeroed: &[StructuralHash],
        other_live_roots_reachable: &HashSet<StructuralHash>,
    ) {
        RefcountTable::debug_assert_zeroed_not_reachable_elsewhere(
            zeroed,
            other_live_roots_reachable,
        );
    }

    /// Delegates to the underlying table's count.
    #[must_use]
    pub fn count(&self, hash: &StructuralHash) -> u64 {
        self.table.count(hash)
    }

    /// The number of distinct hashes with a nonzero tracked count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// True if no hash has a nonzero tracked count.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

/// Tracks a live reference count per HAMT node hash, incrementally.
///
/// Never performs a full-universe scan — every operation's cost is
/// proportional to the number of hashes passed to it, not to the table's
/// total size. See the module docs for the full timing contract.
#[derive(Debug, Clone, Default)]
pub struct RefcountTable {
    counts: HashMap<StructuralHash, u64>,
}

/// [`RefcountTable::apply_superseded`] was asked to decrement a hash whose
/// count was already zero (or never tracked).
///
/// This is a caller bookkeeping bug, not a GC signal: it means a decrement
/// was applied without a matching prior increment, applied twice, or applied
/// before its matching `apply_new` landed. It is deliberately *not* treated
/// as "already garbage, ignore it" — that would silently mask exactly the
/// ordering bugs the timing contract above exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefcountUnderflow {
    /// The hash whose count would have gone negative.
    pub hash: StructuralHash,
}

impl fmt::Display for RefcountUnderflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refcount underflow: decremented a hash with no tracked positive count \
             (missing or out-of-order apply_new, or a double decrement)"
        )
    }
}

impl core::error::Error for RefcountUnderflow {}

impl RefcountTable {
    /// An empty table, tracking nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeds absolute counts from a one-time full reachability walk over
    /// every currently-live root (see
    /// [`reachable_node_hashes`](super::delta::reachable_node_hashes)).
    ///
    /// This is the one place this module does `O(|universe|)` work — and
    /// only once, at bootstrap time for a store that already has content.
    /// A hash reachable from `k` live roots is counted `k` times if it
    /// appears `k` times in `hashes` (i.e. the caller walks each root and
    /// chains the results); passing a deduplicated set instead would
    /// under-count shared subtrees and cause a premature GC candidate later.
    pub fn bootstrap(&mut self, hashes: impl IntoIterator<Item = StructuralHash>) {
        for hash in hashes {
            let count = self.counts.entry(hash).or_insert(0);
            *count = count.saturating_add(1);
        }
    }

    /// Increments refcounts for `new_node_hashes` from a
    /// [`NodeHashDelta`](super::delta::NodeHashDelta). Safe to call as soon
    /// as the new root is persisted.
    pub fn apply_new(&mut self, hashes: &[StructuralHash]) {
        for &hash in hashes {
            let count = self.counts.entry(hash).or_insert(0);
            *count = count.saturating_add(1);
        }
    }

    /// Decrements refcounts for `superseded_node_hashes` from a
    /// [`NodeHashDelta`](super::delta::NodeHashDelta), once the old root is
    /// actually retired. Returns the hashes that reached zero as a result —
    /// the actual GC candidates, safe to delete (subject to the branching
    /// hazard in the module docs).
    ///
    /// Applies atomically: either every hash in `hashes` is decremented, or
    /// (on [`RefcountUnderflow`]) none of them are. `hashes` may repeat a
    /// value; repeats are treated as that many decrements, not one.
    ///
    /// # Errors
    /// Returns [`RefcountUnderflow`] naming the first hash (in `hashes`
    /// order) whose count could not absorb the requested decrements. See
    /// [`RefcountUnderflow`]'s docs for what this means and why it isn't
    /// silently tolerated.
    pub fn apply_superseded(
        &mut self,
        hashes: &[StructuralHash],
    ) -> Result<Vec<StructuralHash>, RefcountUnderflow> {
        // Two passes for atomicity: tally how many decrements each distinct
        // hash needs (hashes may repeat), validate every one is affordable
        // against the current count, and only then mutate. A batch is
        // bounded by one transition's delta size, so the extra pass is cheap.
        let mut requested: HashMap<StructuralHash, u64> = HashMap::new();
        for &hash in hashes {
            let count = requested.entry(hash).or_insert(0);
            *count = count.saturating_add(1);
        }
        // Validate in `hashes` order (not the unordered `requested` map's
        // iteration order) so the reported underflow names the first failing
        // distinct hash as documented. Each distinct hash is checked once;
        // `validated` dedups repeats of the same hash across `hashes`.
        let mut validated: HashSet<StructuralHash> = HashSet::default();
        for &hash in hashes {
            if !validated.insert(hash) {
                continue;
            }
            // Every hash in `hashes` was tallied into `requested` above, so
            // this lookup always hits; `if let` keeps it panic-free.
            if let Some(&need) = requested.get(&hash) {
                let have = self.counts.get(&hash).copied().unwrap_or(0);
                if have < need {
                    return Err(RefcountUnderflow { hash });
                }
            }
        }

        let mut zeroed = Vec::new();
        for &hash in hashes {
            // Entry is guaranteed present and >= 1 by the validation pass
            // above; `unwrap_or` here is defensive, not load-bearing.
            let remaining = self.counts.get_mut(&hash).map_or(0, |count| {
                *count = count.saturating_sub(1);
                *count
            });
            if remaining == 0 {
                self.counts.remove(&hash);
                zeroed.push(hash);
            }
        }
        Ok(zeroed)
    }

    /// Debug/test-only hazard check for the branching case documented in the
    /// module docs: asserts that none of `zeroed` (the hashes
    /// [`apply_superseded`](Self::apply_superseded) just reported as
    /// reclaimable) is also reachable from `other_live_roots_reachable` —
    /// the set of hashes reachable from every *other* currently-live root
    /// (typically via [`reachable_node_hashes`](super::delta::reachable_node_hashes)),
    /// i.e. every root besides the one whose retirement produced `zeroed`.
    ///
    /// A no-op in release builds (`debug_assert!`, not `assert!`): building
    /// `other_live_roots_reachable` is an `O(|universe|)` walk per call,
    /// which is exactly the cost this module's incremental design exists to
    /// avoid paying on the hot path. Call this from tests, and optionally
    /// from debug-build integration code, right after a call to
    /// `apply_superseded` whose safety you want double-checked.
    ///
    /// # Panics
    /// In debug builds, panics if any hash in `zeroed` is also present in
    /// `other_live_roots_reachable` — i.e. `apply_superseded` would have
    /// reclaimed a node a different live root still needs.
    pub fn debug_assert_zeroed_not_reachable_elsewhere(
        zeroed: &[StructuralHash],
        other_live_roots_reachable: &HashSet<StructuralHash>,
    ) {
        for hash in zeroed {
            debug_assert!(
                !other_live_roots_reachable.contains(hash),
                "GC branching hazard: {hash:?} was reported zeroed by \
                 apply_superseded but is still reachable from another \
                 live root -- see the module docs' \"Branching hazard\" \
                 section"
            );
        }
    }

    /// The current tracked count for `hash` (0 if untracked).
    #[must_use]
    pub fn count(&self, hash: &StructuralHash) -> u64 {
        self.counts.get(hash).copied().unwrap_or(0)
    }

    /// The number of distinct hashes with a nonzero tracked count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// True if no hash has a nonzero tracked count.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::super::delta::NodeHashDelta;
    use super::*;
    use alloc::vec;

    fn h(byte: u8) -> StructuralHash {
        [byte; 32]
    }

    fn delta(new: &[u8], superseded: &[u8]) -> NodeHashDelta {
        NodeHashDelta {
            new_node_hashes: new.iter().map(|&b| h(b)).collect(),
            superseded_node_hashes: superseded.iter().map(|&b| h(b)).collect(),
        }
    }

    #[test]
    fn bootstrap_sets_current_root() {
        let chain = LinearRootChain::bootstrap(vec![h(1), h(2)], h(0));
        assert_eq!(chain.current_root(), Some(h(0)));
        assert!(!chain.has_pending_retirement());
        assert_eq!(chain.count(&h(1)), 1);
        assert_eq!(chain.count(&h(2)), 1);
    }

    #[test]
    fn advance_one_step() {
        let mut chain = LinearRootChain::bootstrap(vec![h(1)], h(0));
        // Root A has hash 1. Transition to root B: new=2, superseded=1.
        let d = delta(&[2], &[1]);
        let zeroed = chain.advance(&d, h(10)).unwrap();
        assert_eq!(chain.current_root(), Some(h(10)));
        assert!(!chain.has_pending_retirement());
        assert_eq!(chain.count(&h(1)), 0);
        assert_eq!(chain.count(&h(2)), 1);
        assert!(zeroed.contains(&h(1)));
    }

    #[test]
    fn transition_then_retire_previous() {
        let mut chain = LinearRootChain::bootstrap(vec![h(1)], h(0));
        let d = delta(&[2], &[1]);
        chain.transition(&d, h(10)).unwrap();
        assert_eq!(chain.current_root(), Some(h(10)));
        assert!(chain.has_pending_retirement());

        let zeroed = chain.retire_previous().unwrap();
        assert!(!chain.has_pending_retirement());
        assert_eq!(chain.count(&h(1)), 0);
        assert_eq!(chain.count(&h(2)), 1);
        assert!(zeroed.contains(&h(1)));
    }

    #[test]
    #[should_panic(expected = "retirement is pending")]
    fn second_transition_rejected_while_pending() {
        let mut chain = LinearRootChain::bootstrap(vec![h(1)], h(0));
        let d1 = delta(&[2], &[1]);
        chain.transition(&d1, h(10)).unwrap();
        // Second transition without retiring the first should panic.
        let d2 = delta(&[3], &[2]);
        chain.transition(&d2, h(20)).unwrap();
    }

    #[test]
    #[should_panic(expected = "retirement is pending")]
    fn advance_rejected_while_pending() {
        let mut chain = LinearRootChain::bootstrap(vec![h(1)], h(0));
        let d1 = delta(&[2], &[1]);
        chain.transition(&d1, h(10)).unwrap();
        // advance after transition (without retire_previous) should panic.
        let d2 = delta(&[3], &[2]);
        chain.advance(&d2, h(20)).unwrap();
    }

    #[test]
    #[should_panic(expected = "retire_previous called without a pending transition")]
    fn retire_previous_without_transition_panics() {
        let mut chain = LinearRootChain::bootstrap(vec![h(1)], h(0));
        let _ = chain.retire_previous();
    }

    #[test]
    fn chain_of_advances() {
        let mut chain = LinearRootChain::bootstrap(vec![h(1)], h(0));
        // A -> B
        let zeroed = chain.advance(&delta(&[2], &[1]), h(10)).unwrap();
        assert!(zeroed.contains(&h(1)));
        // B -> C
        let zeroed = chain.advance(&delta(&[3], &[2]), h(20)).unwrap();
        assert!(zeroed.contains(&h(2)));
        // C -> D
        let zeroed = chain.advance(&delta(&[4], &[3]), h(30)).unwrap();
        assert!(zeroed.contains(&h(3)));
        assert_eq!(chain.current_root(), Some(h(30)));
        assert_eq!(chain.count(&h(4)), 1);
    }

    #[test]
    fn shared_hashes_across_steps() {
        let mut chain = LinearRootChain::bootstrap(vec![h(1), h(5)], h(0));
        // A -> B: new={2,5}, superseded={1}
        let zeroed = chain.advance(&delta(&[2, 5], &[1]), h(10)).unwrap();
        assert!(zeroed.contains(&h(1)));
        // Hash 5 was in A (count=1) and incremented by A->B delta (count=2).
        // Only h(1) was superseded; h(5) was not, so its count stays at 2.
        assert_eq!(chain.count(&h(5)), 2);
        // B -> C: new={3}, superseded={2,5}
        // h(5) goes 2->1, not zeroed; h(2) goes 1->0, zeroed.
        let zeroed = chain.advance(&delta(&[3], &[2, 5]), h(20)).unwrap();
        assert!(zeroed.contains(&h(2)));
        assert!(!zeroed.contains(&h(5)));
        assert_eq!(chain.count(&h(5)), 1);
    }
}
