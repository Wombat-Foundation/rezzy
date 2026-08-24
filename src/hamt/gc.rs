//! Incremental, refcount-based garbage collection bookkeeping for
//! content-addressed HAMT storage.
//!
//! This is the replacement for a periodic full-universe reachability sweep
//! (see [`super::audit`]): instead of re-deriving "what's live" from scratch
//! on every audit, [`RefcountTable`] is fed directly from the
//! [`NodeHashDelta`](super::delta::NodeHashDelta) each mutation already
//! produces, and does `O(|delta|)` work per state transition rather than
//! `O(|universe|)` per sweep.
//!
//! # Why this replaces periodic sweeping, not just supplements it
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

use alloc::vec::Vec;
use core::fmt;

use crate::HashMap;

use super::StructuralHash;

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

#[cfg(feature = "std")]
impl std::error::Error for RefcountUnderflow {}

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
        for (&hash, &need) in &requested {
            let have = self.counts.get(&hash).copied().unwrap_or(0);
            if have < need {
                return Err(RefcountUnderflow { hash });
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
