// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Incremental state computation — room state at arbitrary DAG positions.
//!
//! This module computes the resolved room state *after* any given event in the
//! DAG, without requiring external state snapshots. It walks the `prev_events`
//! graph backwards, builds the state at each ancestor, and merges fork points.
//!
//! Key optimizations:
//!
//! - `O(1)` structural sharing: persistent state is represented via
//!   [`imbl::OrdMap`](`SharedState`). Fork branches are created and merged
//!   incrementally with zero allocations for identical shared subtrees.
//! - **Batch mode:** computes state at multiple targets in a single topological
//!   pass, amortizing the graph traversal cost.

use crate::basespec::event_types::EventType;
use crate::basespec::rezzy_types::{LeanEvent, StateResVersion};
use crate::{FastMap, HashMap};
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// An entry in the local auth cache, pairing an event with its discovery depth.
///
/// The `depth` field tracks how many hops through `auth_events` it took to
/// reach this event. When the same `(type, state_key)` is found at multiple
/// depths, the shallowest (closest) entry wins.
#[derive(Debug, Clone)]
pub struct LocalAuthEntry<Id, C = serde_json::Value, K = String> {
    /// The auth event itself.
    pub event: LeanEvent<Id, C, K>,
    /// Number of auth-chain hops from the original event to this one.
    pub auth_depth: usize,
}

/// Inner type for the local auth cache to satisfy clippy's `type_complexity` lint.
pub type LocalAuthCacheMap<Id, C, K> = BTreeMap<(EventType, K), LocalAuthEntry<Id, C, K>>;

/// Memoization cache for local auth context computation.
///
/// Maps `event_id -> BTreeMap<(type, state_key) -> LocalAuthEntry>`, allowing
/// the local auth context to be computed once and reused for all events that
/// share auth chain prefixes.
///
/// This cache tracks which `StateResVersion` its entries were computed for.
/// Callers must clear the cache when reusing it with a different `StateResVersion`
/// (higher-level helpers like `resolve_iterative_sort_with_cache*` do this automatically).
pub struct LocalAuthCache<Id = String, C = serde_json::Value, K = String> {
    pub version: StateResVersion,
    pub map: crate::HashMap<Id, LocalAuthCacheMap<Id, C, K>>,
}

impl<Id, C, K> LocalAuthCache<Id, C, K> {
    /// Create a new local auth cache for the specified room version.
    #[must_use]
    pub fn new(version: StateResVersion) -> Self {
        Self {
            version,
            map: crate::HashMap::default(),
        }
    }
}

pub(crate) struct OverlayState<'a, Id, C, S1, S2, K = String> {
    pub(crate) resolved: &'a crate::state::at::SharedState<Id, K>,
    pub(crate) auth_context: &'a HashMap<Id, LeanEvent<Id, C, K>, S1>,
    pub(crate) sort_set: &'a HashMap<Id, LeanEvent<Id, C, K>, S2>,
    pub(crate) local_auth: BTreeMap<(EventType, K), LeanEvent<Id, C, K>>,
    pub(crate) create_ev: Option<&'a LeanEvent<Id, C, K>>,
    pub(crate) version: StateResVersion,
    pub(crate) is_power_phase: bool,
    pub(crate) candidate_event_type: &'a str,
}

impl<
        Id: crate::basespec::rezzy_types::EventId,
        C: crate::basespec::rezzy_types::EventContent,
        S1: core::hash::BuildHasher,
        S2: core::hash::BuildHasher,
        K,
    > crate::auth::StateProvider<Id, C, LeanEvent<Id, C, K>> for OverlayState<'_, Id, C, S1, S2, K>
where
    K: Ord + Clone + Default + AsRef<str> + 'static,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    /// Returns the resolved event or a limited local-auth fallback for the query.
    fn get_event(&self, event_type: &str, state_key: &str) -> Option<&LeanEvent<Id, C, K>> {
        use crate::basespec::event_types::{M_ROOM_MEMBER, M_ROOM_POWER_LEVELS};

        let query: &dyn crate::auth::StateKeyDyn = &(event_type, state_key);

        // V2.1+ (MSC4297): required auth keys come from the (resolved) state in
        // ALL phases — power phase included. The prior PL-only power-phase
        // restriction and the V2.1.1 ban/kick-only member supplement were both
        // non-spec "causal-domination" scaffolding; a banned sender's later
        // power event must be rejected against the resolved ban.

        // Check consensus resolved state
        let resolved_ev = self.resolved.get(query).and_then(|eid| {
            self.auth_context
                .get(eid)
                .or_else(|| self.sort_set.get(eid))
        });

        if let Some(ev) = resolved_ev {
            return Some(ev);
        }

        if let Some(ev) = self.local_auth.get(query) {
            // Under Matrix State Resolution, during the power phase, a required auth event in the conflicted set
            // can ONLY be used if it has been successfully authorized and resolved
            // (i.e. is present in the resolved state).
            let is_required_type = event_type == M_ROOM_POWER_LEVELS
                || event_type == crate::basespec::event_types::M_ROOM_JOIN_RULES;

            // Gate the power-phase fallback behind V2.1+ (MSC4297) so it
            // behaves consistently across V2.1 and V2.1.1: in the power
            // phase, a required auth key in the conflicted set is only used
            // via the local-auth fallback under the narrow conditions below,
            // rather than being trusted unconditionally.
            let is_v2_1_plus = self.version.is_v2_1_plus();

            if self.is_power_phase
                && is_v2_1_plus
                && is_required_type
                && self.sort_set.contains_key(&ev.event_id)
            {
                if let Some(resolved_id) = self.resolved.get(query) {
                    if let Some(resolved_ev) = self
                        .auth_context
                        .get(resolved_id)
                        .or_else(|| self.sort_set.get(resolved_id))
                    {
                        return Some(resolved_ev);
                    }
                    None
                } else {
                    // Under V2.1+, during the power phase, we fall back to the local auth event
                    // if NO event of this type has been resolved yet, BUT only if we are currently
                    // resolving a power/required event itself. This prevents non-power events from
                    // bypass-authorizing against unresolved/conflicted power events.
                    // Type-level approximation: a plain join isn't a power event in the spec's
                    // sense, but only power-phase candidates reach this branch, so the
                    // content-level ban/kick distinction is unnecessary here.
                    let candidate_is_power = self.candidate_event_type == M_ROOM_POWER_LEVELS
                        || self.candidate_event_type
                            == crate::basespec::event_types::M_ROOM_JOIN_RULES
                        || self.candidate_event_type == M_ROOM_MEMBER;
                    if candidate_is_power {
                        Some(ev)
                    } else {
                        None
                    }
                }
            } else {
                Some(ev)
            }
        } else {
            // Fallback for create
            if event_type == crate::basespec::event_types::M_ROOM_CREATE
                && state_key == crate::basespec::event_types::M_EMPTY_STATE_KEY
            {
                return self.create_ev;
            }
            None
        }
    }
}

/// Evaluates whether an event passes authentication checks given a resolved state map,
/// delegating to the core `crate::auth::check_auth` logic via a temporary `OverlayState` view.
///
/// NOTE: In V2.1/MSC4297, progressive state starts empty. The first event's sender membership
/// check must use its own `auth_events` (via `local_auth` / `OverlayState` fallback), not the
/// empty state. This is critical for competing bans where both senders need membership validation.
#[allow(clippy::too_many_arguments)]
/// Authenticates an event against the current resolved state and an optional local auth context.
/// Ensures the event complies with the Matrix spec rules for its given type.
pub(crate) fn iterative_auth_ok<Id, C, S1, S2, K>(
    ev: &LeanEvent<Id, C, K>,
    resolved: &crate::state::at::SharedState<Id, K>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    sort_set: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
    local_auth: BTreeMap<(EventType, K), LeanEvent<Id, C, K>>,
    cached_create: Option<&LeanEvent<Id, C, K>>,
    version: StateResVersion,
    is_power_phase: bool,
) -> bool
where
    Id: crate::basespec::rezzy_types::EventId,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    if ev.rejected || ev.soft_fail {
        return false;
    }

    let overlay = OverlayState {
        resolved,
        auth_context,
        sort_set,
        local_auth,
        create_ev: cached_create,
        version,
        is_power_phase,
        candidate_event_type: &ev.event_type,
    };

    crate::auth::check_auth(ev, &overlay, version, None).is_ok()
}

/// Merges an event into a local auth map if it is an auth event (e.g. power levels, join rules).
/// Ensures that newer auth events replace older ones during chain traversal.
pub(crate) fn update_local_auth<Id: Clone + Ord, C: Clone, K: Clone + Ord>(
    local_auth: &mut BTreeMap<(EventType, K), LocalAuthEntry<Id, C, K>>,
    aev: &LeanEvent<Id, C, K>,
    depth: usize,
) {
    let Some(sk) = &aev.state_key else {
        return;
    };
    let key = (EventType::from(aev.event_type.as_str()), sk.clone());
    match local_auth.entry(key) {
        alloc::collections::btree_map::Entry::Vacant(e) => {
            e.insert(LocalAuthEntry {
                event: aev.clone(),
                auth_depth: depth,
            });
        }
        alloc::collections::btree_map::Entry::Occupied(mut e) => {
            if depth < e.get().auth_depth {
                e.insert(LocalAuthEntry {
                    event: aev.clone(),
                    auth_depth: depth,
                });
            }
        }
    }
}

/// Resolves the auth chain context incrementally and stores it in the shared cache.
pub(crate) fn compute_local_auth<Id, C, S1, S2, K>(
    event: &LeanEvent<Id, C, K>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
    cache: &mut LocalAuthCache<Id, C, K>,
    version: StateResVersion,
) -> BTreeMap<(EventType, K), LeanEvent<Id, C, K>>
where
    Id: crate::basespec::rezzy_types::EventId,
    C: Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    K: Clone + Ord,
{
    if let Some(cached) = cache.map.get(&event.event_id) {
        return cached
            .clone()
            .into_iter()
            .map(|(k, entry)| (k, entry.event))
            .collect();
    }

    let mut local_auth: BTreeMap<(EventType, K), LocalAuthEntry<Id, C, K>> = BTreeMap::new();
    let mut queue = alloc::collections::VecDeque::new();
    for aid in &event.auth_events {
        queue.push_back((aid.clone(), 1));
    }
    let mut visited = BTreeSet::new();

    while let Some((aid, current_depth)) = queue.pop_front() {
        if !visited.insert(aid.clone()) {
            continue;
        }

        if let Some(cached_ancestor) = cache.map.get(&aid) {
            // The cache only contains the parents of `aid`. We must also insert `aid` itself!
            if let Some(aev) = auth_context
                .get(&aid)
                .or_else(|| conflicted_events.get(&aid))
            {
                update_local_auth(&mut local_auth, aev, current_depth);
            }

            // NOTE: V2.1.1 (Proposed) replaces unbounded DFS with a pure memoized BFS traversal.
            // Therefore, both V2.1.1 and V2.2 natively gather transitive auth context!
            if matches!(version, StateResVersion::V2_1_1 | StateResVersion::V2_2) {
                for (key, entry) in cached_ancestor {
                    let total_depth = current_depth.saturating_add(entry.auth_depth);
                    match local_auth.entry(key.clone()) {
                        alloc::collections::btree_map::Entry::Vacant(e) => {
                            e.insert(LocalAuthEntry {
                                event: entry.event.clone(),
                                auth_depth: total_depth,
                            });
                        }
                        alloc::collections::btree_map::Entry::Occupied(mut e) => {
                            if total_depth < e.get().auth_depth {
                                e.insert(LocalAuthEntry {
                                    event: entry.event.clone(),
                                    auth_depth: total_depth,
                                });
                            }
                        }
                    }
                }
            }
            continue;
        }

        if let Some(aev) = auth_context
            .get(&aid)
            .or_else(|| conflicted_events.get(&aid))
        {
            update_local_auth(&mut local_auth, aev, current_depth);

            // TODO: confirm the V2.2 auth traversal rule remains aligned with V2.1.1.
            // For V2.1 and below, we only check the immediate auth_events.
            if matches!(version, StateResVersion::V2_1_1 | StateResVersion::V2_2) {
                for parent_id in &aev.auth_events {
                    queue.push_back((parent_id.clone(), current_depth.saturating_add(1)));
                }
            }
        }
    }

    cache.map.insert(event.event_id.clone(), local_auth.clone());
    local_auth
        .into_iter()
        .map(|(k, entry)| (k, entry.event))
        .collect()
}

/// An O(1) cloneable, persistent state map. Note that `state_key: ""`
/// is _never_ `null` or `None`.
///
/// The `event_type` half of the key is interned via [`EventType`] so that
/// well-known types use compact enum representations and avoid per-entry
/// type-string allocations in state keys. Equality, ordering, and hashing
/// still follow the canonical string form.
///
/// Generic over the state-key type `K` (defaults to `String`); see
/// [`crate::basespec::rezzy_types::StateKey`].
///
/// A HAMT-backed state map was benchmarked as a replacement
/// (`benches/state_backend.rs`) and lost on the access pattern that
/// matters most here: forking a state map into several branches and
/// diverging each (what conflict resolution does), where it was 6-22x
/// slower than `OrdMap`'s clone. `imbl::OrdMap`'s RRB-tree is tuned
/// specifically for cheap-clone/structural-sharing workloads, so it stays.
pub type SharedState<Id = String, K = String> = imbl::OrdMap<(EventType, K), Id>;

/// Computes the resolved room state *after* a given event.
///
/// This walks the `prev_events` graph backwards from `target_event_id`,
/// topologically sorts all reachable ancestors, and incrementally builds
/// the state by applying each state event in order. Fork points are resolved
/// via [`crate::resolve::iterative::resolve_iterative_sort`] with the given `version` semantics.
///
/// Returns `None` if `target_event_id` is not found in `events_map`.
///
/// # Panics
///
/// Will panic if graph invariants are violated (specifically, if an ancestor event
/// present in the reachable subgraph is missing from `events_map` during topological processing).
#[must_use]
pub fn compute_state_at<Id, C, Q, S, K>(
    target_event_id: &Q,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
) -> Option<BTreeMap<(EventType, K), Id>>
where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + Ord + core::hash::Hash,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    if !events_map.contains_key(target_event_id) {
        return None;
    }

    let mut result = None;
    compute_state_at_streaming(&[target_event_id], events_map, version, |_, state| {
        result = Some(state.into_iter().collect());
    });
    result
}

/// Computes the resolved room state at multiple target events in a single pass.
///
/// This is the batch variant of [`compute_state_at`]. It shares the topological
/// sort and ancestor traversal across all targets, which is significantly faster
/// than calling `compute_state_at` in a loop when the targets share ancestors.
/// TODO: once the incremental state pipeline uses `crate::hamt`, this should
/// be able to reuse more structure between forked states.
///
/// Returns a map from each found target event ID to its resolved state.
/// Target IDs not found in `events_map` are silently skipped.
///
/// # Memory and Performance
///
/// This function materializes and returns a complete `BTreeMap` for every
/// target event. For large rooms with many target events, this will cause
/// massive memory spikes and allocation overhead.
///
/// For processing multiple events in production (e.g., full room rebuilds),
/// use [`compute_state_at_streaming`] instead to stream states via a callback
/// and keep memory bounded to the DAG's width.
/// Computes the state of a room at multiple target events concurrently.
///
/// # Panics
///
/// Will panic if graph invariants are violated (specifically, if an ancestor event
/// present in the reachable subgraph is missing from `events_map` during topological processing).
#[must_use]
pub fn compute_state_at_batch<Id, C, Q, S, K>(
    target_event_ids: &[&Q],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
) -> HashMap<Id, BTreeMap<(EventType, K), Id>>
where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let mut results = HashMap::with_capacity(target_event_ids.len());

    compute_state_at_streaming(target_event_ids, events_map, version, |id, state| {
        results.insert(id, state.into_iter().collect());
    });

    results
}

/// Errors that can occur during streaming state computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateComputationError<E> {
    /// The timeline DAG contains a cycle, making topological sorting impossible.
    CycleDetected,
    /// The caller-provided callback returned an error.
    Callback(E),
}

impl<E: core::fmt::Display> core::fmt::Display for StateComputationError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CycleDetected => {
                write!(f, "Cycle detected in DAG. Reachable subgraph is malformed.")
            }
            Self::Callback(e) => write!(f, "Callback error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for StateComputationError<E> {}

/// Same as [`compute_state_at_batch`] but yields each resolved room state
/// to a callback (as soon as it is ready).
///
/// This function is **strictly superior** to [`compute_state_at_batch`] for
/// large-scale state reconstruction (e.g. homeserver full state rebuilds).
/// By passing ownership of the computed state to the callback, callers can
/// immediately compress and store the state (e.g. directly into a `RocksDB`
/// buffer), bounding the peak memory for materialized state maps to the live
/// frontier/DAG width under strict `O(n_reachable_ancestors)` indexing metadata.
/// TODO: pair this with the HAMT-backed state map to reduce clone pressure on
/// large fork-heavy DAGs.
///
/// **NOTE:** Target IDs not found in `events_map` are silently skipped!
///
/// # Panics
///
/// Will panic if graph invariants are violated (specifically, if an ancestor event
/// present in the reachable subgraph is missing from `events_map` during topological processing).
pub fn compute_state_at_streaming<Id, C, Q, S, F, K>(
    target_event_ids: &[&Q],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    mut on_target_resolved: F,
) where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    F: FnMut(Id, SharedState<Id, K>),
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let result = try_compute_state_at_streaming(
        target_event_ids,
        events_map,
        version,
        |id, state| -> Result<(), core::convert::Infallible> {
            on_target_resolved(id, state);
            Ok(())
        },
    );

    match result {
        Ok(()) => {}
        Err(StateComputationError::CycleDetected) => {
            #[cfg(feature = "std")]
            std::eprintln!(
                "rezzy::compute_state_at: Cycle detected! Reachable subgraph is malformed."
            );
        }
        Err(StateComputationError::Callback(infallible)) => match infallible {},
    }
}

/// A fallible variant of [`compute_state_at_streaming`].
///
/// Functions identically to `compute_state_at_streaming`, but threads a `Result` through
/// the callback so that callers can abort early (e.g. on I/O errors during storage).
///
/// # Errors
/// Returns `StateComputationError::CycleDetected` if a cycle is found in the reachable graph.
/// Returns `StateComputationError::Callback(e)` if the callback yields an error.
pub fn try_compute_state_at_streaming<Id, C, Q, S, F, E, K>(
    target_event_ids: &[&Q],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    mut on_target_resolved: F,
) -> Result<(), StateComputationError<E>>
where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    F: FnMut(Id, SharedState<Id, K>) -> Result<(), E>,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let mut actual_target_ids = Vec::new();
    let mut seen = alloc::collections::BTreeSet::new();
    for &tid in target_event_ids {
        if let Some((k, _)) = events_map.get_key_value(tid) {
            if seen.insert(k) {
                actual_target_ids.push(k.clone());
            }
        }
    }

    if actual_target_ids.is_empty() {
        return Ok(());
    }

    let target_refs: Vec<&Id> = actual_target_ids.iter().collect();
    let (id_to_index, index_to_id) = collect_ancestor_short_ids_batch(&target_refs, events_map);

    let mut is_target = alloc::vec![false; index_to_id.len()];
    for tid in &actual_target_ids {
        if let Some(&idx) = id_to_index.get(tid) {
            is_target[idx] = true;
        }
    }

    run_state_pipeline_streaming(
        &index_to_id,
        &id_to_index,
        &is_target,
        events_map,
        version,
        |idx, shared_state| {
            let id = index_to_id[idx].clone();
            on_target_resolved(id, shared_state)
        },
    )
}

/// Core topological graph traversal loop for batch state reconstruction.
///
/// Topologically sorts all reachable ancestors, incrementally merges state at forks,
/// and yields the target states as they are completed.
fn run_state_pipeline_streaming<'a, Id, C, S, F, E, K>(
    index_to_id: &[&'a Id],
    id_to_index: &FastMap<&'a Id, usize>,
    is_target: &[bool],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    mut on_target: F,
) -> Result<(), StateComputationError<E>>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    F: FnMut(usize, SharedState<Id, K>) -> Result<(), E>,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let (sorted_ancestors, mut out_degree) =
        topological_sort_short_ids(index_to_id, id_to_index, events_map);

    if sorted_ancestors.len() != index_to_id.len() {
        return Err(StateComputationError::CycleDetected);
    }

    let mut global_auth_cache = LocalAuthCache::new(version);
    let mut mainline_cache: FastMap<Id, Option<Id>> = FastMap::default();

    let mut state_after_map: Vec<Option<SharedState<Id, K>>> = core::iter::repeat_with(|| None)
        .take(index_to_id.len())
        .collect();

    for idx in sorted_ancestors {
        let id_val = index_to_id[idx];
        let ev = events_map.get(id_val).unwrap();

        let mut prev_states = Vec::with_capacity(ev.prev_events.len());
        for pe in &ev.prev_events {
            let Some(&pe_idx) = id_to_index.get(pe) else {
                continue;
            };
            if out_degree[pe_idx] == 0 {
                continue;
            }
            out_degree[pe_idx] = out_degree[pe_idx].saturating_sub(1);
            if out_degree[pe_idx] == 0 {
                if let Some(pe_state) = state_after_map[pe_idx].take() {
                    prev_states.push(pe_state);
                }
            } else if let Some(ref pe_state) = state_after_map[pe_idx] {
                prev_states.push(pe_state.clone());
            }
        }

        let mut state_before: SharedState<Id, K> = if prev_states.is_empty() {
            SharedState::new()
        } else if prev_states.len() == 1 {
            prev_states.into_iter().next().unwrap()
        } else {
            resolve_merge_fast_path(
                &prev_states,
                events_map,
                &mut global_auth_cache,
                &mut mainline_cache,
                version,
            )
        };

        if ev.state_key.is_some() {
            state_before.insert(
                (
                    EventType::from(ev.event_type.as_str()),
                    ev.state_key.clone().unwrap_or_default(),
                ),
                ev.event_id.clone(),
            );
        }

        if is_target[idx] {
            on_target(idx, state_before.clone()).map_err(StateComputationError::Callback)?;
        }

        if out_degree[idx] > 0 {
            state_after_map[idx] = Some(state_before);
        }
    }

    Ok(())
}

/// A point in the DAG where a subset of forward extremities converge.
///
/// Returned by [`compute_merge_bases`]. Each junction records which extremities
/// are reachable (via `mask`), the event at the convergence point, and its depth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeBase<Id> {
    /// The event ID at the junction point.
    pub event_id: Id,
    /// Bitmask of which extremities can reach this node.
    /// Bit `i` is set iff extremity `i` is an ancestor-or-self.
    pub mask: u8,
    /// DAG depth of the junction event.
    pub depth: u64,
}

/// Default hard cap on backward walk steps for [`compute_merge_bases`].
pub const MERGE_BASE_MAX_STEPS: usize = 5_000;

/// Finds **all** primitive merge bases for up to 8 forward extremities in a
/// single backward pass.
///
/// Unlike [`compute_merge_base`] (which returns only the global common
/// ancestor), this function discovers every subset junction — the points where
/// different subsets of extremities first converge. The result is a minimal set
/// of [`MergeBase`] entries after superseding pruning.
///
/// # Algorithm (bitmask-propagating backward walk)
///
/// 1. Each extremity gets a unique bit in a `u8` mask.
/// 2. A max-heap ordered by depth walks backward through `prev_events`,
///    propagating masks via bitwise OR.
/// 3. When a node's mask gains `popcount ≥ 2`, it is recorded as a candidate
///    junction for that mask value.
/// 4. Walk terminates when the global merge base is found (all bits set) and
///    no unexplored paths remain, or when `max_steps` is exceeded.
/// 5. Superseded junctions are pruned: if mask M₂ ⊃ M₁ and J₂.depth ≥ J₁.depth,
///    then J₁ is redundant.
///
/// # Complexity
///
/// - **Time**: `O((V + E) · k)` where V/E are visited nodes/edges, k ≤ 8.
///   Bitmask ops are single CPU instructions.
/// - **Space**: `O(V)` for the mask map (one `u8` per visited event).
///
/// # Panics
///
/// Panics if `extremities.len() > 8` (bitmask overflow).
///
/// # Example
///
/// ```rust
/// use rezzy::{compute_merge_bases, MERGE_BASE_MAX_STEPS, DagNode};
/// use rezzy::{LeanEvent, HashMap};
///
/// let events: HashMap<String, LeanEvent<String>> = HashMap::new();
/// let tips = vec!["$tip_a", "$tip_b", "$tip_c"];
/// let junctions = compute_merge_bases(&tips, &events, MERGE_BASE_MAX_STEPS);
/// for j in &junctions {
///     println!("junction {:?} mask={:08b} depth={}", j.event_id, j.mask, j.depth);
/// }
/// ```
#[must_use]
pub fn compute_merge_bases<'a, Id, Q, S, Node>(
    extremities: &[&Q],
    events_map: &'a HashMap<Id, Node, S>,
    max_steps: usize,
) -> Vec<MergeBase<&'a Id>>
where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    Node: crate::basespec::rezzy_types::DagNode<Id = Id>,
{
    use alloc::collections::BinaryHeap;

    assert!(
        extremities.len() <= 8,
        "compute_merge_bases supports at most 8 extremities"
    );

    if extremities.len() < 2 {
        return Vec::new();
    }

    let k = extremities.len();
    let full_mask: u8 = 1u8
        .checked_shl(u32::try_from(k).expect("extremity count overflow"))
        .and_then(|v| v.checked_sub(1))
        .expect("bitmask overflow: k must be <= 8");

    // Max-heap: (depth, &Id) — highest depth pops first.
    let mut queue: BinaryHeap<(u64, &Id)> = BinaryHeap::new();
    let mut masks: HashMap<&Id, u8> = HashMap::new();

    // Track the highest-depth (closest to tips) junction found per mask.
    let mut best_junction: HashMap<u8, (&Id, u64)> = HashMap::new();

    for (i, &head) in extremities.iter().enumerate() {
        if let Some((k, ev)) = events_map.get_key_value(head) {
            let bit = 1u8 << i;
            let entry = masks.entry(k).or_insert(0);
            *entry |= bit;
            queue.push((ev.depth(), k));
        }
    }

    let mut steps: usize = 0;

    while let Some((depth, current_id)) = queue.pop() {
        if steps >= max_steps {
            break;
        }
        steps = steps.saturating_add(1);

        // Every id ever pushed onto `queue` was inserted into `masks` first
        // (initial extremity seeding above, or `masks.entry(pk)` before the
        // parent push below); `masks` entries are never removed. So this
        // lookup cannot miss.
        let &current_mask = masks
            .get(current_id)
            .expect("queue entries are only pushed for ids already present in `masks`");

        let popcount = current_mask.count_ones();

        // Record junction if this is a convergence point (≥ 2 extremities).
        if popcount >= 2 {
            best_junction
                .entry(current_mask)
                .or_insert((current_id, depth));
            // We use or_insert because the first time we see a mask, it's at
            // the highest depth (closest to tips) due to max-heap ordering.
        }

        // Global merge base found — ancestors are redundant.
        if current_mask == full_mask {
            break;
        }

        // Propagate mask to parents.
        if let Some(ev) = events_map.get(current_id.borrow()) {
            for parent_id in ev.prev_events() {
                let parent_q: &Q = parent_id.borrow();
                if let Some((pk, parent_ev)) = events_map.get_key_value(parent_q) {
                    let parent_mask = masks.entry(pk).or_insert(0);
                    let old = *parent_mask;
                    *parent_mask |= current_mask;

                    if *parent_mask != old {
                        queue.push((parent_ev.depth(), pk));
                    }
                }
            }
        }
    }

    // If we didn't find even a 2-bit convergence, return empty.
    if best_junction.is_empty() {
        return Vec::new();
    }

    // Superseding pruning: remove junction J₁ (mask M₁) if there exists
    // J₂ (mask M₂ ⊃ M₁) where J₂.depth ≥ J₁.depth (the larger subset
    // converged at least as close to the tips).
    let mut junctions: Vec<MergeBase<&'a Id>> = Vec::new();
    let masks_vec: Vec<(u8, &Id, u64)> = best_junction
        .into_iter()
        .map(|(mask, (id, depth))| (mask, id, depth))
        .collect();

    for &(mask, id, depth) in &masks_vec {
        let superseded = masks_vec
            .iter()
            .any(|&(m2, _, d2)| m2 != mask && (m2 & mask) == mask && d2 >= depth);
        if !superseded {
            junctions.push(MergeBase {
                event_id: id,
                mask,
                depth,
            });
        }
    }

    // Sort by descending depth (closest to tips first).
    junctions.sort_by_key(|j| core::cmp::Reverse(j.depth));
    junctions
}

/// Computes the most recent common ancestor (merge base) of multiple DAG tips.
///
/// Uses a max-heap ordered by event `depth` with roaring bitmap reachability
/// masks. Each extremity gets a unique bit index; as the heap walks backward
/// through `prev_events`, bitmasks propagate via bitwise OR. The first event
/// whose bitmask contains all extremity bits is the merge base.
///
/// Returns `None` if the extremities have no common ancestor (disjoint DAGs)
/// or if `extremities` is empty.
///
/// # Complexity
///
/// - **Time**: `O(V + E)` bounded to the subgraph between the extremities and
///   their merge base. Events below the merge base are never visited.
/// - **Space**: `O(V)` for the bitmask map, where each bitmask is a compressed
///   roaring bitmap.
///
/// ## **TODO:** Future optimization
///
/// With offline preprocessing (binary lifting or Euler tour + sparse table),
/// repeated LCA queries against the same DAG could be answered in `O(log V)`
/// per query after `O(V log V)` pre-processing.
///
/// # Panics
///
/// Panics if there are more than `2^32` extremities (practically unreachable).
///
/// # Example
///
/// ```rust
/// use rezzy::{compute_merge_base, DagNode};
/// use rezzy::{LeanEvent, HashMap};
///
/// let mut events: HashMap<String, LeanEvent<String>> = HashMap::new();
/// // ... populate events ...
/// let tips = vec!["$tip_a", "$tip_b"];
/// let merge_base = compute_merge_base(&tips, &events);
/// ```
#[must_use]
/// Computes the merge base (common ancestors) of a set of target events in the DAG.
#[cfg(feature = "std")]
pub fn compute_merge_base<'a, Id, Q, S, Node>(
    extremities: &[&Q],
    events_map: &'a HashMap<Id, Node, S>,
) -> Option<&'a Id>
where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    Node: crate::basespec::rezzy_types::DagNode<Id = Id>,
{
    use alloc::collections::BinaryHeap;

    use roaring::RoaringBitmap;

    if extremities.is_empty() {
        return None;
    }

    // Single extremity: it is its own merge base.
    if extremities.len() == 1 {
        return events_map.get_key_value(extremities[0]).map(|(k, _)| k);
    }

    let target_count = extremities.len() as u64;

    // Max-heap: (depth, &Id) — highest depth pops first, ensuring a parent
    // is never processed until all of its descendants have propagated bits.
    let mut queue: BinaryHeap<(u64, &Id)> = BinaryHeap::new();
    let mut masks: HashMap<&Id, RoaringBitmap> = HashMap::new();

    for (i, &head) in extremities.iter().enumerate() {
        if let Some((k, ev)) = events_map.get_key_value(head) {
            let idx = u32::try_from(i).expect("more than 2^32 extremities");
            let entry = masks.entry(k).or_default();
            entry.insert(idx);
            queue.push((ev.depth(), k));
        }
    }

    while let Some((_, current_id)) = queue.pop() {
        // Same invariant as `compute_merge_bases`: every id pushed onto
        // `queue` was inserted into `masks` first, and entries are never
        // removed, so this lookup cannot miss.
        let current_mask = masks
            .get(current_id)
            .cloned()
            .expect("queue entries are only pushed for ids already present in `masks`");

        // If reachable by ALL extremities, this is the merge base.
        if current_mask.len() == target_count {
            return Some(current_id);
        }

        if let Some(ev) = events_map.get(current_id.borrow()) {
            for parent_id in ev.prev_events() {
                let parent_q: &Q = parent_id.borrow();
                if let Some((pk, parent_ev)) = events_map.get_key_value(parent_q) {
                    let is_new = !masks.contains_key(pk);
                    let parent_mask = masks.entry(pk).or_default();
                    let old_len = parent_mask.len();
                    *parent_mask |= &current_mask;
                    let new_len = parent_mask.len();

                    if is_new || new_len > old_len {
                        queue.push((parent_ev.depth(), pk));
                    }
                }
            }
        }
    }

    None // Disjoint DAGs (no common ancestor)
}

/// Collects all reachable ancestor events across a batch of target events and assigns them
/// contiguous integer IDs (short IDs) for fast topological processing and array lookups.
fn collect_ancestor_short_ids_batch<'a, Id, C, S, K>(
    target_event_ids: &[&'a Id],
    events_map: &'a HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> (FastMap<&'a Id, usize>, Vec<&'a Id>)
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: Clone,
{
    let mut id_to_index: FastMap<&Id, usize> = FastMap::default();
    let mut index_to_id: Vec<&Id> = Vec::new();
    let mut queue = Vec::new();

    for &tid in target_event_ids {
        if !id_to_index.contains_key(tid) {
            let next_idx = index_to_id.len();
            id_to_index.insert(tid, next_idx);
            index_to_id.push(tid);
            queue.push(tid);
        }
    }

    let mut head = 0;
    while head < queue.len() {
        let current_id = queue[head];
        head = head.saturating_add(1);

        let Some(ev) = events_map.get(current_id) else {
            continue;
        };
        for pe in &ev.prev_events {
            if events_map.contains_key(pe) && !id_to_index.contains_key(pe) {
                let next_idx = index_to_id.len();
                id_to_index.insert(pe, next_idx);
                index_to_id.push(pe);
                queue.push(pe);
            }
        }
    }

    (id_to_index, index_to_id)
}

/// Performs a topological sort of the graph represented by short `usize` indexes.
/// Performs Kahn's topological sort on the collected ancestor graph.
/// Returns the events sorted such that parents always appear before their children.
fn topological_sort_short_ids<Id, C, S, K>(
    index_to_id: &[&Id],
    id_to_index: &FastMap<&Id, usize>,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> (Vec<usize>, Vec<usize>)
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: Clone,
{
    let num_reachable = index_to_id.len();
    let mut in_degree = alloc::vec![0usize; num_reachable];
    let mut adjacency = alloc::vec![Vec::new(); num_reachable];
    let mut out_degree = alloc::vec![0usize; num_reachable];

    for (i, id) in index_to_id.iter().enumerate() {
        let Some(ev) = events_map.get(*id) else {
            continue;
        };
        let mut seen = if ev.prev_events.len() > 1 {
            Some(crate::FastSet::default())
        } else {
            None
        };
        for parent in &ev.prev_events {
            if let Some(&parent_idx) = id_to_index.get(parent) {
                // Dedup: only count each parent edge once, even if prev_events has duplicates.
                if let Some(seen_set) = &mut seen {
                    if !seen_set.insert(parent_idx) {
                        continue;
                    }
                }
                in_degree[i] = in_degree[i].saturating_add(1);
                adjacency[parent_idx].push(i);
                out_degree[parent_idx] = out_degree[parent_idx].saturating_add(1);
            }
        }
    }

    let mut topo_queue = alloc::collections::VecDeque::new();
    for (i, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            topo_queue.push_back(i);
        }
    }

    let mut sorted_ancestors = Vec::with_capacity(num_reachable);
    while let Some(idx) = topo_queue.pop_front() {
        sorted_ancestors.push(idx);
        for &child_idx in &adjacency[idx] {
            in_degree[child_idx] = in_degree[child_idx].saturating_sub(1);
            if in_degree[child_idx] == 0 {
                topo_queue.push_back(child_idx);
            }
        }
    }

    (sorted_ancestors, out_degree)
}

/// Fast-path resolution for merging multiple states when they are all structurally identical.
/// Bypasses full state resolution by simply returning one of the identical parent states.
fn resolve_merge_fast_path<Id, C, S, K>(
    prev_states: &[SharedState<Id, K>],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    global_auth_cache: &mut LocalAuthCache<Id, C, K>,
    mainline_cache: &mut FastMap<Id, Option<Id>>,
    version: StateResVersion,
) -> SharedState<Id, K>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let first = &prev_states[0];
    let all_match = prev_states[1..].iter().all(|state| first == state);

    if all_match {
        first.clone()
    } else {
        resolve_multiple_prev_states(
            prev_states,
            events_map,
            global_auth_cache,
            mainline_cache,
            version,
        )
        .into_iter()
        .collect()
    }
}

/// Slow path for merging multiple parent states via the state resolution algorithm.
/// Full state resolution path for DAG nodes with multiple parents (forks).
/// Groups the unconflicted state and runs `resolve_iterative_sort` on the conflicted subset.
fn resolve_multiple_prev_states<Id, C, S, K>(
    prev_states: &[SharedState<Id, K>],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    global_auth_cache: &mut LocalAuthCache<Id, C, K>,
    mainline_cache: &mut FastMap<Id, Option<Id>>,
    version: StateResVersion,
) -> SharedState<Id, K>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let mut conflicted_keys = crate::FastSet::default();
    let mut conflicted_state_set = crate::HashSet::new();
    let base = &prev_states[0];

    for other in &prev_states[1..] {
        for diff_item in base.diff(other) {
            match diff_item {
                imbl::ordmap::DiffItem::Add(k, v) | imbl::ordmap::DiffItem::Remove(k, v) => {
                    conflicted_keys.insert(k.clone());
                    conflicted_state_set.insert(v.clone());
                }
                imbl::ordmap::DiffItem::Update {
                    old: (k, old_v),
                    new: (_, new_v),
                } => {
                    conflicted_keys.insert(k.clone());
                    conflicted_state_set.insert(old_v.clone());
                    conflicted_state_set.insert(new_v.clone());
                }
            }
        }
    }

    let mut unconflicted_state = base.clone();
    for k in &conflicted_keys {
        unconflicted_state.remove(k);
    }

    let mut conflicted_events = HashMap::new();
    for id_val in &conflicted_state_set {
        if let Some(event) = events_map.get(id_val) {
            conflicted_events.insert(id_val.clone(), event.clone());
        }
    }

    // Supplement conflicted_events with the auth difference auth(C) \ auth(U)
    let auth_diff = compute_auth_chain_diff(&unconflicted_state, &conflicted_state_set, events_map);
    for id_val in auth_diff {
        if let Some(event) = events_map.get(&id_val) {
            conflicted_events.insert(id_val, event.clone());
        }
    }

    let mut pl_cache = HashMap::new();
    crate::resolve::iterative::resolve_iterative_sort_with_all_caches(
        unconflicted_state,
        conflicted_events,
        events_map,
        Some(global_auth_cache),
        version,
        &mut pl_cache,
        mainline_cache,
        &conflicted_keys,
    )
}

/// Computes the **auth chain difference**: `auth(C) \ auth(U)`.
///
/// Walks the unconflicted (U) and conflicted (C) auth chains in
/// parallel by depth, pruning C-side events already reachable
/// from U. Returns the set of event IDs in the conflicted auth
/// chains that are NOT reachable from unconflicted state.
///
/// This is the core input to state resolution — the set of
/// events that must be considered during iterative auth. By
/// exposing this as a public API, homeservers can compute the
/// auth difference without reimplementing the bounded dual-heap
/// traversal.
///
/// # Parameters
///
/// - `unconflicted_state`: The agreed-upon state (values are
///   event IDs whose auth chains define the "known" baseline).
/// - `conflicted_state_set`: Event IDs that differ across forks.
/// - `events_map`: Full event context containing all referenced
///   events and their auth chains.
///
/// # Returns
///
/// The set of event IDs reachable from `conflicted_state_set`'s
/// auth chains but NOT reachable from `unconflicted_state`'s
/// auth chains.
///
/// # Complexity
///
/// - **Time**: `O((|U| + |C|) · log(|U| + |C|))` — bounded by
///   the total auth chain size, with early pruning.
/// - **Space**: `O(|U| + |C|)` for visited sets.
///
/// # Panics
///
/// Internal `unwrap()` calls are guarded by `peek()`
/// checks and cannot panic under normal operation.
pub fn compute_auth_chain_diff<Id, C, S1, S2, K>(
    unconflicted_state: &SharedState<Id, K>,
    conflicted_state_set: &crate::HashSet<Id, S2>,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S1>,
) -> crate::HashSet<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: Ord + Clone,
{
    let mut u_visited = crate::FastSet::default();
    let mut u_heap_elements = Vec::with_capacity(unconflicted_state.len());
    for id in unconflicted_state.values() {
        if u_visited.insert(id.clone()) {
            if let Some(ev) = events_map.get(id) {
                u_heap_elements.push((ev.depth, id.clone()));
            }
        }
    }
    let mut u_heap = alloc::collections::BinaryHeap::from(u_heap_elements);

    let mut c_visited = crate::FastSet::default();
    let mut c_heap = alloc::collections::BinaryHeap::new();
    for id in conflicted_state_set {
        if u_visited.contains(id) {
            continue; // PRUNE EARLY
        }
        if c_visited.insert(id.clone()) {
            if let Some(ev) = events_map.get(id) {
                c_heap.push((ev.depth, id.clone()));
            }
        }
    }

    let mut auth_diff = crate::HashSet::new();

    while let Some(&(c_depth, _)) = c_heap.peek() {
        // Catch up U's traversal to C's current depth
        while let Some(&(u_depth, _)) = u_heap.peek() {
            if u_depth < c_depth {
                break;
            }
            let (_, u_id) = u_heap
                .pop()
                .expect("invariant: heap peek implies non-empty pop");
            let ev = events_map.get(&u_id).expect(
                "invariant: every heap entry corresponds to an event present in events_map",
            );
            for auth_id in &ev.auth_events {
                if u_visited.insert(auth_id.clone()) {
                    if let Some(a_ev) = events_map.get(auth_id) {
                        u_heap.push((a_ev.depth, auth_id.clone()));
                    }
                }
            }
        }

        let (_, c_id) = c_heap
            .pop()
            .expect("invariant: heap peek implies non-empty pop");
        if !u_visited.contains(&c_id) {
            auth_diff.insert(c_id.clone());
            let ev = events_map.get(&c_id).expect(
                "invariant: every heap entry corresponds to an event present in events_map",
            );
            for auth_id in &ev.auth_events {
                if u_visited.contains(auth_id) {
                    continue; // PRUNE EARLY
                }
                if c_visited.insert(auth_id.clone()) {
                    if let Some(a_ev) = events_map.get(auth_id) {
                        c_heap.push((a_ev.depth, auth_id.clone()));
                    }
                }
            }
        }
    }

    auth_diff
}

/// A backward extremity: an event in the local DAG whose `prev_events`
/// reference one or more parent IDs that are neither present in the
/// provided event map nor recognized by the caller's `exists` predicate.
///
/// Backward extremities represent gaps in the local DAG — points where
/// the timeline is incomplete and a federation `/backfill` request should
/// be issued to fill the hole.
///
/// # Fields
///
/// - `event_id`: The known event that has missing parents.
/// - `missing_prev_events`: The specific parent IDs that are unknown locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackwardExtremity<Id> {
    /// The event that has one or more missing parents.
    pub event_id: Id,
    /// The parent event IDs that are missing from the local DAG.
    pub missing_prev_events: Vec<Id>,
}

/// Scans a set of DAG events and identifies **backward extremities** —
/// events whose `prev_events` reference parent IDs that are missing from
/// both the provided `events` map and the caller's `exists` oracle.
///
/// This is the pure graph-analysis core of a homeserver's backfill loop.
/// By extracting it into rezzy, it becomes testable and reusable without
/// async database I/O or federation networking.
///
/// # Arguments
///
/// - `events`: The local event map to scan.
/// - `exists`: A predicate that returns `true` if an event ID is known to
///   exist outside `events` (e.g. in a database). This prevents reporting
///   false gaps for events that are stored but not loaded into memory.
///
/// # Returns
///
/// A `Vec<BackwardExtremity<Id>>` for every event that has at least one
/// missing parent. Events whose parents are all accounted for (either in
/// `events` or via `exists`) are not included.
///
/// # Example
///
/// ```rust
/// use rezzy::{find_backward_extremities, LeanEvent, HashMap};
///
/// let mut events: HashMap<String, LeanEvent> = HashMap::new();
/// // ... populate events ...
/// let gaps = find_backward_extremities(&events, |_id| false);
/// for gap in &gaps {
///     println!("Event {} missing parents: {:?}", gap.event_id, gap.missing_prev_events);
/// }
/// ```
///
/// # Complexity
///
/// - **Time**: `O(Σ |prev_events|)` — linear in the total number of parent
///   references across all events.
/// - **Space**: `O(G)` where `G` is the total number of missing parent IDs
///   across all backward extremities.
#[must_use]
pub fn find_backward_extremities<Id, Node, S, F>(
    events: &crate::HashMap<Id, Node, S>,
    exists: F,
) -> Vec<BackwardExtremity<Id>>
where
    Id: crate::basespec::rezzy_types::EventId,
    Node: crate::basespec::rezzy_types::DagNode<Id = Id>,
    S: core::hash::BuildHasher,
    F: Fn(&Id) -> bool,
{
    let mut result = Vec::new();

    for node in events.values() {
        let mut missing = Vec::new();
        for prev_id in node.prev_events() {
            if !events.contains_key(prev_id) && !exists(prev_id) {
                missing.push(prev_id.clone());
            }
        }
        if !missing.is_empty() {
            result.push(BackwardExtremity {
                event_id: node.event_id().clone(),
                missing_prev_events: missing,
            });
        }
    }

    result
}

// ─── Auth gap detection ──────────────────────────────────────────────

/// An event whose `auth_events` reference IDs missing from the local set.
///
/// Unlike [`BackwardExtremity`] (which tracks missing `prev_events` —
/// "incomplete timeline, backfill needed"), a missing auth event means
/// "can't verify authorization — potentially unsafe state." Different
/// severity, different remediation, different logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingAuthEvent<Id> {
    /// The event that references missing auth events.
    pub event_id: Id,
    /// The auth event IDs that are missing from the local set.
    pub missing_auth_events: Vec<Id>,
}

/// Scans a set of DAG events and identifies events whose `auth_events`
/// reference IDs missing from both the provided `events` map and the
/// caller's `exists` oracle.
///
/// This is the auth-chain counterpart of [`find_backward_extremities`].
/// A homeserver uses this to detect authorization gaps — events it cannot
/// fully auth-check because required auth chain entries are missing.
///
/// # Arguments
///
/// - `events`: The local event map to scan.
/// - `exists`: A predicate that returns `true` if an event ID is known to
///   exist outside `events` (e.g. in a database).
///
/// # Complexity
///
/// - **Time**: `O(Σ |auth_events|)` — linear in the total number of auth
///   references across all events.
/// - **Space**: `O(G)` where `G` is the total number of missing auth IDs.
#[must_use]
pub fn find_missing_auth_events<Id, Node, S, F>(
    events: &crate::HashMap<Id, Node, S>,
    exists: F,
) -> Vec<MissingAuthEvent<Id>>
where
    Id: crate::basespec::rezzy_types::EventId,
    Node: crate::basespec::rezzy_types::DagNode<Id = Id>,
    S: core::hash::BuildHasher,
    F: Fn(&Id) -> bool,
{
    let mut result = Vec::new();

    for node in events.values() {
        let mut missing = Vec::new();
        for auth_id in node.auth_events() {
            if !events.contains_key(auth_id) && !exists(auth_id) {
                missing.push(auth_id.clone());
            }
        }
        if !missing.is_empty() {
            result.push(MissingAuthEvent {
                event_id: node.event_id().clone(),
                missing_auth_events: missing,
            });
        }
    }

    result
}

// ─── Position-based topological ordering ─────────────────────────────

/// Computes position-based topological depths for all events in the map.
///
/// Unlike [`compute_depths`] (which returns `1 + max(parent_depths)` —
/// the spec-correct DAG depth), this function returns the **1-indexed
/// position** of each event in Kahn's topological sort. This produces a
/// total ordering suitable for building a database index where every
/// event gets a unique depth value.
///
/// The `tiebreak` closure determines the ordering of events at the same
/// topological level (zero in-degree simultaneously). Typical choices:
/// - `|a, b| ts(a).cmp(&ts(b)).then(a.cmp(b))` — chronological with
///   lexicographic event ID fallback (deterministic).
/// - `|_, _| Ordering::Equal` — arbitrary (fastest, non-deterministic).
///
/// # Difference from `compute_depths`
///
/// ```text
///          A
///         / \
///        B   C
///         \ /
///          D
///
///  compute_depths:         A=1, B=2, C=2, D=3
///  compute_topo_positions: A=1, B=2, C=3, D=4  (total order)
/// ```
///
/// `compute_depths` preserves DAG structure (siblings share a depth).
/// `compute_topo_positions` produces a strict total order (every event
/// gets a unique position). The latter is what a homeserver needs for
/// its `roomid_topologicalorder_pducount` index.
///
/// # Complexity
///
/// - **Time**: `O(V log V + E)` — Kahn sort plus a comparison sort for
///   deterministic tiebreaking within topological levels.
/// - **Space**: `O(V)` for the position map.
#[must_use]
pub fn compute_topo_positions<Id, C, S, F, K>(
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    tiebreak: F,
) -> Vec<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: Clone,
    F: Fn(&Id, &Id) -> core::cmp::Ordering,
{
    if events_map.is_empty() {
        return Vec::new();
    }

    let all_ids: Vec<&Id> = events_map.keys().collect();
    let (id_to_index, index_to_id) = collect_ancestor_short_ids_batch(&all_ids, events_map);
    let (sorted, _) = topological_sort_short_ids(&index_to_id, &id_to_index, events_map);

    debug_assert_eq!(
        sorted.len(),
        index_to_id.len(),
        "compute_topo_positions: Kahn sort returned fewer nodes than expected — \
         the input graph contains a cycle"
    );

    // Kahn sort gives a valid topological order; apply tiebreak within
    // each topological level for deterministic output.
    // First compute parent-max depths to identify levels.
    let mut depth_by_idx = alloc::vec![0u64; index_to_id.len()];
    for &idx in &sorted {
        let id = index_to_id[idx];
        if let Some(ev) = events_map.get(id) {
            let max_parent = ev
                .prev_events
                .iter()
                .filter_map(|pe| id_to_index.get(pe))
                .map(|&pi| depth_by_idx[pi])
                .max()
                .unwrap_or(0);
            depth_by_idx[idx] = max_parent.saturating_add(1);
        }
    }

    // Sort by depth ascending (parents first), tiebreak within level.
    let mut result: Vec<Id> = sorted.iter().map(|&idx| index_to_id[idx].clone()).collect();

    result.sort_by(|a, b| {
        let da = id_to_index.get(a).map_or(0, |&i| depth_by_idx[i]);
        let db = id_to_index.get(b).map_or(0, |&i| depth_by_idx[i]);
        da.cmp(&db).then_with(|| tiebreak(a, b))
    });

    result
}

// ─── Pagination verification ─────────────────────────────────────────

/// Computes the topological depth of every event reachable from the given
/// targets in the DAG. Depth is defined as `1 + max(parent depths)`, with
/// root events (no parents in the map) having depth 1.
///
/// This is the reference depth computation. A homeserver should use these
/// values when building its topological index — any mismatch is a bug in
/// the storage layer.
///
/// # Complexity
///
/// - **Time**: `O(V + E)` — one Kahn sort pass over the reachable subgraph.
/// - **Space**: `O(V)` for the depth map.
///
/// # Panics
///
/// Panics if a sorted event ID is not found in `events_map` (indicates a
/// bug in the topological sort).
#[must_use]
pub fn compute_depths<Id, C, S, K>(
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> HashMap<Id, u64>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: Clone,
{
    if events_map.is_empty() {
        return HashMap::new();
    }

    let all_ids: Vec<&Id> = events_map.keys().collect();
    let (id_to_index, index_to_id) = collect_ancestor_short_ids_batch(&all_ids, events_map);
    let (sorted, _) = topological_sort_short_ids(&index_to_id, &id_to_index, events_map);

    let mut depths = alloc::vec![0u64; index_to_id.len()];

    for idx in &sorted {
        let id = index_to_id[*idx];
        let ev = events_map.get(id).unwrap();
        let max_parent_depth = ev
            .prev_events
            .iter()
            .filter_map(|pe| id_to_index.get(pe))
            .map(|&pi| depths[pi])
            .max()
            .unwrap_or(0);
        depths[*idx] = max_parent_depth.saturating_add(1);
    }

    let mut result = HashMap::with_capacity(index_to_id.len());
    for (i, &id) in index_to_id.iter().enumerate() {
        result.insert(id.clone(), depths[i]);
    }
    result
}

// ─── Gap-fill depth hardening ─────────────────────────────────────────

/// A `prev_events` edge whose two endpoints' wire-supplied `depth` values
/// are not consistent with the DAG structure: the child's claimed `depth`
/// does not exceed its parent's.
///
/// Both `depth` and `prev_events` are covered by an event's content hash
/// (and therefore its signature), so a signature proves the sender *said*
/// `depth: N` — it doesn't prove `N` is a truthful function of the parents
/// it also signed. `prev_events` is checkable against the DAG the local
/// server already holds; `depth` is not independently checkable at all
/// except by comparing it back against that same DAG. That comparison is
/// what this type reports: a byzantine or buggy peer can attach any
/// `depth` it likes, and this flags claims that are structurally
/// impossible given the parent it also claims.
///
/// This only checks *relative* monotonicity across a single edge, not
/// absolute depth-from-room-creation — an edge check works on a partial
/// view (e.g. a backfill gap-fill batch, where ancestors above the gap
/// aren't in `events_map`), whereas an absolute check would require the
/// full DAG back to `m.room.create` and would flag every legitimate
/// partial batch as a false positive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepthDivergence<Id> {
    /// The parent event (referenced via `prev_events`).
    pub parent: Id,
    /// The child event (the one whose `prev_events` includes `parent`).
    pub child: Id,
    /// The parent's claimed wire `depth`.
    pub parent_depth: u64,
    /// The child's claimed wire `depth`.
    pub child_depth: u64,
}

/// Scans a set of events and reports every `prev_events` edge whose
/// endpoints' wire `depth` values violate DAG monotonicity — i.e. a child
/// whose claimed `depth` does not exceed its parent's claimed `depth`.
/// Only edges where **both** endpoints are present in `events_map` are
/// checked; an edge to a parent outside the map (a genuine gap) is
/// silently skipped rather than treated as a violation.
///
/// This is a pure detector — it doesn't decide what to do about a
/// divergence, only surfaces it. A homeserver can use this to log or alert
/// on peers sending events with implausible depths, independent of whether
/// it also chooses to use [`resolve_gap_fill_order`] to sidestep the
/// untrusted value entirely when merging a gap-fill batch.
///
/// # Complexity
///
/// `O(Σ |prev_events|)` — linear in the total number of parent references.
#[must_use]
pub fn find_depth_divergences<Id, C, S, K>(
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> Vec<DepthDivergence<Id>>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: Clone,
{
    let mut divergences = Vec::new();
    let mut seen_edges = BTreeSet::new();

    for child in events_map.values() {
        for parent_id in &child.prev_events {
            let Some(parent) = events_map.get(parent_id) else {
                continue; // parent outside the map — a gap, not a violation
            };
            if !seen_edges.insert((parent_id.clone(), child.event_id.clone())) {
                continue;
            }
            if parent.depth == u64::MAX && child.depth == u64::MAX {
                continue; // saturated clamp: both endpoints reached the cap
            }
            if child.depth <= parent.depth {
                divergences.push(DepthDivergence {
                    parent: parent_id.clone(),
                    child: child.event_id.clone(),
                    parent_depth: parent.depth,
                    child_depth: child.depth,
                });
            }
        }
    }

    // `events_map` iteration order is hash-map-arbitrary; sort for a
    // deterministic, reproducible report.
    divergences.sort_by(|a, b| (&a.parent, &a.child).cmp(&(&b.parent, &b.child)));
    divergences
}

/// Re-derives the ordering of a backfill gap-fill batch directly from
/// `prev_events` DAG edges, ignoring every event's wire-supplied `depth`
/// field entirely.
///
/// This is not new logic — it's [`compute_topo_positions`] under a name
/// that documents the intended call site: the point where a homeserver
/// merges a `/backfill` response into its timeline index, where trusting
/// wire `depth` for ordering would otherwise be tempting because the value
/// is "right there" on each PDU. `compute_topo_positions` already ignores
/// `depth` and derives order purely from `prev_events`, which is why it's
/// safe to reuse as-is rather than needing new derivation logic; only the
/// entry point is new.
///
/// Works correctly on a partial batch: the derived order is a valid
/// topological order of the subgraph you pass in, which is what a gap-fill
/// merge needs, even though it says nothing about where that subgraph
/// slots into the full room DAG above the gap.
///
/// Pair with [`find_depth_divergences`] if you also want to log/alert on
/// peers whose claimed depths are structurally inconsistent with this
/// derived order, rather than silently overriding them.
///
/// # Complexity
///
/// Identical to [`compute_topo_positions`]: `O(V log V + E)`.
#[must_use]
pub fn resolve_gap_fill_order<Id, C, S, F, K>(
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    tiebreak: F,
) -> Vec<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: Clone,
    F: Fn(&Id, &Id) -> core::cmp::Ordering,
{
    compute_topo_positions(events_map, tiebreak)
}

/// Returns events reachable from `tip` in **reverse topological order**
/// (newest first). This is the spec-correct ordering for
/// `/messages?dir=b` backward pagination.
///
/// Tie-breaking within the same topological level is determined by
/// `tiebreak`. Typical choices:
/// - Homeserver: `|a, b| pdu_count(a).cmp(&pdu_count(b)).reverse()` (insertion order)
/// - Tests: `|a, b| a.cmp(&b).reverse()` (lexicographic event ID)
///
/// # Complexity
///
/// - **Time**: `O(V + E)` for ancestor collection + Kahn sort.
/// - **Space**: `O(V)`.
#[must_use]
pub fn reverse_topological_order<Id, C, Q, S, F, K>(
    tip: &Q,
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    tiebreak: F,
) -> Vec<Id>
where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    C: Clone,
    F: Fn(&Id, &Id) -> core::cmp::Ordering,
{
    let Some((tip_key, _)) = events_map.get_key_value(tip) else {
        return Vec::new();
    };

    let targets = [tip_key];
    let (id_to_index, index_to_id) = collect_ancestor_short_ids_batch(&targets, events_map);
    let (sorted, _) = topological_sort_short_ids(&index_to_id, &id_to_index, events_map);

    // Compute depths inline using the index arrays
    let mut depth_by_idx = alloc::vec![0u64; index_to_id.len()];
    for &idx in &sorted {
        let id = index_to_id[idx];
        if let Some(ev) = events_map.get(id.borrow()) {
            let max_parent = ev
                .prev_events
                .iter()
                .filter_map(|pe| id_to_index.get(pe))
                .map(|&pi| depth_by_idx[pi])
                .max()
                .unwrap_or(0);

            depth_by_idx[idx] = max_parent.saturating_add(1);
        }
    }

    // Kahn sort gives parents-first; reverse for newest-first,
    // then stable-sort by depth descending with tiebreak.
    let mut result: Vec<Id> = sorted
        .iter()
        .rev()
        .map(|&idx| index_to_id[idx].clone())
        .collect();

    result.sort_by(|a, b| {
        let da = id_to_index.get(a).map_or(0, |&i| depth_by_idx[i]);
        let db = id_to_index.get(b).map_or(0, |&i| depth_by_idx[i]);
        db.cmp(&da).then_with(|| tiebreak(a, b))
    });

    result
}

/// The kind of violation detected by [`verify_pagination`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaginationViolation<Id> {
    /// An event appeared on more than one page.
    Duplicate {
        event_id: Id,
        first_page: usize,
        second_page: usize,
    },
    /// An ancestor appeared *after* its descendant in the page sequence
    /// (violates the reverse-topological ordering invariant).
    AncestorAfterDescendant {
        ancestor: Id,
        descendant: Id,
        ancestor_page: usize,
        descendant_page: usize,
    },
}

/// Verifies that a sequence of pagination pages respects DAG ordering
/// invariants:
///
/// 1. **No duplicates** — each event ID appears on at most one page.
/// 2. **Topological monotonicity** — if event A is an ancestor of B,
///    then A must not appear on an *earlier* page than B (in backward
///    pagination, descendants come first).
///
/// This is a pure property checker. Feed it the actual pages from your
/// paginator; any violation is a bug in the storage/pagination layer.
///
/// Completeness (every reachable event present) is intentionally NOT
/// checked — pagination may stop at room creation, budget limits, or
/// ACL boundaries.
///
/// # Returns
///
/// A `Vec` of violations. Empty means the pages are well-formed.
#[must_use]
pub fn verify_pagination<Id, C, S, K>(
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    pages: &[Vec<Id>],
) -> Vec<PaginationViolation<Id>>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: Clone,
{
    let mut violations = Vec::new();

    // 1. Check for duplicates
    let mut seen: HashMap<&Id, usize> = HashMap::new();
    for (page_idx, page) in pages.iter().enumerate() {
        for id in page {
            if let Some(&first_page) = seen.get(id) {
                violations.push(PaginationViolation::Duplicate {
                    event_id: id.clone(),
                    first_page,
                    second_page: page_idx,
                });
            } else {
                seen.insert(id, page_idx);
            }
        }
    }

    // 2. Check topological monotonicity (ancestor must not appear before descendant)
    // In backward pagination, page 0 has the newest events. If event B is on
    // page 1 and B's ancestor A is on page 0 (earlier), that's wrong — A should
    // be on a later page (higher index).
    for (page_idx, page) in pages.iter().enumerate() {
        for id in page {
            let Some(ev) = events_map.get(id) else {
                continue;
            };
            // Each prev_event is an ancestor. It must be on a page with
            // index >= this event's page (or not present at all).
            for parent_id in &ev.prev_events {
                if let Some(&parent_page) = seen.get(parent_id) {
                    if parent_page < page_idx {
                        violations.push(PaginationViolation::AncestorAfterDescendant {
                            ancestor: parent_id.clone(),
                            descendant: id.clone(),
                            ancestor_page: parent_page,
                            descendant_page: page_idx,
                        });
                    }
                }
            }
        }
    }

    violations
}

/// Represents an optimization-friendly state update yielded during topological streaming.
///
/// Manual `Clone`/`Debug`/`PartialEq`/`Eq` impls (rather than `#[derive]`) because
/// `SharedState<Id, K>` (an `imbl::OrdMap`) requires `K: Ord` structurally, which
/// `#[derive]`'s naive per-field bound inference does not add automatically.
pub enum StateUpdate<'b, Id, K = String> {
    /// The state has been newly resolved, or modified by a state-changing event.
    New {
        /// The resolved state map at this target.
        state: SharedState<Id, K>,
        /// The incrementally maintained `LtHash` digest for this state, borrowed
        /// from the pipeline's owned state. Zero-copy: callers that only compare,
        /// look up, or digest can borrow; only callers that need to retain the
        /// hash (e.g. across a thread channel) should copy it.
        hash: &'b crate::state::lthash::LtHash,
    },
    /// The state at this event is completely unchanged from its parent's state.
    /// Consumers can reuse the parent's state directly, skipping compression and O(N) traversals.
    ///
    /// # Important
    ///
    /// The referenced `parent_event_id` may not have been yielded as a target.
    /// Callers must have the parent's state available from a prior persistence pass
    /// (e.g., a full-rebuild pipeline). Use [`StateUpdate::into_state`] with a closure
    /// that can look up any ancestor's state, not just previously-yielded targets.
    Unchanged {
        /// The event ID of the single parent event from which this state is inherited.
        parent_event_id: &'b Id,
        /// The `LtHash` digest of the parent state, borrowed from the pipeline's
        /// owned state (zero-copy; see [`StateUpdate::New`]).
        hash: &'b crate::state::lthash::LtHash,
    },
}

impl<Id: core::fmt::Debug, K: core::fmt::Debug + Ord> core::fmt::Debug for StateUpdate<'_, Id, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::New { state, hash } => f
                .debug_struct("New")
                .field("state", state)
                .field("hash", hash)
                .finish(),
            Self::Unchanged {
                parent_event_id,
                hash,
            } => f
                .debug_struct("Unchanged")
                .field("parent_event_id", parent_event_id)
                .field("hash", hash)
                .finish(),
        }
    }
}

impl<Id: Clone, K: Ord + Clone> Clone for StateUpdate<'_, Id, K> {
    fn clone(&self) -> Self {
        match self {
            Self::New { state, hash } => Self::New {
                state: state.clone(),
                hash,
            },
            Self::Unchanged {
                parent_event_id,
                hash,
            } => Self::Unchanged {
                parent_event_id,
                hash,
            },
        }
    }
}

impl<Id: PartialEq, K: Ord + PartialEq> PartialEq for StateUpdate<'_, Id, K> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::New {
                    state: s1,
                    hash: h1,
                },
                Self::New {
                    state: s2,
                    hash: h2,
                },
            ) => s1 == s2 && h1 == h2,
            (
                Self::Unchanged {
                    parent_event_id: p1,
                    hash: h1,
                },
                Self::Unchanged {
                    parent_event_id: p2,
                    hash: h2,
                },
            ) => p1 == p2 && h1 == h2,
            _ => false,
        }
    }
}

impl<Id: Eq, K: Ord + Eq> Eq for StateUpdate<'_, Id, K> {}

impl<Id, K> StateUpdate<'_, Id, K>
where
    Id: Clone,
    K: Ord + Clone,
{
    /// Resolves and yields the full `SharedState<Id, K>`, either returning the newly resolved state
    /// or looking up the parent state via a provided closure.
    ///
    /// # Panics
    ///
    /// Panics if the update is `StateUpdate::Unchanged` and the provided callback fails to
    /// return the parent event state.
    pub fn into_state(
        self,
        mut get_parent_state: impl FnMut(&Id) -> Option<SharedState<Id, K>>,
    ) -> SharedState<Id, K> {
        match self {
            StateUpdate::New { state, .. } => state,
            StateUpdate::Unchanged {
                parent_event_id, ..
            } => get_parent_state(parent_event_id)
                .expect("StateUpdate::Unchanged requires the parent state to be available"),
        }
    }

    /// Borrows the carried `LtHash` lattice (the 2 KiB homomorphic accumulator)
    /// — zero-copy. The 32-byte cryptographic hash of it is [`StateUpdate::digest`].
    #[must_use]
    pub fn lattice(&self) -> &crate::state::lthash::LtHash {
        match self {
            StateUpdate::New { hash, .. } | StateUpdate::Unchanged { hash, .. } => hash,
        }
    }

    /// Computes the 32-byte MSC4500 §6 digest of the carried `LtHash` lattice.
    ///
    /// Cheap (`BLAKE2b` over the 2 KiB lattice) and collision-resistant to 256 bits;
    /// useful as a compact dedup/identity key without copying the full lattice.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.lattice().digest()
    }
}

/// A wrapper that pairs a `SharedState` map with its incrementally maintained `LtHash`.
///
/// Manual `Clone`/`Debug` impls (rather than `#[derive]`) because `SharedState<Id, K>`
/// (an `imbl::OrdMap`) requires `K: Ord` structurally, which `#[derive]`'s naive
/// per-field bound inference does not add automatically.
pub struct HashedState<Id, K = String> {
    /// The underlying state map.
    pub state: SharedState<Id, K>,
    /// The incrementally updated cryptographic `LtHash`.
    pub hash: crate::state::lthash::LtHash,
}

impl<Id: Clone, K: Ord + Clone> Clone for HashedState<Id, K> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            hash: self.hash,
        }
    }
}

impl<Id: core::fmt::Debug, K: Ord + core::fmt::Debug> core::fmt::Debug for HashedState<Id, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HashedState")
            .field("state", &self.state)
            .field("hash", &self.hash)
            .finish()
    }
}

impl<Id, K: Ord + Clone> Default for HashedState<Id, K> {
    fn default() -> Self {
        Self {
            state: SharedState::new(),
            hash: crate::state::lthash::LtHash::default(),
        }
    }
}

impl<Id, K> HashedState<Id, K>
where
    Id: crate::basespec::rezzy_types::EventId,
    K: Ord + Clone + AsRef<str>,
{
    /// Creates a new empty `HashedState`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Incremental insertion of a state entry into both the map and `LtHash`.
    pub fn insert(&mut self, key: (EventType, K), event_id: Id) {
        if let Some(old_id) = self.state.get(&key) {
            self.hash.remove(key.0.as_str(), key.1.as_ref(), old_id);
        }
        self.hash.insert(key.0.as_str(), key.1.as_ref(), &event_id);
        self.state.insert(key, event_id);
    }
}

/// Resolve multiple parent states using LtHash-based fast-path detection.
///
/// If all parent states are identical (verified by `LtHash` + `ptr_eq` + full equality),
/// returns the first state directly. Otherwise falls back to full state resolution.
/// TODO: swap the state payload over to the HAMT-backed structure so this
/// fast path can reuse more structure across fork-heavy merges.
///
/// # Panics
///
/// Panics if `prev_states` is empty. At least 2 entries are needed for meaningful merging.
pub fn resolve_merge_fast_path_hashed<Id, C, S, K>(
    prev_states: &[HashedState<Id, K>],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    global_auth_cache: &mut LocalAuthCache<Id, C, K>,
    version: StateResVersion,
) -> HashedState<Id, K>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    resolve_merge_fast_path_hashed_with_cache(
        prev_states,
        events_map,
        global_auth_cache,
        &mut FastMap::default(),
        version,
    )
}

/// Like [`resolve_merge_fast_path_hashed`], but additionally accepts a
/// `mainline_cache` that callers invoking this repeatedly against the same DAG
/// (e.g. [`run_state_pipeline_streaming_optimized`]'s fork-merge loop) can
/// thread across calls, so `build_mainline`'s BFS-per-call turns into an
/// `O(M)` cache-hit walk instead of restarting from scratch every time.
fn resolve_merge_fast_path_hashed_with_cache<Id, C, S, K>(
    prev_states: &[HashedState<Id, K>],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    global_auth_cache: &mut LocalAuthCache<Id, C, K>,
    mainline_cache: &mut FastMap<Id, Option<Id>>,
    version: StateResVersion,
) -> HashedState<Id, K>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let first = &prev_states[0];

    // Fast-path comparison design:
    // - first.hash == state.hash serves as an O(1) negative filter.
    // - first.state.ptr_eq(...) serves as an O(1) positive proof of identity.
    // - first.state == state.state serves as the ultimate authority for defense-in-depth,
    //   protecting against hypothetical full-lattice collisions (requiring a ~2^200 SIS solution).
    let all_match = prev_states[1..].iter().all(|state| {
        first.hash == state.hash && (first.state.ptr_eq(&state.state) || first.state == state.state)
    });

    if all_match {
        first.clone()
    } else {
        let shared_states: Vec<SharedState<Id, K>> =
            prev_states.iter().map(|s| s.state.clone()).collect();
        let resolved = resolve_multiple_prev_states(
            &shared_states,
            events_map,
            global_auth_cache,
            mainline_cache,
            version,
        );

        // Incremental LtHash update from the first parent state!
        let mut hash = first.hash;
        for diff_item in first.state.diff(&resolved) {
            match diff_item {
                imbl::ordmap::DiffItem::Add(key, new_id) => {
                    hash.insert(key.0.as_str(), key.1.as_ref(), new_id);
                }
                imbl::ordmap::DiffItem::Remove(key, old_id) => {
                    hash.remove(key.0.as_str(), key.1.as_ref(), old_id);
                }
                imbl::ordmap::DiffItem::Update {
                    old: (key, old_id),
                    new: (_, new_id),
                } => {
                    hash.remove(key.0.as_str(), key.1.as_ref(), old_id);
                    hash.insert(key.0.as_str(), key.1.as_ref(), new_id);
                }
            }
        }

        HashedState {
            state: resolved,
            hash,
        }
    }
}

fn run_state_pipeline_streaming_optimized<'a, Id, C, S, F, E, K>(
    index_to_id: &[&'a Id],
    id_to_index: &FastMap<&'a Id, usize>,
    is_target: &[bool],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    mut on_target: F,
) -> Result<(), StateComputationError<E>>
where
    Id: crate::basespec::rezzy_types::EventId,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    F: for<'b> FnMut(usize, StateUpdate<'b, Id, K>) -> Result<(), E>,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let (sorted_ancestors, mut out_degree) =
        topological_sort_short_ids(index_to_id, id_to_index, events_map);

    if sorted_ancestors.len() != index_to_id.len() {
        return Err(StateComputationError::CycleDetected);
    }

    let mut global_auth_cache = LocalAuthCache::new(version);
    let mut mainline_cache: FastMap<Id, Option<Id>> = FastMap::default();

    let mut state_after_map: Vec<Option<HashedState<Id, K>>> = core::iter::repeat_with(|| None)
        .take(index_to_id.len())
        .collect();

    for idx in sorted_ancestors {
        let id_val = index_to_id[idx];
        let ev = events_map.get(id_val).unwrap();

        let mut prev_states = Vec::with_capacity(ev.prev_events.len());
        let mut seen_parents = if ev.prev_events.len() > 1 {
            Some(crate::FastSet::default())
        } else {
            None
        };
        for pe in &ev.prev_events {
            let Some(&pe_idx) = id_to_index.get(pe) else {
                continue;
            };
            // Dedup: adversarial events may carry duplicate prev_events.
            // Without this, out_degree is decremented twice for one child,
            // causing premature take() and wrong merge results.
            if let Some(seen) = &mut seen_parents {
                if !seen.insert(pe_idx) {
                    continue;
                }
            }
            out_degree[pe_idx] = out_degree[pe_idx].saturating_sub(1);
            if out_degree[pe_idx] == 0 {
                if let Some(pe_state) = state_after_map[pe_idx].take() {
                    prev_states.push(pe_state);
                }
            } else if let Some(ref pe_state) = state_after_map[pe_idx] {
                prev_states.push(pe_state.clone());
            }
        }

        let is_state = ev.state_key.is_some();
        let has_single_parent = prev_states.len() == 1;

        let mut state_before: HashedState<Id, K> = if prev_states.is_empty() {
            HashedState::new()
        } else if has_single_parent && !is_state {
            let parent_state = prev_states.into_iter().next().unwrap();
            if is_target[idx] {
                on_target(
                    idx,
                    StateUpdate::Unchanged {
                        parent_event_id: ev
                            .prev_events
                            .iter()
                            .find(|pe| id_to_index.contains_key(*pe))
                            .expect("has_single_parent implies at least one prev_event is in id_to_index"),
                        hash: &parent_state.hash,
                    },
                )
                .map_err(StateComputationError::Callback)?;
            }
            if out_degree[idx] > 0 {
                state_after_map[idx] = Some(parent_state);
            }
            continue;
        } else if has_single_parent {
            prev_states.into_iter().next().unwrap()
        } else {
            resolve_merge_fast_path_hashed_with_cache(
                &prev_states,
                events_map,
                &mut global_auth_cache,
                &mut mainline_cache,
                version,
            )
        };

        if is_state {
            let key = (
                EventType::from(ev.event_type.as_str()),
                ev.state_key.clone().unwrap_or_default(),
            );
            state_before.insert(key, ev.event_id.clone());
        }

        if is_target[idx] {
            on_target(
                idx,
                StateUpdate::New {
                    state: state_before.state.clone(),
                    hash: &state_before.hash,
                },
            )
            .map_err(StateComputationError::Callback)?;
        }

        if out_degree[idx] > 0 {
            state_after_map[idx] = Some(state_before);
        }
    }

    Ok(())
}

/// A high-performance, fallible variant of [`compute_state_at_streaming`] designed for
/// massive rebuild pipelines.
///
/// Rather than cloning full `SharedState` maps for every target, this function yields
/// `StateUpdate` events that support zero-clone streaming when states are unchanged
/// from their parent, and $O(1)$ LtHash-based matching.
///
/// # Errors
/// Returns `StateComputationError::CycleDetected` if a cycle is found in the reachable graph.
/// Returns `StateComputationError::Callback(e)` if the callback yields an error.
///
/// # Behavior
/// Duplicate target IDs are silently deduplicated, and targets absent from `events_map`
/// are dropped. The callback count may therefore be less than the input count.
pub fn try_compute_state_at_streaming_optimized<Id, C, Q, S, F, E, K>(
    target_event_ids: &[&Q],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    mut on_target_resolved: F,
) -> Result<(), StateComputationError<E>>
where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    F: for<'b> FnMut(Id, StateUpdate<'b, Id, K>) -> Result<(), E>,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let mut actual_target_ids = Vec::new();
    let mut seen = alloc::collections::BTreeSet::new();
    for &tid in target_event_ids {
        if let Some((k, _)) = events_map.get_key_value(tid) {
            if seen.insert(k) {
                actual_target_ids.push(k.clone());
            }
        }
    }

    if actual_target_ids.is_empty() {
        return Ok(());
    }

    let target_refs: Vec<&Id> = actual_target_ids.iter().collect();
    let (id_to_index, index_to_id) = collect_ancestor_short_ids_batch(&target_refs, events_map);

    let mut is_target = alloc::vec![false; index_to_id.len()];
    for tid in &actual_target_ids {
        if let Some(&idx) = id_to_index.get(tid) {
            is_target[idx] = true;
        }
    }

    run_state_pipeline_streaming_optimized(
        &index_to_id,
        &id_to_index,
        &is_target,
        events_map,
        version,
        |idx, update| {
            let id = index_to_id[idx].clone();
            on_target_resolved(id, update)
        },
    )
}

/// A high-performance, non-fallible variant of [`compute_state_at_streaming`] designed for
/// massive rebuild pipelines.
///
/// Returns `true` if the graph traversal completed successfully, or `false` if a cycle
/// was detected in the reachable subgraph.
#[must_use = "a `false` return means a cycle was detected and results are incomplete; silently discarding it defeats the purpose of cycle detection"]
pub fn compute_state_at_streaming_optimized<Id, C, Q, S, F, K>(
    target_event_ids: &[&Q],
    events_map: &HashMap<Id, LeanEvent<Id, C, K>, S>,
    version: StateResVersion,
    mut on_target_resolved: F,
) -> bool
where
    Id: crate::basespec::rezzy_types::EventId + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    F: for<'b> FnMut(Id, StateUpdate<'b, Id, K>),
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let result = try_compute_state_at_streaming_optimized(
        target_event_ids,
        events_map,
        version,
        |id, update| -> Result<(), core::convert::Infallible> {
            on_target_resolved(id, update);
            Ok(())
        },
    );

    match result {
        Ok(()) => true,
        Err(StateComputationError::CycleDetected) => false,
        Err(StateComputationError::Callback(infallible)) => match infallible {},
    }
}

/// Computes the true forward extremities (DAG leaves) from a batched set of events.
/// This uses `RoaringBitmap` set differences (`all_events - all_parents`) to
/// instantly find the leaves of a DAG, no matter how deep.
///
/// # Arguments
/// - `events`: An iterator yielding tuples of `(event_id, prev_event_ids)`.
///
/// # Returns
/// A `Vec<Id>` of all events that are not referenced as a `prev_event` by any other event in the set.
///
/// # Panics
/// Panics if the number of distinct event IDs exceeds `u32::MAX`.
#[cfg(feature = "std")]
pub fn find_forward_extremities_roaring<Id, I, P>(events: I) -> alloc::vec::Vec<Id>
where
    Id: core::hash::Hash + Eq + Clone,
    I: IntoIterator<Item = (Id, P)>,
    P: IntoIterator<Item = Id>,
{
    use roaring::RoaringBitmap;
    let mut id_map = crate::HashMap::default();
    let mut reverse_map = alloc::vec::Vec::new();

    let get_or_insert = |id: Id,
                         id_map: &mut crate::HashMap<Id, u32>,
                         reverse_map: &mut alloc::vec::Vec<Id>|
     -> u32 {
        *id_map.entry(id).or_insert_with_key(|id| {
            let idx = u32::try_from(reverse_map.len()).expect("event count exceeds u32");
            reverse_map.push(id.clone());
            idx
        })
    };

    let mut all_events = RoaringBitmap::new();
    let mut has_children = RoaringBitmap::new();

    for (id, prevs) in events {
        let idx = get_or_insert(id, &mut id_map, &mut reverse_map);
        all_events.insert(idx);

        for prev_id in prevs {
            let prev_idx = get_or_insert(prev_id, &mut id_map, &mut reverse_map);
            has_children.insert(prev_idx);
        }
    }

    let extremities_bitmap = core::ops::Sub::sub(all_events, has_children);

    let mut extremities =
        alloc::vec::Vec::with_capacity(usize::try_from(extremities_bitmap.len()).unwrap());
    for idx in extremities_bitmap {
        extremities.push(reverse_map[idx as usize].clone());
    }

    extremities
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::auth::StateProvider;
    use crate::basespec::event_types::M_ROOM_POWER_LEVELS;
    use alloc::string::ToString;
    use alloc::vec;
    use serde_json::json;
    use std::collections::BTreeSet;

    #[test]
    fn test_conflicted_auth_event_validation_in_power_phase() {
        // Create a minimal room context
        let create_ev = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            sender: "@admin:example.com".into(),
            content: json!({ "room_version": "11" }),
            ..Default::default()
        };

        // A conflicted power level event where @bot has PL 100
        let pl_bot = LeanEvent {
            event_id: "$pl_bot".into(),
            event_type: "m.room.power_levels".into(),
            sender: "@admin:example.com".into(),
            content: json!({ "users": { "@bot:example.com": 100 } }),
            prev_events: vec!["$create".to_string()],
            auth_events: vec!["$create".to_string()],
            ..Default::default()
        };

        // A conflicted join event of the sender (@bot)
        let bot_join = LeanEvent {
            event_id: "$bot_join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bot:example.com".into()),
            sender: "@bot:example.com".into(),
            content: json!({ "membership": "join" }),
            prev_events: vec!["$pl_bot".to_string()],
            auth_events: vec!["$create".to_string(), "$pl_bot".to_string()],
            ..Default::default()
        };

        // A state event (m.room.topic) sent by @bot (which requires PL 50 if no power levels event is resolved)
        let bot_msg = LeanEvent {
            event_id: "$bot_msg".into(),
            event_type: "m.room.topic".into(),
            state_key: Some(String::new()),
            sender: "@bot:example.com".into(),
            content: json!({ "topic": "hello" }),
            prev_events: vec!["$bot_join".to_string()],
            auth_events: vec![
                "$create".to_string(),
                "$pl_bot".to_string(),
                "$bot_join".to_string(),
            ],
            ..Default::default()
        };

        let mut auth_context = HashMap::new();
        auth_context.insert("$create".to_string(), create_ev.clone());
        auth_context.insert("$pl_bot".to_string(), pl_bot.clone());
        auth_context.insert("$bot_join".to_string(), bot_join.clone());
        auth_context.insert("$bot_msg".to_string(), bot_msg.clone());

        let mut conflicted = HashMap::new();
        // Mark the power levels event as conflicted
        conflicted.insert("$pl_bot".to_string(), pl_bot.clone());

        // Create a resolved map where $pl_bot is NOT resolved yet (empty resolved map)
        let resolved = imbl::OrdMap::new();

        let local_auth = vec![
            (
                (EventType::from("m.room.create"), String::new()),
                create_ev.clone(),
            ),
            (
                (EventType::from("m.room.power_levels"), String::new()),
                pl_bot.clone(),
            ),
            (
                (
                    EventType::from("m.room.member"),
                    "@bot:example.com".to_string(),
                ),
                bot_join.clone(),
            ),
        ]
        .into_iter()
        .collect();

        // Under V2.1.1, during the power phase, a conflicted required auth event ($pl_bot)
        // that is NOT in resolved MUST be rejected!
        let is_ok = iterative_auth_ok(
            &bot_msg,
            &resolved,
            &auth_context,
            &conflicted,
            local_auth,
            Some(&create_ev),
            StateResVersion::V2_1_1,
            true, // is_power_phase
        );

        assert!(
            !is_ok,
            "The message must be rejected because the conflicted power levels event was not resolved!"
        );
    }

    /// Direct `V2.1` vs `V2.1.1` comparison for `OverlayState::get_event`'s
    /// power-phase local-auth fallback (lines ~122-168): confirms the *real*
    /// polarity of the version gate, since a first-pass reading of just the
    /// comments here ("gate the power-phase fallback behind V2.1.1+ only")
    /// suggested V2.1.1 is strictly more permissive than V2.1. Tracing the
    /// actual control flow (and `test_overlay_state_coverage_boosters` case 3
    /// below) shows the opposite: when the gate is *false* (V2.1, or any
    /// non-power-phase/non-required-type/non-power-candidate case), the code
    /// falls through to an unconditional `Some(ev)` -- V2.1 is the more
    /// permissive one. The gate only *narrows* things further, for V2.1.1+,
    /// when the query is a required type (`PL/join_rules`) mid-power-phase: it
    /// then additionally requires the candidate itself to be a power-shaped
    /// event before falling back to local auth, returning `None` otherwise.
    #[test]
    fn test_overlay_state_v2_1_vs_v2_1_1_power_phase_fallback_polarity() {
        let create_ev: LeanEvent<String, serde_json::Value> = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            sender: "@creator:example.com".into(),
            ..Default::default()
        };
        let pl_ev: LeanEvent<String, serde_json::Value> = LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            sender: "@creator:example.com".into(),
            ..Default::default()
        };

        // A required-type (PL) query, present in local_auth but not yet in
        // `resolved`, requested on behalf of a non-power candidate
        // (`m.room.message`) during the power phase.
        let build_overlay = |version: StateResVersion| {
            let resolved = imbl::OrdMap::new();
            let auth_context = HashMap::new();
            let mut sort_set = HashMap::new();
            sort_set.insert("$pl".to_string(), pl_ev.clone());
            let mut local_auth = BTreeMap::new();
            local_auth.insert(
                (EventType::from(M_ROOM_POWER_LEVELS), String::new()),
                pl_ev.clone(),
            );
            (resolved, auth_context, sort_set, local_auth, version)
        };

        let (resolved, auth_context, sort_set, local_auth, version) =
            build_overlay(StateResVersion::V2_1);
        let overlay_v21 = OverlayState {
            resolved: &resolved,
            auth_context: &auth_context,
            sort_set: &sort_set,
            local_auth,
            create_ev: Some(&create_ev),
            version,
            is_power_phase: true,
            candidate_event_type: "m.room.message",
        };
        assert!(
            overlay_v21.get_event(M_ROOM_POWER_LEVELS, "").is_some(),
            "V2.1 has no power-phase gate at all here -- it falls back to local \
             auth unconditionally, regardless of what kind of event is asking"
        );

        let (resolved, auth_context, sort_set, local_auth, version) =
            build_overlay(StateResVersion::V2_1_1);
        let overlay_v211 = OverlayState {
            resolved: &resolved,
            auth_context: &auth_context,
            sort_set: &sort_set,
            local_auth,
            create_ev: Some(&create_ev),
            version,
            is_power_phase: true,
            candidate_event_type: "m.room.message",
        };
        assert!(
            overlay_v211.get_event(M_ROOM_POWER_LEVELS, "").is_none(),
            "V2.1.1 is the *stricter* one here: a non-power candidate (a plain \
             message) may not bypass-authorize against an unresolved, only \
             locally-known power_levels event"
        );
    }

    /// Exercises the overlay-state fallback paths for resolved required events
    /// across all supported state-resolution versions.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_overlay_state_coverage_boosters() {
        let create_ev: LeanEvent<String, serde_json::Value> = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            sender: "@creator:example.com".into(),
            ..Default::default()
        };

        let pl_ev: LeanEvent<String, serde_json::Value> = LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            sender: "@creator:example.com".into(),
            ..Default::default()
        };

        let jr_ev: LeanEvent<String, serde_json::Value> = LeanEvent {
            event_id: "$jr".into(),
            event_type: "m.room.join_rules".into(),
            sender: "@creator:example.com".into(),
            ..Default::default()
        };

        let member_ban_ev: LeanEvent<String, serde_json::Value> = LeanEvent {
            event_id: "$member_ban".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@bannee:example.com".into()),
            sender: "@moderator:example.com".into(),
            ..Default::default()
        };

        // 1. Test case: resolved_id is found but the event is missing from both auth_context and sort_set (returns None).
        {
            let mut resolved = imbl::OrdMap::new();
            resolved.insert(
                (EventType::from(M_ROOM_POWER_LEVELS), String::new()),
                "$pl_missing".to_string(),
            );

            let auth_context = HashMap::new();
            let mut sort_set = HashMap::new();
            sort_set.insert("$pl".to_string(), pl_ev.clone());

            let mut local_auth = BTreeMap::new();
            local_auth.insert(
                (EventType::from(M_ROOM_POWER_LEVELS), String::new()),
                pl_ev.clone(),
            );

            let overlay = OverlayState {
                resolved: &resolved,
                auth_context: &auth_context,
                sort_set: &sort_set,
                local_auth,
                create_ev: Some(&create_ev),
                version: StateResVersion::V2_1_1,
                is_power_phase: true,
                candidate_event_type: M_ROOM_POWER_LEVELS,
            };

            let res = overlay.get_event(M_ROOM_POWER_LEVELS, "");
            assert!(res.is_none());
        }

        // 2. Test case: resolved_id is NOT found, and candidate_is_power is true (returns Some(ev)).
        {
            let resolved = imbl::OrdMap::new();
            let auth_context = HashMap::new();
            let mut sort_set = HashMap::new();
            sort_set.insert("$pl".to_string(), pl_ev.clone());

            let mut local_auth = BTreeMap::new();
            local_auth.insert(
                (EventType::from(M_ROOM_POWER_LEVELS), String::new()),
                pl_ev.clone(),
            );

            let overlay = OverlayState {
                resolved: &resolved,
                auth_context: &auth_context,
                sort_set: &sort_set,
                local_auth,
                create_ev: Some(&create_ev),
                version: StateResVersion::V2_1_1,
                is_power_phase: true,
                candidate_event_type: M_ROOM_POWER_LEVELS,
            };

            let res = overlay.get_event(M_ROOM_POWER_LEVELS, "");
            assert!(res.is_some());
            assert_eq!(res.unwrap().event_id, "$pl");
        }

        // 3. Test case: resolved_id is NOT found, and candidate_is_power is false (returns None).
        {
            let resolved = imbl::OrdMap::new();
            let auth_context = HashMap::new();
            let mut sort_set = HashMap::new();
            sort_set.insert("$pl".to_string(), pl_ev.clone());

            let mut local_auth = BTreeMap::new();
            local_auth.insert(
                (EventType::from(M_ROOM_POWER_LEVELS), String::new()),
                pl_ev.clone(),
            );

            let overlay = OverlayState {
                resolved: &resolved,
                auth_context: &auth_context,
                sort_set: &sort_set,
                local_auth,
                create_ev: Some(&create_ev),
                version: StateResVersion::V2_1_1,
                is_power_phase: true,
                candidate_event_type: "m.room.message",
            };

            let res = overlay.get_event(M_ROOM_POWER_LEVELS, "");
            assert!(res.is_none());
        }

        // 4. Test case: a required event (m.room.join_rules) that IS resolved.
        // V2.1.1 does not supplement join_rules, so the early resolved-state
        // return is skipped; the power-phase fallback (line 176) then returns
        // the resolved event itself.
        {
            let mut resolved = imbl::OrdMap::new();
            resolved.insert(
                (
                    EventType::from(crate::basespec::event_types::M_ROOM_JOIN_RULES),
                    String::new(),
                ),
                "$jr".to_string(),
            );

            let auth_context = HashMap::new();
            let mut sort_set = HashMap::new();
            sort_set.insert("$jr".to_string(), jr_ev.clone());

            let mut local_auth = BTreeMap::new();
            local_auth.insert(
                (
                    EventType::from(crate::basespec::event_types::M_ROOM_JOIN_RULES),
                    String::new(),
                ),
                jr_ev.clone(),
            );

            let overlay = OverlayState {
                resolved: &resolved,
                auth_context: &auth_context,
                sort_set: &sort_set,
                local_auth,
                create_ev: Some(&create_ev),
                version: StateResVersion::V2_1_1,
                is_power_phase: true,
                candidate_event_type: crate::basespec::event_types::M_ROOM_JOIN_RULES,
            };

            let res = overlay.get_event(crate::basespec::event_types::M_ROOM_JOIN_RULES, "");
            assert!(res.is_some());
            assert_eq!(res.unwrap().event_id, "$jr");
        }

        // 5. Test case: a resolved member ban is returned directly during
        // power-phase authorization across V2, V2.1, and V2.1.1.
        {
            let mut resolved = imbl::OrdMap::new();
            resolved.insert(
                (
                    EventType::from(crate::basespec::event_types::M_ROOM_MEMBER),
                    "@bannee:example.com".into(),
                ),
                "$member_ban".to_string(),
            );

            let auth_context = HashMap::new();
            let mut sort_set = HashMap::new();
            sort_set.insert("$member_ban".to_string(), member_ban_ev.clone());

            let candidate_event_type = "m.room.message";
            for version in [
                StateResVersion::V2,
                StateResVersion::V2_1,
                StateResVersion::V2_1_1,
            ] {
                let overlay = OverlayState {
                    resolved: &resolved,
                    auth_context: &auth_context,
                    sort_set: &sort_set,
                    local_auth: BTreeMap::new(),
                    create_ev: Some(&create_ev),
                    version,
                    is_power_phase: true,
                    candidate_event_type,
                };

                let res = overlay.get_event(
                    crate::basespec::event_types::M_ROOM_MEMBER,
                    "@bannee:example.com",
                );
                assert!(res.is_some());
                assert_eq!(res.unwrap().event_id, "$member_ban");
            }
        }

        // 6. Test case: no resolved event, but a matching local-auth candidate
        // for a required type, with a NON-power candidate. Under the V2.1+ gate
        // the unresolved conflicted power-level auth event must be rejected
        // (None) identically for V2.1 and V2.1.1. This diverges from the old
        // code, which returned the local-auth event for V2.1 (its gate excluded
        // V2.1), so the test fails against the previous implementation.
        {
            let resolved = imbl::OrdMap::new();
            let auth_context = HashMap::new();
            let mut sort_set = HashMap::new();
            sort_set.insert("$pl".to_string(), pl_ev.clone());

            let mut local_auth = BTreeMap::new();
            local_auth.insert(
                (EventType::from(M_ROOM_POWER_LEVELS), String::new()),
                pl_ev.clone(),
            );

            for version in [StateResVersion::V2_1, StateResVersion::V2_1_1] {
                let overlay = OverlayState {
                    resolved: &resolved,
                    auth_context: &auth_context,
                    sort_set: &sort_set,
                    local_auth: local_auth.clone(),
                    create_ev: Some(&create_ev),
                    version,
                    is_power_phase: true,
                    candidate_event_type: "m.room.message",
                };
                let res = overlay.get_event(M_ROOM_POWER_LEVELS, "");
                assert!(
                    res.is_none(),
                    "a non-power candidate must not authorize an unresolved conflicted power-level auth event (V2.1 and V2.1.1 alike)"
                );
            }
        }
    }

    /// Coverage: `LocalAuthCache` hit path (at.rs:263-268).
    /// Calls `compute_local_auth` twice for the same event. Second call returns
    /// from cache without re-walking the auth chain.
    #[test]
    fn test_find_forward_extremities_roaring_empty() {
        let extremities = find_forward_extremities_roaring::<String, _, Vec<String>>(Vec::new());
        assert!(extremities.is_empty());
    }

    #[test]
    fn test_find_forward_extremities_roaring_leaf_detection() {
        let extremities = find_forward_extremities_roaring(vec![
            ("$a".to_string(), Vec::<String>::new()),
            ("$b".to_string(), vec!["$a".to_string()]),
            ("$c".to_string(), vec!["$a".to_string()]),
            ("$d".to_string(), vec!["$b".to_string(), "$c".to_string()]),
            ("$e".to_string(), vec!["$c".to_string()]),
        ]);

        let actual: BTreeSet<String> = extremities.into_iter().collect();
        let expected: BTreeSet<String> = ["$d".to_string(), "$e".to_string()].into_iter().collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_find_forward_extremities_roaring_disconnected_and_chain() {
        let extremities = find_forward_extremities_roaring(vec![
            ("$root".to_string(), Vec::<String>::new()),
            ("$mid".to_string(), vec!["$root".to_string()]),
            ("$leaf".to_string(), vec!["$mid".to_string()]),
            ("$isolated".to_string(), Vec::<String>::new()),
        ]);

        let actual: BTreeSet<String> = extremities.into_iter().collect();
        let expected: BTreeSet<String> = ["$leaf".to_string(), "$isolated".to_string()]
            .into_iter()
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_local_auth_cache_hit() {
        let create_ev: LeanEvent = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@alice:x".into(),
            depth: 1,
            content: json!({"room_version": "10", "creator": "@alice:x"}),
            ..Default::default()
        };
        let join_ev: LeanEvent = LeanEvent {
            event_id: "$join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:x".into()),
            sender: "@alice:x".into(),
            depth: 2,
            auth_events: vec!["$create".into()],
            content: json!({"membership": "join"}),
            ..Default::default()
        };
        let topic_ev: LeanEvent = LeanEvent {
            event_id: "$topic".into(),
            event_type: "m.room.topic".into(),
            state_key: Some(String::new()),
            sender: "@alice:x".into(),
            depth: 3,
            auth_events: vec!["$create".into(), "$join".into()],
            content: json!({"topic": "hello"}),
            ..Default::default()
        };

        let mut auth_context: HashMap<String, LeanEvent> =
            [("$create".into(), create_ev), ("$join".into(), join_ev)]
                .into_iter()
                .collect();

        let conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let mut cache = LocalAuthCache::new(StateResVersion::V2);

        // First call: populates cache
        let result1 = compute_local_auth(
            &topic_ev,
            &auth_context,
            &conflicted,
            &mut cache,
            StateResVersion::V2,
        );
        assert!(
            cache.map.contains_key("$topic"),
            "Cache must be populated after first call"
        );
        let cache_len_after_first = cache.map.len();

        // Mutate auth_context so a fresh (non-cached) re-computation would
        // produce a DIFFERENT result. If the cache hit works, result2 will
        // still equal result1 (the stale cached value).
        auth_context.remove("$join");

        // Second call: must hit cache early return
        let result2 = compute_local_auth(
            &topic_ev,
            &auth_context,
            &conflicted,
            &mut cache,
            StateResVersion::V2,
        );

        // Cache size must not grow (no re-insert)
        assert_eq!(
            cache.map.len(),
            cache_len_after_first,
            "Cache must not grow on cache hit"
        );

        // Cached result must match original, proving the cache was used
        // (a fresh computation with $join removed would differ)
        assert_eq!(result1, result2, "Cached result must match uncached result");
    }

    /// Regression test: paginating a forked DAG must never produce
    /// duplicate events or violate topological ordering.
    ///
    /// DAG shape:
    /// ```text
    ///         A (depth=1)
    ///        / \
    ///       B   C (fork: B at depth 2, C at depth 5)
    ///       |   |
    ///       D   |  (D at depth 3)
    ///        \ /
    ///         E (merge: depth 6)
    /// ```
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn test_forked_dag_pagination_no_duplicates() {
        let a = LeanEvent {
            event_id: "A".into(),
            depth: 1,
            prev_events: vec![],
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            content: json!({"room_version": "10", "creator": "@x:x"}),
            ..Default::default()
        };
        let b = LeanEvent {
            event_id: "B".into(),
            depth: 2,
            prev_events: vec!["A".into()],
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            ..Default::default()
        };
        let c = LeanEvent {
            event_id: "C".into(),
            depth: 5,
            prev_events: vec!["A".into()],
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            ..Default::default()
        };
        let d = LeanEvent {
            event_id: "D".into(),
            depth: 3,
            prev_events: vec!["B".into()],
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            ..Default::default()
        };
        let e = LeanEvent {
            event_id: "E".into(),
            depth: 6,
            prev_events: vec!["C".into(), "D".into()],
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);
        events_map.insert("C".into(), c);
        events_map.insert("D".into(), d);
        events_map.insert("E".into(), e);

        // Get the reference ordering
        let order = reverse_topological_order("E", &events_map, |a: &String, b: &String| {
            a.cmp(b).reverse()
        });
        assert_eq!(order.len(), 5, "all 5 events should be reachable");

        // Simulate pages of size 2
        let pages: Vec<Vec<String>> = order
            .chunks(2)
            .map(<[std::string::String]>::to_vec)
            .collect();

        let violations = verify_pagination(&events_map, &pages);
        assert!(
            violations.is_empty(),
            "pagination must have no violations, got: {violations:?}"
        );
    }

    /// Test that `compute_depths` produces correct depths for a forked DAG.
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn test_compute_depths_forked_dag() {
        let a = LeanEvent {
            event_id: "A".into(),
            prev_events: vec![],
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            content: json!({"room_version": "10", "creator": "@x:x"}),
            ..Default::default()
        };
        let b = LeanEvent {
            event_id: "B".into(),
            prev_events: vec!["A".into()],
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            ..Default::default()
        };
        let c = LeanEvent {
            event_id: "C".into(),
            prev_events: vec!["A".into()],
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            ..Default::default()
        };
        let d = LeanEvent {
            event_id: "D".into(),
            prev_events: vec!["B".into(), "C".into()],
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);
        events_map.insert("C".into(), c);
        events_map.insert("D".into(), d);

        let depths = compute_depths(&events_map);
        assert_eq!(depths["A"], 1, "root has depth 1");
        assert_eq!(depths["B"], 2, "B is child of A");
        assert_eq!(depths["C"], 2, "C is child of A");
        assert_eq!(depths["D"], 3, "D is child of max(B, C) + 1");
    }

    /// Coverage: `compute_topo_positions` with empty input (line 1447).
    #[test]
    fn test_compute_topo_positions_empty() {
        let events_map: HashMap<String, LeanEvent> = HashMap::new();
        let result = compute_topo_positions(&events_map, core::cmp::Ord::cmp);
        assert!(result.is_empty());
    }

    /// Coverage: `compute_depths` with empty input (line 1520).
    #[test]
    fn test_compute_depths_empty() {
        let events_map: HashMap<String, LeanEvent> = HashMap::new();
        let result = compute_depths(&events_map);
        assert!(result.is_empty());
    }

    /// `find_depth_divergences` must stay silent when every child's wire
    /// `depth` exceeds its parent's, even on a full-DAG view.
    #[test]
    fn test_find_depth_divergences_no_divergence() {
        let a = LeanEvent {
            event_id: "A".into(),
            prev_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let b = LeanEvent {
            event_id: "B".into(),
            prev_events: vec!["A".into()],
            depth: 2,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);

        let divergences = find_depth_divergences(&events_map);
        assert!(
            divergences.is_empty(),
            "expected no divergences, got: {divergences:?}"
        );
    }

    /// `find_depth_divergences` must NOT flag a partial view (the shape of
    /// a real backfill gap-fill batch) just because it doesn't reach back
    /// to `m.room.create` — a genuinely legitimate pair of consecutive
    /// wire depths (e.g. 26/27) whose parent above the gap isn't loaded
    /// must not be reported as a divergence.
    #[test]
    fn test_find_depth_divergences_ignores_edges_outside_the_batch() {
        // "A" (parent of B) deliberately NOT inserted — it's above the gap.
        let b = LeanEvent {
            event_id: "B".into(),
            prev_events: vec!["A".into()],
            depth: 26,
            ..Default::default()
        };
        let c = LeanEvent {
            event_id: "C".into(),
            prev_events: vec!["B".into()],
            depth: 27,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("B".into(), b);
        events_map.insert("C".into(), c);

        let divergences = find_depth_divergences(&events_map);
        assert!(
            divergences.is_empty(),
            "edges to a parent outside the batch must not be flagged, got: {divergences:?}"
        );
    }

    /// `find_depth_divergences` must flag an edge whose child's claimed
    /// `depth` doesn't exceed its parent's — simulating a byzantine/buggy
    /// peer attaching a `depth` that's structurally impossible given the
    /// parent it also claims.
    #[test]
    fn test_find_depth_divergences_detects_non_monotonic_edge() {
        let a = LeanEvent {
            event_id: "A".into(),
            prev_events: vec![],
            depth: 5,
            ..Default::default()
        };
        // B claims to be a child of A but claims a *lower* depth than A.
        let b = LeanEvent {
            event_id: "B".into(),
            prev_events: vec!["A".into()],
            depth: 3,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);

        let divergences = find_depth_divergences(&events_map);
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].parent, "A");
        assert_eq!(divergences[0].child, "B");
        assert_eq!(divergences[0].parent_depth, 5);
        assert_eq!(divergences[0].child_depth, 3);
    }

    /// `find_depth_divergences` must not flag an edge whose parent sits at
    /// saturated depth (`u64::MAX`): a correct sender clamps at the
    /// maximum rather than incrementing past it, so `child.depth <=
    /// parent.depth` at saturation is expected, not a violation.
    #[test]
    fn test_find_depth_divergences_ignores_saturated_parent() {
        let a = LeanEvent {
            event_id: "A".into(),
            prev_events: vec![],
            depth: u64::MAX,
            ..Default::default()
        };
        let b = LeanEvent {
            event_id: "B".into(),
            prev_events: vec!["A".into()],
            depth: u64::MAX, // correctly clamped, not incremented
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);

        let divergences = find_depth_divergences(&events_map);
        assert!(
            divergences.is_empty(),
            "saturated parent depth must not be flagged, got: {divergences:?}"
        );
    }

    /// `resolve_gap_fill_order` must recover the correct total order from
    /// `prev_events` edges even when wire `depth` is wildly wrong — the
    /// wrong `depth` value must not influence the derived order at all.
    #[test]
    fn test_resolve_gap_fill_order_ignores_wire_depth() {
        let a = LeanEvent {
            event_id: "A".into(),
            prev_events: vec![],
            depth: 9999, // implausible wire depth, should be ignored entirely
            ..Default::default()
        };
        let b = LeanEvent {
            event_id: "B".into(),
            prev_events: vec!["A".into()],
            depth: 1, // claims to be *before* its own parent
            ..Default::default()
        };
        let c = LeanEvent {
            event_id: "C".into(),
            prev_events: vec!["B".into()],
            depth: 2,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);
        events_map.insert("C".into(), c);

        let order = resolve_gap_fill_order(&events_map, core::cmp::Ord::cmp);
        assert_eq!(
            order,
            vec!["A".to_string(), "B".to_string(), "C".to_string()]
        );
    }

    /// Coverage: `reverse_topological_order` with missing tip (line 1576).
    #[test]
    fn test_reverse_topological_order_missing_tip() {
        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                ..Default::default()
            },
        );
        let result = reverse_topological_order("missing_tip", &events_map, core::cmp::Ord::cmp);
        assert!(result.is_empty());
    }

    /// Coverage: `compute_auth_chain_diff` prune-early when conflicted ID
    /// is already in the unconflicted set (line 1187).
    #[test]
    fn test_auth_chain_diff_prune_shared_id() {
        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        let shared = LeanEvent {
            event_id: "shared".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@a:x".into()),
            sender: "@a:x".into(),
            depth: 1,
            content: json!({"membership": "join"}),
            ..Default::default()
        };
        events_map.insert("shared".into(), shared);

        // unconflicted state includes "shared"
        let mut unconflicted = imbl::OrdMap::new();
        unconflicted.insert(("m.room.member".into(), "@a:x".into()), "shared".into());

        // conflicted set ALSO references "shared" → prune early
        let mut conflicted = crate::HashSet::new();
        conflicted.insert("shared".to_string());

        let diff = compute_auth_chain_diff(&unconflicted, &conflicted, &events_map);
        // shared is in both sets, so the diff should be empty
        assert!(diff.is_empty(), "shared event should be pruned, empty diff");
    }

    /// Coverage / reachability probe for `compute_auth_chain_diff`'s defensive
    /// `else { continue }` guards (lines 1314 and 1329).
    ///
    /// The heap-based traversals only ever push an event id after verifying it
    /// is present in `events_map`, and `events_map` is immutable for the call,
    /// so a popped id is always present. This test drives the function with
    /// ids that are absent from `events_map` (in both `unconflicted_state` and
    /// `conflicted_state_set`) and with an event whose `auth_events` reference a
    /// missing id, exercising every skip-guard but confirming that the
    /// `else continue` branches themselves are never taken.
    #[test]
    fn test_auth_chain_diff_missing_ids_are_skipped_not_pushed() {
        // A genuine event with an auth_event that is NOT in events_map.
        let a = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@a:x".into()),
            sender: "@a:x".into(),
            depth: 2,
            content: json!({"membership": "join"}),
            auth_events: vec!["GHOST_AUTH".into()],
            ..Default::default()
        };
        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);

        // conflicted_state_set contains "A" (present) plus "GHOST_CONFLICT" (absent).
        let mut conflicted = crate::HashSet::new();
        conflicted.insert("A".to_string());
        conflicted.insert("GHOST_CONFLICT".to_string());

        // unconflicted_state maps a state entry to "GHOST_UNCONFLICTED" (absent).
        let mut unconflicted = imbl::OrdMap::new();
        unconflicted.insert(
            ("m.room.member".into(), "@ghost:x".into()),
            "GHOST_UNCONFLICTED".into(),
        );

        // Must not panic; absent ids are silently skipped rather than pushed.
        let diff = compute_auth_chain_diff(&unconflicted, &conflicted, &events_map);
        // "A" is in the conflicted set and not reachable from unconflicted, so it
        // lands in the diff; ghost ids are dropped.
        assert!(diff.contains("A"));
        assert!(!diff.contains("GHOST_CONFLICT"));
        assert!(!diff.contains("GHOST_UNCONFLICTED"));
        assert!(!diff.contains("GHOST_AUTH"));
    }

    /// Coverage: `compute_merge_base` when a popped event has no mask (line 908).
    /// This happens when an extremity references a `prev_event` that was pushed
    /// onto the heap but never had a mask entry (orphan in the graph).
    #[test]
    fn test_compute_merge_base_missing_mask_event() {
        use crate::state::at::compute_merge_base;

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        // A references B as prev_event, but B references C which doesn't exist
        events_map.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                depth: 3,
                prev_events: vec!["B".into()],
                ..Default::default()
            },
        );
        events_map.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                depth: 2,
                prev_events: vec!["orphan".into()],
                ..Default::default()
            },
        );
        // No "orphan" in map → when B tries to push orphan's parents, orphan won't be found
        // Two extremities that don't share a common ancestor
        events_map.insert(
            "X".into(),
            LeanEvent {
                event_id: "X".into(),
                depth: 3,
                prev_events: vec![],
                ..Default::default()
            },
        );

        let tips = vec!["A", "X"];
        let result = compute_merge_base(&tips, &events_map);
        assert!(result.is_none(), "disjoint DAGs have no merge base");
    }

    /// Coverage: missing event in `events_map` during `compute_state_at`.
    /// Simultaneously hits:
    /// - `collect_ancestor_short_ids_batch` line 967 continue
    /// - `topological_sort_short_ids` line 1002 continue
    /// - `compute_state_at` line 602 continue
    #[test]
    fn test_compute_state_at_with_missing_events_coverage() {
        let p = LeanEvent {
            event_id: "P".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            content: json!({"room_version": "10", "creator": "@admin:x"}),
            depth: 1,
            ..Default::default()
        };
        let a = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:x".into()),
            sender: "@alice:x".into(),
            content: json!({"membership": "join"}),
            depth: 2,
            prev_events: vec!["P".into()],
            auth_events: vec!["P".into()],
            ..Default::default()
        };
        // Event "C" is missing from events_map, but referenced by "D"
        let d = LeanEvent {
            event_id: "D".into(),
            event_type: "m.room.message".into(),
            sender: "@admin:x".into(),
            depth: 3,
            prev_events: vec!["A".into(), "C".into()],
            auth_events: vec!["P".into(), "A".into()],
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("P".into(), p);
        events_map.insert("A".into(), a);
        events_map.insert("D".into(), d);

        let result = compute_state_at(&"D".to_string(), &events_map, crate::StateResVersion::V2);
        assert!(result.is_some());
    }

    /// Coverage: `verify_pagination` when `events_map` is missing an event (line 1689).
    #[test]
    fn test_verify_pagination_missing_event() {
        use crate::state::at::verify_pagination;

        let events_map: HashMap<String, LeanEvent> = HashMap::new();
        // Page references an event not in the map
        let pages: Vec<Vec<String>> = vec![vec!["missing".into()]];
        let violations = verify_pagination(&events_map, &pages);
        // No panic, no violations (event silently skipped)
        assert!(
            violations.is_empty(),
            "missing event should be skipped, not crash"
        );
    }

    /// Coverage: `out_degree[pe_idx] == 0` continue in `compute_state_at`
    /// (line 601). This fires when a `prev_event` has already been fully
    /// consumed by all its children.
    #[test]
    fn test_compute_state_at_out_degree_zero() {
        // Diamond: A → B, A → C, B → D, C → D
        // When processing D, both B and C point to A.
        // After B consumes A's out_degree slot, C finds out_degree[A] == 0.
        let a = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            content: json!({"room_version": "10", "creator": "@x:x"}),
            depth: 1,
            ..Default::default()
        };
        let b = LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@x:x".into()),
            sender: "@x:x".into(),
            content: json!({"membership": "join"}),
            depth: 2,
            prev_events: vec!["A".into()],
            auth_events: vec!["A".into()],
            ..Default::default()
        };
        let c = LeanEvent {
            event_id: "C".into(),
            event_type: "m.room.topic".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            depth: 2,
            prev_events: vec!["A".into()],
            auth_events: vec!["A".into()],
            ..Default::default()
        };
        let d = LeanEvent {
            event_id: "D".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            depth: 3,
            prev_events: vec!["B".into(), "C".into()],
            auth_events: vec!["A".into(), "B".into()],
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);
        events_map.insert("C".into(), c);
        events_map.insert("D".into(), d);

        // compute_state_at traverses backwards from D. When both B and C
        // reference A, the out_degree bookkeeping must handle the second
        // reference finding out_degree[A] == 0.
        let result = compute_state_at(&"D".to_string(), &events_map, crate::StateResVersion::V2);
        assert!(result.is_some(), "should reconstruct state at D");
        let state = result.unwrap();
        // create event should be in state
        assert!(state.contains_key(&("m.room.create".into(), String::new())));
    }

    #[test]
    fn test_hashed_state_incremental() {
        let mut hs = HashedState::new();
        hs.insert(
            ("m.room.create".into(), String::new()),
            "create_event".to_string(),
        );
        hs.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "join_event".to_string(),
        );

        let expected_hash = crate::state::lthash::LtHash::from_state(&hs.state);
        assert_eq!(hs.hash, expected_hash);

        // Update an existing key
        hs.insert(
            ("m.room.member".into(), "@alice:x".into()),
            "new_join_event".to_string(),
        );
        let updated_hash = crate::state::lthash::LtHash::from_state(&hs.state);
        assert_eq!(hs.hash, updated_hash);
    }

    #[test]
    fn test_compute_state_at_streaming_cycle() {
        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert(
            "A".to_string(),
            LeanEvent {
                event_id: "A".to_string(),
                event_type: "m.room.message".to_string(),
                prev_events: vec!["B".to_string()],
                ..Default::default()
            },
        );
        events_map.insert(
            "B".to_string(),
            LeanEvent {
                event_id: "B".to_string(),
                event_type: "m.room.message".to_string(),
                prev_events: vec!["A".to_string()],
                ..Default::default()
            },
        );

        let target = ["A"];
        let completed = compute_state_at_streaming_optimized(
            &target,
            &events_map,
            StateResVersion::V2_1_1,
            |_, _| {},
        );
        assert!(
            !completed,
            "cycle A <-> B must be reported, not silently ignored"
        );
    }

    #[test]
    fn test_state_update_into_state_unchanged() {
        let mut parent_state: SharedState<String> = SharedState::new();
        parent_state.insert(
            ("m.room.create".into(), String::new()),
            "create_event".to_string(),
        );

        let hash = crate::state::lthash::LtHash::from_state(&parent_state);
        let parent_id = "parent_event".to_string();

        let update = StateUpdate::Unchanged {
            parent_event_id: &parent_id,
            hash: &hash,
        };

        let resolved = update.into_state(|id| {
            if id == "parent_event" {
                Some(parent_state.clone())
            } else {
                None
            }
        });

        assert_eq!(resolved, parent_state);
    }

    #[test]
    fn test_optimized_streaming_diamond() {
        let a = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            depth: 1,
            ..Default::default()
        };
        // State-changing event
        let b = LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.topic".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            depth: 2,
            prev_events: vec!["A".into()],
            auth_events: vec!["A".into()],
            ..Default::default()
        };
        // Non-state event inheriting parent state (single parent A)
        let c = LeanEvent {
            event_id: "C".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            depth: 2,
            prev_events: vec!["A".into()],
            auth_events: vec!["A".into()],
            ..Default::default()
        };
        // Merge event
        let d = LeanEvent {
            event_id: "D".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            depth: 3,
            prev_events: vec!["B".into(), "C".into()],
            auth_events: vec!["A".into()],
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);
        events_map.insert("C".into(), c);
        events_map.insert("D".into(), d);

        let mut b_has_new_state = false;
        let mut c_parent_unchanged_id = None;
        let mut d_has_new_state = false;

        let completed = compute_state_at_streaming_optimized(
            &["B", "C", "D"],
            &events_map,
            crate::StateResVersion::V2,
            |id, update| match id.as_str() {
                "B" => {
                    if matches!(update, StateUpdate::New { .. }) {
                        b_has_new_state = true;
                    }
                }
                "C" => {
                    if let StateUpdate::Unchanged {
                        parent_event_id, ..
                    } = update
                    {
                        c_parent_unchanged_id = Some(parent_event_id.clone());
                    }
                }
                "D" => {
                    if matches!(update, StateUpdate::New { .. }) {
                        d_has_new_state = true;
                    }
                }
                _ => {}
            },
        );

        // Assert updates are correct
        assert!(completed, "acyclic diamond graph must not report a cycle");
        assert!(b_has_new_state, "B should have been yielded as New!");
        assert_eq!(
            c_parent_unchanged_id.as_deref(),
            Some("A"),
            "C should have been yielded as Unchanged with parent A!"
        );
        assert!(d_has_new_state, "D should have been yielded as New!");
    }

    /// Coverage: `run_state_pipeline_streaming`'s `out_degree[pe_idx] == 0`
    /// continue, and `topological_sort_short_ids`'s parent-edge dedup
    /// continue. Both fire for the same scenario: an event that lists the
    /// same `prev_events` parent twice (a duplicate a byzantine/buggy peer
    /// could send). `topological_sort_short_ids` dedupes the duplicate when
    /// computing `out_degree`, so `out_degree[parent]` reflects one distinct
    /// child — the second occurrence in `D`'s own `prev_events` list then
    /// finds `out_degree` already driven to zero by the first occurrence.
    #[test]
    fn test_compute_state_at_duplicate_prev_events() {
        let a = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            content: json!({"room_version": "10", "creator": "@x:x"}),
            depth: 1,
            ..Default::default()
        };
        let b = LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            depth: 2,
            prev_events: vec!["A".into()],
            ..Default::default()
        };
        // D lists B twice as a parent.
        let d = LeanEvent {
            event_id: "D".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            depth: 3,
            prev_events: vec!["B".into(), "B".into()],
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);
        events_map.insert("D".into(), d);

        // Must not panic (e.g. double-take on B's state) and must resolve.
        let result = compute_state_at(&"D".to_string(), &events_map, crate::StateResVersion::V2);
        assert!(result.is_some());
    }

    /// Coverage: the `?`-propagated callback error path in
    /// `run_state_pipeline_streaming` (reached via `try_compute_state_at_streaming`).
    #[test]
    fn test_try_compute_state_at_streaming_propagates_callback_error() {
        let a = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            content: json!({"room_version": "10", "creator": "@x:x"}),
            depth: 1,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);

        let result: Result<(), StateComputationError<&'static str>> =
            try_compute_state_at_streaming(
                &["A"],
                &events_map,
                crate::StateResVersion::V2,
                |_, _| Err("callback aborted"),
            );

        assert_eq!(
            result,
            Err(StateComputationError::Callback("callback aborted"))
        );
    }

    /// Coverage: `try_compute_state_at_streaming` early-returns when all
    /// requested targets are absent from `events_map` (line 537).
    #[test]
    fn test_try_compute_state_at_streaming_with_no_resolvable_targets() {
        let events_map: HashMap<String, LeanEvent> = HashMap::new();
        let mut callback_called = false;

        let result = try_compute_state_at_streaming(
            &["ghost"],
            &events_map,
            crate::StateResVersion::V2,
            |_, _| {
                callback_called = true;
                Ok::<(), &'static str>(())
            },
        );

        assert_eq!(result, Ok(()));
        assert!(
            !callback_called,
            "callback must not run with no actual targets"
        );
    }

    /// Coverage: `collect_ancestor_short_ids_batch` (missing target, line 967)
    /// and `topological_sort_short_ids` (missing event, line 1002). Every
    /// current public call site pre-filters targets to ones present in
    /// `events_map`, so these guards are only reachable by calling the
    /// private helpers directly with an unfiltered target — which is exactly
    /// what these functions tolerate rather than assume away.
    #[test]
    fn test_collect_ancestor_and_topo_sort_tolerate_missing_target() {
        let a = LeanEvent {
            event_id: "A".into(),
            prev_events: vec![],
            depth: 1,
            ..Default::default()
        };
        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);

        // "ghost" is never inserted into events_map.
        let ghost = "ghost".to_string();
        let targets: Vec<&String> = alloc::vec![&ghost];

        let (id_to_index, index_to_id) = collect_ancestor_short_ids_batch(&targets, &events_map);
        assert_eq!(
            index_to_id.len(),
            1,
            "the unresolvable target still gets a short id"
        );
        assert!(id_to_index.contains_key(&ghost));

        // Must not panic when the topological sort walks an id absent from events_map.
        let (sorted, out_degree) =
            topological_sort_short_ids(&index_to_id, &id_to_index, &events_map);
        assert_eq!(sorted.len(), 1);
        assert_eq!(out_degree.len(), 1);
    }

    /// Coverage: `StateUpdate::into_state`'s `New` arm (the `Unchanged` arm
    /// is covered by `test_state_update_into_state_unchanged`).
    #[test]
    fn test_state_update_into_state_new() {
        let mut state: SharedState<String> = SharedState::new();
        state.insert(
            ("m.room.create".into(), String::new()),
            "create_event".into(),
        );
        let hash = crate::state::lthash::LtHash::from_state(&state);

        let update = StateUpdate::New {
            state: state.clone(),
            hash: &hash,
        };

        // The callback must never be invoked for the `New` arm.
        let resolved = update.into_state(|_| panic!("New must not consult the parent lookup"));
        assert_eq!(resolved, state);
    }

    /// Coverage: `resolve_merge_fast_path_hashed`'s defense-in-depth full
    /// equality check — two independently built states with identical
    /// content (same `LtHash`, same entries) but distinct allocations
    /// (`ptr_eq` false), simulating two DAG branches that converge on the
    /// same room state through different edit histories.
    #[test]
    fn test_resolve_merge_fast_path_hashed_full_equality_fallback() {
        let mut state_a: SharedState<String> = SharedState::new();
        state_a.insert(("m.room.topic".into(), String::new()), "final".into());
        let hash_a = crate::state::lthash::LtHash::from_state(&state_a);

        let mut state_b: SharedState<String> = SharedState::new();
        state_b.insert(("m.room.topic".into(), String::new()), "final".into());
        let hash_b = crate::state::lthash::LtHash::from_state(&state_b);

        assert_eq!(hash_a, hash_b, "identical content must hash identically");
        assert!(
            !state_a.ptr_eq(&state_b),
            "must be distinct allocations to exercise the full-equality fallback, \
             not just the ptr_eq fast path"
        );

        let prev_states = alloc::vec![
            HashedState {
                state: state_a.clone(),
                hash: hash_a,
            },
            HashedState {
                state: state_b,
                hash: hash_b,
            },
        ];

        let events_map: HashMap<String, LeanEvent> = HashMap::new();
        let mut cache = LocalAuthCache::new(crate::StateResVersion::V2);
        let result = resolve_merge_fast_path_hashed(
            &prev_states,
            &events_map,
            &mut cache,
            crate::StateResVersion::V2,
        );

        assert_eq!(
            result.state, state_a,
            "matching content must take the fast path rather than re-resolving"
        );
    }

    /// Coverage: the deterministic sort comparator in `find_depth_divergences`
    /// only runs when there are 2+ divergences to order.
    #[test]
    fn test_find_depth_divergences_sorts_multiple_results() {
        let a = LeanEvent {
            event_id: "A".into(),
            prev_events: vec![],
            depth: 10,
            ..Default::default()
        };
        // Two independent non-monotonic children of A, inserted in an order
        // that requires the comparator to actually reorder them.
        let z = LeanEvent {
            event_id: "Z".into(),
            prev_events: vec!["A".into()],
            depth: 1,
            ..Default::default()
        };
        let b = LeanEvent {
            event_id: "B".into(),
            prev_events: vec!["A".into()],
            depth: 2,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("Z".into(), z);
        events_map.insert("B".into(), b);

        let divergences = find_depth_divergences(&events_map);
        assert_eq!(divergences.len(), 2);
        // Sorted by (parent, child): both share parent "A", so child order breaks the tie.
        assert_eq!(divergences[0].child, "B");
        assert_eq!(divergences[1].child, "Z");
    }

    fn init_state() -> SharedState<String, String> {
        let mut state: SharedState<String, String> = SharedState::new();
        state.insert(
            (
                EventType::from("m.room.member"),
                "@alice:example.com".to_string(),
            ),
            "$evt".to_string(),
        );
        state
    }

    static ZERO_HASH: crate::state::lthash::LtHash = crate::state::lthash::LtHash([0; 1024]);
    static ONE_HASH: crate::state::lthash::LtHash = crate::state::lthash::LtHash([1; 1024]);

    fn new_update() -> StateUpdate<'static, String, String> {
        StateUpdate::New {
            state: init_state(),
            hash: &ZERO_HASH,
        }
    }

    /// Coverage: `Debug for StateUpdate` must print the correct variant name.
    #[test]
    fn test_state_update_debug() {
        // New variant formats as `New { state: ..., hash: ... }`.
        let f = alloc::format!("{:?}", new_update());
        assert!(
            f.contains("New"),
            "debug output should name the New variant: {f}"
        );
        assert!(f.contains("state"));
        assert!(f.contains("hash"));

        // Unchanged variant formats as `Unchanged { parent_event_id: ..., hash: ... }`.
        let parent = String::from("$parent");
        let test_unchanged: StateUpdate<'_, String, String> = StateUpdate::Unchanged {
            parent_event_id: &parent,
            hash: &ZERO_HASH,
        };
        let f = alloc::format!("{test_unchanged:?}");
        assert!(
            f.contains("Unchanged"),
            "debug output should name the Unchanged variant: {f}"
        );
        assert!(f.contains("parent_event_id"));
        assert!(f.contains("hash"));
    }

    /// Coverage: `Clone for StateUpdate` must deep-clone the state and copy the hash.
    #[test]
    fn test_state_update_clone() {
        let new = new_update();
        assert_eq!(new.clone(), new);

        let parent = String::from("$parent");
        let unchanged: StateUpdate<'_, String, String> = StateUpdate::Unchanged {
            parent_event_id: &parent,
            hash: &ZERO_HASH,
        };
        assert_eq!(unchanged.clone(), unchanged);
    }

    /// Coverage: `PartialEq for StateUpdate` must compare variant-specific fields.
    #[test]
    fn test_state_update_partial_eq() {
        // Same New (identical state map and hash) compares equal.
        assert_eq!(new_update(), new_update());

        // New with a different hash compares unequal.
        let a = new_update();
        let b: StateUpdate<'_, String, String> = StateUpdate::New {
            state: init_state(),
            hash: &ONE_HASH,
        };
        assert_ne!(a, b);

        // New with a different state map compares unequal.
        let c: StateUpdate<'_, String, String> = StateUpdate::New {
            state: SharedState::new(),
            hash: &ZERO_HASH,
        };
        assert_ne!(a, c);

        // Unchanged compares equal when parent id and hash match, unequal otherwise.
        let p1 = String::from("$parent");
        let p2 = String::from("$other");
        let d1: StateUpdate<'_, String, String> = StateUpdate::Unchanged {
            parent_event_id: &p1,
            hash: &ZERO_HASH,
        };
        let d2: StateUpdate<'_, String, String> = StateUpdate::Unchanged {
            parent_event_id: &p2,
            hash: &ZERO_HASH,
        };
        assert_eq!(d1.clone(), d1);
        assert_ne!(d1, d2);

        // A New and an Unchanged are never equal, even with the same hash.
        let different_hash = crate::state::lthash::LtHash([2; 1024]);
        let new: StateUpdate<'_, String, String> = StateUpdate::New {
            state: SharedState::new(),
            hash: &different_hash,
        };
        let unchanged: StateUpdate<'_, String, String> = StateUpdate::Unchanged {
            parent_event_id: &p1,
            hash: &different_hash,
        };
        assert_ne!(new, unchanged);
    }

    /// Coverage: `StateUpdate::lattice` and `StateUpdate::digest` must expose the
    /// carried `LtHash` lattice (borrowed, zero-copy) and its 32-byte digest, for
    /// both the `New` and `Unchanged` variants.
    #[test]
    fn test_state_update_lattice_and_digest_accessors() {
        let mut state: SharedState<String, String> = SharedState::new();
        state.insert(
            (EventType::from("m.room.topic"), String::new()),
            "$topic".to_string(),
        );
        let hash = crate::state::lthash::LtHash::from_state(&state);
        let parent = String::from("$parent");

        let new: StateUpdate<'_, String, String> = StateUpdate::New {
            state: state.clone(),
            hash: &hash,
        };
        assert_eq!(new.lattice(), &hash);
        assert_eq!(new.digest(), hash.digest());
        assert_eq!(new.digest().len(), 32);

        let unchanged: StateUpdate<'_, String, String> = StateUpdate::Unchanged {
            parent_event_id: &parent,
            hash: &hash,
        };
        assert_eq!(unchanged.lattice(), &hash);
        assert_eq!(unchanged.digest(), hash.digest());

        // Both variants derived from the same lattice must share a digest.
        assert_eq!(new.digest(), unchanged.digest());
    }

    fn init_hashed_state() -> HashedState<String, String> {
        HashedState {
            state: init_state(),
            hash: crate::state::lthash::LtHash::default(),
        }
    }

    /// Coverage: `Default for HashedState` yields an empty state and a default hash.
    #[test]
    fn test_hashed_state_default() {
        let hs = HashedState::<String, String>::default();
        assert!(hs.state.is_empty(), "default state should be empty");
        assert_eq!(hs.hash, crate::state::lthash::LtHash::default());
    }

    /// Coverage: `Debug for HashedState` must print the struct name and both fields.
    #[test]
    fn test_hashed_state_debug() {
        let f = alloc::format!("{:?}", init_hashed_state());
        assert!(
            f.contains("HashedState"),
            "debug output should name HashedState: {f}"
        );
        assert!(f.contains("state"));
        assert!(f.contains("hash"));
    }

    /// Coverage: `Clone for HashedState` must deep-clone the state and copy the hash.
    #[test]
    fn test_hashed_state_clone() {
        let hs = init_hashed_state();
        let cloned = hs.clone();
        assert_eq!(cloned.state, hs.state);
        assert_eq!(cloned.hash, hs.hash);
    }

    /// Coverage: `find_depth_divergences`'s seen-edge guard (line 1725): when a
    /// child repeats the same `prev_event` id twice, only the first occurrence
    /// is examined; the duplicate is short-circuited.
    #[test]
    fn test_find_depth_divergences_dedups_repeated_parent() {
        let a = LeanEvent {
            event_id: "A".into(),
            prev_events: vec![],
            depth: 1,
            ..Default::default()
        };
        // B lists A twice and claims a depth that violates monotonicity.
        let b = LeanEvent {
            event_id: "B".into(),
            prev_events: vec!["A".into(), "A".into()],
            depth: 1,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);

        let divergences = find_depth_divergences(&events_map);
        // The duplicated (A,B) edge is only counted once.
        assert_eq!(
            divergences.len(),
            1,
            "duplicate parent must be deduplicated"
        );
    }

    /// Coverage: `try_compute_state_at_streaming_optimized` early-returns when
    /// every requested target is absent from `events_map` (line 2403).
    #[test]
    fn test_try_compute_state_at_streaming_optimized_with_no_resolvable_targets() {
        let events_map: HashMap<String, LeanEvent> = HashMap::new();
        let mut callback_called = false;

        let result: Result<(), StateComputationError<&'static str>> =
            try_compute_state_at_streaming_optimized(
                &["ghost"],
                &events_map,
                crate::StateResVersion::V2,
                |_, _| {
                    callback_called = true;
                    Ok(())
                },
            );

        assert_eq!(result, Ok(()));
        assert!(
            !callback_called,
            "callback must not run when there are no actual targets"
        );
    }

    /// Coverage: the `run_state_pipeline_streaming_optimized` `prev_events` loop
    /// guards — a parent outside the batch (line 2276) and a duplicated parent
    /// in a single event's `prev_events` (line 2283).
    #[test]
    fn test_streaming_optimized_tolerates_missing_and_duplicate_parents() {
        // A is a genuine root.
        let a = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            content: json!({"room_version": "10"}),
            depth: 1,
            ..Default::default()
        };
        // B targets a missing parent ("MISSING") and repeats "A" twice.
        let b = LeanEvent {
            event_id: "B".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@b:x".into()),
            sender: "@x:x".into(),
            content: json!({"membership": "join"}),
            prev_events: vec!["A".into(), "A".into(), "MISSING".into()],
            depth: 2,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("A".into(), a);
        events_map.insert("B".into(), b);

        let mut yielded_ids = alloc::vec![];
        let mut saw_new = false;
        let ok = compute_state_at_streaming_optimized(
            &["B"],
            &events_map,
            crate::StateResVersion::V2,
            |id, update| {
                yielded_ids.push(id);
                if matches!(update, StateUpdate::New { .. }) {
                    saw_new = true;
                }
            },
        );

        assert!(ok, "must complete without panicking");
        // B is the only target and must be yielded exactly once.
        assert_eq!(yielded_ids, alloc::vec!["B".to_string()]);
        assert!(saw_new, "B's state is new, not inherited");
    }

    /// Coverage: `iterative_auth_ok`'s rejected/soft-fail short-circuit (line 240).
    #[test]
    fn test_iterative_auth_ok_rejected_and_soft_fail() {
        let resolved: SharedState<String, String> = SharedState::new();
        let auth_context: HashMap<String, LeanEvent> = HashMap::new();
        let sort_set: HashMap<String, LeanEvent> = HashMap::new();

        let rejected = LeanEvent {
            event_id: "X".into(),
            event_type: "m.room.message".into(),
            rejected: true,
            ..Default::default()
        };
        assert!(!iterative_auth_ok(
            &rejected,
            &resolved,
            &auth_context,
            &sort_set,
            BTreeMap::new(),
            None,
            crate::StateResVersion::V2,
            false,
        ));

        let soft_failed = LeanEvent {
            event_id: "Y".into(),
            event_type: "m.room.message".into(),
            soft_fail: true,
            ..Default::default()
        };
        assert!(!iterative_auth_ok(
            &soft_failed,
            &resolved,
            &auth_context,
            &sort_set,
            BTreeMap::new(),
            None,
            crate::StateResVersion::V2,
            false,
        ));
    }

    /// Coverage: `update_local_auth` — the no-state-key early return (line 265)
    /// and the occupied-entry replacement when a shallower depth wins
    /// (lines 275-281).
    #[test]
    fn test_update_local_auth_shallower_depth_replaces() {
        let mut local_auth: BTreeMap<
            (EventType, String),
            LocalAuthEntry<String, serde_json::Value, String>,
        > = BTreeMap::new();

        // Non-state event has no state_key -> early return.
        let msg = LeanEvent {
            event_id: "M".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            ..Default::default()
        };
        update_local_auth(&mut local_auth, &msg, 5);
        assert!(local_auth.is_empty());

        // Two state events on the same key: the shallower depth replaces the deeper.
        let m1 = LeanEvent {
            event_id: "M1".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:x".into()),
            sender: "@alice:x".into(),
            content: json!({"membership": "join"}),
            ..Default::default()
        };
        let m2 = LeanEvent {
            event_id: "M2".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:x".into()),
            sender: "@alice:x".into(),
            content: json!({"membership": "join"}),
            ..Default::default()
        };
        update_local_auth(&mut local_auth, &m1, 3);
        update_local_auth(&mut local_auth, &m2, 1);

        let key = (EventType::from("m.room.member"), "@alice:x".to_string());
        let entry = local_auth
            .get(&key)
            .expect("member key must be present in local auth");
        assert_eq!(entry.event.event_id, "M2", "shallower depth must win");
        assert_eq!(entry.auth_depth, 1);
    }

    /// Coverage: `compute_local_auth` — the duplicate-auth visited guard
    /// (line 318), the V2.1.1 cached-ancestor propagation (lines 333-348), and
    /// the V2.1.1 BFS parent-queueing for uncached auth events (lines 365-366).
    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::too_many_lines)]
    #[test]
    fn test_compute_local_auth_duplicate_and_cached_ancestors() {
        let root = LeanEvent {
            event_id: "R".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@x:x".into(),
            depth: 0,
            ..Default::default()
        };
        let a = LeanEvent {
            event_id: "A".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@a:x".into()),
            sender: "@a:x".into(),
            content: json!({"membership": "join"}),
            auth_events: vec!["R".into()],
            depth: 1,
            ..Default::default()
        };
        let x = LeanEvent {
            event_id: "X".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            auth_events: vec!["R".into()],
            depth: 1,
            ..Default::default()
        };
        let e = LeanEvent {
            event_id: "E".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            auth_events: vec!["A".into(), "A".into()],
            depth: 2,
            ..Default::default()
        };
        let e2 = LeanEvent {
            event_id: "E2".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            auth_events: vec!["X".into()],
            depth: 3,
            ..Default::default()
        };
        let p = LeanEvent {
            event_id: "P".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            auth_events: vec!["R".into()],
            depth: 1,
            ..Default::default()
        };
        let d = LeanEvent {
            event_id: "D".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            auth_events: vec!["P".into()],
            depth: 2,
            ..Default::default()
        };
        let e3 = LeanEvent {
            event_id: "E3".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            // D (uncached) drives the uncached V2.1.1 queue through P to the
            // create event; A (cached) is queued alongside to exercise the
            // cached-empty-map arm for R.
            auth_events: vec!["D".into(), "A".into()],
            depth: 4,
            ..Default::default()
        };
        let p2 = LeanEvent {
            event_id: "P2".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            auth_events: vec!["R".into()],
            depth: 1,
            ..Default::default()
        };
        let a2 = LeanEvent {
            event_id: "A2".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@a2:x".into()),
            sender: "@a2:x".into(),
            content: json!({"membership": "join"}),
            // A2's cache entry reaches the create at auth_depth 2 (via P2).
            auth_events: vec!["P2".into()],
            depth: 1,
            ..Default::default()
        };
        let b2 = LeanEvent {
            event_id: "B2".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@b2:x".into()),
            sender: "@b2:x".into(),
            content: json!({"membership": "join"}),
            // B2's cache entry reaches the create at auth_depth 1 (direct).
            auth_events: vec!["R".into()],
            depth: 1,
            ..Default::default()
        };
        let e4 = LeanEvent {
            event_id: "E4".into(),
            event_type: "m.room.message".into(),
            sender: "@x:x".into(),
            auth_events: vec!["A2".into(), "B2".into()],
            depth: 4,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert("R".into(), root.clone());
        events_map.insert("A".into(), a.clone());
        events_map.insert("X".into(), x);
        events_map.insert("E".into(), e.clone());
        events_map.insert("E2".into(), e2.clone());
        events_map.insert("P".into(), p);
        events_map.insert("D".into(), d);
        events_map.insert("E3".into(), e3.clone());
        events_map.insert("P2".into(), p2);
        events_map.insert("A2".into(), a2.clone());
        events_map.insert("B2".into(), b2.clone());
        events_map.insert("E4".into(), e4.clone());

        let conflicted: HashMap<String, LeanEvent> = HashMap::new();
        let mut cache = LocalAuthCache::new(crate::StateResVersion::V2_1_1);

        // Prime the cache for A so the cached-ancestor path is live below.
        compute_local_auth(
            &a,
            &events_map,
            &conflicted,
            &mut cache,
            crate::StateResVersion::V2_1_1,
        );

        // E.auth = [A, A]: A is cached (propagation path) and duplicated (visited guard).
        let la_e = compute_local_auth(
            &e,
            &events_map,
            &conflicted,
            &mut cache,
            crate::StateResVersion::V2_1_1,
        );
        assert!(la_e.contains_key(&("m.room.member".into(), "@a:x".into())));
        assert!(la_e.contains_key(&("m.room.create".into(), String::new())));

        // E2.auth = [X]: X is uncached, so its parents are queued for V2.1.1.
        let la_e2 = compute_local_auth(
            &e2,
            &events_map,
            &conflicted,
            &mut cache,
            crate::StateResVersion::V2_1_1,
        );
        assert!(la_e2.contains_key(&("m.room.create".into(), String::new())));

        // Prime the cache for R (create, no auth) so E3's R hit takes the
        // cached-ancestor path too.
        compute_local_auth(
            &root,
            &events_map,
            &conflicted,
            &mut cache,
            crate::StateResVersion::V2_1_1,
        );

        // E3.auth = [A, R]: A's propagation adds (create,"")->R at total depth 2;
        // R then claims the same key at depth 1, replacing it via the occupied
        // local_auth entry arm (strictly-shallower-depth branch).
        let la_e3 = compute_local_auth(
            &e3,
            &events_map,
            &conflicted,
            &mut cache,
            crate::StateResVersion::V2_1_1,
        );
        assert!(la_e3.contains_key(&("m.room.create".into(), String::new())));
        assert!(la_e3.contains_key(&("m.room.member".into(), "@a:x".into())));

        // Prime the cache for A2 (create at auth_depth 2 via P2) and B2 (create
        // at auth_depth 1). When E4 processes both cached ancestors, A2 claims
        // the create at total depth 3 and B2's shallower total depth 2 must
        // replace it — the occupied local_auth entry arm.
        compute_local_auth(
            &a2,
            &events_map,
            &conflicted,
            &mut cache,
            crate::StateResVersion::V2_1_1,
        );
        compute_local_auth(
            &b2,
            &events_map,
            &conflicted,
            &mut cache,
            crate::StateResVersion::V2_1_1,
        );

        let la_e4 = compute_local_auth(
            &e4,
            &events_map,
            &conflicted,
            &mut cache,
            crate::StateResVersion::V2_1_1,
        );
        assert!(la_e4.contains_key(&("m.room.create".into(), String::new())));
        assert!(la_e4.contains_key(&("m.room.member".into(), "@a2:x".into())));
        assert!(la_e4.contains_key(&("m.room.member".into(), "@b2:x".into())));
    }
}
