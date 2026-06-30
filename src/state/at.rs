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

use crate::basespec::rezzy_types::{LeanEvent, StateResVersion};
use crate::HashMap;
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
pub struct LocalAuthEntry<Id, C = serde_json::Value> {
    /// The auth event itself.
    pub event: LeanEvent<Id, C>,
    /// Number of auth-chain hops from the original event to this one.
    pub auth_depth: usize,
}

/// Inner type for the local auth cache to satisfy clippy's `type_complexity` lint.
pub type LocalAuthCacheMap<Id, C> = BTreeMap<(String, Option<String>), LocalAuthEntry<Id, C>>;

/// Memoization cache for local auth context computation.
///
/// Maps `event_id -> BTreeMap<(type, state_key) -> LocalAuthEntry>`, allowing
/// the local auth context to be computed once and reused for all events that
/// share auth chain prefixes.
///
/// This cache tracks which `StateResVersion` its entries were computed for.
/// Callers must clear the cache when reusing it with a different `StateResVersion`
/// (higher-level helpers like `resolve_lean_with_cache*` do this automatically).
pub struct LocalAuthCache<Id = String, C = serde_json::Value> {
    pub version: StateResVersion,
    pub map: crate::HashMap<Id, LocalAuthCacheMap<Id, C>>,
}

impl<Id, C> LocalAuthCache<Id, C> {
    #[must_use]
    pub fn new(version: StateResVersion) -> Self {
        Self {
            version,
            map: crate::HashMap::default(),
        }
    }
}

pub(crate) struct OverlayState<'a, Id, C, S1, S2> {
    pub(crate) resolved: &'a crate::state::at::SharedState<Id>,
    pub(crate) auth_context: &'a HashMap<Id, LeanEvent<Id, C>, S1>,
    pub(crate) sort_set: &'a HashMap<Id, LeanEvent<Id, C>, S2>,
    pub(crate) local_auth: BTreeMap<(String, Option<String>), LeanEvent<Id, C>>,
    pub(crate) create_ev: Option<&'a LeanEvent<Id, C>>,
    pub(crate) version: StateResVersion,
    pub(crate) is_power_phase: bool,
}

impl<
        Id: Clone + Eq + core::hash::Hash + Ord,
        C: crate::basespec::rezzy_types::EventContent,
        S1: core::hash::BuildHasher,
        S2: core::hash::BuildHasher,
    > crate::auth::StateProvider<Id, C> for OverlayState<'_, Id, C, S1, S2>
{
    fn get_event(&self, event_type: &str, state_key: Option<&str>) -> Option<&LeanEvent<Id, C>> {
        let query: &dyn crate::auth::StateKeyDyn = &(event_type, state_key);

        // In V2.1 (Stock MSC4297), we supplement with ONLY m.room.power_levels during Step 2 (power phase).
        // In Step 4 (remaining events phase), we supplement with all event types.
        let should_supplement = match self.version {
            StateResVersion::V2_1 => {
                if self.is_power_phase {
                    event_type == "m.room.power_levels" && state_key == Some("")
                } else {
                    true
                }
            }
            StateResVersion::V2_1_1 => {
                (event_type == "m.room.power_levels" && state_key == Some(""))
                    || (event_type == "m.room.member")
            }
            _ => true,
        };

        if should_supplement {
            // Check consensus resolved state
            if let Some(eid) = self.resolved.get(query) {
                if let Some(ev) = self
                    .auth_context
                    .get(eid)
                    .or_else(|| self.sort_set.get(eid))
                {
                    if self.version == StateResVersion::V2_1_1
                        && self.is_power_phase
                        && event_type == "m.room.member"
                    {
                        // V2.1.1 Fix: Only supplement bans and kicks in power phase
                        if let Some(membership) = ev.get_membership() {
                            let is_ban = membership == "ban";
                            let is_kick = membership == "leave"
                                && state_key.is_some()
                                && Some(ev.sender.as_str()) != state_key;
                            if is_ban || is_kick {
                                return Some(ev);
                            }
                        }
                        // If it's a normal join/invite, fall through to local auth
                    } else {
                        return Some(ev);
                    }
                }
            }
        }

        // Check local auth chain (BFS result) second!
        if let Some(ev) = self.local_auth.get(query) {
            // Under Matrix State Resolution, during the power phase, a required auth event in the conflicted set
            // can ONLY be used if it has been successfully authorized and resolved
            // (i.e. is present in the resolved state).
            let is_required_type =
                event_type == "m.room.power_levels" || event_type == "m.room.join_rules";

            let is_v2_1_or_above = self.version == StateResVersion::V2_1
                || self.version == StateResVersion::V2_1_1
                || self.version == StateResVersion::V2_2;

            if self.is_power_phase
                && is_v2_1_or_above
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
                }
                None
            } else {
                Some(ev)
            }
        } else {
            // Fallback for create
            if event_type == "m.room.create" && state_key == Some("") {
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
pub(crate) fn iterative_auth_ok<
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
>(
    ev: &LeanEvent<Id, C>,
    resolved: &crate::state::at::SharedState<Id>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S1>,
    sort_set: &HashMap<Id, LeanEvent<Id, C>, S2>,
    local_auth: BTreeMap<(String, Option<String>), LeanEvent<Id, C>>,
    cached_create: Option<&LeanEvent<Id, C>>,
    version: StateResVersion,
    is_power_phase: bool,
) -> bool {
    let overlay = OverlayState {
        resolved,
        auth_context,
        sort_set,
        local_auth,
        create_ev: cached_create,
        version,
        is_power_phase,
    };

    crate::auth::check_auth(ev, &overlay, version).is_ok()
}

/// Merges an event into a local auth map if it is an auth event (e.g. power levels, join rules).
/// Ensures that newer auth events replace older ones during chain traversal.
pub(crate) fn update_local_auth<Id: Clone + Ord, C: Clone>(
    local_auth: &mut BTreeMap<(String, Option<String>), LocalAuthEntry<Id, C>>,
    aev: &LeanEvent<Id, C>,
    depth: usize,
) {
    let key = (aev.event_type.clone(), aev.state_key.clone());
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
pub(crate) fn compute_local_auth<Id, C, S1, S2>(
    event: &LeanEvent<Id, C>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S1>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>, S2>,
    cache: &mut LocalAuthCache<Id, C>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), LeanEvent<Id, C>>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    C: Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
{
    if let Some(cached) = cache.map.get(&event.event_id) {
        return cached
            .clone()
            .into_iter()
            .map(|(k, entry)| (k, entry.event))
            .collect();
    }

    let mut local_auth: BTreeMap<(String, Option<String>), LocalAuthEntry<Id, C>> = BTreeMap::new();
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

            // NOTE: V2.1.1 (Proposed) replaces unbounded DFS with a pure memoized BFS traversal.
            // Therefore, both V2.1.1 and V2.2 natively gather transitive auth context!
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

/// An O(1) cloneable, persistent state map.
pub type SharedState<Id = String> = imbl::OrdMap<(String, Option<String>), Id>;

/// Computes the resolved room state *after* a given event.
///
/// This walks the `prev_events` graph backwards from `target_event_id`,
/// topologically sorts all reachable ancestors, and incrementally builds
/// the state by applying each state event in order. Fork points are resolved
/// via [`crate::resolve::iterative::resolve_lean`] with the given `version` semantics.
///
/// Returns `None` if `target_event_id` is not found in `events_map`.
///
/// # Panics
///
/// Will panic if graph invariants are violated (specifically, if an ancestor event
/// present in the reachable subgraph is missing from `events_map` during topological processing).
#[must_use]
pub fn compute_state_at<Id, C, Q, S>(
    target_event_id: &Q,
    events_map: &HashMap<Id, LeanEvent<Id, C>, S>,
    version: StateResVersion,
) -> Option<BTreeMap<(String, Option<String>), Id>>
where
    Id: Clone + Eq + Ord + core::fmt::Debug + core::hash::Hash + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + Ord + core::hash::Hash,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
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
pub fn compute_state_at_batch<Id, C, Q, S>(
    target_event_ids: &[&Q],
    events_map: &HashMap<Id, LeanEvent<Id, C>, S>,
    version: StateResVersion,
) -> HashMap<Id, BTreeMap<(String, Option<String>), Id>>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
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
///
/// **NOTE:** Target IDs not found in `events_map` are silently skipped!
///
/// # Panics
///
/// Will panic if graph invariants are violated (specifically, if an ancestor event
/// present in the reachable subgraph is missing from `events_map` during topological processing).
pub fn compute_state_at_streaming<Id, C, Q, S, F>(
    target_event_ids: &[&Q],
    events_map: &HashMap<Id, LeanEvent<Id, C>, S>,
    version: StateResVersion,
    mut on_target_resolved: F,
) where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    F: FnMut(Id, SharedState<Id>),
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
pub fn try_compute_state_at_streaming<Id, C, Q, S, F, E>(
    target_event_ids: &[&Q],
    events_map: &HashMap<Id, LeanEvent<Id, C>, S>,
    version: StateResVersion,
    mut on_target_resolved: F,
) -> Result<(), StateComputationError<E>>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    F: FnMut(Id, SharedState<Id>) -> Result<(), E>,
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
fn run_state_pipeline_streaming<'a, Id, C, S, F, E>(
    index_to_id: &[&'a Id],
    id_to_index: &HashMap<&'a Id, usize>,
    is_target: &[bool],
    events_map: &HashMap<Id, LeanEvent<Id, C>, S>,
    version: StateResVersion,
    mut on_target: F,
) -> Result<(), StateComputationError<E>>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    F: FnMut(usize, SharedState<Id>) -> Result<(), E>,
{
    let (sorted_ancestors, mut out_degree) =
        topological_sort_short_ids(index_to_id, id_to_index, events_map);

    if sorted_ancestors.len() != index_to_id.len() {
        return Err(StateComputationError::CycleDetected);
    }

    let mut global_auth_cache = LocalAuthCache::new(version);

    let mut state_after_map: Vec<Option<SharedState<Id>>> = core::iter::repeat_with(|| None)
        .take(index_to_id.len())
        .collect();

    for idx in sorted_ancestors {
        let id_val = index_to_id[idx];
        let ev = events_map.get(id_val).unwrap();

        let mut prev_states = Vec::with_capacity(ev.prev_events.len());
        for pe in &ev.prev_events {
            if let Some(&pe_idx) = id_to_index.get(pe) {
                if out_degree[pe_idx] > 0 {
                    out_degree[pe_idx] = out_degree[pe_idx].saturating_sub(1);
                    if out_degree[pe_idx] == 0 {
                        if let Some(pe_state) = state_after_map[pe_idx].take() {
                            prev_states.push(pe_state);
                        }
                    } else if let Some(ref pe_state) = state_after_map[pe_idx] {
                        prev_states.push(pe_state.clone());
                    }
                }
            }
        }

        let mut state_before: SharedState<Id> = if prev_states.is_empty() {
            SharedState::new()
        } else if prev_states.len() == 1 {
            prev_states.into_iter().next().unwrap()
        } else {
            resolve_merge_fast_path(&prev_states, events_map, &mut global_auth_cache, version)
        };

        if ev.state_key.is_some() {
            state_before.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
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
pub fn compute_merge_base<'a, Id, Q, S, Node>(
    extremities: &[&Q],
    events_map: &'a HashMap<Id, Node, S>,
) -> Option<&'a Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::borrow::Borrow<Q>,
    Q: ?Sized + Eq + core::hash::Hash + Ord,
    S: core::hash::BuildHasher,
    Node: crate::basespec::rezzy_types::DagNode<Id>,
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
        let current_mask = match masks.get(current_id) {
            Some(m) => m.clone(),
            None => continue,
        };

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
fn collect_ancestor_short_ids_batch<'a, Id, C, S>(
    target_event_ids: &[&'a Id],
    events_map: &'a HashMap<Id, LeanEvent<Id, C>, S>,
) -> (HashMap<&'a Id, usize>, Vec<&'a Id>)
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S: core::hash::BuildHasher,
    C: Clone,
{
    let mut id_to_index: HashMap<&Id, usize> = HashMap::new();
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

        if let Some(ev) = events_map.get(current_id) {
            for pe in &ev.prev_events {
                if events_map.contains_key(pe) && !id_to_index.contains_key(pe) {
                    let next_idx = index_to_id.len();
                    id_to_index.insert(pe, next_idx);
                    index_to_id.push(pe);
                    queue.push(pe);
                }
            }
        }
    }

    (id_to_index, index_to_id)
}

/// Performs a topological sort of the graph represented by short `usize` indexes.
/// Performs Kahn's topological sort on the collected ancestor graph.
/// Returns the events sorted such that parents always appear before their children.
fn topological_sort_short_ids<Id, C, S>(
    index_to_id: &[&Id],
    id_to_index: &HashMap<&Id, usize>,
    events_map: &HashMap<Id, LeanEvent<Id, C>, S>,
) -> (Vec<usize>, Vec<usize>)
where
    Id: Clone + Eq + core::hash::Hash,
    S: core::hash::BuildHasher,
    C: Clone,
{
    let num_reachable = index_to_id.len();
    let mut in_degree = alloc::vec![0usize; num_reachable];
    let mut adjacency = alloc::vec![Vec::new(); num_reachable];
    let mut out_degree = alloc::vec![0usize; num_reachable];

    for (i, id) in index_to_id.iter().enumerate() {
        if let Some(ev) = events_map.get(*id) {
            for parent in &ev.prev_events {
                if let Some(&parent_idx) = id_to_index.get(parent) {
                    in_degree[i] = in_degree[i].saturating_add(1);
                    adjacency[parent_idx].push(i);
                    out_degree[parent_idx] = out_degree[parent_idx].saturating_add(1);
                }
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
fn resolve_merge_fast_path<Id, C, S>(
    prev_states: &[SharedState<Id>],
    events_map: &HashMap<Id, LeanEvent<Id, C>, S>,
    global_auth_cache: &mut LocalAuthCache<Id, C>,
    version: StateResVersion,
) -> SharedState<Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
{
    let first = &prev_states[0];
    let all_match = prev_states[1..].iter().all(|state| first == state);

    if all_match {
        first.clone()
    } else {
        resolve_multiple_prev_states(prev_states, events_map, global_auth_cache, version)
            .into_iter()
            .collect()
    }
}

/// Slow path for merging multiple parent states via the state resolution algorithm.
/// Full state resolution path for DAG nodes with multiple parents (forks).
/// Groups the unconflicted state and runs `resolve_lean` on the conflicted subset.
fn resolve_multiple_prev_states<Id, C, S>(
    prev_states: &[SharedState<Id>],
    events_map: &HashMap<Id, LeanEvent<Id, C>, S>,
    global_auth_cache: &mut LocalAuthCache<Id, C>,
    version: StateResVersion,
) -> SharedState<Id>
where
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    S: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
{
    let mut conflicted_keys = hashbrown::HashSet::new();
    let mut conflicted_state_set = hashbrown::HashSet::new();
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

    // Compute the auth difference (auth(C) \ auth(U)) using a bounded dual-heap traversal.
    // This perfectly restores algorithmic invariants for `expand_v2_power_events_auth_chains`
    // without the massive O(N) bottleneck of unbounded DAG walks.
    let mut u_visited = hashbrown::HashSet::new();
    let mut u_heap_elements = Vec::with_capacity(unconflicted_state.len());
    for id in unconflicted_state.values() {
        if u_visited.insert(id.clone()) {
            if let Some(ev) = events_map.get(id) {
                u_heap_elements.push((ev.depth, id.clone()));
            }
        }
    }
    let mut u_heap = alloc::collections::BinaryHeap::from(u_heap_elements);

    let mut c_visited = hashbrown::HashSet::new();
    let mut c_heap = alloc::collections::BinaryHeap::new();
    for id in &conflicted_state_set {
        if u_visited.contains(id) {
            continue; // PRUNE EARLY
        }
        if c_visited.insert(id.clone()) {
            if let Some(ev) = events_map.get(id) {
                c_heap.push((ev.depth, id.clone()));
            }
        }
    }

    let mut auth_diff = hashbrown::HashSet::new();

    while let Some(&(c_depth, _)) = c_heap.peek() {
        // Catch up U's traversal to C's current depth
        while let Some(&(u_depth, _)) = u_heap.peek() {
            if u_depth < c_depth {
                break;
            }
            let (_, u_id) = u_heap.pop().unwrap();
            if let Some(ev) = events_map.get(&u_id) {
                for auth_id in &ev.auth_events {
                    if u_visited.insert(auth_id.clone()) {
                        if let Some(a_ev) = events_map.get(auth_id) {
                            u_heap.push((a_ev.depth, auth_id.clone()));
                        }
                    }
                }
            }
        }

        let (_, c_id) = c_heap.pop().unwrap();
        if !u_visited.contains(&c_id) {
            auth_diff.insert(c_id.clone());
            if let Some(ev) = events_map.get(&c_id) {
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
    }

    for id_val in auth_diff {
        if let Some(event) = events_map.get(&id_val) {
            conflicted_events.insert(id_val, event.clone());
        }
    }

    crate::resolve::iterative::resolve_lean_with_cache(
        unconflicted_state,
        conflicted_events,
        events_map,
        Some(global_auth_cache),
        version,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use serde_json::json;

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
                ("m.room.create".to_string(), Some(String::new())),
                create_ev.clone(),
            ),
            (
                ("m.room.power_levels".to_string(), Some(String::new())),
                pl_bot.clone(),
            ),
            (
                (
                    "m.room.member".to_string(),
                    Some("@bot:example.com".to_string()),
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
}
