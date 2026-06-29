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

//! State resolution entry point — the [`resolve_lean`] function.
//!
//! This module implements the full Matrix state resolution pipeline:
//!
//! 1. **CDO pre-filter** (V2.1.1 only): removes causally dominated events.
//! 2. **Power phase**: classifies events as power vs. non-power, expands auth
//!    chains, then iteratively auth-checks power events in reverse topological order.
//! 3. **Non-power phase**: sorts remaining events by mainline distance and
//!    iteratively auth-checks them against the progressively-built resolved state.
//!
//! For the lattice-coordinatized variant (parallel, `O(1)` projection), see
//! [`crate::lattice::resolve_lattice_coordinatized`].

use crate::{
    sorting::{build_mainline, lean_kahn_sort, mainline_sort},
    state_at::{compute_local_auth, iterative_auth_ok, LocalAuthCache},
    types::{LeanEvent, StateResVersion},
    HashMap,
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};

/// Prepares the conflicted events map and tracks original conflicted keys before CDO pre-filtering.
pub(crate) fn prepare_conflicted_and_keys<
    Id: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug,
    C: crate::types::EventContent,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    conflicted_events: &mut HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    version: StateResVersion,
) -> alloc::collections::BTreeSet<Id> {
    let original_conflicted_keys = conflicted_events.keys().cloned().collect();
    if version == StateResVersion::V2_1_1 {
        let filtered = crate::cdo::apply_cdo_filter(conflicted_events, auth_context);
        conflicted_events.clear();
        for (k, v) in filtered {
            conflicted_events.insert(k, v);
        }
    }
    original_conflicted_keys
}

/// State Resolution V2+ auth-chain expansion (room versions 2 - 11+, Spec [§State Resolution]).
///
/// After the initial power/non-power classification, this function recursively
/// walks the `auth_events` of each power event. Any event found in the
/// conflicted set (`sort_set`) is promoted from `non_power_events` to
/// `power_events`. This ensures that the auth chain dependencies of power
/// events are resolved in the correct (power) phase.
///
/// This is specified in the [V2 state resolution algorithm][v2-spec], Step 3,
/// and applies to all versions that use V2-derived resolution: V2, V2.1, V2.1.1, and V2.2.
///
/// [v2-spec]: https://spec.matrix.org/v1.13/rooms/v2/#state-resolution
/// Expands the auth chains for a set of V2 power events, building an auth context.
pub fn expand_v2_power_events_auth_chains<
    Id: Clone + Eq + core::hash::Hash,
    C: Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    S3: core::hash::BuildHasher,
>(
    power_events: &mut HashMap<Id, LeanEvent<Id, C>, S1>,
    non_power_events: &mut HashMap<Id, LeanEvent<Id, C>, S2>,
    sort_set: &HashMap<Id, LeanEvent<Id, C>, S3>,
) {
    let mut queue: alloc::collections::VecDeque<Id> = power_events.keys().cloned().collect();
    while let Some(id) = queue.pop_front() {
        if let Some(ev) = sort_set.get(&id) {
            for aid in &ev.auth_events {
                if !power_events.contains_key(aid) {
                    if let Some(aev) = sort_set.get(aid) {
                        power_events.insert(aid.clone(), aev.clone());
                        non_power_events.remove(aid);
                        queue.push_back(aid.clone());
                    }
                }
            }
        }
    }
}

/// MSC4297 (v2.1+): Routes administrative ancestral power events from `auth_context` into `power_events`.
pub(crate) fn route_msc4297_ancestral_power_events<
    Id: Clone + Eq + core::hash::Hash + Ord,
    C: crate::types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    power_events: &mut HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    original_conflicted_keys: &alloc::collections::BTreeSet<Id>,
    version: StateResVersion,
) {
    if matches!(
        version,
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2
    ) {
        let mut conflicted_power_ancestry = alloc::collections::BTreeSet::new();
        let mut queue = alloc::collections::VecDeque::new();
        for ev in power_events.values() {
            for aid in &ev.auth_events {
                queue.push_back(aid.clone());
            }
        }
        while let Some(aid) = queue.pop_front() {
            if conflicted_power_ancestry.insert(aid.clone()) {
                if let Some(aev) = auth_context.get(&aid) {
                    for parent_id in &aev.auth_events {
                        queue.push_back(parent_id.clone());
                    }
                }
            }
        }

        for id in &conflicted_power_ancestry {
            if original_conflicted_keys.contains(id) {
                continue;
            }
            if let Some(ev) = auth_context.get(id) {
                // NOTE: V2.1.1+ strictly isolates the supplemental merge to PLs and creates.
                // V2.1 (MSC4297) supplemented `m.room.join_rules`, which inadvertently caused the
                // Invite Lock bug (evaluating historical joins against newer invite-only rules).
                let is_join_rules_allowed =
                    ev.event_type == "m.room.join_rules" && version == StateResVersion::V2_1;

                if ev.event_type == "m.room.power_levels"
                    || ev.event_type == "m.room.create"
                    || is_join_rules_allowed
                {
                    power_events.insert(id.clone(), ev.clone());
                }
            }
        }
    }
}

/// Runs the sequential power phase iterative auth checks to establish the authoritative administrative framework.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_power_phase_iterative_checks<Id, C, S2, S3, S4>(
    resolved: &mut BTreeMap<(String, Option<String>), Id>,
    power_events: &HashMap<Id, LeanEvent<Id, C>, S4>,
    sort_context: &impl crate::types::EventProvider<Id, C>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>, S3>,
    _original_conflicted_keys: &alloc::collections::BTreeSet<Id>,
    version: StateResVersion,
    local_auth_cache: &mut crate::state_at::LocalAuthCache<Id, C>,
    create_ev: Option<&LeanEvent<Id, C>>,
) where
    Id: crate::types::EventId,
    S2: core::hash::BuildHasher,
    S3: core::hash::BuildHasher,
    S4: core::hash::BuildHasher,
    C: crate::types::EventContent,
{
    let sorted_power_ids = lean_kahn_sort(power_events, sort_context, create_ev, version);
    for id in &sorted_power_ids {
        if let Some(event) = conflicted_events.get(id).or_else(|| auth_context.get(id)) {
            let local_auth = compute_local_auth(
                event,
                auth_context,
                conflicted_events,
                local_auth_cache,
                version,
            );
            if iterative_auth_ok(
                event,
                resolved,
                auth_context,
                conflicted_events,
                local_auth,
                create_ev,
                version,
                true,
            ) {
                resolved.insert(
                    (event.event_type.clone(), event.state_key.clone()),
                    event.event_id.clone(),
                );
            }
        }
    }
}

/// Returns the starting point for state resolution based on the algorithm version.
/// V1 and V2 inherit the unconflicted state as their base, whereas V2.1+ starts from an empty set.
pub(crate) fn get_initial_resolved_state<Id>(
    unconflicted_state: &BTreeMap<(String, Option<String>), Id>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), Id>
where
    Id: Clone,
{
    match version {
        StateResVersion::V2_1 | StateResVersion::V2_1_1 | StateResVersion::V2_2 => BTreeMap::new(),
        _ => unconflicted_state.clone(),
    }
}

/// Executes the first half of the Matrix State Resolution algorithm (the power phase).
///
/// This involves setting up the sorting context, dividing events into power and non-power events,
/// tracking the deterministically chosen `m.room.create` event, and yielding the separated subsets
/// for subsequent Kahn sorting and iterative auth checks.
#[allow(clippy::type_complexity)]
pub(crate) fn execute_power_phase<'a, Id, C, S1, S2>(
    unconflicted_state: &BTreeMap<(String, Option<String>), Id>,
    conflicted_events: &'a HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &'a HashMap<Id, LeanEvent<Id, C>, S2>,
    original_conflicted_keys: &alloc::collections::BTreeSet<Id>,
    version: StateResVersion,
) -> (
    crate::types::SortContext<'a, Id, C, S1, S2>, // sort_context
    HashMap<Id, LeanEvent<Id, C>>,                // power_events
    HashMap<Id, LeanEvent<Id, C>>,                // non_power_events
    Option<&'a LeanEvent<Id, C>>,                 // m.room.create event
)
where
    Id: crate::types::EventId,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    C: crate::types::EventContent,
{
    let sort_context = crate::types::SortContext {
        primary: conflicted_events,
        secondary: auth_context,
    };

    let mut power_events = HashMap::new();
    let mut non_power_events = HashMap::new();
    crate::lattice::route_power_events(
        conflicted_events,
        &mut power_events,
        &mut non_power_events,
        version,
    );

    if version != StateResVersion::V1 {
        expand_v2_power_events_auth_chains(
            &mut power_events,
            &mut non_power_events,
            conflicted_events,
        );
    }

    route_msc4297_ancestral_power_events(
        &mut power_events,
        auth_context,
        original_conflicted_keys,
        version,
    );

    let create_key = (
        String::from(crate::event_types::M_ROOM_CREATE),
        Some(String::new()),
    );

    let create_ev = unconflicted_state
        .get(&create_key)
        // 1. O(1) Fast Path: It's already in the agreed unconflicted state
        .and_then(|id| auth_context.get(id).or_else(|| conflicted_events.get(id)))
        // 2. Slow Path: It's currently in conflict (e.g. root of DAG)
        // We only scan the tiny `conflicted_events` set, NEVER the massive `auth_context`!
        .or_else(|| {
            conflicted_events
                .values()
                .find(|ev| ev.event_type == crate::event_types::M_ROOM_CREATE)
        })
        .or_else(|| {
            // Fallback only for weird test fixtures where create is completely missing from state
            auth_context
                .values()
                .find(|ev| ev.event_type == crate::event_types::M_ROOM_CREATE)
        });

    // Return updated refs
    (sort_context, power_events, non_power_events, create_ev)
}

/// Resolves conflicted Matrix room state using the specified algorithm version.
///
/// This is the primary entry point for state resolution. Given the set of
/// unconflicted state (agreed upon by all forks), the conflicted events
/// (present in some forks but not others), and the full auth context,
/// it produces the single deterministic resolved state map.
///
/// # Parameters
///
/// - `unconflicted_state`: State entries that all forks agree on, keyed by
///   `(event_type, state_key) -> event_id`. For **partial joins**, pass the
///   trusted state snapshot from the join response — this serves as the
///   checkpoint base. See _Checkpoint / Partial-Join_ below.
/// - `conflicted_events`: Events that differ across forks. These will be
///   sorted, auth-checked, and selectively applied.
/// - `auth_context`: The full set of events reachable via `auth_events`
///   from the conflicted set. Must include all power-level, membership,
///   and join-rules events needed for authorization.
/// - `version`: Which resolution algorithm to use (see [`StateResVersion`]).
///
/// # Returns
///
/// A `BTreeMap<(event_type, state_key), event_id>` representing the resolved
/// room state — the union of unconflicted state and the winners from the
/// conflicted set.
///
/// # Checkpoint / Partial-Join
///
/// For partial joins (federated rooms where a server doesn't have full
/// history), pass the trusted state snapshot as `unconflicted_state`:
///
/// ```rust,no_run
/// # use rezzy::{resolve_lean, LeanEvent, StateResVersion, HashMap};
/// # use std::collections::BTreeMap;
/// // State snapshot from /send_join response
/// let checkpoint: BTreeMap<(String, Option<String>), String> = /* ... */
/// # BTreeMap::new();
/// let new_events: HashMap<String, LeanEvent> = /* events since join */
/// # HashMap::new();
/// let auth_ctx: HashMap<String, LeanEvent> = /* auth chain for new_events */
/// # HashMap::new();
///
/// let resolved = resolve_lean(checkpoint, new_events, &auth_ctx, StateResVersion::V2);
/// ```
///
/// # Auth Chain Safety
///
/// **The auth chain for conflicted events must be complete.** You can trust a
/// snapshot for the unconflicted base, but truncating the auth chain for
/// conflicted events causes:
///
/// - **Sorting failures**: cannot establish mainline order without the full
///   power-level chain.
/// - **Auth check failures**: missing historical power levels or membership
///   events cause events to be incorrectly rejected.
/// - **State reset attacks**: an adversary can craft events whose truncated
///   auth chain makes an illegitimate power grab appear valid
///   (ref: CVE-2025-49090).
///
/// # Panics
///
/// Will panic if an event referenced in `auth_events` or `prev_events` by
/// a conflicted event is missing from both `conflicted_events` and
/// `auth_context`.
///
/// # Algorithm overview
///
/// 1. Classify conflicted events into **power events** (create, PL, join rules,
///    bans/kicks) and **non-power events**.
/// 2. Sort power events via [`lean_kahn_sort`] and iteratively auth-check them
///    to build the authoritative administrative state.
/// 3. Sort non-power events via [`mainline_sort`] (by proximity to the resolved
///    power-levels chain) and iteratively auth-check them.
/// 4. Merge winners into the unconflicted base.
#[must_use]
pub fn resolve_lean<
    Id: crate::types::EventId,
    C: crate::types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    unconflicted_state: BTreeMap<(String, Option<String>), Id>,
    conflicted_events: HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), Id> {
    resolve_lean_with_cache::<Id, C, S1, S2>(
        unconflicted_state,
        conflicted_events,
        auth_context,
        None,
        version,
    )
}

/// Like [`resolve_lean`], but allows passing an external local auth cache to amortize
/// allocation costs across multiple invocations.
#[must_use]
pub fn resolve_lean_with_cache<
    Id: crate::types::EventId,
    C: crate::types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    unconflicted_state: BTreeMap<(String, Option<String>), Id>,
    mut conflicted_events: HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    external_auth_cache: Option<&mut LocalAuthCache<Id, C>>,
    version: StateResVersion,
) -> BTreeMap<(String, Option<String>), Id> {
    let original_conflicted_keys =
        prepare_conflicted_and_keys(&mut conflicted_events, auth_context, version);

    // MSC4297 (v2.1+): The algorithm starts from an empty set of state.
    let mut resolved = get_initial_resolved_state(&unconflicted_state, version);

    let (sort_context, power_events, non_power_events, create_ev) = execute_power_phase(
        &unconflicted_state,
        &conflicted_events,
        auth_context,
        &original_conflicted_keys,
        version,
    );

    let mut fallback_cache = crate::state_at::LocalAuthCache::<Id, C>::new(version);
    let local_auth_cache = match external_auth_cache {
        Some(cache) => cache,
        None => &mut fallback_cache,
    };
    if local_auth_cache.version != version {
        local_auth_cache.map.clear();
        local_auth_cache.version = version;
    }

    run_power_phase_iterative_checks(
        &mut resolved,
        &power_events,
        &sort_context,
        auth_context,
        &conflicted_events,
        &original_conflicted_keys,
        version,
        local_auth_cache,
        create_ev,
    );

    let sort_set = &conflicted_events;

    // Step 3: Build the power-level mainline for mainline sort
    let mainline = build_mainline(&resolved, &sort_context);

    // Step 4: Sort non-power events by mainline ordering + iterative auth check
    let mut non_power_list: Vec<&LeanEvent<Id, C>> = non_power_events.values().collect();
    mainline_sort(&mut non_power_list, &mainline, &sort_context);

    for ev in non_power_list {
        let local_auth = compute_local_auth(ev, auth_context, sort_set, local_auth_cache, version);
        if iterative_auth_ok(
            ev,
            &resolved,
            auth_context,
            sort_set,
            local_auth,
            create_ev,
            version,
            false,
        ) {
            resolved.insert(
                (ev.event_type.clone(), ev.state_key.clone()),
                ev.event_id.clone(),
            );
        }
    }

    let mut final_resolved = unconflicted_state;
    for (k, v) in resolved {
        final_resolved.insert(k, v);
    }
    drop(conflicted_events);
    final_resolved
}

/// Like [`resolve_lean`], but also returns per-event
/// [`ResolutionDelta`](crate::state_delta::ResolutionDelta)s showing what
/// changed (or was rejected) at each step.
///
/// The deltas are ordered: power-phase events first, then non-power events,
/// each in their sorted processing order. Both accepted and rejected events
/// produce a delta entry.
///
/// # Returns
///
/// A tuple of `(resolved_state, deltas)`.
///
/// # Panics
///
/// Same conditions as [`resolve_lean`].
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
pub fn resolve_lean_with_deltas<
    Id: crate::types::EventId,
    C: crate::types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    unconflicted_state: BTreeMap<(String, Option<String>), Id>,
    conflicted_events: HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    version: StateResVersion,
) -> (
    BTreeMap<(String, Option<String>), Id>,
    alloc::vec::Vec<crate::state_delta::ResolutionDelta<Id>>,
) {
    resolve_lean_with_cache_and_deltas::<Id, C, S1, S2>(
        unconflicted_state,
        conflicted_events,
        auth_context,
        None,
        version,
    )
}

/// Internal helper combining the functionality of [`resolve_lean_with_deltas`] and
/// [`resolve_lean_with_cache`].
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
pub fn resolve_lean_with_cache_and_deltas<
    Id: crate::types::EventId,
    C: crate::types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    unconflicted_state: BTreeMap<(String, Option<String>), Id>,
    mut conflicted_events: HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    external_auth_cache: Option<&mut LocalAuthCache<Id, C>>,
    version: StateResVersion,
) -> (
    BTreeMap<(String, Option<String>), Id>,
    alloc::vec::Vec<crate::state_delta::ResolutionDelta<Id>>,
) {
    use crate::state_delta::{ResolutionDelta, ResolvePhase};

    let original_conflicted_keys =
        prepare_conflicted_and_keys(&mut conflicted_events, auth_context, version);

    let mut resolved = get_initial_resolved_state(&unconflicted_state, version);
    let mut deltas = alloc::vec::Vec::new();

    // --- Power phase (with delta tracking) ---

    let (sort_context, power_events, non_power_events, create_ev) = execute_power_phase(
        &unconflicted_state,
        &conflicted_events,
        auth_context,
        &original_conflicted_keys,
        version,
    );

    let mut fallback_cache = LocalAuthCache::new(version);
    let local_auth_cache = match external_auth_cache {
        Some(cache) => cache,
        None => &mut fallback_cache,
    };
    if local_auth_cache.version != version {
        local_auth_cache.map.clear();
        local_auth_cache.version = version;
    }

    let sort_set = &conflicted_events;

    let sorted_power_ids = lean_kahn_sort(&power_events, &sort_context, create_ev, version);
    for id in &sorted_power_ids {
        if let Some(event) = sort_set.get(id).or_else(|| auth_context.get(id)) {
            let key = (event.event_type.clone(), event.state_key.clone());
            let local_auth =
                compute_local_auth(event, auth_context, sort_set, local_auth_cache, version);
            let accepted = iterative_auth_ok(
                event,
                &resolved,
                auth_context,
                sort_set,
                local_auth,
                create_ev,
                version,
                true,
            );
            let replaced = if accepted {
                let old = resolved.get(&key).cloned();
                resolved.insert(key.clone(), event.event_id.clone());
                old
            } else {
                resolved.get(&key).cloned()
            };
            if original_conflicted_keys.contains(&event.event_id) {
                deltas.push(ResolutionDelta {
                    event_id: event.event_id.clone(),
                    accepted,
                    key,
                    replaced,
                    phase: ResolvePhase::Power,
                });
            }
        }
    }

    // --- Non-power phase (with delta tracking) ---

    let mainline = build_mainline(&resolved, &sort_context);
    let mut non_power_list: alloc::vec::Vec<&LeanEvent<Id, C>> =
        non_power_events.values().collect();
    mainline_sort(&mut non_power_list, &mainline, &sort_context);

    for ev in non_power_list {
        let key = (ev.event_type.clone(), ev.state_key.clone());
        let local_auth = compute_local_auth(ev, auth_context, sort_set, local_auth_cache, version);
        let accepted = iterative_auth_ok(
            ev,
            &resolved,
            auth_context,
            sort_set,
            local_auth,
            create_ev,
            version,
            false,
        );
        let replaced = if accepted {
            let old = resolved.get(&key).cloned();
            resolved.insert(key.clone(), ev.event_id.clone());
            old
        } else {
            resolved.get(&key).cloned()
        };
        deltas.push(ResolutionDelta {
            event_id: ev.event_id.clone(),
            accepted,
            key,
            replaced,
            phase: ResolvePhase::NonPower,
        });
    }

    let mut final_resolved = unconflicted_state;
    for (k, v) in resolved {
        final_resolved.insert(k, v);
    }
    drop(conflicted_events);
    (final_resolved, deltas)
}
