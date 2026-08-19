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

//! State resolution entry point — the [`resolve_iterative_sort`] function.
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
//! [`crate::resolve::lattice::resolve_lattice_fold`].

use crate::basespec::event_types::EventType;
use crate::basespec::rezzy_types::{LeanEvent, StateResVersion};
use crate::{
    resolve::sorting::{build_mainline, build_mainline_with_cache, lean_kahn_sort, mainline_sort},
    state::at::{compute_local_auth, iterative_auth_ok, LocalAuthCache},
    FastMap, HashMap,
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Prepares the conflicted events map and tracks original conflicted keys before CDO pre-filtering.
pub(crate) fn prepare_conflicted_and_keys<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    conflicted_events: &mut HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    version: StateResVersion,
) -> alloc::collections::BTreeSet<Id> {
    let original_conflicted_keys = conflicted_events.keys().cloned().collect();
    if version == StateResVersion::V2_1_1 {
        let filtered = crate::resolve::cdo::apply_cdo_filter(conflicted_events, auth_context);
        conflicted_events.clear();
        for (k, v) in filtered {
            conflicted_events.insert(k, v);
        }
    }
    original_conflicted_keys
}

/// Derives a genuine-conflicted-key set by treating every event in
/// `conflicted_events` as genuinely conflicting (as opposed to being present
/// only as auth-chain context for a *different* key's genuine conflict).
///
/// This is the default used by the public `resolve_iterative_sort*` entry
/// points, which take a single flat `conflicted_events` map and have no way
/// to know which of its entries came from a real per-key state-map diff
/// versus a supplemental auth-diff/MSC4297-subgraph walk — so they preserve
/// the pre-existing (pre-fix) behavior: nothing in `conflicted_events` is
/// blocked from deciding its own key. Callers that *do* know the real
/// distinction (`resolve_multiple_prev_states` in `state::at`, and
/// `resolve_state_maps`/`resolve_state_maps_lazy_with_diff` in
/// `resolve::multi`) bypass this default and call
/// `resolve_iterative_sort_with_all_caches` directly with the narrower,
/// real set captured *before* their own supplementation step.
// TODO(perf): this calls `EventType::from(ev.event_type.as_str())` once per
// conflicted event just to build the gate set, and the power/non-power
// phase loops below call it *again* on the same event when actually
// inserting into `resolved`. For well-known types (the common case:
// create/power_levels/join_rules/member) that's just a few cheap string
// comparisons, but for `EventType::Custom` it's a duplicate `Box<str>` heap
// allocation per conflicted event. Fixing this properly means threading the
// already-interned `EventType` alongside each event through
// `route_power_events`/`power_events`/`non_power_events` (currently keyed by
// `Id` only) instead of re-deriving it — a real (if narrow) restructure, not
// attempted here since it's a constant-factor cost bounded by the conflicted
// set size, not the full event set.
pub(crate) fn derive_all_conflicted_keys<Id, C, S>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>, S>,
) -> crate::FastSet<(EventType, String)>
where
    Id: crate::basespec::rezzy_types::EventId,
{
    conflicted_events
        .values()
        .map(|ev| {
            (
                EventType::from(ev.event_type.as_str()),
                ev.state_key.clone().unwrap_or_default(),
            )
        })
        .collect()
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
    Id: crate::basespec::rezzy_types::EventId,
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
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + Clone,
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
    resolved: &mut crate::state::at::SharedState<Id>,
    power_events: &HashMap<Id, LeanEvent<Id, C>, S4>,
    sort_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C>, S3>,
    version: StateResVersion,
    local_auth_cache: &mut LocalAuthCache<Id, C>,
    create_ev: Option<&LeanEvent<Id, C>>,
    pl_cache: &mut HashMap<Id, i64>,
    conflicted_keys: &crate::FastSet<(EventType, String)>,
) where
    Id: crate::basespec::rezzy_types::EventId,
    S2: core::hash::BuildHasher,
    S3: core::hash::BuildHasher,
    S4: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
{
    let sorted_power_ids = lean_kahn_sort(power_events, sort_context, create_ev, version, pl_cache);
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
                if let Some(sk) = &event.state_key {
                    let key = (EventType::from(event.event_type.as_str()), sk.clone());
                    // Only a genuinely conflicted key may be decided by the
                    // power phase. `power_events` can also contain events
                    // pulled in purely as auth-chain context (the
                    // `auth(C) \ auth(U)` supplement, or the MSC4297
                    // conflicted subgraph) — those exist so *other*, actually
                    // conflicting events' auth chains can be validated, not
                    // so their own (possibly stale, superseded) key can win
                    // over a value every merge parent already agreed on.
                    if !conflicted_keys.contains(&key) {
                        continue;
                    }
                    resolved.insert(key, event.event_id.clone());
                }
            }
        }
    }
}

/// Returns the starting point for state resolution based on the algorithm version.
/// V1 and V2 inherit the unconflicted state as their base, whereas V2.1+ starts from an empty set.
pub(crate) fn get_initial_resolved_state<Id>(
    unconflicted_state: &crate::state::at::SharedState<Id>,
    version: StateResVersion,
) -> crate::state::at::SharedState<Id>
where
    Id: Clone,
{
    if version.is_v2_1_plus() {
        imbl::OrdMap::new()
    } else {
        unconflicted_state.clone()
    }
}

pub(crate) fn merge_unconflicted_power_events<Id>(
    version: StateResVersion,
    unconflicted_state: &crate::state::at::SharedState<Id>,
    resolved: &mut crate::state::at::SharedState<Id>,
) where
    Id: Clone,
{
    use crate::basespec::event_types::{M_ROOM_CREATE, M_ROOM_JOIN_RULES, M_ROOM_POWER_LEVELS};

    // Under V2.1+, progressive state resolution starts empty, meaning unconflicted power
    // events are missing from `resolved`. We must merge unconflicted power events (like power levels)
    // into `resolved` before building the mainline, so they are visible to `build_mainline` and sorting.
    if version.is_v2_1_plus() {
        for event_type in [M_ROOM_POWER_LEVELS, M_ROOM_JOIN_RULES, M_ROOM_CREATE] {
            let key = (EventType::from(event_type), alloc::string::String::new());
            if let Some(v) = unconflicted_state.get(&key) {
                resolved.entry(key).or_insert_with(|| v.clone());
            }
        }
    }
}

/// Executes the first half of the Matrix State Resolution algorithm (the power phase).
///
/// This involves setting up the sorting context, dividing events into power and non-power events,
/// tracking the deterministically chosen `m.room.create` event, and yielding the separated subsets
/// for subsequent Kahn sorting and iterative auth checks.
#[allow(clippy::type_complexity)]
pub(crate) fn execute_power_phase<'a, Id, C, S1, S2>(
    unconflicted_state: &crate::state::at::SharedState<Id>,
    conflicted_events: &'a HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &'a HashMap<Id, LeanEvent<Id, C>, S2>,
    original_conflicted_keys: &alloc::collections::BTreeSet<Id>,
    version: StateResVersion,
) -> (
    crate::basespec::rezzy_types::SortContext<'a, Id, C, S1, S2>, // sort_context
    HashMap<Id, LeanEvent<Id, C>>,                                // power_events
    HashMap<Id, LeanEvent<Id, C>>,                                // non_power_events
    Option<&'a LeanEvent<Id, C>>,                                 // m.room.create event
)
where
    Id: crate::basespec::rezzy_types::EventId,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
{
    let sort_context = crate::basespec::rezzy_types::SortContext {
        primary: conflicted_events,
        secondary: auth_context,
        _marker: core::marker::PhantomData,
    };

    let mut power_events = HashMap::new();
    let mut non_power_events = HashMap::new();
    crate::resolve::lattice::route_power_events(
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
        EventType::from(crate::basespec::event_types::M_ROOM_CREATE),
        String::new(),
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
                .filter(|ev| ev.event_type == crate::basespec::event_types::M_ROOM_CREATE)
                .min_by_key(|ev| &ev.event_id)
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
/// A `imbl::OrdMap<(event_type, state_key), event_id>` representing the resolved
/// room state — the union of unconflicted state and the winners from the
/// conflicted set.
///
/// # Checkpoint / Partial-Join
///
/// For partial joins (federated rooms where a server doesn't have full
/// history), pass the trusted state snapshot as `unconflicted_state`:
///
/// ```rust,no_run
/// # use rezzy::{resolve_iterative_sort, LeanEvent, StateResVersion, HashMap};
/// # use rezzy::basespec::event_types::EventType;
/// # use imbl::OrdMap;
/// // State snapshot from /send_join response
/// let checkpoint: imbl::OrdMap<(EventType, String), String> = /* ... */
/// # imbl::OrdMap::new();
/// let new_events: HashMap<String, LeanEvent> = /* events since join */
/// # HashMap::new();
/// let auth_ctx: HashMap<String, LeanEvent> = /* auth chain for new_events */
/// # HashMap::new();
///
/// let resolved = resolve_iterative_sort(checkpoint, new_events, &auth_ctx, StateResVersion::V2, &mut std::collections::HashMap::new());
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
#[allow(clippy::implicit_hasher)]
pub fn resolve_iterative_sort<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    unconflicted_state: crate::state::at::SharedState<Id>,
    conflicted_events: HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> crate::state::at::SharedState<Id> {
    resolve_iterative_sort_with_cache::<Id, C, S1, S2>(
        unconflicted_state,
        conflicted_events,
        auth_context,
        None,
        version,
        pl_cache,
    )
}

/// Like [`resolve_iterative_sort`], but allows passing an external local auth cache to amortize
/// allocation costs across multiple invocations.
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn resolve_iterative_sort_with_cache<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    unconflicted_state: crate::state::at::SharedState<Id>,
    conflicted_events: HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    external_auth_cache: Option<&mut LocalAuthCache<Id, C>>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> crate::state::at::SharedState<Id> {
    let conflicted_keys = derive_all_conflicted_keys(&conflicted_events);
    resolve_iterative_sort_with_all_caches::<Id, C, S1, S2>(
        unconflicted_state,
        conflicted_events,
        auth_context,
        external_auth_cache,
        version,
        pl_cache,
        &mut FastMap::default(),
        &conflicted_keys,
    )
}

/// Like [`resolve_iterative_sort_with_cache`], but additionally accepts a
/// `mainline_cache` (nearest `m.room.power_levels` ancestor per event ID) that
/// callers invoking this repeatedly against the same DAG (e.g. the fork-merge
/// loop in [`crate::state::at::run_state_pipeline_streaming`]) can thread
/// across calls, so `build_mainline`'s BFS-per-call turns into an `O(M)`
/// cache-hit walk instead of restarting from scratch every time.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_iterative_sort_with_all_caches<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    unconflicted_state: crate::state::at::SharedState<Id>,
    mut conflicted_events: HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    external_auth_cache: Option<&mut LocalAuthCache<Id, C>>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
    mainline_cache: &mut FastMap<Id, Option<Id>>,
    conflicted_keys: &crate::FastSet<(EventType, String)>,
) -> crate::state::at::SharedState<Id> {
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

    let mut fallback_cache = crate::state::at::LocalAuthCache::<Id, C>::new(version);
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
        version,
        local_auth_cache,
        create_ev,
        pl_cache,
        conflicted_keys,
    );

    let sort_set = &conflicted_events;

    merge_unconflicted_power_events(version, &unconflicted_state, &mut resolved);

    // Step 3: Build the power-level mainline for mainline sort
    let mainline = build_mainline_with_cache(&resolved, &sort_context, mainline_cache);

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
            if let Some(sk) = &ev.state_key {
                let key = (EventType::from(ev.event_type.as_str()), sk.clone());
                // Same guard as the power phase: only a genuinely conflicted
                // key may be decided here.
                if conflicted_keys.contains(&key) {
                    resolved.insert(key, ev.event_id.clone());
                }
            }
        }
    }

    // Final step (Matrix v2 spec): "Update the result of step 5 with the
    // unconflicted state." The correct merge direction depends on what
    // `resolved` already contains, which differs by version:
    //
    // - V1/V2: `get_initial_resolved_state` seeds `resolved` as a *clone* of
    //   `unconflicted_state`, so every unconflicted value is already present.
    //   Applying unconflicted last is then a no-op for every legitimately
    //   resolved key, and only matters where an auth-diff-supplied power
    //   event (pulled into `conflicted_events` purely to supply auth context
    //   for a genuinely conflicting *other* key) incorrectly overwrote a key
    //   that was never actually in conflict — which it must not be allowed
    //   to do. So unconflicted must win here.
    // - V2.1+: `resolved` starts *empty*, and `merge_unconflicted_power_events`
    //   deliberately re-admits only power_levels/join_rules/create (via
    //   `or_insert_with`, never overwriting). Other keys — notably
    //   membership — are intentionally left for the power/non-power phases
    //   to populate from scratch, which is how MSC4297 ban/kick
    //   supplementation works: a validly-authorized ban pulled in via the
    //   auth diff must be able to override a stale "unconflicted" join,
    //   and federation convergence requires matching other MSC4297
    //   implementations here. So `resolved` must win.
    let final_resolved = if version.is_v2_1_plus() {
        let mut f = unconflicted_state;
        for (k, v) in resolved {
            f.insert(k, v);
        }
        f
    } else {
        let mut f = resolved;
        for (k, v) in unconflicted_state {
            f.insert(k, v);
        }
        f
    };
    drop(conflicted_events);
    final_resolved
}

/// Like [`resolve_iterative_sort`], but also returns per-event
/// [`ResolutionDelta`](crate::state::delta::ResolutionDelta)s showing what
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
/// Same conditions as [`resolve_iterative_sort`].
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
#[allow(clippy::implicit_hasher)]
pub fn resolve_iterative_sort_with_deltas<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    unconflicted_state: crate::state::at::SharedState<Id>,
    conflicted_events: HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> (
    crate::state::at::SharedState<Id>,
    alloc::vec::Vec<crate::state::delta::ResolutionDelta<Id>>,
) {
    resolve_iterative_sort_with_cache_and_deltas::<Id, C, S1, S2>(
        unconflicted_state,
        conflicted_events,
        auth_context,
        None,
        version,
        pl_cache,
    )
}

/// Internal helper combining the functionality of [`resolve_iterative_sort_with_deltas`] and
/// [`resolve_iterative_sort_with_cache`].
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
#[allow(clippy::implicit_hasher)]
pub fn resolve_iterative_sort_with_cache_and_deltas<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
>(
    unconflicted_state: crate::state::at::SharedState<Id>,
    mut conflicted_events: HashMap<Id, LeanEvent<Id, C>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C>, S2>,
    external_auth_cache: Option<&mut LocalAuthCache<Id, C>>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> (
    crate::state::at::SharedState<Id>,
    alloc::vec::Vec<crate::state::delta::ResolutionDelta<Id>>,
) {
    use crate::state::delta::{ResolutionDelta, ResolvePhase};

    let conflicted_keys = derive_all_conflicted_keys(&conflicted_events);
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

    let sorted_power_ids =
        lean_kahn_sort(&power_events, &sort_context, create_ev, version, pl_cache);
    for id in &sorted_power_ids {
        if let Some(event) = sort_set.get(id).or_else(|| auth_context.get(id)) {
            let Some(sk) = &event.state_key else { continue };
            let key = (EventType::from(event.event_type.as_str()), sk.clone());
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
            let replaced = if accepted && conflicted_keys.contains(&key) {
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
                    key: (key.0.to_string(), key.1),
                    replaced,
                    phase: ResolvePhase::Power,
                });
            }
        }
    }

    // --- Non-power phase (with delta tracking) ---

    merge_unconflicted_power_events(version, &unconflicted_state, &mut resolved);

    let mainline = build_mainline(&resolved, &sort_context);
    let mut non_power_list: alloc::vec::Vec<&LeanEvent<Id, C>> =
        non_power_events.values().collect();
    mainline_sort(&mut non_power_list, &mainline, &sort_context);

    for ev in non_power_list {
        let Some(sk) = &ev.state_key else { continue };
        let key = (EventType::from(ev.event_type.as_str()), sk.clone());
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
        let replaced = if accepted && conflicted_keys.contains(&key) {
            let old = resolved.get(&key).cloned();
            resolved.insert(key.clone(), ev.event_id.clone());
            old
        } else {
            resolved.get(&key).cloned()
        };
        deltas.push(ResolutionDelta {
            event_id: ev.event_id.clone(),
            accepted,
            key: (key.0.to_string(), key.1),
            replaced,
            phase: ResolvePhase::NonPower,
        });
    }

    // Same version-gated fix as resolve_iterative_sort_with_all_caches: see
    // the comment there for why V1/V2 and V2.1+ need opposite merge
    // directions for this final step.
    let final_resolved = if version.is_v2_1_plus() {
        let mut f = unconflicted_state;
        for (k, v) in resolved {
            f.insert(k, v);
        }
        f
    } else {
        let mut f = resolved;
        for (k, v) in unconflicted_state {
            f.insert(k, v);
        }
        f
    };
    drop(conflicted_events);
    (final_resolved, deltas)
}
