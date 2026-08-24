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
//! 1. **Resolved-state screening pass** (V2.1.1+): drops non-power conflicted
//!    events whose sender is already banned in the resolved state
//!    (`is_sender_banned`), the sound replacement for the retired CDO pre-filter.
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
use alloc::vec::Vec;

/// Prepares the conflicted events map and tracks the original conflicted keys
/// for the resolved-state screening pass (the CDO pre-filter that formerly ran
/// here is retired — see the body comment below).
pub(crate) fn prepare_conflicted_and_keys<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    K,
>(
    conflicted_events: &mut HashMap<Id, LeanEvent<Id, C, K>, S1>,
    _auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
    _version: StateResVersion,
) -> alloc::collections::BTreeSet<Id>
where
    K: AsRef<str> + Clone,
{
    // The V2.1.1 CDO pre-filter used to run here, dropping conflicted events
    // that are causally dominated by a structurally-admin event
    // (ban/kick/lockdown/demotion) without verifying the dominator passes auth.
    // That is a state-erasure vector: an auth-invalid, low-power user's forged
    // ban erases legitimate memberships on CDO-running servers while non-CDO
    // (Synapse) servers keep them — a permanent federation fork. A drop is
    // sound iff IterativeAuthChecks would have rejected the event, which the
    // CDO could not establish at this (pre-auth) point.
    //
    // The pre-filter is retired from the live path (see src/resolve/cdo.rs,
    // retained as design history). Its sound replacement -- a resolved-state
    // screening pass that applies auth predicates (is the sender banned?)
    // directly instead of approximating domination -- lives in
    // `is_sender_banned` below, applied after the power phase, not here.
    // Do NOT restore this call without an equivalent soundness guarantee.
    conflicted_events.keys().cloned().collect()
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
pub(crate) fn derive_all_conflicted_keys<Id, C, S, K>(
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S>,
) -> crate::FastSet<(EventType, K)>
where
    Id: crate::basespec::rezzy_types::EventId,
    K: Clone + Default + Eq + core::hash::Hash,
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
    K: Clone,
>(
    power_events: &mut HashMap<Id, LeanEvent<Id, C, K>, S1>,
    non_power_events: &mut HashMap<Id, LeanEvent<Id, C, K>, S2>,
    sort_set: &HashMap<Id, LeanEvent<Id, C, K>, S3>,
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
    K: Clone,
>(
    power_events: &mut HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
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
pub(crate) fn run_power_phase_iterative_checks<Id, C, S2, S3, S4, K>(
    resolved: &mut crate::state::at::SharedState<Id, K>,
    power_events: &HashMap<Id, LeanEvent<Id, C, K>, S4>,
    sort_context: &impl crate::basespec::rezzy_types::EventProvider<Id, C, LeanEvent<Id, C, K>>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
    conflicted_events: &HashMap<Id, LeanEvent<Id, C, K>, S3>,
    version: StateResVersion,
    local_auth_cache: &mut LocalAuthCache<Id, C, K>,
    create_ev: Option<&LeanEvent<Id, C, K>>,
    pl_cache: &mut HashMap<Id, i64>,
    conflicted_keys: &crate::FastSet<(EventType, K)>,
) where
    Id: crate::basespec::rezzy_types::EventId,
    S2: core::hash::BuildHasher,
    S3: core::hash::BuildHasher,
    S4: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let sorted_power_ids = lean_kahn_sort(power_events, sort_context, create_ev, version, pl_cache);
    for id in &sorted_power_ids {
        // Every power event is drawn from the conflicted set or the auth
        // context (route_power_events + expand_v2 + route_msc4297), so a sorted
        // id is always resolvable here.
        let event = conflicted_events
            .get(id)
            .or_else(|| auth_context.get(id))
            .expect("sorted power events are always present in conflicted_events or auth_context");
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
            // Power events are usually state events, but malformed or
            // network-originated input may lack a state_key; skip those
            // rather than panic.
            let Some(sk) = event.state_key.as_ref() else {
                continue;
            };
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

/// Returns the starting point for state resolution based on the algorithm version.
/// V1 and V2 inherit the unconflicted state as their base, whereas V2.1+ starts from an empty set.
pub(crate) fn get_initial_resolved_state<Id, K>(
    unconflicted_state: &crate::state::at::SharedState<Id, K>,
    version: StateResVersion,
) -> crate::state::at::SharedState<Id, K>
where
    Id: Clone,
    K: Ord + Clone,
{
    if version.is_v2_1_plus() {
        imbl::OrdMap::new()
    } else {
        unconflicted_state.clone()
    }
}

pub(crate) fn merge_unconflicted_power_events<Id, K>(
    version: StateResVersion,
    unconflicted_state: &crate::state::at::SharedState<Id, K>,
    resolved: &mut crate::state::at::SharedState<Id, K>,
) where
    Id: Clone,
    K: Ord + Clone + Default,
{
    use crate::basespec::event_types::{M_ROOM_CREATE, M_ROOM_JOIN_RULES, M_ROOM_POWER_LEVELS};

    // Under V2.1+, progressive state resolution starts empty, meaning unconflicted power
    // events are missing from `resolved`. We must merge unconflicted power events (like power levels)
    // into `resolved` before building the mainline, so they are visible to `build_mainline` and sorting.
    if version.is_v2_1_plus() {
        for event_type in [M_ROOM_POWER_LEVELS, M_ROOM_JOIN_RULES, M_ROOM_CREATE] {
            let key = (EventType::from(event_type), K::default());
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
pub(crate) fn execute_power_phase<'a, Id, C, S1, S2, K>(
    unconflicted_state: &crate::state::at::SharedState<Id, K>,
    conflicted_events: &'a HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &'a HashMap<Id, LeanEvent<Id, C, K>, S2>,
    original_conflicted_keys: &alloc::collections::BTreeSet<Id>,
    version: StateResVersion,
) -> (
    crate::basespec::rezzy_types::SortContext<'a, Id, C, S1, S2, LeanEvent<Id, C, K>>, // sort_context
    HashMap<Id, LeanEvent<Id, C, K>>, // power_events
    HashMap<Id, LeanEvent<Id, C, K>>, // non_power_events
    Option<&'a LeanEvent<Id, C, K>>,  // m.room.create event
)
where
    Id: crate::basespec::rezzy_types::EventId,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    C: crate::basespec::rezzy_types::EventContent,
    K: Ord + Clone + Default + AsRef<str>,
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
        K::default(),
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

/// Returns `true` if `ev`'s sender is banned in the resolved state.
///
/// This is the resolved-state screening pass predicate — the sound replacement
/// for the retired CDO pre-filter. Bans are established by the power phase: a
/// sender banned in the power-phase `resolved` is banned throughout the
/// non-power phase (bans only change via power events, which are complete), so
/// the non-power iterative auth would reject such an event regardless of any
/// accepted-event mutations. Dropping these events before the mainline sort is
/// therefore sound, and it only removes events (never reorders), so the
/// mainline ordering of the surviving set is unchanged.
pub(crate) fn is_sender_banned<Id, C, K>(
    ev: &LeanEvent<Id, C, K>,
    resolved: &crate::state::at::SharedState<Id, K>,
    events: &impl crate::basespec::rezzy_types::EventProvider<Id, C, LeanEvent<Id, C, K>>,
) -> bool
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
    K: Ord + Clone + Default + AsRef<str> + 'static,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    use crate::auth::StateKeyDyn;
    use crate::basespec::event_types::{MEM_BAN, M_ROOM_MEMBER};
    let query: &dyn StateKeyDyn = &(M_ROOM_MEMBER, ev.sender.as_str());
    match resolved.get(query) {
        Some(member_id) => events
            .get_event(member_id)
            .is_some_and(|m| m.get_membership() == Some(MEM_BAN)),
        None => false,
    }
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
/// # Resolved-state screening pass
///
/// For V2.1+, after the power phase, non-power conflicted events whose sender
/// is already banned in `resolved` are dropped before the mainline sort (see
/// the private `is_sender_banned` helper below). This is the sound
/// replacement for the retired CDO pre-filter: it applies the auth predicate
/// directly against the authoritative resolved state rather than
/// approximating causal domination.
///
/// # Algorithm overview
///
/// 1. Classify conflicted events into **power events** (create, PL, join rules,
///    bans/kicks) and **non-power events**.
/// 2. Sort power events via [`lean_kahn_sort`] and iteratively auth-check them
///    to build the authoritative administrative state.
/// 3. Sort non-power events via [`mainline_sort`] (by proximity to the resolved
///    power-levels chain) and iteratively auth-check them, after the
///    resolved-state screening pass drops senders already banned in `resolved`.
/// 4. Merge winners into the unconflicted base.
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn resolve_iterative_sort<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    K,
>(
    unconflicted_state: crate::state::at::SharedState<Id, K>,
    conflicted_events: HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> crate::state::at::SharedState<Id, K>
where
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    resolve_iterative_sort_with_cache::<Id, C, S1, S2, K>(
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
    K,
>(
    unconflicted_state: crate::state::at::SharedState<Id, K>,
    conflicted_events: HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
    external_auth_cache: Option<&mut LocalAuthCache<Id, C, K>>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> crate::state::at::SharedState<Id, K>
where
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    let conflicted_keys = derive_all_conflicted_keys(&conflicted_events);
    resolve_iterative_sort_with_all_caches::<Id, C, S1, S2, K>(
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
    K,
>(
    unconflicted_state: crate::state::at::SharedState<Id, K>,
    mut conflicted_events: HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
    external_auth_cache: Option<&mut LocalAuthCache<Id, C, K>>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
    mainline_cache: &mut FastMap<Id, Option<Id>>,
    conflicted_keys: &crate::FastSet<(EventType, K)>,
) -> crate::state::at::SharedState<Id, K>
where
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
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

    let mut fallback_cache = crate::state::at::LocalAuthCache::<Id, C, K>::new(version);
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

    // Resolved-state screening pass (V2.1.1+): drop non-power conflicted events
    // whose sender is already banned in `resolved`, before mainline sort. Sound
    // because bans are fixed by the power phase (see [`is_sender_banned`]). This
    // is the sound replacement for the retired CDO pre-filter, which itself was
    // gated to `V2_1_1` only (never `V2_1`) before its retirement -- V2.1 does
    // not get this hardening by default. Goes through the shared
    // `has_ban_evasion_hardening` method (not a local `matches!` copy) so
    // this can't silently drift from `state::at`'s `get_event` gate again --
    // see `StateResVersion::has_ban_evasion_hardening`'s docs.
    let mut non_power_list: Vec<&LeanEvent<Id, C, K>> = if version.has_ban_evasion_hardening() {
        non_power_events
            .iter()
            .filter(|(_, ev)| !is_sender_banned(ev, &resolved, &sort_context))
            .map(|(_, ev)| ev)
            .collect()
    } else {
        non_power_events.values().collect()
    };
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
    K,
>(
    unconflicted_state: crate::state::at::SharedState<Id, K>,
    conflicted_events: HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> (
    crate::state::at::SharedState<Id, K>,
    alloc::vec::Vec<crate::state::delta::ResolutionDelta<Id, K>>,
)
where
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
    resolve_iterative_sort_with_cache_and_deltas::<Id, C, S1, S2, K>(
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
///
/// # Panics
/// Panics (with a descriptive message) if an invariant of the power phase is
/// violated: a topologically-sorted power event id is missing from both
/// `conflicted_events` and `auth_context`, or a power event lacks a
/// `state_key`. Both are structural guarantees — power events are always
/// drawn from those two maps and are always state events — so these panics
/// indicate a routing bug rather than a caller-input condition.
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_lines)]
#[allow(clippy::implicit_hasher)]
pub fn resolve_iterative_sort_with_cache_and_deltas<
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent + Clone,
    S1: core::hash::BuildHasher,
    S2: core::hash::BuildHasher,
    K,
>(
    unconflicted_state: crate::state::at::SharedState<Id, K>,
    mut conflicted_events: HashMap<Id, LeanEvent<Id, C, K>, S1>,
    auth_context: &HashMap<Id, LeanEvent<Id, C, K>, S2>,
    external_auth_cache: Option<&mut LocalAuthCache<Id, C, K>>,
    version: StateResVersion,
    pl_cache: &mut HashMap<Id, i64>,
) -> (
    crate::state::at::SharedState<Id, K>,
    alloc::vec::Vec<crate::state::delta::ResolutionDelta<Id, K>>,
)
where
    K: crate::basespec::rezzy_types::StateKey,
    for<'q> (EventType, K): core::borrow::Borrow<dyn crate::auth::StateKeyDyn + 'q>,
{
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
        // Same invariant as the non-delta power phase: every power event is
        // drawn from the conflicted set or the auth context.
        let event = sort_set
            .get(id)
            .or_else(|| auth_context.get(id))
            .expect("sorted power events are always present in sort_set or auth_context");
        // Power events are usually state events, but malformed or
        // network-originated input may lack a state_key; skip those rather
        // than panic.
        let Some(sk) = event.state_key.as_ref() else {
            continue;
        };
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
                key: key.clone(),
                replaced,
                phase: ResolvePhase::Power,
            });
        }
    }

    // --- Non-power phase (with delta tracking) ---

    merge_unconflicted_power_events(version, &unconflicted_state, &mut resolved);

    let mainline = build_mainline(&resolved, &sort_context);
    // Same resolved-state screening pass (V2.1.1+) as the main path in
    // `resolve_iterative_sort_with_all_caches`: drop non-power conflicted
    // events whose sender is already banned in `resolved` before mainline sort,
    // so the delta path has the same ban-evasion behavior. See that pass's
    // comment for the soundness argument and version gating. Screened events
    // are collected separately so the per-event delta contract still records
    // their rejection below.
    let mut non_power_list: alloc::vec::Vec<&LeanEvent<Id, C, K>> = alloc::vec::Vec::new();
    let mut screened: alloc::vec::Vec<&LeanEvent<Id, C, K>> = alloc::vec::Vec::new();
    if version.has_ban_evasion_hardening() {
        for ev in non_power_events.values() {
            if is_sender_banned(ev, &resolved, &sort_context) {
                screened.push(ev);
            } else {
                non_power_list.push(ev);
            }
        }
    } else {
        non_power_list.extend(non_power_events.values());
    }
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
            key: key.clone(),
            replaced,
            phase: ResolvePhase::NonPower,
        });
    }

    // Banned-sender events were screened out before mainline sort above (same
    // as the main path), but the per-event delta contract still requires a
    // rejected delta for each one rather than silently omitting it.
    for ev in screened {
        let Some(sk) = &ev.state_key else { continue };
        let key = (EventType::from(ev.event_type.as_str()), sk.clone());
        let replaced = resolved.get(&key).cloned();
        deltas.push(ResolutionDelta {
            event_id: ev.event_id.clone(),
            accepted: false,
            key,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basespec::event_types::{EventType, MEM_BAN, MEM_JOIN, M_ROOM_MEMBER};
    use crate::basespec::rezzy_types::LeanEvent;
    use crate::state::at::SharedState;
    use alloc::string::{String, ToString};

    fn member_ev(id: &str, sender: &str, target: &str, membership: &str) -> LeanEvent {
        LeanEvent {
            event_id: id.into(),
            event_type: M_ROOM_MEMBER.into(),
            state_key: Some(target.into()),
            sender: sender.into(),
            content: serde_json::json!({ "membership": membership }),
            ..Default::default()
        }
    }

    #[test]
    fn is_sender_banned_detects_banned_sender() {
        let mut resolved: SharedState<String, String> = SharedState::new();
        resolved.insert(
            (EventType::from(M_ROOM_MEMBER), "@bob".to_string()),
            "$ban".to_string(),
        );
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "$ban".to_string(),
            member_ev("$ban", "@admin", "@bob", MEM_BAN),
        );

        let ev = member_ev("$bob_msg", "@bob", "@bob", MEM_JOIN);
        assert!(is_sender_banned(&ev, &resolved, &events));
    }

    #[test]
    fn is_sender_banned_false_when_not_banned() {
        let mut resolved: SharedState<String, String> = SharedState::new();
        resolved.insert(
            (EventType::from(M_ROOM_MEMBER), "@bob".to_string()),
            "$join".to_string(),
        );
        let mut events: HashMap<String, LeanEvent> = HashMap::new();
        events.insert(
            "$join".to_string(),
            member_ev("$join", "@admin", "@bob", MEM_JOIN),
        );

        let ev = member_ev("$bob_msg", "@bob", "@bob", MEM_JOIN);
        assert!(!is_sender_banned(&ev, &resolved, &events));

        // No membership event at all -> not banned.
        assert!(!is_sender_banned(&ev, &SharedState::new(), &HashMap::new()));
    }

    /// A shared room for the resolved-state screening tests below: create,
    /// power levels (admin only), public join rule, two joins, and a ban of bob.
    /// Returns `(unconflicted, auth_context)` with only create agreed-upon.
    fn screening_room_fixture() -> (SharedState<String, String>, HashMap<String, LeanEvent>) {
        let create = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            sender: "@admin:example.com".into(),
            content: serde_json::json!({"room_version": "12.1", "creator": "@admin:example.com"}),
            ..Default::default()
        };
        let admin_join = member_ev(
            "$admin_join",
            "@admin:example.com",
            "@admin:example.com",
            MEM_JOIN,
        );
        let pl = LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@admin:example.com".into(),
            content: serde_json::json!({
                "users": { "@admin:example.com": 100 },
                "ban": 50,
                "state_default": 50
            }),
            auth_events: alloc::vec!["$create".to_string(), "$admin_join".to_string()],
            ..Default::default()
        };
        let join_rules = LeanEvent {
            event_id: "$jr".into(),
            event_type: "m.room.join_rules".into(),
            state_key: Some(String::new()),
            sender: "@admin:example.com".into(),
            content: serde_json::json!({"join_rule": "public"}),
            auth_events: alloc::vec![
                "$create".to_string(),
                "$admin_join".to_string(),
                "$pl".to_string()
            ],
            ..Default::default()
        };
        let bob_join = member_ev(
            "$bob_join",
            "@bob:example.com",
            "@bob:example.com",
            MEM_JOIN,
        );
        let carol_join = member_ev(
            "$carol_join",
            "@carol:example.com",
            "@carol:example.com",
            MEM_JOIN,
        );
        let ban_bob = LeanEvent {
            event_id: "$ban_bob".into(),
            event_type: M_ROOM_MEMBER.into(),
            state_key: Some("@bob:example.com".into()),
            sender: "@admin:example.com".into(),
            content: serde_json::json!({"membership": MEM_BAN}),
            auth_events: alloc::vec![
                "$create".to_string(),
                "$admin_join".to_string(),
                "$bob_join".to_string(),
                "$pl".to_string()
            ],
            ..Default::default()
        };

        let mut ac = HashMap::new();
        for e in [
            &create,
            &admin_join,
            &pl,
            &join_rules,
            &bob_join,
            &carol_join,
            &ban_bob,
        ] {
            ac.insert(e.event_id.clone(), e.clone());
        }
        let mut unconflicted = SharedState::new();
        unconflicted.insert(
            (EventType::from("m.room.create"), String::new()),
            "$create".to_string(),
        );
        (unconflicted, ac)
    }

    /// Covers the V2.1.1+ resolved-state screening filter in the delta path
    /// (`resolve_iterative_sort_with_cache_and_deltas`): the
    /// `!is_sender_banned(...)` predicate must drop a non-power event whose
    /// sender is already banned in `resolved` (fixed by the power phase), while
    /// keeping an unbanned sender's event. V2.1 must NOT apply the filter.
    #[test]
    fn non_power_screening_filter_drops_banned_sender_in_v2_1_1() {
        let (unconflicted, ac) = screening_room_fixture();
        let bob_msg = LeanEvent {
            event_id: "$bob_msg".into(),
            event_type: "m.room.message".into(),
            state_key: Some(String::new()),
            sender: "@bob:example.com".into(),
            content: serde_json::json!({"body": "spam"}),
            auth_events: alloc::vec![
                "$create".to_string(),
                "$bob_join".to_string(),
                "$pl".to_string()
            ],
            ..Default::default()
        };
        let carol_msg = LeanEvent {
            event_id: "$carol_msg".into(),
            event_type: "m.room.message".into(),
            state_key: Some(String::new()),
            sender: "@carol:example.com".into(),
            content: serde_json::json!({"body": "hello"}),
            auth_events: alloc::vec![
                "$create".to_string(),
                "$carol_join".to_string(),
                "$pl".to_string()
            ],
            ..Default::default()
        };

        let mk_conflicted = || {
            let mut m = HashMap::new();
            m.insert("$ban_bob".to_string(), ac["$ban_bob"].clone());
            m.insert("$bob_msg".to_string(), bob_msg.clone());
            m.insert("$carol_msg".to_string(), carol_msg.clone());
            m
        };

        // V2.1.1 (has_ban_evasion_hardening): bob's banned-sender message is
        // screened out of the resolved state but still surfaces as a rejected
        // per-event delta (the screening pass is part of the delta contract),
        // while carol's unbanned message survives.
        let (_, deltas) = resolve_iterative_sort_with_cache_and_deltas(
            unconflicted.clone(),
            mk_conflicted(),
            &ac,
            None,
            StateResVersion::V2_1_1,
            &mut HashMap::new(),
        );
        let bob_delta = deltas
            .iter()
            .find(|d| d.event_id == "$bob_msg")
            .expect("a banned sender's non-power event must surface a rejected delta in V2.1.1");
        assert!(
            !bob_delta.accepted,
            "a banned sender's non-power event must be rejected in V2.1.1"
        );
        assert!(
            deltas.iter().any(|d| d.event_id == "$carol_msg"),
            "an unbanned sender's non-power event must survive the V2.1.1 screening filter"
        );

        // V2.1 predates the hardening: bob's message is processed, not screened.
        let (_, deltas) = resolve_iterative_sort_with_cache_and_deltas(
            unconflicted,
            mk_conflicted(),
            &ac,
            None,
            StateResVersion::V2_1,
            &mut HashMap::new(),
        );
        assert!(
            deltas.iter().any(|d| d.event_id == "$bob_msg"),
            "V2.1 must not apply the ban-evasion screening filter"
        );
    }

    /// Covers the `let Some(sk) = &ev.state_key else { continue }` guard in the
    /// delta path: a non-power event with no `state_key` is skipped (no delta,
    /// no insert) rather than panicking or polluting the resolved state.
    #[test]
    fn non_power_event_without_state_key_is_skipped() {
        let (unconflicted, ac) = screening_room_fixture();
        let alice_join = member_ev(
            "$alice_join",
            "@alice:example.com",
            "@alice:example.com",
            MEM_JOIN,
        );
        let stateless = LeanEvent {
            event_id: "$stateless".into(),
            event_type: "m.room.message".into(),
            state_key: None,
            sender: "@alice:example.com".into(),
            content: serde_json::json!({"body": "hi"}),
            auth_events: alloc::vec![
                "$create".to_string(),
                "$alice_join".to_string(),
                "$pl".to_string()
            ],
            ..Default::default()
        };
        let mut ac = ac;
        for e in [&alice_join, &stateless] {
            ac.insert(e.event_id.clone(), e.clone());
        }

        let mut conflicted = HashMap::new();
        conflicted.insert("$alice_join".to_string(), alice_join);
        conflicted.insert("$stateless".to_string(), stateless);

        let (_, deltas) = resolve_iterative_sort_with_cache_and_deltas(
            unconflicted,
            conflicted,
            &ac,
            None,
            StateResVersion::V2_1,
            &mut HashMap::new(),
        );
        assert!(
            deltas.iter().any(|d| d.event_id == "$alice_join"),
            "the stateful non-power event should still be processed"
        );
        assert!(
            !deltas.iter().any(|d| d.event_id == "$stateless"),
            "a non-power event without a state_key must be skipped (continue), not inserted"
        );
    }

    #[test]
    fn expand_v2_skips_power_ids_absent_from_sort_set() {
        // A power event whose id is not present in `sort_set`: the loop's
        // `sort_set.get(id)` returns `None` and the event is left untouched
        // rather than having its auth chain expanded.
        let mut power_events: HashMap<String, LeanEvent> = HashMap::new();
        power_events.insert(
            "$orphan".to_string(),
            member_ev("$orphan", "@a:example.com", "@a:example.com", MEM_JOIN),
        );
        let mut non_power_events: HashMap<String, LeanEvent> = HashMap::new();
        let sort_set: HashMap<String, LeanEvent> = HashMap::new();

        expand_v2_power_events_auth_chains(&mut power_events, &mut non_power_events, &sort_set);

        assert!(
            power_events.contains_key("$orphan"),
            "an id missing from sort_set must be skipped, not dropped"
        );
        assert!(non_power_events.is_empty());
    }

    #[test]
    fn route_msc4297_skips_ancestry_ids_absent_from_auth_context() {
        // A power event whose auth chain cites `$missing`, which is absent from
        // `auth_context`: the ancestry walk reaches it and `auth_context.get`
        // returns `None`, so nothing is added to `power_events`.
        let mut power_events: HashMap<String, LeanEvent> = HashMap::new();
        power_events.insert(
            "$pl".to_string(),
            LeanEvent {
                event_id: "$pl".into(),
                event_type: "m.room.power_levels".into(),
                state_key: Some(String::new()),
                sender: "@a:example.com".into(),
                content: serde_json::json!({ "users": { "@a:example.com": 100 } }),
                auth_events: alloc::vec!["$missing".to_string()],
                ..Default::default()
            },
        );
        let auth_context: HashMap<String, LeanEvent> = HashMap::new();
        let original_conflicted_keys = alloc::collections::BTreeSet::new();

        route_msc4297_ancestral_power_events(
            &mut power_events,
            &auth_context,
            &original_conflicted_keys,
            StateResVersion::V2_1,
        );

        assert_eq!(
            power_events.len(),
            1,
            "an ancestry id absent from auth_context must add nothing"
        );
        assert!(power_events.contains_key("$pl"));
    }
}
