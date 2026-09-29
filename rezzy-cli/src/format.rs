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

use crate::error::AppError;
use crate::provenance::{self, StreamOrderIndex};
use crate::timeline_order::{
    build_key, kahn_order_by, KeyValue, OrderKey, TimelineOrder, DEFAULT_TIE_BREAK,
};
use crate::utils::{compute_state_hash, epoch_days_to_ymd, resolve_parent_states, SharedStateMap};
use crate::{Args, OutputFormat};
use rezzy::auth::{apply_authorized_redactions, RedactionReport, RoomState};
use rezzy::basespec::event_types::EventType;
use rezzy::{resolved_state_entries, LeanEvent, StateResVersion};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::PathBuf;

pub struct FormattingContext<'a> {
    pub args: &'a Args,
    pub events_map: &'a HashMap<String, LeanEvent>,
    pub raw_map: &'a HashMap<String, rezzy::JsonValue>,
    pub heads: &'a [String],
    pub final_state_map: &'a imbl::OrdMap<(EventType, String), String>,
    pub resolved_state_list: &'a [String],
    pub auth_chain_ids: &'a [String],
    pub auth_graph: &'a rezzy::auth::roaring::AuthGraph,
    pub version: StateResVersion,
    pub room_version: Option<&'a str>,
    pub duration: std::time::Duration,
    pub event_count: usize,
    pub stream_order: Option<&'a StreamOrderIndex>,
}

/// Format the output for deltas.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn format_deltas_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    let debug = ctx.args.debug;
    let total = ctx.event_count;
    let progress_interval = if debug { 10_000 } else { 50_000 };
    if debug {
        eprintln!("[DEBUG] deltas: walking {total} events...");
    }
    let overall_start = std::time::Instant::now();

    let mut sorted_events: Vec<&LeanEvent> = ctx.events_map.values().collect();
    sorted_events.sort_by(|a, b| a.cmp_by_depth(b));

    let mut state_after_map: HashMap<String, SharedStateMap> = HashMap::new();
    let mut state_hash_map: HashMap<String, String> = HashMap::new();
    let mut checkpoints = Vec::new();

    let mut fork_count: usize = 0;
    let mut fork_time = std::time::Duration::ZERO;
    let mut processed: usize = 0;

    for ev in &sorted_events {
        processed = processed.saturating_add(1);
        if debug && processed.checked_rem(progress_interval) == Some(0) {
            eprintln!(
                "[DEBUG] deltas: {processed}/{total} events walked ({fork_count} forks resolved, {:.2?} spent in state-res) elapsed {:.2?}",
                fork_time,
                overall_start.elapsed()
            );
        }
        let mut state_before = std::sync::Arc::new(imbl::OrdMap::new());
        let mut parent_hash = None;

        if ev.prev_events.is_empty() {
            // Empty state before
        } else if ev.prev_events.len() == 1 {
            let prev_id = &ev.prev_events[0];
            if let Some(prev_state) = state_after_map.get(prev_id) {
                state_before = prev_state.clone();
                parent_hash = state_hash_map.get(prev_id).cloned();
            }
        } else {
            let mut parent_states = Vec::new();
            for prev_id in &ev.prev_events {
                if let Some(prev_state) = state_after_map.get(prev_id) {
                    parent_states.push(prev_state.clone());
                }
            }

            if !parent_states.is_empty() {
                if parent_states.len() == 1 {
                    state_before = parent_states[0].clone();
                    parent_hash = ev
                        .prev_events
                        .first()
                        .and_then(|prev_id| state_hash_map.get(prev_id))
                        .cloned();
                } else {
                    let t = std::time::Instant::now();
                    state_before = resolve_parent_states(
                        &parent_states,
                        ctx.events_map,
                        ctx.version,
                        ctx.auth_graph,
                    );
                    let elapsed = t.elapsed();
                    fork_count = fork_count.saturating_add(1);
                    fork_time = fork_time.saturating_add(elapsed);
                    if debug && elapsed.as_millis() > 50 {
                        eprintln!(
                            "[DEBUG] deltas: slow fork resolve at {} ({} parents) took {elapsed:.2?}",
                            ev.event_id,
                            parent_states.len()
                        );
                    }
                    parent_hash = Some(compute_state_hash(state_before.as_ref()));
                }
            }
        }

        let mut state_after = state_before.clone();
        if let Some(state_key) = &ev.state_key {
            let mut modified = state_before.as_ref().clone();
            modified.insert(
                (EventType::from(ev.event_type.clone()), state_key.clone()),
                ev.event_id.clone(),
            );
            state_after = std::sync::Arc::new(modified);
        }

        let hash_str = compute_state_hash(&state_after);
        state_after_map.insert(ev.event_id.clone(), state_after.clone());
        state_hash_map.insert(ev.event_id.clone(), hash_str.clone());

        let mut deltas = Vec::new();
        if ev.prev_events.is_empty() {
            for (key, event_id) in state_after.as_ref() {
                deltas.push(rezzy::json!({
                    "type": &key.0,
                    "state_key": &key.1,
                    "event_id": event_id,
                }));
            }
        } else {
            let parent_state = state_before.as_ref();
            for (key, event_id) in state_after.as_ref() {
                match parent_state.get(key) {
                    Some(parent_event_id) if parent_event_id == event_id => {}
                    _ => {
                        deltas.push(rezzy::json!({
                            "type": &key.0,
                            "state_key": &key.1,
                            "event_id": event_id,
                        }));
                    }
                }
            }
            for key in parent_state.keys() {
                if !state_after.contains_key(key) {
                    deltas.push(rezzy::json!({
                        "type": &key.0,
                        "state_key": &key.1,
                        "event_id": rezzy::JsonValue::Null,
                    }));
                }
            }
        }

        checkpoints.push(rezzy::json!({
            "hash": hash_str,
            "parent": parent_hash,
            "event_id": &ev.event_id,
            "deltas": deltas,
        }));
    }

    if debug {
        eprintln!(
            "[DEBUG] deltas: done. {processed} events walked, {fork_count} forks resolved via state-res ({:.2?} total), overall {:.2?}",
            fork_time,
            overall_start.elapsed()
        );
    }

    rezzy::json!(checkpoints)
}

/// Compute the roots of the components.
#[must_use]
pub fn compute_component_roots(
    events_map: &HashMap<String, LeanEvent, impl std::hash::BuildHasher>,
    include_prev: bool,
    include_auth: bool,
) -> Vec<String> {
    let mut component_roots = Vec::new();
    if !events_map.is_empty() {
        let mut parent: Vec<usize> = (0..events_map.len()).collect();
        let index_to_ev: Vec<&LeanEvent> = events_map.values().collect();
        let id_to_index = rezzy::index_by_event_id(index_to_ev.iter().copied());
        let find_root = |mut node: usize, parent: &mut Vec<usize>| -> usize {
            while parent[node] != node {
                parent[node] = parent[parent[node]];
                node = parent[node];
            }
            node
        };
        let union_nodes = |u: usize, v: usize, parent: &mut Vec<usize>| {
            let root_u = find_root(u, parent);
            let root_v = find_root(v, parent);
            if root_u != root_v {
                parent[root_u] = root_v;
            }
        };

        for ev in events_map.values() {
            if let Some(&u) = id_to_index.get(ev.event_id.as_str()) {
                if include_prev {
                    for prev in &ev.prev_events {
                        if let Some(&v) = id_to_index.get(prev.as_str()) {
                            union_nodes(u, v, &mut parent);
                        }
                    }
                }
                if include_auth {
                    for auth in &ev.auth_events {
                        if let Some(&v) = id_to_index.get(auth.as_str()) {
                            union_nodes(u, v, &mut parent);
                        }
                    }
                }
            }
        }
        let mut comp_roots_map: HashMap<usize, &LeanEvent> = HashMap::new();
        for (i, &ev) in index_to_ev.iter().enumerate() {
            let u = find_root(i, &mut parent);
            comp_roots_map
                .entry(u)
                .and_modify(|e| {
                    if ev.depth < e.depth || (ev.depth == e.depth && ev.event_id < e.event_id) {
                        *e = ev;
                    }
                })
                .or_insert(ev);
        }
        component_roots = comp_roots_map
            .values()
            .map(|e| e.event_id.clone())
            .collect();
        component_roots.sort();
    }
    component_roots
}

/// Format the summary output.
pub fn format_summary_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    let mut state_entries: Vec<rezzy::JsonValue> = Vec::new();
    let mut members: HashMap<String, Vec<rezzy::JsonValue>> = HashMap::new();

    for ((typ, sk), eid) in ctx.final_state_map {
        let ev = ctx.events_map.get(eid);
        if typ.as_str() == "m.room.member" {
            let membership = ev
                .and_then(|e| e.content.get("membership"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let displayname = ev
                .and_then(|e| e.content.get("displayname"))
                .and_then(|d| d.as_str())
                .unwrap_or("");
            members
                .entry(membership.to_string())
                .or_default()
                .push(rezzy::json!({
                    "user_id": sk,
                    "displayname": displayname,
                    "event_id": eid,
                    "depth": ev.map_or(0, |e| e.depth),
                }));
        } else {
            state_entries.push(rezzy::json!({
                "type": typ,
                "state_key": sk,
                "event_id": eid,
                "sender": ev.map_or("?", |e| e.sender.as_str()),
                "depth": ev.map_or(0, |e| e.depth),
            }));
        }
    }

    state_entries.sort_by(|a, b| {
        let ta = a["type"].as_str().unwrap_or("");
        let tb = b["type"].as_str().unwrap_or("");
        ta.cmp(tb).then_with(|| {
            let sa = a["state_key"].as_str().unwrap_or("");
            let sb = b["state_key"].as_str().unwrap_or("");
            sa.cmp(sb)
        })
    });

    for list in members.values_mut() {
        list.sort_by(|a, b| {
            let ua = a["user_id"].as_str().unwrap_or("");
            let ub = b["user_id"].as_str().unwrap_or("");
            ua.cmp(ub)
        });
    }

    let membership_order = ["join", "invite", "knock", "leave", "ban"];
    let mut membership_obj = rezzy::JsonObject::new();
    for status in &membership_order {
        if let Some(list) = members.get(*status) {
            membership_obj.insert(
                (*status).to_string(),
                rezzy::json!({
                    "count": list.len(),
                    "users": list
                }),
            );
        }
    }
    for (status, list) in &members {
        if !membership_order.contains(&status.as_str()) {
            membership_obj.insert(
                status.clone(),
                rezzy::json!({
                    "count": list.len(),
                    "users": list
                }),
            );
        }
    }

    let min_depth = ctx.events_map.values().map(|e| e.depth).min().unwrap_or(0);
    let max_depth = ctx.events_map.values().map(|e| e.depth).max().unwrap_or(0);
    let root_event_id = ctx
        .events_map
        .values()
        .min_by_key(|e| e.depth)
        .map_or("", |e| e.event_id.as_str());

    let component_roots_prev = compute_component_roots(ctx.events_map, true, false);
    let component_roots_auth = compute_component_roots(ctx.events_map, false, true);
    let component_roots_union = compute_component_roots(ctx.events_map, true, true);

    rezzy::json!({
        "status": "success",
        "version": ctx.version,
        "duration_ms": ctx.duration.as_millis(),
        "total_events": ctx.event_count,
        "resolved_state_size": state_entries.len().saturating_add(members.values().map(std::vec::Vec::len).sum::<usize>()),
        "auth_chain_size": ctx.auth_chain_ids.len(),
        "min_depth": min_depth,
        "max_depth": max_depth,
        "root_event_id": root_event_id,
        "n_components": component_roots_union.len(),
        "n_components_prev": component_roots_prev.len(),
        "n_components_auth": component_roots_auth.len(),
        "component_roots_prev": component_roots_prev,
        "heads": ctx.heads,
        "membership": membership_obj,
        "state": state_entries
    })
}

fn format_resolve_state_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    let resolved_state: Vec<rezzy::JsonValue> = resolved_state_entries(ctx.final_state_map)
        .into_iter()
        .map(|entry| {
            rezzy::json!({
                "type": entry.event_type,
                "state_key": entry.state_key,
                "event_id": entry.event_id,
            })
        })
        .collect();

    rezzy::json!({
        "status": "success",
        "format": "resolve_state",
        "resolved_state": resolved_state,
    })
}

/// Get a user's display name.
#[must_use]
pub fn get_user_displayname(
    user_id: &str,
    displaynames: &HashMap<String, String, impl std::hash::BuildHasher>,
) -> String {
    displaynames.get(user_id).cloned().unwrap_or_else(|| {
        user_id
            .split(':')
            .next()
            .unwrap_or(user_id)
            .trim_start_matches('@')
            .to_string()
    })
}

/// Format an event description.
#[must_use]
pub fn format_event_description(
    ev: &LeanEvent,
    sender: &str,
    displaynames: &HashMap<String, String, impl std::hash::BuildHasher>,
) -> Option<String> {
    match ev.event_type.as_str() {
        "m.room.create" => Some(format!("{sender} sent m.room.create state event")),
        "m.room.member" => {
            let membership = ev
                .content
                .get("membership")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let target =
                get_user_displayname(ev.state_key.as_deref().unwrap_or_default(), displaynames);
            let reason = ev
                .content
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match membership {
                "join" => Some(format!("joined the room — {target}")),
                "leave" if ev.state_key.as_ref() == Some(&ev.sender) => {
                    Some(format!("left the room — {target}"))
                }
                "leave" => Some(format!(
                    "{} kicked {}{}",
                    sender,
                    target,
                    if reason.is_empty() {
                        String::new()
                    } else {
                        format!(" {reason}")
                    }
                )),
                "ban" => Some(format!(
                    "{} banned {}{}",
                    sender,
                    target,
                    if reason.is_empty() {
                        String::new()
                    } else {
                        format!(" {reason}")
                    }
                )),
                "invite" => Some(format!("{sender} invited {target}")),
                "knock" => Some(format!("knocked — {target}")),
                _ => Some(format!(
                    "{sender} set {target}'s membership to {membership}"
                )),
            }
        }
        "m.room.message" => {
            let body = ev
                .content
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let msgtype = ev
                .content
                .get("msgtype")
                .and_then(|v| v.as_str())
                .unwrap_or("m.text");
            match msgtype {
                "m.text" | "m.notice" => Some(format!("{sender}: {body}")),
                "m.image" => Some(format!("{sender} sent an image")),
                "m.video" => Some(format!("{sender} sent a video")),
                "m.audio" => Some(format!("{sender} sent an audio file")),
                "m.file" => Some(format!("{sender} sent a file")),
                "m.emote" => Some(format!("* {sender} {body}")),
                _ => Some(format!("{sender} sent {msgtype}")),
            }
        }
        "m.room.name" => {
            let name = ev
                .content
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            Some(format!("{sender} changed room name to \"{name}\""))
        }
        "m.room.topic" => {
            let topic = ev
                .content
                .get("topic")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            Some(format!("{sender} changed room topic to \"{topic}\""))
        }
        "m.room.avatar" => Some(format!("{sender} changed room avatar")),
        "m.room.redaction" => Some(format!("{sender} redacted an event")),
        "m.reaction" => None,
        "m.sticker" => Some(format!("{sender} sent a sticker")),
        typ => Some(format!("{sender} sent {typ} state event")),
    }
}

/// Logs a redaction application report's outcomes to stderr under `--debug`.
fn log_redaction_report<Id: std::fmt::Display>(redaction_report: &RedactionReport<Id>) {
    for (rid, tid) in &redaction_report.applied {
        eprintln!("[INFO] redaction {rid} stripped {tid}");
    }
    for (rid, tid) in &redaction_report.skipped_unauthorized {
        eprintln!("[WARN] redaction {rid} rejected for {tid}: sender lacks authorization");
    }
    for (rid, tid) in &redaction_report.target_not_in_batch {
        eprintln!(
            "[WARN] redaction {rid} targets {tid}, absent from the input set; redaction deferred"
        );
    }
    for (rid, tid) in &redaction_report.failed_to_apply {
        eprintln!(
            "[WARN] redaction {rid} targets {tid}, present but failed to apply (e.g. already redacted by a cycle)"
        );
    }
}

/// Whether `args` selects an ordering that needs sidecar stream order.
#[must_use]
pub fn needs_stream_order(args: &Args) -> bool {
    matches!(args.format, OutputFormat::Timeline)
        && (args.timeline_order == TimelineOrder::Synapse
            || args
                .tie_break
                .iter()
                .copied()
                .any(OrderKey::needs_stream_order))
}

/// Load and validate the stream-order index for `--timeline-order synapse`.
///
/// An explicit `--metadata` path is fatal on error. Auto-discovered sibling
/// sidecars are best-effort: missing, mismatched, or conflicting entries are
/// counted and reported in one summary warning, and the caller falls back.
///
/// # Errors
/// Returns an error only when an explicit `--metadata` sidecar cannot be read.
pub fn load_stream_order(
    args: &Args,
    events_map: &HashMap<String, LeanEvent>,
    raw_map: &HashMap<String, rezzy::JsonValue>,
    room_version: Option<&str>,
) -> Result<Option<StreamOrderIndex>, AppError> {
    let explicit = args.metadata.clone();
    let paths: Vec<PathBuf> = match &explicit {
        Some(path) => vec![path.clone()],
        None => args
            .input
            .iter()
            .filter(|path| {
                path.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
            })
            .map(|path| provenance::sidecar_path(path))
            .filter(|path| path.is_file())
            .collect(),
    };
    if paths.is_empty() {
        warn_once(
            args.quiet,
            "no provenance sidecar found; falling back to origin_server_ts for stream ordering",
        );
        return Ok(None);
    }

    let expected_room_id = raw_map
        .values()
        .find_map(|value| value.get("room_id").and_then(rezzy::JsonValue::as_str));
    let mut index = StreamOrderIndex::default();
    let mut missing = 0_usize;
    let mut mismatched = 0_usize;
    let mut room_mismatch = 0_usize;
    for path in &paths {
        let sidecar = if explicit.is_some() {
            provenance::load_sidecar(path)?
        } else {
            match provenance::load_sidecar(path) {
                Ok(sidecar) => sidecar,
                Err(error) => {
                    warn_once(
                        args.quiet,
                        &format!("ignoring provenance sidecar {}: {error}", path.display()),
                    );
                    continue;
                }
            }
        };
        if room_version.is_some()
            && sidecar.room_version.is_some()
            && room_version != sidecar.room_version.as_deref()
        {
            room_mismatch = room_mismatch.saturating_add(1);
            continue;
        }
        if expected_room_id.is_some()
            && sidecar
                .room_id
                .as_deref()
                .is_some_and(|id| Some(id) != expected_room_id)
        {
            room_mismatch = room_mismatch.saturating_add(1);
            continue;
        }
        for (event_id, _event) in events_map {
            let Some(record) = sidecar.events.get(event_id) else {
                missing = missing.saturating_add(1);
                continue;
            };
            if let Some(raw) = raw_map.get(event_id) {
                if let Ok(serialized) = rezzy::json::write_string_value(raw) {
                    if provenance::sha256_id(serialized.as_bytes()) != record.payload_sha256 {
                        mismatched = mismatched.saturating_add(1);
                        continue;
                    }
                }
            }
            match record.stream_ordering {
                Some(value) => {
                    index.by_event.insert(event_id.clone(), value);
                }
                None => missing = missing.saturating_add(1),
            }
        }
    }
    if index.is_empty() {
        warn_once(
            args.quiet,
            "provenance sidecar had no usable stream_ordering; falling back to origin_server_ts",
        );
        return Ok(None);
    }
    if missing > 0 || mismatched > 0 || room_mismatch > 0 {
        warn_once(
            args.quiet,
            &format!(
                "stream_ordering incomplete ({missing} missing/conflicting, {mismatched} payload mismatch, {room_mismatch} room/version mismatch); those events fall back to origin_server_ts"
            ),
        );
    }
    Ok(Some(index))
}

fn warn_once(quiet: bool, message: &str) {
    if !quiet {
        eprintln!("[WARN] {message}");
    }
}

/// Format the timeline output.
/// Render the timeline to a string, applying only authorized redactions.
fn render_timeline(ctx: &FormattingContext) -> String {
    let mut sorted_events = prepare_timeline_events(ctx);
    match ctx.args.timeline_order {
        TimelineOrder::Causal => sort_timeline_causal(ctx, &mut sorted_events),
        TimelineOrder::Synapse => sort_timeline_synapse(ctx, &mut sorted_events),
    }
    render_timeline_events(ctx, &sorted_events)
}

/// Render the timestamp-primary human view (`-f timeline-chronological`).
fn render_timeline_chronological(ctx: &FormattingContext) -> String {
    let mut sorted_events = prepare_timeline_events(ctx);
    sorted_events.sort_by(|a, b| {
        a.origin_server_ts
            .cmp(&b.origin_server_ts)
            .then(a.depth.cmp(&b.depth))
            .then(a.event_id.cmp(&b.event_id))
    });
    render_timeline_events(ctx, &sorted_events)
}

/// Collect events and apply only authorized redactions.
fn prepare_timeline_events(ctx: &FormattingContext) -> Vec<LeanEvent> {
    // Owned copy of the events so the authorized redaction pass can mutate the
    // in-set targets in place. The resolved room state below is what the
    // redaction pass needs to authorize each redaction.
    let mut sorted_events: Vec<LeanEvent> = ctx.events_map.values().cloned().collect();

    // Prefer the resolved `m.room.create` event's own `room_version` field
    // over `ctx.room_version` (a pre-resolution guess derived from the raw
    // input, before conflicts were settled). Fall back to `ctx.room_version`,
    // then "1", only when no create event made it into the resolved state.
    let create_room_version = ctx
        .final_state_map
        .get(&(EventType::from("m.room.create"), String::new()))
        .and_then(|eid| ctx.events_map.get(eid))
        .and_then(|ev| ev.content.get("room_version"))
        .and_then(|v| v.as_str());
    let room_version = create_room_version.or(ctx.room_version).unwrap_or("1");

    // Resolved room state (event type + state_key -> event), used to check the
    // `redact` power level and each redaction sender's own power level.
    // NOTE: This uses final resolved state, not per-redaction event-time state.
    // The spec requires per-redaction state, but reconstructing it requires
    // proper topological state resolution at each redaction's prev_events —
    // depth-based ordering is insufficient because depth is untrusted and does
    // not guarantee parent-before-child processing. A future fix should use
    // apply_authorized_redactions_with_state_at with proper state resolution.
    let mut room_state: RoomState<String, rezzy::JsonValue, String> = RoomState::new();
    for ((typ, sk), eid) in ctx.final_state_map {
        if let Some(ev) = ctx.events_map.get(eid) {
            room_state.insert((typ.as_str().to_string(), sk.clone()), ev.clone());
        }
    }

    // Apply redactions resolvable within the input set, but only when the
    // sender is authorized: the target's own sender, a sender holding the
    // `redact` power level, or (room v1/v2) a same-domain sender. An
    // unauthorized redaction leaves the target untouched. The returned report
    // drives the --debug diagnostics below.
    let redaction_report = if sorted_events.iter().any(LeanEvent::is_redaction) {
        apply_authorized_redactions(&mut sorted_events, &room_state, ctx.version, room_version)
    } else {
        RedactionReport::default()
    };

    if ctx.args.debug {
        log_redaction_report(&redaction_report);
    }

    sorted_events
}

/// Kahn causal order; the ready queue uses `--tie-break` (default
/// `origin_server_ts,matrix_depth,event_id`). Stream-order key components are
/// dropped with a warning when no sidecar supplied them.
fn sort_timeline_causal(ctx: &FormattingContext, events: &mut Vec<LeanEvent>) {
    let requested: Vec<OrderKey> = if ctx.args.tie_break.is_empty() {
        DEFAULT_TIE_BREAK.to_vec()
    } else {
        ctx.args.tie_break.clone()
    };
    let stream = ctx.stream_order;
    let mut ready_keys: Vec<OrderKey> = Vec::with_capacity(requested.len());
    let mut dropped_stream = false;
    for key in requested {
        if key.needs_stream_order() && stream.is_none() {
            dropped_stream = true;
            continue;
        }
        ready_keys.push(key);
    }
    if ready_keys.is_empty() {
        ready_keys.push(OrderKey::EventId);
    }
    if dropped_stream {
        warn_once(
            ctx.args.quiet,
            "stream_ordering unavailable; dropping it from --tie-break",
        );
    }

    let ids: Vec<String> = events.iter().map(|event| event.event_id.clone()).collect();
    let parents: Vec<Vec<String>> = events
        .iter()
        .map(|event| event.prev_events.clone())
        .collect();
    let keys: Vec<Vec<KeyValue>> = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let stream_value = stream
                .and_then(|index| index.get(&event.event_id))
                .unwrap_or(event.origin_server_ts);
            build_key(
                &ready_keys,
                &ids[index],
                event.depth,
                event.origin_server_ts,
                stream_value,
            )
        })
        .collect();
    let order = kahn_order_by(&ids, &parents, &keys);
    let reordered: Vec<LeanEvent> = order
        .into_iter()
        .map(|index| events[index].clone())
        .collect();
    *events = reordered;
}

/// Synapse-like `matrix_depth, stream_ordering, event_id`. Events without a
/// known stream order fall back to `origin_server_ts` and sort after those
/// that have one.
fn sort_timeline_synapse(ctx: &FormattingContext, events: &mut Vec<LeanEvent>) {
    let stream = ctx.stream_order;
    let fallbacks = events
        .iter()
        .filter(|event| {
            stream
                .and_then(|index| index.get(&event.event_id))
                .is_none()
        })
        .count();
    if fallbacks > 0 {
        warn_once(
            ctx.args.quiet,
            &format!(
                "{fallbacks} event(s) had no stream_ordering; fell back to matrix_depth, origin_server_ts, event_id"
            ),
        );
    }
    events.sort_by(|a, b| {
        let a_stream = stream.and_then(|index| index.get(&a.event_id));
        let b_stream = stream.and_then(|index| index.get(&b.event_id));
        a.depth
            .cmp(&b.depth)
            .then_with(|| match (a_stream, b_stream) {
                (Some(left), Some(right)) => left.cmp(&right),
                (None, None) => a.origin_server_ts.cmp(&b.origin_server_ts),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
            })
            .then(a.event_id.cmp(&b.event_id))
    });
}

fn render_timeline_events(ctx: &FormattingContext, sorted_events: &[LeanEvent]) -> String {
    let mut displaynames: HashMap<String, String> = HashMap::new();
    for ev in sorted_events {
        if ev.event_type == "m.room.member" {
            if let Some(dn) = ev.content.get("displayname").and_then(|v| v.as_str()) {
                if !dn.is_empty() {
                    displaynames.insert(ev.state_key.clone().unwrap_or_default(), dn.to_string());
                }
            }
        }
    }

    let mut output = String::new();
    let mut last_date = String::new();

    for ev in sorted_events {
        let sender = get_user_displayname(&ev.sender, &displaynames);
        let Some(desc) = format_event_description(ev, &sender, &displaynames) else {
            continue;
        };
        let desc = if ev.soft_fail {
            // Hide soft-failed and rejected events from the default timeline;
            // only surface them under --debug, flagged, as they're diagnostic.
            if !ctx.args.debug {
                continue;
            }
            format!("[SOFT-FAIL] {desc}")
        } else if ev.rejected {
            if !ctx.args.debug {
                continue;
            }
            format!("[REJECTED] {desc}")
        } else {
            desc
        };

        let ts_ms = ev.origin_server_ts;
        let ts_secs = i64::try_from(ts_ms / 1000).unwrap();
        let time_of_day =
            u64::try_from((ts_secs.wrapping_rem(86_400).wrapping_add(86_400)).wrapping_rem(86_400))
                .unwrap();
        let hours = time_of_day / 3_600;
        let minutes = (time_of_day % 3_600) / 60;
        let days = ts_secs.div_euclid(86_400);

        let (y, m, d) = epoch_days_to_ymd(days);
        let month_names = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let month_str = month_names
            .get(m.saturating_sub(1) as usize)
            .unwrap_or(&"???");
        let ampm = if hours < 12 { "AM" } else { "PM" };
        let h12 = if hours == 0 {
            12
        } else if hours > 12 {
            hours.wrapping_sub(12)
        } else {
            hours
        };
        let date = format!("{d} {month_str} {y} {h12:02}:{minutes:02} {ampm}");

        if date != last_date {
            if !last_date.is_empty() {
                output.push('\n');
            }
            last_date.clone_from(&date);
        }

        output.push_str(&desc);
        output.push('\n');
        output.push_str(&date);
        output.push('\n');
    }

    output
}

/// Format the timeline output, printing the rendered timeline to stderr.
#[must_use]
pub fn format_timeline_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    eprint!("{}", render_timeline(ctx));
    rezzy::json!({
        "status": "success",
        "format": "timeline",
        "order": format_name(ctx.args.timeline_order),
        "events": ctx.event_count
    })
}

#[must_use]
pub fn format_timeline_chronological_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    eprint!("{}", render_timeline_chronological(ctx));
    rezzy::json!({
        "status": "success",
        "format": "timeline-chronological",
        "events": ctx.event_count
    })
}

fn format_name(order: TimelineOrder) -> &'static str {
    match order {
        TimelineOrder::Causal => "causal",
        TimelineOrder::Synapse => "synapse",
    }
}

/// Format the main CLI output.
#[must_use]
pub fn format_cli_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    match ctx.args.format {
        OutputFormat::Deltas => format_deltas_output(ctx),
        OutputFormat::Summary => format_summary_output(ctx),
        OutputFormat::ResolveState => format_resolve_state_output(ctx),
        OutputFormat::Timeline => format_timeline_output(ctx),
        OutputFormat::TimelineChronological => format_timeline_chronological_output(ctx),
        OutputFormat::Events => {
            let mut state_events: Vec<&rezzy::JsonValue> = ctx
                .resolved_state_list
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();
            state_events.sort_by(|a, b| {
                let a_ev = a
                    .get("event_id")
                    .and_then(|id| id.as_str())
                    .and_then(|id| ctx.events_map.get(id));
                let b_ev = b
                    .get("event_id")
                    .and_then(|id| id.as_str())
                    .and_then(|id| ctx.events_map.get(id));

                let a_depth = a_ev.map_or(0, |e| e.depth);
                let b_depth = b_ev.map_or(0, |e| e.depth);

                a_depth.cmp(&b_depth).then_with(|| {
                    let a_id = a_ev.map_or("", |e| e.event_id.as_str());
                    let b_id = b_ev.map_or("", |e| e.event_id.as_str());
                    a_id.cmp(b_id)
                })
            });
            rezzy::json!(state_events)
        }
        OutputFormat::Federation => {
            let state_events: Vec<&rezzy::JsonValue> = ctx
                .resolved_state_list
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();
            let auth_chain_events: Vec<&rezzy::JsonValue> = ctx
                .auth_chain_ids
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();

            rezzy::json!({
                "origin": &ctx.args.origin,
                "state": state_events,
                "auth_chain": auth_chain_events
            })
        }
        OutputFormat::Default => rezzy::json!({
            "status": "success",
            "version": ctx.version,
            "duration_ms": ctx.duration.as_millis(),
            "resolved_state_size": ctx.resolved_state_list.len(),
            "auth_chain_size": ctx.auth_chain_ids.len(),
            "state_event_ids": ctx.resolved_state_list
        }),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn build_auth_graph(
        events_map: &HashMap<String, LeanEvent>,
    ) -> rezzy::auth::roaring::AuthGraph {
        rezzy::auth::roaring::AuthGraph::build(events_map)
    }

    fn test_args(format: OutputFormat) -> Args {
        Args {
            input: Vec::new(),
            room: None,
            homeserver: None,
            token: None,
            output: None,
            state_res: None,
            format,
            debug: false,
            quiet: false,
            check: false,
            origin: String::from("matrix.org"),
            timeline_order: TimelineOrder::default(),
            tie_break: Vec::new(),
            timeline_order_explicit: false,
            metadata: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn formatting_context<'a>(
        room_version: Option<&'a str>,
        duration: std::time::Duration,
        event_count: usize,
        args: &'a Args,
        events_map: &'a HashMap<String, LeanEvent>,
        raw_map: &'a HashMap<String, rezzy::JsonValue>,
        heads: &'a [String],
        final_state_map: &'a imbl::OrdMap<(EventType, String), String>,
        resolved_state_list: &'a [String],
        auth_chain_ids: &'a [String],
        auth_graph: &'a rezzy::auth::roaring::AuthGraph,
    ) -> FormattingContext<'a> {
        FormattingContext {
            args,
            events_map,
            raw_map,
            heads,
            final_state_map,
            resolved_state_list,
            auth_chain_ids,
            auth_graph,
            version: StateResVersion::V2,
            room_version,
            duration,
            event_count,
            stream_order: None,
        }
    }

    #[test]
    fn empty_context_supports_all_non_timeline_output_formats() {
        let events_map = HashMap::new();
        let raw_map = HashMap::new();
        let heads = Vec::new();
        let final_state_map = imbl::OrdMap::new();
        let resolved_state_list = Vec::new();
        let auth_chain_ids = Vec::new();
        let auth_graph = build_auth_graph(&events_map);

        let render = |format| {
            let args = test_args(format);
            let ctx = formatting_context(
                None,
                std::time::Duration::ZERO,
                0,
                &args,
                &events_map,
                &raw_map,
                &heads,
                &final_state_map,
                &resolved_state_list,
                &auth_chain_ids,
                &auth_graph,
            );
            format_cli_output(&ctx)
        };

        assert_eq!(render(OutputFormat::Events), rezzy::json!([]));
        assert_eq!(
            render(OutputFormat::Federation),
            rezzy::json!({"origin": "matrix.org", "state": [], "auth_chain": []})
        );
        assert_eq!(
            render(OutputFormat::Default)["status"].as_str(),
            Some("success")
        );
        assert_eq!(
            render(OutputFormat::Summary)["status"].as_str(),
            Some("success")
        );
        assert_eq!(render(OutputFormat::Deltas), rezzy::json!([]));
        assert_eq!(
            render(OutputFormat::ResolveState)["resolved_state"],
            rezzy::json!([])
        );
    }

    #[test]
    fn resolve_state_output_exposes_the_resolved_state_entries() {
        let args = test_args(OutputFormat::ResolveState);

        let events_map = HashMap::new();
        let raw_map = HashMap::new();
        let heads = Vec::new();
        let mut final_state_map = imbl::OrdMap::new();
        final_state_map.insert(("m.room.create".into(), String::new()), "$create".into());
        final_state_map.insert(("m.room.member".into(), "@alice:x".into()), "$join".into());
        let resolved_state_list = vec!["$create".to_string(), "$join".to_string()];
        let auth_chain_ids = Vec::new();
        let auth_graph = build_auth_graph(&events_map);

        let ctx = formatting_context(
            Some("11"),
            std::time::Duration::from_millis(0),
            2,
            &args,
            &events_map,
            &raw_map,
            &heads,
            &final_state_map,
            &resolved_state_list,
            &auth_chain_ids,
            &auth_graph,
        );

        let output = format_cli_output(&ctx);
        assert_eq!(output["status"].as_str(), Some("success"));
        assert_eq!(output["format"].as_str(), Some("resolve_state"));
        assert_eq!(
            output["resolved_state"],
            rezzy::json!([
                {
                    "type": "m.room.create",
                    "state_key": "",
                    "event_id": "$create",
                },
                {
                    "type": "m.room.member",
                    "state_key": "@alice:x",
                    "event_id": "$join",
                }
            ])
        );
    }

    /// The CLI timeline applies a redaction only when it is authorized against
    /// the resolved room state: an unrelated sender with no `redact` power must
    /// not strip the target, while the target's own sender may.
    #[test]
    fn timeline_redaction_requires_authorization() {
        let render = |events: Vec<LeanEvent>| -> String {
            let mut events_map = HashMap::new();
            for ev in &events {
                events_map.insert(ev.event_id.clone(), ev.clone());
            }
            let args = test_args(OutputFormat::Timeline);
            let raw_map = HashMap::new();
            let heads = Vec::new();
            let mut final_state_map = imbl::OrdMap::new();
            final_state_map.insert(("m.room.power_levels".into(), String::new()), "$pl".into());
            let resolved_state_list: Vec<String> = Vec::new();
            let auth_chain_ids: Vec<String> = Vec::new();
            let auth_graph = build_auth_graph(&events_map);
            let ctx = formatting_context(
                Some("11"),
                std::time::Duration::from_millis(0),
                events.len(),
                &args,
                &events_map,
                &raw_map,
                &heads,
                &final_state_map,
                &resolved_state_list,
                &auth_chain_ids,
                &auth_graph,
            );
            render_timeline(&ctx)
        };

        let pl: LeanEvent = LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            content: rezzy::json!({
                "users": { "@admin:x": 100, "@bob:x": 0, "@mallory:x": 0 },
                "redact": 50
            }),
            ..Default::default()
        };
        let msg: LeanEvent = LeanEvent {
            event_id: "$msg".into(),
            event_type: "m.room.message".into(),
            sender: "@bob:x".into(),
            origin_server_ts: 10,
            content: rezzy::json!({ "body": "secret" }),
            ..Default::default()
        };
        let mallory_redact: LeanEvent = LeanEvent {
            event_id: "$r_mal".into(),
            event_type: "m.room.redaction".into(),
            sender: "@mallory:x".into(),
            origin_server_ts: 11,
            content: rezzy::json!({ "redacts": "$msg" }),
            ..Default::default()
        };
        let self_redact: LeanEvent = LeanEvent {
            event_id: "$r_self".into(),
            event_type: "m.room.redaction".into(),
            sender: "@bob:x".into(),
            origin_server_ts: 12,
            content: rezzy::json!({ "redacts": "$msg" }),
            ..Default::default()
        };

        // Unauthorized: mallory (PL 0 < redact 50, not the target's sender)
        // must NOT strip Bob's message.
        let out = render(vec![pl.clone(), msg.clone(), mallory_redact.clone()]);
        assert!(
            out.contains("secret"),
            "unauthorized redaction must not strip the target; got: {out:?}"
        );

        // Authorized: Bob redacts his own message -> content is stripped.
        let out = render(vec![pl.clone(), msg.clone(), self_redact.clone()]);
        assert!(
            !out.contains("secret"),
            "authorized self-redaction must strip the target content; got: {out:?}"
        );
    }
}
