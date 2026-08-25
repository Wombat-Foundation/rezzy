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

use crate::utils::{compute_state_hash, epoch_days_to_ymd, resolve_parent_states, SharedStateMap};
use crate::{Args, OutputFormat};
use rezzy::auth::{apply_authorized_redactions, RedactionReport, RoomState};
use rezzy::basespec::event_types::EventType;
use rezzy::{resolved_state_entries, LeanEvent, StateResVersion};
use std::collections::HashMap;

pub struct FormattingContext<'a> {
    pub args: &'a Args,
    pub events_map: &'a HashMap<String, LeanEvent>,
    pub raw_map: &'a HashMap<String, serde_json::Value>,
    pub heads: &'a [String],
    pub final_state_map: &'a imbl::OrdMap<(EventType, String), String>,
    pub resolved_state_list: &'a [String],
    pub auth_chain_ids: &'a [String],
    pub version: StateResVersion,
    pub room_version: Option<&'a str>,
    pub duration: std::time::Duration,
    pub event_count: usize,
}

/// Format the output for deltas.
pub fn format_deltas_output(ctx: &FormattingContext) -> serde_json::Value {
    let mut sorted_events: Vec<&LeanEvent> = ctx.events_map.values().collect();
    sorted_events.sort_by(|a, b| a.cmp_by_depth(b));

    let mut state_after_map: HashMap<String, SharedStateMap> = HashMap::new();
    let mut state_hash_map: HashMap<String, String> = HashMap::new();
    let mut checkpoints = Vec::new();

    for ev in &sorted_events {
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
                    state_before =
                        resolve_parent_states(&parent_states, ctx.events_map, ctx.version);
                    parent_hash = Some(compute_state_hash(state_before.as_ref()));
                }
            }
        }

        let mut state_after = state_before.clone();
        if ev.state_key.is_some() {
            let mut modified = state_before.as_ref().clone();
            modified.insert(
                (
                    EventType::from(ev.event_type.clone()),
                    ev.state_key.clone().unwrap(),
                ),
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
                deltas.push(serde_json::json!({
                    "type": key.0,
                    "state_key": key.1,
                    "event_id": event_id,
                }));
            }
        } else {
            let parent_state = state_before.as_ref();
            for (key, event_id) in state_after.as_ref() {
                match parent_state.get(key) {
                    Some(parent_event_id) if parent_event_id == event_id => {}
                    _ => {
                        deltas.push(serde_json::json!({
                            "type": key.0,
                            "state_key": key.1,
                            "event_id": event_id,
                        }));
                    }
                }
            }
            for key in parent_state.keys() {
                if !state_after.contains_key(key) {
                    deltas.push(serde_json::json!({
                        "type": key.0,
                        "state_key": key.1,
                        "event_id": serde_json::Value::Null,
                    }));
                }
            }
        }

        checkpoints.push(serde_json::json!({
            "hash": hash_str,
            "parent": parent_hash,
            "event_id": ev.event_id,
            "deltas": deltas,
        }));
    }

    serde_json::json!(checkpoints)
}

/// Compute the roots of the components.
pub fn compute_component_roots(
    events_map: &HashMap<String, LeanEvent>,
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
pub fn format_summary_output(ctx: &FormattingContext) -> serde_json::Value {
    let mut state_entries: Vec<serde_json::Value> = Vec::new();
    let mut members: HashMap<String, Vec<serde_json::Value>> = HashMap::new();

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
                .push(serde_json::json!({
                    "user_id": sk,
                    "displayname": displayname,
                    "event_id": eid,
                    "depth": ev.map_or(0, |e| e.depth),
                }));
        } else {
            state_entries.push(serde_json::json!({
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
    let mut membership_obj = serde_json::Map::new();
    for status in &membership_order {
        if let Some(list) = members.get(*status) {
            membership_obj.insert(
                (*status).to_string(),
                serde_json::json!({
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
                serde_json::json!({
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

    serde_json::json!({
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

fn format_resolve_state_output(ctx: &FormattingContext) -> serde_json::Value {
    let resolved_state: Vec<serde_json::Value> = resolved_state_entries(ctx.final_state_map)
        .into_iter()
        .map(|entry| {
            serde_json::json!({
                "type": entry.event_type,
                "state_key": entry.state_key,
                "event_id": entry.event_id,
            })
        })
        .collect();

    serde_json::json!({
        "status": "success",
        "format": "resolve_state",
        "resolved_state": resolved_state,
    })
}

/// Get a user's display name.
pub fn get_user_displayname(user_id: &str, displaynames: &HashMap<String, String>) -> String {
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
pub fn format_event_description(
    ev: &LeanEvent,
    sender: &str,
    displaynames: &HashMap<String, String>,
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
                "join" => Some(format!("{target} joined the room")),
                "leave" if ev.state_key.as_ref() == Some(&ev.sender) => {
                    Some(format!("{target} left the room"))
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
                "knock" => Some(format!("{target} knocked")),
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

/// Format the timeline output.
/// Render the timeline to a string, applying only authorized redactions.
fn render_timeline(ctx: &FormattingContext) -> String {
    // Owned copy of the events so the authorized redaction pass can mutate the
    // in-set targets in place. The resolved room state below is what the
    // redaction pass needs to authorize each redaction.
    let mut sorted_events: Vec<LeanEvent> = ctx.events_map.values().cloned().collect();
    let room_version = ctx.room_version.unwrap_or("1");

    // Resolved room state (event type + state_key -> event), used to check the
    // `redact` power level and each redaction sender's own power level.
    let mut room_state: RoomState<String, serde_json::Value, String> = RoomState::new();
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
    }

    sorted_events.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.event_id.cmp(&b.event_id)));

    let mut displaynames: HashMap<String, String> = HashMap::new();
    for ev in &sorted_events {
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

    for ev in &sorted_events {
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
pub fn format_timeline_output(ctx: &FormattingContext) -> serde_json::Value {
    eprint!("{}", render_timeline(ctx));
    serde_json::json!({
        "status": "success",
        "format": "timeline",
        "events": ctx.event_count
    })
}

/// Format the main CLI output.
pub fn format_cli_output(ctx: &FormattingContext) -> serde_json::Value {
    match ctx.args.format {
        OutputFormat::Deltas => format_deltas_output(ctx),
        OutputFormat::Summary => format_summary_output(ctx),
        OutputFormat::ResolveState => format_resolve_state_output(ctx),
        OutputFormat::Timeline => format_timeline_output(ctx),
        OutputFormat::Events => {
            let mut state_events: Vec<&serde_json::Value> = ctx
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
            serde_json::json!(state_events)
        }
        OutputFormat::Federation => {
            let state_events: Vec<&serde_json::Value> = ctx
                .resolved_state_list
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();
            let auth_chain_events: Vec<&serde_json::Value> = ctx
                .auth_chain_ids
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();

            serde_json::json!({
                "origin": ctx.args.origin,
                "state": state_events,
                "auth_chain": auth_chain_events
            })
        }
        OutputFormat::Default => serde_json::json!({
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
    use rezzy::StateResVersion;

    #[test]
    fn resolve_state_output_exposes_the_resolved_state_entries() {
        let args = Args {
            input: Vec::new(),
            room: None,
            homeserver: None,
            token: None,
            output: None,
            state_res: None,
            format: OutputFormat::ResolveState,
            debug: false,
            quiet: false,
            origin: "matrix.org".to_string(),
        };

        let events_map = HashMap::new();
        let raw_map = HashMap::new();
        let heads = Vec::new();
        let mut final_state_map = imbl::OrdMap::new();
        final_state_map.insert(("m.room.create".into(), String::new()), "$create".into());
        final_state_map.insert(("m.room.member".into(), "@alice:x".into()), "$join".into());
        let resolved_state_list = vec!["$create".to_string(), "$join".to_string()];
        let auth_chain_ids = Vec::new();

        let ctx = FormattingContext {
            args: &args,
            events_map: &events_map,
            raw_map: &raw_map,
            heads: &heads,
            final_state_map: &final_state_map,
            resolved_state_list: &resolved_state_list,
            auth_chain_ids: &auth_chain_ids,
            version: StateResVersion::V2,
            room_version: Some("11"),
            duration: std::time::Duration::from_millis(0),
            event_count: 2,
        };

        let output = format_cli_output(&ctx);
        assert_eq!(output["status"], "success");
        assert_eq!(output["format"], "resolve_state");
        assert_eq!(
            output["resolved_state"],
            serde_json::json!([
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
            let args = Args {
                input: Vec::new(),
                room: None,
                homeserver: None,
                token: None,
                output: None,
                state_res: None,
                format: OutputFormat::Timeline,
                debug: false,
                quiet: false,
                origin: "matrix.org".to_string(),
            };
            let raw_map = HashMap::new();
            let heads = Vec::new();
            let mut final_state_map = imbl::OrdMap::new();
            final_state_map.insert(("m.room.power_levels".into(), String::new()), "$pl".into());
            let resolved_state_list: Vec<String> = Vec::new();
            let auth_chain_ids: Vec<String> = Vec::new();
            let ctx = FormattingContext {
                args: &args,
                events_map: &events_map,
                raw_map: &raw_map,
                heads: &heads,
                final_state_map: &final_state_map,
                resolved_state_list: &resolved_state_list,
                auth_chain_ids: &auth_chain_ids,
                version: StateResVersion::V2,
                room_version: Some("11"),
                duration: std::time::Duration::from_millis(0),
                event_count: events.len(),
            };
            render_timeline(&ctx)
        };

        let pl: LeanEvent = LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            content: serde_json::json!({
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
            content: serde_json::json!({ "body": "secret" }),
            ..Default::default()
        };
        let mallory_redact: LeanEvent = LeanEvent {
            event_id: "$r_mal".into(),
            event_type: "m.room.redaction".into(),
            sender: "@mallory:x".into(),
            origin_server_ts: 11,
            content: serde_json::json!({ "redacts": "$msg" }),
            ..Default::default()
        };
        let self_redact: LeanEvent = LeanEvent {
            event_id: "$r_self".into(),
            event_type: "m.room.redaction".into(),
            sender: "@bob:x".into(),
            origin_server_ts: 12,
            content: serde_json::json!({ "redacts": "$msg" }),
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
