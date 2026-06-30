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
use rezzy::{LeanEvent, StateResVersion};
use std::collections::HashMap;

pub struct FormattingContext<'a> {
    pub args: &'a Args,
    pub events_map: &'a HashMap<String, LeanEvent>,
    pub raw_map: &'a HashMap<String, serde_json::Value>,
    pub heads: &'a [String],
    pub final_state_map: &'a imbl::OrdMap<(String, String), String>,
    pub resolved_state_list: &'a [String],
    pub auth_chain_ids: &'a [String],
    pub version: StateResVersion,
    pub duration: std::time::Duration,
    pub event_count: usize,
}

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
                (ev.event_type.clone(), ev.state_key.clone().unwrap()),
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

pub fn compute_component_roots(
    events_map: &HashMap<String, LeanEvent>,
    include_prev: bool,
    include_auth: bool,
) -> Vec<String> {
    let mut component_roots = Vec::new();
    if !events_map.is_empty() {
        let mut parent: Vec<usize> = (0..events_map.len()).collect();
        let mut id_to_index: HashMap<&str, usize> = HashMap::with_capacity(events_map.len());
        let mut index_to_ev: Vec<&LeanEvent> = Vec::with_capacity(events_map.len());
        for (i, ev) in events_map.values().enumerate() {
            id_to_index.insert(ev.event_id.as_str(), i);
            index_to_ev.push(ev);
        }
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

pub fn format_summary_output(ctx: &FormattingContext) -> serde_json::Value {
    let mut state_entries: Vec<serde_json::Value> = Vec::new();
    let mut members: HashMap<String, Vec<serde_json::Value>> = HashMap::new();

    for ((typ, sk), eid) in ctx.final_state_map {
        let ev = ctx.events_map.get(eid);
        if typ == "m.room.member" {
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
                status.to_string(),
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

pub fn format_timeline_output(ctx: &FormattingContext) -> serde_json::Value {
    let mut displaynames: HashMap<String, String> = HashMap::new();
    let mut sorted_events: Vec<&LeanEvent> = ctx.events_map.values().collect();
    sorted_events.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.event_id.cmp(&b.event_id)));

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

    eprint!("{output}");
    serde_json::json!({
        "status": "success",
        "format": "timeline",
        "events": ctx.event_count
    })
}

pub fn format_cli_output(ctx: &FormattingContext) -> serde_json::Value {
    match ctx.args.format {
        OutputFormat::Deltas => format_deltas_output(ctx),
        OutputFormat::Summary => format_summary_output(ctx),
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
