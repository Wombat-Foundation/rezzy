#!/usr/bin/env bash
set -e

# Setup a minimal ruma-cli for E2E parity testing
mkdir -p .tmp/ruma-cli/src

# Clone ruma if not already there
if [ ! -d .tmp/ruma ]; then
	git clone --depth 1 https://github.com/ruma/ruma.git .tmp/ruma
fi

cat <<EOF >.tmp/ruma-cli/Cargo.toml
[package]
name = "ruma-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
ruma-state-res = { path = "../ruma/crates/ruma-state-res" }
ruma-events = { path = "../ruma/crates/ruma-events" }
ruma-common = { path = "../ruma/crates/ruma-common" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"
clap = { version = "4.4", features = ["derive"] }
async-trait = "0.1"
EOF

# Use the logic from the previously successfully built ruma-cli
cat <<EOF >.tmp/ruma-cli/src/main.rs
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

use clap::Parser;
use ruma_common::{
    EventId, MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, UserId,
};
use ruma_events::TimelineEventType;
use ruma_state_res::{Event, StateMap, resolve, events::RoomCreateEvent};
use serde_json::{Value, value::RawValue as RawJsonValue};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    input: PathBuf,
}

#[derive(serde::Deserialize, Clone)]
struct Pdu {
    event_id: OwnedEventId,
    room_id: Option<OwnedRoomId>,
    sender: OwnedUserId,
    origin_server_ts: MilliSecondsSinceUnixEpoch,
    #[serde(rename = "type")]
    event_type: TimelineEventType,
    content: Box<RawJsonValue>,
    state_key: Option<String>,
    prev_events: Vec<OwnedEventId>,
    auth_events: Vec<OwnedEventId>,
    redacts: Option<OwnedEventId>,
    #[serde(default)]
    rejected: bool,
}

impl Event for Pdu {
    type Id = OwnedEventId;
    fn event_id(&self) -> &Self::Id { &self.event_id }
    fn room_id(&self) -> Option<&RoomId> { self.room_id.as_deref() }
    fn sender(&self) -> &UserId { &self.sender }
    fn origin_server_ts(&self) -> MilliSecondsSinceUnixEpoch { self.origin_server_ts }
    fn event_type(&self) -> &TimelineEventType { &self.event_type }
    fn content(&self) -> &RawJsonValue { &self.content }
    fn state_key(&self) -> Option<&str> { self.state_key.as_deref() }
    fn prev_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> { Box::new(self.prev_events.iter()) }
    fn auth_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> { Box::new(self.auth_events.iter()) }
    fn redacts(&self) -> Option<&Self::Id> { self.redacts.as_ref() }
    fn rejected(&self) -> bool { self.rejected }
}

fn pdu_auth_chain(pdu: &Pdu, pdus_map: &HashMap<OwnedEventId, Pdu>) -> HashSet<OwnedEventId> {
    let mut auth_chain = HashSet::new();
    let mut stack = pdu.auth_events.clone();
    while let Some(event_id) = stack.pop() {
        if auth_chain.contains(&event_id) { continue; }
        if let Some(pdu) = pdus_map.get(&event_id) {
            stack.extend(pdu.auth_events.clone());
            auth_chain.insert(event_id);
        }
    }
    auth_chain
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let data = fs::read_to_string(args.input)?;
    let input_val: Value = serde_json::from_str(&data)?;
    let (pdus, heads) = if let Some(obj) = input_val.as_object() {
        if obj.contains_key("events") && obj.contains_key("heads") {
            let evs: Vec<Pdu> = serde_json::from_value(obj.get("events").unwrap().clone())?;
            let hds = obj.get("heads").unwrap().as_array().expect("heads should be array").iter()
                .map(|v| v.as_str().expect("head should be string").to_string())
                .collect::<Vec<_>>();
            (evs, hds)
        } else { (serde_json::from_value::<Vec<Pdu>>(input_val)?, Vec::new()) }
    } else { (serde_json::from_value::<Vec<Pdu>>(input_val)?, Vec::new()) };

    let pdus_map: HashMap<OwnedEventId, Pdu> = pdus.clone().into_iter().map(|pdu| (pdu.event_id.clone(), pdu)).collect();
    let mut state_maps = Vec::new();
    let mut auth_chain_ids = HashSet::new();

    if heads.is_empty() {
        let mut state_map = StateMap::new();
        for pdu in &pdus {
            if let Some(state_key) = &pdu.state_key {
                state_map.insert((pdu.event_type().to_string().into(), state_key.clone()), pdu.event_id.clone());
            }
            auth_chain_ids.extend(pdu_auth_chain(pdu, &pdus_map));
        }
        state_maps.push(state_map);
    } else {
        for head_id in heads {
            let mut state_map = StateMap::new();
            let mut visited = HashSet::new();
            let head_owned = <EventId>::parse(head_id).expect("invalid head id").to_owned();
            let mut stack = vec![head_owned.clone()];
            while let Some(ev_id) = stack.pop() {
                if !visited.insert(ev_id.clone()) { continue; }
                if let Some(pdu) = pdus_map.get(&ev_id) {
                    if let Some(state_key) = &pdu.state_key {
                        let key = (pdu.event_type().to_string().into(), state_key.clone());
                        state_map.entry(key).or_insert(ev_id.clone());
                    }
                    stack.extend(pdu.prev_events.clone());
                    auth_chain_ids.extend(pdu_auth_chain(pdu, &pdus_map));
                }
            }
            state_maps.push(state_map);
        }
    }

    let room_create_pdu = pdus.iter().find(|p| p.event_type == TimelineEventType::RoomCreate).expect("room create event missing");
    let room_create_event = RoomCreateEvent::new(room_create_pdu.clone());
    let room_version_id = room_create_event.room_version().map_err(anyhow::Error::msg)?;
    let rules = room_version_id.rules().expect("unsupported room version");
    let auth_rules = rules.authorization;
    let state_res_rules = rules.state_res.v2_rules().expect("only v2 supported");

    let resolved = resolve(&auth_rules, state_res_rules, &state_maps, vec![auth_chain_ids], |x| pdus_map.get(x).cloned(), |_| Some(HashSet::new()))?;

    let mut state_events = Vec::new();
    for event_id in resolved.values() {
        if let Some(pdu) = pdus_map.get(event_id) {
            let val: Value = serde_json::from_str(pdu.content.get())?;
            state_events.push(serde_json::json!({
                "event_id": pdu.event_id,
                "type": pdu.event_type,
                "state_key": pdu.state_key,
                "content": val,
                "sender": pdu.sender,
                "origin_server_ts": pdu.origin_server_ts,
                "prev_events": pdu.prev_events,
                "auth_events": pdu.auth_events,
            }));
        }
    }

    println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "state": state_events, "auth_chain": [] }))?);
    Ok(())
}
EOF
