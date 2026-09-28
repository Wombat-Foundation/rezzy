"""
Generates a 1,000-event synthetic Matrix Room State DAG vector for benchmarking.
"""

import hashlib
import json
import os
import random
import sys
import time
from typing import Any

NUM_EVENTS = 1000
OUTPUT_FILE = "res/benchmark_1k.json"


def sha256_hash(data_str):
    """Return the hex digest of the SHA-256 hash of a string."""
    return hashlib.sha256(data_str.encode("utf-8")).hexdigest()


if not os.path.exists("res"):
    os.makedirs("res")

print(f"Generating {NUM_EVENTS} synthetic Matrix state events...", file=sys.stderr)

events: list[dict[str, Any]] = []
ROOM_ID = "!benchmark_room:example.com"
members = [f"@user_{i}:example.com" for i in range(50)]

# Create initial events
CREATE_EVENT_ID = "$00000-m-room-create"
events.append(
    {
        "event_id": CREATE_EVENT_ID,
        "room_id": ROOM_ID,
        "sender": "@creator:example.com",
        "type": "m.room.create",
        "content": {"creator": "@creator:example.com", "room_version": "10"},
        "state_key": "",
        "origin_server_ts": int(time.time() * 1000) - 10000000,
        "prev_events": [],
        "auth_events": [],
        "power_level": 100,
        "depth": 1,
    }
)

CREATOR_JOIN_ID = "$00000.5-creator-join"
events.append(
    {
        "event_id": CREATOR_JOIN_ID,
        "room_id": ROOM_ID,
        "sender": "@creator:example.com",
        "type": "m.room.member",
        "content": {"membership": "join"},
        "state_key": "@creator:example.com",
        "origin_server_ts": int(time.time() * 1000) - 9500000,
        "prev_events": [CREATE_EVENT_ID],
        "auth_events": [CREATE_EVENT_ID],
        "power_level": 100,
        "depth": 2,
    }
)

POWER_LEVELS_EVENT_ID = "$00001-power-levels"
users_dict = {"@creator:example.com": 100}
for m in members:
    users_dict[m] = 100

events.append(
    {
        "event_id": POWER_LEVELS_EVENT_ID,
        "room_id": ROOM_ID,
        "sender": "@creator:example.com",
        "type": "m.room.power_levels",
        "content": {
            "users_default": 100,
            "events_default": 0,
            "state_default": 0,
            "users": users_dict,
        },
        "state_key": "",
        "origin_server_ts": int(time.time() * 1000) - 9000000,
        "prev_events": [CREATE_EVENT_ID],
        "auth_events": [CREATE_EVENT_ID],
        "power_level": 100,
        "depth": 3,
    }
)

event_types = [
    "m.room.power_levels",
    "m.room.join_rules",
]

for i in range(3, NUM_EVENTS):
    sender = "@creator:example.com"
    ev_type = random.choice(event_types)
    ts = events[-1]["origin_server_ts"] + random.randint(1, 1000)

    prev_event_id = events[-1]["event_id"]

    content: dict[str, Any] = {}
    state_key = ""
    if ev_type == "m.room.member":
        content = {"membership": random.choice(["invite", "leave"])}
        state_key = random.choice(members)
    elif ev_type == "m.room.power_levels":
        content = {"users": users_dict}  # keep it the same to not lose power
    else:
        content = {"join_rule": random.choice(["public", "invite"])}

    event_id = f"${sha256_hash(str(i))[:20]}"

    events.append(
        {
            "event_id": event_id,
            "room_id": ROOM_ID,
            "sender": sender,
            "type": ev_type,
            "content": content,
            "state_key": state_key,
            "origin_server_ts": ts,
            "prev_events": [prev_event_id],
            "auth_events": [CREATE_EVENT_ID, CREATOR_JOIN_ID, POWER_LEVELS_EVENT_ID],
            "power_level": 100,
            "depth": i + 1,
        }
    )

# Create two heads for a fork
head1 = events[-2]["event_id"]
head2 = events[-1]["event_id"]

# V2 File
V2_FILE = "res/benchmark_1k.json"
with open(V2_FILE, "w", encoding="utf-8") as f:
    output = {"events": events, "heads": [head1, head2]}
    json.dump(output, f, indent=2)

print(f"Success! Generated {NUM_EVENTS} events to {V2_FILE}", file=sys.stderr)

# V2.1 File (Room Version 12)
V2_1_FILE = "res/benchmark_1k_v2_1.json"
events_v2_1: list[dict[str, Any]] = []
for ev in events:
    new_ev = ev.copy()
    if ev["type"] == "m.room.create":
        new_ev["content"] = {"creator": ev["content"]["creator"], "room_version": "12"}
    events_v2_1.append(new_ev)

with open(V2_1_FILE, "w", encoding="utf-8") as f:
    output = {"events": events_v2_1, "heads": [head1, head2]}
    json.dump(output, f, indent=2)

print(f"Success! Generated {NUM_EVENTS} events to {V2_1_FILE}", file=sys.stderr)
