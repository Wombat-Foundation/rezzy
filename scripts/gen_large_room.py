#!/usr/bin/env python3
"""Generate a realistic large Matrix room fixture for stress-testing ruma-lean.

Simulates a room like Matrix HQ (#matrix:matrix.org) with:
- 10,000+ events with proper auth_events and prev_events DAG structure
- Concurrent forks from multiple servers (federation splits)
- Power level battles (admin vs moderator)
- Mass join/leave waves (spam bots, bridge users)
- Bans during power level changes
- Topic wars (concurrent topic changes)
- Room version upgrade events
- Realistic membership churn patterns

Output: res/realistic_large_room.json
"""

import hashlib
import json
import random
import sys

random.seed(42)  # Deterministic for reproducibility

NUM_EVENTS = 10000
ROOM_ID = "!stress_test_room:matrix.org"

# Users with varying power levels
ADMINS = ["@admin:matrix.org", "@moderator:matrix.org"]
MODS = [f"@mod{i}:matrix.org" for i in range(3)]
REGULARS = [f"@user{i}:matrix.org" for i in range(50)]
BOTS = [f"@bot{i}:bridge.matrix.org" for i in range(20)]
SPAMMERS = [f"@spam{i}:evil.example" for i in range(10)]
ALL_USERS = ADMINS + MODS + REGULARS + BOTS + SPAMMERS

events = []
event_ids = []
state = {}  # (type, state_key) -> event_id
joined_users = set()
power_levels = {}
current_ts = 1700000000000
event_counter = 0


def make_event_id():
    global event_counter
    h = hashlib.sha256(f"event_{event_counter}".encode()).hexdigest()[:20]
    eid = f"${h}"
    event_counter += 1
    return eid


def get_auth_events():
    """Get the auth events for a new event (create, PL, join rules, sender's membership)."""
    auths = []
    if ("m.room.create", "") in state:
        auths.append(state[("m.room.create", "")])
    if ("m.room.power_levels", "") in state:
        auths.append(state[("m.room.power_levels", "")])
    if ("m.room.join_rules", "") in state:
        auths.append(state[("m.room.join_rules", "")])
    return auths


def get_auth_for_member(sender, target_user):
    auths = get_auth_events()
    if ("m.room.member", sender) in state:
        auths.append(state[("m.room.member", sender)])
    if target_user != sender and ("m.room.member", target_user) in state:
        auths.append(state[("m.room.member", target_user)])
    return auths


def add_event(event_type, state_key, sender, content, prev=None):
    global current_ts
    eid = make_event_id()

    if prev is None:
        # Default: reference the last 1-2 events
        if len(event_ids) >= 2 and random.random() < 0.3:
            prev = [event_ids[-1], event_ids[-2]]
        elif event_ids:
            prev = [event_ids[-1]]
        else:
            prev = []

    if event_type == "m.room.member":
        auth = get_auth_for_member(sender, state_key)
    else:
        auth = get_auth_events()
        if ("m.room.member", sender) in state:
            auth.append(state[("m.room.member", sender)])

    event = {
        "event_id": eid,
        "room_id": ROOM_ID,
        "sender": sender,
        "type": event_type,
        "content": content,
        "state_key": state_key,
        "origin_server_ts": current_ts,
        "prev_events": prev,
        "auth_events": list(set(auth)),  # dedupe
        "depth": len(events) + 1,
        "power_level": power_levels.get(sender, 0),
    }

    events.append(event)
    event_ids.append(eid)
    state[(event_type, state_key)] = eid
    current_ts += random.randint(100, 30000)

    return eid


# ============================================================================
# Phase 1: Room Bootstrap (events 0-7)
# ============================================================================
print("Phase 1: Bootstrap...")
add_event(
    "m.room.create",
    "",
    ADMINS[0],
    {
        "creator": ADMINS[0],
        "room_version": "10",
    },
    prev=[],
)

add_event("m.room.member", ADMINS[0], ADMINS[0], {"membership": "join"})
joined_users.add(ADMINS[0])
power_levels[ADMINS[0]] = 100

add_event(
    "m.room.power_levels",
    "",
    ADMINS[0],
    {
        "users": {ADMINS[0]: 100, ADMINS[1]: 50},
        "users_default": 0,
        "events_default": 0,
        "state_default": 50,
        "ban": 50,
        "kick": 50,
        "invite": 0,
    },
)

add_event("m.room.join_rules", "", ADMINS[0], {"join_rule": "public"})
add_event("m.room.history_visibility", "", ADMINS[0], {"history_visibility": "shared"})
add_event("m.room.name", "", ADMINS[0], {"name": "Stress Test Room"})
add_event(
    "m.room.topic", "", ADMINS[0], {"topic": "Testing ruma-lean state resolution"}
)

# Moderator joins
add_event("m.room.member", ADMINS[1], ADMINS[1], {"membership": "join"})
joined_users.add(ADMINS[1])
power_levels[ADMINS[1]] = 50

# ============================================================================
# Phase 2: Initial Join Wave (events ~8-200)
# ============================================================================
print("Phase 2: Initial joins...")
for user in MODS:
    add_event("m.room.member", user, user, {"membership": "join"})
    joined_users.add(user)
    power_levels[user] = 50

for user in REGULARS[:30]:
    add_event("m.room.member", user, user, {"membership": "join"})
    joined_users.add(user)

# ============================================================================
# Phase 3: Activity + Membership Churn (events ~200-5000)
# ============================================================================
print("Phase 3: Activity + churn...")
for i in range(4800):
    r = random.random()

    if r < 0.4:
        # New user joins
        pool = [u for u in ALL_USERS if u not in joined_users]
        if pool:
            user = random.choice(pool)
            add_event("m.room.member", user, user, {"membership": "join"})
            joined_users.add(user)
        else:
            # Random user leaves and rejoins later
            leavable = [u for u in joined_users if u not in ADMINS]
            if leavable:
                user = random.choice(list(leavable))
                add_event("m.room.member", user, user, {"membership": "leave"})
                joined_users.discard(user)

    elif r < 0.45:
        # User leaves
        leavable = [u for u in joined_users if u not in ADMINS]
        if leavable:
            user = random.choice(list(leavable))
            add_event("m.room.member", user, user, {"membership": "leave"})
            joined_users.discard(user)

    elif r < 0.48:
        # Admin bans a spammer
        bannable = [u for u in joined_users if u in SPAMMERS]
        if bannable:
            target = random.choice(bannable)
            add_event("m.room.member", target, ADMINS[0], {"membership": "ban"})
            joined_users.discard(target)

    elif r < 0.50:
        # Power level change (mod promotes/demotes)
        if joined_users:
            target = random.choice(list(joined_users - set(ADMINS)))
            new_pl = random.choice([0, 10, 50])
            power_levels[target] = new_pl
            users_dict = {u: power_levels.get(u, 0) for u in joined_users}
            users_dict[ADMINS[0]] = 100
            users_dict[ADMINS[1]] = 50
            add_event(
                "m.room.power_levels",
                "",
                ADMINS[0],
                {
                    "users": users_dict,
                    "users_default": 0,
                    "state_default": 50,
                    "ban": 50,
                    "kick": 50,
                },
            )

    elif r < 0.52:
        # Topic change
        topics = [
            "Testing state resolution",
            "ruma-lean stress test",
            "Matrix protocol development",
            "State res v2.1 validation",
            "Auth chain verification",
        ]
        changer = random.choice(list(joined_users & set(ADMINS + MODS)))
        add_event(
            "m.room.topic",
            "",
            changer,
            {
                "topic": random.choice(topics),
            },
        )

    else:
        # Regular membership event (rejoin after leave)
        pool = [u for u in ALL_USERS if u not in joined_users and u not in SPAMMERS]
        if pool:
            user = random.choice(pool)
            add_event("m.room.member", user, user, {"membership": "join"})
            joined_users.add(user)
        else:
            leavable = [u for u in joined_users if u not in ADMINS]
            if leavable:
                user = random.choice(list(leavable))
                add_event("m.room.member", user, user, {"membership": "leave"})
                joined_users.discard(user)

# ============================================================================
# Phase 4: Federation Fork Simulation (events ~5000-7000)
# Creates parallel branches in the DAG
# ============================================================================
print("Phase 4: Federation forks...")
fork_point = event_ids[-1]

# Fork A: Server 1 sees these events
fork_a_ids = []
for i in range(200):
    user = random.choice(list(joined_users - set(ADMINS)))
    eid = add_event(
        "m.room.member",
        user,
        user,
        {
            "membership": random.choice(["leave", "join"]),
        },
        prev=[fork_a_ids[-1] if fork_a_ids else fork_point],
    )
    fork_a_ids.append(eid)

# Fork B: Server 2 sees different events (concurrent with fork A)
fork_b_ids = []
for i in range(200):
    user = random.choice(list(joined_users - set(ADMINS)))
    eid = add_event(
        "m.room.member",
        user,
        user,
        {
            "membership": random.choice(["leave", "join"]),
        },
        prev=[fork_b_ids[-1] if fork_b_ids else fork_point],
    )
    fork_b_ids.append(eid)

# Merge point: references tips of both forks
merge_prev = [fork_a_ids[-1], fork_b_ids[-1]]
add_event(
    "m.room.member",
    random.choice(list(joined_users)),
    ADMINS[0],
    {
        "membership": "join",
    },
    prev=merge_prev,
)

# ============================================================================
# Phase 5: Power Level War (events ~7000-8000)
# Admin and mod issue competing power level changes
# ============================================================================
print("Phase 5: Power level wars...")
for i in range(500):
    if random.random() < 0.5:
        # Admin changes PLs
        users_dict = {u: power_levels.get(u, 0) for u in joined_users}
        users_dict[ADMINS[0]] = 100
        users_dict[ADMINS[1]] = 50
        # Admin demotes a random mod
        target = random.choice(MODS)
        users_dict[target] = random.choice([0, 10, 25])
        add_event(
            "m.room.power_levels",
            "",
            ADMINS[0],
            {
                "users": users_dict,
                "users_default": 0,
                "state_default": 50,
            },
        )
    else:
        # Mod tries to change PLs (may or may not have authority)
        mod = random.choice(MODS)
        if mod in joined_users:
            users_dict = {u: power_levels.get(u, 0) for u in joined_users}
            users_dict[ADMINS[0]] = 100
            add_event(
                "m.room.power_levels",
                "",
                mod,
                {
                    "users": users_dict,
                    "users_default": 0,
                    "state_default": 50,
                },
            )

# ============================================================================
# Phase 6: Final Churn + Wrap Up (events ~8000-10000)
# ============================================================================
print("Phase 6: Final churn...")
remaining = NUM_EVENTS - len(events)
for i in range(remaining):
    r = random.random()
    if r < 0.6:
        pool = [u for u in ALL_USERS if u not in joined_users]
        if pool:
            user = random.choice(pool)
            add_event("m.room.member", user, user, {"membership": "join"})
            joined_users.add(user)
        else:
            user = random.choice(list(joined_users - set(ADMINS)))
            add_event("m.room.member", user, user, {"membership": "leave"})
            joined_users.discard(user)
    elif r < 0.8:
        user = random.choice(list(joined_users - set(ADMINS)))
        add_event("m.room.member", user, user, {"membership": "leave"})
        joined_users.discard(user)
    else:
        user = random.choice(list(joined_users - set(ADMINS)))
        add_event("m.room.member", user, user, {"membership": "join"})

# ============================================================================
# Compute stats
# ============================================================================
types = {}
for e in events:
    t = e["type"]
    types[t] = types.get(t, 0) + 1

max_depth = max(e.get("depth", 0) for e in events)
max_auth_chain = max(len(e.get("auth_events", [])) for e in events)
fork_events = sum(1 for e in events if len(e.get("prev_events", [])) > 1)

print(f"\n=== Generated {len(events)} events ===")
print(f"Max depth: {max_depth}")
print(f"Max auth chain refs: {max_auth_chain}")
print(f"Fork merge points: {fork_events}")
for t in sorted(types, key=lambda x: -types[x]):
    print(f"  {t}: {types[t]}")

# Identify heads (events not referenced by any other event's prev_events)
all_prev = set()
for e in events:
    all_prev.update(e.get("prev_events", []))
heads = [e["event_id"] for e in events if e["event_id"] not in all_prev]
print(f"DAG heads: {len(heads)}")

output = {
    "events": events,
    "heads": heads[:10],  # Cap at 10 heads
    "metadata": {
        "total_events": len(events),
        "unique_senders": len(set(e["sender"] for e in events)),
        "event_types": types,
        "max_depth": max_depth,
        "fork_merges": fork_events,
        "heads": len(heads),
    },
}

with open("res/realistic_large_room.json", "w") as f:
    json.dump(output, f, separators=(",", ":"))

print(
    f"\nWritten to res/realistic_large_room.json ({len(json.dumps(output)) // 1024}KB)"
)
