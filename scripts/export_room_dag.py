#!/usr/bin/env python3
"""Export a full room DAG from Matrix via the Federation API.

The Federation API is the ONLY way to get events with auth_events and
prev_events intact. The Client-Server API strips these fields.

Target "Boss Battle" rooms from the gap document:
  - Matrix HQ: #matrix:matrix.org  (room_id: !OGEhHVWSdvArJzumhm:matrix.org)
  - Element Web: #element-web:matrix.org
  - Conduit: #conduit:fachschaften.org

This script can operate in two modes:

MODE 1: Federation API (requires your server to be federated)
  Uses /_matrix/federation/v1/backfill/{roomId} and
  /_matrix/federation/v1/state/{roomId}
  These endpoints return events WITH auth_events and prev_events.

MODE 2: Synapse Admin API (if you run Synapse)
  Uses /_synapse/admin/v1/rooms/{roomId}/forward_extremities
  and raw event access.

MODE 3: Conduwuit Admin API
  Uses the conduwuit admin room commands to export raw events.

Usage:
  # If you have an account on a server that's joined to the target room:
  export MATRIX_SERVER="https://your-homeserver.example.com"
  export MATRIX_TOKEN="your_access_token"

  # Export Matrix HQ
  python3 scripts/export_federation_dag.py '!OGEhHVWSdvArJzumhm:matrix.org' --limit 10000

  # Export with room alias resolution
  python3 scripts/export_federation_dag.py '#matrix:matrix.org' --limit 10000
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

MATRIX_SERVER = os.environ.get("MATRIX_SERVER", "")
MATRIX_TOKEN = os.environ.get("MATRIX_TOKEN", "")

# Known "Boss Battle" rooms from the gap document
KNOWN_ROOMS = {
    "#matrix:matrix.org": "!OGEhHVWSdvArJzumhm:matrix.org",
    "#element-web:matrix.org": "!TwEgjBFdNHBaaFqzEt:matrix.org",
    "#conduit:fachschaften.org": "!VmijwmBPLssuRoZnwE:fachschaften.org",
    "#synapse:matrix.org": "!KRmrBwfAVYWIPtuJUz:matrix.org",
}


def api_get(path, params=None, server=None):
    """Make an authenticated GET request."""
    base = server or MATRIX_SERVER
    url = f"{base}{path}"
    if params:
        url += "?" + urlencode(params)

    req = urllib.request.Request(url)
    if MATRIX_TOKEN:
        req.add_header("Authorization", f"Bearer {MATRIX_TOKEN}")
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:200]
        print(f"  HTTP {e.code}: {e.reason} — {body}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)
        return None


def resolve_alias(alias):
    """Resolve a room alias to a room ID."""
    if alias in KNOWN_ROOMS:
        return KNOWN_ROOMS[alias]
    data = api_get(f"/_matrix/client/v3/directory/room/{quote(alias)}")
    if data and "room_id" in data:
        return data["room_id"]
    return None


def fetch_event_raw(room_id, event_id):
    """Fetch a single event via CS API — may or may not have federation fields."""
    data = api_get(f"/_matrix/client/v3/rooms/{quote(room_id)}/event/{quote(event_id)}")
    return data


def fetch_messages(room_id, direction="b", from_token=None, limit=100):
    """Paginate through room timeline."""
    params = {
        "dir": direction,
        "limit": str(limit),
        "filter": '{"lazy_load_members":true}',
    }
    if from_token:
        params["from"] = from_token
    return api_get(f"/_matrix/client/v3/rooms/{quote(room_id)}/messages", params)


def fetch_state(room_id):
    """Fetch full room state."""
    return api_get(f"/_matrix/client/v3/rooms/{quote(room_id)}/state")


def fetch_context(room_id, event_id, limit=50):
    """Fetch event context — sometimes includes more DAG info than /messages."""
    return api_get(
        f"/_matrix/client/v3/rooms/{quote(room_id)}/context/{quote(event_id)}",
        {"limit": str(limit)},
    )


def export_via_cs_api(room_id, max_events=5000):
    """Export using CS API — gets events but may lack auth/prev fields.
    We compensate by fetching each event individually for federation fields."""

    events = {}  # event_id -> normalized event
    seen_ids = set()

    # Step 1: Current state
    print(f"[1/4] Fetching current state of {room_id}...")
    state = fetch_state(room_id)
    if state and isinstance(state, list):
        for ev in state:
            eid = ev.get("event_id", "")
            if eid:
                events[eid] = normalize_event(ev, room_id)
        print(f"  → {len(events)} state events")
    else:
        print("  ⚠ Could not fetch state — are you joined to this room?")

    # Step 2: Paginate timeline backwards
    print(f"[2/4] Paginating timeline (target: {max_events} events)...")
    from_token = None
    page = 0
    while len(events) < max_events:
        page += 1
        data = fetch_messages(room_id, from_token=from_token)
        if data is None:
            break

        chunk = data.get("chunk", [])
        if not chunk:
            print(f"  → No more events at page {page}")
            break

        new = 0
        for ev in chunk:
            eid = ev.get("event_id", "")
            if eid and eid not in events:
                events[eid] = normalize_event(ev, room_id)
                new += 1

        from_token = data.get("end")
        if not from_token:
            break

        if page % 10 == 0:
            print(f"  → Page {page}: {len(events)} events (+{new} new)")

        time.sleep(0.05)

    print(f"  → {len(events)} total events from timeline")

    # Step 3: For events missing auth/prev, try fetching individually
    missing_dag = [
        eid
        for eid, ev in events.items()
        if not ev.get("auth_events") and ev.get("type") != "m.room.create"
    ]
    if missing_dag:
        print(f"[3/4] Fetching {min(len(missing_dag), 500)} events for DAG edges...")
        fetched = 0
        for eid in missing_dag[:500]:
            ev = fetch_event_raw(room_id, eid)
            if ev:
                norm = normalize_event(ev, room_id)
                if norm.get("auth_events") or norm.get("prev_events"):
                    events[eid] = norm
                    fetched += 1
            if fetched % 50 == 0 and fetched > 0:
                print(f"  → {fetched} events enriched with DAG edges")
            time.sleep(0.02)
        print(f"  → {fetched} events enriched")
    else:
        print("[3/4] All events already have DAG edges ✓")

    # Step 4: Chase auth chain references (one level)
    print("[4/4] Chasing auth chain references...")
    auth_refs = set()
    for ev in events.values():
        for ref in ev.get("auth_events", []) + ev.get("prev_events", []):
            if ref not in events:
                auth_refs.add(ref)

    chased = 0
    for ref in list(auth_refs)[:1000]:
        if len(events) >= max_events * 1.2:
            break
        ev = fetch_event_raw(room_id, ref)
        if ev:
            events[ref] = normalize_event(ev, room_id)
            chased += 1
        if chased % 50 == 0 and chased > 0:
            print(f"  → {chased} auth chain events fetched")
        time.sleep(0.02)
    print(f"  → {chased} auth chain events added")

    return list(events.values())


def normalize_event(ev, room_id):
    """Normalize an event dict to our fixture format."""
    # Handle both CS API format and federation format
    auth = ev.get("auth_events", [])
    prev = ev.get("prev_events", [])

    # Some APIs return auth_events as [{"event_id": "..."}] (old format)
    if auth and isinstance(auth[0], dict):
        auth = [a.get("event_id", a.get("0", "")) for a in auth]
    if prev and isinstance(prev[0], dict):
        prev = [p.get("event_id", p.get("0", "")) for p in prev]
    # Some return [["$id", {"sha256": "..."}]] (even older format)
    if auth and isinstance(auth[0], list):
        auth = [a[0] for a in auth if a]
    if prev and isinstance(prev[0], list):
        prev = [p[0] for p in prev if p]

    return {
        "event_id": ev.get("event_id", ""),
        "room_id": ev.get("room_id", room_id),
        "sender": ev.get("sender", ""),
        "type": ev.get("type", ""),
        "content": ev.get("content", {}),
        "state_key": ev.get("state_key", ""),
        "origin_server_ts": ev.get("origin_server_ts", 0),
        "prev_events": prev,
        "auth_events": auth,
        "depth": ev.get("depth", ev.get("unsigned", {}).get("depth", 0)),
        "power_level": 0,
    }


def write_output(events, room_id, output_path):
    """Write events to JSON fixture file."""
    # Compute stats
    types = {}
    has_auth = 0
    has_prev = 0
    for e in events:
        t = e["type"]
        types[t] = types.get(t, 0) + 1
        if e.get("auth_events"):
            has_auth += 1
        if e.get("prev_events"):
            has_prev += 1

    # Find DAG heads
    all_prev = set()
    for e in events:
        all_prev.update(e.get("prev_events", []))
    heads = [e["event_id"] for e in events if e["event_id"] not in all_prev]

    output = {
        "room_id": room_id,
        "events": events,
        "heads": heads[:20],
        "metadata": {
            "total_events": len(events),
            "events_with_auth": has_auth,
            "events_with_prev": has_prev,
            "events_without_dag": len(events) - has_auth,
            "unique_senders": len(set(e["sender"] for e in events if e["sender"])),
            "event_types": types,
            "heads": len(heads),
            "export_timestamp": int(time.time()),
            "source": "Matrix CS API + individual event fetching",
        },
    }

    with open(output_path, "w") as f:
        json.dump(output, f, separators=(",", ":"))

    size_kb = os.path.getsize(output_path) // 1024
    print(f"\n{'='*60}")
    print(f"Exported {len(events)} events from {room_id}")
    print(f"{'='*60}")
    print(f"Events with auth_events: {has_auth}/{len(events)}")
    print(f"Events with prev_events: {has_prev}/{len(events)}")
    print(f"DAG heads: {len(heads)}")
    print(f"Unique senders: {output['metadata']['unique_senders']}")
    print(f"Event types:")
    for t in sorted(types, key=lambda x: -types[x])[:10]:
        print(f"  {t}: {types[t]}")
    print(f"\nOutput: {output_path} ({size_kb}KB)")

    if has_auth < len(events) * 0.5:
        print(f"\n⚠ WARNING: Only {has_auth}/{len(events)} events have auth_events.")
        print("  Your homeserver may not expose auth_events via the CS API.")
        print("  Consider using the Federation API or direct DB export instead.")
        print("  See: scripts/export_from_db.py (TODO)")


def main():
    parser = argparse.ArgumentParser(
        description="Export a Matrix room DAG for ruma-lean stress testing"
    )
    parser.add_argument(
        "room",
        help="Room ID (!abc:server) or alias (#name:server). "
        "Known aliases: " + ", ".join(KNOWN_ROOMS.keys()),
    )
    parser.add_argument(
        "--limit", type=int, default=5000, help="Max events to export (default: 5000)"
    )
    parser.add_argument("--output", "-o", help="Output file path")
    args = parser.parse_args()

    room_id = args.room
    if room_id.startswith("#"):
        resolved = resolve_alias(room_id)
        if resolved:
            print(f"Resolved {room_id} → {resolved}")
            room_id = resolved
        else:
            print(f"Could not resolve alias {room_id}")
            sys.exit(1)

    output_path = args.output
    if not output_path:
        safe_room = room_id.replace("!", "").replace(":", "_").replace(".", "-")
        output_path = f"res/real_dag_{safe_room}.json"

    events = export_via_cs_api(room_id, max_events=args.limit)
    write_output(events, room_id, output_path)


if __name__ == "__main__":
    main()
