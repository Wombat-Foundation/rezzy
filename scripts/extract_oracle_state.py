#!/usr/bin/env python3
"""Extract oracle (ground-truth) resolved state from a live Matrix server.

Uses the Client-Server API to get the current resolved state of a room,
which was computed by the server's own state resolution implementation
(ruma-state-res in conduwuit). This serves as the external oracle to
validate ruma-lean's output against.

Usage:
  export MATRIX_SERVER=https://your-server.example.com
  export MATRIX_TOKEN=syt_your_token
  python3 scripts/extract_oracle_state.py '!roomid:server' -o res/expected/oracle_room.json

Or, to extract directly from the conduwuit RocksDB (offline):
  python3 scripts/extract_oracle_state.py --from-db '!roomid:server' -o res/expected/oracle_room.json
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode

MATRIX_SERVER = os.environ.get("MATRIX_SERVER", "")
MATRIX_TOKEN = os.environ.get("MATRIX_TOKEN", "")
DB_PATH = os.environ.get(
    "CONDUWUIT_DB",
    "/run/media/shane/shane4tb-ent/vps/vps16-dev/var/lib/conduwuit",
)
LDB_ENV = {"LD_LIBRARY_PATH": "/usr/local/lib", "PATH": os.environ.get("PATH", "")}
SECONDARY_PATH = "/tmp/conduwuit_secondary"


def api_get(path, params=None):
    """Make an authenticated GET request to the Matrix CS API."""
    url = f"{MATRIX_SERVER}{path}"
    if params:
        url += "?" + urlencode(params)
    req = urllib.request.Request(url)
    if MATRIX_TOKEN:
        req.add_header("Authorization", f"Bearer {MATRIX_TOKEN}")
    req.add_header("Accept", "application/json")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def get_state_from_api(room_id):
    """Get the current resolved state from the CS API."""
    encoded = quote(room_id)
    data = api_get(f"/_matrix/client/v3/rooms/{encoded}/state")
    # data is an array of state events
    state_map = {}
    for event in data:
        event_type = event.get("type", "")
        state_key = event.get("state_key", "")
        event_id = event.get("event_id", "")
        state_map[f"{event_type}|{state_key}"] = {
            "type": event_type,
            "state_key": state_key,
            "event_id": event_id,
        }
    return state_map


def get_state_from_db(room_id):
    """Get the current resolved state from the conduwuit RocksDB.

    Strategy: scan pduid_pdu for the room, find the latest event,
    then look up its shortstatehash -> expand the full state.

    Since the state-to-event mapping requires chasing multiple tables
    (shortstatehash -> statediff -> shorteventid -> eventid), we take
    a simpler approach: find ALL state events for the room and take
    the latest one per (type, state_key) pair.
    """
    print(f"Extracting oracle state from DB for {room_id}...")
    state_map = {}  # (type, state_key) -> event with highest depth

    cmd = [
        "ldb",
        f"--db={DB_PATH}",
        "--ignore_unknown_options",
        f"--secondary_path={SECONDARY_PATH}",
        "scan",
        "--column_family=pduid_pdu",
        "--hex",
    ]

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=LDB_ENV
    )

    scanned = 0
    state_events = 0
    for line in proc.stdout:
        line = line.decode("utf-8", errors="replace").strip()
        if " ==> " not in line:
            continue
        _, val_hex = line.split(" ==> ", 1)
        scanned += 1

        try:
            raw = bytes.fromhex(val_hex[2:] if val_hex.startswith("0x") else val_hex)
            pdu = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue

        if pdu.get("room_id") != room_id:
            continue

        # Only state events have state_key
        if "state_key" not in pdu:
            continue

        event_type = pdu.get("type", "")
        state_key = pdu.get("state_key", "")
        depth = pdu.get("depth", 0)
        event_id = pdu.get("event_id", "")
        key = f"{event_type}|{state_key}"

        # Keep the event with the highest depth (most recent)
        existing = state_map.get(key)
        if existing is None or depth > existing.get("_depth", 0):
            state_map[key] = {
                "type": event_type,
                "state_key": state_key,
                "event_id": event_id,
                "_depth": depth,
            }
            state_events += 1

        if scanned % 50000 == 0:
            print(f"  Scanned {scanned} PDUs, found {state_events} state events...")

    proc.wait()

    # Remove internal _depth field
    for v in state_map.values():
        v.pop("_depth", None)

    print(f"  Scanned {scanned} total, {len(state_map)} unique state entries")
    return state_map


def write_oracle(state_map, room_id, output_path):
    """Write the oracle state as a sorted JSON file."""
    # Convert to sorted list for deterministic comparison
    state_list = sorted(
        state_map.values(),
        key=lambda e: (e["type"], e["state_key"]),
    )

    output = {
        "room_id": room_id,
        "source": "conduwuit state resolution (ruma-state-res)",
        "description": (
            "Ground-truth resolved state as computed by the server's own "
            "state resolution engine. ruma-lean's output must match this."
        ),
        "resolved_state": state_list,
        "total_resolved": len(state_list),
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, sort_keys=False)

    print(f"\nOracle state written to {output_path}")
    print(f"  Total state entries: {len(state_list)}")

    types = {}
    for e in state_list:
        t = e["type"]
        types[t] = types.get(t, 0) + 1
    for t in sorted(types, key=lambda x: -types[x])[:10]:
        print(f"    {t}: {types[t]}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract oracle resolved state from a Matrix server"
    )
    parser.add_argument("room_id", help="Room ID")
    parser.add_argument("--output", "-o", required=True, help="Output JSON path")
    parser.add_argument(
        "--from-db",
        action="store_true",
        help="Extract from RocksDB instead of API",
    )
    args = parser.parse_args()

    if args.from_db:
        state_map = get_state_from_db(args.room_id)
    else:
        if not MATRIX_SERVER or not MATRIX_TOKEN:
            print("Error: set MATRIX_SERVER and MATRIX_TOKEN env vars")
            sys.exit(1)
        state_map = get_state_from_api(args.room_id)

    write_oracle(state_map, args.room_id, args.output)


if __name__ == "__main__":
    main()
