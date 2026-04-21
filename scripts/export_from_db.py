#!/usr/bin/env python3
"""Export real room DAGs from a conduwuit RocksDB database via ldb.

Reads pduid_pdu and eventid_outlierpdu column families directly,
extracts full PDU JSON including auth_events and prev_events.

Usage:
  python3 scripts/export_from_db.py '!OGEhHVWSdvArJzumhm:matrix.org' --limit 10000
  python3 scripts/export_from_db.py '!MdDkJvlsmftq3VQigM:nutra.tk' -o res/real_dag_nutra.json

Known Boss Battle rooms:
  !OGEhHVWSdvArJzumhm:matrix.org  — Matrix HQ
  !TwEgjBFdNHBaaFqzEt:matrix.org  — Element Web
"""

import argparse
import json
import os
import subprocess
import sys

DB_PATH = os.environ.get(
    "CONDUWUIT_DB",
    "/run/media/shane/shane4tb-ent/vps/vps16-dev/var/lib/conduwuit",
)
SECONDARY_PATH = "/tmp/conduwuit_secondary"
LDB_ENV = {"LD_LIBRARY_PATH": "/usr/local/lib", "PATH": os.environ.get("PATH", "")}


def ldb_scan(column_family, max_keys=None, from_hex=None):
    """Scan a column family using ldb, yielding (key_hex, value_hex) tuples."""
    cmd = [
        "ldb",
        f"--db={DB_PATH}",
        "--ignore_unknown_options",
        f"--secondary_path={SECONDARY_PATH}",
        "scan",
        f"--column_family={column_family}",
        "--hex",
    ]
    if max_keys:
        cmd.append(f"--max_keys={max_keys}")
    if from_hex:
        cmd.append(f"--from={from_hex}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=LDB_ENV,
    )

    for line in proc.stdout:
        line = line.decode("utf-8", errors="replace").strip()
        if " ==> " in line:
            parts = line.split(" ==> ", 1)
            yield parts[0].strip(), parts[1].strip()

    proc.wait()


def hex_to_bytes(hex_str):
    """Convert '0xABCD...' to bytes."""
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def hex_to_json(hex_str):
    """Convert hex-encoded JSON to a dict."""
    try:
        raw = hex_to_bytes(hex_str)
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


def export_room(room_id, max_events=10000, output_path=None):
    """Export events for a specific room from both pduid_pdu and outliers."""
    events = {}

    # Phase 1: Scan pduid_pdu (main timeline events)
    print(f"[1/3] Scanning pduid_pdu for room {room_id}...")
    scanned = 0
    matched = 0
    # We need to scan ALL keys since pduid keys are (short_room_id, count)
    # and we don't know the short_room_id mapping without querying roomid_shortroomid
    for key_hex, val_hex in ldb_scan("pduid_pdu"):
        scanned += 1
        pdu = hex_to_json(val_hex)
        if pdu and pdu.get("room_id") == room_id:
            eid = pdu.get("event_id", "")
            if eid and eid not in events:
                events[eid] = normalize_pdu(pdu, room_id)
                matched += 1
                if matched >= max_events:
                    break
        if scanned % 50000 == 0:
            print(f"  Scanned {scanned} PDUs, found {matched} matching events...")

    print(f"  → {matched} events from pduid_pdu (scanned {scanned} total)")

    # Phase 2: Scan eventid_outlierpdu (outlier/backfilled events)
    if matched < max_events:
        print(f"[2/3] Scanning eventid_outlierpdu for room {room_id}...")
        outlier_scanned = 0
        outlier_matched = 0
        for key_hex, val_hex in ldb_scan("eventid_outlierpdu"):
            outlier_scanned += 1
            pdu = hex_to_json(val_hex)
            if pdu and pdu.get("room_id") == room_id:
                eid = pdu.get("event_id", "")
                if eid and eid not in events:
                    events[eid] = normalize_pdu(pdu, room_id)
                    outlier_matched += 1
                    if matched + outlier_matched >= max_events:
                        break
            if outlier_scanned % 50000 == 0:
                print(
                    f"  Scanned {outlier_scanned} outliers, "
                    f"found {outlier_matched} matching..."
                )
        print(f"  → {outlier_matched} events from outliers (scanned {outlier_scanned})")
    else:
        print("[2/3] Already at limit, skipping outliers.")

    if not events:
        print(f"\n⚠ No events found for room {room_id}")
        print("  Check that the room_id is correct and your server is joined to it.")

        # List some rooms we can see
        print("\n  Rooms found in DB (first 10 unique):")
        seen_rooms = set()
        for _, val_hex in ldb_scan("pduid_pdu", max_keys=1000):
            pdu = hex_to_json(val_hex)
            if pdu:
                rid = pdu.get("room_id", "")
                if rid and rid not in seen_rooms:
                    seen_rooms.add(rid)
                    print(f"    {rid}")
                    if len(seen_rooms) >= 10:
                        break
        sys.exit(1)

    # Phase 3: Write output
    print(f"[3/3] Writing {len(events)} events...")
    event_list = sorted(events.values(), key=lambda e: e.get("origin_server_ts", 0))
    write_output(event_list, room_id, output_path)


def normalize_pdu(pdu, room_id):
    """Normalize a raw PDU to our fixture format."""
    auth = pdu.get("auth_events", [])
    prev = pdu.get("prev_events", [])

    # Handle old event format: [["$id", {"sha256": "..."}]] or [{"event_id": "..."}]
    if auth and isinstance(auth[0], list):
        auth = [a[0] for a in auth if a]
    elif auth and isinstance(auth[0], dict):
        auth = [a.get("event_id", "") for a in auth]

    if prev and isinstance(prev[0], list):
        prev = [p[0] for p in prev if p]
    elif prev and isinstance(prev[0], dict):
        prev = [p.get("event_id", "") for p in prev]

    return {
        "event_id": pdu.get("event_id", ""),
        "room_id": pdu.get("room_id", room_id),
        "sender": pdu.get("sender", ""),
        "type": pdu.get("type", ""),
        "content": pdu.get("content", {}),
        "state_key": pdu.get("state_key", ""),
        "origin_server_ts": pdu.get("origin_server_ts", 0),
        "prev_events": prev,
        "auth_events": auth,
        "depth": pdu.get("depth", 0),
        "power_level": 0,
    }


def write_output(events, room_id, output_path):
    """Write events to JSON fixture."""
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
            "unique_senders": len(set(e["sender"] for e in events if e["sender"])),
            "event_types": types,
            "heads": len(heads),
            "source": "conduwuit RocksDB via ldb",
        },
    }

    if output_path is None:
        safe = room_id.replace("!", "").replace(":", "_").replace(".", "-")
        output_path = f"res/real_dag_{safe}.json"

    with open(output_path, "w") as f:
        json.dump(output, f, separators=(",", ":"))

    size_kb = os.path.getsize(output_path) // 1024
    print(f"\n{'='*60}")
    print(f"Exported {len(events)} REAL events from {room_id}")
    print(f"{'='*60}")
    print(f"Events with auth_events: {has_auth}/{len(events)}")
    print(f"Events with prev_events: {has_prev}/{len(events)}")
    print(f"DAG heads: {len(heads)}")
    print(f"Unique senders: {output['metadata']['unique_senders']}")
    for t in sorted(types, key=lambda x: -types[x])[:10]:
        print(f"  {t}: {types[t]}")
    print(f"\nOutput: {output_path} ({size_kb}KB)")


def list_rooms(max_scan=5000):
    """List unique rooms found in the DB."""
    print(f"Scanning first {max_scan} PDUs for unique rooms...")
    rooms = {}
    for _, val_hex in ldb_scan("pduid_pdu", max_keys=max_scan):
        pdu = hex_to_json(val_hex)
        if pdu:
            rid = pdu.get("room_id", "")
            if rid:
                rooms[rid] = rooms.get(rid, 0) + 1

    print(f"\nFound {len(rooms)} unique rooms:")
    for rid, count in sorted(rooms.items(), key=lambda x: -x[1])[:30]:
        print(f"  {rid}: {count} events")


def main():
    parser = argparse.ArgumentParser(
        description="Export room DAG from conduwuit RocksDB"
    )
    parser.add_argument(
        "room_id",
        nargs="?",
        help="Room ID to export (e.g. !OGEhHVWSdvArJzumhm:matrix.org)",
    )
    parser.add_argument("--limit", type=int, default=10000, help="Max events")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--list-rooms", action="store_true", help="List rooms in DB")
    parser.add_argument("--db", help="Override DB path")
    args = parser.parse_args()

    if args.db:
        global DB_PATH
        DB_PATH = args.db

    if args.list_rooms:
        list_rooms()
        return

    if not args.room_id:
        parser.error("room_id required (or use --list-rooms)")

    export_room(args.room_id, max_events=args.limit, output_path=args.output)


if __name__ == "__main__":
    main()
