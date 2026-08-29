#!/usr/bin/env python3
"""Compare resolved state across three homeservers using rezzy.

Fetches room state from dev/nightly/unredacted servers and measures each
server's state resolution accuracy against a merged set of resolved state
events. Note: the `/state` endpoint returns Client-Server API state events,
which strip `auth_events`/`prev_events` — this is not a full canonical DAG.
"""

import json
import os
import subprocess
import sys

import requests

# Get configuration from environment
ROOM_ID = os.environ.get("MATRIX_ROOM_ID_TARGET", "!4zKUu8M4fstFjTFZ9E:nutra.tk")
TOKEN_DEV = os.environ.get("MATRIX_TOKEN", "").strip('"')
TOKEN_NIGHTLY = os.environ.get("MATRIX_TOKEN_NIGHTLY", "").strip('"')
TOKEN_UNREDACTED = os.environ.get("MATRIX_TOKEN_UNREDACTED", "").strip('"')

SERVERS = {
    "dev": "https://matrix.nutra.tk",
    "nightly": "https://mdev.nutra.tk",
    "unredacted": "https://matrix.unredacted.org",
}


def fetch_state(server_url, room_id, token):
    """Fetch the current resolved state for a room from a homeserver."""
    print(f"Fetching state from {server_url}...")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        res = requests.get(
            f"{server_url}/_matrix/client/v3/rooms/{room_id}/state",
            headers=headers,
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
        print(f"Error from {server_url}: {res.status_code} {res.text}")
    except requests.RequestException as e:
        print(f"Failed to connect to {server_url}: {e}")
    return None


def run_ruma_lean(file_path):
    """Run rezzy on a state file and return the parsed summary."""
    cmd = [
        "cargo",
        "run",
        "--release",
        "--features",
        "cli",
        "--",
        "-i",
        file_path,
        "--format",
        "default",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode == 0:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"Failed to parse JSON output from rezzy for {file_path}")
            return None
    print(f"Error running rezzy on {file_path}: {result.stderr}")
    return None


def main():
    """Drive the three-way fork accuracy analysis."""
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    if not TOKEN_DEV or not TOKEN_NIGHTLY or not TOKEN_UNREDACTED:
        print(
            "Error: Required environment variables (MATRIX_TOKEN, "
            "MATRIX_TOKEN_NIGHTLY, and MATRIX_TOKEN_UNREDACTED) are not set."
        )
        sys.exit(1)

    tokens = {
        "dev": TOKEN_DEV,
        "nightly": TOKEN_NIGHTLY,
        "unredacted": TOKEN_UNREDACTED,
    }

    states = {}
    for name, url in SERVERS.items():
        state = fetch_state(url, ROOM_ID, tokens[name])
        if state:
            file_path = f"res/state_{name}.json"
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(state, f)
            states[name] = file_path

    if len(states) < 2:
        print("Error: Could not fetch state from at least two servers.")
        return

    results = {}
    for name, path in states.items():
        print(f"Processing {name} state with rezzy...")
        results[name] = run_ruma_lean(path)

    if not all(results.values()):
        return

    print("\n" + "=" * 50)
    print("      MATRIX 3-WAY FORK ACCURACY ANALYSIS")
    print("=" * 50)

    # Calculate unified canonical state
    print("\nMerging all DAGs to find the mathematically canonical state...")
    unified_map = {}
    for name, path in states.items():
        with open(path, "r", encoding="utf-8") as f:
            events = json.load(f)
            for ev in events:
                unified_map[ev["event_id"]] = ev

    unified_path = "res/state_unified_3way.json"
    with open(unified_path, "w", encoding="utf-8") as f:
        json.dump(list(unified_map.values()), f)

    canonical_res = run_ruma_lean(unified_path)
    if not canonical_res:
        return

    canonical_ids = set(canonical_res.get("state_event_ids", []))
    print(f"Canonical State Size: {len(canonical_ids)}")

    accuracies = {}
    for name, res in results.items():
        server_ids = set(res.get("state_event_ids", []))
        accuracy = len(server_ids & canonical_ids) / len(canonical_ids) * 100
        accuracies[name] = accuracy
        print(f"{name.capitalize()} State Size: {res.get('resolved_state_size')}")
        print(f"{name.capitalize()} Accuracy:   {accuracy:.2f}%")

    print("\n" + "-" * 50)
    winner = max(accuracies, key=accuracies.get)
    print(f"VERDICT: {winner.capitalize()} is the Global Canonical Leader.")
    print("-" * 50)

    # Check for the specific Forestpunk discrepancy
    # sukidusk6125:matrix.org
    target_user = "@sukidusk6125:matrix.org"
    print(f"\nTarget Analysis: {target_user}")
    for name, path in states.items():
        with open(path, "r", encoding="utf-8") as f:
            events = json.load(f)
            member_ev = next(
                (
                    ev
                    for ev in events
                    if ev.get("type") == "m.room.member"
                    and ev.get("state_key") == target_user
                ),
                None,
            )
            if member_ev:
                print(
                    f" - {name.capitalize()}: "
                    f"{member_ev['content'].get('membership')} "
                    f"(ID: {member_ev['event_id'][:12]}...)"
                )
            else:
                print(f" - {name.capitalize()}: MISSING")

    # Canonical view
    with open(unified_path, "r", encoding="utf-8") as f:
        all_events = json.load(f)
        canonical_event_id = next(
            (
                eid
                for eid in canonical_ids
                if any(
                    ev["event_id"] == eid
                    and ev.get("type") == "m.room.member"
                    and ev.get("state_key") == target_user
                    for ev in all_events
                )
            ),
            None,
        )
        if canonical_event_id:
            canon_ev = next(
                ev for ev in all_events if ev["event_id"] == canonical_event_id
            )
            print(
                f" - CANONICAL: {canon_ev['content'].get('membership')} "
                f"(ID: {canon_ev['event_id'][:12]}...)"
            )
        else:
            print(" - CANONICAL: MISSING")


if __name__ == "__main__":
    main()
