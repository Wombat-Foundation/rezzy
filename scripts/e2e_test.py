#!/usr/bin/env python3
"""
E2E Test Runner for Ruma-Lean.
Verifies that the resolution output is consistent and follows Matrix protocol rules.
"""

import json
import os
import subprocess
import sys


def run_ruma_lean(input_file, hs_name):
    print(f"Running E2E test for homeserver: {hs_name} using {input_file}")

    cmd = [
        "./target/release/ruma-lean",
        "--input",
        input_file,
        "--format",
        "federation",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: ruma-lean failed with exit code {e.returncode}")
        print(f"Stderr: {e.stderr}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse ruma-lean output as JSON: {e}")
        sys.exit(1)


def verify_resolution(output, input_data, hs_name):
    print(f"Verifying resolution for {hs_name}...")

    if "state" not in output or "auth_chain" not in output:
        print("Error: Output missing 'state' or 'auth_chain' keys")
        return False

    state = output["state"]
    auth_chain = output["auth_chain"]

    # 1. Verify uniqueness of (type, state_key) in state
    seen_keys = set()
    for ev in state:
        key = (ev.get("type"), ev.get("state_key", ""))
        if key in seen_keys:
            print(f"Error: Duplicate state key found in resolved state: {key}")
            return False
        seen_keys.add(key)

    # 2. Verify all events in output were in input
    if isinstance(input_data, dict) and "events" in input_data:
        input_events = input_data["events"]
    else:
        input_events = input_data

    input_event_ids = {ev["event_id"] for ev in input_events}

    for ev in state:
        if ev["event_id"] not in input_event_ids:
            print(f"Error: Event {ev['event_id']} in state was not in input data")
            return False

    for ev in auth_chain:
        if ev["event_id"] not in input_event_ids:
            print(f"Error: Event {ev['event_id']} in auth_chain was not in input data")
            return False

    print(f"✓ Resolution for {hs_name} verified successfully!")
    print(f"  Resolved state size: {len(state)}")
    print(f"  Auth chain size: {len(auth_chain)}")
    return True


def main():
    if len(sys.argv) < 3:
        print("Usage: e2e_test.py <input_file> <hs_name>")
        sys.exit(1)

    input_file = sys.argv[1]
    hs_name = sys.argv[2]

    if not os.path.exists(input_file):
        print(f"Error: Input file {input_file} not found")
        sys.exit(1)

    with open(input_file, "r") as f:
        input_data = json.load(f)

    output = run_ruma_lean(input_file, hs_name)

    if verify_resolution(output, input_data, hs_name):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
