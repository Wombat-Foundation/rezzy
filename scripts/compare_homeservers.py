import json
import os
import subprocess
import sys

import requests

# Get configuration from environment
ROOM_ID = os.environ.get("MATRIX_ROOM_ID_TARGET", "!4zKUu8M4fstFjTFZ9E:nutra.tk")
TOKEN_DEV = os.environ.get("MATRIX_TOKEN", "").strip('"')
TOKEN_NIGHTLY = os.environ.get("MATRIX_TOKEN_NIGHTLY", "").strip('"')

SERVERS = {"dev": "https://matrix.nutra.tk", "nightly": "https://mdev.nutra.tk"}


def fetch_state(server_url, room_id, token):
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
        else:
            print(f"Error from {server_url}: {res.status_code} {res.text}")
    except Exception as e:
        print(f"Failed to connect to {server_url}: {e}")
    return None


def run_ruma_lean(file_path):
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
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        try:
            return json.loads(result.stdout)
        except:
            print(f"Failed to parse JSON output from ruma-lean for {file_path}")
            return None
    else:
        print(f"Error running ruma-lean on {file_path}: {result.stderr}")
        return None


def main():
    if not TOKEN_DEV or not TOKEN_NIGHTLY:
        print(
            "Error: Required environment variables (MATRIX_TOKEN and MATRIX_TOKEN_NIGHTLY) are not set."
        )
        sys.exit(1)

    tokens = {"dev": TOKEN_DEV, "nightly": TOKEN_NIGHTLY}

    states = {}
    for name, url in SERVERS.items():
        state = fetch_state(url, ROOM_ID, tokens[name])
        if state:
            file_path = f"res/state_{name}.json"
            with open(file_path, "w") as f:
                json.dump(state, f)
            states[name] = file_path

    if len(states) < 2:
        print("Error: Could not fetch state from both servers.")
        return

    results = {}
    for name, path in states.items():
        print(f"Processing {name} state with ruma-lean...")
        results[name] = run_ruma_lean(path)

    if not all(results.values()):
        return

    print("\n" + "=" * 40)
    print("      MATRIX FORK ACCURACY ANALYSIS")
    print("=" * 40)
    dev_res = results["dev"]
    nightly_res = results["nightly"]

    print(f"Dev (nutra.tk) State Size: {dev_res.get('resolved_state_size')}")
    print(
        f"Nightly (mdev.nutra.tk) State Size: {nightly_res.get('resolved_state_size')}"
    )

    dev_ids = set(dev_res.get("state_event_ids", []))
    nightly_ids = set(nightly_res.get("state_event_ids", []))

    only_dev = dev_ids - nightly_ids
    only_nightly = nightly_ids - dev_ids

    if not only_dev and not only_nightly:
        print("\n[RESULT] Perfect Consensus: Both servers agree exactly.")
    else:
        print(f"\n[DISCREPANCY] Fork detected!")
        print(f" - Events only in Dev: {len(only_dev)}")
        print(f" - Events only in Nightly: {len(only_nightly)}")

        print("\nMerging both DAGs to find the mathematically canonical state...")

        with open(states["dev"], "r") as f:
            dev_events = json.load(f)
        with open(states["nightly"], "r") as f:
            nightly_events = json.load(f)

        unified_map = {ev["event_id"]: ev for ev in dev_events}
        for ev in nightly_events:
            unified_map[ev["event_id"]] = ev

        unified_path = "res/state_unified.json"
        with open(unified_path, "w") as f:
            json.dump(list(unified_map.values()), f)

        canonical_res = run_ruma_lean(unified_path)
        if canonical_res:
            canonical_ids = set(canonical_res.get("state_event_ids", []))
            print(f"Canonical State Size: {len(canonical_ids)}")

            dev_accuracy = len(dev_ids & canonical_ids) / len(canonical_ids) * 100
            nightly_accuracy = (
                len(nightly_ids & canonical_ids) / len(canonical_ids) * 100
            )

            print(f"Dev Accuracy: {dev_accuracy:.2f}%")
            print(f"Nightly Accuracy: {nightly_accuracy:.2f}%")

            print("\n" + "-" * 40)
            if dev_accuracy > nightly_accuracy:
                print("VERDICT: Dev (nutra.tk) is the Canonical Leader.")
            elif nightly_accuracy > dev_accuracy:
                print("VERDICT: Nightly (mdev.nutra.tk) is the Canonical Leader.")
            else:
                print(
                    "VERDICT: Tie. Both servers have diverged equally from the truth."
                )
            print("-" * 40)


if __name__ == "__main__":
    main()
