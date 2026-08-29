"""
Fetches raw Matrix DAG state resolution arrays dynamically from live Server instances via HTTP.

NOTE: The default endpoint (`/_matrix/client/v3/rooms/{ROOM_ID}/state`) returns
Client-Server API state events. These events STRIP out the `auth_events` and
`prev_events` properties which are required to compute an auth chain for full
joins (yielding an `auth_chain_size` of 0 in `rezzy` testing).

To fetch full PDUs (which include these fields), use the `--full-pdus` flag.
This flag requires a Server Admin token and uses the Synapse Admin API.
"""

import argparse
import concurrent.futures
import json
import os
import sys

import requests


def fetch_event(event_id, homeserver, headers):
    """Fetch a single full PDU via the Synapse Admin API, or None on failure."""
    try:
        res = requests.get(
            f"{homeserver}/_synapse/admin/v1/events/{event_id}",
            headers=headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
    except (requests.RequestException, ValueError):
        return None
    return None


def fetch_and_save_room(room_id, output_path, homeserver, headers, full_pdus):
    """Fetch room state from the homeserver and write it to output_path."""
    # pylint: disable=too-many-locals,too-many-statements
    print(f"\nFetching room state for {room_id}...", file=sys.stderr)
    try:
        state_res = requests.get(
            f"{homeserver}/_matrix/client/v3/rooms/{room_id}/state",
            headers=headers,
            stream=True,
            timeout=300,
        )
    except requests.RequestException as e:
        print(f"Failed to fetch state for {room_id}: {e}", file=sys.stderr)
        return

    if state_res.status_code != 200:
        print(
            f"Failed to fetch state for {room_id}: {state_res.text}",
            file=sys.stderr,
        )
        return

    total_size = int(state_res.headers.get("content-length", 0))
    downloaded = 0
    chunks = []

    print("Streaming state payload from Homeserver...", file=sys.stderr, flush=True)
    try:
        for chunk in state_res.iter_content(chunk_size=1024 * 1024):
            if chunk:
                chunks.append(chunk)
                downloaded += len(chunk)
                mb = downloaded / (1024 * 1024)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    print(
                        f"\rDownloaded {mb:.2f} MB ({percent:.1f}%)...",
                        end="",
                        file=sys.stderr,
                        flush=True,
                    )
                else:
                    print(
                        f"\rDownloaded {mb:.2f} MB...",
                        end="",
                        file=sys.stderr,
                        flush=True,
                    )
    except requests.RequestException as e:
        print(f"Stream interrupted for {room_id}: {e}", file=sys.stderr)
        return

    print("\nParsing JSON payload...", file=sys.stderr)
    raw_bytes = b"".join(chunks)
    state_events = json.loads(raw_bytes.decode("utf-8"))

    if full_pdus:
        print(
            "Fetching full PDUs via Synapse Admin API (this may take a while)...",
            file=sys.stderr,
        )
        full_events = []
        event_ids = [ev.get("event_id") for ev in state_events if "event_id" in ev]

        completed = 0
        total = len(event_ids)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(fetch_event, eid, homeserver, headers): eid
                for eid in event_ids
            }
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    full_events.append(res)
                completed += 1
                if completed % 100 == 0 or completed == total:
                    print(
                        f"\rFetched {completed}/{total} PDUs...",
                        end="",
                        file=sys.stderr,
                        flush=True,
                    )

        print("\nFinished fetching PDUs.", file=sys.stderr)
        state_events = full_events

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(state_events, f, separators=(",", ":"))

    print(
        f"\nSuccess! Saved {len(state_events)} events to {output_path}",
        file=sys.stderr,
    )


def main():
    """Fetch Matrix room state from a live homeserver for rezzy testing."""
    parser = argparse.ArgumentParser(description="Fetch Matrix room state for testing.")
    parser.add_argument(
        "--full-pdus",
        action="store_true",
        help="Fetch full PDUs via Synapse Admin API to include auth_events and "
        "prev_events (requires Admin token, can be slow).",
    )
    args = parser.parse_args()

    room_id = os.environ.get("MATRIX_ROOM_ID", "").strip()
    room_id_v2_1 = os.environ.get("MATRIX_ROOM_ID_V2_1", "").strip()
    homeserver = os.environ.get("MATRIX_HOMESERVER", "").strip()
    access_token = os.environ.get("MATRIX_TOKEN", "").strip()

    if not access_token or not homeserver:
        print(
            "Error: Please set MATRIX_TOKEN and MATRIX_HOMESERVER environment variables.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not room_id and not room_id_v2_1:
        print(
            "Error: Please set at least one of MATRIX_ROOM_ID or MATRIX_ROOM_ID_V2_1.",
            file=sys.stderr,
        )
        sys.exit(1)

    headers = {"Authorization": f"Bearer {access_token}"}

    if room_id:
        fetch_and_save_room(
            room_id, "res/real_matrix_state.json", homeserver, headers, args.full_pdus
        )
    if room_id_v2_1:
        fetch_and_save_room(
            room_id_v2_1,
            "res/real_matrix_state_v2_1.json",
            homeserver,
            headers,
            args.full_pdus,
        )


if __name__ == "__main__":
    main()
