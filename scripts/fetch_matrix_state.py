"""
Fetches raw Matrix DAG state resolution arrays dynamically from live Server instances via HTTP.

NOTE: The default endpoint (`/_matrix/client/v3/rooms/{ROOM_ID}/state`) returns
Client-Server API state events. These events STRIP out the `auth_events` and
`prev_events` properties which are required to compute an auth chain for full
joins (yielding an `auth_chain_size` of 0 in `ruma-lean` testing).

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
    try:
        res = requests.get(
            f"{homeserver}/_synapse/admin/v1/events/{event_id}",
            headers=headers,
            timeout=10,
        )
        if res.status_code == 200:
            return res.json()
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="Fetch Matrix room state for testing.")
    parser.add_argument(
        "--full-pdus",
        action="store_true",
        help="Fetch full PDUs via Synapse Admin API to include auth_events and prev_events (requires Admin token, can be slow).",
    )
    args = parser.parse_args()

    ROOM_ID = os.environ.get("MATRIX_ROOM_ID", "").strip()
    ROOM_ID_V2_1 = os.environ.get("MATRIX_ROOM_ID_V2_1", "").strip()
    HOMESERVER = os.environ.get("MATRIX_HOMESERVER", "").strip()
    ACCESS_TOKEN = os.environ.get("MATRIX_TOKEN", "").strip()

    if not ACCESS_TOKEN or not HOMESERVER:
        print(
            "Error: Please set MATRIX_TOKEN and MATRIX_HOMESERVER environment variables.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not ROOM_ID and not ROOM_ID_V2_1:
        print(
            "Error: Please set at least one of MATRIX_ROOM_ID or MATRIX_ROOM_ID_V2_1.",
            file=sys.stderr,
        )
        sys.exit(1)

    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}

    def fetch_and_save_room(room_id, output_path):
        print(f"\nFetching room state for {room_id}...", file=sys.stderr)
        state_res = requests.get(
            f"{HOMESERVER}/_matrix/client/v3/rooms/{room_id}/state",
            headers=headers,
            stream=True,
            timeout=300,
        )

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

        print("\nParsing JSON payload...", file=sys.stderr)
        raw_bytes = b"".join(chunks)
        state_events = json.loads(raw_bytes.decode("utf-8"))

        if args.full_pdus:
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
                    executor.submit(fetch_event, eid, HOMESERVER, headers): eid
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

    if ROOM_ID:
        fetch_and_save_room(ROOM_ID, "res/real_matrix_state.json")
    if ROOM_ID_V2_1:
        fetch_and_save_room(ROOM_ID_V2_1, "res/real_matrix_state_v2_1.json")


if __name__ == "__main__":
    main()
