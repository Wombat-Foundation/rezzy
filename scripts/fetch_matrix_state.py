"""
Fetches raw Matrix DAG state resolution arrays dynamically from live Server instances via HTTP.
"""

import json
import os
import sys

import requests

# You can easily change this to a room ID you are in that has a huge history
ROOM_ID = os.environ.get("MATRIX_ROOM_ID", "").strip()
HOMESERVER = os.environ.get("MATRIX_HOMESERVER", "").strip()
ACCESS_TOKEN = os.environ.get("MATRIX_TOKEN", "").strip()

if not ACCESS_TOKEN or not HOMESERVER or not ROOM_ID:
    print(
        "Error: Please set the MATRIX_TOKEN, MATRIX_HOMESERVER, and MATRIX_ROOM_ID environment variables.",
        file=sys.stderr,
    )
    sys.exit(1)

headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}

print(f"Fetching room state for {ROOM_ID}...", file=sys.stderr)
print(
    f"Waiting for homeserver to compile JSON (this can take minutes for large spaces!)...",
    file=sys.stderr,
    flush=True,
)
state_res = requests.get(
    f"{HOMESERVER}/_matrix/client/v3/rooms/{ROOM_ID}/state",
    headers=headers,
    stream=True,
    timeout=300,  # Large rooms can take forever to timeout
)

if state_res.status_code != 200:
    print(f"Failed to fetch state: {state_res.text}", file=sys.stderr)
    sys.exit(1)

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
            print(f"\rDownloaded {mb:.2f} MB...", end="", file=sys.stderr, flush=True)

print("\nParsing massive JSON payload into RAM...", file=sys.stderr)
raw_bytes = b"".join(chunks)
state_events = json.loads(raw_bytes.decode("utf-8"))

with open("res/real_matrix_state.json", "w", encoding="utf-8") as f:
    f.write(raw_bytes.decode("utf-8"))

event_count = (
    len(state_events)
    if isinstance(state_events, list)
    else len(state_events.get("pdu_ids", []))
)

print(
    f"\nSuccess! Saved payload containing {event_count} state events",
    file=sys.stderr,
)
