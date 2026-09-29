# Raw JSONL and aggregates

Keep downloaded or otherwise unmerged event files in `unmerged/`. Treat them as
immutable evidence. `rezzy aggregate` creates a derived, sorted event set in
`merged/` for a room, plus a per-room provenance sidecar. The room slug selects
the raw filename family and the aggregate filename is its identity.

The command discovers `.jsonl` inputs, deduplicates by `event_id`, retains
identical events only once, rejects conflicting payloads, and orders the result
by a causal (Kahn) topological sort: parents always precede children, and
concurrently-ready events are ordered by `origin_server_ts`, `depth`, then
`event_id`. It never modifies `unmerged/`.

The merged output keeps the full Matrix event envelope, including `signatures`
and `unsigned`. Non-envelope top-level fields — Rezzy ingestion markers such as
`__rejected`/`__soft_fail`, stream-order hints such as `__pducount`, and
genuinely unknown keys — are removed from the merged event and preserved in the
sidecar instead. Custom keys inside `content` are application-defined Matrix
content and are left untouched.

For each room, `merged-<room>.jsonl` is accompanied by
`merged-<room>.rezzy-meta.jsonl`. Its first line is a manifest (schema, room id,
room version, input file hashes); each following line is one event keyed by
`event_id` with one observation per source file/line. Observations retain the
source's `signatures`, `unsigned`, stripped top-level metadata, rejection and
soft-fail claims, and any normalized `stream_ordering` (from the
`__stream_ordering`, `__stream_order`, `__pdu_count`, or `__pducount` aliases).
When sources disagree, the record reports
`"metadata_status": "source_disagreement"`; no observation is discarded. Pass
`--no-provenance` to skip the sidecar.

Duplicate detection compares each versioned event's Matrix redacted canonical
form (the reference-hash input), so sources that differ only in `unsigned` or
`signatures` still merge as one event.

Diagnostics are written to stderr: input files with non-envelope metadata
produce `[info]` lines and conflicting payloads produce `[warn]` lines. Use
`--quiet` to suppress them without changing the JSON report.

## Finding missing events

Aggregation does not fetch missing events. To inspect references made by the
aggregate that are not present in it, run:

```sh
rezzy inspect gaps \
  --input merged/merged-room-v12.jsonl \
  --json > gaps.json
```

The JSON report contains:

- `missing_events`: the count of unique missing event IDs across both kinds;
- `prev_events`: the missing IDs needed to complete the timeline DAG;
- `auth_events`: the missing IDs needed to complete event authorization
  chains; and
- `references`: the present event IDs that refer to each missing ID, with
  `kind` set to `prev_events` or `auth_events`.

The flat default output is the deduplicated union of the missing IDs and is
intended for piping into `federation get-remote-dag --from-file -`. Missing
`prev_events` are fetched through DAG backfill; missing `auth_events` require
the event-authentication endpoint. `federation gap-fill` can perform both in
rounds when a valid federation signing key is configured. Fetched files must
be included in a later `aggregate` invocation; the original aggregate is not
mutated.

## Selecting inputs

There are three ways to choose what gets aggregated.

### One room by slug (`--room`)

```sh
cargo run --release -p rezzy-cli --bin rezzy -- aggregate \
  --input-dir unmerged \
  --room c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk \
  --output-dir merged
```

This matches every `.jsonl` file in `--input-dir` whose name contains the slug
as a delimiter-bounded substring, and writes:

```text
merged/merged-c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk.jsonl
```

The slug must identify one filename family. Matching inputs must either all
be unversioned or all contain the same delimiter-bounded `-v<number>` token.
If the slug mixes versioned and unversioned names, or multiple versions, include
the version in `--room` or use a more specific slug.

This mode returns the bare result object for the single room (see
[Report shape](#report-shape)).

### Explicit files (`-i`)

```sh
cargo run --release -p rezzy-cli --bin rezzy -- aggregate \
  -i unmerged/remote-room-v12.jsonl unmerged/local-room-v12.jsonl \
  --output-dir merged
```

Each file is grouped by the room slug derived from its filename (see
[Room slugs](#room-slugs)) and every group is aggregated independently. Every
explicit filename must yield a slug; an unversioned name aborts the whole run
before anything is processed. `-o` is only allowed when the inputs belong to a
single room.

### Every room in a directory (scan)

```sh
cargo run --release -p rezzy-cli --bin rezzy -- aggregate --input-dir unmerged
```

With neither `--room` nor `-i`, the command scans `--input-dir` and aggregates
each room it finds. Scan mode requires a `-v<number>` token in the filename;
files without one are skipped and listed in the report's `skipped` array
(even under `--quiet`), with a warning also printed to stderr unless
`--quiet` is given. One output file is written per room, named from the
derived slug.

## Room slugs

`--room` matches a delimiter-bounded substring and names the output from the
token exactly as given, so it also accepts unversioned files. Scan mode derives
the slug from the filename instead: it drops a leading `local-`/`remote-` and an
optional `dag-`, then truncates the name after the matching `-v<number>` token.
For example, all of these yield the slug `room-v12`:

```text
local-room-v12.jsonl
remote-room-v12.jsonl
remote-dag-room-v12-merged.jsonl
local-dag-room-v12.jsonl
```

Passing a derived slug to `--room` selects the same inputs and writes the same
output name.

## Report shape

`--room` returns the bare single-room result object. `-i` and scan mode always
return a report, even for one room:

```json
{
  "status": "written",
  "failed": 0,
  "skipped": [],
  "rooms": [
    { "room": "room-v12", "status": "written", "output": "merged/merged-room-v12.jsonl", "metadata_output": "merged/merged-room-v12.rezzy-meta.jsonl", "unique_events": 42, "input_files": 2, "duplicate_event_copies": 0 }
  ]
}
```

Per-room `status` is `written` after a successful write, `current` under
`--check`, or `error` with `code` and `error` fields when that room failed.
Unlike `--room`, a failing room does not discard the others: the report still
contains every successful room, `failed` counts the errors, the top-level
`status` becomes `partial`, and the process exits `1`. In `-i` mode `skipped` is
always empty, because unslugged explicit inputs abort instead of being skipped.

The per-room fields differ by status: `current` carries only `unique_events`;
`written` adds `output`, `metadata_output`, `input_files`, and
`duplicate_event_copies`; `error` carries `code` and `error` instead. A caller
scripting against `rooms[]` should branch on `status` rather than assuming a
fixed set of fields.

With `--check` and no failures, the top-level `status` is also `current`
rather than `written`, since nothing was written:

```json
{
  "status": "current",
  "failed": 0,
  "skipped": [],
  "rooms": [
    { "status": "current", "unique_events": 42, "room": "room-v12" }
  ]
}
```

## Checking

To check whether the named aggregate is current, regenerate the deterministic
bytes in memory and compare them without writing:

```sh
cargo run --release -p rezzy-cli --bin rezzy -- aggregate \
  --input-dir unmerged \
  --room c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk \
  --output-dir merged \
  --check
```

`--check` exits successfully only when the aggregate bytes (and, unless
`--no-provenance` is given, the provenance sidecar bytes) match the current raw
inputs; the top-level and per-room statuses are `current`, never `written`,
because nothing was written. A different raw input set that produces identical
aggregate and sidecar bytes is considered current.

## Output writing

Use `--output` instead of `--output-dir` for an unusual destination. The input
and output directories must be different. This prevents an old aggregate from
being discovered as another matching input after the output name changes.
Explicit `-i` inputs must not be the output itself or a direct child of the
output directory; deeper subdirectories are not scanned, so they cannot be
swept back in.

Output files are written through a temporary file, synced, and atomically
renamed. The parent-directory sync is attempted where supported by the platform
and its failure is ignored because the aggregate is regenerable. Temporary
`.tmp-*` files may remain after a process crash and are safe to remove after
confirming that no aggregation process is running.

The existing multi-`--input` resolution path also rejects conflicting duplicate
event payloads.

## Timeline ordering from the sidecar

`rezzy -f timeline` uses a causal (Kahn) sort by default: parents always
precede children, and simultaneously-eligible events are ordered by
`--tie-break` (default `origin_server_ts,matrix_depth,event_id`).

```sh
rezzy -i merged-room-v12.jsonl -f timeline \
  --timeline-order causal \
  --tie-break origin_server_ts,matrix_depth,event_id
```

`--timeline-order synapse` instead orders by
`matrix_depth, stream_ordering, event_id`, reading stream order from the
provenance sidecar. It auto-discovers `<input>.rezzy-meta.jsonl`, or accepts an
explicit `--metadata <path>`. The sidecar must match the input's room
id/version and each event's payload hash; events with missing or conflicting
stream order fall back to `matrix_depth, origin_server_ts, event_id` with one
summary warning.

`-f timeline-chronological` remains the stable timestamp-primary human view and
rejects `--timeline-order`, `--tie-break`, and `--metadata`.

## Shell completions

Generate a completion script for your shell:

```sh
rezzy completions bash   # or zsh, fish, elvish, powershell
```
