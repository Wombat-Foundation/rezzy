# Raw JSONL and aggregates

Keep downloaded or otherwise unmerged event files in `unmerged/`. Treat them as
immutable evidence. `rezzy aggregate` creates one derived, sorted event set in
`merged/` for a room. The room slug selects the raw filename family and the
aggregate filename is its identity; no manifest or
sidecar file is created.

The command discovers `.jsonl` inputs, deduplicates by `event_id`, retains
identical duplicates only once, rejects conflicting payloads, and sorts the
result by `depth`, `origin_server_ts`, and `event_id`. It never modifies
`unmerged/`.

## Selecting inputs

There are three ways to choose what gets aggregated.

### One room by slug (`--room`)

```sh
cargo run --release --bin rezzy -- aggregate \
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
cargo run --release --bin rezzy -- aggregate \
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
cargo run --release --bin rezzy -- aggregate --input-dir unmerged
```

With neither `--room` nor `-i`, the command scans `--input-dir` and aggregates
each room it finds. Scan mode requires a `-v<number>` token in the filename;
files without one are skipped with a warning on stderr and listed in the
report's `skipped` array (even under `--quiet`). One output file is written per
room, named from the derived slug.

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
    { "room": "room-v12", "status": "written", "output": "merged/merged-room-v12.jsonl", "unique_events": 42, "input_files": 2, "duplicate_event_copies": 0 }
  ]
}
```

Per-room `status` is `written` after a successful write, `current` under
`--check`, or `error` with `code` and `error` fields when that room failed.
Unlike `--room`, a failing room does not discard the others: the report still
contains every successful room, `failed` counts the errors, the top-level
`status` becomes `partial`, and the process exits `1`. In `-i` mode `skipped` is
always empty, because unslugged explicit inputs abort instead of being skipped.

## Checking

To check whether the named aggregate is current, regenerate the deterministic
bytes in memory and compare them without writing:

```sh
cargo run --release --bin rezzy -- aggregate \
  --input-dir unmerged \
  --room c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk \
  --output-dir merged \
  --check
```

`--check` exits successfully only when the aggregate bytes match the current
raw inputs; the top-level and per-room statuses are `current`, never `written`,
because nothing was written. It does not provide input provenance; a different
raw input set that produces identical aggregate bytes is considered current.

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

## Shell completions

Generate a completion script for your shell:

```sh
rezzy completions bash   # or zsh, fish, elvish, powershell
```
