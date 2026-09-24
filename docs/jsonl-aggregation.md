# Raw JSONL and aggregates

Keep downloaded or otherwise unmerged event files in `unmerged/`. Treat them as
immutable evidence. `rezzy aggregate` creates one derived, sorted event set in
`merged/` for a room. The room slug selects the raw filename family and the
aggregate filename is its identity; no manifest or
sidecar file is created.

For one room:

```sh
cargo run --release --bin rezzy -- aggregate \
  --input-dir unmerged \
  --room c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk \
  --output-dir merged
```

This writes:

```text
merged/merged-c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk.jsonl
```

The command discovers matching `.jsonl` inputs, deduplicates by `event_id`,
retains identical duplicates only once, rejects conflicting payloads, and sorts
the result by `depth`, `origin_server_ts`, and `event_id`. It never modifies
`unmerged/`.

Use `--output` instead of `--output-dir` for an unusual destination. The output
is excluded from input discovery, but the input and output directories must be
different. This prevents an old aggregate from being discovered as another
matching input after the output name changes.

The room slug must identify one filename family. Matching inputs must either all
be unversioned or all contain the same delimiter-bounded `-v<number>` token.
If the slug mixes versioned and unversioned names, or multiple versions, include
the version in `--room` or use a more specific slug.

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
raw inputs. It does not provide input provenance; a different raw input set
that produces identical aggregate bytes is considered current. Output files
are written through a temporary file, synced, and atomically renamed. The
parent-directory sync is attempted where supported by the platform and its
failure is ignored because the aggregate is regenerable. Temporary `.tmp-*`
files may remain after a process crash and are safe to remove after confirming
that no aggregation process is running.

The existing multi-`--input` resolution path also rejects conflicting duplicate
event payloads.
