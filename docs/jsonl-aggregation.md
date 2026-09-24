# Raw JSONL and aggregates

Keep downloaded or otherwise unmerged event files in `unmerged/`. Treat them as
immutable evidence. `rezzy aggregate` creates a derived, sorted event set in
`merged/` and records the exact input files and hashes in a manifest.

For one room:

```sh
cargo run --release --bin rezzy -- aggregate \
  --input-dir unmerged \
  --room c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk \
  --output merged/merged-c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk.jsonl \
  --manifest merged/merged-c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk.manifest.json
```

The command deduplicates by `event_id`, retains identical duplicates only once,
and sorts the result by `depth`, `origin_server_ts`, and `event_id`. Input
files are processed in lexical order, so `--allow-conflicts` retains the first
copy from that order when payloads differ. It never modifies `unmerged/`. The v3
manifest records logical non-empty JSONL records, not the trailing empty split
created by a final newline.

If the same `event_id` appears with different payloads, aggregation fails
instead of selecting one arbitrarily. Use `--allow-conflicts` to retain the
first copy intentionally; the choice is recorded in the manifest. Identical
duplicate copies are retained only once and counted separately from conflicting
copies in the manifest.

Output and manifest files are written through temporary files, synced, and
renamed separately. A crash between those two renames can leave a detectable
mismatch; `--check` reports it as stale so the pair can be regenerated.

After new raw files arrive, rerun the same command to update the aggregate. To
check whether it needs updating without writing anything:

```sh
cargo run --release --bin rezzy -- aggregate \
  --input-dir unmerged \
  --room c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk \
  --output merged/merged-c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk.jsonl \
  --manifest merged/merged-c10y-fNiMx5ijtgGFibzPUfNs9hpQvnJYPTV-fD2KPk.manifest.json \
  --check
```

`--check` exits successfully only when both the aggregate bytes and manifest
match the current raw inputs. The existing multi-`--input` resolution path is
unchanged; use the aggregate command when you want a persisted artifact.
