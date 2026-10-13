#!/usr/bin/env python3
"""Append one successful benchmark run to a durable CSV history."""

from __future__ import annotations

import argparse
import csv
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from compare_bench import extract


FIELDS = ("timestamp_utc", "revision", "branch", "metric", "milliseconds")


def git_value(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", required=True, help="captured benchmark output")
    parser.add_argument(
        "--out", default="benches/bench-results.csv", help="CSV history path"
    )
    args = parser.parse_args()

    metrics = extract(args.current)
    if not metrics:
        parser.error("no benchmark metrics parsed; refusing to append an empty run")

    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    revision = git_value("rev-parse", "--short", "HEAD")
    branch = git_value("branch", "--show-current") or "detached"
    output = Path(args.out)
    needs_header = not output.exists() or output.stat().st_size == 0

    with output.open("a", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        if needs_header:
            writer.writeheader()
        for metric, milliseconds in sorted(metrics.items()):
            writer.writerow(
                {
                    "timestamp_utc": timestamp,
                    "revision": revision,
                    "branch": branch,
                    "metric": metric,
                    "milliseconds": f"{milliseconds:.9f}",
                }
            )

    print(f"appended {len(metrics)} benchmark metrics to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
