#!/usr/bin/env python3
"""Extract labeled wall-clock metrics from a `cargo bench` tee file and compare
them against the previous best within a configurable margin.

The benches in `benches/` use a custom harness (`std::time::Instant`) rather
than criterion, and print labeled millisecond metrics in a couple of shapes:

    label: <value> ms
    label: <value> ms/op

This script extracts those into `{label: milliseconds}`, compares each current
value against the previous best (`--best`, a JSON object), FAILS if any metric
regressed beyond `--margin` (default 10%), and writes the running best (the
fastest value seen for each label) to `--out`.

Exit code is 1 if any metric regressed beyond the margin, else 0. This is
intended to be driven from `.github/workflows/benches.yml` after teeing the
bench output to a file.

NOTE: wall-clock benchmarks on shared CI runners are noisy; if the 10% margin
proves flaky, widen `--margin` rather than deleting the regression gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

# `label: <number> ms` or `label: <number> ms/op`. Deliberately does NOT match
# the ratio lines ("=> foo is 1.23x faster than bar") or the parenthesized
# `label: (setup: ..., algo: ..., ...)` forms, so only the stable per-op/total
# ms metrics are tracked.
METRIC = re.compile(r"^(.+?):\s+([0-9]+(?:\.[0-9]+)?)\s*ms\b")
CHECKPOINT = re.compile(r"^\s*S=(\d+):\s*$")
BENCHMARK_SECTION = re.compile(r"^\s*\[[^]]+\]\s+BENCHMARK:")


def extract(path: str) -> dict[str, float]:
    """Parse the tee'd bench output into {label: milliseconds}."""
    metrics: dict[str, float] = {}
    checkpoint: str | None = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if BENCHMARK_SECTION.match(line):
                checkpoint = None
                continue
            checkpoint_match = CHECKPOINT.match(line)
            if checkpoint_match:
                checkpoint = checkpoint_match.group(1)
                continue
            m = METRIC.match(line)
            if not m:
                continue
            label = m.group(1).strip()
            if checkpoint is not None:
                label = f"S={checkpoint}: {label}"
            if label in metrics:
                raise ValueError(f"duplicate benchmark label: {label}")
            metrics[label] = float(m.group(2))
    return metrics


def main() -> int:
    """Compare current bench metrics against the best and write the running best."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--current", required=True, help="tee'd bench output")
    ap.add_argument("--best", required=True, help="previous best JSON (bench.json)")
    ap.add_argument("--out", required=True, help="path to write the running best JSON")
    ap.add_argument(
        "--margin", type=float, default=0.10, help="allowed regression fraction"
    )
    args = ap.parse_args()

    if not 0.0 < args.margin < 1.0:
        ap.error("--margin must be in (0, 1)")

    try:
        current = extract(args.current)
    except (OSError, ValueError) as exc:
        print(f"could not parse benchmark output: {exc}", file=sys.stderr)
        return 1
    if not current:
        print("no benchmark metrics parsed", file=sys.stderr)
        return 1
    try:
        with open(args.best, encoding="utf-8") as fh:
            best: dict[str, float] = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        best = {}

    violations: list[str] = []
    new_best = dict(best)
    for label, cur in sorted(current.items()):
        prev = best.get(label)
        if prev is not None and cur > prev * (1.0 + args.margin):
            violations.append(
                f"{label}: {cur:.4f}ms regressed >{args.margin * 100:.0f}% vs best {prev:.4f}ms"
            )
        if prev is None or cur < prev:
            new_best[label] = cur

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(new_best, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(
        f"parsed {len(current)} metrics, comparing against {len(best)} previous bests"
    )
    for label, val in sorted(current.items()):
        prev = best.get(label)
        suffix = "" if prev is None else f" (best {prev:.4f}ms)"
        print(f"  {label}: {val:.4f}ms{suffix}")

    if violations:
        print("\nREGRESSIONS (failing):")
        for v in violations:
            print(f"  FAIL {v}")
        return 1

    print("\nOK: all metrics within margin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
