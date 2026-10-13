#!/usr/bin/env python3
"""Extract labeled wall-clock metrics from a `cargo bench` tee file and compare
them against the previous best. Regressions above the warning margin are
reported as yellow warnings; regressions at or above the failure margin fail.

The benches in `benches/` use a custom harness (`std::time::Instant`) rather
than criterion, and print labeled millisecond metrics in a couple of shapes:

    label: <value> ms
    label: <value> ms/op

This script extracts those into `{label: milliseconds}`, compares each current
value against the previous best (`--best`, a JSON object), FAILS if any metric
regressed by at least `--failure-margin` (default 70%), warns above
`--warning-margin` (default 10%), and writes the running best (the fastest
value seen for each label) to `--out`.

When the runner prints benchmark section headers, they are included in each
metric key so equal operation names from separate benchmarks do not collide.

Exit code is 1 if any metric regressed by at least the failure margin, else 0. This is
intended to be driven from `.github/workflows/benches.yml` after teeing the
bench output to a file.

NOTE: wall-clock benchmarks on shared CI runners are noisy. Yellow warnings
surface smaller changes while the 70% red threshold catches severe regressions.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

# `label: <number> ms` or `label: <number> ms/op` or `label: <number> ns/op`.
# Deliberately does NOT match the ratio lines ("=> foo is 1.23x faster than
# bar") or the parenthesized `label: (setup: ..., algo: ..., ...)` forms,
# so only the stable per-op/total metrics are tracked.
METRIC = re.compile(
    r"^(.+?):\s+([0-9]+(?:\.[0-9]+)?)\s*(ns|ms)(?:/op)?(?:\s*\([^)]*\))?\s*$"
)
CHECKPOINT = re.compile(r"^\s*S=(\d+):\s*$")
BENCHMARK_SECTION = re.compile(r"^\s*\[([^]]+)\]\s+BENCHMARK:\s*(.+?)\s*$")


def extract(path: str) -> dict[str, float]:
    """Parse the tee'd bench output into {label: milliseconds}."""
    metrics: dict[str, float] = {}
    checkpoint: str | None = None
    benchmark: str | None = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            section_match = BENCHMARK_SECTION.match(line)
            if section_match:
                benchmark = f"{section_match.group(1)}/{section_match.group(2)}"
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
            if benchmark is not None:
                label = f"{benchmark}: {label}"
            if checkpoint is not None:
                label = f"S={checkpoint}: {label}"
            if label in metrics:
                raise ValueError(f"duplicate benchmark label: {label}")
            value = float(m.group(2))
            unit = m.group(3)
            # Normalise nanoseconds to milliseconds for consistent comparison.
            if unit == "ns":
                value /= 1_000_000.0
            metrics[label] = value
    return metrics


def parse_args() -> argparse.Namespace:
    """Parse the benchmark comparison command line."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--current", required=True, help="tee'd bench output")
    ap.add_argument("--best", required=True, help="previous best JSON (bench.json)")
    ap.add_argument("--out", required=True, help="path to write the running best JSON")
    ap.add_argument(
        "--warning-margin",
        "--margin",
        dest="warning_margin",
        type=float,
        default=0.10,
        help="warn above this regression fraction (default 10%%)",
    )
    ap.add_argument(
        "--failure-margin",
        type=float,
        default=0.70,
        help="fail at or above this regression fraction (default 70%%)",
    )
    args = ap.parse_args()
    if not 0.0 < args.warning_margin < args.failure_margin:
        ap.error("margins must satisfy 0 < warning-margin < failure-margin")
    return args


def load_best(path: str) -> dict[str, float]:
    """Load prior best metrics, treating missing or invalid JSON as empty."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def legacy_label_counts(current: dict[str, float]) -> dict[str, int]:
    """Count suffixes for safe migration of pre-section metric labels."""
    counts: dict[str, int] = {}
    for label in current:
        suffix = label.rsplit(": ", 1)[-1]
        counts[suffix] = counts.get(suffix, 0) + 1
    return counts


def previous_best(
    label: str, best: dict[str, float], suffix_counts: dict[str, int]
) -> float | None:
    """Find the baseline, migrating a bare legacy label only when unambiguous."""
    if label in best:
        return best[label]
    suffix = label.rsplit(": ", 1)[-1]
    return best.get(suffix) if suffix_counts.get(suffix) == 1 else None


def compare_metrics(
    current: dict[str, float],
    best: dict[str, float],
    warning_margin: float,
    failure_margin: float,
) -> tuple[dict[str, float], list[str], list[str]]:
    """Update best values and classify regressions as warnings or failures."""
    suffix_counts = legacy_label_counts(current)
    new_best = dict(best)
    warnings: list[str] = []
    failures: list[str] = []
    for label, value in sorted(current.items()):
        prior = previous_best(label, best, suffix_counts)
        if prior is None:
            new_best[label] = value
            continue
        increase = (
            value / prior - 1.0 if prior > 0 else (float("inf") if value > 0 else 0.0)
        )
        message = (
            f"{label}: {value:.4f}ms is {increase * 100:.1f}% above best {prior:.4f}ms"
        )
        if increase >= failure_margin:
            failures.append(message)
        elif increase > warning_margin:
            warnings.append(message)
        if value < prior:
            new_best[label] = value
    return new_best, warnings, failures


def write_best(path: str, metrics: dict[str, float]) -> None:
    """Write the updated best metrics as formatted JSON."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2, sort_keys=True)
        fh.write("\n")


def report_results(
    current: dict[str, float],
    best: dict[str, float],
    warnings: list[str],
    failures: list[str],
) -> None:
    """Print the metrics and GitHub warning/error annotations."""
    suffix_counts = legacy_label_counts(current)
    print(
        f"parsed {len(current)} metrics, comparing against {len(best)} previous bests"
    )
    for label, value in sorted(current.items()):
        prior = previous_best(label, best, suffix_counts)
        suffix = "" if prior is None else f" (best {prior:.4f}ms)"
        print(f"  {label}: {value:.4f}ms{suffix}")
    if warnings:
        print("\nYELLOW WARNINGS (not failing):")
        for warning in warnings:
            print(f"  WARN {warning}")
            print(f"::warning title=Benchmark regression::{warning}")
    if failures:
        print("\nRED REGRESSIONS (failing):")
        for failure in failures:
            print(f"  FAIL {failure}")
            print(f"::error title=Benchmark regression::{failure}")


def main() -> int:
    """Compare current benchmarks with the baseline and report regressions."""
    args = parse_args()
    try:
        current = extract(args.current)
    except (OSError, ValueError) as exc:
        print(f"could not parse benchmark output: {exc}", file=sys.stderr)
        return 1
    if not current:
        print("no benchmark metrics parsed", file=sys.stderr)
        return 1
    best = load_best(args.best)
    new_best, warnings, failures = compare_metrics(
        current, best, args.warning_margin, args.failure_margin
    )
    write_best(args.out, new_best)
    report_results(current, best, warnings, failures)
    if failures:
        return 1

    print("\nOK: no red regressions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
