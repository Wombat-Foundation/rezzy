#!/usr/bin/env python3
"""Extract labeled wall-clock metrics from a `cargo bench` tee file and compare
them against the previous best. Regressions use three tiers:

    10–50%  blue notice
    50–85%  yellow warning
    85%+    red failure (fails the job)

The benches in `benches/` use a custom harness (`std::time::Instant`) rather
than criterion, and print labeled millisecond metrics in a couple of shapes:

    label: <value> ms
    label: <value> ms/op

This script extracts those into `{label: milliseconds}`, compares each current
value against the previous best (`--best`, a JSON object), FAILS if any metric
regressed by at least `--failure-margin` (default 85%), warns above
`--warning-margin` (default 50%), notices above `--notice-margin` (default 10%),
and writes the running best (the fastest value seen for each label) to `--out`.

Regressions whose absolute delta is below `--min-absolute-delta` (default
0.05ms) are ignored entirely. Shared-CI jitter on single-digit-microsecond
microbenches can exceed 85% relative while being a few microseconds of absolute
noise; the floor keeps those from permanently failing the job while still
ratcheting a new best when one is set.

When the runner prints benchmark section headers, they are included in each
metric key so equal operation names from separate benchmarks do not collide.

Exit code is 1 if any metric regressed by at least the failure margin, else 0. This is
intended to be driven from `.github/workflows/benches.yml` after teeing the
bench output to a file.

NOTE: wall-clock benchmarks on shared CI runners are noisy. Blue notices
surface small drift, yellow warnings flag moderate regressions, and the 85%
red threshold catches severe regressions only.
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
        "--notice-margin",
        type=float,
        default=0.10,
        help="blue notice above this regression fraction (default 10%%)",
    )
    ap.add_argument(
        "--warning-margin",
        "--margin",
        dest="warning_margin",
        type=float,
        default=0.50,
        help="yellow warn above this regression fraction (default 50%%)",
    )
    ap.add_argument(
        "--failure-margin",
        type=float,
        default=0.85,
        help="fail at or above this regression fraction (default 85%%)",
    )
    ap.add_argument(
        "--min-absolute-delta",
        type=float,
        default=0.05,
        help="ignore regressions whose absolute delta is below this many "
        "milliseconds (default 0.05ms = 50us)",
    )
    args = ap.parse_args()
    if not 0.0 < args.notice_margin < args.warning_margin < args.failure_margin:
        ap.error(
            "margins must satisfy 0 < notice-margin < warning-margin < failure-margin"
        )
    if args.min_absolute_delta < 0.0:
        ap.error("min-absolute-delta must be >= 0")
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
    notice_margin: float,
    warning_margin: float,
    failure_margin: float,
    min_absolute_delta: float,
) -> tuple[dict[str, float], list[str], list[str], list[str]]:
    """Update best values and classify regressions as notices, warnings, or failures."""
    suffix_counts = legacy_label_counts(current)
    new_best = dict(best)
    notices: list[str] = []
    warnings: list[str] = []
    failures: list[str] = []
    for label, value in sorted(current.items()):
        prior = previous_best(label, best, suffix_counts)
        if prior is None:
            new_best[label] = value
            continue
        if value < prior:
            new_best[label] = value
            continue
        delta = value - prior
        # Sub-floor deltas are pure runner jitter on microbenches: skip
        # classification entirely (the new-best ratchet above already ran).
        if delta < min_absolute_delta:
            continue
        increase = (
            value / prior - 1.0 if prior > 0 else (float("inf") if value > 0 else 0.0)
        )
        message = (
            f"{label}: {value:.4f}ms is {increase * 100:.1f}% above best "
            f"{prior:.4f}ms (+{delta:.4f}ms)"
        )
        if increase >= failure_margin:
            failures.append(message)
        elif increase >= warning_margin:
            warnings.append(message)
        elif increase > notice_margin:
            notices.append(message)
    return new_best, notices, warnings, failures


def write_best(path: str, metrics: dict[str, float]) -> None:
    """Write the updated best metrics as formatted JSON."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2, sort_keys=True)
        fh.write("\n")


def report_results(
    current: dict[str, float],
    best: dict[str, float],
    notices: list[str],
    warnings: list[str],
    failures: list[str],
) -> None:
    """Print the metrics and GitHub notice/warning/error annotations."""
    suffix_counts = legacy_label_counts(current)
    print(
        f"parsed {len(current)} metrics, comparing against {len(best)} previous bests"
    )
    for label, value in sorted(current.items()):
        prior = previous_best(label, best, suffix_counts)
        suffix = "" if prior is None else f" (best {prior:.4f}ms)"
        print(f"  {label}: {value:.4f}ms{suffix}")
    if notices:
        print("\nBLUE NOTICES (10–50%):")
        for notice in notices:
            print(f"  NOTICE {notice}")
            print(f"::notice title=Benchmark regression::{notice}")
    if warnings:
        print("\nYELLOW WARNINGS (50–85%, not failing):")
        for warning in warnings:
            print(f"  WARN {warning}")
            print(f"::warning title=Benchmark regression::{warning}")
    if failures:
        print("\nRED REGRESSIONS (85%+, failing):")
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
    new_best, notices, warnings, failures = compare_metrics(
        current,
        best,
        args.notice_margin,
        args.warning_margin,
        args.failure_margin,
        args.min_absolute_delta,
    )
    write_best(args.out, new_best)
    report_results(current, best, notices, warnings, failures)
    if failures:
        return 1

    print("\nOK: no red regressions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
