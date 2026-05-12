#!/usr/bin/env python3
"""Federated DAG comparison and ranking tool.

Usage:
    dagcmp.py <room-slug> [--prefix PREFIX] [--verbose] [--rank]
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ServerReport:
    server: str
    events: int = 0
    min_depth: int = 0
    max_depth: int = 0
    root: str = ""
    joined: int = 0
    left: int = 0
    banned: int = 0
    invited: int = 0
    missing: int = 0
    extra: int = 0
    missing_users: list = field(default_factory=list)
    extra_users: list = field(default_factory=list)
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


def run_ruma(files: list[str], version: str = "v2-1") -> dict | None:
    inputs = []
    for f in files:
        inputs.extend(["-i", f])
    cmd = ["ruma-lean", "-q"] + inputs + ["--state-res", version, "-f", "summary"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def load_event_ids(path: str) -> set[str]:
    """Load all event_ids from a JSONL file without running state res."""
    ids = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                eid = obj.get("event_id")
                if eid:
                    ids.add(eid)
            except json.JSONDecodeError:
                continue
    return ids


def get_members(summary: dict) -> set[str]:
    try:
        return {
            u["user_id"]
            for u in summary.get("membership", {}).get("join", {}).get("users", [])
        }
    except (KeyError, TypeError):
        return set()


def get_member_event_ids(summary: dict) -> dict[str, dict[str, str]]:
    """Map category -> {user_id: event_id} for all membership types."""
    result = {}
    for cat in ("join", "leave", "ban", "invite", "knock"):
        result[cat] = {}
        cat_data = summary.get("membership", {}).get(cat, {})
        for u in cat_data.get("users", []):
            result[cat][u["user_id"]] = u["event_id"]
    return result


def get_state_event_ids(summary: dict) -> set[str]:
    """Get active state event IDs (joined members + non-member state only)."""
    ids = set()
    # Non-member state entries
    for entry in summary.get("state", []):
        eid = entry.get("event_id")
        if eid:
            ids.add(eid)
    # Only joined members (not left/banned/etc)
    join_data = summary.get("membership", {}).get("join", {})
    for u in join_data.get("users", []):
        eid = u.get("event_id")
        if eid:
            ids.add(eid)
    return ids


def get_state_size(summary: dict) -> int:
    """Joined members + non-member state entries."""
    n_state = len(summary.get("state", []))
    n_join = summary.get("membership", {}).get("join", {}).get("count", 0)
    return n_state + n_join


def get_depth_stats(path: str) -> tuple[int, int, str]:
    """Get min_depth, max_depth, and root_event_id from a JSONL file."""
    min_d = float("inf")
    max_d = 0
    root_id = ""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                d = obj.get("depth", 0)
                if d < min_d:
                    min_d = d
                    root_id = obj.get("event_id", "")
                if d > max_d:
                    max_d = d
            except json.JSONDecodeError:
                continue
    return (int(min_d) if min_d != float("inf") else 0), max_d, root_id


def analyze(room: str, prefix: str, verbose: bool, rank: bool):
    pattern = f"{prefix}-{room}-*.jsonl"
    files = sorted(Path(".").glob(pattern))

    if not files:
        print(f"No files matching {pattern}", file=sys.stderr)
        sys.exit(1)

    file_strs = [str(f) for f in files]

    # Ground truth: merge all
    print(f"Merging {len(files)} server DAGs...", file=sys.stderr)
    gt = run_ruma(file_strs)
    if not gt:
        print("Failed to compute ground truth", file=sys.stderr)
        sys.exit(1)

    gt_members = get_members(gt)
    gt_member_eids = get_member_event_ids(gt)
    gt_n = len(gt_members)
    gt_left = len(gt_member_eids.get("leave", {}))
    gt_banned = len(gt_member_eids.get("ban", {}))
    gt_invited = len(gt_member_eids.get("invite", {}))
    gt_events = gt["total_events"]
    gt_min = gt["min_depth"]
    gt_max = gt["max_depth"]
    gt_root = gt["root_event_id"]

    print(
        f"ground truth: {gt_n} joined, {gt_left} left, {gt_banned} banned, "
        f"{gt_events} events, depth {gt_min}..{gt_max}, root {gt_root}\n"
    )

    # Group files by base domain (matrix.org-00, matrix.org-tip → matrix.org)
    import re
    from collections import defaultdict

    domain_files: dict[str, list[Path]] = defaultdict(list)
    for f in files:
        fname = f.name
        server = fname.replace(f"{prefix}-{room}-", "").replace(".jsonl", "")
        # Strip trailing -SUFFIX (digits, "tip", short tags) to get base domain
        base = re.sub(r"-(\d+|tip|[a-z]{1,4}\d*)$", "", server)
        domain_files[base].append(f)

    # Per-domain analysis
    reports: list[ServerReport] = []
    for domain, dfiles in sorted(domain_files.items()):
        # Merge event IDs across all files for this domain
        srv_eids: set[str] = set()
        min_d = float("inf")
        max_d = 0
        root_id = ""
        for f in dfiles:
            for eid in load_event_ids(str(f)):
                srv_eids.add(eid)
            f_min, f_max, f_root = get_depth_stats(str(f))
            if f_min < min_d:
                min_d = f_min
                root_id = f_root
            if f_max > max_d:
                max_d = f_max

        r = ServerReport(server=domain)
        r.events = len(srv_eids)
        r.min_depth = int(min_d) if min_d != float("inf") else 0
        r.max_depth = max_d
        r.root = root_id

        # Coverage per membership category
        def count_coverage(cat_eids: dict[str, str]) -> int:
            return sum(1 for eid in cat_eids.values() if eid in srv_eids)

        r.joined = count_coverage(gt_member_eids.get("join", {}))
        r.left = count_coverage(gt_member_eids.get("leave", {}))
        r.banned = count_coverage(gt_member_eids.get("ban", {}))
        r.invited = count_coverage(gt_member_eids.get("invite", {}))

        # Missing/extra for joined members
        srv_missing_users = [
            uid
            for uid, eid in gt_member_eids.get("join", {}).items()
            if eid not in srv_eids
        ]

        # Extra: members resolved as joined from this domain's events that GT doesn't have
        srv_summary = run_ruma([str(f) for f in dfiles])
        srv_own_members = get_members(srv_summary) if srv_summary else set()
        extra_users = sorted(srv_own_members - gt_members)

        r.missing = len(srv_missing_users)
        r.extra = len(extra_users)
        r.missing_users = sorted(srv_missing_users)
        r.extra_users = extra_users

        tp = r.joined
        r.precision = tp / (tp + r.extra) if (tp + r.extra) > 0 else 0
        r.recall = tp / gt_n if gt_n > 0 else 0
        r.f1 = (
            2 * r.precision * r.recall / (r.precision + r.recall)
            if (r.precision + r.recall) > 0
            else 0
        )

        reports.append(r)

    if rank:
        reports.sort(key=lambda r: r.f1, reverse=True)

    # Header
    if rank:
        cols = (
            f"{'#':<3} {'SERVER':<26} {'JOINED':>6} {'LEFT':>5} {'BAN':>4} "
            f"{'EVENTS':>6} {'PREC':>6} {'RECALL':>6} {'F1':>6} "
            f"{'DIFF':>10} {'DEPTH':<14} ROOT"
        )
    else:
        cols = (
            f"{'SERVER':<26} {'JOINED':>6} {'LEFT':>5} {'BAN':>4} "
            f"{'EVENTS':>6} {'DEPTH':<14} {'DIFF':>10} ROOT"
        )
    print(cols)
    print("-" * len(cols))

    for i, r in enumerate(reports, 1):
        diff = f"-{r.missing}/+{r.extra}" if (r.missing or r.extra) else "✓"
        depth = f"{r.min_depth}..{r.max_depth}"

        if rank:
            print(
                f"{i:<3} {r.server:<26} {r.joined:>6} {r.left:>5} {r.banned:>4} "
                f"{r.events:>6} {r.precision:>5.1%} {r.recall:>5.1%} "
                f"{r.f1:>5.1%} {diff:>10} {depth:<14} {r.root}"
            )
        else:
            print(
                f"{r.server:<26} {r.joined:>6} {r.left:>5} {r.banned:>4} "
                f"{r.events:>6} {depth:<14} {diff:>10} {r.root}"
            )

        if verbose and (r.missing_users or r.extra_users):
            if r.missing_users:
                print("  missing:")
                for u in r.missing_users:
                    print(f"    - {u}")
            if r.extra_users:
                print("  extra:")
                for u in r.extra_users:
                    print(f"    + {u}")


def main():
    parser = argparse.ArgumentParser(description="Federated DAG comparison tool")
    parser.add_argument("room", help="Room slug (e.g. c10y-...-v12)")
    parser.add_argument(
        "--prefix",
        default="remote-dag",
        help="JSONL file prefix (default: remote-dag)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show per-user diffs"
    )
    parser.add_argument("-r", "--rank", action="store_true", help="Rank by F1 score")
    args = parser.parse_args()

    analyze(args.room, args.prefix, args.verbose, args.rank)


if __name__ == "__main__":
    main()
