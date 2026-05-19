#!/usr/bin/env python3
"""Federated DAG comparison and ranking tool.

Usage:
    dagcmp.py <room-slug> [--prefix PREFIX] [--verbose] [--rank] [--chain]
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ServerReport:
    server: str
    events: int = 0
    min_depth: int = 0
    max_depth: int = 0
    root: str = ""

    # Final state-res user outcomes (State Fidelity)
    res_joined: int = 0
    res_left: int = 0
    res_banned: int = 0

    bf: float = 0.0  # branching factor (avg prev_events per event)

    missing: int = 0
    extra: int = 0
    missing_users: list[str] = field(default_factory=list)
    extra_users: list[str] = field(default_factory=list)

    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


def run_ruma(files: list[str], version: str = "v2-1") -> dict | None:
    inputs = []
    for f in files:
        inputs.extend(["-i", f])
    cmd = [
        "ruma-lean",
        "-q",
        *inputs,
        "--state-res",
        version,
        "-f",
        "summary",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def load_event_ids(path: str) -> set[str]:
    """Load all event_ids from a JSONL file."""
    ids = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if eid := obj.get("event_id"):
                    ids.add(eid)
            except json.JSONDecodeError:
                continue
    return ids


def get_depth_stats(path: str) -> tuple[int, int, str, float]:
    """Get min_depth, max_depth, root_event_id, and branching factor."""
    min_d = float("inf")
    max_d = 0
    root_id = ""
    total_prev = 0
    n_events = 0
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
                prev = obj.get("prev_events", [])
                total_prev += len(prev) if isinstance(prev, list) else 0
                n_events += 1
            except json.JSONDecodeError:
                continue
    bf = total_prev / n_events if n_events > 0 else 0.0
    return (
        (int(min_d) if min_d != float("inf") else 0),
        max_d,
        root_id,
        bf,
    )


def get_members(summary: dict, category: str = "join") -> set[str]:
    """Extract users belonging to a membership category."""
    try:
        return {
            u["user_id"]
            for u in summary.get("membership", {}).get(category, {}).get("users", [])
        }
    except (KeyError, TypeError):
        return set()


def get_member_event_ids(
    summary: dict,
) -> dict[str, dict[str, str]]:
    """Map category -> {user_id: event_id}."""
    result = {}
    for cat in ("join", "leave", "ban", "invite", "knock"):
        result[cat] = {}
        cat_data = summary.get("membership", {}).get(cat, {})
        for u in cat_data.get("users", []):
            result[cat][u["user_id"]] = u["event_id"]
    return result


def analyze(
    room: str,
    prefix: str,
    verbose: bool,
    rank: bool,
    chain_analysis: bool,
):
    pattern = f"{prefix}-{room}-*.jsonl"
    files = sorted(Path(".").glob(pattern))

    if not files:
        print(f"No files matching {pattern}", file=sys.stderr)
        sys.exit(1)

    # Group files by base domain
    # Domains don't contain dashes after TLD, so iteratively strip
    # user-added suffixes like -d, -22807, -base99, -tip, etc.
    domain_files: dict[str, list[Path]] = defaultdict(list)
    for f in files:
        fname = f.name
        server = fname.replace(f"{prefix}-{room}-", "").replace(".jsonl", "")
        base = server
        prev = None
        while base != prev:
            prev = base
            base = re.sub(r"-(\d+|tip|[a-z]{1,4}\d*)$", "", base)
        domain_files[base].append(f)

    # Ground truth: merge all
    file_strs = [str(f) for f in files]
    print(
        f"Merging {len(files)} server DAGs...",
        file=sys.stderr,
    )
    gt = run_ruma(file_strs)
    if not gt:
        print(
            "Failed to compute ground truth",
            file=sys.stderr,
        )
        sys.exit(1)

    gt_members = get_members(gt, "join")
    gt_member_eids = get_member_event_ids(gt)
    gt_n = len(gt_members)
    gt_left = len(gt_member_eids.get("leave", {}))
    gt_banned = len(gt_member_eids.get("ban", {}))

    gt_events = gt.get("total_events", 0)
    gt_min = gt.get("min_depth", 0)
    gt_max = gt.get("max_depth", 0)
    gt_root = gt.get("root_event_id", "")

    print(
        f"ground truth: {gt_n} joined, {gt_left} left, "
        f"{gt_banned} banned, {gt_events} events, "
        f"depth {gt_min}..{gt_max}, root {gt_root}\n"
    )

    reports: list[ServerReport] = []
    domain_eids: dict[str, set[str]] = {}

    for domain, dfiles in sorted(domain_files.items()):
        srv_eids: set[str] = set()
        min_d = float("inf")
        max_d = 0
        root_id = ""
        total_prev = 0
        n_events = 0
        for f in dfiles:
            srv_eids |= load_event_ids(str(f))
            f_min, f_max, f_root, f_bf = get_depth_stats(str(f))
            if f_min < min_d:
                min_d = f_min
                root_id = f_root
            if f_max > max_d:
                max_d = f_max
            # Accumulate for BF
            n_f = len(load_event_ids(str(f)))
            total_prev += int(f_bf * n_f)
            n_events += n_f

        domain_eids[domain] = srv_eids

        r = ServerReport(server=domain)
        r.events = len(srv_eids)
        r.min_depth = int(min_d) if min_d != float("inf") else 0
        r.max_depth = max_d
        r.root = root_id
        r.bf = total_prev / n_events if n_events > 0 else 0.0

        # State-res on this domain's files alone
        srv_summary = run_ruma([str(f) for f in dfiles])

        if srv_summary is None:
            r.res_joined = -1
            r.res_left = -1
            r.res_banned = -1
            srv_own_members = set()
        else:
            srv_own_members = get_members(srv_summary, "join")
            r.res_joined = len(srv_own_members)
            r.res_left = len(get_members(srv_summary, "leave"))
            r.res_banned = len(get_members(srv_summary, "ban"))

        r.missing_users = sorted(gt_members - srv_own_members)
        r.extra_users = sorted(srv_own_members - gt_members)
        r.missing = len(r.missing_users)
        r.extra = len(r.extra_users)

        # F1 from resolved User IDs (apples to apples)
        tp = len(gt_members & srv_own_members)
        r.precision = tp / len(srv_own_members) if srv_own_members else 0
        r.recall = tp / gt_n if gt_n > 0 else 0
        r.f1 = (
            2 * r.precision * r.recall / (r.precision + r.recall)
            if (r.precision + r.recall) > 0
            else 0
        )

        reports.append(r)

    # Assign join order based on min_depth (lowest = first to join)
    by_depth = sorted(reports, key=lambda r: (r.min_depth if r.min_depth > 0 else float('inf')))
    join_order: dict[str, int] = {}
    for idx, r in enumerate(by_depth, 1):
        join_order[r.server] = idx

    if rank:
        reports.sort(key=lambda r: r.f1, reverse=True)

    # Display
    if rank:
        cols = (
            f"{'#':<3} {'SERVER':<26} {'ORD':>3} {'JOINED':>6} "
            f"{'LEFT':>5} {'BAN':>4} "
            f"{'EVENTS':>6} {'BF':>5} {'PREC':>6} {'RECALL':>6} "
            f"{'F1':>6} "
            f"{'DIFF':>10} {'DEPTH':<14} ROOT"
        )
    else:
        cols = (
            f"{'SERVER':<26} {'ORD':>3} {'JOINED':>6} "
            f"{'LEFT':>5} {'BAN':>4} "
            f"{'EVENTS':>6} {'BF':>5} {'DEPTH':<14} "
            f"{'DIFF':>10} ROOT"
        )
    print(cols)
    print("-" * len(cols))

    for i, r in enumerate(reports, 1):
        depth_range = r.max_depth - r.min_depth + 1
        if depth_range > 0 and r.events / depth_range < 0.5:
            depth = f"{r.min_depth}.?.{r.max_depth}"
        else:
            depth = f"{r.min_depth}..{r.max_depth}"

        bf_str = f"{r.bf:.3f}"

        if r.res_joined == -1:
            j_str, l_str, b_str = "ERR", "ERR", "ERR"
            prec_str, rec_str, f1_str = "  ERR", "  ERR", "  ERR"
            diff = "ERR"
        else:
            j_str = str(r.res_joined)
            l_str = str(r.res_left)
            b_str = str(r.res_banned)
            prec_str = f"{r.precision:>5.1%}"
            rec_str = f"{r.recall:>5.1%}"
            f1_str = f"{r.f1:>5.1%}"
            diff = f"-{r.missing}/+{r.extra}" if (r.missing or r.extra) else "✓"

        ord_num = join_order.get(r.server, 0)

        if rank:
            print(
                f"{i:<3} {r.server:<26} "
                f"{ord_num:>3} {j_str:>6} {l_str:>5} "
                f"{b_str:>4} "
                f"{r.events:>6} {bf_str:>5} {prec_str:>6} "
                f"{rec_str:>6} "
                f"{f1_str:>6} {diff:>10} "
                f"{depth:<14} {r.root}"
            )
        else:
            print(
                f"{r.server:<26} {ord_num:>3} {j_str:>6} "
                f"{l_str:>5} {b_str:>4} "
                f"{r.events:>6} {bf_str:>5} {depth:<14} "
                f"{diff:>10} {r.root}"
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

    # --- Greedy Chain Analysis ---
    if not chain_analysis:
        return

    print("\nChain Analysis:")
    hdr = (
        f"{'SERVER':<26} {'JOINED':>6} "
        f"{'LEFT':>5} {'BAN':>4} "
        f"{'CHAIN':>5} {'REFS':>4} PARTNERS"
    )
    print(hdr)
    print("-" * 80)

    # Target ALL state events (join+leave+ban+invite)
    target_eids: set[str] = set()
    for cat in ("join", "leave", "ban", "invite"):
        target_eids.update(gt_member_eids.get(cat, {}).values())

    chain_results = []

    for start in sorted(domain_files.keys()):
        current_chain = [start]
        covered = domain_eids[start] & target_eids
        uncovered = target_eids - covered

        while uncovered:
            best = None
            best_added: set[str] = set()

            for candidate, c_eids in domain_eids.items():
                if candidate in current_chain:
                    continue
                added = uncovered & c_eids
                if len(added) > len(best_added):
                    best = candidate
                    best_added = added

            if not best:
                break

            current_chain.append(best)
            covered |= best_added
            uncovered -= best_added

        # State-res on the chain
        chain_files = []
        for d in current_chain:
            chain_files.extend(str(f) for f in domain_files[d])

        summary = run_ruma(chain_files)
        if not summary:
            continue

        c_joined = len(get_members(summary, "join"))
        c_left = len(get_members(summary, "leave"))
        c_ban = len(get_members(summary, "ban"))

        partners = "+".join(current_chain[1:]) if len(current_chain) > 1 else "(solo)"
        chain_results.append(
            {
                "server": start,
                "joined": c_joined,
                "left": c_left,
                "ban": c_ban,
                "chain_len": len(current_chain),
                "partners": current_chain[1:],
            }
        )

    # Count how many chains reference each server
    ref_counts: dict[str, int] = defaultdict(int)
    for cr in chain_results:
        for p in cr["partners"]:
            ref_counts[p] += 1

    # Print with REFS column
    for cr in chain_results:
        refs = ref_counts.get(cr["server"], 0)
        partners = "+".join(cr["partners"]) if cr["partners"] else "(solo)"
        print(
            f"{cr['server']:<26} {cr['joined']:>6} "
            f"{cr['left']:>5} {cr['ban']:>4} "
            f"{cr['chain_len']:>5} {refs:>4} "
            f"{partners}"
        )

    # Summary: strongest links
    if ref_counts:
        top = sorted(
            ref_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        n = len(chain_results)
        print("\n    strongest links:")
        max_srv = max(len(srv) for srv, _ in top[:5])
        for srv, count in top[:5]:
            print(f"      {srv + ':':<{max_srv + 1}} {count:>2}/{n} chains")


def main():
    parser = argparse.ArgumentParser(description="Federated DAG comparison tool")
    parser.add_argument("room", help="Room slug (e.g. c10y-...-v12)")
    parser.add_argument(
        "--prefix",
        default="remote-dag",
        help="JSONL file prefix (default: remote-dag)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show per-user diffs",
    )
    parser.add_argument(
        "-r",
        "--rank",
        action="store_true",
        help="Rank by F1 score",
    )
    parser.add_argument(
        "-c",
        "--chain",
        action="store_true",
        help="Greedy chain analysis",
    )
    args = parser.parse_args()

    analyze(
        args.room,
        args.prefix,
        args.verbose,
        args.rank,
        args.chain,
    )


if __name__ == "__main__":
    main()
