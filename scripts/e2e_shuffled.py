#!/usr/bin/env python3
"""
E2E Test Runner for Ruma-Lean: Order Independence.
Verifies that the resolution output is identical regardless of input event order.
"""

import json
import os
import random
import subprocess
import sys
import tempfile


def run_ruma_lean(input_file):
    cmd = [
        "./target/release/ruma-lean",
        "--input",
        input_file,
        "--format",
        "federation",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: ruma-lean failed with exit code {e.returncode}")
        print(f"Stderr: {e.stderr}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse ruma-lean output as JSON: {e}")
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("Usage: e2e_shuffled.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]

    if not os.path.exists(input_file):
        print(f"Error: Input file {input_file} not found")
        sys.exit(1)

    with open(input_file, "r") as f:
        input_data = json.load(f)

    print(f"Running order independence test using {input_file}...")

    # 1. Run with original order
    output1 = run_ruma_lean(input_file)

    # 2. Run with shuffled order
    if isinstance(input_data, dict) and "events" in input_data:
        events = input_data["events"]
        random.shuffle(events)
        shuffled_data = {"events": events, "heads": input_data["heads"]}
    else:
        random.shuffle(input_data)
        shuffled_data = input_data

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(shuffled_data, tmp)
        tmp_name = tmp.name

    try:
        output2 = run_ruma_lean(tmp_name)
    finally:
        os.remove(tmp_name)

    if output1 == output2:
        print(f"✓ Order independence verified! Outputs are identical.")
        sys.exit(0)
    else:
        print(f"Error: Order independence failed! Outputs differ.")
        sys.exit(1)


if __name__ == "__main__":
    main()
