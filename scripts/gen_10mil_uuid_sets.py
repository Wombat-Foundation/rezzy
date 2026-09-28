#!/usr/bin/env python3
"""Generate two files of 10 million shared UUIDs plus 500 unique to each file."""

import time
import uuid

print("Opening files A.txt and B.txt...")
start = time.time()
with (
    open("A.txt", "w", encoding="utf-8") as fa,
    open("B.txt", "w", encoding="utf-8") as fb,
):
    print("Step 1/3: Generating 10,000,000 shared UUIDs (in both A and B)...")
    for i in range(10_000_000):
        u = str(uuid.uuid4())
        fa.write(u + "\n")
        fb.write(u + "\n")
        if i % 2_500_000 == 0 and i > 0:
            print(f"  ... {i} done")

    print("Step 2/3: Generating 500 UUIDs exclusively for A...")
    for _ in range(500):
        fa.write(str(uuid.uuid4()) + "\n")

    print("Step 3/3: Generating 500 UUIDs exclusively for B...")
    for _ in range(500):
        fb.write(str(uuid.uuid4()) + "\n")

end = time.time()
print(
    f"\nSuccess! 10,001,000 total unique UUIDs generated in {end - start:.2f} seconds."
)
print(" - A.txt contains 10,000,500 UUIDs")
print(" - B.txt contains 10,000,500 UUIDs")
