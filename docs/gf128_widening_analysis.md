# GF(2^64) → GF(2^128) widening: cost and security analysis

Status: analysis only. Nothing here is implemented; `rezzy-recon` runs the
MSC4521 GF(2^64) profile today. This records what widening the reconciliation
field to 128 bits would cost in time, memory, and disk, and exactly which
security property it would (and would not) buy.

Baseline figures come from `.tmp/reconcile_bench_results.md` (snapshot of
`cargo bench --bench reconcile`, commit `68af901`, 2026-08-23; `.tmp/` is
gitignored, so treat it as an uncommitted local record and re-run
`cargo bench --bench reconcile` before relying on any of it). Derived figures
come from the work-unit cost model pinned in
`rezzy-recon/src/pinsketch.rs:495-565` and its tests
(`rezzy-recon/src/pinsketch.rs:817-896`); those are exact arithmetic, not
measurements. Time-per-unit multipliers are estimates and are labeled as such.

## Scope and assumptions

"Widening" means: the reconciled element key becomes 128 bits (SHA-256 digest
bytes 0..16) instead of 64, syndromes are computed in GF(2^128) instead of
GF(2^64), and every coordinate/root/key field in `rezzy-recon` grows from 8 to
16 bytes. The 128-bit integrity residual already exists and stays as-is (it
becomes digest bytes 16..32, the other half of the digest).

Unless stated otherwise, all capacities, strata counts, round limits, and
bucketing parameters are assumed **unchanged**. Keeping the wire budget fixed
and halving capacity instead is a different trade (same bytes, half the
correctable delta per sketch) and is not analyzed here.

## Baseline: where GF(2^64) lives

A field element is a bare Rust `u64`. There is no newtype, no `Gf64` wrapper,
and no field-element type alias; the width is implicit in the type
(`type Polynomial = Vec<u64>` at `rezzy-recon/src/pinsketch.rs:14` is the only
alias, and it aliases `u64`).

| Concern                                              | Location                               | Field-typed data                                          |
| ---------------------------------------------------- | -------------------------------------- | --------------------------------------------------------- |
| Field multiply, reduction `x^64 + x^4 + x^3 + x + 1` | `rezzy-recon/src/gf64.rs:9-98`         | `u64 × u64 → u64`                                         |
| SIMD polynomial MAC (Scalar/SSE/AVX-512)             | `rezzy-recon/src/gf64_simd.rs:19-192`  | `poly_mac(term: u64, source: &[u64], target: &mut [u64])` |
| Element key                                          | `rezzy-recon/src/algebraic.rs:133-143` | `ElementHash { h128: u128, h64: u64 }`                    |
| Sketch syndromes                                     | `rezzy-recon/src/algebraic.rs:429-431` | `SyndromeSketch { coordinates: Vec<u64> }`                |
| Resident per-room state                              | `rezzy-recon/src/resident.rs:37`       | `strata: [[u64; 8]; 32]`                                  |
| Per-round peer digest                                | `rezzy-recon/src/client.rs:102-108`    | `RemoteDigest { strata: [[u64; 8]; 32], .. }`             |
| Sorted population columns                            | `rezzy-recon/src/server.rs:338-341`    | `h64: Vec<u64>`, `h128: Vec<u128>`                        |
| Decoder (BM, Frobenius root finding)                 | `rezzy-recon/src/pinsketch.rs`         | throughout; `FIELD_BITS: usize = 64` at `:16`             |

Key constants that any widening must revisit:

- `STRATA_COUNT = 32`, `STRATUM_CAPACITY = 8`
  (`rezzy-recon/src/resident.rs:14-16`)
- `MAX_SKETCH_CAPACITY = 32`, `MAX_OVERFLOW_SKETCH_CAPACITY = 256`
  (`rezzy-recon/src/algebraic.rs:47-59`)
- `MAX_BUCKET_SKETCH_CAPACITY = 32`, `MAX_BUCKETED_SKETCH_CAPACITY = 4096`
  (`rezzy-recon/src/triage.rs:14-16`, asserted at `rezzy-recon/src/lib.rs:80`)
- `MAX_BUCKETS_PER_ROUND = 128`, `MAX_RECONCILIATION_ROUNDS = 20`
  (`rezzy-recon/src/client.rs:43-45`)
- `MAX_FACTOR_WORK = 16_000_000` (`rezzy-recon/src/pinsketch.rs:46`)

## Time

### Per-multiply

| Backend                                       | Today                                                          | GF(2^128) | Basis                                                                                                                                                                     |
| --------------------------------------------- | -------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Portable (`mul_bitwise`)                      | 64 shift/xor iterations                                        | ~2×       | loop trip count doubles exactly (`gf64.rs:14-25`); `u128` shifts cost more on targets without native 128-bit shifts                                                       |
| PCLMULQDQ (scalar)                            | 1 `clmul` + fold + 4-iteration overflow loop (`gf64.rs:71-98`) | ~1.5-2.5× | 256-bit product needs 4 `clmul`s (3 with Karatsuba) plus 2-3 reduction `clmul`s                                                                                           |
| AVX-512 `vpclmulqdq` (`gf64_simd.rs:140-165`) | 4-way 64-bit products                                          | ~1.5-2×   | two `vpclmulqdq` for a 256-bit product + 1-2 for reduction; `vpclmulqdq`'s 128-bit lanes are natural for GF(2^128), so the SIMD path amortizes better than the scalar one |

Measured anchor: `gf64 multiply: 0.000005 ms/op` (5 ns, 1,000,000 iterations) in
`.tmp/reconcile_bench_results.md`. Expected GF(2^128) range: **10-15 ns**. This
multiplier is an instruction-count estimate, not a measurement.

### Encode paths (multiply-bound, ×~2)

Encode is `1 + capacity` field multiplies per element per sketch (`toggle`,
`rezzy-recon/src/algebraic.rs:486-497`) plus a coordinate XOR that doubles in
width.

| Benchmark                | Today       | GF(2^128) est. |
| ------------------------ | ----------- | -------------- |
| `algebraic/toggle/32x32` | 0.007497 ms | ~15 µs         |
| `resident insert/10000`  | 0.620924 ms | ~1.3 ms        |
| `extract/N=10M Δ≈4096`   | 0.970029 ms | ~2 ms          |

### Decode paths (×~4-5)

Decode is dominated by root finding, whose per-node cost model is
(`rezzy-recon/src/pinsketch.rs:495-530`):

```text
frobenius_basis_cost(d)        = (FIELD_BITS - 1) * d^2
factor_trial_cost_with_basis(d) = FIELD_BITS * d + d^2
split_cost(d)                  = d^2
single_call_work_ceiling(d)    = basis + (8 + FIELD_BITS) * per_trial + split
```

Three separate factors stack on top of the ~2× per-multiply:

1. Basis build rounds double: `FIELD_BITS - 1` = 63 → 127
   (`build_frobenius_basis`, `rezzy-recon/src/pinsketch.rs:392-403`).
2. The factor-parameter ladder doubles: `FACTOR_TRIALS = 8 + FIELD_BITS`
   (`rezzy-recon/src/pinsketch.rs:17-18`) = 72 → 136 trials. The trials past 8
   sweep one deterministic parameter per basis bit
   (`rezzy-recon/src/pinsketch.rs:609-619`), so the count is structural.
3. The per-trial trace term `FIELD_BITS * d` doubles (`trace_from_basis`,
   `rezzy-recon/src/pinsketch.rs:407-421`).

Together the ladder term is ~`FIELD_BITS^2 * d`: it grows ~3.8× at small degree
and ~2× at large degree (where the `d^2` GCD term dominates). Measured anchors
scaled by the derived unit ratio and ~2× per unit:

| Benchmark                                    | Today       | GF(2^128) est. |
| -------------------------------------------- | ----------- | -------------- |
| `pinsketch decode/8`                         | 0.097334 ms | ~0.4-0.5 ms    |
| `pinsketch decode/32`                        | 1.014605 ms | ~4-5 ms        |
| `algebraic/decode/32x32`                     | 1.632425 ms | ~6-8 ms        |
| `triage/estimate strata/100`                 | 1.938625 ms | ~8-10 ms       |
| `extract+decode/N=1M Δ≈4096`                 | 194.73 ms   | ~0.8-1 s       |
| `exchange/100000 +5000/-4000` (pathological) | 16,091.9 ms | ~1 min         |

Unit-count scaling at the degrees that matter:

| Degree         | `single_call_work_ceiling` F=64 | F=128      | Ratio |
| -------------- | ------------------------------- | ---------- | ----- |
| 8 (stratum)    | 45,568                          | 156,160    | 3.43× |
| 32 (bucket)    | 286,720                         | 827,392    | 2.89× |
| 256 (overflow) | 10,092,544                      | 21,757,952 | 2.16× |

### Work budgets and the DoS ceiling

`single_call_work_ceiling` is not just a comment constant: `triage` derives its
shared budgets from it (`rezzy-recon/src/triage.rs:24-40`), and those budgets
are the CPU-amplification defense described in `docs/design_notes.md:57-59`.
Exact derived values:

| Constant                            | Today       | F=128                     | Units ratio | Wall-clock ratio at ~2×/unit |
| ----------------------------------- | ----------- | ------------------------- | ----------- | ---------------------------- |
| `MAX_FACTOR_WORK` (hardcoded)       | 16,000,000  | must rise to ≥ 21,757,952 | 1.36×       | 2.72×                        |
| `MAX_BATCH_FACTOR_WORK`             | 36,700,160  | 105,906,176               | 2.89×       | 5.77×                        |
| `MAX_STRATA_FACTOR_WORK`            | 1,458,176   | 4,997,120                 | 3.43×       | 6.85×                        |
| degenerate-chain sum, `d = 2..=256` | 916,609,400 | 2,057,692,920             | 2.24×       | —                            |

Two scenarios, and neither is free:

- **Scenario A — keep capacities, raise budgets.** `MAX_FACTOR_WORK = 16M` can
  no longer hold a degree-256 decode: the F=128 ceiling is 21,757,952 units and
  a typical degree-256 decode already draws ~93% of the F=64 ceiling
  (`rezzy-recon/src/pinsketch.rs:27-33`), i.e. ~19-20M units. Raising the budget
  keeps the capacity-256 overflow path legal but lifts the implied per-call CPU
  ceiling ~2.7×, the per-round batch ceiling ~5.8×, and the per-strata-pass
  ceiling ~6.9×. The "budget-hardened, no 32× amplification" property weakens by
  that factor.
- **Scenario B — keep CPU ceilings, cut capacities.** Not achievable at any
  usable capacity. Holding today's wall-clock strata ceiling requires
  `single_call_work_ceiling(d) ≤ 22,784` at F=128; even `d = 4` costs 73,856
  units and `d = 3` costs 54,600. Stratum capacity would have to fall from 8 to
  2, which guts the estimator.

The worst-case factorization gap documented at
`rezzy-recon/src/pinsketch.rs:25-45` also widens: the hypothetical degenerate
split chain grows from 916,609,400 units (57× the 16M budget) to 2,057,692,920
units (~128× an unchanged budget, or still ~57× a budget scaled by the same
2.24×). The gap stays open either way; it gets larger in absolute terms.

## Memory

| Item                                            | Today               | F=128                                   | Source                                 |
| ----------------------------------------------- | ------------------- | --------------------------------------- | -------------------------------------- |
| `ResidentKernel.strata`                         | 2048 B              | 4096 B (+2 KiB/room)                    | `rezzy-recon/src/resident.rs:37`       |
| `SyndromeSketch` at capacity 32                 | 256 B               | 512 B                                   | `rezzy-recon/src/algebraic.rs:429-431` |
| `SyndromeSketch` at capacity 256                | 2 KiB               | 4 KiB                                   | `rezzy-recon/src/algebraic.rs:52-59`   |
| `RemoteDigest.strata`                           | 2048 B/round        | 4096 B/round                            | `rezzy-recon/src/client.rs:108`        |
| `SortedPopulation`                              | 24 B/elem           | 32 B/elem (+33%)                        | `rezzy-recon/src/server.rs:338-341`    |
| `ElementHash`                                   | 24 B                | 32 B                                    | `rezzy-recon/src/algebraic.rs:133-143` |
| Locator `Polynomial` (transient, d=256)         | 257 × `u64` ≈ 2 KiB | 257 × `u128` ≈ 4 KiB                    | `rezzy-recon/src/pinsketch.rs:14`      |
| Frobenius basis (per active recursion node)     | ~132 KB at d=256    | ~526 KB (4×: 2× polynomials × 2× width) | `rezzy-recon/src/pinsketch.rs:392-403` |
| `solve_quadratic_form` rows (per degree-2 node) | 64 × `u64` = 512 B  | 128 × `u128` ≈ 2 KiB (4×)               | `rezzy-recon/src/pinsketch.rs:429-440` |

The `SortedPopulation` figure is the one that scales with room size: the key
column doubles (`Vec<u64>` → `Vec<u128>`) and the residual column stays 16 B, so
a 10M-event population goes from 240 MB to 320 MB.

## Disk and wire

Everything is exactly 2× because a coordinate is exactly one field element:

| Item                                | Today                                   | F=128                               |
| ----------------------------------- | --------------------------------------- | ----------------------------------- |
| Sketch wire, capacity 32            | 256 B raw / 342 base64url chars         | 512 B / 683 chars                   |
| Sketch wire, capacity 256           | 2048 B / 2731 chars                     | 4096 B / 5462 chars                 |
| Per-round aggregate (capacity 4096) | 32,768 B raw / 43,691 chars (~42.7 KiB) | 65,536 B / 87,382 chars (~85.3 KiB) |
| Strata digest per round             | 2048 B                                  | 4096 B                              |
| Decoded roots / candidates          | 8 B each                                | 16 B each                           |
| `ResidentKernel` record             | 2073 B, format version 1                | 4121 B, version must bump           |

Constants: `RESIDENT_SERIALIZED_LEN = 1 + 16 + 8 + 32 * 8 * 8`
(`rezzy-recon/src/resident.rs:21`); sketch encoding is base64url-no-pad over
little-endian coordinates (`rezzy-recon/src/algebraic.rs:607-614`); bucket
sketches are raw concatenated coordinates with no length prefix
(`rezzy-recon/src/triage.rs:304-376`).

Unchanged: event IDs (still 32-byte SHA-256 digests), `RoomAccumulator` wire
form (16 B digest, `rezzy-recon/src/algebraic.rs:284-287`), and `NodeSummary`
(24 B, `rezzy-recon/src/triage.rs:93-151`).

`ResidentKernel::to_bytes` is currently exercised only by its own tests
(`rezzy-recon/src/resident.rs:228-261`); no production caller persists the
record yet, so the disk impact today is the wire, not a storage format.

## Security gain

### The binding cost is pair production

A PinSketch syndrome is a function of the field key alone: for a two-element
difference `{a, b}` the first coordinate is `a + b`, which vanishes only when
`a = b`. So any forgery that needs the sketch to _not_ see a hidden difference
must be built from pairs of distinct events that **collide in the field key**.

Producing one colliding pair is a plain birthday search:

- GF(2^64) key: **2^32** hashes (bulk birthday).
- GF(2^128) key: **2^64** hashes.

Both are unkeyed and fully offline against V3/V4+ content-hash event IDs
(`rezzy-recon/src/algebraic.rs:146-205`).

### Effect on the accumulator forgery estimates

The numbers below are the arithmetic estimates recorded in
`2026-10-02-142636-local-command-caveatthe-command-below-was-run-d.txt` (same
session, never executed — the notes state "These are arithmetic only"). That
analysis's own conclusion was that pair production is the cost floor: "past
about 256 bits, widening the sum stops helping, because the cost floor becomes
producing the colliding pairs." Widening the field key moves exactly that floor,
so every pair-gated figure shifts up by ~2^32:

| Accumulator                     | Today | GF(2^128) key                     |
| ------------------------------- | ----- | --------------------------------- |
| XOR, 128-bit residual (current) | ~2^37 | **~2^69**                         |
| sum mod 2^128                   | ~2^43 | ~2^75                             |
| sum mod 2^256                   | ~2^48 | ~2^80                             |
| LtHash-style, ~2048 bits        | ~2^97 | ~2^97 (not pair-gated; unchanged) |

Caveat: this scaling is conditional on pair production remaining the dominant
term after widening, which the original analysis asserts as the floor but did
not re-derive with a 128-bit key in place. The Wagner k-list structure over the
XOR group is untouched; it is merely gated behind 2^64 pairs now.

The ranking of options is unchanged, but the practical gap between "stay with
XOR" and the expensive accumulators collapses from ~2^60 to ~2^28. That is
enough to re-open the accumulator question the earlier session deferred, and it
is the single largest security consequence of this change.

### Random collisions

In a 10M-event population, the expected number of key collisions is
`N(N-1)/2 / 2^64 ≈ 2.7e-6` today and `≈ 1.5e-25` at 128 bits. Practical effects:

- The multi-candidate disambiguation path (`SortedPopulation::candidates`,
  `rezzy-recon/src/server.rs:392`) becomes dead in practice.
- The "one wasted fetch per collision" nuisance, described in
  `2026-10-02-142636-local-command-caveatthe-command-below-was-run-d.txt`,
  disappears.
- The `h128` residual no longer has to rescue colliding keys; it stays purely as
  an independent integrity residual.

### Targeted forgery

Making one event's key equal a chosen target root goes from 2^64 to 2^128. Both
are already infeasible; this is a non-gain.

### Not improved

- **Prefix-grinding placement attack** (`TODO(prefix-grinding)`,
  `rezzy-recon/src/algebraic.rs:146-205`, `rezzy-recon/src/resident.rs:24-33`,
  `rezzy-recon/src/client.rs:26-42`). The splitter descends one key bit per
  round over `MAX_RECONCILIATION_ROUNDS = 20`; grinding a ~20-bit shared prefix
  costs ~2^20 hashes per bit of prefix, independent of field width. The fix
  remains an epoch-rotated keyed placement hash.
- **Round exhaustion** and the `MAX_NO_PROGRESS_ROUNDS = 3` mitigation
  (`rezzy-recon/src/client.rs:149`) — unchanged.
- **`MAX_FACTOR_WORK` worst-case gap** (`rezzy-recon/src/pinsketch.rs:25-45`) —
  unchanged in kind, worse in absolute units (see Time).
- **DoS CPU ceilings** — strictly weaker under Scenario A (see Time).
- **Syndrome-level forgery with hidden weight above capacity** — was never the
  cheap path at either width; a weight-`w` set with all-zero syndromes is pinned
  by the uniqueness the decoder relies on, and the residual check is independent
  of field width.
- **Residual XOR-group structure** — the residual stays 128-bit XOR.

### Key-derivation side effects

Today `h64` is the _first non-zero_ 8-byte big-endian chunk of the 32-byte
digest, scanning all four chunks with fallback 1
(`rezzy-recon/src/algebraic.rs:208-225`), and the residual is disjoint only in
the common case (comment at `:134-138`). A 128-bit key makes the split exact and
permanent: key = bytes 0..16, residual = bytes 16..32. That is cleaner, but two
behaviors must be re-specified:

- The zero-key rejection in `toggle` / `insert`
  (`rezzy-recon/src/algebraic.rs:486-489`,
  `rezzy-recon/src/resident.rs:146-169`) must handle a 128-bit zero key
  (probability 2^-128; still needs a defined fallback).
- `MAX_DEPTH = 32` (`rezzy-recon/src/lib.rs:37`) and the 32-strata
  trailing-zeros placement (`rezzy-recon/src/resident.rs:172-181`) are
  unchanged, so placement statistics are unchanged; a wider key does not buy
  deeper tries or more strata without separate constant changes.

## Interop, format, and engineering surface

- **libminisketch cannot be a reference.** Upstream `minisketch_bits_supported`
  accepts 2..=64 bits only. There is no GF(2^128) oracle, so
  `sketch_wire_format_matches_libminisketch_64_bit_serialization`
  (`tests/unit/test_reconcile_algebraic.rs:104-119`, vectors generated with
  `pyminisketch.py`) dies with no replacement. A new profile identifier and an
  independently implemented GF(2^128) test-vector generator are required, plus a
  format-version bump for `ResidentKernel` (`rezzy-recon/src/resident.rs:19`).
- **Type sweep.** 265 textual `u64` mentions across the 11 source files of
  `rezzy-recon`; a large fraction are field-typed and all of `pinsketch`,
  `algebraic`, `resident`, `triage`, `server`, `client`, `verify`, `gf64`, and
  `gf64_simd` touch the element type. No existing newtype to widen.
- **New arithmetic backend.** `gf64.rs` (158 lines) and `gf64_simd.rs` (535
  lines) do not carry over: GF(2^128) needs its own reduction polynomial, a
  portable 128-iteration reference, a PCLMUL reduction chain, and an AVX-512
  `vpclmulqdq` MAC. The existing AVX-512 high-bit regression test
  (`rezzy-recon/src/gf64_simd.rs:469-534`) is evidence this is easy to get
  subtly wrong.
- **Cost model and pins.** `FIELD_BITS` feeds `frobenius_basis_cost`,
  `factor_trial_cost_with_basis`, `FACTOR_TRIALS`, `TRACE_SQUARES`, and
  `single_call_work_ceiling`. At least 8 pinned tests break, including
  `assert_eq!(single_call_work_ceiling(256), Some(10_092_544))`
  (`rezzy-recon/src/pinsketch.rs:885`) and
  `assert_eq!(total_degenerate_work, 916_609_400)`
  (`rezzy-recon/src/pinsketch.rs:895`), plus the explicit `16_000_000` budget in
  the overflow tests (`rezzy-recon/src/algebraic.rs:983-988`).
- **`solve_quadratic_form`** grows from a 64×65 to a 128×129 GF(2)-linear system
  (`rezzy-recon/src/pinsketch.rs:429-484`): 4× row storage, ~8× naive
  elimination work, called once per degree-2 recursion node.

## Alternatives compared

| Option                                                                                 | Security effect                                                                                                                | Cost                                                                                                                        |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| Widen field to GF(2^128) (this document)                                               | pair grinding 2^32 → 2^64; accumulator forgery ~2^37 → ~2^69                                                                   | ×2 encode, ×4-5 decode, ×2 wire/memory, ~4-7× weaker DoS ceilings, interop break                                            |
| Epoch-rotated keyed placement hash (Yang et al. §4.3; the `TODO(prefix-grinding)` fix) | defeats the prefix-grinding attack this change does **not** touch                                                              | one key per epoch; preserves `ResidentKernel` amortization within an epoch; no field change                                 |
| LtHash accumulator profile                                                             | forgery ~2^97, not pair-gated                                                                                                  | ~2 KiB resident state per room + ~2 KiB wire per reconciliation; already partially implemented at `src/incremental/lthash/` |
| Widen the accumulator sum only (mod 2^128 / 2^256)                                     | ~2^43 / ~2^48 today; dominated by the same 2^32 pair floor                                                                     | format change with no field change; previously judged "not worth a format change on its own"                                |
| Document the limit and keep GF(2^64)                                                   | accepts ~2^37 accumulator forgery, which only hides the attacker's own events and blocks repair of a split the attacker caused | zero                                                                                                                        |

Note that these are complementary, not exclusive: the field widening buys the
pair-cost floor, the keyed placement hash buys the liveness attack, and the
accumulator choice buys residual forgery resistance.

## Bottom line

Widening to GF(2^128) costs roughly ×2 on encode paths, ×4-5 on decode, exactly
×2 on every sketch/resident/wire byte, +33% on per-event population memory, and
a 4-7× weakening of the budget-derived DoS CPU ceilings unless capacities are
cut (which the cost model does not permit at any useful capacity). It breaks
MSC4521/libminisketch interoperability with no reference oracle to replace it.

In exchange it moves exactly one number: adversarial key-collision grinding from
2^32 to 2^64, which lifts the pair-gated accumulator forgery estimates by ~2^32.
It does not touch either open TODO in `rezzy-recon` (`prefix-grinding`,
`MAX_FACTOR_WORK`), and it makes the second one larger in absolute units. If the
goal is the documented security gaps, the epoch-rotated placement key addresses
the gap widening misses, at a small fraction of the cost; if the goal is the
accumulator bound, the field change is what makes plain XOR competitive again.

## Appendix: reproducing the derived numbers

The cost model is pure integer arithmetic on `FIELD_BITS` and degree `d`
(`rezzy-recon/src/pinsketch.rs:495-530`):

```text
basis(d)   = (F - 1) * d^2
per_trial(d) = F * d + d^2
ladder(d)  = (8 + F) * per_trial(d)
split(d)   = d^2
ceiling(d) = basis(d) + ladder(d) + split(d)
```

- `MAX_BATCH_FACTOR_WORK = 128 * ceiling(32)`
  (`rezzy-recon/src/triage.rs:24-30`)
- `MAX_STRATA_FACTOR_WORK = 32 * ceiling(8)` (`rezzy-recon/src/triage.rs:36-42`)
- degenerate chain = `sum of ceiling(d) for d in 2..=256`, pinned at
  `rezzy-recon/src/pinsketch.rs:890-896`

Sanity check at F=64, which reproduces every pinned constant exactly:
`ceiling(8) = 45,568`, `ceiling(32) = 286,720`, `ceiling(256) = 10,092,544`,
`128 * ceiling(32) = 36,700,160`, `32 * ceiling(8) = 1,458,176`,
`sum = 916,609,400`. Re-evaluating with `F = 128` yields the F=128 column of the
tables above. Wall-clock ratios additionally assume ~2× time per work unit; that
figure is an estimate and should be re-measured with a real GF(2^128) multiply
before any of the time tables are treated as requirements.
