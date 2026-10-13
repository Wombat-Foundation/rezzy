# MSC4511 causal trie v2: leaf-compressed encoding (design note)

Status: DRAFT, Option A approved; unimplemented. The v1 trie (`src/merkle.rs`,
`mod causal`) is undeployed, so v2 replaces it outright; no migration path is
specified. This note fixes the byte-level encoding other implementations must
match. Numbers marked _est._ are estimates, not measurements.

## 1. Problem with v1

v1 is a binary sparse Merkle _sum_ trie committing to all `CAUSAL_DEPTH = 256`
key bits. For `n` random keys only ~`log2 n` levels hold real branching; the
rest are single-key chains. Costs paid per operation today:

| operation                | v1 cost                                                                                       |
| ------------------------ | --------------------------------------------------------------------------------------------- |
| `insert_mut`             | 256 node hashes (+256 map ops)                                                                |
| `verify_causal_*`        | 256 node hashes                                                                               |
| root rebuild of `n` keys | ~`256·n` node hashes                                                                          |
| proof on the wire        | already small: `EmptyRun` collapses canonical-empty siblings, leaving ~`log n` explicit steps |

The wire format is therefore _not_ the problem (an earlier estimate of "8 KB
proofs" ignored `CompressedCausalStep`); compute on insert, build and verify is.
Hash choice (SHA-256 → BLAKE3) is a constant factor on top and is sequenced
after this change (§9).

## 2. Design: leaf compression (recommended) vs. full Patricia

**Option A, leaf compression (recommended).** A subtree containing exactly one
key is represented by a single `Leaf` node holding the _full_ key. Branch nodes
exist only on paths to subtrees of ≥ 2 keys. No extension node.

- Depth becomes `1 + max LCP(key, other keys)`: ~`log2 n` for random keys.
- Adversarial depth: event IDs are hashes, so forcing a `k`-bit shared prefix
  costs ~`2^k` work and buys `k` extra hashes for a verifier. Worst case stays
  256, but amplification is bounded by attacker work.
- Chains of one-empty-child branches remain above a split (two keys sharing a
  prefix). They are short for hashed keys and need no new node type.

**Option B, full Patricia (extension nodes).** Also collapses those residual
chains, at the cost of a fourth node kind, a skipped-bits commitment, and a
fourth non-inclusion terminal. Only worth it if grinding-induced chain length is
judged a real threat. Not recommended; the rest of this note specifies A. If B
is chosen later, the extension hash must bind the skipped bits **and their
length** and carry the child's count unchanged.

## 3. Node kinds, canonical form, invariants

Bits are indexed MSB-first as in v1 (`causal_bit`).

- `Empty`: the empty set. One constant hash, count 0, **independent of depth**
  (v1's 257-entry `EmptyTable` disappears).
- `Leaf(key)`: exactly one key. Count 1. Commits to all 256 bits of `key`.
- `Branch(depth d, left, right)`: splits on bit `d`.

Invariants (a verifier MUST enforce 1–3; producers MUST maintain all):

1. **Count:** `count(Branch) = count(left) + count(right)`, computed with
   checked `u64` addition. A verifier that sees an overflowing sum, or a sibling
   count that would make the total exceed `u64::MAX`, MUST reject the proof
   (v1's `saturating_add` MUST NOT be carried over: saturation would let two
   different sets share a count). No cap on set size is imposed; sets of 2^64 or
   more distinct keys are unrepresentable and out of scope.
2. **No degenerate branch:** `count(Branch) >= 2`. A subtree of 0 keys is
   `Empty`; of 1 key is `Leaf`, never a branch over a leaf.
3. **Placement:** every key under a `Branch` at depth `d` agrees with the
   branch's path on bits `0..d`, and goes left iff bit `d` is 0. `d < 256`.
4. **Canonical:** the representation of a key set is unique (a function of the
   set only), so the root is insertion-order independent.
5. **Distinct keys:** `Leaf` means one _distinct_ key. Inserting a key that is
   already present is a no-op (as v1's `insert_mut` returning `false`); count
   and invariant 1 are over distinct keys only.

Two separate mechanisms, with different jobs; do not substitute one for the
other:

- **Canonical form (invariants 2 and 4)** gives _uniqueness_: one key set has
  exactly one root, hence insertion-order independence. It also lets a verifier
  reject non-canonical shapes (e.g. a `Branch(Leaf, Empty)`) before hashing,
  generalising v1's minimality check on `path[0]`.
- **Binding `d` into `BRANCH` (§4)** gives _position_: a node hash computed for
  depth `d` cannot be reinterpreted as a node at another depth, so a proof
  cannot shift where a committed subtree sits. The "claimed depth too deep"
  reject vector is covered by both (the shape check rejects it early; a hash
  that tried to pass it would not reproduce the root), but a verifier MUST still
  use the fold position as `d` and not drop it on the grounds that invariant 2
  exists.

## 4. Hash inputs (all lengths fixed; no ambiguity)

The layout is defined once against an abstract tagged hash `H_tag(msg)` (32-byte
output); the hash function is a parameter (§9), the bytes of `msg` are not.

```text
EMPTY  = H_empty ( "" )                                       count 0
LEAF   = H_leaf  ( key[32] )                                  count 1
BRANCH = H_branch( u16be(d) || left[32] || u64be(lcount)
                           || right[32] || u64be(rcount) )
```

Tags: `msc4511:causal-v2:empty`, `msc4511:causal-v2:leaf`,
`msc4511:causal-v2:branch`. They are ASCII, distinct, and no tag is a prefix of
another (required by the prefix instantiation below).

Instantiations:

- **SHA-256:** `H_tag(msg) = SHA-256(tag || msg)`.
- **BLAKE3:** `H_tag(msg) = BLAKE3_derive_key(context = tag).update(msg)`.

The two are different functions; a deployment names exactly one, and the version
tag identifies the choice (a BLAKE3 instantiation bumps to `causal-v3` tags
rather than reusing `v2`).

Binding `d` into `BRANCH` stops a node from being replayed at another depth.
Counts are inside the hash, so a forged count changes the root. The root of the
set is the hash of its top node: `EMPTY`, a `LEAF` (one key), or a `BRANCH` at
depth 0.

## 5. Proofs

A proof is the sibling list from the terminal's depth `t` up to the root (`t`
entries, deepest first). Each entry is `(hash, count)`; the side is derived from
the target key's bit at that depth. Existing `EmptyRun` encoding stays valid
(now just `length`, since empty is depth-free).

Verifier folds from the terminal upward, computing `BRANCH` at depths `t-1 … 0`,
and checks invariants 1 and 2 on every fold.

Terminals (exactly three):

1. **Member:** `Leaf(key)` with `key == target`. Needs `path[0]` non-empty if
   `t > 0` (else the parent is a degenerate branch).
2. **Non-member, empty:** `Empty` at depth `t`. `path[0]` must have count `>= 2`
   (a lone `Leaf` sibling would have collapsed the parent).
3. **Non-member, foreign leaf:** `Leaf(k')` with `k' != target` and `k'`
   agreeing with `target` on bits `0..t`. Verifier recomputes `LEAF(k')`, checks
   the prefix agreement and `k' != target`, then folds. This replaces the
   "divergence inside a compressed run" case: without extension nodes the
   divergent object is a whole committed key, so nothing is skipped.

Proof carries `t` and, for terminal 3, `k'`.

## 6. Reference algorithm and oracle independence

The production `CausalSet` builds the trie by incremental insert with leaf-split
on collision (find the first differing bit between the new key and the resident
leaf, emit branches down to it).

The differential oracle MUST NOT share that logic. Specified oracle: sort the
keys bytewise, compute adjacent-pair longest common prefixes by direct byte/bit
comparison, and assemble the trie bottom-up from those LCPs (the Cartesian-tree
/ stack construction). It never descends bit by bit, so both sides cannot agree
on a wrong split depth by sharing a descent loop. The retained v1-style
recursive partition (`subtree_root`) can be kept as a third check, adapted to
emit `Leaf` at count 1.

## 7. Cross-implementation vectors

Generated from the reference implementation, committed as JSON: empty set, 1
key, 2 keys with LCP 0 / 1 / 7 / 8 / 255, a 3-key set whose two lowest keys
share a long prefix, and one randomized 64-key set; for each, root, count,
member proofs, empty-terminal and foreign-leaf non-member proofs, plus a block
of **must-reject** proofs (inflated count, degenerate branch, foreign leaf with
`k' == target`, foreign leaf with wrong prefix, `t` too deep, sibling swapped,
wrong depth tag).

## 8. Code impact

`src/merkle.rs` `mod causal`: `CausalSet` node cache and `insert_mut`, `root`,
proof builders, `verify_causal_*`, `compress_causal_path`/`decompress`,
`CausalOracle` and `TerminalKind` (add `ForeignLeaf`), `empty_table` (removed).
Not yet read, to be audited for proof-layout coupling: `src/signing/attest.rs`,
`src/cuckoo_verify.rs`, `src/resolve/*`. MSC4511 text and `docs/spec_audit.md`
rows must be updated.

## 9. Sequencing and hash

1. Land §2–§7 with the current SHA-256 `hash_parts`; re-measure.
2. Instantiate `H_tag` with BLAKE3 (new `v3` tags, §4) (already a workspace dep,
   used by MSC4500; ~3-5× _est._ on small inputs, more with batched SIMD per
   level during bulk build). Domain separation comes from
   `Hasher::new_derive_key`.
3. Re-measure on an idle machine.

## 10. Open decisions

- Option A vs B (§2). A recommended.
- Keep `d` inside `BRANCH` (recommended; costs 2 bytes).
- Binary vs 16-ary fan-out: skip; compression removes most of the benefit and
  16-ary multiplies sibling-set size per proof.
- Whether `EmptyRun` stays in the wire format or proofs become plain lists (with
  compression, runs are rare).
