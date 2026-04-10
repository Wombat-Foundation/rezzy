<!-- markdownlint-disable MD013 MD033 -->

# Ruma Lean

[![CI](https://github.com/gamesguru/ruma-zk/actions/workflows/ci.yml/badge.svg)](https://github.com/gamesguru/ruma-zk/actions/workflows/ci.yml)

Formal verification of Kahn's sort and State Res v2 using **Lean 4**.

Reference standard implementation in `rust` for other homeservers.

## What's Inside?

The project is structured into three main parts in `RumaLean/`:

1. **`DirectedAcyclicGraph.lean`**

2. **`Kahn.lean`**

3. **`StateRes.lean`**

## Equivalence Proof: Lean vs. Rust

### Tie-Breaking Rule

The Matrix spec mandates tie-breaking by Power Level, Timestamp, and Event ID.

<table>
<tr>
<th>Lean 4 (StateRes.lean)</th>
<th>Rust (src/lib.rs)</th>
</tr>
<tr>
<td valign="top">

```lean
def eventToLex (e : Event) : ℕᵒᵈ ×ₗ ℕ ×ₗ String :=
  toLex (OrderDual.toDual e.power_level,
    toLex (e.origin_server_ts, e.event_id))
```

</td>
<td valign="top">

```rust
impl Ord for LeanEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        match other.power_level.cmp(&self.power_level) {
            Ordering::Equal => match self.origin_server_ts.cmp(&other.origin_server_ts) {
                Ordering::Equal => self.event_id.cmp(&other.event_id),
                ord => ord,
            },
            ord => ord,
        }
    }
}
```

</td>
</tr>
</table>

### Topological Sort (Kahn's)

The sorting algorithm must be deterministic to ensure state consistency across the Matrix.

<table>
<tr>
<th>Lean 4 (Kahn.lean)</th>
<th>Rust (src/lib.rs)</th>
</tr>
<tr>
<td valign="top">

```lean
/-- Kahn's sort implementation -/
def kahnSort (g : Graph) : List Event :=
  -- Logic proven deterministic
  -- in Lean's total order
```

</td>
<td valign="top">

```rust
pub fn lean_kahn_sort(events: &HashMap<String, LeanEvent>, version: StateResVersion) -> Vec<String> {
    let mut queue: BinaryHeap<SortPriority> = BinaryHeap::new();
    while let Some(priority) = queue.pop() {
        let event = priority.event;
        result.push(event.event_id.clone());
        // Update degrees and neighbors
    }
}
```

</td>
</tr>
</table>

## Development

You can run development tasks directly:

```bash
make test      # Run Rust unit tests (20+ verified cases)
make coverage  # Generate focused HTML coverage report
make lint      # Run clippy checks
make prove     # Run Lean theorem proofs
```

## Why "Lean"?

1. **Dependency Minimization**: The Rust implementation carries **zero** external dependencies, avoiding the 400-600 crate bloat of the full Ruma stack.
2. **Formal Correctness**: Every line of the Rust implementation is mirrored by a mathematical proof in the Lean model.
3. **ZK Efficiency**: Fewer instructions and smaller memory footprints result in significantly lower AIR trace rows in zkVMs.

---

_Written securely with zero `sorry` proofs left behind._
