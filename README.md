# Ruma Lean

Formal verification of Kahn's sort and State Res v2 using **Lean 4**.

## What's Inside?

The project is structured into three primary modules located in `RumaLean/`:

1. **`DirectedAcyclicGraph.lean`**: Provides structural foundations for
   Directed Graphs and Reachability definitions.

2. **`Kahn.lean`**: Implements Kahn's Topological Sort. Executes on graphs
   with proofs of deterministic resolution.

3. **`StateRes.lean`**: Contains the Matrix `Event` modeling.
   Formalizes tricky V2 tie-breaking hierarchy
   (Power Level, Origin Server TS, Event ID) natively onto
   Lean's battle-tested lexicographical `LinearOrder` abstractions.

## Building and Proving

To verify the proofs on your machine, simply run:

```bash
make prove
```

---

_Written securely with zero `sorry` proofs left behind._
