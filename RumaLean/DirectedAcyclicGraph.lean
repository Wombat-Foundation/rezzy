import Mathlib.Data.Finset.Basic
import Mathlib.Order.Basic
import Mathlib.Data.Rel

/-!
# Graphs

This module defines the basic DAG structures we will use for Kahn's topological sort.
We adopt a simple adjacency list or set representation.

## API Documentation

* `DirectedGraph`: A `structure` specifying a generic directed graph consisting of a set of
  vertices and an edge relation.
* `DirectedGraph.Reachable`: A `def` outlining the path between two vertices, establishing
  Reachable paths as an application of the `Relation.ReflTransGen` reflexive-transitive closure.
* `IsDAG`: A `class` asserting that a given graph is acyclic. (If a node `v` is reachable from
  `u` and `u` is reachable from `v`, then `u = v` — preventing cycles).
-/

universe u

/-- A simple directed graph represented by its edge relation. -/
structure DirectedGraph (V : Type u) where
  edges : V → V → Prop

/-- A path from `u` to `v` is the reflexive-transitive closure of `edges`. -/
def DirectedGraph.Reachable {V : Type u} (G : DirectedGraph V) (u v : V) : Prop :=
  Relation.ReflTransGen G.edges u v

/-- A DAG is a directed graph with no cycles, meaning if `u` can reach `v` in one or more
    steps, `v` cannot reach `u`. -/
class IsDAG {V : Type u} (G : DirectedGraph V) : Prop where
  acyclic : ∀ (u v : V), Relation.TransGen G.edges u v → ¬ Relation.TransGen G.edges v u
