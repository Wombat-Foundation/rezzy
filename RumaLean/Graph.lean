import Mathlib.Data.Finset.Basic
import Mathlib.Order.Basic
import Mathlib.Data.Rel

/-!
# Graphs

This module defines the basic DAG structures we will use for Kahn's topological sort.
We adopt a simple adjacency list or set representation.
-/

universe u

/-- A simple directed graph represented by its edge relation. -/
structure DirectedGraph (V : Type u) where
  edges : V → V → Prop

/-- A path from `u` to `v` is the reflexive-transitive closure of `edges`. -/
def DirectedGraph.Reachable {V : Type u} (G : DirectedGraph V) (u v : V) : Prop :=
  Relation.ReflTransGen G.edges u v

/-- A DAG is a directed graph with no cycles, meaning if `v` is reachable from `u` and `u` is reachable from `v`, then `u = v`. -/
class IsDAG {V : Type u} (G : DirectedGraph V) : Prop where
  acyclic : ∀ (u v : V), G.Reachable u v → G.Reachable v u → u = v
