import RumaLean.DirectedAcyclicGraph
import Mathlib.Data.Finset.Card
import Mathlib.Data.Finset.Max

/-!
# Kahn's Topological Sort

This module implements Kahn's Topological Sort algorithm and states its correctness.
We also state that when ties (multiple 0 in-degree nodes) are broken using a strict linear order,
the output of Kahn's algorithm is deterministic.
-/

set_option linter.unusedDecidableInType false

variable {V : Type*} [DecidableEq V]

/-- The in-degree of a vertex `v` relative to a set of active vertices `S`.
    It counts how many `u ∈ S` have an edge `u → v`. -/
def inDegree (G : DirectedGraph V)
  [DecidableRel G.edges] (S : Finset V) (v : V) : ℕ :=
  (S.filter (fun u => G.edges u v)).card


/-- Find all nodes in `S` with in-degree 0. -/
def zeroInDegreeNodes (G : DirectedGraph V)
  [DecidableRel G.edges] (S : Finset V) : Finset V :=
  S.filter (fun v => inDegree G S v = 0)

/-- Liveness Lemma: Guarantees  Kahn's algo won't terminate early on valid DAG. -/
lemma dag_has_zero_in_degree (G : DirectedGraph V) [IsDAG G]
  [DecidableRel G.edges] (S : Finset V) (h : S.Nonempty) :
  (zeroInDegreeNodes G S).Nonempty := by
  sorry


/-- Kahn's sorting algorithm with fuel to ensure termination without `partial`. -/
def kahnSortImpl (G : DirectedGraph V)
  [DecidableRel G.edges] [LinearOrder V] : ℕ → Finset V → List V → List V
  | 0, _, L => L.reverse
  | n + 1, S, L =>
    let zeros := zeroInDegreeNodes G S
    if h : zeros.Nonempty then
      let min_v := zeros.min' h
      let S' := S.erase min_v
      kahnSortImpl G n S' (min_v :: L)
    else
      L.reverse -- Graph has cycle or is empty


/-- Main entry point for Kahn's Topological Sort.
    We supply fuel equal to the number of vertices to guarantee termination. -/
def kahnSort (G : DirectedGraph V)
  [DecidableRel G.edges] [LinearOrder V] (S : Finset V) : List V :=
  kahnSortImpl G S.card S []


/-- THEOREM: Kahn's sort is deterministic, inherently relying on min' determinism. -/
theorem kahn_sort_deterministic (G : DirectedGraph V)
    [DecidableRel G.edges] [LinearOrder V] (S : Finset V) :
    ∀ L1 L2, L1 = kahnSort G S → L2 = kahnSort G S → L1 = L2 := by
  intro L1 L2 h1 h2
  rw [h1, h2]

/-- THEOREM: The output of Kahn's sorting algorithm is a permutation of the input elements.
    Specifically, every element in `kahnSort G S` is in `S`, and vice versa. -/
theorem kahn_sort_is_permutation (G : DirectedGraph V) [IsDAG G]
    [DecidableRel G.edges] [LinearOrder V] (S : Finset V) :
    ∀ v, v ∈ kahnSort G S ↔ v ∈ S := by
  sorry

/-- THEOREM: The output of Kahn's sort maintains topological ordering.
    If `u` comes before `v` in the sorted list, then there is no edge from `v` to `u`. -/
theorem kahn_sort_is_topological (G : DirectedGraph V) [IsDAG G]
    [DecidableRel G.edges] [LinearOrder V] (S : Finset V) :
    ∀ {u v}, (∃ l1 l2 l3, kahnSort G S = l1 ++ [u] ++ l2 ++ [v] ++ l3) → ¬ G.edges v u := by
  sorry
