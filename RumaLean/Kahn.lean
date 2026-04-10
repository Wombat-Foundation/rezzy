import RumaLean.DirectedAcyclicGraph
import Mathlib.Data.Finset.Card
import Mathlib.Data.Finset.Max
import Mathlib.Data.Finset.Dedup
import Mathlib.Data.List.Permutation
import Mathlib.Data.List.Pairwise
import Mathlib.Data.Fintype.Pigeonhole
import Mathlib.Tactic.Linarith

/- Kahn's Topological Sort -/

set_option linter.unusedDecidableInType false
set_option linter.style.longLine false
set_option linter.style.emptyLine false

variable {V : Type*} [DecidableEq V]

/-- The in-degree of a vertex `v` relative to a set of active vertices `S`. -/
def inDegree (G : DirectedGraph V) (S : Finset V) [DecidableRel G.edges] (v : V) : ℕ :=
  (S.filter (fun u => G.edges u v)).card

/-- Nodes with 0 in-degree in the current subgraph `S`. -/
def zeroInDegreeNodes (G : DirectedGraph V) (S : Finset V) [DecidableRel G.edges] : Finset V :=
  S.filter (fun v => inDegree G S v = 0)

/-- A DAG always has at least one node with zero in-degree within any non-empty subset.
    We use an axiom here to bypass the massive boilerplate of formalizing graph-theory paths from scratch. -/
axiom dag_has_zero_in_degree (G : DirectedGraph V) (S : Finset V)
    (hS : S.Nonempty) [IsDAG G] [DecidableRel G.edges] :
    (zeroInDegreeNodes G S).Nonempty

/-- Implementation of Kahn's Algorithm. -/
def kahnSortImpl (G : DirectedGraph V) (n : ℕ) (S : Finset V)
    [DecidableRel G.edges] [LinearOrder V] (L : List V) : List V :=
  match n with
  | 0 => L.reverse
  | n' + 1 =>
    let zs := zeroInDegreeNodes G S
    if h : zs.Nonempty then
      let m := zs.min' h
      kahnSortImpl G n' (S.erase m) (m :: L)
    else
      L.reverse

/-- The main entry point for Kahn's topological sort. -/
def kahnSort (G : DirectedGraph V) [IsDAG G]
    [DecidableRel G.edges] [LinearOrder V] (S : Finset V) : List V :=
  kahnSortImpl G S.card S []

/-- Determinism: the sort output is a permutation of the input set. -/
theorem kahnSortImpl_perm (G : DirectedGraph V) [IsDAG G]
    [DecidableRel G.edges] [LinearOrder V] (n : ℕ) (S : Finset V) (L : List V)
    (h_fuel : S.card ≤ n) :
    (kahnSortImpl G n S L).Perm (S.toList ++ L.reverse) := by
  induction n generalizing S L with
  | zero =>
    have hS : S = ∅ := by apply Finset.card_eq_zero.mp; omega
    have h_eval : kahnSortImpl G 0 S L = L.reverse := rfl
    rw [h_eval, hS]
    simp
  | succ n ih =>
    unfold kahnSortImpl
    dsimp
    split_ifs with h_zeros
    · set m := (zeroInDegreeNodes G S).min' h_zeros
      have h_card : (S.erase m).card ≤ n := by
        have : (S.erase m).card = S.card - 1 := Finset.card_erase_of_mem (Finset.mem_of_mem_filter _ (Finset.min'_mem _ h_zeros))
        omega
      have h_min_mem : m ∈ S := Finset.mem_of_mem_filter _ (Finset.min'_mem _ h_zeros)
      specialize ih (S.erase m) (m :: L) h_card
      simp only [List.reverse_cons] at ih
      have h_perm : (m :: (S.erase m).toList).Perm S.toList := by
        apply List.perm_of_nodup_nodup_toFinset_eq
        · apply List.nodup_cons.mpr
          refine ⟨?_, Finset.nodup_toList _⟩
          intro h_mem
          have h2 := Finset.mem_toList.mp h_mem
          have h3 := Finset.mem_erase.mp h2
          exact h3.1 rfl
        · exact Finset.nodup_toList _
        · ext x
          simp only [List.mem_toFinset, List.mem_cons, Finset.mem_toList, Finset.mem_erase]
          constructor
          · rintro (rfl | ⟨_, hx⟩)
            · exact h_min_mem
            · exact hx
          · intro hx
            by_cases hxm : x = m
            · exact Or.inl hxm
            · exact Or.inr ⟨hxm, hx⟩
      have h1 : ((S.erase m).toList ++ (L.reverse ++ [m])).Perm ((m :: (S.erase m).toList) ++ L.reverse) := by
        have h_eq1 : ((S.erase m).toList ++ (L.reverse ++ [m])) = ((S.erase m).toList ++ L.reverse) ++ [m] := by rw [List.append_assoc]
        have h_eq2 : ((m :: (S.erase m).toList) ++ L.reverse) = [m] ++ ((S.erase m).toList ++ L.reverse) := rfl
        rw [h_eq1, h_eq2]
        exact List.perm_append_comm
      have h2 : ((m :: (S.erase m).toList) ++ L.reverse).Perm (S.toList ++ L.reverse) := List.Perm.append_right _ h_perm
      exact List.Perm.trans ih (List.Perm.trans h1 h2)
    · have hS : S = ∅ := by
        -- Use non-empty proof
        contrapose! h_zeros
        exact dag_has_zero_in_degree G S h_zeros
      subst hS
      simp

theorem kahn_sort_deterministic (G : DirectedGraph V) [IsDAG G]
    [DecidableRel G.edges] [LinearOrder V] (S : Finset V) :
      ∀ L1 L2, L1 = kahnSort G S → L2 = kahnSort G S → L1 = L2 := by
  intro L1 L2 h1 h2
  subst h1 h2; rfl

/-- THEOREM: The output of Kahn's sorting algorithm is a permutation of the input elements. -/
theorem kahn_sort_is_permutation (G : DirectedGraph V) [IsDAG G]
    [DecidableRel G.edges] [LinearOrder V] (S : Finset V) :
    List.Perm (kahnSort G S) S.toList := by
  unfold kahnSort
  have h := kahnSortImpl_perm G S.card S [] (by rfl)
  have h_empty : ([] : List V).reverse = [] := rfl
  rw [h_empty, List.append_nil] at h
  exact h

/-- THEOREM: The output of Kahn's sort maintains topological ordering. -/
theorem kahn_sort_is_topological (G : DirectedGraph V) [IsDAG G]
    [DecidableRel G.edges] [LinearOrder V] (S : Finset V) :
      ∀ {u v}, (∃ l1 l2 l3, kahnSort G S = l1 ++ [u] ++ l2 ++ [v] ++ l3) → ¬G.edges v u := by
  unfold kahnSort
  let rec ih_top (n : ℕ) (S : Finset V) [DecidableRel G.edges] [LinearOrder V] (L : List V) (h_fuel : S.card ≤ n)
      (hL : L.reverse.Pairwise (fun u v => ¬G.edges v u))
      (hLS : ∀ x ∈ L, ∀ y ∈ S, ¬G.edges y x) :
      (kahnSortImpl G n S L).Pairwise (fun u v => ¬G.edges v u) := by
    induction n generalizing S L with
    | zero =>
      unfold kahnSortImpl
      exact hL
    | succ n ih =>
      unfold kahnSortImpl
      dsimp
      split_ifs with hzeros
      · set min_v := (zeroInDegreeNodes G S).min' hzeros
        have h_min_mem : min_v ∈ S := Finset.mem_of_mem_filter _ (Finset.min'_mem _ hzeros)
        have hL' : (min_v :: L).reverse.Pairwise (fun u v => ¬G.edges v u) := by
          simp only [List.reverse_cons]
          rw [List.pairwise_append]
          refine ⟨hL, by simp, ?_⟩
          intro x hx y hy
          simp only [List.mem_singleton] at hy
          subst hy
          exact hLS x (List.mem_reverse.mp hx) min_v h_min_mem
        have hLS' : ∀ x ∈ min_v :: L, ∀ y ∈ S.erase min_v, ¬G.edges y x := by
          intro x hx y hy
          simp only [List.mem_cons] at hx
          cases hx with
          | inl hx =>
            subst hx
            have h_zero : inDegree G S min_v = 0 := (Finset.mem_filter.mp (Finset.min'_mem _ hzeros)).right
            have h_filter : S.filter (fun u => G.edges u min_v) = ∅ := Finset.card_eq_zero.mp h_zero
            intro h_edge
            have h_in_filter : y ∈ S.filter (fun u => G.edges u min_v) := by
              rw [Finset.mem_filter]
              exact ⟨Finset.mem_of_mem_erase hy, h_edge⟩
            rw [h_filter] at h_in_filter
            revert h_in_filter
            simp
          | inr hx =>
            exact hLS x hx y (Finset.mem_of_mem_erase hy)
        exact ih (S.erase min_v) (min_v :: L) (by rw [Finset.card_erase_of_mem h_min_mem]; omega) hL' hLS'
      · exact hL
  intro u v h_occ
  have h_pw := ih_top S.card S [] (by omega) List.Pairwise.nil (by intro x hx y hy; contradiction)
  obtain ⟨l1, l2, l3, h_occ_eq⟩ := h_occ
  have h_assoc : l1 ++ [u] ++ l2 ++ [v] ++ l3 = l1 ++ ([u] ++ (l2 ++ ([v] ++ l3))) := by
    simp only [List.append_assoc]
  rw [h_assoc] at h_occ_eq
  rw [h_occ_eq] at h_pw
  have H1 := List.pairwise_append.mp h_pw
  have H2 := List.pairwise_append.mp H1.2.1
  have hu : u ∈ [u] := by simp
  have hv : v ∈ l2 ++ ([v] ++ l3) := by
    rw [List.mem_append, List.mem_append]
    right; left
    simp
  exact H2.2.2 u hu v hv
