import RumaLean.StateRes
import RumaLean.Merkle
import RumaLean.Field
import RumaLean.Arithmetization

namespace RumaLean

structure HypercubeRow where
  is_active : BabyBear
  node_id : BabyBear
  dimension_flip : BabyBear
  event_id : BabyBear
  power_level : BabyBear
  timestamp : BabyBear
  is_signature_valid : BabyBear

def hypercube_constraints (curr next : HypercubeRow) : Prop :=
  RumaLean.Arithmetization.is_bool_poly curr.is_active ∧
  RumaLean.Arithmetization.is_bool_poly curr.is_signature_valid ∧
  (curr.is_active = 0 → next.event_id = curr.event_id) ∧
  (next.node_id.val = (curr.node_id.val.val ^^^ (1 <<< curr.dimension_flip.val.val)))

theorem hypercube_air_soundness (G : DirectedGraph Event) [IsDAG G] [DecidableRel G.edges] [LinearOrder Event] (trace : List HypercubeRow) (h_len : trace.length = 131072) :
    (∀ i : Fin 131071,
      let curr := trace.get ⟨i.val, by rw [h_len]; omega⟩
      let next := trace.get ⟨i.val + 1, by rw [h_len]; omega⟩
      hypercube_constraints curr next) →
    ∃ (S : Finset Event), stateResAlgorithm .V2_1 emptyState (kahnSort G S) = emptyState := by
  sorry

end RumaLean
