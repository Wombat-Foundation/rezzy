import RumaLean.StateRes
import RumaLean.DirectedAcyclicGraph

namespace RumaLean

def ancestors (G : DirectedGraph Event) (e : Event) : Finset Event :=
  sorry

def sharedHistory (G : DirectedGraph Event) (tips1 tips2 : Finset Event) : Finset Event :=
  (tips1.biUnion (ancestors G)) ∩ (tips2.biUnion (ancestors G))

def mergeBase (G : DirectedGraph Event) (tips1 tips2 : Finset Event) [DecidableRel G.edges] : Finset Event :=
  (sharedHistory G tips1 tips2).filter (λ e =>
    ∀ e' ∈ sharedHistory G tips1 tips2, ¬G.edges e e')

theorem state_recovery_via_merge_base (G : DirectedGraph Event) [IsDAG G] [DecidableRel G.edges]
    [LinearOrder Event] (mergeBaseState : State) (relativeEvents : Finset Event) :
    ∀ L1 L2, L1 = kahnSort G relativeEvents → L2 = kahnSort G relativeEvents →
    stateResAlgorithm .V2_1 mergeBaseState L1 = stateResAlgorithm .V2_1 mergeBaseState L2 := by
  intro L1 L2 h1 h2
  subst h1 h2
  rfl

end RumaLean
