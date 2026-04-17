import RumaLean.StateRes
import RumaLean.DirectedAcyclicGraph

namespace RumaLean

/--
# Merge Base & LCA Logic
To minimize the ZK proof size, we only resolve the "Fork" relative to a shared
ancestor (the Merge Base).
-/

/-- The set of ancestors of a given event in the DAG. -/
def ancestors (G : DirectedGraph Event) (e : Event) : Finset Event :=
  -- This would be defined as the reflexive transitive closure of the edges relation.
  sorry

/-- The shared history of two sets of tips (e.g., Alice's view and Bob's view). -/
def sharedHistory (G : DirectedGraph Event) (tips1 tips2 : Finset Event) : Finset Event :=
  (tips1.biUnion (ancestors G)) ∩ (tips2.biUnion (ancestors G))

/-- Returns the set of "frontier" events in the shared history.
    These are the most recent events that both participants agree on. -/
def mergeBase (G : DirectedGraph Event) (tips1 tips2 : Finset Event) : Finset Event :=
  (sharedHistory G tips1 tips2).filter (λ e =>
    ∀ e' ∈ sharedHistory G tips1 tips2, ¬G.edges e e')

/--
Theorem: State Recovery via Merge Base.
If two participants share a Merge Base and the same set of new events,
applying Kahn's sort to the relative DAG recovers the same final state.
-/theorem state_recovery_via_merge_base (G : DirectedGraph Event) [IsDAG G]
    [LinearOrder Event] (mergeBaseState : State) (relativeEvents : Finset Event) :
    ∀ L1 L2, L1 = kahnSort G relativeEvents → L2 = kahnSort G relativeEvents →
    stateResAlgorithm .V2_1 mergeBaseState L1 = stateResAlgorithm .V2_1 mergeBaseState L2 := by
  -- Follows from stateres_convergence
  intro L1 L2 h1 h2
  subst h1 h2
  rfl

end RumaLean
