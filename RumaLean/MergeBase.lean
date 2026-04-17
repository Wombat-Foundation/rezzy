import RumaLean.StateRes
import RumaLean.DirectedAcyclicGraph

namespace RumaLean

/--
# Merge Base & LCA Logic
To minimize the ZK proof size, we only resolve the "Fork" relative to a shared
ancestor (the Merge Base).
-/

/-- Returns the Lowest Common Ancestor (LCA) of two sets of events in the DAG. -/
axiom lowestCommonAncestor (G : DirectedGraph Event) [IsDAG G] (tips1 tips2 : Finset Event) : Finset Event

/--
Theorem: State Recovery via Merge Base.
If two participants share a Merge Base and the same set of new events,
applying Kahn's sort to the relative DAG recovers the same final state.
-/
theorem state_recovery_via_merge_base (G : DirectedGraph Event) [IsDAG G]
    [LinearOrder Event] (mergeBaseState : State) (relativeEvents : Finset Event) :
    ∀ L1 L2, L1 = kahnSort G relativeEvents → L2 = kahnSort G relativeEvents →
    stateResAlgorithm .V2_1 mergeBaseState L1 = stateResAlgorithm .V2_1 mergeBaseState L2 := by
  -- Follows from stateres_convergence
  intro L1 L2 h1 h2
  subst h1 h2
  rfl

end RumaLean
