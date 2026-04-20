import RumaLean.StateRes
import RumaLean.DirectedAcyclicGraph

namespace RumaLean

/-- Compute the set of ancestors of event `e` within the universe of events in `S`.
    Uses iterative fixed-point expansion: at each step, add all parents of newly discovered
    nodes until convergence. Bounded by `S.card` iterations (since each step adds at least
    one new node or terminates). -/
def ancestorsImpl (G : DirectedGraph Event) [DecidableRel G.edges] (S : Finset Event) (e : Event) : Finset Event :=
  let rec loop (fuel : ℕ) (frontier acc : Finset Event) : Finset Event :=
    match fuel with
    | 0 => acc
    | fuel' + 1 =>
      -- Find all nodes in S that have an edge to any node in the frontier
      let new_parents := S.filter (fun u =>
        (frontier.filter (fun v => G.edges u v)).Nonempty)
      let novel := new_parents \ acc
      if novel.Nonempty then
        loop fuel' novel (acc ∪ novel)
      else
        acc
  loop S.card {e} {e}

def ancestors (G : DirectedGraph Event) [DecidableRel G.edges] (S : Finset Event) (e : Event) : Finset Event :=
  ancestorsImpl G S e

def sharedHistory (G : DirectedGraph Event) [DecidableRel G.edges] (S : Finset Event)
    (tips1 tips2 : Finset Event) : Finset Event :=
  (tips1.biUnion (ancestors G S)) ∩ (tips2.biUnion (ancestors G S))

def mergeBase (G : DirectedGraph Event) [DecidableRel G.edges] (S : Finset Event)
    (tips1 tips2 : Finset Event) : Finset Event :=
  (sharedHistory G S tips1 tips2).filter (λ e =>
    ∀ e' ∈ sharedHistory G S tips1 tips2, ¬G.edges e e')

theorem state_recovery_via_merge_base (G : DirectedGraph Event) [IsDAG G] [DecidableRel G.edges]
    [LinearOrder Event] (mergeBaseState : State) (relativeEvents : Finset Event) :
    ∀ L1 L2, L1 = kahnSort G relativeEvents → L2 = kahnSort G relativeEvents →
    stateResAlgorithm .V2_1 mergeBaseState L1 = stateResAlgorithm .V2_1 mergeBaseState L2 := by
  intro L1 L2 h1 h2
  subst h1 h2
  rfl

end RumaLean
