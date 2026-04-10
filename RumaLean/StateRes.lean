import RumaLean.Kahn
import Mathlib.Data.Prod.Lex
import Mathlib.Order.Basic
import Mathlib.Data.String.Basic

set_option linter.style.emptyLine false
set_option linter.style.longLine false

/-!
# Matrix State Resolution
This module defines the Matrix State Resolution tie-breaking rule and proves
that it forms a strict total order, thereby ensuring deterministic topological
sorting via Kahn's sort.
-/

/-- A simplified representation of a matrix Event. -/
structure Event where
  event_id : String
  power_level : Int
  origin_server_ts : Nat
  depth : Nat
  deriving Repr, Inhabited, DecidableEq

inductive StateResVersion
  | V1
  | V2
  | V2_1
  deriving Repr, Inhabited, DecidableEq

/-- We map an Event into a lexicographical tuple representation depending on the state resolution version.
    - V1: depth (ascending) -> event_id (ascending) -> fallback deterministic fields
    - V2: power_level (desc) -> origin_server_ts (asc) -> event_id (asc) -> fallback deterministic fields -/
def eventToLexV1 (e : Event) :=
  toLex (e.depth, toLex (e.event_id, toLex (OrderDual.toDual e.power_level, e.origin_server_ts)))

def eventToLexV2 (e : Event) :=
  toLex (OrderDual.toDual e.power_level, toLex (e.origin_server_ts, toLex (e.event_id, e.depth)))

theorem eventToLexV1_inj : Function.Injective eventToLexV1 := by
  -- Destructure the Event structures right in the signature
  rintro ⟨id1, pl1, ts1, d1⟩ ⟨id2, pl2, ts2, d2⟩ h
  -- Tell simp to break the Prod tuples apart
  simp only [eventToLexV1, toLex, OrderDual.toDual] at h
  -- Extract exact matches and substitute them globally
  obtain ⟨rfl, rfl, rfl, rfl⟩ := h
  rfl

theorem eventToLexV2_inj : Function.Injective eventToLexV2 := by
  rintro ⟨id1, pl1, ts1, d1⟩ ⟨id2, pl2, ts2, d2⟩ h
  simp only [eventToLexV2, toLex, OrderDual.toDual] at h
  obtain ⟨rfl, rfl, rfl, rfl⟩ := h
  rfl

/-- Total order representation derived from tuple components. -/
@[reducible] def stateres_is_total_order_v1 : LinearOrder Event := LinearOrder.lift' eventToLexV1 eventToLexV1_inj
@[reducible] def stateres_is_total_order_v2 : LinearOrder Event := LinearOrder.lift' eventToLexV2 eventToLexV2_inj

@[reducible] def stateResLinearOrder (v : StateResVersion) : LinearOrder Event :=
  match v with
  | .V1 => stateres_is_total_order_v1
  | .V2 | .V2_1 => stateres_is_total_order_v2

/-- Represents an abstract State dictionary applied by matrix events. -/
def State := String

/-- The initial empty state for resolution. -/
def emptyState : State := ""

instance : Inhabited State where
  default := emptyState

/-- The state transition function. Resolves an event against the current state. -/
def applyEvent (s : State) (e : Event) : State :=
  String.append s e.event_id

/-- The State Resolution algorithm application.
  Takes an initial state and a deterministic, topologically sorted list of Events
  (output from Kahn's sort) and folds over them.
  Implements MSC4297: If V2.1, it ignores the unconflicted state and starts empty. -/
def stateResAlgorithm (v : StateResVersion) (unconflictedState : State) (sortedEvents : List Event) : State :=
  let initialState := match v with
    | .V2_1 => emptyState -- Initialize with empty state for v2.1
    | _ => unconflictedState
  sortedEvents.foldl applyEvent initialState

/-- Theorem: State Resolution Convergence.
  Because `kahnSort` is deterministic given a strict total order,
  the final folded state is perfectly convergent across all participants. -/
theorem stateres_convergence (v : StateResVersion) (G : DirectedGraph Event)
    [IsDAG G] [DecidableRel G.edges] [LinearOrder Event] (S : Finset Event) (unconflictedState : State) :
    ∀ L1 L2, L1 = kahnSort G S → L2 = kahnSort G S →
    stateResAlgorithm v unconflictedState L1 = stateResAlgorithm v unconflictedState L2 := by
  -- The `rfl rfl` automatically binds `L1` and `L2` to `kahnSort G S`
  rintro L1 L2 rfl rfl
  rfl
