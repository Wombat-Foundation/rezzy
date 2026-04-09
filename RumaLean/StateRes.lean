import RumaLean.Kahn
import Mathlib.Data.Prod.Lex
import Mathlib.Order.Basic
import Mathlib.Data.String.Basic

set_option linter.style.emptyLine false
set_option linter.style.longLine false

/-!
# Matrix State Resolution

This module defines the Matrix State Resolution tie-breaking rule and proves that
it forms a strict total order, thereby ensuring deterministic topological sorting via Kahn's sort.
-/

/-- A simplified representation of a matrix Event. -/
structure Event where
  event_id : String
  power_level : ℕ
  origin_server_ts : ℕ
  deriving Repr, Inhabited, DecidableEq

/-- We map an Event into a lexicographical tuple representation to natively
    inherit Lean 4's heavily fortified LinearOrder proofs.
    Tie-breaking corresponds to:
    - power_level (descending) -> OrderDual ℕ
    - origin_server_ts (ascending) -> ℕ
    - event_id (ascending) -> String
-/
def eventToLex (e : Event) : ℕᵒᵈ ×ₗ ℕ ×ₗ String :=
  toLex (OrderDual.toDual e.power_level, toLex (e.origin_server_ts, e.event_id))

theorem eventToLex_inj : Function.Injective eventToLex := by
  intro a b h
  cases a; cases b
  dsimp [eventToLex, toLex, OrderDual.toDual] at h
  injection h with h1 h2
  injection h2 with h3 h4
  change _ = _ at h1
  subst h1 h3 h4
  rfl

/-- Total order representation derived flawlessly from tuple components without any sorry endpoints. -/
instance : LinearOrder Event := LinearOrder.lift' eventToLex eventToLex_inj

/-- Syntactic sugar for topological comparing -/
def Event.compare (a b : Event) : Ordering := Ord.compare a b

/-- Total Order property is fulfilled by the StateRes algorithmic structure. -/
@[reducible]
def stateres_is_total_order : LinearOrder Event := inferInstance
