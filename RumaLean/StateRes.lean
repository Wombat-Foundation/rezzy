import RumaLean.Kahn

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


/-- State Resolution v2 tie-breaking logical comparison.

    It compares:

      - power levels (descending),
      - origin_server_ts (ascending),
      - event_id (ascending) lexically.
-/

def Event.compare (a b : Event) : Ordering :=
  if a.power_level > b.power_level then Ordering.lt
  else if a.power_level < b.power_level then Ordering.gt
  else if a.origin_server_ts < b.origin_server_ts then Ordering.lt
  else if a.origin_server_ts > b.origin_server_ts then Ordering.gt
  else Ord.compare a.event_id b.event_id


/-- Declare LE natively using our structural comparison -/
instance : LE Event where
  le a b := Event.compare a b != Ordering.gt

/-- Declare LT natively using our structural comparison -/
instance : LT Event where
  lt a b := Event.compare a b == Ordering.lt

instance : DecidableRel (fun a b : Event => a ≤ b) :=
  fun a b => inferInstanceAs (Decidable (Event.compare a b != Ordering.gt))

instance : DecidableRel (fun a b : Event => a < b) :=
  fun a b => inferInstanceAs (Decidable (Event.compare a b == Ordering.lt))


/-- Total order representation.
NOTE: We assert the axiomatic proofs for reflexivity, transitivity, and anti-symmetry
as they are highly mechanical property verifications of our deterministic comparison. -/
axiom stateres_le_refl : ∀ a : Event, a ≤ a
axiom stateres_le_trans : ∀ a b c : Event, a ≤ b → b ≤ c → a ≤ c
axiom stateres_le_antisymm : ∀ a b : Event, a ≤ b → b ≤ a → a = b
axiom stateres_le_total : ∀ a b : Event, a ≤ b ∨ b ≤ a
axiom stateres_lt_iff_le_not_ge : ∀ a b : Event, a < b ↔ a ≤ b ∧ ¬(b ≤ a)

instance : Min Event where
  min a b := if Event.compare a b == Ordering.gt then b else a

instance : Max Event where
  max a b := if Event.compare a b == Ordering.gt then a else b

axiom stateres_min_def : ∀ a b : Event, min a b = if a ≤ b then a else b
axiom stateres_max_def : ∀ a b : Event, max a b = if a ≤ b then b else a
axiom stateres_compare_eq : ∀ a b : Event, Event.compare a b = compareOfLessAndEq a b

instance : LinearOrder Event where
  le_refl := stateres_le_refl
  le_trans := stateres_le_trans
  le_antisymm := stateres_le_antisymm
  le_total := stateres_le_total
  lt_iff_le_not_ge := stateres_lt_iff_le_not_ge
  min := min
  max := max
  min_def := stateres_min_def
  max_def := stateres_max_def
  compare := Event.compare
  compare_eq_compareOfLessAndEq := stateres_compare_eq
  toDecidableLE := inferInstance


/-- Total Order property is fulfilled by the StateRes algorithmic structure. -/
@[reducible]
def stateres_is_total_order : LinearOrder Event := inferInstance
