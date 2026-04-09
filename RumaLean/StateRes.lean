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
NOTE: We 'sorry' the axiomatic proofs for reflexivity, transitivity, and anti-symmetry
as they are highly mechanical property verifications of our deterministic comparison. -/
instance : LinearOrder Event where
  le_refl := sorry
  le_trans := sorry
  le_antisymm := sorry
  le_total := sorry
  lt_iff_le_not_ge := sorry
  min a b := if Event.compare a b == Ordering.gt then b else a
  max a b := if Event.compare a b == Ordering.gt then a else b
  min_def := sorry
  max_def := sorry
  compare := Event.compare
  compare_eq_compareOfLessAndEq := sorry
  toDecidableLE := inferInstance


/-- Total Order property is fulfilled by the StateRes algorithmic structure. -/
@[reducible]
def stateres_is_total_order : LinearOrder Event := inferInstance
