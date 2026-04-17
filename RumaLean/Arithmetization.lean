import Mathlib.Algebra.Ring.Basic
import Mathlib.Tactic.Ring

namespace RumaLean.Arithmetization

/-!
# Arithmetization Soundness
We formalize the bridge between pure Matrix logic and the algebraic constraints
used in the STARK prover. STARKs operate over Finite Fields (like BabyBear),
which we abstract as a Commutative Ring `F`.
-/

variable {F : Type} [CommRing F] [IsDomain F]

/-!
## 1. The Boolean Constraint
Forces a value in the trace to be strictly 0 or 1 (e.g., `is_active`).
Polynomial: x * (x - 1) = 0
-/
def is_bool_poly (x : F) : Prop := x * (x - 1) = 0

/-- PROOF OF SOUNDNESS: The polynomial perfectly restricts the value to {0, 1}. -/
theorem bool_poly_soundness (x : F) : is_bool_poly x ↔ (x = 0 ∨ x = 1) := by
  unfold is_bool_poly
  rw [mul_eq_zero, sub_eq_zero]

/-!
## 2. The V2.1 Tie-Breaker Constraint (Lexicographical Multiplexer)
If `is_a_winner` is 1, the output must be `a_val`.
If `is_a_winner` is 0, the output must be `b_val`.
Polynomial: Winner = is_a_winner * a_val + (1 - is_a_winner) * b_val
-/
def tie_break_poly (is_a_winner a_val b_val : F) : F :=
  is_a_winner * a_val + (1 - is_a_winner) * b_val

/-- PROOF OF SOUNDNESS: The polynomial perfectly acts as an algebraic if/else statement. -/
theorem tie_break_soundness (is_a_winner a_val b_val : F) (h_bool : is_a_winner = 0 ∨ is_a_winner = 1) :
    (is_a_winner = 1 → tie_break_poly is_a_winner a_val b_val = a_val) ∧
    (is_a_winner = 0 → tie_break_poly is_a_winner a_val b_val = b_val) := by
  constructor
  · intro h; rw [h]; unfold tie_break_poly; ring
  · intro h; rw [h]; unfold tie_break_poly; ring

/-!
## 3. The Hypercube Padding Constraint
Ensures that inactive "padding" nodes in the hypercube perfectly preserve the current state.
Polynomial: NextState = is_active * mutated_state + (1 - is_active) * current_state
-/
def state_transition_poly (is_active current_state mutated_state : F) : F :=
  is_active * mutated_state + (1 - is_active) * current_state

/-- PROOF OF SOUNDNESS: Dummy nodes do not alter the state. -/
theorem padding_node_preserves_state (is_active current_state mutated_state : F) :
    is_active = 0 → state_transition_poly is_active current_state mutated_state = current_state := by
  intro h
  rw [h]
  unfold state_transition_poly
  ring

end RumaLean.Arithmetization
