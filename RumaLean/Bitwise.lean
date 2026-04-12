import Mathlib.Data.Nat.Bitwise
import Mathlib.Tactic.Linarith

namespace RumaLean

def popcount (n : ℕ) : ℕ :=
  if h : n = 0 then 0
  else (n % 2) + popcount (n / 2)
termination_by n
decreasing_by omega -- `omega` natively proves (n / 2 < n) for n > 0!

@[simp] theorem popcount_zero : popcount 0 = 0 := by
  unfold popcount
  simp

@[simp] theorem popcount_one : popcount 1 = 1 := by
  unfold popcount
  simp -- This solves the goal; any following tactics will cause the error.

theorem popcount_mul_two (n : ℕ) : popcount (2 * n) = popcount n := by
  obtain rfl | hn := eq_or_ne n 0
  · simp
  · rw [popcount] -- Use rw instead of unfold to avoid over-expanding
    split_ifs with h
    · omega -- Handles 2 * n = 0 case
    · have h_mod : 2 * n % 2 = 0 := Nat.mul_mod_right 2 n
      have h_div : 2 * n / 2 = n := Nat.mul_div_right n (by omega)
      rw [h_mod, h_div, Nat.zero_add]

theorem popcount_pow2 (n : ℕ) : popcount (2^n) = 1 := by
  induction n with
  | zero =>
    unfold popcount
    simp
  | succ n ih => rw [Nat.pow_succ, Nat.mul_comm, popcount_mul_two, ih]

end RumaLean
