import RumaLean.StateRes
import Mathlib.Data.List.Basic
import Mathlib.Data.Finset.Basic

namespace RumaLean

/-- A permutation of size N. -/
structure Permutation (n : ℕ) where
  data : List ℕ
  is_perm : data.length = n ∧ (data.toFinset).card = n

/-- A Star Graph step involves swapping the first element (index 0) with the i-th element. -/
def isStarGraphStep {n : ℕ} (p1 p2 : Permutation n) : Prop :=
  ∃ i, i > 0 ∧ i < n ∧
  ∃ (val0 vali : ℕ),
    p1.data[0]? = some val0 ∧
    p1.data[i]? = some vali ∧
    p2.data = (p1.data.set 0 vali).set i val0

/-- A trace is a sequence of permutations. -/
def isValidStarGraphTrace {n : ℕ} : List (Permutation n) → Prop
  | [] => True
  | [_] => True
  | p1 :: p2 :: tail => isStarGraphStep p1 p2 ∧ isValidStarGraphTrace (p2 :: tail)

/-- The Routing Complexity (k * log n) bound.
    For a Star Graph S_n, the diameter is floor(3(n-1)/2).
    For n symbols (n! nodes), the diameter is O(n), which is O(log(nodes)). -/
def routingBound (n : ℕ) : ℕ :=
  3 * (n - 1) / 2

end RumaLean
