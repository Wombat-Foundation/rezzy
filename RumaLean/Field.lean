import Mathlib.Algebra.Ring.Basic
import Mathlib.Data.ZMod.Defs
import Mathlib.Algebra.Ring.TransferInstance

set_option linter.style.longLine false

namespace RumaLean

/-- The BabyBear prime modulus: P = 15 * 2^27 + 1 = 2013265921. -/
abbrev BABYBEAR_P : ℕ := 15 * 2^27 + 1

/-- A field element in the BabyBear prime field (P = 15 * 2^27 + 1). -/
structure BabyBear where
  val : Fin BABYBEAR_P
  deriving DecidableEq

/-- Equivalence between BabyBear and Fin P. -/
def BabyBear.equiv : BabyBear ≃ Fin BABYBEAR_P where
  toFun b := b.val
  invFun f := ⟨f⟩
  left_inv b := by cases b; rfl
  right_inv f := rfl

-- BabyBear inherits CommRing from Fin P via Equiv.commRing.
section BabyBearRing
open Fin.CommRing
instance : CommRing BabyBear := BabyBear.equiv.commRing
end BabyBearRing

end RumaLean
