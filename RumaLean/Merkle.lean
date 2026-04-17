import RumaLean.StateRes
import RumaLean.Field

namespace RumaLean

structure Hash where
  val : List BabyBear

axiom zk_hash (e : Event) : Hash

structure MerklePath where
  path : List Hash

inductive MerkleTree where
  | leaf (h : Hash)
  | node (left right : MerkleTree) (h : Hash)

def merkleRoot : MerkleTree → Hash
  | .leaf h => h
  | .node _ _ h => h

def verify_inclusion (_e : Event) (_root : Hash) (_path : MerklePath) : Prop :=
  sorry

theorem merkle_soundness (e : Event) (root : Hash) (p : MerklePath) :
    verify_inclusion e root p → ∃ (S : Finset Event), e ∈ S := by
  sorry

end RumaLean
