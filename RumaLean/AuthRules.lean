import RumaLean.StateRes

namespace RumaLean

set_option linter.style.longLine false

/-!
# Authorization Rules (Matrix Spec §10.4)

Formalizing the core security invariant of Matrix: auth decisions are always
calculated at the `prev_events` state, never the current global state.
This prevents retroactive authorization tampering in the DAG.
-/

/-- Membership status in a Matrix room. -/
inductive Membership where
  | join
  | leave
  | ban
  | invite
  | knock
  deriving DecidableEq, Repr

/-- An authorization decision for a single event. -/
inductive AuthDecision where
  | accept
  | reject (reason : String)
  deriving DecidableEq, Repr

/-- The room state relevant to authorization decisions.
    Parameterized on the Event type from StateRes. -/
structure AuthState where
  membership : Event → Option Membership
  powerLevel : Event → ℕ        -- sender's power level
  requiredPL : Event → ℕ        -- required PL for this event

/-- An event is authorized if the sender is joined, not banned,
    and has sufficient power level. -/
def isAuthorized (state : AuthState) (e : Event) : AuthDecision :=
  match state.membership e with
  | none => .reject "sender has no membership record"
  | some .ban => .reject "sender is banned"
  | some .join =>
    if state.powerLevel e ≥ state.requiredPL e
    then .accept
    else .reject "insufficient power level"
  | some .leave => .reject "sender has left the room"
  | some .invite => .reject "sender is only invited, not joined"
  | some .knock => .reject "sender is only knocking, not joined"

/-!
## Auth Locality Theorem

Authorization of event `e` depends only on the state at `e`'s `prev_events`,
not on any future state. This is formalized as: if two states agree on the
relevant membership and power level for an event's sender, they produce the
same authorization decision.
-/

/-- Two auth states agree on the relevant fields for event `e`. -/
def authStateAgreeOn (s1 s2 : AuthState) (e : Event) : Prop :=
  s1.membership e = s2.membership e ∧
  s1.powerLevel e = s2.powerLevel e ∧
  s1.requiredPL e = s2.requiredPL e

/-- Auth Locality: if two states agree on the relevant fields for an event,
    they produce the same authorization decision. -/
theorem auth_locality (s1 s2 : AuthState) (e : Event)
    (h : authStateAgreeOn s1 s2 e) :
    isAuthorized s1 e = isAuthorized s2 e := by
  unfold isAuthorized authStateAgreeOn at *
  obtain ⟨h_mem, h_pl, h_req⟩ := h
  rw [h_mem, h_pl, h_req]

/-- Auth Monotonicity: a ban at any point invalidates all future events
    from that user, as long as the ban is not overridden.
    Formalized as: if the state says a user is banned, the auth decision
    is always reject, regardless of power level. -/
theorem ban_always_rejects (state : AuthState) (e : Event)
    (h_ban : state.membership e = some .ban) :
    isAuthorized state e = .reject "sender is banned" := by
  unfold isAuthorized
  rw [h_ban]

end RumaLean
