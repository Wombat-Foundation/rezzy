# Rezzy V2.1.1 and MSC4242 security comparison

This note records what the traversal tests in `tests/unit/test_traversal.rs`
actually establish, how that compares with the local Complement MSC4242 suite
(`../complement/tests/msc4242`), and what could be claimed for a homeserver such
as Synapse _if_ it implemented that proposed room version.

It is deliberately not a claim that a passing unit test, or a passing Complement
suite, proves a security property of another implementation. Rezzy's tests
exercise an in-process resolver. Complement is an integration suite run against
one concrete homeserver. MSC4242 is still proposed and `V2.1.1` is
Rezzy-private: it is not a Matrix-specified room version.

## Terms and current implementation status

- **Stock V2.1 / room version 12** is Rezzy's MSC4297 implementation.
- **V2.1.1 / `12.1`** is an experimental Rezzy-only variant. It has a
  transitive, memoized auth-context walk; narrows an otherwise local-auth
  fallback during the power phase; and screens a non-power event whose sender is
  already resolved as banned. The last two are gated by
  `StateResVersion::has_ban_evasion_hardening()`.
- The previous V2.1.1 CDO causal-domination pre-filter is **not live**. It was
  unsound: an auth-invalid forged administrative event could erase a valid
  concurrent event and cause a federation divergence. The live path instead
  applies the actual banned-sender predicate after the power phase. See
  `docs/cdo_soundness_anomalies.md`.
- **V2.2 / `org.matrix.msc4242.12`** is experimental. Rezzy validates and walks
  a State DAG and derives required auth events from state-before. This is not
  evidence that a complete production MSC4242 federation implementation exists.

## Result matrix

“Yes” means the listed Rezzy test asserts the outcome in the current resolver.
It does not mean that the behavior is a published Matrix guarantee, nor that the
supplied event would pass all PDU/federation validation.

| Traversal test / issue                                                                                                                                                                    | Current Rezzy V2.1.1                                  | Why                                                                                                                                                                                                                                                                                  | MSC4242 Complement coverage                                                                                                                                                                                                                             | A theoretical MSC4242 Synapse                                                                                                                                                                                                                    |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `v2_1_vs_v2_1_1_recursive_auth_lookup`                                                                                                                                                    | **Yes, directly**                                     | V2.1.1 recursively gathers transitive `auth_events`; V2.1 only uses immediate citations in this lookup path.                                                                                                                                                                         | No exact case; E2E, `/send_join`, and GME tests require recursive **State-DAG** traversal, not a missing transitive auth citation.                                                                                                                      | A valid State DAG is better specified here: derive auth from the event's state-before instead of trusting a legacy supplied list. A malformed/disconnected DAG must be rejected rather than recovered from.                                      |
| `v2_1_1_xfail_disconnected_auth`                                                                                                                                                          | **No, intentionally**                                 | The test expects rejection: a required PL is disconnected from the cited auth graph. Recursive walking cannot invent an unreachable authority event.                                                                                                                                 | Only adjacent invalid-DAG cases (`SJ02`, faulty SEND cases).                                                                                                                                                                                            | Not a blanket fix. It accepts only if the validated State DAG actually reconstructs the needed state; otherwise it should reject/fetch missing DAG data.                                                                                         |
| `v2_1_1_ancient_prev_event_allowed`                                                                                                                                                       | **Only at resolver level**                            | The test shows `resolve_iterative_sort` does not consult `prev_events`; valid supplied auth context makes the name event win. It does not test ingress validation.                                                                                                                   | No equivalent acceptance test. `STATE02` tests that old `prev_state_events` do not update current state.                                                                                                                                                | Not necessarily. MSC4242 still permits a timeline `prev_events` history, but requires valid `prev_state_events` for state/auth. An old `prev_events` alone cannot establish authorization.                                                       |
| `v2_1_1_anomaly_02_admin_lockout`                                                                                                                                                         | **Yes**                                               | Resolved invite-only join rules cause the concurrent public self-join to fail.                                                                                                                                                                                                       | **Direct:** `STATE07` has the same lockdown-versus-public-join merge and requires the join to disappear.                                                                                                                                                | Yes, as tested by `STATE07`; this is the clearest implementation-level evidence if Synapse passed that test.                                                                                                                                     |
| `v2_1_1_anomaly_06b_ghost_moderator`                                                                                                                                                      | **Yes, but it preserves the surprising split result** | The join is rejected under the resolved invite rule, while the independent promotion and ban remain. This does _not_ solve the “ghost moderator” semantic; it defines/preserves that outcome.                                                                                        | **Partial:** `STATE07` proves the join rejection. `STATE05` proves a pre-demotion concurrent moderator ban can survive. No test combines them.                                                                                                          | Unknown without a dedicated test. MSC4242's `STATE05` suggests it deliberately preserves historically authorized concurrent actions, so it should not be assumed to delete the promotion/ban transitively.                                       |
| `v2_1_1_cve_demotion_evasion`                                                                                                                                                             | **Yes, for the synthetic resolver case**              | The demotion resolves first and the under-powered name event is rejected despite omitting the demotion from its local auth list.                                                                                                                                                     | **Related:** `STATE09` makes a demotion defeat Bob's concurrent PL grant to Eve; it does not submit the omitted-auth name-event attack.                                                                                                                 | Potentially better defined only when the State DAG places the event after the demotion. For a genuinely concurrent event authorized before demotion, `STATE05` says the privileged action survives; MSC4242 is not a retroactive-demotion model. |
| `v2_1_flaw_concurrent_ban_evasion`                                                                                                                                                        | **Yes**                                               | The ban resolves in the power phase and V2.1.1 screens Bob's concurrent non-power name event as banned. The current V2.1 path also rejects this test's progressive-ban shape through normal iterative auth.                                                                          | **Direct:** `STATE03` bans Bob on one branch, receives Bob's pre-ban-branch name event, and requires the old name to remain current. `SEND01` rejects attempts after a ban across all old/new `prev_events`/`prev_state_events` combinations.           | Yes for the tested State-DAG shapes. It is stronger at ingress because the server validates the State-DAG ancestry, but it is not proof for arbitrary graph shapes.                                                                              |
| `v2_1_spec_compliant_step_4_supplementation`                                                                                                                                              | **Yes**                                               | Resolved membership is used while authorizing the non-power topic; the ban wins and Bob's topic is rejected.                                                                                                                                                                         | **Direct outcome:** `STATE03`; not the same internal Step-4 implementation.                                                                                                                                                                             | Same expected outcome in the tested shape.                                                                                                                                                                                                       |
| `v2_1_1_power_phase_ban_supplementation`, `v2_1_1_ban_supplementation_return_path`, `v2_1_1_power_phase_membership_bypass_prevention`, `v2_1_rejects_pl_from_progressively_banned_sender` | **Yes**                                               | The tests assert that a progressive resolved ban defeats the banned sender's privileged PL event. The last test explicitly establishes that stock V2.1 reaches the same final result. V2.1.1's distinct fallback restriction is internal hardening, not a different promised result. | **Strong semantic overlap:** `STATE06` rejects Bob's concurrent ban of Charlie once Bob's own ban wins. `SEND01` rejects banned senders' message and membership events. Neither uses a competing PL event or attests to Rezzy's fallback-return branch. | Likely the same outcome for the tested membership actions. Whether it applies identically to every PL-event construction needs an explicit MSC4242 test.                                                                                         |
| `v2_1_1_creator_in_users_map_rejected`                                                                                                                                                    | **Yes**                                               | This is V12 auth rule 10.4: creators/additional creators may not appear in a PL `users` map.                                                                                                                                                                                         | None found.                                                                                                                                                                                                                                             | MSC4242 inherits V12-era creator semantics in Rezzy, but the Complement suite has no test proving this rule for an implementation.                                                                                                               |
| `v2_1_strictness_future_v2_2_should_pass`                                                                                                                                                 | **No current V2.1/V2.1.1 fix**                        | The test is explicitly speculative: its join is rejected because its legacy auth list omits join rules.                                                                                                                                                                              | No direct test.                                                                                                                                                                                                                                         | This is exactly the sort of problem State DAGs are intended to avoid: auth can be derived from state-before. It only passes if that State DAG is complete and validates; calling it “should pass” requires a concrete valid DAG fixture.         |
| `v2_2_event_id_tiebreak`                                                                                                                                                                  | **Yes, in Rezzy V2.2 resolver**                       | Equal PL and timestamp candidates use the stated event-ID last-write-wins tie-break.                                                                                                                                                                                                 | No state-resolution analogue. `GME03` orders `/get_missing_events` traversal by event ID, which is a different rule.                                                                                                                                    | Unknown until a state-resolution tie-break test is added and run.                                                                                                                                                                                |

## What is actually “better”?

MSC4242 is not automatically better merely because it has a State DAG. It
changes the evidence available to authorization:

1. State events name their state parents through `prev_state_events`.
2. The receiver validates the DAG (parents exist, are state events, are in the
   room, are not rejected, fan-out is bounded, and non-create state events have
   parents).
3. It computes state-before and derives the auth events required for the event
   from that state, then applies ordinary authorization.

That is better than a bare `auth_events`-list resolver for the specific
incomplete-auth/disconnected-auth ambiguity: authority is reconstructed from a
validated causal state graph rather than guessed or silently supplemented from
unrelated context. It also provides explicit rejection and recovery behavior for
missing or rejected State-DAG ancestors.

It does **not** make all concurrent-authority questions disappear, but it does
make their answer deterministic. Given one complete, valid State DAG, the
State-DAG `state_at(e)` calculation is a pure deterministic function of that
DAG: it yields one state-before for `e`; the derived auth set and normal auth
check then yield one verdict, accepted or rejected. A receiver must not choose
between a local auth list and an unrelated branch's state.

`STATE05` is not an exception to determinism. It specifies that Priya's ban is
accepted because the deterministic state-before of that event contains her
pre-demotion authority, even though the deterministic state after a later merge
also contains her demotion. Conversely, `STATE06` and `STATE07` specify DAG
shapes where the deterministically resolved state-before makes the concurrent
action fail. Thus the remaining question is which exact causal DAG an event
names and whether it validates—not an implementation-dependent choice or a
generic “latest admin event wins” rule.

Therefore the defensible comparison is:

- Rezzy V2.1/V2.1.1 currently demonstrates the listed resolver outcomes. V2.1.1
  adds local hardening and a transitive auth lookup, but its retired CDO must
  not be described as a solution.
- The local Complement suite directly attests three principal outcomes:
  concurrent-ban state suppression (`STATE03`), progressive ban dominance
  (`STATE06`), and concurrent lockdown rejection (`STATE07`). It only partly
  covers demotion and does not cover creator-in-PL, V2.2 state-resolution ID
  tie-breaks, or the exact legacy-auth-list attack.
- A theoretical Synapse that passes the suite would provide stronger evidence
  for those individual State-DAG scenarios, not a proof that it solves every
  Rezzy fixture. Claims beyond those scenarios need a new Complement test and an
  actual run against that Synapse build.

## Added test: derivation vs. a flat legacy auth list

`tests/unit/test_state_dag.rs::test_v2_2_derives_auth_from_single_state_parent_citation`
is the V2.2 companion to `test_v2_1_strictness_future_v2_2_should_pass` in
`test_traversal.rs`. It runs the full path — `compute_state_before_from_dag` →
`derive_auth_events_from_state_dag` → `check_auth_with_context` — for a member
join that cites only its one true `prev_state_events` parent, and shows the
derived auth set (power_levels and join_rules, neither cited directly) is both
correct and sufficient to authorize the event.

It does not literally reproduce the V2.1 "omitted one entry from a flat
auth_events list" bug, because V2.2 has no such flat list for a client to
under-populate: `prev_state_events` names state parents, not required auth
types, and the receiver derives auth from the resulting `state_before` itself.
That structural difference — not a stricter validator — is why the class of bug
in the V2.1 fixture has no direct V2.2 analogue.

## Known gap: DAG connectivity vs. DAG honesty (applies to both V2.1.1 and V2.2)

Both `validate_state_dag_ancestors` (V2.2) and the plain BFS in
`compute_local_auth` (V2.1.1) only ever reason about the local map of events
handed to them. A completeness check — V2.2's hard `IncompleteDag` error, or
V2.1.1's absent-tuple default-deny — proves the _local_ DAG is connected (or
isn't). Neither proves the sender's claimed DAG is _exhaustive_: a malicious
or buggy sender can omit a legitimate concurrent branch entirely, and the
receiver's local view will look complete — connected back to `m.room.create`,
no missing ancestors — while still being smaller than the room's real history.

That is a different problem from the connectivity gap above (DAG _honesty_,
not DAG _connectivity_), and V2.2's state-derivation design does not close
it: deriving auth from `state_before` only helps once the receiver already
has the right ancestors in hand. Whether it has all of them is bounded by
ordinary federation event-fetching/backfill (`/get_missing_events`,
`get_missing_state_events`, and the room's real DAG as held by other
servers), not by anything a local completeness check can catch. No local
validator — in either V2.1.1 or V2.2 — can distinguish "the sender's DAG is
this small" from "the receiver hasn't fetched everything yet."

## Source pointers

- Rezzy V2.1.1 gates: `src/basespec/rezzy_types.rs` and
  `src/resolve/iterative.rs`.
- Transitive auth lookup: `src/state/at.rs`.
- State-DAG validation and derived auth: `src/state/dag.rs` and
  `tests/unit/test_state_dag.rs`.
- Complement scenarios: `../complement/tests/msc4242/msc4242_state_test.go`
  (`STATE03`, `STATE05`, `STATE06`, `STATE07`, and `STATE09`) and
  `msc4242_send_test.go` (`SEND01`).
