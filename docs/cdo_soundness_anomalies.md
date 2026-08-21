# CDO domination soundness — anomalies 17–20

The V2.1.1 Causal Domination Operator (`resolve/cdo.rs`) is a pre-filter:
before full state resolution runs, it drops conflicted events that a
higher-priority admin action (ban, kick, PL demotion, or join-rules
lockdown) "causally dominates" on an independent branch. It must never
change the final answer relative to running full V2.1 resolution with no
CDO at all — that's the entire point of it being a pre-filter rather than
a different algorithm. `assert_benign_convergence` in
`tests/test_critique.rs` encodes that invariant directly: `V2.1 == V2.1.1`
on every fixture that isn't specifically testing a divergence.

Four related bugs/audits came out of restoring CDO's wiring after it had
been (correctly, but silently) disconnected on `dev` for a time. All four
are cataloged as anomalies in `tests/critique_data/`, the same way every
other pathology in this suite is. This doc walks through the two that
found real bugs, with the DAG each fixture encodes.

Diagrams generated with `../dag-toolkit/viz/daggraph.py --show-auth`:
solid gray arrows are `prev_events` (timeline order), dashed purple arrows
are `auth_events` (what each event cites as its authorization).

## Anomaly 19 — demoted but still authorized

**Fixture:** `tests/critique_data/19_demoted_but_still_authorized.jsonl`
**Test:** `test_anomaly_19_demoted_but_still_authorized`
**Fix:** `sender_has_pre_demotion_pl()` in `resolve/cdo.rs`

![Anomaly 19 DAG](img/anomaly_19_demoted_but_still_authorized.png)

Priya is promoted to PL 50 (`$pl_grant_priya`), then the room forks:

- **`$pl_demote_priya`**: Alice demotes Priya back to 0. Her `auth_events`
  cite the room's _original_ PL grant (`$pl_init`), not `$pl_grant_priya`
  — a genuinely independent branch, never having seen Priya's later ban.
- **`$priya_bans_troll`**: Priya, still citing `$pl_grant_priya` in her own
  `auth_events`, bans the troll.

Neither branch is an ancestor of the other. The bug: `is_demotion()` is
`true` for _any_ `m.room.power_levels` event — it doesn't check whether
the event actually demotes anyone relative to what the target's own
authorization chain says. So CDO's domination check saw `$pl_demote_priya`
(an independent-branch admin action) and dropped _every_ one of Priya's
conflicted events wholesale, including her ban — even though her ban was
authorized against a PL grant the demotion never touched and cannot
retroactively invalidate.

`sender_has_pre_demotion_pl()` exempts a target event from demotion-based
domination when its own `auth_events` already cite a `power_levels` event
under which the sender wasn't at PL 0 — the state it was actually
authorized against.

## Anomaly 20 — concurrent ban still holds (audited, not a bug)

**Fixture:** `tests/critique_data/20_concurrent_ban_still_holds.jsonl`
**Test:** `test_anomaly_20_concurrent_ban_still_holds`

![Anomaly 20 DAG](img/anomaly_20_concurrent_ban_still_holds.png)

The structural mirror of anomaly 19, but for `is_ban_or_kick()` instead of
`is_demotion()`: Bob is banned on one branch (`$ban_bob`) while,
independently, he — still citing his PL-50 grant (`$pl_grant_bob`) — bans
Charlie on another (`$bob_bans_charlie`).

This one was audited and found **not** to need a fix. Unlike
`is_lockdown()`/`is_demotion()`, `is_ban_or_kick()`'s domination check
(`state_key == sender`) is already exact rather than a coarse
over-approximation — CDO's early drop of `$bob_bans_charlie` agrees with
what full V2.1 resolution (no CDO at all) independently arrives at: Bob
really is banned by the time full resolution reaches his own ban of
Charlie, so it correctly never takes effect either way. Charlie's own join
(against the room's public `join_rules`) wins the conflict cleanly.
Cataloged here as a checked, closed case rather than left as a bare
assertion — the same reasoning `test_anomaly_17`/`06b` used to _find_ a
bug is worth keeping on record even where it didn't find one.

## Regenerating the diagrams

```sh
python3 ../dag-toolkit/viz/daggraph.py tests/critique_data/19_demoted_but_still_authorized.jsonl \
  --show-auth --highlight priya,troll \
  --title "Anomaly 19: Demoted But Still Authorized" \
  --note "Priya's ban of troll must survive alice's independent-branch demotion" \
  -o /tmp/19.dot && dot -Tpng /tmp/19.dot -o docs/img/anomaly_19_demoted_but_still_authorized.png

python3 ../dag-toolkit/viz/daggraph.py tests/critique_data/20_concurrent_ban_still_holds.jsonl \
  --show-auth --highlight bob,charlie \
  --title "Anomaly 20: Concurrent Ban Still Holds" \
  --note "Bob's ban of charlie must not survive alice's independent-branch ban of bob" \
  -o /tmp/20.dot && dot -Tpng /tmp/20.dot -o docs/img/anomaly_20_concurrent_ban_still_holds.png
```

## See also

- `resolve/cdo.rs` module doc — the full "Soundness: domination must never
  diverge from full resolution" writeup, including anomalies 17 and 06b
  (the join-lockdown case `join_has_prior_authorization()` fixes) and the
  restricted/`knock_restricted` scope-limit finding.
