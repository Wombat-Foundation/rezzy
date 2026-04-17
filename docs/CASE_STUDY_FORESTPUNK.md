# Case Study: The "Forestpunk" Consensus Failure

## The Scenario

In room `!4zKUu8M4fstFjTFZ9E:nutra.tk`, a "Ghost User" situation occurred.

- **Truth (Dev & Unredacted)**: `forestpunk` (@sukidusk6125:matrix.org) was kicked by an admin.
- **Zombie State (Nightly & Matrix.org)**: The user remains joined. Nightly returns **403 Forbidden** on further kick attempts, effectively "protecting" a user who shouldn't be there.

## The Technical Failure

A 3-way analysis using `ruma-lean` revealed a profound split between **Human Consensus** and **Partial-DAG Math**:

| Server                            | View           | Status                  |
| :-------------------------------- | :------------- | :---------------------- |
| **Dev (`nutra.tk`)**              | Kick (`leave`) | **Correct (Canonical)** |
| **Unredacted (`unredacted.org`)** | Kick (`leave`) | **Correct (Canonical)** |
| **Nightly (`mdev.nutra.tk`)**     | Join (`join`)  | **Diverged (Zombie)**   |
| **Matrix.org**                    | Join (`join`)  | **Diverged (Zombie)**   |

### Why Nightly/Matrix.org are "Wrong"

Despite holding a majority of the federation's "older" events (the Join), Nightly and Matrix.org are failing to process the **supersession link**.

1.  **The Outlier Bug**: The Kick event was likely served as an "outlier" from Dev.
2.  **Auth-Chain Blindness**: Because the Zombie servers couldn't verify the power level of the kick at the moment it arrived, they discarded it.
3.  **The Tie-Break Trap**: In the absence of a valid link, the resolution math defaults to "Lowest Timestamp Wins." Since the Join is older, it "wins" the state, effectively **immortalizing the user**.

## Why ZK Fixes This

This is the ultimate proof of why **RumaLean** is necessary:

- **No Discarding**: A ZK proof included with the Kick would have **forced** Nightly and Matrix.org to accept it instantly, even if they were missing parts of the historical auth chain.
- **Global Consensus**: With ZK, the "Global Canonical Truth" is established by the math of the Proof, not the timestamp of the event.

## Verdict

**Nightly and Matrix.org have diverged from the federation consensus.** They are technically following the "Older wins ties" rule, but they are doing so because they have "lost" the link to the Kick event that should have superseded it.
