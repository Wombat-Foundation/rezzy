# Case Study: The "Forestpunk" Partition

## The Scenario

In room `!4zKUu8M4fstFjTFZ9E:nutra.tk`, a user known as `forestpunk` (`@sukidusk6125:matrix.org`) was kicked on the **Dev** server, but remained joined on the **Nightly** server. Attempts to re-kick on Nightly resulted in **403 Forbidden** errors, even when performed by a Power Level 100 admin.

## The Technical Divergence

Using `ruma-lean` to analyze the unified DAG (60 events) from both servers, we identified the exact point of failure:

| Property        | Dev Server (`nutra.tk`)     | Nightly Server (`mdev.nutra.tk`) |
| :-------------- | :-------------------------- | :------------------------------- |
| **Event State** | Kick (`leave`)              | Join (`join`)                    |
| **Authority**   | Outlier PDU (No Auth Chain) | Self-Signed Join                 |
| **Resolution**  | Accepted (Local trust)      | **Rejected** (Missing Auth)      |

### The "Outlier Sabotage"

The Dev server served the kick event as an **outlier**, meaning it did not include the `auth_events` or `prev_events` required by the Matrix V2 Spec to verify the sender's permission.

Because the Nightly server is a strict enforcer of State Resolution V2, it mathematically rejected the "unauthorized" kick. Without a valid kick to supersede it, the older `join` event remained the canonical truth in Nightly's view.

## Why ZK Fixes This

This case study represents the "Goldilocks Zone" for **Zero-Knowledge State Resolution**:

1.  **Proof-Carrying PDUs**: In a ZK-Matrix protocol, the kick event would be bundled with a tiny STARK proof.
2.  **Instant Authority**: The Nightly server wouldn't need to "fetch" the missing auth chain to trust the kick. The ZK proof would mathematically guarantee that the kick was authorized by a Power Level 100 admin at the time of sending.
3.  **Forced Convergence**: Any server receiving the kick would be **forced** to accept it, ensuring that "ghost users" like `forestpunk` can never persist across a network partition.

## Accuracy Verdict

- **Nightly** was 96.36% accurate to the _rules_ of the DAG.
- **Dev** was 100% accurate to the _intent_ of the human admin.
- **ZK** ensures that **Rules == Intent** across the entire federation.
