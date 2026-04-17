use crate::ctopology::Hypercube;
use crate::{lean_kahn_sort, LeanEvent, StateResVersion};
use p3_baby_bear::BabyBear;

use alloc::string::String;
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use hashbrown::HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HypercubeTraceRow {
    pub is_active: BabyBear,
    pub node_id: BabyBear,
    pub dimension_flip: BabyBear,
    // Matrix V2.1 Tie-Break Columns
    pub event_id: BabyBear,
    pub power_level: BabyBear,
    pub timestamp: BabyBear,
    // Auxiliary Cryptographic Columns (Sub-Circuit Results)
    pub is_signature_valid: BabyBear,
}

pub struct TraceCompiler {
    pub hypercube: Hypercube,
}

impl Default for TraceCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceCompiler {
    pub fn new() -> Self {
        // Defaulting to a reasonably sized hypercube for generic use.
        Self {
            hypercube: Hypercube::new(1024),
        }
    }

    /// Compiles a sequence of unsorted Matrix events into a continuous Hypercube walk.
    pub fn compile_trace(
        &self,
        unsorted_events: &HashMap<String, LeanEvent>,
        version: StateResVersion,
    ) -> Vec<HypercubeTraceRow> {
        let sorted_ids = lean_kahn_sort(unsorted_events, version);

        if sorted_ids.is_empty() {
            return Vec::new();
        }

        // Dynamically size the hypercube based on the number of events.
        let hypercube = Hypercube::new(sorted_ids.len());
        let mut trace = Vec::new();

        // Initial mapping: event 0 at node 0.
        let mut current_node = 0;

        let first_id = &sorted_ids[0];
        let first_ev = unsorted_events.get(first_id).unwrap();

        trace.push(HypercubeTraceRow {
            is_active: create_babybear(1),
            node_id: create_babybear(current_node as u32),
            dimension_flip: create_babybear(0),
            event_id: hash_event_id(first_id),
            power_level: create_babybear(first_ev.power_level as u32),
            timestamp: create_babybear((first_ev.origin_server_ts % 0xFFFFFFFF) as u32),
            is_signature_valid: create_babybear(1), // Assume valid for start
        });

        for id in sorted_ids.iter().skip(1) {
            let ev = unsorted_events.get(id).unwrap();
            let hashed_id = hash_event_id(id);

            // In a real ZK prover, this would call a dedicated Ed25519 sub-circuit.
            // Here we simulate the successful result of that check.
            let sig_valid = 1;

            // Heuristic mapping: map hashed ID to a node ID within the hypercube range.
            let target_node = (unsafe { std::mem::transmute_copy::<BabyBear, u32>(&hashed_id) }
                as usize)
                % hypercube.num_nodes;

            // Route from current_node to target_node
            let path = hypercube.get_path(current_node, target_node);

            if path.is_empty() {
                let dim = 0;
                current_node = hypercube.step(current_node, dim);
                trace.push(HypercubeTraceRow {
                    is_active: create_babybear(0),
                    node_id: create_babybear(current_node as u32),
                    dimension_flip: create_babybear(dim as u32),
                    event_id: create_babybear(0),
                    power_level: create_babybear(0),
                    timestamp: create_babybear(0),
                    is_signature_valid: create_babybear(0),
                });

                current_node = hypercube.step(current_node, dim);
                trace.push(HypercubeTraceRow {
                    is_active: create_babybear(1),
                    node_id: create_babybear(current_node as u32),
                    dimension_flip: create_babybear(dim as u32),
                    event_id: hashed_id,
                    power_level: create_babybear(ev.power_level as u32),
                    timestamp: create_babybear((ev.origin_server_ts % 0xFFFFFFFF) as u32),
                    is_signature_valid: create_babybear(sig_valid),
                });
                continue;
            }

            for (step_idx, &dim) in path.iter().enumerate() {
                current_node = hypercube.step(current_node, dim);

                let is_active = if step_idx == path.len() - 1 { 1 } else { 0 };
                let (curr_id, curr_pl, curr_ts, curr_sig) = if is_active == 1 {
                    (
                        hashed_id,
                        ev.power_level as u32,
                        (ev.origin_server_ts % 0xFFFFFFFF) as u32,
                        sig_valid,
                    )
                } else {
                    (create_babybear(0), 0, 0, 0)
                };

                trace.push(HypercubeTraceRow {
                    is_active: create_babybear(is_active),
                    node_id: create_babybear(current_node as u32),
                    dimension_flip: create_babybear(dim as u32),
                    event_id: curr_id,
                    power_level: create_babybear(curr_pl),
                    timestamp: create_babybear(curr_ts),
                    is_signature_valid: create_babybear(curr_sig),
                });
            }
        }

        trace
    }
}

/// Helper to hash a Matrix Event ID into a BabyBear field element.
fn hash_event_id(id: &str) -> BabyBear {
    use core::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    id.hash(&mut hasher);
    create_babybear((hasher.finish() & 0xFFFFFFFF) as u32)
}

fn create_babybear(val: u32) -> BabyBear {
    unsafe { core::mem::transmute::<u32, BabyBear>(val) }
}
