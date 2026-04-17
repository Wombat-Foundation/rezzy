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
    pub event_id: BabyBear,
    pub dimension_flip: BabyBear,
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

        // Map string IDs to BabyBear compatible u32s
        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut u32_events = Vec::new();
        for id in &sorted_ids {
            let mut hasher = DefaultHasher::new();
            id.hash(&mut hasher);
            u32_events.push((hasher.finish() & 0xFFFFFFFF) as u32);
        }
        let events = &u32_events;

        if events.is_empty() {
            return Vec::new();
        }

        // Dynamically size the hypercube based on the number of events.
        let hypercube = Hypercube::new(events.len());
        let mut trace = Vec::new();

        // Initial mapping: event 0 at node 0.
        let mut current_node = 0;

        trace.push(HypercubeTraceRow {
            is_active: create_babybear(1),
            node_id: create_babybear(current_node as u32),
            event_id: create_babybear(events[0]),
            dimension_flip: create_babybear(0), // No flip for the start
        });

        for &event in events.iter().skip(1) {
            // Heuristic mapping: map event ID to a node ID within the hypercube range.
            let target_node = (event as usize) % hypercube.num_nodes;

            // Route from current_node to target_node
            let path = hypercube.get_path(current_node, target_node);

            // In a hypercube, if current_node == target_node, the path is empty.
            // We flip bit 0 and flip it back to ensure we have a valid trace step.
            if path.is_empty() {
                let dim = 0;
                current_node = hypercube.step(current_node, dim);
                trace.push(HypercubeTraceRow {
                    is_active: create_babybear(0),
                    node_id: create_babybear(current_node as u32),
                    event_id: create_babybear(0),
                    dimension_flip: create_babybear(dim as u32),
                });

                current_node = hypercube.step(current_node, dim);
                trace.push(HypercubeTraceRow {
                    is_active: create_babybear(1),
                    node_id: create_babybear(current_node as u32),
                    event_id: create_babybear(event),
                    dimension_flip: create_babybear(dim as u32),
                });
                continue;
            }

            for (step_idx, &dim) in path.iter().enumerate() {
                current_node = hypercube.step(current_node, dim);

                let is_active = if step_idx == path.len() - 1 { 1 } else { 0 };
                let current_event = if is_active == 1 { event } else { 0 };

                trace.push(HypercubeTraceRow {
                    is_active: create_babybear(is_active),
                    node_id: create_babybear(current_node as u32),
                    event_id: create_babybear(current_event),
                    dimension_flip: create_babybear(dim as u32),
                });
            }
        }

        trace
    }
}

fn create_babybear(val: u32) -> BabyBear {
    unsafe { core::mem::transmute::<u32, BabyBear>(val) }
}
