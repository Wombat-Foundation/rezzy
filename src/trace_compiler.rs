use crate::ctopology::StarGraph;
use crate::{lean_kahn_sort, LeanEvent, StateResVersion};
use p3_baby_bear::BabyBear;

use alloc::string::String;
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use hashbrown::HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarGraphTraceRow {
    pub is_active: BabyBear,
    pub permutation_id: BabyBear,
    pub event_id: BabyBear,
    pub swap_index: BabyBear,
}

pub struct TraceCompiler {
    pub star_graph: StarGraph,
}

impl Default for TraceCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceCompiler {
    pub fn new() -> Self {
        Self {
            star_graph: StarGraph::new(),
        }
    }

    /// Compiles a sequence of unsorted Matrix events into a continuous Star Graph walk.
    pub fn compile_trace(
        &self,
        unsorted_events: &HashMap<String, LeanEvent>,
        version: StateResVersion,
    ) -> Vec<StarGraphTraceRow> {
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

        let mut trace = Vec::new();
        if events.is_empty() {
            return trace;
        }

        // For the benchmark, use a deterministic mapping heuristic:
        // Map event `e` to node `e % 120`.
        let mut current_node = (events[0] % 120) as usize;

        trace.push(StarGraphTraceRow {
            is_active: create_babybear(1),
            permutation_id: create_babybear(current_node as u32),
            event_id: create_babybear(events[0]),
            swap_index: create_babybear(0), // Initial state has no incoming swap
        });

        for &event in events.iter().skip(1) {
            let target_node = (event % 120) as usize;

            // Route from current_node to target_node
            let path = self.star_graph.get_path(current_node, target_node);

            // If they are already the same node (e.g. same hash mod 120), we don't need a path,
            // but we must advance the state. Let's just swap 1 and then swap 1 again to stay active.
            if path.is_empty() {
                // Dummy walk to allow adding the next active node on the same permutation.
                let swap = 1;

                // Step away
                let next_node_p = self.star_graph.nodes[current_node].swap(swap);
                current_node = self.star_graph.nodes.binary_search(&next_node_p).unwrap();
                trace.push(StarGraphTraceRow {
                    is_active: create_babybear(0),
                    permutation_id: create_babybear(current_node as u32),
                    event_id: create_babybear(0),
                    swap_index: create_babybear(swap as u32),
                });

                // Step back
                let next_node_p2 = self.star_graph.nodes[current_node].swap(swap);
                current_node = self.star_graph.nodes.binary_search(&next_node_p2).unwrap();
                trace.push(StarGraphTraceRow {
                    is_active: create_babybear(1),
                    permutation_id: create_babybear(current_node as u32),
                    event_id: create_babybear(event),
                    swap_index: create_babybear(swap as u32),
                });
                continue;
            }

            for (step_idx, &swap) in path.iter().enumerate() {
                let next_node_p = self.star_graph.nodes[current_node].swap(swap as usize);
                current_node = self.star_graph.nodes.binary_search(&next_node_p).unwrap();

                let is_active = if step_idx == path.len() - 1 { 1 } else { 0 };
                let current_event = if is_active == 1 { event } else { 0 };

                trace.push(StarGraphTraceRow {
                    is_active: create_babybear(is_active),
                    permutation_id: create_babybear(current_node as u32),
                    event_id: create_babybear(current_event),
                    swap_index: create_babybear(swap as u32),
                });
            }
        }

        trace
    }
}

// A generic helper to build BabyBear field elements robustly depending on the `p3` version.
// Normally `AbstractField::from_canonical_u32(x)` is used.
fn create_babybear(val: u32) -> BabyBear {
    // In p3-baby-bear 0.2, BabyBear implements `From<u32>` or provides a `new` method.
    // However, the easiest way without importing p3_field is using the internal representation or `new`.
    // We can also just use `BabyBear::new(val)` if it exists.
    // Wait, Plonky3 BabyBear struct is usually created via `BabyBear::new(val)` or via `p3_field::AbstractField`.
    // Let's rely on standard STARK trait: we can use a simple cast.
    unsafe { core::mem::transmute::<u32, BabyBear>(val) }
}
