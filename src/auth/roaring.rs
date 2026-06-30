//! Fast auth chain operations using `roaring` bitmaps.
//!
//! [`AuthGraph`] pre-computes a compressed, topologically-ordered representation
//! of the auth DAG. Each event's full transitive auth chain is stored as a
//! `RoaringBitmap`, enabling `O(1)` ancestor queries via bitwise intersection.
//!
//! This is used for fast auth-chain difference computations in state resolution.

use crate::HashMap;
use crate::LeanEvent;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use roaring::RoaringBitmap;

/// A topologically-ordered auth DAG with pre-computed transitive reachability bitmaps.
///
/// Each event is assigned a dense integer index (topological order), and its
/// full auth chain is represented as a `RoaringBitmap`. Checking whether
/// event A is in event B's auth chain is a single `bitmap.contains(idx)` call.
pub struct AuthGraph {
    /// Maps event ID strings to their dense topological index.
    pub id_to_index: HashMap<String, u32>,
    /// Maps dense indices back to event ID strings.
    pub index_to_id: Vec<String>,
    /// Per-event bitmaps: `auth_bitmaps[i]` contains the indices of all
    /// transitive auth ancestors of event `i`.
    pub auth_bitmaps: Vec<RoaringBitmap>,
}

impl AuthGraph {
    /// Build the `AuthGraph` topological structure.
    ///
    /// # Panics
    ///
    /// Will panic if any internal graph invariants are violated during topological sorting.
    #[must_use]
    pub fn build(sort_context: &HashMap<String, LeanEvent>) -> Self {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();

        for (id, ev) in sort_context {
            in_degree.entry(id.as_str()).or_insert(0);
            for auth_id in &ev.auth_events {
                if sort_context.contains_key(auth_id.as_str()) {
                    adjacency
                        .entry(auth_id.as_str())
                        .or_default()
                        .push(id.as_str());
                    let val = in_degree.entry(id.as_str()).or_insert(0);
                    *val = val.saturating_add(1);
                }
            }
        }

        let mut queue = VecDeque::new();
        for (id, &deg) in &in_degree {
            if deg == 0 {
                queue.push_back(*id);
            }
        }

        let mut sorted = Vec::with_capacity(sort_context.len());
        while let Some(id) = queue.pop_front() {
            sorted.push(id);
            if let Some(children) = adjacency.get(id) {
                for child in children {
                    let deg = in_degree.get_mut(child).unwrap();
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push_back(*child);
                    }
                }
            }
        }

        let mut id_to_index = HashMap::with_capacity(sorted.len());
        let mut index_to_id = Vec::with_capacity(sorted.len());
        for (idx, &id) in sorted.iter().enumerate() {
            id_to_index.insert(id.to_string(), u32::try_from(idx).unwrap());
            index_to_id.push(id.to_string());
        }

        let mut auth_bitmaps = vec![RoaringBitmap::new(); sorted.len()];
        for (idx, &id) in sorted.iter().enumerate() {
            let mut bitmap = RoaringBitmap::new();
            if let Some(ev) = sort_context.get(id) {
                for auth_id in &ev.auth_events {
                    if let Some(&p_idx) = id_to_index.get(auth_id) {
                        bitmap |= &auth_bitmaps[p_idx as usize];
                        bitmap.insert(p_idx);
                    }
                }
            }
            auth_bitmaps[idx] = bitmap;
        }

        Self {
            id_to_index,
            index_to_id,
            auth_bitmaps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_graph_build() {
        let mut sort_context = HashMap::new();

        // Create events:
        // A is the creator / pl event (no auth events)
        // B auths with A
        // C auths with B
        let ev_a = LeanEvent {
            event_id: "A".to_string(),
            event_type: "m.room.create".to_string(),
            auth_events: vec![],
            ..Default::default()
        };
        let ev_b = LeanEvent {
            event_id: "B".to_string(),
            event_type: "m.room.member".to_string(),
            auth_events: vec!["A".to_string()],
            ..Default::default()
        };
        let ev_c = LeanEvent {
            event_id: "C".to_string(),
            event_type: "m.room.message".to_string(),
            auth_events: vec!["B".to_string()],
            ..Default::default()
        };

        sort_context.insert("A".to_string(), ev_a);
        sort_context.insert("B".to_string(), ev_b);
        sort_context.insert("C".to_string(), ev_c);

        let graph = AuthGraph::build(&sort_context);

        assert_eq!(graph.id_to_index.len(), 3);
        assert_eq!(graph.index_to_id.len(), 3);

        let idx_a = graph.id_to_index["A"];
        let idx_b = graph.id_to_index["B"];
        let idx_c = graph.id_to_index["C"];

        // Verify topological sorting holds (A is parent, so it should be processed before B, B before C)
        assert!(idx_a < idx_b);
        assert!(idx_b < idx_c);

        // Verify auth bitmaps
        let bitmap_a = &graph.auth_bitmaps[idx_a as usize];
        let bitmap_b = &graph.auth_bitmaps[idx_b as usize];
        let bitmap_c = &graph.auth_bitmaps[idx_c as usize];

        // A has no auth events
        assert!(bitmap_a.is_empty());

        // B has A as auth event
        assert!(bitmap_b.contains(idx_a));
        assert_eq!(bitmap_b.len(), 1);

        // C has B as auth event, and B transitively has A
        assert!(bitmap_c.contains(idx_b));
        assert!(bitmap_c.contains(idx_a));
        assert_eq!(bitmap_c.len(), 2);
    }
}
