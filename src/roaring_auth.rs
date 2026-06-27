use crate::HashMap;
use crate::LeanEvent;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use roaring::RoaringBitmap;

pub struct AuthGraph {
    pub id_to_index: HashMap<String, u32>,
    pub index_to_id: Vec<String>,
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
                    *in_degree.entry(id.as_str()).or_insert(0) += 1;
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
                    *deg -= 1;
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
