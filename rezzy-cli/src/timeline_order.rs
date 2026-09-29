use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

/// Return a deterministic parent-before-child ordering for an event set.
/// Missing parents are treated as external references; cycles are appended by
/// the same deterministic key after all acyclic events have been emitted.
pub fn kahn_order(
    ids: &[String],
    parents: &[Vec<String>],
    timestamps: &[u64],
    depths: &[u64],
) -> Vec<usize> {
    let mut indices = HashMap::with_capacity(ids.len());
    for (index, id) in ids.iter().enumerate() {
        indices.insert(id.as_str(), index);
    }
    let mut indegree = vec![0_usize; ids.len()];
    let mut children = vec![Vec::new(); ids.len()];
    for (child, event_parents) in parents.iter().enumerate() {
        for parent in event_parents {
            if let Some(&parent_index) = indices.get(parent.as_str()) {
                indegree[child] = indegree[child].saturating_add(1);
                children[parent_index].push(child);
            }
        }
    }
    let key = |index: usize| (timestamps[index], depths[index], ids[index].clone());
    let mut ready = BinaryHeap::new();
    for (index, degree) in indegree.iter().enumerate() {
        if *degree == 0 {
            ready.push(Reverse((key(index), index)));
        }
    }
    let mut emitted = vec![false; ids.len()];
    let mut ordered = Vec::with_capacity(ids.len());
    while let Some(Reverse((_, index))) = ready.pop() {
        if emitted[index] {
            continue;
        }
        emitted[index] = true;
        ordered.push(index);
        for child in &children[index] {
            indegree[*child] = indegree[*child].saturating_sub(1);
            if indegree[*child] == 0 {
                ready.push(Reverse((key(*child), *child)));
            }
        }
    }
    let mut remainder: Vec<usize> = emitted
        .iter()
        .enumerate()
        .filter_map(|(index, emitted)| (!emitted).then_some(index))
        .collect();
    remainder.sort_by_key(|index| key(*index));
    ordered.extend(remainder);
    ordered
}

#[cfg(test)]
mod tests {
    use super::kahn_order;

    #[test]
    fn parents_precede_children_even_when_timestamp_is_later() {
        let ids = vec!["child".to_owned(), "parent".to_owned()];
        let parents = vec![vec!["parent".to_owned()], Vec::new()];
        let timestamps = vec![1, 2];
        let depths = vec![2, 1];
        assert_eq!(kahn_order(&ids, &parents, &timestamps, &depths), vec![1, 0]);
    }

    #[test]
    fn ready_events_use_timestamp_then_depth_then_id() {
        let ids = vec!["b".to_owned(), "a".to_owned(), "c".to_owned()];
        let parents = vec![Vec::new(), Vec::new(), Vec::new()];
        let timestamps = vec![2, 1, 1];
        let depths = vec![1, 3, 2];
        assert_eq!(
            kahn_order(&ids, &parents, &timestamps, &depths),
            vec![2, 1, 0]
        );
    }
}
