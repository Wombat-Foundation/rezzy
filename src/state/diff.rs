// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! State snapshot diffing — compute what changed between
//! two resolved states.

use crate::basespec::rezzy_types::EventId;
use crate::state::at::SharedState;
use alloc::string::String;
use alloc::vec::Vec;

/// A single entry in a state diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateDiffEntry<Id> {
    /// Key exists in `new` but not in `old`.
    Added { key: (String, String), event_id: Id },
    /// Key exists in `old` but not in `new`.
    Removed { key: (String, String), event_id: Id },
    /// Key exists in both but maps to different events.
    Changed {
        key: (String, String),
        old_event_id: Id,
        new_event_id: Id,
    },
}

/// The result of diffing two state snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDiff<Id> {
    /// All differences between old and new state.
    pub entries: Vec<StateDiffEntry<Id>>,
}

impl<Id: EventId> StateDiff<Id> {
    /// Number of state keys that changed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the two states are identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over only the added entries.
    pub fn added(&self) -> impl Iterator<Item = &StateDiffEntry<Id>> {
        self.entries
            .iter()
            .filter(|e| matches!(e, StateDiffEntry::Added { .. }))
    }

    /// Iterate over only the removed entries.
    pub fn removed(&self) -> impl Iterator<Item = &StateDiffEntry<Id>> {
        self.entries
            .iter()
            .filter(|e| matches!(e, StateDiffEntry::Removed { .. }))
    }

    /// Iterate over only the changed entries.
    pub fn changed(&self) -> impl Iterator<Item = &StateDiffEntry<Id>> {
        self.entries
            .iter()
            .filter(|e| matches!(e, StateDiffEntry::Changed { .. }))
    }
}

/// Compute the diff between two state snapshots.
///
/// Returns a [`StateDiff`] describing all keys that were
/// added, removed, or changed between `old` and `new`.
///
/// # Example
///
/// ```rust
/// use rezzy::state::diff::{compute_state_diff, StateDiffEntry};
/// use rezzy::SharedState;
///
/// let mut old: SharedState<String> = SharedState::new();
/// old.insert(("m.room.topic".into(), "".into()), "$t1".into());
/// old.insert(("m.room.name".into(), "".into()), "$n1".into());
///
/// let mut new = SharedState::new();
/// new.insert(("m.room.topic".into(), "".into()), "$t2".into());
/// new.insert(("m.room.avatar".into(), "".into()), "$a1".into());
///
/// let diff = compute_state_diff(&old, &new);
/// assert_eq!(diff.len(), 3); // topic changed, name removed, avatar added
/// ```
#[must_use]
pub fn compute_state_diff<Id: EventId>(
    old: &SharedState<Id>,
    new: &SharedState<Id>,
) -> StateDiff<Id> {
    let mut entries = Vec::new();

    // Check old keys against new
    for (key, old_id) in old {
        match new.get(key) {
            Some(new_id) if new_id != old_id => {
                entries.push(StateDiffEntry::Changed {
                    key: key.clone(),
                    old_event_id: old_id.clone(),
                    new_event_id: new_id.clone(),
                });
            }
            None => {
                entries.push(StateDiffEntry::Removed {
                    key: key.clone(),
                    event_id: old_id.clone(),
                });
            }
            _ => {} // identical — no diff
        }
    }

    // Check for keys only in new
    for (key, new_id) in new {
        if !old.contains_key(key) {
            entries.push(StateDiffEntry::Added {
                key: key.clone(),
                event_id: new_id.clone(),
            });
        }
    }

    StateDiff { entries }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_states_produce_empty_diff() {
        let mut state: SharedState<String> = SharedState::new();
        state.insert(("m.room.create".into(), String::new()), "$c".into());
        let diff = compute_state_diff(&state, &state);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_added_key() {
        let old: SharedState<String> = SharedState::new();
        let mut new = SharedState::new();
        new.insert(("m.room.topic".into(), String::new()), "$t".into());
        let diff = compute_state_diff(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff.added().count(), 1);
    }

    #[test]
    fn test_removed_key() {
        let mut old = SharedState::new();
        old.insert(("m.room.topic".into(), String::new()), "$t".into());
        let new: SharedState<String> = SharedState::new();
        let diff = compute_state_diff(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff.removed().count(), 1);
    }

    #[test]
    fn test_changed_key() {
        let mut old: SharedState<String> = SharedState::new();
        old.insert(("m.room.topic".into(), String::new()), "$t1".into());
        let mut new = SharedState::new();
        new.insert(("m.room.topic".into(), String::new()), "$t2".into());
        let diff = compute_state_diff(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff.changed().count(), 1);
    }

    #[test]
    fn test_mixed_diff() {
        let mut old: SharedState<String> = SharedState::new();
        old.insert(("m.room.create".into(), String::new()), "$c".into());
        old.insert(("m.room.topic".into(), String::new()), "$t1".into());
        old.insert(("m.room.name".into(), String::new()), "$n".into());

        let mut new = SharedState::new();
        new.insert(("m.room.create".into(), String::new()), "$c".into()); // same
        new.insert(("m.room.topic".into(), String::new()), "$t2".into()); // changed
        new.insert(("m.room.avatar".into(), String::new()), "$a".into()); // added
                                                                          // name: intentionally not inserted → shows as Removed

        let diff = compute_state_diff(&old, &new);
        assert_eq!(diff.len(), 3);
        assert_eq!(diff.added().count(), 1);
        assert_eq!(diff.removed().count(), 1);
        assert_eq!(diff.changed().count(), 1);
    }
}
