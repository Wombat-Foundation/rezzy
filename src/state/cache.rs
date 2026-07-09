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

//! LRU cache for pre-constructed [`LeanEvent`]s, eliminating repeated
//! deserialization and string copying on hot state resolution paths.
//!
//! # Motivation
//!
//! State resolution is a CPU-critical hot path in Matrix homeservers. Every
//! resolution call typically requires converting native PDU types into
//! [`LeanEvent`] structures — cloning strings for `event_type`, `sender`,
//! `state_key`, and deep-copying JSON content. For active rooms, the same
//! events are converted hundreds of times.
//!
//! `LeanEventCache` amortizes this cost to once-per-event by caching
//! `Arc<LeanEvent>` with LRU eviction. It implements [`EventProvider`](crate::basespec::rezzy_types::EventProvider) so
//! it plugs directly into [`resolve_state_maps_lazy_with_diff`](crate::resolve::multi::resolve_state_maps_lazy_with_diff).
//!
//! # Example
//!
//! ```rust,no_run
//! use rezzy::state::cache::LeanEventCache;
//! use rezzy::{LeanEvent, HashMap};
//!
//! let mut cache = LeanEventCache::<String>::new(10_000);
//!
//! // Insert a pre-built LeanEvent
//! let event = LeanEvent {
//!     event_id: "$abc".into(),
//!     event_type: "m.room.member".into(),
//!     state_key: Some("@alice:x".into()),
//!     sender: "@alice:x".into(),
//!     depth: 1,
//!     ..Default::default()
//! };
//! cache.insert(event);
//!
//! // Retrieve (O(1) lookup, updates LRU order)
//! let cached = cache.get("$abc").unwrap();
//! assert_eq!(cached.sender, "@alice:x");
//! ```

use crate::HashMap;
use crate::basespec::rezzy_types::{EventContent, EventId, LeanEvent};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::cell::{Cell, RefCell};

/// A fixed-capacity LRU cache for pre-constructed [`LeanEvent`]s.
///
/// Events are stored as `Arc<LeanEvent<Id, C>>` for cheap cloning. When the
/// cache exceeds capacity, the least-recently-used entry is evicted.
///
/// The cache is **not** internally synchronized — callers must wrap it in a
/// `Mutex` or `RwLock` for concurrent access. This keeps the core `no_std`
/// compatible while allowing `std` users to choose their synchronization
/// strategy.
///
/// # Implementation
///
/// Uses a `HashMap` for O(1) key lookup plus a `BTreeMap<u64, Id>` side-index
/// for **O(log n)** LRU eviction. The `BTreeMap` maps generation ticks to
/// event IDs, so `pop_first()` instantly yields the least-recently-used entry.
///
/// # Interior mutability
///
/// The `BTreeMap` side-index is wrapped in [`RefCell`] and per-entry
/// `last_access` fields use [`Cell<u64>`] so that the
/// [`EventProvider`](crate::basespec::rezzy_types::EventProvider)
/// implementation (which takes `&self`) can update LRU state. This ensures
/// events accessed through the lazy resolver path are properly marked as
/// recently used and not prematurely evicted.
pub struct LeanEventCache<Id: EventId, C: EventContent = serde_json::Value> {
    map: HashMap<Id, CacheEntry<Id, C>>,
    /// Sorted index: generation → event ID. Enables O(log n) eviction via
    /// `pop_first()`. Wrapped in `RefCell` for interior mutability through
    /// `&self` (the `EventProvider` path).
    access_order: RefCell<BTreeMap<u64, Id>>,
    generation: Cell<u64>,
    capacity: usize,
    hits: Cell<u32>,
    misses: Cell<u32>,
    evictions: Cell<u32>,
}

struct CacheEntry<Id: EventId, C: EventContent> {
    event: Arc<LeanEvent<Id, C>>,
    last_access: Cell<u64>,
}

impl<Id: EventId, C: EventContent> LeanEventCache<Id, C> {
    /// Creates a new cache with the given maximum capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "LeanEventCache capacity must be > 0");
        Self {
            map: HashMap::with_capacity(capacity),
            access_order: RefCell::new(BTreeMap::new()),
            generation: Cell::new(0),
            capacity,
            hits: Cell::new(0),
            misses: Cell::new(0),
            evictions: Cell::new(0),
        }
    }

    /// Returns the number of cached events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns the maximum capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns a snapshot of the current cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.get(),
            misses: self.misses.get(),
            evictions: self.evictions.get(),
        }
    }

    /// Shared LRU bump — increments generation, updates `last_access`,
    /// and rotates the `BTreeMap` side-index entry. Called from both
    /// `touch` (returns `Arc`) and `EventProvider::get_event` (returns `&`).
    fn bump_entry(&self, entry: &CacheEntry<Id, C>) {
        let old_gen = entry.last_access.get();
        let new_gen = self.generation.get().wrapping_add(1);
        self.generation.set(new_gen);
        entry.last_access.set(new_gen);

        let mut order = self.access_order.borrow_mut();
        order.remove(&old_gen);
        order.insert(new_gen, entry.event.event_id.clone());
    }

    /// Internal LRU touch — bumps generation and updates `last_access`
    /// plus the `BTreeMap` side-index through interior mutability, so it
    /// works from both `&self` and `&mut self` contexts.
    fn touch<Q>(&self, id: &Q) -> Option<Arc<LeanEvent<Id, C>>>
    where
        Id: core::borrow::Borrow<Q>,
        Q: ?Sized + Eq + core::hash::Hash,
    {
        if let Some(entry) = self.map.get(id) {
            self.bump_entry(entry);
            self.hits.set(self.hits.get().saturating_add(1));
            Some(Arc::clone(&entry.event))
        } else {
            self.misses.set(self.misses.get().saturating_add(1));
            None
        }
    }

    /// Looks up an event by ID, returning a shared reference and updating
    /// the LRU generation.
    pub fn get<Q>(&mut self, id: &Q) -> Option<Arc<LeanEvent<Id, C>>>
    where
        Id: core::borrow::Borrow<Q>,
        Q: ?Sized + Eq + core::hash::Hash,
    {
        self.touch(id)
    }

    /// Inserts a `LeanEvent`, wrapping it in `Arc`. If the cache is at
    /// capacity, the least-recently-used entry is evicted first.
    ///
    /// If an event with the same ID already exists, it is replaced.
    pub fn insert(&mut self, event: LeanEvent<Id, C>) -> Arc<LeanEvent<Id, C>> {
        let arc = Arc::new(event);
        self.insert_arc(Arc::clone(&arc));
        arc
    }

    /// Inserts a pre-wrapped `Arc<LeanEvent>`. Useful when the caller already
    /// has an `Arc` (e.g., from a shared database layer).
    pub fn insert_arc(&mut self, event: Arc<LeanEvent<Id, C>>) {
        let r#gen = self.generation.get().wrapping_add(1);
        self.generation.set(r#gen);
        let id = event.event_id.clone();

        // Replace existing entry — remove old generation from side-index
        if let Some(existing) = self.map.get_mut(&id) {
            let old_gen = existing.last_access.get();
            self.access_order.borrow_mut().remove(&old_gen);
            existing.event = event;
            existing.last_access.set(r#gen);
            self.access_order.borrow_mut().insert(r#gen, id);
            return;
        }

        // New entry — evict if at capacity
        if self.map.len() >= self.capacity {
            self.evict_lru();
        }

        let entry = CacheEntry {
            event,
            last_access: Cell::new(r#gen),
        };
        self.access_order.borrow_mut().insert(r#gen, id.clone());
        self.map.insert(id, entry);
    }

    /// Gets an event by ID, or inserts one created by the closure if missing.
    ///
    /// This is the primary API for homeserver integration — the closure
    /// typically converts a native PDU type into a `LeanEvent`:
    ///
    /// ```rust,no_run
    /// # use rezzy::state::cache::LeanEventCache;
    /// # use rezzy::LeanEvent;
    /// # let mut cache = LeanEventCache::<String>::new(100);
    /// let event = cache.get_or_insert("$abc", || {
    ///     // Convert from native PDU type
    ///     LeanEvent {
    ///         event_id: "$abc".into(),
    ///         event_type: "m.room.member".into(),
    ///         sender: "@alice:x".into(),
    ///         state_key: Some("@alice:x".into()),
    ///         depth: 1,
    ///         ..Default::default()
    ///     }
    /// });
    /// ```
    ///
    /// # Panics (debug only)
    ///
    /// In debug builds, panics if the closure returns a `LeanEvent` whose
    /// `event_id` does not match the requested `id`.
    pub fn get_or_insert<Q>(
        &mut self,
        id: &Q,
        f: impl FnOnce() -> LeanEvent<Id, C>,
    ) -> Arc<LeanEvent<Id, C>>
    where
        Id: core::borrow::Borrow<Q>,
        Q: ?Sized + Eq + core::hash::Hash,
    {
        if let Some(arc) = self.get(id) {
            return arc;
        }
        let event = f();
        debug_assert!(
            event.event_id.borrow() == id,
            "get_or_insert: closure produced event with mismatched event_id"
        );
        self.insert(event)
    }

    /// Inserts a batch of events, returning a `HashMap` of `Arc`s.
    ///
    /// Events already in the cache are returned from cache (updating LRU).
    /// Missing events are inserted.
    pub fn insert_batch(
        &mut self,
        events: impl IntoIterator<Item = LeanEvent<Id, C>>,
    ) -> HashMap<Id, Arc<LeanEvent<Id, C>>> {
        let mut result = HashMap::new();
        for event in events {
            let id = event.event_id.clone();
            let arc = match self.get(&id) {
                Some(cached) => cached,
                _ => self.insert(event),
            };
            result.insert(id, arc);
        }
        result
    }

    /// Removes all entries from the cache.
    pub fn clear(&mut self) {
        self.map.clear();
        self.access_order.borrow_mut().clear();
        self.generation.set(0);
    }

    /// Evicts the least-recently-used entry in **O(log n)** via the
    /// `BTreeMap` side-index.
    fn evict_lru(&mut self) {
        if let Some((_gen, id)) = self.access_order.borrow_mut().pop_first() {
            self.map.remove(&id);
            self.evictions.set(self.evictions.get().saturating_add(1));
        }
    }
}

/// `LeanEventCache` implements [`EventProvider`](crate::basespec::rezzy_types::EventProvider) so it can be passed directly
/// to [`resolve_state_maps_lazy_with_diff`](crate::resolve::multi::resolve_state_maps_lazy_with_diff).
///
/// Unlike a plain `HashMap` provider, this implementation updates the LRU
/// generation for every access through interior mutability (`Cell` + `RefCell`),
/// ensuring that events heavily used during lazy resolution are not prematurely
/// evicted.
impl<Id: EventId, C: EventContent> crate::basespec::rezzy_types::EventProvider<Id, C>
    for LeanEventCache<Id, C>
{
    fn get_event(&self, id: &Id) -> Option<&LeanEvent<Id, C>> {
        if let Some(entry) = self.map.get(id) {
            self.bump_entry(entry);
            self.hits.set(self.hits.get().saturating_add(1));
            Some(entry.event.as_ref())
        } else {
            self.misses.set(self.misses.get().saturating_add(1));
            None
        }
    }
}

/// Collects cache hit/miss statistics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u32,
    /// Number of cache misses.
    pub misses: u32,
    /// Number of evictions.
    pub evictions: u32,
}

impl CacheStats {
    /// Returns the hit rate as a percentage (0.0–100.0).
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits.saturating_add(self.misses);
        if total == 0 {
            return 0.0;
        }
        (f64::from(self.hits) / f64::from(total)) * 100.0
    }
}

/// Convenience type alias for the most common cache configuration.
pub type StringLeanEventCache = LeanEventCache<alloc::string::String>;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use alloc::string::String;

    fn make_event(id: &str, depth: u64) -> LeanEvent<String> {
        LeanEvent {
            event_id: id.into(),
            event_type: "m.room.member".into(),
            state_key: Some("@test:x".into()),
            sender: "@test:x".into(),
            depth,
            ..Default::default()
        }
    }

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = LeanEventCache::new(10);
        assert_eq!(cache.capacity(), 10);
        cache.insert(make_event("$a", 1));
        cache.insert(make_event("$b", 2));

        assert_eq!(cache.len(), 2);
        let a = cache.get("$a").unwrap();
        assert_eq!(a.event_id, "$a");
        assert_eq!(a.depth, 1);
    }

    #[test]
    fn test_cache_miss() {
        let mut cache = LeanEventCache::<String>::new(10);
        assert!(cache.get("$missing").is_none());
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = LeanEventCache::new(3);
        cache.insert(make_event("$a", 1));
        cache.insert(make_event("$b", 2));
        cache.insert(make_event("$c", 3));

        // Access $b and $c to make $a the LRU
        let _ = cache.get("$b");
        let _ = cache.get("$c");

        // Insert $d → should evict $a (least recently used)
        cache.insert(make_event("$d", 4));

        assert_eq!(cache.len(), 3);
        assert!(cache.get("$a").is_none(), "$a should be evicted");
        assert!(cache.get("$b").is_some());
        assert!(cache.get("$c").is_some());
        assert!(cache.get("$d").is_some());
    }

    #[test]
    fn test_cache_replace_existing() {
        let mut cache = LeanEventCache::new(10);
        cache.insert(make_event("$a", 1));
        cache.insert(make_event("$a", 99));

        assert_eq!(cache.len(), 1);
        let a = cache.get("$a").unwrap();
        assert_eq!(a.depth, 99, "should be replaced with new event");
    }

    #[test]
    fn test_cache_get_or_insert() {
        let mut cache = LeanEventCache::new(10);

        // First call: miss → insert
        let ev1 = cache.get_or_insert("$a", || make_event("$a", 1));
        assert_eq!(ev1.depth, 1);

        // Second call: hit → return cached
        let ev2 = cache.get_or_insert("$a", || make_event("$a", 999));
        assert_eq!(ev2.depth, 1, "should return cached, not re-create");
    }

    #[test]
    fn test_cache_insert_batch() {
        let mut cache = LeanEventCache::new(10);

        // Pre-insert "$a" to seed the cache
        cache.insert(make_event("$a", 1));

        let events = alloc::vec![
            make_event("$a", 999), // Already cached, should return cached depth 1
            make_event("$b", 2),
            make_event("$c", 3),
        ];

        let result = cache.insert_batch(events);
        assert_eq!(result.len(), 3);
        assert_eq!(cache.len(), 3);
        assert_eq!(
            result["$a"].depth, 1,
            "should have retrieved cached version of $a"
        );
        assert_eq!(result["$b"].depth, 2);
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = LeanEventCache::new(10);
        cache.insert(make_event("$a", 1));
        cache.insert(make_event("$b", 2));
        cache.clear();

        assert!(cache.is_empty());
        assert!(cache.get("$a").is_none());
    }

    #[test]
    fn test_cache_as_event_provider() {
        use crate::basespec::rezzy_types::EventProvider;

        let mut cache = LeanEventCache::new(10);
        cache.insert(make_event("$a", 1));

        // EventProvider::get_event updates LRU state via interior mutability
        let key_a: String = "$a".into();
        let ev = EventProvider::get_event(&cache, &key_a);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().depth, 1);

        let key_missing: String = "$missing".into();
        assert!(EventProvider::get_event(&cache, &key_missing).is_none());
    }

    #[test]
    fn test_cache_event_provider_updates_lru() {
        use crate::basespec::rezzy_types::EventProvider;

        let mut cache = LeanEventCache::new(3);
        cache.insert(make_event("$a", 1)); // gen 1
        cache.insert(make_event("$b", 2)); // gen 2
        cache.insert(make_event("$c", 3)); // gen 3

        // Access $a via EventProvider (immutable borrow) — should update LRU
        let key_a: String = "$a".into();
        let _ = EventProvider::get_event(&cache, &key_a); // gen 4

        // Now $b is the LRU (gen 2). Insert $d → should evict $b, not $a.
        cache.insert(make_event("$d", 4));

        assert!(
            cache.get("$a").is_some(),
            "$a was touched via EventProvider, should survive"
        );
        assert!(cache.get("$b").is_none(), "$b was LRU, should be evicted");
        assert!(cache.get("$c").is_some());
        assert!(cache.get("$d").is_some());
    }

    #[test]
    fn test_cache_eviction_order_respects_access() {
        let mut cache = LeanEventCache::new(3);
        cache.insert(make_event("$a", 1)); // gen 1
        cache.insert(make_event("$b", 2)); // gen 2
        cache.insert(make_event("$c", 3)); // gen 3

        // Touch $a → now $b is LRU
        let _ = cache.get("$a"); // gen 4

        cache.insert(make_event("$d", 4)); // evicts $b (gen 2)

        assert!(cache.get("$a").is_some(), "$a was touched, should survive");
        assert!(cache.get("$b").is_none(), "$b was LRU, should be evicted");
        assert!(cache.get("$c").is_some());
        assert!(cache.get("$d").is_some());
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn test_cache_zero_capacity_panics() {
        let _ = LeanEventCache::<String>::new(0);
    }

    #[test]
    fn test_cache_stats_hit_rate() {
        let stats = CacheStats {
            hits: 80,
            misses: 20,
            evictions: 5,
        };
        let rate = stats.hit_rate();
        assert!((rate - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_stats_empty() {
        let stats = CacheStats::default();
        assert!((stats.hit_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_arc_sharing() {
        let mut cache = LeanEventCache::new(10);
        let arc1 = cache.insert(make_event("$a", 1));
        let arc2 = cache.get("$a").unwrap();

        // Both Arcs point to the same allocation
        assert!(Arc::ptr_eq(&arc1, &arc2));
    }

    #[test]
    fn test_cache_stats_tracking() {
        let mut cache = LeanEventCache::new(3);

        // Misses
        assert!(cache.get("$missing").is_none());
        assert_eq!(cache.stats().misses, 1);

        // Inserts + hits
        cache.insert(make_event("$a", 1));
        cache.insert(make_event("$b", 2));
        cache.insert(make_event("$c", 3));

        let _ = cache.get("$a"); // hit
        let _ = cache.get("$b"); // hit
        assert_eq!(cache.stats().hits, 2);

        // Eviction
        cache.insert(make_event("$d", 4));
        assert_eq!(cache.stats().evictions, 1);
    }

    #[test]
    fn test_cache_stats_via_event_provider() {
        use crate::basespec::rezzy_types::EventProvider;

        let mut cache = LeanEventCache::new(10);
        cache.insert(make_event("$a", 1));

        let key_a: String = "$a".into();
        let key_b: String = "$missing".into();

        let _ = EventProvider::get_event(&cache, &key_a);
        let _ = EventProvider::get_event(&cache, &key_b);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1, "EventProvider hit should be tracked");
        assert_eq!(stats.misses, 1, "EventProvider miss should be tracked");
    }

    /// Verifies the `BTreeMap` side-index stays in sync: after multiple
    /// accesses and replacements, the side-index length must equal map length.
    #[test]
    fn test_cache_side_index_consistency() {
        let mut cache = LeanEventCache::new(5);
        for i in 0..10 {
            cache.insert(make_event(&alloc::format!("${i}"), i));
        }
        // After 10 inserts into capacity-5, should have exactly 5 entries
        assert_eq!(cache.len(), 5);
        assert_eq!(cache.access_order.borrow().len(), 5);

        // Replace an existing entry
        cache.insert(make_event("$9", 99));
        assert_eq!(cache.len(), 5);
        assert_eq!(cache.access_order.borrow().len(), 5);
    }
}
