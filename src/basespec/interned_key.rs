//! SPIKE: can a dedicated `StateProvider` impl let a borrowing `InternId<'a>`
//! be used as a room-state key WITHOUT the `for<'q> (String, K): Borrow<dyn
//! StateKeyDyn + 'q>` / `'static` wall?
//!
//! The shared blanket impl routes lookups through `Borrow<dyn StateKeyDyn>`
//! (zero-alloc `&str` queries against an arbitrary `K`), which forces `K:
//! 'static`. This module instead builds a wrapper that holds `&'a Interner`
//! and converts the query `&str` into an OWNED key on the spot via the
//! interner — no borrowed trait-object lookup, no `for<'q>`, no `'static`.
//!
//! The map key is `(InternId<'a>, InternId<'a>)` — BOTH halves are `Copy` and
//! ranked from a single arena interned in sorted string order, so `get_event`
//! resolves both `&str` halves through `id_of` with ZERO allocation (the same
//! cost profile as the `Borrow<dyn StateKeyDyn>` path it replaces), and the
//! tuple's rank `Ord` agrees with the `StateKeyDyn` `(ev_type, state_key)`
//! lexicographic ordering contract.

use alloc::borrow::ToOwned;
use core::fmt;

use crate::auth::StateProvider;
use crate::basespec::rezzy_types::LeanEvent;

/// Owns the string arena + `string -> id` map. Slot 0 reserved for "".
#[derive(Debug, Clone)]
pub struct Interner {
    id_to_str: alloc::vec::Vec<alloc::string::String>,
    str_to_id: crate::HashMap<alloc::string::String, u32>,
}

impl Default for Interner {
    /// Delegates to [`Self::new`] so slot 0 is always reserved for "" —
    /// `#[derive(Default)]` would instead produce an empty interner,
    /// breaking the invariant every other constructor upholds.
    fn default() -> Self {
        Self::new()
    }
}

impl Interner {
    #[must_use]
    pub fn new() -> Self {
        let mut str_to_id = crate::HashMap::new();
        str_to_id.insert(alloc::string::String::new(), 0);
        Self {
            id_to_str: alloc::vec![alloc::string::String::new()],
            str_to_id,
        }
    }

    /// Interns `s`, returning its dense index (idempotent).
    ///
    /// # Panics
    ///
    /// Panics if more than `u32::MAX` distinct strings are interned.
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.str_to_id.get(s) {
            return id;
        }
        let id = u32::try_from(self.id_to_str.len()).expect("interner overflow");
        self.id_to_str.push(s.to_owned());
        self.str_to_id.insert(s.to_owned(), id);
        id
    }

    /// The index for `s`, if it has been interned.
    #[must_use]
    pub fn id_of(&self, s: &str) -> Option<u32> {
        self.str_to_id.get(s).copied()
    }

    /// Resolves an index back to its string.
    ///
    /// # Panics
    ///
    /// Panics if `id` was not issued by this interner.
    #[must_use]
    pub fn get(&self, id: u32) -> &str {
        &self.id_to_str[usize::try_from(id).expect("non-negative")]
    }
}

/// A `Copy` interned state key: `u32` into an [`Interner`]. `Ord` by rank.
#[derive(Debug, Clone, Copy)]
pub struct InternId<'a> {
    idx: u32,
    interner: &'a Interner,
}

// Equality/order/hash are by the dense index only (the interner reference is
// not part of the key's identity). Ids must be assigned in sorted string order
// (sort-once) for this rank `Ord` to agree with the `StateKeyDyn` ordering
// contract.
impl PartialEq for InternId<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.idx == other.idx
    }
}
impl Eq for InternId<'_> {}
impl PartialOrd for InternId<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for InternId<'_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.idx.cmp(&other.idx)
    }
}
impl core::hash::Hash for InternId<'_> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.idx.hash(state);
    }
}

impl<'a> InternId<'a> {
    #[must_use]
    pub fn from_index(interner: &'a Interner, idx: u32) -> Self {
        Self { idx, interner }
    }

    #[must_use]
    pub fn index(self) -> u32 {
        self.idx
    }

    #[must_use]
    pub fn interner(self) -> &'a Interner {
        self.interner
    }
}

impl AsRef<str> for InternId<'_> {
    fn as_ref(&self) -> &str {
        self.interner.get(self.idx)
    }
}

impl fmt::Display for InternId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

/// A room-state map keyed by `(InternId<'a>, InternId<'a>)` — both halves
/// `Copy` — whose `StateProvider` impl converts a `&str` query into the key via
/// the interner with no allocation. No `Borrow<dyn StateKeyDyn>`, no `'static`.
pub struct InternedRoomState<'a, Id = alloc::string::String, C = serde_json::Value> {
    interner: &'a Interner,
    map: alloc::collections::BTreeMap<(InternId<'a>, InternId<'a>), LeanEvent<Id, C, InternId<'a>>>,
}

impl<'a, Id, C> InternedRoomState<'a, Id, C> {
    /// Builds a room state directly from an already-interned map. `benches/`
    /// uses this to construct a realistic room for the `get_event` micro-bench
    /// without reaching into private fields.
    ///
    /// # Panics
    /// `InternId`'s `Eq`/`Ord`/`Hash` compare only the dense index, not which
    /// `Interner` produced it (see the note beside those impls) -- so a map
    /// keyed by `InternId`s from a DIFFERENT arena than `interner` would let
    /// `get_event` resolve a query through `interner` and silently return the
    /// wrong event for it. Panics if any key or state-key value in `map` was
    /// not produced by `interner`.
    #[must_use]
    pub fn new(
        interner: &'a Interner,
        map: alloc::collections::BTreeMap<
            (InternId<'a>, InternId<'a>),
            LeanEvent<Id, C, InternId<'a>>,
        >,
    ) -> Self {
        for ((et, sk), ev) in &map {
            assert!(
                core::ptr::eq(et.interner(), interner)
                    && core::ptr::eq(sk.interner(), interner)
                    && ev
                        .state_key
                        .map_or(true, |k| core::ptr::eq(k.interner(), interner)),
                "InternedRoomState::new: map contains InternId(s) from a \
                 different Interner than the one supplied"
            );
        }
        Self { interner, map }
    }
}

impl<'a, Id, C> StateProvider<Id, C, LeanEvent<Id, C, InternId<'a>>>
    for InternedRoomState<'a, Id, C>
where
    Id: crate::basespec::rezzy_types::EventId,
    C: crate::basespec::rezzy_types::EventContent,
{
    fn get_event(
        &self,
        event_type: &str,
        state_key: &str,
    ) -> Option<&LeanEvent<Id, C, InternId<'a>>> {
        let et = self.interner.id_of(event_type)?;
        let sk = self.interner.id_of(state_key)?;
        let key = (
            InternId::from_index(self.interner, et),
            InternId::from_index(self.interner, sk),
        );
        self.map.get(&key)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::auth::StateProvider;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::hash::BuildHasher;

    /// `Default` must uphold the same "slot 0 is the empty string" invariant
    /// as `new()` — a derived `Default` would instead produce an empty
    /// interner with no reserved slot.
    #[test]
    fn test_default_reserves_empty_string_at_slot_0() {
        let interner = Interner::default();
        assert_eq!(interner.id_of(""), Some(0));
        assert_eq!(interner.id_to_str, Interner::new().id_to_str);
    }

    /// `InternId`'s `Eq`/`Ord` compare only the dense index (see the note
    /// beside those impls), so a map built from a DIFFERENT `Interner` than
    /// the one `InternedRoomState::new` is given would let `get_event`
    /// resolve queries against the wrong arena's strings. `new` must reject
    /// that at construction rather than let it silently return wrong events.
    #[test]
    #[should_panic(expected = "different Interner")]
    fn test_new_rejects_cross_arena_intern_ids() {
        let mut arena_a = Interner::new();
        arena_a.intern("m.room.member");
        arena_a.intern("@a:x");

        let mut arena_b = Interner::new();
        arena_b.intern("m.room.member");
        arena_b.intern("@a:x");

        // Keyed with InternIds from arena_a, but constructed with arena_b.
        let et = InternId::from_index(&arena_a, arena_a.id_of("m.room.member").unwrap());
        let sk = InternId::from_index(&arena_a, arena_a.id_of("@a:x").unwrap());
        let map = alloc::collections::BTreeMap::from([(
            (et, sk),
            LeanEvent::<alloc::string::String, serde_json::Value, InternId<'_>> {
                event_id: "$a".to_string(),
                event_type: "m.room.member".to_string(),
                state_key: Some(sk),
                power_level: 0,
                origin_server_ts: 0,
                sender: "@a:x".to_string(),
                content: serde_json::Value::Null,
                prev_events: Vec::new(),
                auth_events: Vec::new(),
                prev_state_events: Vec::new(),
                depth: 0,
                rejected: false,
                soft_fail: false,
                room_id: None,
            },
        )]);

        let _ = InternedRoomState::new(&arena_b, map);
    }

    /// Empirically confirms a NON-'static, per-call interner works as a
    /// `StateProvider` key: no `'static` bound, no `for<'q>`, no
    /// `Borrow<dyn StateKeyDyn>` — the `'static` wall was an artifact of the
    /// shared blanket impl, not a fundamental constraint.
    #[test]
    fn spike_dedicated_state_provider_avoids_static_wall() {
        let mut interner = Interner::new();
        // Single arena, rank-sorted: "" < "@a:x" < "@b:x" < "m.room.member"
        // → ranks 0,1,2,3. Both the event-type and state-key halves resolve
        // through the same ranked arena, so the `(rank, rank)` key preserves
        // the `(ev_type, state_key)` lexicographic ordering contract.
        let mut keys = vec!["m.room.member", "@b:x", "@a:x"];
        keys.sort_unstable();
        for k in keys {
            interner.intern(k);
        }

        let interner_ref = &interner; // borrows for 'a; NOT 'static
        let et = InternId::from_index(interner_ref, interner.id_of("m.room.member").unwrap());
        let a = InternId::from_index(interner_ref, interner.id_of("@a:x").unwrap());
        let b = InternId::from_index(interner_ref, interner.id_of("@b:x").unwrap());

        let map = InternedRoomState {
            interner: interner_ref,
            map: alloc::collections::BTreeMap::from([
                (
                    (et, a),
                    LeanEvent {
                        event_id: alloc::string::String::from("$a"),
                        event_type: alloc::string::String::from("m.room.member"),
                        state_key: Some(a),
                        power_level: 0,
                        origin_server_ts: 0,
                        sender: alloc::string::String::from("@a:x"),
                        content: serde_json::Value::Null,
                        prev_events: Vec::new(),
                        auth_events: Vec::new(),
                        prev_state_events: Vec::new(),
                        depth: 1,
                        rejected: false,
                        soft_fail: false,
                        room_id: None,
                    },
                ),
                (
                    (et, b),
                    LeanEvent {
                        event_id: alloc::string::String::from("$b"),
                        event_type: alloc::string::String::from("m.room.member"),
                        state_key: Some(b),
                        power_level: 0,
                        origin_server_ts: 0,
                        sender: alloc::string::String::from("@b:x"),
                        content: serde_json::Value::Null,
                        prev_events: Vec::new(),
                        auth_events: Vec::new(),
                        prev_state_events: Vec::new(),
                        depth: 1,
                        rejected: false,
                        soft_fail: false,
                        room_id: None,
                    },
                ),
            ]),
        };

        // Query via the trait's &str boundary; resolves both halves through the
        // interner (id_of) to the owned key with zero allocation. No 'static.
        let found = StateProvider::get_event(&map, "m.room.member", "@a:x")
            .expect("must find @a via owned-key lookup");
        assert_eq!(found.event_id, "$a");
        assert!(StateProvider::get_event(&map, "m.room.member", "@nope:x").is_none());
        // The `(rank, rank)` ordering agrees with the lexicographic contract:
        // "@a:x" < "@b:x" even though "@b:x" was sorted after "@a:x".
        assert!(a < b);
    }

    /// Covers the `InternId` accessors and trait impls not exercised by the
    /// state-provider lookup: the `intern` idempotent early-return, `index()`,
    /// `interner()`, `AsRef<str>`, `Display`, `PartialOrd` (the `<` path, which
    /// `BTreeMap` never uses — it calls `Ord::cmp`), and `Hash`.
    #[test]
    fn intern_id_accessors_and_trait_impls() {
        let mut interner = Interner::new();
        let idx1 = interner.intern("@alice:x");
        let idx2 = interner.intern("@alice:x"); // idempotent -> early `return id`
        let idx_bob = interner.intern("@bob:x");
        assert_eq!(idx1, idx2, "intern is idempotent");

        let interner_ref = &interner;
        let key = InternId::from_index(interner_ref, idx1);
        let key2 = InternId::from_index(interner_ref, idx2);
        let other = InternId::from_index(interner_ref, idx_bob);

        // Accessors.
        assert_eq!(key.index(), idx1);
        assert_eq!(key.interner().get(idx1), "@alice:x");

        // AsRef<str> + Display.
        assert_eq!(key.as_ref(), "@alice:x");
        assert_eq!(key.to_string(), "@alice:x");

        // PartialEq / Eq.
        assert_eq!(key, key2);
        // PartialOrd: the `<` operator routes through `partial_cmp`, which the
        // BTreeMap state-provider path never exercises (it uses `Ord::cmp`).
        assert!(key < other, "rank order: @alice:x < @bob:x");

        // Hash agrees with Eq under one BuildHasher.
        let build_hasher = crate::HashSet::<()>::default().hasher().clone();
        assert_eq!(
            build_hasher.hash_one(key),
            build_hasher.hash_one(key2),
            "equal InternIds must hash identically"
        );
    }
}
