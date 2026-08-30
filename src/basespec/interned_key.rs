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
//! The map key is `(InternId<'a>, InternId<'a>)` — BOTH halves are `Copy`, so
//! `get_event` resolves both `&str` halves through `id_of` with ZERO
//! allocation (the same cost profile as the `Borrow<dyn StateKeyDyn>` path it
//! replaces). `InternId`'s `Ord` always compares the resolved strings (not
//! the interner's discovery-order index), so the tuple's `Ord` agrees with
//! the `StateKeyDyn` `(ev_type, state_key)` lexicographic ordering contract
//! unconditionally — independent of interning order.

use alloc::rc::Rc;
use core::fmt;

use crate::auth::StateProvider;
use crate::basespec::rezzy_types::LeanEvent;

/// Owns the string arena + `string -> id` map. Slot 0 reserved for "".
///
/// Each interned string is allocated exactly once, as an `Rc<str>`; both
/// `id_to_str` and `str_to_id` hold clones of that same `Rc` (a refcount
/// bump, not a fresh allocation).
#[derive(Debug, Clone)]
pub struct Interner {
    id_to_str: alloc::vec::Vec<Rc<str>>,
    str_to_id: crate::HashMap<Rc<str>, u32>,
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
        let empty: Rc<str> = Rc::from("");
        let mut str_to_id = crate::HashMap::new();
        str_to_id.insert(Rc::clone(&empty), 0);
        Self {
            id_to_str: alloc::vec![empty],
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
        // Single allocation: `s` is converted to an `Rc<str>` once, and
        // `id_to_str`/`str_to_id` each hold a cheap `Rc::clone` (refcount
        // bump) of it rather than a second independent copy of the string.
        let rc: Rc<str> = Rc::from(s);
        self.id_to_str.push(Rc::clone(&rc));
        self.str_to_id.insert(rc, id);
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

    /// Number of distinct strings interned so far (including the reserved
    /// slot 0 for `""`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.id_to_str.len()
    }

    /// Whether any strings beyond the reserved slot 0 have been interned.
    ///
    /// Slot 0 (`""`) is always present after [`Self::new`]/[`Self::default`],
    /// so `id_to_str` itself is never actually empty — this compares against
    /// `1`, not `0`, to match the doc's "beyond slot 0" contract.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.id_to_str.len() <= 1
    }
}

/// A `Copy` interned state key: `u32` into an [`Interner`]. `Ord` by rank.
#[derive(Debug, Clone, Copy)]
pub struct InternId<'a> {
    idx: u32,
    interner: &'a Interner,
}

// RESOLVED: Cross-interner collision
// Two different `Interner`s can hand out the same dense index to different
// strings, so comparing indices alone would let unrelated `InternId`s from
// different arenas compare equal and collapse map entries. `InternId` now
// carries the `&Interner` it was minted from (it always did, via
// `from_index`/`interner()`), so equality takes arena identity into account:
// same arena compares by index (cheap, and unambiguous because one arena
// never assigns the same index to two different strings); different arenas
// fall back to comparing the resolved strings, which is always correct
// regardless of which arena assigned which index.
//
// RESOLVED: Ordering mismatch
// `Interner::intern` assigns indices in first-use (discovery) order, not
// sorted string order, so index order need not agree with string order.
// Relying on `debug_assert!`-checked "callers must sort before inserting"
// would silently misorder `BTreeMap` keys in release builds whenever that
// invariant slipped. Instead `Ord` always compares the resolved strings
// (never the index), so the ordering is correct unconditionally, independent
// of interning order or which arena(s) the operands came from — no invariant
// to violate.
impl PartialEq for InternId<'_> {
    fn eq(&self, other: &Self) -> bool {
        if core::ptr::eq(self.interner, other.interner) {
            // Same arena: `Interner::intern` never assigns the same index to
            // two different strings, so index equality is exactly string
            // equality here, without resolving either side.
            self.idx == other.idx
        } else {
            self.as_ref() == other.as_ref()
        }
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
        // Always compare the resolved strings: index order tracks discovery
        // (first-use) order, not string order, so it cannot be trusted for
        // `Ord` even within a single arena.
        self.as_ref().cmp(other.as_ref())
    }
}
impl core::hash::Hash for InternId<'_> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Must hash the same value `eq` compares on some path for any pair
        // of (possibly cross-arena) equal `InternId`s, so hash the resolved
        // string unconditionally rather than the index.
        self.as_ref().hash(state);
    }
}

impl<'a> InternId<'a> {
    /// # Panics
    ///
    /// Panics if `idx` was not issued by `interner` (i.e. is out of bounds
    /// for it).
    #[must_use]
    pub fn from_index(interner: &'a Interner, idx: u32) -> Self {
        assert!(
            (idx as usize) < interner.len(),
            "InternId::from_index: idx {idx} out of bounds for interner of len {}",
            interner.len()
        );
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
    /// `InternId`'s `Eq`/`Ord`/`Hash` fall back to comparing resolved strings
    /// across different arenas (see the note beside those impls), so mixing
    /// arenas is no longer a correctness hazard by itself -- but it silently
    /// forfeits the zero-cost index fast path on every comparison and usually
    /// indicates a bug (an `InternId` escaping the arena it was meant to
    /// belong to). Panics if any key or state-key value in `map` was not
    /// produced by `interner`.
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
        // No sortedness invariant to check here: `InternId::cmp` always
        // compares resolved strings (never the interner's discovery-order
        // index), so `BTreeMap`'s key order already agrees with the
        // `StateKeyDyn` lexicographic contract unconditionally.
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

    /// `is_empty()` must return `true` for a freshly-constructed interner
    /// even though slot 0 (`""`) is already reserved — it means "nothing
    /// beyond the reserved slot has been interned", not "the backing vec is
    /// literally empty" (which never happens after `new()`/`Default`).
    #[test]
    fn test_is_empty_true_for_fresh_interner() {
        assert!(Interner::new().is_empty());
        assert!(Interner::default().is_empty());
    }

    /// Interning any real string — even `""` again, which is idempotent with
    /// the reserved slot 0 — must not make `is_empty()` incorrectly flip; but
    /// interning a genuinely new string must flip it to `false`, and `len()`
    /// must track the count of distinct strings including the reserved slot.
    #[test]
    fn test_is_empty_false_after_intern() {
        let mut interner = Interner::new();
        assert_eq!(interner.len(), 1);

        // Re-interning the already-reserved "" is a no-op: still empty.
        interner.intern("");
        assert!(interner.is_empty());
        assert_eq!(interner.len(), 1);

        interner.intern("m.room.create");
        assert!(!interner.is_empty());
        assert_eq!(interner.len(), 2);
    }

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
                        depth: 1,
                        rejected: false,
                        soft_fail: false,
                        room_id: None,
                    },
                ),
            ]),
        };
        let map = InternedRoomState::new(interner_ref, map.map);

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

    /// `from_index` must reject an index that was never issued by the given
    /// interner instead of building an `InternId` that panics later (or
    /// worse, silently reads someone else's slot) the first time it is
    /// resolved.
    #[test]
    #[should_panic(expected = "out of bounds")]
    fn from_index_rejects_out_of_bounds_idx() {
        let interner = Interner::new(); // len() == 1 (slot 0 == "")
        let _ = InternId::from_index(&interner, 1);
    }

    /// `Interner::intern` assigns ids in first-use (discovery) order, not
    /// sorted string order. `InternId::Ord` must still agree with plain
    /// string ordering even though the indices here are deliberately
    /// out of string order (unlike the sorted-insertion spike test above).
    #[test]
    fn ord_follows_string_order_even_when_indices_are_unsorted() {
        let mut interner = Interner::new();
        // Discovery order gives "zebra" index 1 and "apple" index 2, i.e.
        // index order is the OPPOSITE of string order.
        let idx_zebra = interner.intern("zebra");
        let idx_apple = interner.intern("apple");
        assert!(idx_zebra < idx_apple, "sanity: indices are unsorted");

        let zebra = InternId::from_index(&interner, idx_zebra);
        let apple = InternId::from_index(&interner, idx_apple);

        // Despite zebra's index being smaller, "apple" < "zebra" as strings.
        assert!(apple < zebra);
        assert_eq!(apple.cmp(&zebra), core::cmp::Ordering::Less);
    }

    /// Two different `Interner`s can (and, with discovery-order assignment,
    /// routinely do) hand out the same dense index to different strings.
    /// `InternId`'s `Eq`/`Ord`/`Hash` must resolve this via the strings
    /// rather than treating same-index `InternId`s from different arenas as
    /// interchangeable.
    #[test]
    fn cross_interner_same_index_does_not_collide() {
        let mut arena_a = Interner::new();
        let idx_a = arena_a.intern("aaa"); // idx 1

        let mut arena_b = Interner::new();
        let idx_b = arena_b.intern("zzz"); // also idx 1

        assert_eq!(idx_a, idx_b, "sanity: same dense index in both arenas");

        let a = InternId::from_index(&arena_a, idx_a);
        let b = InternId::from_index(&arena_b, idx_b);

        // Must NOT compare equal just because the raw indices match.
        assert_ne!(a, b);
        assert_eq!(a.cmp(&b), core::cmp::Ordering::Less, "\"aaa\" < \"zzz\"");
        assert!(a < b);

        let build_hasher = crate::HashSet::<()>::default().hasher().clone();
        assert_ne!(
            build_hasher.hash_one(a),
            build_hasher.hash_one(b),
            "unequal cross-arena InternIds should (almost certainly) hash \
             differently"
        );

        // Same string, different arenas, same index -> still equal, since
        // equality falls back to comparing resolved strings across arenas.
        let mut arena_c = Interner::new();
        let idx_c = arena_c.intern("aaa");
        let c = InternId::from_index(&arena_c, idx_c);
        assert_eq!(
            a, c,
            "equal strings from different arenas must compare equal"
        );
        assert_eq!(
            build_hasher.hash_one(a),
            build_hasher.hash_one(c),
            "equal cross-arena InternIds must hash identically"
        );
    }
}
