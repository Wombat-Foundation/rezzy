//! C-style interned state key: a flat `Copy` integer index into an owned string
//! arena.
//!
//! This is the genuinely C-like alternative to [`InternedKey`](crate::InternedKey)'s
//! `Arc<str>`: no atomic refcount, no per-clone allocation, integer copy. A
//! `u32` index into an [`Interner`] arena is compared/`Copy`-moved like a scalar;
//! the only string work happens when a key is actually resolved to its text
//! (e.g. at the auth boundary or for `Ord`).
//!
//! # Ordering contract
//!
//! The resolver's `Borrow<dyn StateKeyDyn>` lookups are sound only because the
//! key type's `Ord` agrees with lexicographic string ordering (see the soundness
//! note beside that impl in `src/auth/mod.rs`). [`InternId`] therefore resolves
//! `Ord`/`PartialOrd` *through the interner* (string compare), NOT by raw index
//! value, so ids may be assigned in first-seen order without breaking the
//! contract. `Eq`/`Hash` remain index-based, which is consistent because every
//! distinct string owns a distinct id (the [`Interner`] guarantees uniqueness).
//!
//! # `Default`
//!
//! [`StateKey`](crate::basespec::rezzy_types::StateKey) requires `Default`, which
//! the pipeline uses as the "missing/empty state key" sentinel. Every [`Interner`]
//! reserves slot `0` for the empty string, so `InternId::default()` points at the
//! shared empty interner and resolves to `""`.

use core::fmt;

use alloc::borrow::ToOwned;

/// Owns the string arena and the `string -> id` and `id -> string` maps.
///
/// Slot `0` is reserved for the empty string so `InternId::default()` (which has
/// no interner reference available) still resolves to `""`. Build one per
/// resolution run (or per room) and hand `&Interner` to the keys.
#[derive(Debug, Clone, Default)]
pub struct Interner {
    id_to_str: alloc::vec::Vec<alloc::string::String>,
    str_to_id: crate::HashMap<alloc::string::String, u32>,
}

impl Interner {
    /// A fresh interner with slot `0` reserved for `""`.
    #[must_use]
    pub fn new() -> Self {
        let mut str_to_id = crate::HashMap::new();
        str_to_id.insert(alloc::string::String::new(), 0);
        Self {
            id_to_str: alloc::vec![alloc::string::String::new()],
            str_to_id,
        }
    }

    /// Interns `s`, returning its dense index. Idempotent: repeated calls with
    /// the same string return the same index.
    ///
    /// # Panics
    ///
    /// Panics if more than `u32::MAX` distinct state keys are interned.
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.str_to_id.get(s) {
            return id;
        }
        let id = self.id_to_str.len();
        let id = u32::try_from(id).expect("interner overflow: >u32 distinct state keys");
        self.id_to_str.push(s.to_owned());
        self.str_to_id.insert(s.to_owned(), id);
        id
    }

    /// The index for `s`, if it has been interned.
    #[must_use]
    pub fn id_of(&self, s: &str) -> Option<u32> {
        self.str_to_id.get(s).copied()
    }

    /// Resolves an index back to its string. Panics on an out-of-range or
    /// un-interned index (callers must only use indices this interner issued).
    ///
    /// # Panics
    ///
    /// Panics if `id` was not issued by this interner (i.e. is `>= len`).
    #[must_use]
    pub fn get(&self, id: u32) -> &str {
        let id = usize::try_from(id).expect("non-negative u32 index");
        self.id_to_str
            .get(id)
            .unwrap_or_else(|| panic!("Interner::get({id}) out of range"))
    }

    /// Number of distinct interned strings (including the reserved empty slot).
    #[must_use]
    pub fn len(&self) -> usize {
        self.id_to_str.len()
    }

    /// True when the arena holds only the reserved empty slot.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() <= 1
    }
}

/// A `Copy` interned state key: a dense `u32` index into an [`Interner`] arena.
#[derive(Debug, Clone, Copy)]
pub struct InternId<'a> {
    idx: u32,
    interner: &'a Interner,
}

impl<'a> InternId<'a> {
    /// Interns `s` into `interner` and returns the corresponding key. Borrows
    /// `interner` mutably, so only use this during the build phase before any
    /// `InternId` values that borrow `interner` are held.
    #[must_use]
    pub fn intern(interner: &'a mut Interner, s: &str) -> Self {
        let idx = interner.intern(s);
        Self { idx, interner }
    }

    /// Builds a key for an already-interned index, from a shared `&Interner`.
    /// Use after the build phase, when `InternId` values will be stored while
    /// the interner is immutable.
    #[must_use]
    pub fn from_index(interner: &'a Interner, idx: u32) -> Self {
        Self { idx, interner }
    }

    /// The reserved empty-string key for `interner`.
    #[must_use]
    pub fn empty(interner: &'a Interner) -> Self {
        Self { idx: 0, interner }
    }

    /// The underlying dense index (stable within one interner).
    #[must_use]
    pub fn index(self) -> u32 {
        self.idx
    }

    /// The interner this key indexes into.
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

// `Ord`/`PartialOrd` resolve through the interner so index order never breaks the
// `Borrow<dyn StateKeyDyn>` string-ordering contract (ids are first-seen, not
// sorted). `Eq`/`Hash` are index-based — sound because the interner guarantees a
// unique index per distinct string.
impl PartialOrd for InternId<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InternId<'_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl PartialEq for InternId<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.idx == other.idx
    }
}

impl Eq for InternId<'_> {}

impl core::hash::Hash for InternId<'_> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.idx.hash(state);
    }
}

/// The shared empty interner backing `InternId::default()`. Its only entry is
/// slot `0 = ""`, so a defaulted key resolves to the empty state key.
///
/// `OnceLock` (not `LazyLock`, stable only since 1.80) to keep this crate's
/// MSRV of 1.75.
static EMPTY_INTERNER: std::sync::OnceLock<Interner> = std::sync::OnceLock::new();

impl Default for InternId<'_> {
    fn default() -> Self {
        Self {
            idx: 0,
            interner: EMPTY_INTERNER.get_or_init(Interner::new),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::basespec::event_types::EventType;
    use crate::basespec::rezzy_types::StateKey;
    use alloc::vec::Vec;

    /// `InternId` satisfies `StateKey` (Clone + Eq + Hash + Ord + `AsRef`<str> +
    /// Default). This pins the *positive* side of the 'static gate: it holds for
    /// a `'static` interner reference, which is what a `K = InternId<'static>`
    /// would require in the resolution pipeline.
    #[test]
    fn intern_id_is_state_key_for_static_reference() {
        fn assert_state_key<T: StateKey>() {}
        assert_state_key::<InternId<'static>>();
    }

    #[test]
    fn interner_reserves_empty_slot_zero() {
        let mut i = Interner::new();
        assert_eq!(i.intern(""), 0, "empty string is slot 0");
        assert_eq!(i.id_of(""), Some(0));
        assert_eq!(i.get(0), "");
        assert!(i.is_empty());
    }

    #[test]
    fn intern_is_idempotent_and_unique() {
        let mut i = Interner::new();
        let a = i.intern("alpha");
        let a2 = i.intern("alpha");
        let b = i.intern("beta");
        assert_eq!(a, a2, "same string -> same id");
        assert_ne!(a, b, "distinct strings -> distinct ids");
        assert_eq!(i.get(a), "alpha");
        assert_eq!(i.get(b), "beta");
        assert_eq!(i.len(), 3, "empty + alpha + beta");
    }

    #[test]
    fn default_resolves_to_empty_string() {
        let key = InternId::default();
        assert_eq!(key.as_ref(), "");
    }

    #[test]
    fn ord_matches_string_order_not_index_order() {
        // Interned first-seen ("zeta" gets id 1, "alpha" id 2), but Ord must be
        // lexicographic, so "alpha" < "zeta" regardless of index.
        let mut i = Interner::new();
        let zeta_idx = i.intern("zeta");
        let alpha_idx = i.intern("alpha");
        let interner = &i;
        let zeta = InternId::from_index(interner, zeta_idx);
        let alpha = InternId::from_index(interner, alpha_idx);
        assert!(alpha.index() > zeta.index(), "index order is first-seen");
        assert!(alpha < zeta, "Ord follows string order, not index order");
    }

    /// The `Borrow<dyn StateKeyDyn>` contract: a `BTreeMap<(EventType, K), _>`
    /// must be iterable in the same order as its `K = String` equivalent, and
    /// lookups by borrowed `(&str, &str)` must find keys.
    #[test]
    fn stat_key_dyn_ordering_and_borrow_lookup() {
        let mut i = Interner::new();
        let entries = [
            ("m.room.member", "@b:x"),
            ("m.room.member", "@a:x"),
            ("m.room.power_levels", ""),
        ];
        // Phase 1: intern every key (mutable) and record indices.
        let mut ids = Vec::new();
        for (_, k) in entries {
            ids.push(i.intern(k));
        }
        // Phase 2: build InternId values from the now-immutable interner.
        let interner = &i;
        let mut room_state: alloc::collections::BTreeMap<
            (EventType, InternId<'_>),
            alloc::string::String,
        > = alloc::collections::BTreeMap::new();
        for ((et, _), idx) in entries.iter().zip(&ids) {
            room_state.insert(
                (EventType::from(*et), InternId::from_index(interner, *idx)),
                alloc::string::String::new(),
            );
        }

        // Ordering must match the String-keyed equivalent.
        let mut str_state: alloc::collections::BTreeMap<(EventType, &str), alloc::string::String> =
            alloc::collections::BTreeMap::new();
        for (et, k) in entries {
            str_state.insert((EventType::from(et), k), alloc::string::String::new());
        }
        let interned_order: Vec<(EventType, &str)> = room_state
            .keys()
            .map(|(et, k)| (et.clone(), k.as_ref()))
            .collect();
        let str_order: Vec<(EventType, &str)> =
            str_state.keys().map(|(et, k)| (et.clone(), *k)).collect();
        assert_eq!(interned_order, str_order);

        // Borrow lookup through `dyn StateKeyDyn` must find a key by borrowed
        // (&str, &str) without constructing a K.
        let q: (&str, &str) = ("m.room.member", "@a:x");
        assert!(room_state.contains_key(&q as &dyn crate::auth::StateKeyDyn));
    }

    #[test]
    fn intern_id_intern_builds_key_during_mutable_phase() {
        let mut i = Interner::new();
        let key = InternId::intern(&mut i, "alpha");
        assert_eq!(key.as_ref(), "alpha");
        assert_eq!(key.index(), i.id_of("alpha").unwrap());
    }

    #[test]
    fn intern_id_empty_is_reserved_slot_zero() {
        let mut i = Interner::new();
        i.intern("alpha");
        let key = InternId::empty(&i);
        assert_eq!(key.index(), 0);
        assert_eq!(key.as_ref(), "");
    }

    #[test]
    fn intern_id_interner_getter_roundtrips() {
        let mut i = Interner::new();
        let idx = i.intern("alpha");
        let interner = &i;
        let key = InternId::from_index(interner, idx);
        // The returned reference is the same interner the key was built from,
        // so resolving through it yields the same string.
        assert_eq!(key.interner().get(idx), "alpha");
    }

    #[test]
    fn intern_id_eq_is_index_based() {
        let mut i = Interner::new();
        let a = i.intern("alpha");
        let b = i.intern("beta");
        let interner = &i;
        let a1 = InternId::from_index(interner, a);
        let a2 = InternId::from_index(interner, a);
        let b1 = InternId::from_index(interner, b);
        assert_eq!(a1, a2, "same index -> equal");
        assert_ne!(a1, b1, "distinct index -> not equal");
    }

    #[test]
    fn intern_id_hash_matches_eq_for_equal_keys() {
        use core::hash::BuildHasher;

        // A single fixed BuildHasher shared across both calls: RandomState is
        // seeded per-instance, so two independent `default()`s would produce
        // different hashes even for equal inputs and say nothing about the
        // Eq/Hash contract.
        let build_hasher = crate::HashSet::<()>::default().hasher().clone();
        let hash_of = |v: &InternId<'_>| build_hasher.hash_one(v);

        let mut i = Interner::new();
        let a = i.intern("alpha");
        let interner = &i;
        let a1 = InternId::from_index(interner, a);
        let a2 = InternId::from_index(interner, a);
        assert_eq!(a1, a2);
        assert_eq!(
            hash_of(&a1),
            hash_of(&a2),
            "equal InternIds must hash identically (Eq/Hash contract)"
        );
    }
}
