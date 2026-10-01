use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

/// How `-f timeline` linearizes the DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimelineOrder {
    /// Kahn topological order; parents always precede children. The ready queue
    /// is ordered by `--tie-break` (default `origin_server_ts,matrix_depth,event_id`).
    ///
    /// With the default (all-[`OrderKey::is_portable`]) tie-break this is the
    /// server-agnostic ordering: deterministic across servers and needing no
    /// sidecar. Including a stream key makes it server-local.
    #[default]
    Causal,
    /// Synapse-like `matrix_depth, stream_ordering, event_id`. Missing stream
    /// order entries use `MISSING_STREAM_ORDER` and sort after known entries.
    Synapse,
}

impl clap::ValueEnum for TimelineOrder {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Causal, Self::Synapse]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Causal => clap::builder::PossibleValue::new("causal"),
            Self::Synapse => clap::builder::PossibleValue::new("synapse"),
        })
    }
}

/// A key usable in `--tie-break`.
///
/// Keys split into two classes:
///
/// * **Portable / server-agnostic** — [`Self::OriginServerTs`],
///   [`Self::MatrixDepth`], [`Self::EventId`]. For room v3+ these fields are
///   bound to the event ID by the reference hash of the redacted event, so any
///   server that verifies the same event ID sees the same value. An ordering
///   built only from these keys is deterministic across servers and needs no
///   sidecar. It is still only a *convention*: timestamps and depth are
///   origin-asserted, so a malicious or backdated origin produces a valid but
///   misleading order. Only the DAG edges carry real causal information.
/// * **Server-local / non-portable** — [`Self::StreamOrdering`] and
///   [`Self::PduCount`]. These are a server's local receive order and cannot be
///   reproduced without the provenance sidecar (`--metadata`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderKey {
    /// `origin_server_ts` (untrusted ordering hint; portable).
    OriginServerTs,
    /// The Matrix `depth` field (untrusted ordering hint; portable).
    MatrixDepth,
    /// The event ID (content-addressed, deterministic; portable).
    EventId,
    /// Normalized stream order from the provenance sidecar (server-local).
    StreamOrdering,
    /// Alias of [`Self::StreamOrdering`] (Congruent/Tuwunel name; server-local).
    PduCount,
}

impl clap::ValueEnum for OrderKey {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::OriginServerTs,
            Self::MatrixDepth,
            Self::EventId,
            Self::StreamOrdering,
            Self::PduCount,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::OriginServerTs => clap::builder::PossibleValue::new("origin_server_ts"),
            Self::MatrixDepth => clap::builder::PossibleValue::new("matrix_depth"),
            Self::EventId => clap::builder::PossibleValue::new("event_id"),
            Self::StreamOrdering => clap::builder::PossibleValue::new("stream_ordering"),
            Self::PduCount => clap::builder::PossibleValue::new("pdu_count"),
        })
    }
}

impl OrderKey {
    /// Whether this key requires stream-order metadata from a sidecar.
    #[must_use]
    pub const fn needs_stream_order(self) -> bool {
        matches!(self, Self::StreamOrdering | Self::PduCount)
    }

    /// Whether this key is portable, i.e. reproducible by any server that has
    /// verified the event, with no local receive-order metadata.
    ///
    /// An ordering is server-agnostic only when every key is portable.
    #[must_use]
    pub const fn is_portable(self) -> bool {
        !self.needs_stream_order()
    }
}

/// The default causal tie-break: `origin_server_ts, matrix_depth, event_id`.
pub const DEFAULT_TIE_BREAK: [OrderKey; 3] = [
    OrderKey::OriginServerTs,
    OrderKey::MatrixDepth,
    OrderKey::EventId,
];

/// The causal `--timeline-order synapse` tie-break:
/// `matrix_depth, stream_ordering, event_id`.
pub const SYNAPSE_TIE_BREAK: [OrderKey; 3] = [
    OrderKey::MatrixDepth,
    OrderKey::StreamOrdering,
    OrderKey::EventId,
];

/// Sentinel for a requested stream-order component with no known value.
///
/// Stream order is a server-local monotonic counter, so `u64::MAX` is beyond
/// any real value. It sorts an event after every event with a known stream
/// order within the same higher-priority components, rather than substituting
/// `origin_server_ts` (which would compare a counter against epoch
/// milliseconds).
pub const MISSING_STREAM_ORDER: u64 = u64::MAX;

/// One component of a lexicographic sort key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyValue {
    /// Numeric component (`origin_server_ts`, `matrix_depth`, stream order).
    Num(u64),
    /// Text component (`event_id`).
    Text(String),
}

/// Build a lexicographic key for one event from `keys`.
///
/// `stream_ordering` and `pdu_count` both read `stream`; callers resolve the
/// fallback before calling.
#[must_use]
pub fn build_key(
    keys: &[OrderKey],
    event_id: &str,
    depth: u64,
    timestamp: u64,
    stream: u64,
) -> Vec<KeyValue> {
    keys.iter()
        .map(|key| match key {
            OrderKey::OriginServerTs => KeyValue::Num(timestamp),
            OrderKey::MatrixDepth => KeyValue::Num(depth),
            OrderKey::EventId => KeyValue::Text(event_id.to_owned()),
            OrderKey::StreamOrdering | OrderKey::PduCount => KeyValue::Num(stream),
        })
        .collect()
}

/// Return a deterministic parent-before-child ordering for an event set.
/// Missing parents are treated as external references; cycles are appended by
/// the same deterministic key after all acyclic events have been emitted.
#[must_use]
pub fn kahn_order(
    ids: &[String],
    parents: &[Vec<String>],
    timestamps: &[u64],
    depths: &[u64],
) -> Vec<usize> {
    let keys: Vec<Vec<KeyValue>> = ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            vec![
                KeyValue::Num(timestamps[index]),
                KeyValue::Num(depths[index]),
                KeyValue::Text(id.clone()),
            ]
        })
        .collect();
    kahn_order_by(ids, parents, &keys)
}

/// Kahn topological sort with a caller-supplied lexicographic key per event.
///
/// `keys[index]` orders the currently-ready events only; it never lets a child
/// precede an unemitted parent. Cycles are appended by the same key after all
/// acyclic events have been emitted.
#[must_use]
pub fn kahn_order_by(
    ids: &[String],
    parents: &[Vec<String>],
    keys: &[Vec<KeyValue>],
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
    let mut ready = BinaryHeap::new();
    for (index, degree) in indegree.iter().enumerate() {
        if *degree == 0 {
            ready.push(Reverse((&keys[index], index)));
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
                ready.push(Reverse((&keys[*child], *child)));
            }
        }
    }
    let mut remainder: Vec<usize> = emitted
        .iter()
        .enumerate()
        .filter_map(|(index, emitted)| (!emitted).then_some(index))
        .collect();
    remainder.sort_by(|a, b| keys[*a].cmp(&keys[*b]));
    ordered.extend(remainder);
    ordered
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

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

    #[test]
    fn only_event_id_bound_keys_are_portable() {
        for key in [
            OrderKey::OriginServerTs,
            OrderKey::MatrixDepth,
            OrderKey::EventId,
        ] {
            assert!(key.is_portable(), "{key:?} should be server-agnostic");
            assert!(!key.needs_stream_order());
        }
        for key in [OrderKey::StreamOrdering, OrderKey::PduCount] {
            assert!(!key.is_portable(), "{key:?} should be server-local");
            assert!(key.needs_stream_order());
        }
        assert!(DEFAULT_TIE_BREAK.iter().all(|key| key.is_portable()));
    }

    #[test]
    fn kahn_order_by_respects_a_custom_ready_key() {
        let ids = vec!["b".to_owned(), "a".to_owned(), "c".to_owned()];
        let parents = vec![Vec::new(), Vec::new(), Vec::new()];
        let keys = vec![
            vec![KeyValue::Num(2)],
            vec![KeyValue::Num(1)],
            vec![KeyValue::Num(1), KeyValue::Text(String::from("c"))],
        ];
        assert_eq!(kahn_order_by(&ids, &parents, &keys), vec![1, 2, 0]);
    }
}
