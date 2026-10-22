//! Small stderr subscriber for applications that opt into Rezzy logging.

use std::fmt::Write as _;
use std::string::String;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::span::{self, Id};
use tracing::{Event, Level, Metadata, Subscriber};

static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);

struct StderrSubscriber {
    max_level: LevelFilter,
}

impl Subscriber for StderrSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        level_enabled(*metadata.level(), self.max_level)
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(self.max_level)
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> Id {
        Id::from_u64(NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed))
    }

    fn record(&self, _span: &Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        let mut fields = FieldOutput::default();
        event.record(&mut fields);
        std::eprintln!(
            "{} {} {}: {}{}",
            metadata.level(),
            metadata.target(),
            metadata
                .name()
                .strip_prefix("event ")
                .unwrap_or(metadata.name()),
            fields.message,
            fields.fields
        );
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[derive(Default)]
struct FieldOutput {
    message: String,
    fields: String,
}

impl Visit for FieldOutput {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let rendered = std::format!("{value:?}");
            self.message = String::from(
                rendered
                    .strip_prefix('"')
                    .and_then(|message| message.strip_suffix('"'))
                    .unwrap_or(&rendered),
            );
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

/// Install a compact stderr subscriber using a global `RUST_LOG` level.
///
/// Supported values are `off`, `error`, `warn`, `info`, `debug`, and `trace`.
/// Calls after a subscriber has already been installed are ignored.
pub fn init() {
    let max_level = std::env::var("RUST_LOG")
        .ok()
        .as_deref()
        .and_then(parse_level)
        .unwrap_or(LevelFilter::INFO);
    let _ = tracing::subscriber::set_global_default(StderrSubscriber { max_level });
}

fn parse_level(value: &str) -> Option<LevelFilter> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::OFF),
        "error" => Some(LevelFilter::ERROR),
        "warn" | "warning" => Some(LevelFilter::WARN),
        "info" => Some(LevelFilter::INFO),
        "debug" => Some(LevelFilter::DEBUG),
        "trace" => Some(LevelFilter::TRACE),
        _ => None,
    }
}

fn level_enabled(level: Level, max: LevelFilter) -> bool {
    match level {
        Level::ERROR => max >= LevelFilter::ERROR,
        Level::WARN => max >= LevelFilter::WARN,
        Level::INFO => max >= LevelFilter::INFO,
        Level::DEBUG => max >= LevelFilter::DEBUG,
        Level::TRACE => max >= LevelFilter::TRACE,
    }
}

#[cfg(test)]
mod tests {
    use super::{level_enabled, parse_level};
    use tracing::level_filters::LevelFilter;
    use tracing::Level;

    #[test]
    fn parses_global_rust_log_levels() {
        assert_eq!(parse_level("trace"), Some(LevelFilter::TRACE));
        assert_eq!(parse_level("WARN"), Some(LevelFilter::WARN));
        assert_eq!(parse_level("target=debug"), None);
    }

    #[test]
    fn level_filter_is_a_ceiling() {
        assert!(level_enabled(Level::WARN, LevelFilter::WARN));
        assert!(!level_enabled(Level::INFO, LevelFilter::WARN));
    }
}
