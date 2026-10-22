use std::fmt::Write as _;
use std::io::IsTerminal as _;
use std::string::String;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::span::{self, Id};
use tracing::{Event, Level, Metadata, Subscriber};

static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);
static INIT: Once = Once::new();

struct TestSubscriber {
    max_level: LevelFilter,
}

pub(super) fn init() {
    INIT.call_once(|| {
        let max_level = std::env::var("RUST_LOG")
            .ok()
            .as_deref()
            .and_then(parse_level)
            .unwrap_or(LevelFilter::INFO);
        let _ = tracing::subscriber::set_global_default(TestSubscriber { max_level });
    });
}

impl Subscriber for TestSubscriber {
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
        let level = format_level(*metadata.level(), std::io::stderr().is_terminal());
        std::eprintln!(
            "{} {} {}: {}{}",
            level,
            metadata.target(),
            metadata
                .name()
                .strip_prefix("event ")
                .unwrap_or_else(|| metadata.name()),
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

fn format_level(level: Level, is_terminal: bool) -> String {
    let label = level.as_str();
    if !is_terminal || std::env::var_os("NO_COLOR").is_some() {
        return String::from(label);
    }

    let color = match level {
        Level::ERROR => "31",
        Level::WARN => "33",
        Level::INFO => "34",
        Level::DEBUG => "32",
        Level::TRACE => "37",
    };
    std::format!("\x1b[{color}m{label}\x1b[0m")
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
