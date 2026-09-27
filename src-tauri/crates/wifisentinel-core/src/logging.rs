// wifisentinel-core/src/logging.rs
// Structured logging initialization.

use std::path::Path;
use tracing::Level;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the tracing subscriber.
///
/// Writes to stderr and optionally to a rolling log file.
/// Does NOT log secrets or sensitive data.
pub fn init_logging(log_level: &str, log_dir: Option<&Path>) -> anyhow::Result<()> {
    let level = log_level.parse::<Level>().unwrap_or(Level::INFO);

    let filter = EnvFilter::from_default_env()
        .add_directive(
            format!("wifisentinel={}", level).parse()?,
        )
        .add_directive("tokio=warn".parse()?)
        .add_directive("sqlx=warn".parse()?);

    let registry = tracing_subscriber::registry().with(filter);

    if let Some(dir) = log_dir {
        std::fs::create_dir_all(dir)?;

        let file_appender = tracing_appender::rolling::daily(dir, "wifisentinel.log");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        // File: JSON format for machine parsing
        let file_layer = fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_target(true)
            .with_thread_ids(true);

        // Stderr: human-readable
        let stderr_layer = fmt::layer()
            .with_writer(std::io::stderr)
            .with_target(false)
            .compact();

        registry
            .with(file_layer)
            .with(stderr_layer)
            .init();

        // Guard must be kept alive — we accept the leak here since
        // the process lifetime == guard lifetime.
        std::mem::forget(_guard);
    } else {
        let stderr_layer = fmt::layer()
            .with_writer(std::io::stderr)
            .compact();

        registry.with(stderr_layer).init();
    }

    Ok(())
}

/// Diagnostic information for the logging subsystem.
#[derive(Debug, serde::Serialize)]
pub struct LoggingDiagnostics {
    pub level: String,
    pub file_logging: bool,
    pub log_dir: Option<String>,
}
