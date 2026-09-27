// wifisentinel-core/src/db/migrations.rs
// Inline SQL migrations (no external migration files required).

use sqlx::SqlitePool;
use tracing::info;

use crate::Result;

/// Run all database migrations in order.
/// Migrations are idempotent — safe to call on each startup.
pub async fn run(pool: &SqlitePool) -> Result<()> {
    info!("Running database migrations");

    // Create migration tracking table.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS _migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(pool)
    .await?;

    apply(pool, "001_core_schema", MIGRATION_001).await?;
    apply(pool, "002_indexes", MIGRATION_002).await?;
    apply(pool, "003_trusted_lists", MIGRATION_003).await?;

    info!("Database migrations complete");
    Ok(())
}

async fn apply(pool: &SqlitePool, name: &str, sql: &str) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM _migrations WHERE name = ?)",
    )
    .bind(name)
    .fetch_one(pool)
    .await?;

    if !exists {
        info!("Applying migration: {}", name);
        // Execute multi-statement SQL.
        for statement in sql.split(';').filter(|s| !s.trim().is_empty()) {
            sqlx::query(statement).execute(pool).await?;
        }
        sqlx::query("INSERT INTO _migrations (name) VALUES (?)")
            .bind(name)
            .execute(pool)
            .await?;
    }

    Ok(())
}

const MIGRATION_001: &str = r#"
CREATE TABLE IF NOT EXISTS adapters (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    guid TEXT NOT NULL UNIQUE,
    mac_address TEXT,
    manufacturer TEXT,
    driver_version TEXT,
    driver_date TEXT,
    inf_file TEXT,
    driver_type TEXT,
    state TEXT NOT NULL DEFAULT 'unknown',
    connected_ssid TEXT,
    connected_bssid TEXT,
    active_band TEXT,
    active_channel INTEGER,
    active_phy TEXT,
    signal_dbm INTEGER,
    signal_percent INTEGER,
    rx_rate_mbps REAL,
    tx_rate_mbps REAL,
    supported_bands TEXT NOT NULL DEFAULT '[]',
    supported_phys TEXT NOT NULL DEFAULT '[]',
    fips_supported INTEGER,
    pmf_supported INTEGER,
    hosted_network_supported INTEGER,
    capture_capability TEXT NOT NULL DEFAULT 'unknown',
    monitor_mode_capability TEXT NOT NULL DEFAULT 'unknown',
    compatibility_score INTEGER NOT NULL DEFAULT 0,
    compatibility_notes TEXT NOT NULL DEFAULT '[]',
    supported_auth_ciphers TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_points (
    id TEXT PRIMARY KEY,
    bssid TEXT NOT NULL,
    ssid TEXT,
    vendor TEXT,
    band TEXT NOT NULL DEFAULT 'unknown',
    channel INTEGER NOT NULL,
    channel_width TEXT,
    rssi_dbm INTEGER NOT NULL,
    signal_percent INTEGER NOT NULL,
    phy TEXT,
    auth_mode TEXT NOT NULL DEFAULT 'unknown',
    cipher TEXT NOT NULL DEFAULT 'unknown',
    pmf TEXT,
    beacon_interval_tu INTEGER,
    capability_flags INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_trusted INTEGER NOT NULL DEFAULT 0,
    observed_by_adapter TEXT NOT NULL,
    network_id TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (observed_by_adapter) REFERENCES adapters(id),
    FOREIGN KEY (network_id) REFERENCES wireless_networks(id)
);

CREATE TABLE IF NOT EXISTS wireless_networks (
    id TEXT PRIMARY KEY,
    ssid TEXT NOT NULL,
    security_profile TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    is_trusted INTEGER NOT NULL DEFAULT 0,
    anomaly_flags TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    mac_address TEXT NOT NULL UNIQUE,
    vendor TEXT,
    associated_bssid TEXT,
    associated_ssid TEXT,
    associated_ap_id TEXT,
    rssi_dbm INTEGER,
    is_randomized_mac INTEGER NOT NULL DEFAULT 0,
    is_trusted INTEGER NOT NULL DEFAULT 0,
    anomaly_flags TEXT NOT NULL DEFAULT '[]',
    probe_requests_observed TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    frame_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS security_findings (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence_score INTEGER NOT NULL,
    confidence_explanation TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '[]',
    recommendation TEXT NOT NULL,
    technical_detail TEXT NOT NULL DEFAULT '',
    plain_explanation TEXT NOT NULL DEFAULT '',
    affected_ap_id TEXT,
    affected_client_id TEXT,
    related_finding_ids TEXT NOT NULL DEFAULT '[]',
    is_acknowledged INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (affected_ap_id) REFERENCES access_points(id),
    FOREIGN KEY (affected_client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    related_ap_id TEXT,
    related_ap_bssid TEXT,
    related_ap_ssid TEXT,
    related_client_id TEXT,
    related_client_mac TEXT,
    related_finding_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS capture_sessions (
    id TEXT PRIMARY KEY,
    adapter_name TEXT NOT NULL,
    device_name TEXT NOT NULL,
    monitor_mode INTEGER NOT NULL DEFAULT 0,
    filter TEXT,
    output_path TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    state TEXT NOT NULL DEFAULT 'stopped',
    packet_count INTEGER NOT NULL DEFAULT 0,
    dropped_count INTEGER NOT NULL DEFAULT 0,
    packet_rate REAL NOT NULL DEFAULT 0.0,
    file_size_bytes INTEGER NOT NULL DEFAULT 0,
    error TEXT
);

CREATE TABLE IF NOT EXISTS packets_meta (
    id TEXT PRIMARY KEY,
    capture_session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    frame_type TEXT NOT NULL,
    frame_subtype TEXT NOT NULL,
    source_mac TEXT,
    destination_mac TEXT,
    bssid TEXT,
    channel INTEGER,
    rssi_dbm INTEGER,
    data_rate_mbps REAL,
    has_radiotap INTEGER NOT NULL DEFAULT 0,
    payload_bytes INTEGER NOT NULL,
    is_encrypted INTEGER NOT NULL DEFAULT 0,
    is_retry INTEGER NOT NULL DEFAULT 0,
    sequence_number INTEGER,
    management_info TEXT,
    FOREIGN KEY (capture_session_id) REFERENCES capture_sessions(id)
);

CREATE TABLE IF NOT EXISTS signal_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ap_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    rssi_dbm INTEGER NOT NULL,
    FOREIGN KEY (ap_id) REFERENCES access_points(id)
);

CREATE TABLE IF NOT EXISTS channel_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ap_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    channel INTEGER NOT NULL,
    band TEXT NOT NULL,
    FOREIGN KEY (ap_id) REFERENCES access_points(id)
);

CREATE TABLE IF NOT EXISTS security_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ap_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    auth_mode TEXT NOT NULL,
    cipher TEXT NOT NULL,
    FOREIGN KEY (ap_id) REFERENCES access_points(id)
);

CREATE TABLE IF NOT EXISTS association_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    bssid TEXT NOT NULL,
    ssid TEXT,
    event_type TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id)
)
"#;

const MIGRATION_002: &str = r#"
CREATE INDEX IF NOT EXISTS idx_access_points_bssid ON access_points(bssid);
CREATE INDEX IF NOT EXISTS idx_access_points_ssid ON access_points(ssid);
CREATE INDEX IF NOT EXISTS idx_access_points_network_id ON access_points(network_id);
CREATE INDEX IF NOT EXISTS idx_access_points_last_seen ON access_points(last_seen);
CREATE INDEX IF NOT EXISTS idx_clients_mac ON clients(mac_address);
CREATE INDEX IF NOT EXISTS idx_clients_associated_bssid ON clients(associated_bssid);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON security_findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON security_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_is_active ON security_findings(is_active);
CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_timeline_event_type ON timeline_events(event_type);
CREATE INDEX IF NOT EXISTS idx_timeline_severity ON timeline_events(severity);
CREATE INDEX IF NOT EXISTS idx_packets_session ON packets_meta(capture_session_id);
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets_meta(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_frame_type ON packets_meta(frame_type);
CREATE INDEX IF NOT EXISTS idx_signal_history_ap ON signal_history(ap_id);
CREATE INDEX IF NOT EXISTS idx_channel_history_ap ON channel_history(ap_id)
"#;

const MIGRATION_003: &str = r#"
CREATE TABLE IF NOT EXISTS trusted_ssids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL UNIQUE,
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS trusted_bssids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid TEXT NOT NULL UNIQUE,
    ssid TEXT,
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS trusted_vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT NOT NULL UNIQUE,
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS ignored_ssids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid TEXT NOT NULL UNIQUE,
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS configuration (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"#;
