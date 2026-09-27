// wifisentinel-core/src/db/repository.rs
// Data access layer — typed queries over the database.

use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;
use tracing::{debug, instrument};

use crate::{
    models::{
        AccessPoint, WirelessAdapter,
        SecurityFinding, TimelineEvent,
    },
    Result,
};

// ──────────────────────────────────────────────
// Access Point Repository
// ──────────────────────────────────────────────

pub struct ApRepository<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ApRepository<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    #[instrument(skip(self, ap))]
    pub async fn upsert(&self, ap: &AccessPoint) -> Result<()> {
        debug!("Upserting AP: {}", ap.bssid);

        sqlx::query(
            "INSERT INTO access_points (
                id, bssid, ssid, vendor, band, channel, channel_width,
                rssi_dbm, signal_percent, phy, auth_mode, cipher, pmf,
                beacon_interval_tu, capability_flags, is_active, is_trusted,
                observed_by_adapter, network_id, first_seen, last_seen,
                observation_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                ssid = excluded.ssid,
                vendor = excluded.vendor,
                band = excluded.band,
                channel = excluded.channel,
                channel_width = excluded.channel_width,
                rssi_dbm = excluded.rssi_dbm,
                signal_percent = excluded.signal_percent,
                phy = excluded.phy,
                auth_mode = excluded.auth_mode,
                cipher = excluded.cipher,
                pmf = excluded.pmf,
                beacon_interval_tu = excluded.beacon_interval_tu,
                capability_flags = excluded.capability_flags,
                is_active = excluded.is_active,
                last_seen = excluded.last_seen,
                observation_count = excluded.observation_count",
        )
        .bind(ap.id.to_string())
        .bind(ap.bssid.to_string())
        .bind(ap.ssid.as_deref())
        .bind(ap.vendor.as_deref())
        .bind(serde_json::to_string(&ap.band).unwrap_or_default())
        .bind(ap.channel as i64)
        .bind(ap.channel_width.as_ref().map(|w| serde_json::to_string(w).unwrap_or_default()))
        .bind(ap.rssi_dbm as i64)
        .bind(ap.signal_percent as i64)
        .bind(ap.phy.as_ref().map(|p| serde_json::to_string(p).unwrap_or_default()))
        .bind(serde_json::to_string(&ap.auth_mode).unwrap_or_default())
        .bind(serde_json::to_string(&ap.cipher).unwrap_or_default())
        .bind(ap.pmf.as_ref().map(|p| serde_json::to_string(p).unwrap_or_default()))
        .bind(ap.beacon_interval_tu.map(|b| b as i64))
        .bind(ap.capability_flags.map(|c| c as i64))
        .bind(ap.is_active as i64)
        .bind(ap.is_trusted as i64)
        .bind(ap.observed_by_adapter.to_string())
        .bind(ap.network_id.map(|n| n.to_string()))
        .bind(ap.first_seen.to_rfc3339())
        .bind(ap.last_seen.to_rfc3339())
        .bind(ap.observation_count as i64)
        .execute(self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_by_bssid(&self, bssid: &str) -> Result<Option<Uuid>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM access_points WHERE bssid = ? LIMIT 1",
        )
        .bind(bssid)
        .fetch_optional(self.pool)
        .await?;

        Ok(row.map(|(id,)| Uuid::parse_str(&id).ok()).flatten())
    }

    pub async fn get_all(&self) -> Result<Vec<ApRow>> {
        let rows = sqlx::query_as::<_, ApRow>(
            "SELECT id, bssid, ssid, vendor, band, channel, rssi_dbm, signal_percent,
                    auth_mode, cipher, is_active, is_trusted, first_seen, last_seen,
                    observation_count, phy, channel_width, pmf, beacon_interval_tu
             FROM access_points ORDER BY last_seen DESC"
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn mark_inactive_before(&self, cutoff: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE access_points SET is_active = 0 WHERE last_seen < ?",
        )
        .bind(cutoff.to_rfc3339())
        .execute(self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn record_signal(&self, ap_id: Uuid, rssi_dbm: i16) -> Result<()> {
        sqlx::query(
            "INSERT INTO signal_history (ap_id, timestamp, rssi_dbm) VALUES (?, ?, ?)"
        )
        .bind(ap_id.to_string())
        .bind(Utc::now().to_rfc3339())
        .bind(rssi_dbm as i64)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_channel_change(&self, ap_id: Uuid, channel: u8, band: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO channel_history (ap_id, timestamp, channel, band) VALUES (?, ?, ?, ?)"
        )
        .bind(ap_id.to_string())
        .bind(Utc::now().to_rfc3339())
        .bind(channel as i64)
        .bind(band)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn count_active(&self) -> Result<i64> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM access_points WHERE is_active = 1"
        )
        .fetch_one(self.pool)
        .await?;
        Ok(count.0)
    }

    pub async fn count_by_band(&self) -> Result<Vec<(String, i64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT band, COUNT(*) as cnt FROM access_points WHERE is_active = 1 GROUP BY band"
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }
}

/// Lightweight row type for AP list queries.
#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct ApRow {
    pub id: String,
    pub bssid: String,
    pub ssid: Option<String>,
    pub vendor: Option<String>,
    pub band: String,
    pub channel: i64,
    pub rssi_dbm: i64,
    pub signal_percent: i64,
    pub auth_mode: String,
    pub cipher: String,
    pub is_active: i64,
    pub is_trusted: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub observation_count: i64,
    pub phy: Option<String>,
    pub channel_width: Option<String>,
    pub pmf: Option<String>,
    pub beacon_interval_tu: Option<i64>,
}

// ──────────────────────────────────────────────
// Timeline Repository
// ──────────────────────────────────────────────

pub struct TimelineRepository<'a> {
    pool: &'a SqlitePool,
}

impl<'a> TimelineRepository<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, event: &TimelineEvent) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO timeline_events (
                id, timestamp, event_type, description, severity,
                related_ap_id, related_ap_bssid, related_ap_ssid,
                related_client_id, related_client_mac, related_finding_id, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(event.id.to_string())
        .bind(event.timestamp.to_rfc3339())
        .bind(serde_json::to_string(&event.event_type).unwrap_or_default().trim_matches('"').to_string())
        .bind(&event.description)
        .bind(serde_json::to_string(&event.severity).unwrap_or_default().trim_matches('"').to_string())
        .bind(event.related_ap_id.map(|id| id.to_string()))
        .bind(event.related_ap_bssid.as_deref())
        .bind(event.related_ap_ssid.as_deref())
        .bind(event.related_client_id.map(|id| id.to_string()))
        .bind(event.related_client_mac.as_deref())
        .bind(event.related_finding_id.map(|id| id.to_string()))
        .bind(event.metadata.to_string())
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn query(
        &self,
        limit: i64,
        offset: i64,
        severity_filter: Option<&str>,
        ap_bssid_filter: Option<&str>,
    ) -> Result<Vec<TimelineRow>> {
        // Build dynamic query with optional filters.
        let mut conditions = vec!["1=1"];
        let mut q = String::from(
            "SELECT id, timestamp, event_type, description, severity,
                    related_ap_bssid, related_ap_ssid, related_client_mac,
                    related_finding_id, metadata
             FROM timeline_events WHERE "
        );

        if severity_filter.is_some() {
            conditions.push("severity = ?");
        }
        if ap_bssid_filter.is_some() {
            conditions.push("related_ap_bssid = ?");
        }

        q.push_str(&conditions.join(" AND "));
        q.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

        let mut query = sqlx::query_as::<_, TimelineRow>(&q);

        if let Some(s) = severity_filter {
            query = query.bind(format!("\"{}\"", s));
        }
        if let Some(b) = ap_bssid_filter {
            query = query.bind(b);
        }
        query = query.bind(limit).bind(offset);

        Ok(query.fetch_all(self.pool).await?)
    }
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct TimelineRow {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
    pub severity: String,
    pub related_ap_bssid: Option<String>,
    pub related_ap_ssid: Option<String>,
    pub related_client_mac: Option<String>,
    pub related_finding_id: Option<String>,
    pub metadata: String,
}

// ──────────────────────────────────────────────
// Findings Repository
// ──────────────────────────────────────────────

pub struct FindingsRepository<'a> {
    pool: &'a SqlitePool,
}

impl<'a> FindingsRepository<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, finding: &SecurityFinding) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO security_findings (
                id, rule_id, title, description, severity,
                confidence_score, confidence_explanation, evidence,
                recommendation, technical_detail, plain_explanation,
                affected_ap_id, affected_client_id, related_finding_ids,
                is_acknowledged, is_active, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(finding.id.to_string())
        .bind(&finding.rule_id)
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(serde_json::to_string(&finding.severity).unwrap_or_default().trim_matches('"').to_string())
        .bind(finding.confidence.score as i64)
        .bind(&finding.confidence.explanation)
        .bind(serde_json::to_string(&finding.evidence).unwrap_or_default())
        .bind(&finding.recommendation)
        .bind(&finding.technical_detail)
        .bind(&finding.plain_explanation)
        .bind(finding.affected_ap_id.map(|id| id.to_string()))
        .bind(finding.affected_client_id.map(|id| id.to_string()))
        .bind(serde_json::to_string(&finding.related_finding_ids).unwrap_or_default())
        .bind(finding.is_acknowledged as i64)
        .bind(finding.is_active as i64)
        .bind(finding.created_at.to_rfc3339())
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_active(&self) -> Result<Vec<FindingRow>> {
        let rows = sqlx::query_as::<_, FindingRow>(
            "SELECT id, rule_id, title, severity, confidence_score, is_active,
                    affected_ap_id, created_at, recommendation, plain_explanation
             FROM security_findings WHERE is_active = 1
             ORDER BY severity DESC, created_at DESC"
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn acknowledge(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE security_findings SET is_acknowledged = 1 WHERE id = ?")
            .bind(id.to_string())
            .execute(self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct FindingRow {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub confidence_score: i64,
    pub is_active: i64,
    pub affected_ap_id: Option<String>,
    pub created_at: String,
    pub recommendation: String,
    pub plain_explanation: String,
}

// ──────────────────────────────────────────────
// Adapter Repository
// ──────────────────────────────────────────────

pub struct AdapterRepository<'a> {
    pool: &'a SqlitePool,
}

impl<'a> AdapterRepository<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn upsert(&self, adapter: &WirelessAdapter) -> Result<()> {
        sqlx::query(
            "INSERT INTO adapters (
                id, name, description, guid, mac_address, manufacturer,
                driver_version, driver_date, inf_file, driver_type, state,
                connected_ssid, connected_bssid, active_band, active_channel,
                active_phy, signal_dbm, signal_percent, rx_rate_mbps, tx_rate_mbps,
                supported_bands, supported_phys, fips_supported, pmf_supported,
                hosted_network_supported, capture_capability, monitor_mode_capability,
                compatibility_score, compatibility_notes, supported_auth_ciphers,
                first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(guid) DO UPDATE SET
                state = excluded.state,
                connected_ssid = excluded.connected_ssid,
                connected_bssid = excluded.connected_bssid,
                active_band = excluded.active_band,
                active_channel = excluded.active_channel,
                active_phy = excluded.active_phy,
                signal_dbm = excluded.signal_dbm,
                signal_percent = excluded.signal_percent,
                rx_rate_mbps = excluded.rx_rate_mbps,
                tx_rate_mbps = excluded.tx_rate_mbps,
                capture_capability = excluded.capture_capability,
                monitor_mode_capability = excluded.monitor_mode_capability,
                compatibility_score = excluded.compatibility_score,
                compatibility_notes = excluded.compatibility_notes,
                last_seen = excluded.last_seen"
        )
        .bind(adapter.id.to_string())
        .bind(&adapter.name)
        .bind(&adapter.description)
        .bind(&adapter.guid)
        .bind(adapter.mac_address.map(|m| m.to_string()))
        .bind(adapter.manufacturer.as_deref())
        .bind(adapter.driver_version.as_deref())
        .bind(adapter.driver_date.as_deref())
        .bind(adapter.inf_file.as_deref())
        .bind(adapter.driver_type.as_deref())
        .bind(serde_json::to_string(&adapter.state).unwrap_or_default())
        .bind(adapter.connected_ssid.as_deref())
        .bind(adapter.connected_bssid.as_deref())
        .bind(adapter.active_band.as_ref().map(|b| serde_json::to_string(b).unwrap_or_default()))
        .bind(adapter.active_channel.map(|c| c as i64))
        .bind(adapter.active_phy.as_ref().map(|p| serde_json::to_string(p).unwrap_or_default()))
        .bind(adapter.signal_dbm.map(|s| s as i64))
        .bind(adapter.signal_percent.map(|s| s as i64))
        .bind(adapter.rx_rate_mbps)
        .bind(adapter.tx_rate_mbps)
        .bind(serde_json::to_string(&adapter.supported_bands).unwrap_or_default())
        .bind(serde_json::to_string(&adapter.supported_phys).unwrap_or_default())
        .bind(adapter.fips_supported.map(|b| b as i64))
        .bind(adapter.pmf_supported.map(|b| b as i64))
        .bind(adapter.hosted_network_supported.map(|b| b as i64))
        .bind(serde_json::to_string(&adapter.capture_capability).unwrap_or_default())
        .bind(serde_json::to_string(&adapter.monitor_mode_capability).unwrap_or_default())
        .bind(adapter.compatibility_score as i64)
        .bind(serde_json::to_string(&adapter.compatibility_notes).unwrap_or_default())
        .bind(serde_json::to_string(&adapter.supported_auth_ciphers).unwrap_or_default())
        .bind(adapter.first_seen.to_rfc3339())
        .bind(adapter.last_seen.to_rfc3339())
        .execute(self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_all(&self) -> Result<Vec<AdapterRow>> {
        let rows = sqlx::query_as::<_, AdapterRow>(
            "SELECT id, name, description, guid, mac_address, manufacturer,
                    driver_version, state, active_band, active_channel,
                    signal_percent, capture_capability, monitor_mode_capability,
                    compatibility_score, connected_ssid, supported_bands, active_phy,
                    fips_supported, pmf_supported
             FROM adapters ORDER BY name"
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct AdapterRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub guid: String,
    pub mac_address: Option<String>,
    pub manufacturer: Option<String>,
    pub driver_version: Option<String>,
    pub state: String,
    pub active_band: Option<String>,
    pub active_channel: Option<i64>,
    pub signal_percent: Option<i64>,
    pub capture_capability: String,
    pub monitor_mode_capability: String,
    pub compatibility_score: i64,
    pub connected_ssid: Option<String>,
    pub supported_bands: String,
    pub active_phy: Option<String>,
    pub fips_supported: Option<i64>,
    pub pmf_supported: Option<i64>,
}
