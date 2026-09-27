// wifisentinel-core/src/db/mod.rs
// Database layer using sqlx + SQLite.

pub mod repository;
pub mod migrations;

use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::path::Path;
use tracing::{info, instrument};

use crate::Result;

/// Shared database pool.
pub type DbPool = SqlitePool;

/// Initialize the database pool and run migrations.
#[instrument(skip(db_path))]
pub async fn init_database(db_path: &Path, wal_mode: bool) -> Result<DbPool> {
    // Ensure parent directory exists.
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(crate::Error::Io)?;
    }

    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

    info!("Initializing database at {}", db_path.display());

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    // Enable WAL mode for better concurrent read performance.
    if wal_mode {
        sqlx::query("PRAGMA journal_mode=WAL;")
            .execute(&pool)
            .await?;
    }

    // Enable foreign keys.
    sqlx::query("PRAGMA foreign_keys=ON;")
        .execute(&pool)
        .await?;

    // Run migrations.
    migrations::run(&pool).await?;

    info!("Database initialized successfully");
    Ok(pool)
}
