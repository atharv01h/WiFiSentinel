// wifisentinel-core/src/lib.rs
// Core library: re-exports all public modules.

pub mod config;
pub mod db;
pub mod error;
pub mod logging;
pub mod models;

pub use error::{Error, Result};
