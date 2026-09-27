// wifisentinel-detection/src/lib.rs

pub mod engine;
pub mod posture;
pub mod rules;

pub use engine::{DetectionContext, DetectionEngine, DetectionRule, Finding};
