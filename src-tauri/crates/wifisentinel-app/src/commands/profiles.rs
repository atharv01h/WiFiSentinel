use std::os::windows::process::CommandExt;
const CREATE_NO_WINDOW: u32 = 0x08000000;
// wifisentinel-app/src/commands/profiles.rs

use serde::{Deserialize, Serialize};
use std::process::Command;
use wifisentinel_core::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct SavedProfile {
    pub ssid: String,
    pub password: Option<String>,
}

#[tauri::command]
pub async fn getsavedprofiles() -> Result<Vec<SavedProfile>, Error> {
    let mut profiles = Vec::new();
    
    // Get profiles list
    let output = tokio::task::spawn_blocking(|| {
        Command::new("netsh").creation_flags(CREATE_NO_WINDOW)
            .args(&["wlan", "show", "profiles"])
            .output()
    })
    .await
    .map_err(|e| Error::Other(format!("Task panic: {}", e)))?
    .map_err(|e| Error::Other(format!("Failed to execute netsh: {}", e)))?;
        
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    for line in stdout.lines() {
        if line.contains("All User Profile") || line.contains("User Profile") {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let ssid = parts[1..].join(":").trim().to_string();
                if !ssid.is_empty() {
                    profiles.push(SavedProfile {
                        ssid,
                        password: None,
                    });
                }
            }
        }
    }
    
    // Get passwords for each profile concurrently
    let mut tasks = Vec::new();
    for mut profile in profiles {
        let ssid = profile.ssid.clone();
        let task = tokio::task::spawn_blocking(move || {
            let output = Command::new("netsh").creation_flags(CREATE_NO_WINDOW)
                .args(&["wlan", "show", "profile", &format!("name={}", ssid), "key=clear"])
                .output();
                
            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("Key Content") {
                        let parts: Vec<&str> = line.split(':').collect();
                        if parts.len() >= 2 {
                            profile.password = Some(parts[1..].join(":").trim().to_string());
                        }
                        break;
                    }
                }
            }
            profile
        });
        tasks.push(task);
    }
    
    let mut final_profiles = Vec::new();
    for task in tasks {
        if let Ok(profile) = task.await {
            final_profiles.push(profile);
        }
    }
    
    Ok(final_profiles)
}

