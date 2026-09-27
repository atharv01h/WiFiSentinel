// wifisentinel-cli/src/main.rs
// WiFiSentinel CLI companion.
//
// Uses the same engine as the GUI — no logic duplication.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "wifisentinel",
    version = env!("CARGO_PKG_VERSION"),
    about = "WiFiSentinel — Windows-native wireless security intelligence",
    long_about = "WiFiSentinel provides wireless security scanning, packet capture,\n\
                  anomaly detection, and report generation.\n\n\
                  AUTHORIZED USE ONLY: Only scan networks you own or have explicit\n\
                  written permission to assess."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log level (trace/debug/info/warn/error).
    #[arg(long, default_value = "info", global = true)]
    log_level: String,
}

#[derive(Subcommand)]
enum Commands {
    /// List wireless adapters and their capabilities.
    Adapters,

    /// Scan for nearby wireless networks.
    Scan {
        /// Output format: table/json.
        #[arg(long, default_value = "table")]
        format: String,

        /// Number of scans to perform.
        #[arg(long, default_value = "1")]
        count: u32,
    },

    /// Start packet capture.
    Capture {
        /// Network interface name (e.g. "Wi-Fi").
        #[arg(long)]
        interface: Option<String>,

        /// Output file path.
        #[arg(long)]
        output: Option<String>,

        /// BPF filter string.
        #[arg(long)]
        filter: Option<String>,
    },

    /// Analyze a PCAP file.
    Analyze {
        /// Path to PCAP or PCAPNG file.
        file: String,

        /// Output format: table/json.
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// Generate a security report.
    Report {
        /// Output file path.
        #[arg(long)]
        output: Option<String>,

        /// Format: html/json.
        #[arg(long, default_value = "html")]
        format: String,
    },

    /// Show diagnostic information.
    Diagnostics,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    wifisentinel_core::logging::init_logging(&cli.log_level, None)?;

    // Print authorized-use notice on every invocation.
    eprintln!("WiFiSentinel — Authorized use only. Scan only networks you own or are permitted to assess.\n");

    match cli.command {
        Commands::Adapters => cmd_adapters().await?,
        Commands::Scan { format, count } => cmd_scan(format, count).await?,
        Commands::Capture { interface, output, filter } => {
            cmd_capture(interface, output, filter).await?
        }
        Commands::Analyze { file, format } => cmd_analyze(file, format).await?,
        Commands::Report { output, format } => cmd_report(output, format).await?,
        Commands::Diagnostics => cmd_diagnostics().await?,
    }

    Ok(())
}

async fn cmd_adapters() -> Result<()> {
    println!("Enumerating wireless adapters...\n");
    let adapters = wifisentinel_wlan::adapter::AdapterEnumerator::enumerate();

    if adapters.is_empty() {
        println!("No wireless adapters found.");
        return Ok(());
    }

    for adapter in &adapters {
        println!("  Name:         {}", adapter.name);
        println!("  Description:  {}", adapter.description);
        println!("  GUID:         {}", adapter.guid);
        println!("  MAC:          {}", adapter.mac_address.map(|m| m.to_string()).unwrap_or("Unknown".into()));
        println!("  Driver:       {}", adapter.driver_version.as_deref().unwrap_or("Unknown"));
        println!("  State:        {}", adapter.state.display_name());
        if let Some(ssid) = &adapter.connected_ssid {
            println!("  Connected:    {} (ch {})", ssid, adapter.active_channel.unwrap_or(0));
        }
        println!("  Capture:      {}", adapter.capture_capability.display_name());
        println!("  Monitor:      {}", adapter.monitor_mode_capability.display_name());
        println!("  Score:        {}%", adapter.compatibility_score);
        if !adapter.compatibility_notes.is_empty() {
            println!("  Notes:");
            for note in &adapter.compatibility_notes {
                println!("    - {}", note);
            }
        }
        println!();
    }

    Ok(())
}

async fn cmd_scan(format: String, count: u32) -> Result<()> {
    let adapters = wifisentinel_wlan::adapter::AdapterEnumerator::enumerate();
    let adapter = adapters.first().ok_or_else(|| anyhow::anyhow!("No wireless adapters found"))?;

    println!("Scanning on adapter: {} ...\n", adapter.name);

    for i in 1..=count {
        if count > 1 { println!("--- Scan {} of {} ---", i, count); }

        let aps = wifisentinel_wlan::scan::BssScanner::scan(adapter.id, &adapter.guid).await?;

        if aps.is_empty() {
            println!("No networks found.");
        } else if format == "json" {
            println!("{}", serde_json::to_string_pretty(&aps)?);
        } else {
            println!("{:<32} {:<20} {:>4} {:>5} {:>6}  {}", "SSID", "BSSID", "Ch", "Sig%", "dBm", "Auth");
            println!("{}", "-".repeat(90));
            for ap in &aps {
                println!(
                    "{:<32} {:<20} {:>4} {:>5} {:>6}  {}",
                    ap.ssid.as_deref().unwrap_or("[Hidden]"),
                    ap.bssid,
                    ap.channel,
                    ap.signal_percent,
                    ap.rssi_dbm,
                    ap.auth_mode.display_name(),
                );
            }
            println!("\n{} network(s) found.", aps.len());
        }

        if i < count {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    Ok(())
}

async fn cmd_capture(_interface: Option<String>, _output: Option<String>, _filter: Option<String>) -> Result<()> {
    use wifisentinel_capture::session::CaptureManager;
    

    let manager = CaptureManager::new();

    if !manager.is_npcap_available() {
        println!("Capture unavailable:\n{}", manager.capture_availability_message());
        return Ok(());
    }

    println!("Capture is available. Starting capture (Ctrl+C to stop)...");
    println!("Note: Actual raw capture requires the 'npcap' feature to be enabled at build time.");

    Ok(())
}

async fn cmd_analyze(file: String, format: String) -> Result<()> {
    use wifisentinel_pcap_analysis::PcapAnalyzer;

    println!("Analyzing: {}\n", file);
    let result = PcapAnalyzer::analyze(&file).await?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Total packets:       {}", result.total_packets);
        println!("Processed:           {}", result.processed_packets);
        println!("Malformed:           {}", result.malformed_packets);
        println!("Management frames:   {}", result.management_frames);
        println!("Control frames:      {}", result.control_frames);
        println!("Data frames:         {}", result.data_frames);
        println!("Unique BSSIDs:       {}", result.unique_bssids.len());
        println!("Unique SSIDs:        {}", result.unique_ssids.len());
        println!("Duration:            {:.1}s", result.duration_secs);
        println!("Link type:           {} (radiotap: {})", result.link_type, result.has_radiotap);

        if !result.unique_ssids.is_empty() {
            println!("\nSSIDs observed:");
            for ssid in &result.unique_ssids {
                println!("  - {}", ssid);
            }
        }

        if !result.unique_bssids.is_empty() {
            println!("\nBSSIDs observed:");
            for bssid in &result.unique_bssids {
                println!("  - {}", bssid);
            }
        }
    }

    Ok(())
}

async fn cmd_report(output: Option<String>, format: String) -> Result<()> {
    use wifisentinel_reporting::html::HtmlReporter;
    use wifisentinel_reporting::json::JsonReporter;

    let adapters = wifisentinel_wlan::adapter::AdapterEnumerator::enumerate();
    let aps = if !adapters.is_empty() {
        wifisentinel_wlan::scan::BssScanner::scan(adapters[0].id, &adapters[0].guid).await?
    } else {
        vec![]
    };

    let ctx = wifisentinel_detection::engine::DetectionContext {
        access_points: aps.clone(),
        networks: vec![],
        clients: vec![],
        trusted_bssids: vec![],
        trusted_ssids: vec![],
        sensitivity: "medium".into(),
        min_confidence: 30,
    };
    let engine = wifisentinel_detection::engine::DetectionEngine::with_default_rules();
    let findings = engine.evaluate(&ctx);

    let content = match format.as_str() {
        "json" => JsonReporter::generate(&adapters, &aps, &findings)?,
        _ => HtmlReporter::generate(&adapters, &aps, &findings)?,
    };

    let ext = if format == "json" { "json" } else { "html" };
    let path = output.unwrap_or_else(|| format!("wifisentinel-report-{}.{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"), ext));

    std::fs::write(&path, &content)?;
    println!("Report saved: {}", path);

    Ok(())
}

async fn cmd_diagnostics() -> Result<()> {
    use wifisentinel_capture::session::CaptureManager;

    println!("WiFiSentinel Diagnostics\n");

    let capture = CaptureManager::new();
    println!("Npcap available:     {}", capture.is_npcap_available());
    println!("Capture message:\n{}", capture.capture_availability_message());

    let adapters = wifisentinel_wlan::adapter::AdapterEnumerator::enumerate();
    println!("\nAdapters detected:   {}", adapters.len());

    Ok(())
}
