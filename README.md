<div align="center">
  <img src="WiFiSentinel%20icon.png" alt="WiFiSentinel Logo" width="150"/>
  <h1>WiFiSentinel</h1>
  <p><b>Advanced 802.11 Analysis, Live Capture, and Security Auditing Platform</b></p>
  <p><i>Created by Atharv Hatwar</i></p>

  <p>
    <a href="https://github.com/atharv01h/WiFiSentinel/releases"><img src="https://img.shields.io/github/v/release/atharv01h/WiFiSentinel?style=for-the-badge&color=10b981" alt="Release" /></a>
    <img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge&logo=windows" alt="Platform" />
    <img src="https://img.shields.io/badge/Built_with-Tauri_&_Rust-orange?style=for-the-badge&logo=rust" alt="Tauri & Rust" />
  </p>
</div>

---

## 🛡️ Overview

**WiFiSentinel** is a highly capable and visually stunning wireless security and analysis desktop application. Built exclusively for Windows using **Tauri** and **Rust**, it offers performance-critical packet capture combined with a premium, hardware-accelerated React frontend.

Designed for network administrators, security researchers, and enthusiasts, WiFiSentinel simplifies the complex task of monitoring 802.11 traffic, auditing network configurations, and analyzing raw PCAP data in real-time.

## ✨ Key Features

- 📡 **Live Wireless Discovery**: Scan for nearby Access Points (APs) and view real-time data including SSIDs, BSSIDs, signal strength (RSSI), channel distribution, and security protocols.
- 🦈 **Raw Packet Capture (Monitor Mode)**: Leverage Npcap to capture raw 802.11 frames directly from your wireless adapter.
- 📦 **Offline PCAP Analysis**: Load saved `.pcap` or `.pcapng` files for deep inspection. Features a detailed Wireshark-like packet list that parses Management, Control, and Data frames.
- 🔒 **Security Posture & Findings**: Automatically analyze networks for misconfigurations (e.g., Open networks, weak WEP/WPA encryption, missing PMF).
- 🎨 **Premium UI/UX**: A dark-mode, glassmorphic design system inspired by modern security tooling, featuring high-performance data tables and real-time metric updates.

---

## 🚀 Installation

### Prerequisites (Windows)
1. Ensure your wireless adapter supports monitor mode (if you intend to use live capture features).
2. You **must** install [Npcap](https://npcap.com/) (with "Install Npcap in WinPcap API-compatible Mode" enabled) to enable raw packet capture capabilities.

### Downloading the App
1. Go to the [Releases](https://github.com/atharv01h/WiFiSentinel/releases) page.
2. Download the latest `WiFiSentinel_setup.exe` or `.msi` file.
3. Run the installer and launch **WiFiSentinel** (Run as Administrator is recommended for packet capture).

---

## 🛠️ Building from Source

If you wish to compile WiFiSentinel yourself, ensure you have the following installed:
- [Node.js](https://nodejs.org/) (v18+)
- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- Visual Studio Build Tools with C++ workload (for Rust Windows compilation)
- Npcap SDK (extracted and linked via the `LIB` environment variable)

```bash
# Clone the repository
git clone https://github.com/atharv01h/WiFiSentinel.git
cd WiFiSentinel

# Install frontend dependencies
npm install

# Build the application
# Note: Ensure the Npcap SDK /Lib/x64 path is available to the Rust compiler
$env:LIB="C:\path\to\Npcap-SDK\Lib\x64"
npm run tauri build
```

---

## 📖 Usage Guide

1. **Dashboard**: View high-level metrics, active capture status, and recent security findings.
2. **Networks**: See a live list of discovered Access Points and their configurations.
3. **Capture**: Start or stop live 802.11 packet capture. Ensure the app is running as Administrator!
4. **PCAP Analysis**: Load a previously captured `.pcap` file to view a breakdown of frame types and a detailed list of all recorded packets.

---

## 👨‍💻 Author

**Atharv Hatwar**
- GitHub: [@atharv01h](https://github.com/atharv01h)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
