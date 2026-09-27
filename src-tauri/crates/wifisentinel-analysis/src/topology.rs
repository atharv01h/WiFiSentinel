// wifisentinel-analysis/src/topology.rs
// Network topology representation.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use wifisentinel_core::models::{AccessPoint, ClientDevice, WirelessNetwork};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub node_type: NodeType,
    pub label: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub band: Option<String>,
    pub channel: Option<u8>,
    pub signal_pct: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Network,
    AccessPoint,
    Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyGraph {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

pub fn build_topology(
    networks: &[WirelessNetwork],
    aps: &[AccessPoint],
    clients: &[ClientDevice],
) -> TopologyGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    let ap_by_id: HashMap<Uuid, &AccessPoint> = aps.iter().map(|a| (a.id, a)).collect();

    // Add network nodes.
    for net in networks {
        nodes.push(TopologyNode {
            id: format!("net-{}", net.id),
            node_type: NodeType::Network,
            label: net.ssid.clone(),
            bssid: None,
            ssid: Some(net.ssid.clone()),
            band: None,
            channel: None,
            signal_pct: None,
        });

        // Add AP nodes and edges.
        for ap_id in &net.ap_ids {
            if let Some(ap) = ap_by_id.get(ap_id) {
                nodes.push(TopologyNode {
                    id: format!("ap-{}", ap.id),
                    node_type: NodeType::AccessPoint,
                    label: ap.bssid.to_string(),
                    bssid: Some(ap.bssid.to_string()),
                    ssid: ap.ssid.clone(),
                    band: Some(ap.band.display_name().to_string()),
                    channel: Some(ap.channel),
                    signal_pct: Some(ap.signal_percent),
                });
                edges.push(TopologyEdge {
                    source: format!("net-{}", net.id),
                    target: format!("ap-{}", ap.id),
                    label: format!("ch {}", ap.channel),
                });
            }
        }
    }

    // Add client nodes and edges.
    for client in clients {
        nodes.push(TopologyNode {
            id: format!("client-{}", client.id),
            node_type: NodeType::Client,
            label: client.mac_address.to_string(),
            bssid: Some(client.mac_address.to_string()),
            ssid: client.associated_ssid.clone(),
            band: None,
            channel: None,
            signal_pct: client.rssi_dbm.map(|r| AccessPoint::signal_pct_from_dbm(r)),
        });

        if let Some(assoc_bssid) = &client.associated_bssid {
            if let Some(ap) = aps.iter().find(|a| a.bssid.to_string() == assoc_bssid.to_string()) {
                edges.push(TopologyEdge {
                    source: format!("client-{}", client.id),
                    target: format!("ap-{}", ap.id),
                    label: "associated".into(),
                });
            }
        }
    }

    TopologyGraph { nodes, edges }
}
