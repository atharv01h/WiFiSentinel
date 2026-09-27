import { useState } from "react";
import { Search, Activity, Cpu, AlertCircle, FileSearch, Hash, List } from "lucide-react";
import { analyzePcap } from "../api/commands";
import type { PcapAnalysisResult } from "../api/types";

export default function PcapAnalysis() {
  const [filePath, setFilePath] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PcapAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!filePath) return;
    setLoading(true);
    setError(null);
    setResult(null);
    
    try {
      const res = await analyzePcap(filePath);
      setResult(res);
    } catch (e: any) {
      setError(e.toString());
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-col h-full w-full">
      <div className="topbar">
        <div className="topbar-header">
          <h2 className="topbar-title">PCAP Analysis</h2>
          <div className="topbar-subtitle">Offline analysis of 802.11 capture files</div>
        </div>
      </div>

      <div className="page-content" style={{ maxWidth: '1200px', margin: '0 auto', width: '100%' }}>
        <div className="card mb-6">
          <div className="form-group">
            <label className="form-label">Capture File Path (.pcap / .pcapng)</label>
            <input 
              type="text" 
              className="form-input"
              placeholder="C:\Users\User\Documents\capture.pcap"
              value={filePath}
              onChange={(e) => setFilePath(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="flex justify-end gap-3 mt-4 border-t border-border-subtle pt-6">
            <button 
              className="btn btn-primary" 
              onClick={handleAnalyze}
              disabled={loading || !filePath}
            >
              {loading ? <Activity size={16} className="animate-spin" /> : <Search size={16} />}
              {loading ? "Analyzing..." : "Analyze PCAP"}
            </button>
          </div>
          
          {error && (
            <div className="mt-4 p-4 rounded bg-sev-critical-bg border border-sev-critical-border text-danger flex items-center gap-3">
              <AlertCircle size={20} />
              <div>
                <div className="font-semibold">Analysis Failed</div>
                <div className="text-sm">{error}</div>
              </div>
            </div>
          )}
        </div>

        {result && (
          <div className="card">
            <div className="card-header">
              <div className="card-title">Analysis Results</div>
              <span className="text-tertiary mono text-xs bg-bg-base px-2 py-1 rounded border border-border-subtle">{result.session_id}</span>
            </div>
            
            <div className="grid-2 mb-8">
              <div className="stat-card">
                <div className="stat-header">
                  <div className="stat-label">Total Packets</div>
                  <Hash className="stat-icon" />
                </div>
                <div className="stat-value">{result.total_packets.toLocaleString()}</div>
              </div>
              <div className="stat-card">
                <div className="stat-header">
                  <div className="stat-label">Processed (802.11)</div>
                  <Cpu className="stat-icon" />
                </div>
                <div className="stat-value">{result.processed_packets.toLocaleString()}</div>
              </div>
            </div>

            <div className="mb-8">
              <h3 className="mb-4 text-sm text-tertiary uppercase font-semibold tracking-wider flex items-center gap-2">
                <Activity size={16} /> Frame Distribution
              </h3>
              <div className="table-container">
                <table className="data-table">
                  <tbody>
                    <tr>
                      <td style={{width: '240px'}} className="font-medium text-secondary">Management Frames</td>
                      <td className="mono text-primary">{result.management_frames.toLocaleString()}</td>
                    </tr>
                    <tr>
                      <td className="font-medium text-secondary">Control Frames</td>
                      <td className="mono text-primary">{result.control_frames.toLocaleString()}</td>
                    </tr>
                    <tr>
                      <td className="font-medium text-secondary">Data Frames</td>
                      <td className="mono text-primary">{result.data_frames.toLocaleString()}</td>
                    </tr>
                    <tr>
                      <td className="font-medium text-danger">Malformed Packets</td>
                      <td className="mono text-danger">{result.malformed_packets.toLocaleString()}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div>
              <h3 className="mb-4 text-sm text-tertiary uppercase font-semibold tracking-wider flex items-center gap-2">
                <FileSearch size={16} /> Network Discovery
              </h3>
              <div className="table-container">
                <table className="data-table">
                  <tbody>
                    <tr>
                      <td style={{width: '240px'}} className="font-medium text-secondary">Unique BSSIDs</td>
                      <td className="mono text-primary">{result.unique_bssids.length}</td>
                    </tr>
                    <tr>
                      <td className="font-medium text-secondary">Unique SSIDs</td>
                      <td className="mono text-primary">{result.unique_ssids.length}</td>
                    </tr>
                    <tr>
                      <td className="font-medium text-secondary">Radiotap Headers</td>
                      <td>{result.has_radiotap ? <span className="badge badge-success">Present</span> : <span className="badge badge-info text-tertiary bg-transparent border-transparent px-0">Missing</span>}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {result && result.packets && result.packets.length > 0 && (
          <div className="card mt-6">
            <div className="card-header border-b border-border-subtle pb-4 mb-4">
              <div className="card-title flex items-center gap-2">
                <List size={20} className="text-primary" />
                Packet List (First {Math.min(result.packets.length, 10000)} frames)
              </div>
            </div>
            
            <div className="table-container" style={{ maxHeight: '600px', overflowY: 'auto' }}>
              <table className="data-table">
                <thead style={{ position: 'sticky', top: 0, backgroundColor: 'var(--bg-surface)', zIndex: 1 }}>
                  <tr>
                    <th className="w-16">No.</th>
                    <th className="w-32">Time</th>
                    <th className="w-32">Source</th>
                    <th className="w-32">Destination</th>
                    <th className="w-32">Protocol</th>
                    <th className="w-16">Length</th>
                    <th>Info</th>
                  </tr>
                </thead>
                <tbody>
                  {result.packets.map((pkt, idx) => {
                    const typeName = typeof pkt.frame_type === 'string' ? pkt.frame_type : Object.keys(pkt.frame_type)[0];
                    const subtypeName = typeof pkt.frame_subtype === 'string' ? pkt.frame_subtype : Object.keys(pkt.frame_subtype)[0];
                    
                    const timeStr = new Date(pkt.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 } as any);
                    
                    let info = "";
                    if (pkt.management_info) {
                      if (pkt.management_info.ssid) {
                        info += `SSID: ${pkt.management_info.ssid} `;
                      }
                      if (pkt.management_info.reason_code !== null) {
                        info += `Reason: ${pkt.management_info.reason_code} `;
                      }
                    }
                    if (pkt.channel) {
                      info += `Ch: ${pkt.channel} `;
                    }
                    if (pkt.rssi_dbm !== null) {
                      info += `${pkt.rssi_dbm}dBm `;
                    }

                    return (
                      <tr key={pkt.id} className="hover:bg-bg-surface-hover">
                        <td className="mono text-tertiary">{idx + 1}</td>
                        <td className="mono text-xs">{timeStr}</td>
                        <td className="mono text-xs">{pkt.source_mac || "Broadcast"}</td>
                        <td className="mono text-xs">{pkt.destination_mac || "Broadcast"}</td>
                        <td className="text-xs uppercase font-semibold text-secondary">
                          {typeName === 'management' ? '802.11 Mgmt' : typeName === 'control' ? '802.11 Ctrl' : typeName === 'data' ? '802.11 Data' : '802.11'}
                        </td>
                        <td className="mono text-xs">{pkt.payload_bytes}</td>
                        <td className="text-xs truncate max-w-xs">{subtypeName.replace(/_/g, ' ')} {info}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
