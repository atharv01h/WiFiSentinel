/**
 * Created and maintained by Atharv Hatwar.
 * Purpose: Dashboard view for displaying system overview and posture.
 */
import { useEffect, useState } from "react";
import { Activity, Radio, ShieldAlert, Zap, WifiOff, CheckCircle2 } from "lucide-react";
import { getAdapters, scanNetworks, getFindings, getAccessPoints } from "../api/commands";
import type { WirelessAdapter, SecurityFinding, ScanResult } from "../api/types";

export default function Dashboard({
  onNavigate,
  setFindingsCount
}: {
  onNavigate: (view: any) => void;
  setFindingsCount: (c: number) => void;
}) {
  const [adapters, setAdapters] = useState<WirelessAdapter[]>([]);
  const [scanRes, setScanRes] = useState<ScanResult | null>(null);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    getAdapters().then(setAdapters).catch(e => {
      console.error(e);
      alert("IPC Error: " + String(e));
    });
    getFindings().then(f => {
      setFindings(f);
      setFindingsCount(f.length);
    }).catch(e => {
      console.error(e);
      alert("IPC Findings Error: " + String(e));
    });
    
    getAccessPoints().then(aps => {
      setScanRes(prev => prev || {
        access_points: aps,
        new_count: 0,
        total_count: aps.length,
        findings_count: 0
      });
    });
  }, []);

  const handleScan = async () => {
    setScanning(true);
    try {
      const res = await scanNetworks();
      setScanRes(res);
      const f = await getFindings();
      setFindings(f);
      setFindingsCount(f.length);
    } catch (e) {
      console.error(e);
    } finally {
      setScanning(false);
    }
  };

  const criticalFindings = findings.filter(f => f.severity === "critical").length;
  const highFindings = findings.filter(f => f.severity === "high").length;

  return (
    <div className="flex-col h-full w-full">
      <div className="topbar">
        <div className="topbar-header">
          <h2 className="topbar-title">Dashboard</h2>
          <div className="topbar-subtitle">System Overview & Posture</div>
        </div>
        <div className="topbar-spacer" />
        <button 
          className="btn btn-primary" 
          onClick={handleScan}
          disabled={scanning}
        >
          {scanning ? <Activity size={16} className="animate-spin" /> : <Zap size={16} />}
          {scanning ? "Scanning..." : "Quick Scan"}
        </button>
      </div>

      <div className="page-content">
        <div className="grid-3">
          <div className="stat-card">
            <div className="stat-header">
              <div className="stat-label">Detected APs</div>
              <Radio className="stat-icon" />
            </div>
            <div className="stat-value">{scanRes ? scanRes.total_count : "—"}</div>
            <div className="stat-sub">
              {scanRes ? <span className="text-success">+{scanRes.new_count} new this scan</span> : "Run scan to detect"}
            </div>
          </div>
          
          <div className="stat-card" style={{ borderColor: findings.length > 0 ? 'var(--sev-critical-border)' : '' }}>
            <div className="stat-header">
              <div className="stat-label">Security Findings</div>
              <ShieldAlert className="stat-icon text-danger" />
            </div>
            <div className={`stat-value ${findings.length > 0 ? 'text-danger' : 'text-primary'}`}>
              {findings.length}
            </div>
            <div className="stat-sub">
              {findings.length > 0 ? `${criticalFindings} critical, ${highFindings} high` : "Environment secure"}
            </div>
          </div>
          
          <div className="stat-card">
            <div className="stat-header">
              <div className="stat-label">Active Adapters</div>
              <Activity className="stat-icon" />
            </div>
            <div className="stat-value">
              {adapters.filter(a => a.state === "up" || a.state === "connected").length}
            </div>
            <div className="stat-sub">
              Out of {adapters.length} total interfaces
            </div>
          </div>
        </div>

        <div className="grid-2">
          <div className="card">
            <div className="card-header">
              <div className="card-title">Wireless Interfaces</div>
            </div>
            {adapters.length === 0 ? (
              <div className="empty-state">
                <WifiOff className="empty-icon" />
                <div className="empty-title">No Adapters Found</div>
                <div className="empty-desc">Ensure Wi-Fi is enabled on your system.</div>
              </div>
            ) : (
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Adapter Name</th>
                      <th>State</th>
                      <th>Monitor Mode</th>
                    </tr>
                  </thead>
                  <tbody>
                    {adapters.map(a => (
                      <tr key={a.id}>
                        <td><strong>{a.name}</strong></td>
                        <td>
                          <span className={`badge ${a.state === "connected" ? "badge-success" : "badge-info"}`}>
                            {a.state}
                          </span>
                        </td>
                        <td>
                          {a.monitor_mode_capability === "supported" ? (
                            <span className="text-success text-sm font-medium">Supported</span>
                          ) : (
                            <span className="text-tertiary text-sm font-medium">Unsupported</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          
          <div className="card">
            <div className="card-header">
              <div className="card-title">Recent Findings</div>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("findings")}>View All</button>
            </div>
            {findings.length === 0 ? (
              <div className="empty-state">
                <CheckCircle2 className="empty-icon text-success" style={{ opacity: 0.8 }} />
                <div className="empty-title">Clean Environment</div>
                <div className="empty-desc">No security findings detected.</div>
              </div>
            ) : (
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Finding</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.slice(0, 5).map(f => (
                      <tr key={f.id}>
                        <td>
                          <span className={`badge badge-${f.severity}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="truncate" style={{maxWidth: "200px"}} title={f.title}>
                          {f.title}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
