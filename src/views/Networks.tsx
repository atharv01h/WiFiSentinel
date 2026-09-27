import { useEffect, useState, useMemo } from "react";
import { RefreshCw, Search, WifiOff, Wifi as WifiIcon } from "lucide-react";
import { getAccessPoints } from "../api/commands";
import type { AccessPoint } from "../api/types";

export default function Networks() {
  const [aps, setAps] = useState<AccessPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    getAccessPoints().then(data => {
      setAps(data);
    }).finally(() => {
      setLoading(false);
    });
  }, []);

  const filteredAps = useMemo(() => {
    if (!search.trim()) return aps;
    const lower = search.toLowerCase();
    return aps.filter(ap => 
      (ap.ssid && ap.ssid.toLowerCase().includes(lower)) || 
      ap.bssid.toLowerCase().includes(lower) ||
      (ap.vendor && ap.vendor.toLowerCase().includes(lower))
    );
  }, [aps, search]);

  const renderSignal = (percent: number) => {
    let active = 'none';
    if (percent > 80) active = 'good';
    else if (percent > 60) active = 'medium';
    else if (percent > 40) active = 'high';
    else active = 'critical';
    
    return (
      <div className="flex items-center gap-3">
        <div className="signal-bars">
          <div className={`signal-bar ${percent > 0 ? 'active-'+active : ''}`} style={{height: '4px'}}></div>
          <div className={`signal-bar ${percent > 40 ? 'active-'+active : ''}`} style={{height: '8px'}}></div>
          <div className={`signal-bar ${percent > 60 ? 'active-'+active : ''}`} style={{height: '12px'}}></div>
          <div className={`signal-bar ${percent > 80 ? 'active-'+active : ''}`} style={{height: '16px'}}></div>
        </div>
        <span className="text-xs text-secondary font-medium">{percent}%</span>
      </div>
    );
  };

  return (
    <div className="flex-col h-full w-full">
      <div className="topbar">
        <div className="topbar-header">
          <h2 className="topbar-title">Known Networks</h2>
          <div className="topbar-subtitle">Discovered Access Points</div>
        </div>
        <div className="topbar-spacer" />
        <div className="flex items-center gap-4">
          <div className="relative flex items-center">
            <Search size={16} className="text-tertiary absolute left-3" />
            <input 
              type="text" 
              className="form-input"
              placeholder="Filter by SSID, BSSID, Vendor..." 
              style={{ paddingLeft: '36px', width: '280px', marginBottom: 0 }}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button className="btn btn-secondary" onClick={() => {
            setLoading(true);
            import("../api/commands").then(m => m.scanNetworks()).then(() => getAccessPoints()).then(setAps).finally(() => setLoading(false));
          }} disabled={loading}>
            <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
            Scan Networks
          </button>
        </div>
      </div>

      <div className="page-content">
        <div className="table-container shadow-sm" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <table className="data-table" style={{ width: '100%' }}>
              <thead style={{ position: 'sticky', top: 0, zIndex: 1, boxShadow: 'var(--shadow-sm)' }}>
                <tr>
                  <th>SSID</th>
                  <th>BSSID</th>
                  <th>Vendor</th>
                  <th>Channel</th>
                  <th>Signal</th>
                  <th>Security</th>
                  <th>Trust</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '64px' }}>
                      <RefreshCw size={24} className="animate-spin text-tertiary mx-auto mb-4" />
                      <div className="text-secondary">Scanning networks...</div>
                    </td>
                  </tr>
                ) : filteredAps.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ padding: '64px' }}>
                      <div className="empty-state" style={{ margin: 0, border: 'none', background: 'transparent' }}>
                        <WifiOff className="empty-icon" />
                        <div className="empty-title">No Networks Found</div>
                        <div className="empty-desc">
                          {search ? "No networks match your filter criteria." : "Run a scan to discover nearby wireless networks."}
                        </div>
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredAps.map(ap => (
                    <tr key={ap.id}>
                      <td>
                        <div className="flex items-center gap-2">
                          <WifiIcon size={16} className={ap.ssid ? "text-primary" : "text-tertiary"} />
                          <strong className={!ap.ssid ? "text-tertiary" : ""}>
                            {ap.ssid || "<Hidden>"}
                          </strong>
                        </div>
                      </td>
                      <td className="mono text-tertiary">{ap.bssid}</td>
                      <td className="text-secondary">{ap.vendor || 'Unknown'}</td>
                      <td>
                        <div className="flex items-center gap-2">
                          <span>{ap.channel}</span>
                          <span className="badge badge-info">{ap.band.replace('band', '').replace('_ghz', 'GHz')}</span>
                        </div>
                      </td>
                      <td>{renderSignal(ap.signal_percent)}</td>
                      <td>
                        <div className="flex-col gap-1">
                          <span className={`badge badge-${
                            ap.auth_mode.includes('open') ? 'critical' : 
                            ap.auth_mode.includes('wep') ? 'critical' : 
                            ap.auth_mode.includes('wpa3') ? 'success' : 
                            ap.auth_mode.includes('wpa2') ? 'info' : 'warning'
                          }`}>
                            {ap.auth_mode.toUpperCase().replace('_', '-')}
                          </span>
                          <span className="text-xs text-tertiary mt-1">{ap.cipher}</span>
                        </div>
                      </td>
                      <td>
                        {ap.is_trusted ? 
                          <span className="badge badge-success">Trusted</span> : 
                          <span className="badge badge-info text-tertiary bg-transparent border-transparent px-0">Unknown</span>
                        }
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
