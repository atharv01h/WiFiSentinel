import { useEffect, useState } from "react";
import { KeyRound, RefreshCw, Eye, EyeOff } from "lucide-react";
import { getSavedProfiles } from "../api/commands";
import type { SavedProfile } from "../api/types";

export default function Profiles() {
  const [profiles, setProfiles] = useState<SavedProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [visiblePasswords, setVisiblePasswords] = useState<Set<string>>(new Set());

  const fetchProfiles = () => {
    setLoading(true);
    getSavedProfiles().then(setProfiles).finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchProfiles();
  }, []);

  const togglePassword = (ssid: string) => {
    const newSet = new Set(visiblePasswords);
    if (newSet.has(ssid)) {
      newSet.delete(ssid);
    } else {
      newSet.add(ssid);
    }
    setVisiblePasswords(newSet);
  };

  return (
    <div className="flex-col h-full w-full">
      <div className="topbar">
        <div className="topbar-header">
          <h2 className="topbar-title">Saved Profiles</h2>
          <div className="topbar-subtitle">Locally stored Wi-Fi networks and credentials</div>
        </div>
        <div className="topbar-spacer" />
        <button className="btn btn-secondary" onClick={fetchProfiles} disabled={loading}>
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="page-content" style={{ overflowY: 'auto' }}>
        <div className="table-container shadow-sm h-full">
          <table className="data-table">
            <thead style={{ position: 'sticky', top: 0, zIndex: 1, boxShadow: 'var(--shadow-sm)' }}>
              <tr>
                <th>SSID (Network Name)</th>
                <th>Stored Password</th>
                <th style={{ width: '80px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={3} style={{textAlign: 'center', padding: '64px'}}>
                    <RefreshCw size={24} className="animate-spin text-tertiary mx-auto mb-4" />
                    <div className="text-secondary">Loading saved profiles...</div>
                  </td>
                </tr>
              ) : profiles.length === 0 ? (
                <tr>
                  <td colSpan={3} style={{padding: '64px'}}>
                    <div className="empty-state" style={{ margin: 0, border: 'none', background: 'transparent' }}>
                      <KeyRound className="empty-icon" />
                      <div className="empty-title">No Profiles Found</div>
                      <div className="empty-desc">No saved Wi-Fi networks were found on this system.</div>
                    </div>
                  </td>
                </tr>
              ) : (
                profiles.map(p => {
                  const isVisible = visiblePasswords.has(p.ssid);
                  const hasPassword = p.password !== null && p.password.length > 0;
                  
                  return (
                    <tr key={p.ssid}>
                      <td className="font-medium text-primary">
                        {p.ssid}
                      </td>
                      <td className="mono text-sm text-secondary">
                        {!hasPassword ? (
                          <span className="text-tertiary italic">Open network or no password stored</span>
                        ) : isVisible ? (
                          <span className="text-success font-bold">{p.password}</span>
                        ) : (
                          <span className="text-tertiary">••••••••</span>
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {hasPassword && (
                          <button 
                            className="btn btn-secondary btn-sm"
                            onClick={() => togglePassword(p.ssid)}
                            title={isVisible ? "Hide Password" : "Show Password"}
                            style={{ padding: '6px' }}
                          >
                            {isVisible ? <EyeOff size={16} /> : <Eye size={16} />}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
