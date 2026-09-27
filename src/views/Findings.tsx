import { useEffect, useState } from "react";
import { ShieldCheck, RefreshCw, AlertTriangle, ShieldAlert } from "lucide-react";
import { getFindings } from "../api/commands";
import type { SecurityFinding } from "../api/types";

export default function Findings() {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    getFindings().then(setFindings).finally(() => setLoading(false));
  }, []);

  const selectedFinding = findings.find(f => f.id === selectedId);

  return (
    <div className="flex-col h-full w-full">
      <div className="topbar">
        <div className="topbar-header">
          <h2 className="topbar-title">Security Findings</h2>
          <div className="topbar-subtitle">Detected vulnerabilities and misconfigurations</div>
        </div>
        <div className="topbar-spacer" />
        <button className="btn btn-secondary" onClick={() => {
          setLoading(true);
          getFindings().then(setFindings).finally(() => setLoading(false));
        }} disabled={loading}>
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="flex" style={{ height: 'calc(100vh - 64px)' }}>
        <div style={{ width: '360px', borderRight: '1px solid var(--border-subtle)', overflowY: 'auto', background: 'var(--bg-surface)' }}>
          {loading ? (
            <div className="flex-col items-center justify-center h-full text-tertiary gap-4 p-8">
              <RefreshCw size={24} className="animate-spin" />
              <span>Loading findings...</span>
            </div>
          ) : findings.length === 0 ? (
            <div className="empty-state" style={{ border: 'none', background: 'transparent' }}>
              <ShieldCheck className="empty-icon text-success" />
              <div className="empty-title">All Clear</div>
              <div className="empty-desc">No security findings have been detected.</div>
            </div>
          ) : (
            <div className="flex-col p-4 gap-2">
              {findings.map(f => (
                <div 
                  key={f.id} 
                  className="list-item" 
                  style={{ 
                    cursor: 'pointer',
                    borderRadius: 'var(--r-md)',
                    border: '1px solid',
                    padding: '16px',
                    borderColor: selectedId === f.id ? 'var(--border-strong)' : 'transparent',
                    background: selectedId === f.id ? 'var(--bg-surface-active)' : 'transparent',
                  }}
                  onClick={() => setSelectedId(f.id)}
                >
                  <div className="flex-col w-full gap-2">
                    <div className="flex justify-between items-center">
                      <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                      <span className="text-xs text-tertiary font-medium">{new Date(f.created_at).toLocaleTimeString()}</span>
                    </div>
                    <div className="text-primary font-medium mt-1">{f.title}</div>
                    <div className="text-secondary text-xs truncate" style={{ maxWidth: '280px' }}>{f.plain_explanation}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div style={{ flex: 1, background: 'var(--bg-base)', overflowY: 'auto', padding: '32px' }}>
          {selectedFinding ? (
            <div className="flex-col gap-6 max-w-4xl">
              <div className="flex items-center gap-3">
                <span className={`badge badge-${selectedFinding.severity} px-3 py-1 text-sm`}>{selectedFinding.severity}</span>
                <span className="text-tertiary text-sm font-medium">Rule: {selectedFinding.rule_id}</span>
                <span className="text-tertiary text-sm font-medium ml-auto">Detected: {new Date(selectedFinding.created_at).toLocaleString()}</span>
              </div>
              
              <h1 className="text-2xl font-bold tracking-tight text-primary mb-2">{selectedFinding.title}</h1>
              
              <div className="grid-2">
                <div className="card">
                  <h3 className="flex items-center gap-2 mb-4 text-primary">
                    <AlertTriangle size={18} className="text-warning" />
                    Explanation
                  </h3>
                  <p className="text-secondary leading-relaxed">{selectedFinding.plain_explanation}</p>
                </div>
                
                <div className="card">
                  <h3 className="flex items-center gap-2 mb-4 text-primary">
                    <ShieldCheck size={18} className="text-success" />
                    Recommendation
                  </h3>
                  <p className="text-secondary leading-relaxed">{selectedFinding.recommendation}</p>
                </div>
              </div>


            </div>
          ) : (
            <div className="empty-state h-full" style={{ border: 'none', background: 'transparent' }}>
              <ShieldAlert className="empty-icon text-tertiary" style={{ opacity: 0.5, width: '64px', height: '64px' }} />
              <div className="empty-title text-xl">Select a Finding</div>
              <div className="empty-desc">Click on a finding in the list to view detailed analysis and recommendations.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
