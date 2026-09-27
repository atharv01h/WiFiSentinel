import { useState, useEffect } from "react";
import { Trash2, Activity, Settings2, ShieldAlert } from "lucide-react";
import { getDiagnostics, clearHistory } from "../api/commands";

export default function Settings() {
  const [diagnostics, setDiagnostics] = useState<any>(null);
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    getDiagnostics().then(setDiagnostics).catch(console.error);
  }, []);

  const handleClear = async () => {
    if (!confirm("Are you sure you want to clear all historical data? This cannot be undone.")) return;
    setClearing(true);
    try {
      await clearHistory();
      alert("Database cleared successfully.");
    } catch (e) {
      alert("Error clearing database: " + e);
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="flex-col h-full w-full">
      <div className="topbar">
        <div className="topbar-header">
          <h2 className="topbar-title">Settings & Diagnostics</h2>
          <div className="topbar-subtitle">System configuration and maintenance</div>
        </div>
      </div>

      <div className="page-content" style={{ maxWidth: '800px', margin: '0 auto', width: '100%' }}>
        <div className="card mb-6 border-sev-critical-border bg-sev-critical-bg" style={{ boxShadow: 'none' }}>
          <div className="card-header border-b border-sev-critical-border pb-4 mb-4" style={{ margin: '-24px -24px 24px -24px', padding: '24px 24px 16px 24px' }}>
            <div className="card-title text-danger flex items-center gap-2">
              <ShieldAlert size={18} /> Danger Zone
            </div>
          </div>
          
          <div className="flex justify-between items-center bg-bg-base p-6 rounded-lg border border-sev-critical-border">
            <div>
              <div className="font-semibold mb-1 text-primary">Clear Local Database</div>
              <div className="text-secondary text-sm max-w-md leading-relaxed">
                Removes all AP history, timeline events, and findings. Requires app restart to take full effect.
              </div>
            </div>
            <button 
              className="btn btn-secondary text-danger border-sev-critical-border hover:bg-sev-critical-bg" 
              onClick={handleClear}
              disabled={clearing}
            >
              {clearing ? <Activity size={16} className="animate-spin" /> : <Trash2 size={16} />}
              Clear Database
            </button>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title flex items-center gap-2">
              <Settings2 size={18} className="text-tertiary" />
              System Diagnostics
            </div>
          </div>
          {diagnostics ? (
            <div className="mono text-sm bg-bg-surface p-6 rounded-lg border border-border-subtle text-secondary leading-relaxed" style={{whiteSpace: 'pre-wrap', overflowX: 'auto'}}>
              {JSON.stringify(diagnostics, null, 2)}
            </div>
          ) : (
            <div className="flex items-center gap-3 text-tertiary p-6 bg-bg-surface rounded-lg border border-border-subtle border-dashed">
              <Activity size={16} className="animate-spin" />
              Loading diagnostics...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
