import { useEffect, useState, useRef } from "react";
import { Play, Square, Activity, Cpu } from "lucide-react";
import { getAdapters, getCaptureStatus, startCapture, stopCapture } from "../api/commands";
import type { WirelessAdapter, CaptureStatus } from "../api/types";

export default function Capture() {
  const [adapters, setAdapters] = useState<WirelessAdapter[]>([]);
  const [status, setStatus] = useState<CaptureStatus | null>(null);
  const [selectedAdapter, setSelectedAdapter] = useState("");
  const [outputPath, setOutputPath] = useState("");
  const intervalRef = useRef<number | null>(null);

  useEffect(() => {
    getAdapters().then(setAdapters).catch(console.error);
    pollStatus();
    
    intervalRef.current = window.setInterval(pollStatus, 1000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const pollStatus = async () => {
    try {
      const s = await getCaptureStatus();
      setStatus(s);
    } catch (e) {
      console.error(e);
    }
  };

  const handleStart = async () => {
    if (!selectedAdapter) return;
    const adapter = adapters.find(a => a.id === selectedAdapter);
    if (!adapter) return;

    try {
      await startCapture(adapter.name, adapter.guid, outputPath.trim() || undefined);
      pollStatus();
    } catch (e) {
      console.error(e);
    }
  };

  const handleStop = async () => {
    try {
      await stopCapture();
      pollStatus();
    } catch (e) {
      console.error(e);
    }
  };

  const isRunning = status?.state === "running" || status?.state === "initializing";

  return (
    <div className="flex-col h-full w-full">
      <div className="topbar">
        <div className="topbar-header">
          <h2 className="topbar-title">Live Capture</h2>
          <div className="topbar-subtitle">Raw 802.11 packet capture</div>
        </div>
      </div>

      <div className="page-content" style={{ maxWidth: '800px', margin: '0 auto', width: '100%' }}>
        <div className="card mb-6">
          <div className="card-header">
            <div className="card-title">Capture Configuration</div>
          </div>
          
          <div className="form-group mb-4">
            <label className="form-label">Capture Interface</label>
            <select 
              className="form-select"
              value={selectedAdapter}
              onChange={(e) => setSelectedAdapter(e.target.value)}
              disabled={isRunning}
            >
              <option value="">Select an adapter...</option>
              {adapters.map(a => (
                <option key={a.id} value={a.id}>
                  {a.name} {a.monitor_mode_capability === "supported" ? "(Monitor Mode Supported)" : ""}
                </option>
              ))}
            </select>
            <p className="text-xs text-tertiary mt-1">
              Note: Npcap is required for raw 802.11 packet capture on Windows.
            </p>
          </div>

          <div className="form-group">
            <label className="form-label">Output Path (Required)</label>
            <input 
              type="text" 
              className="form-input" 
              placeholder="e.g. C:\Users\user\Desktop\packets.pcap"
              value={outputPath}
              onChange={(e) => setOutputPath(e.target.value)}
              disabled={isRunning}
            />
            <p className="text-xs text-tertiary mt-1">
              You must specify a custom file path to save packets.
            </p>
          </div>

          <div className="flex justify-end gap-3 mt-6 border-t border-border-subtle pt-6">
            <button 
              className="btn btn-secondary text-danger" 
              onClick={handleStop}
              disabled={!isRunning}
            >
              <Square size={16} />
              Stop Capture
            </button>
            <button 
              className="btn btn-primary" 
              onClick={handleStart}
              disabled={isRunning || !selectedAdapter || !outputPath.trim()}
            >
              {isRunning ? <Activity size={16} className="animate-spin" /> : <Play size={16} />}
              Start Capture
            </button>
          </div>
        </div>

        {status && (
          <div className="grid-2">
            <div className="stat-card" style={{ borderColor: isRunning ? 'var(--status-success-border)' : 'var(--border-subtle)' }}>
              <div className="stat-header">
                <div className="stat-label">Capture State</div>
                <Activity className={`stat-icon ${isRunning ? 'text-success' : 'text-tertiary'}`} />
              </div>
              <div className={`stat-value ${isRunning ? 'text-success' : ''}`}>
                {status.state.toUpperCase()}
              </div>
              <div className="stat-sub">
                {status.error ? <span className="text-danger">{status.error}</span> : `Target: ${status.adapter_name || 'None'}`}
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-header">
                <div className="stat-label">Packets Captured</div>
                <Cpu className="stat-icon" />
              </div>
              <div className="stat-value">{status.packet_count.toLocaleString()}</div>
              <div className="stat-sub">
                {status.packet_rate} pkts/sec • {(status.file_size_bytes / 1024 / 1024).toFixed(2)} MB
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
