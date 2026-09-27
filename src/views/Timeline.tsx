import { useEffect, useState } from "react";
import { RefreshCw, Clock, History } from "lucide-react";
import { getTimeline } from "../api/commands";
import type { TimelineEvent } from "../api/types";

export default function Timeline() {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getTimeline({ limit: 500 }).then(setEvents).finally(() => setLoading(false));
  }, []);

  return (
    <div className="flex-col h-full w-full">
      <div className="topbar">
        <div className="topbar-header">
          <h2 className="topbar-title">Event Timeline</h2>
          <div className="topbar-subtitle">Chronological record of environment changes</div>
        </div>
        <div className="topbar-spacer" />
        <button className="btn btn-secondary" onClick={() => {
          setLoading(true);
          getTimeline({ limit: 500 }).then(setEvents).finally(() => setLoading(false));
        }} disabled={loading}>
          <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      <div className="page-content" style={{ overflowY: 'auto' }}>
        <div className="table-container shadow-sm h-full">
          <table className="data-table">
            <thead style={{ position: 'sticky', top: 0, zIndex: 1, boxShadow: 'var(--shadow-sm)' }}>
              <tr>
                <th><div className="flex items-center gap-2"><Clock size={14} /> Time</div></th>
                <th>Severity</th>
                <th>Event Type</th>
                <th>Summary</th>
                <th>Target</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} style={{textAlign: 'center', padding: '64px'}}>
                    <RefreshCw size={24} className="animate-spin text-tertiary mx-auto mb-4" />
                    <div className="text-secondary">Loading timeline...</div>
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{padding: '64px'}}>
                    <div className="empty-state" style={{ margin: 0, border: 'none', background: 'transparent' }}>
                      <History className="empty-icon" />
                      <div className="empty-title">No Events Recorded</div>
                      <div className="empty-desc">The timeline is empty. Events will appear here automatically.</div>
                    </div>
                  </td>
                </tr>
              ) : (
                events.map(ev => (
                  <tr key={ev.id}>
                    <td className="text-secondary text-xs whitespace-nowrap font-medium">
                      {new Date(ev.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td>
                      <span className={`badge badge-${ev.severity.replace(/"/g, '')}`}>{ev.severity.replace(/"/g, '')}</span>
                    </td>
                    <td className="mono text-xs text-primary">{ev.event_type.replace(/"/g, '')}</td>
                    <td className="text-secondary">{ev.description}</td>
                    <td className="mono text-xs text-tertiary">
                      {ev.related_ap_ssid || ev.related_ap_bssid || '-'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
