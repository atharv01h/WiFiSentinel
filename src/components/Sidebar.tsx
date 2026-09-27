import { 
  LayoutDashboard, 
  Wifi, 
  ShieldAlert, 
  Clock, 
  Activity, 
  FileText, 
  Settings as SettingsIcon, 
  Radio,
  Shield,
  KeyRound
} from "lucide-react";

type View = "dashboard" | "networks" | "findings" | "timeline" | "capture" | "pcap" | "profiles" | "reports" | "settings";

interface Props {
  current: View;
  onChange: (v: View) => void;
  findingsCount: number;
}

function NavItem({
  id, label, icon, current, onChange, badge,
}: {
  id: View; label: string; icon: React.ReactNode;
  current: View; onChange: (v: View) => void;
  badge?: number;
}) {
  return (
    <div
      className={`nav-item ${current === id ? "active" : ""}`}
      onClick={() => onChange(id)}
    >
      <span className="nav-icon">{icon}</span>
      <span>{label}</span>
      {badge != null && badge > 0 && (
        <span className="nav-badge">{badge > 99 ? "99+" : badge}</span>
      )}
    </div>
  );
}

export default function Sidebar({ current, onChange, findingsCount }: Props) {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-inner">
          <div className="sidebar-logo-icon" style={{ background: 'transparent', boxShadow: 'none' }}>
            <img src="/icon.png" alt="WiFiSentinel Logo" style={{ width: '28px', height: '28px', objectFit: 'contain' }} />
          </div>
          <div>
            <h1>WiFiSentinel</h1>
            <div className="tagline">Wireless Security</div>
          </div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Monitor</div>
        <NavItem id="dashboard" label="Dashboard"    icon={<LayoutDashboard size={18} />} current={current} onChange={onChange} />
        <NavItem id="networks"  label="Networks"     icon={<Wifi size={18} />} current={current} onChange={onChange} />
        <NavItem id="findings"  label="Findings"     icon={<ShieldAlert size={18} />} current={current} onChange={onChange} badge={findingsCount} />
        <NavItem id="timeline"  label="Timeline"     icon={<Clock size={18} />} current={current} onChange={onChange} />

        <div className="nav-section-label">Capture</div>
        <NavItem id="capture" label="Live Capture"   icon={<Radio size={18} />} current={current} onChange={onChange} />
        <NavItem id="pcap"    label="PCAP Analysis"  icon={<Activity size={18} />} current={current} onChange={onChange} />

        <div className="nav-section-label">Output</div>
        <NavItem id="profiles" label="Saved Profiles" icon={<KeyRound size={18} />} current={current} onChange={onChange} />
        <NavItem id="reports"  label="Reports"       icon={<FileText size={18} />} current={current} onChange={onChange} />
        <NavItem id="settings" label="Settings"      icon={<SettingsIcon size={18} />} current={current} onChange={onChange} />
      </nav>

      <div className="sidebar-footer">
        <div className="mb-4">
          <div className="text-[10px] text-tertiary uppercase tracking-wider font-semibold mb-1">Creator & Developer</div>
          <div 
            className="font-bold tracking-wide" 
            style={{ 
              fontSize: '13px',
              background: 'linear-gradient(90deg, var(--accent-primary), #a855f7)', 
              WebkitBackgroundClip: 'text', 
              WebkitTextFillColor: 'transparent' 
            }}
          >
            Atharv Hatwar
          </div>
        </div>
        <div className="text-tertiary text-xs flex justify-between items-center opacity-80">
          <span>WiFiSentinel v0.1.0</span>
          <Shield size={12} />
        </div>
      </div>
    </aside>
  );
}
