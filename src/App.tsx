/**
 * Created and maintained by Atharv Hatwar.
 * Purpose: Main application shell, router, and state provider for WiFiSentinel.
 */
import { useState } from "react";
import Dashboard from "./views/Dashboard";
import Networks from "./views/Networks";
import Findings from "./views/Findings";
import Timeline from "./views/Timeline";
import Capture from "./views/Capture";
import PcapAnalysis from "./views/PcapAnalysis";
import Reports from "./views/Reports";
import Settings from "./views/Settings";
import Profiles from "./views/Profiles";
import Sidebar from "./components/Sidebar";

type View =
  | "dashboard"
  | "networks"
  | "findings"
  | "timeline"
  | "capture"
  | "pcap"
  | "profiles"
  | "reports"
  | "settings";

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const [findingsCount, setFindingsCount] = useState(0);

  const renderView = () => {
    switch (view) {
      case "dashboard":   return <Dashboard onNavigate={setView} setFindingsCount={setFindingsCount} />;
      case "networks":    return <Networks />;
      case "findings":    return <Findings />;
      case "timeline":    return <Timeline />;
      case "capture":     return <Capture />;
      case "pcap":        return <PcapAnalysis />;
      case "profiles":    return <Profiles />;
      case "reports":     return <Reports />;
      case "settings":    return <Settings />;
    }
  };

  return (
    <div className="app-shell">
      <Sidebar current={view} onChange={setView} findingsCount={findingsCount} />
      <div className="main-content">
        {renderView()}
      </div>
    </div>
  );
}
