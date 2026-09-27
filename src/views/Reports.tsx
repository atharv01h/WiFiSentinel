import { useState, useEffect } from "react";
import { Download, FileJson, Activity, FileText } from "lucide-react";
import { getPosture, generateReport } from "../api/commands";
import type { PostureReport } from "../api/types";

export default function Reports() {
  const [posture, setPosture] = useState<PostureReport | null>(null);
  const [generating, setGenerating] = useState(false);
  const [reportResult, setReportResult] = useState<{path: string, size_bytes: number} | null>(null);

  useEffect(() => {
    getPosture().then(setPosture).catch(console.error);
  }, []);

  const handleGenerate = async (format: "html" | "json") => {
    setGenerating(true);
    setReportResult(null);
    try {
      const res = await generateReport(format);
      setReportResult(res);
    } catch (e) {
      console.error(e);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="flex-col h-full w-full">
      <div className="topbar">
        <div className="topbar-header">
          <h2 className="topbar-title">Reporting & Posture</h2>
          <div className="topbar-subtitle">Compliance and environment summaries</div>
        </div>
      </div>

      <div className="page-content" style={{ maxWidth: '800px', margin: '0 auto', width: '100%' }}>
        <div className="card mb-6">
          <div className="card-header">
            <div className="card-title">Environment Posture Score</div>
          </div>
          
          {posture ? (
            <div>
              <div className="flex items-center gap-8 mb-8">
                <div style={{
                  width: '128px', height: '128px', 
                  borderRadius: '50%', 
                  border: `8px solid ${posture.overall_score >= 80 ? 'var(--status-success)' : posture.overall_score >= 60 ? 'var(--sev-medium)' : 'var(--sev-high)'}`,
                  background: 'var(--bg-base)',
                  boxShadow: `0 0 20px ${posture.overall_score >= 80 ? 'var(--status-success-bg)' : posture.overall_score >= 60 ? 'var(--sev-medium-bg)' : 'var(--sev-high-bg)'}`,
                  display: 'flex', alignItems: 'center', justifyItems: 'center', justifyContent: 'center',
                  fontSize: '3rem', fontWeight: 'bold', color: 'var(--text-primary)'
                }}>
                  {posture.overall_grade}
                </div>
                <div>
                  <h3 className="text-3xl font-bold mb-2 text-primary">{posture.overall_score} <span className="text-tertiary text-lg">/ 100</span></h3>
                  <div className="text-secondary max-w-sm leading-relaxed">Calculated based on active security findings, known APs, and encryption standards.</div>
                </div>
              </div>

              {posture.issues && posture.issues.length > 0 && (
                <div className="mt-8 border-t border-border-subtle pt-6">
                  <h4 className="mb-4 font-semibold text-primary">Key Issues Deductions</h4>
                  <div className="flex flex-col gap-3">
                    {posture.issues.map((iss, i) => (
                      <div key={i} className="flex justify-between items-center bg-bg-base p-4 rounded-lg border border-border-subtle">
                        <span className="text-secondary font-medium">{iss.message}</span>
                        <span className={`badge badge-${iss.severity}`}>{iss.severity}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex-col items-center justify-center p-12 text-tertiary">
              <Activity size={32} className="animate-spin mb-4" />
              <span>Loading posture data...</span>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div className="card-title">Generate Report</div>
          </div>
          <p className="text-secondary mb-6 leading-relaxed">
            Export a comprehensive summary of discovered networks, timeline events, and active security findings.
          </p>
          <div className="flex gap-4">
            <button 
              className="btn btn-primary" 
              onClick={() => handleGenerate("html")}
              disabled={generating}
            >
              {generating ? <Activity size={16} className="animate-spin" /> : <FileText size={16} />}
              Export HTML Report
            </button>
            <button 
              className="btn btn-secondary" 
              onClick={() => handleGenerate("json")}
              disabled={generating}
            >
              {generating ? <Activity size={16} className="animate-spin" /> : <FileJson size={16} />}
              Export JSON Data
            </button>
          </div>

          {reportResult && (
            <div className="mt-6 p-4 rounded-lg bg-status-success-bg border border-status-success-border">
              <div className="text-success font-semibold mb-2 flex items-center gap-2">
                <Download size={16} />
                Report Generated Successfully
              </div>
              <div className="text-sm mono text-secondary mb-1">Path: {reportResult.path}</div>
              <div className="text-sm mono text-tertiary">Size: {(reportResult.size_bytes / 1024).toFixed(2)} KB</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
