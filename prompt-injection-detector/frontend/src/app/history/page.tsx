"use client";

import { useState, useEffect, useCallback } from "react";
import {
  getScanHistory, getScanCount, getExportURL,
  type ScanRecord,
} from "@/lib/api";
import SeverityBadge from "@/components/SeverityBadge";

const ATTACK_CATEGORIES = [
  "Safe", "Prompt Injection", "Jailbreak", "Role Hijacking",
  "System Prompt Extraction", "Data Exfiltration",
  "Indirect Prompt Injection", "Tool Abuse Attempt",
];

const SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"];

const SEVERITY_COLORS: Record<string, string> = {
  Low: "#2ed573", Medium: "#ffd32a", High: "#ff9f43", Critical: "#ff4757",
};

const SORT_OPTIONS: Record<string, [string, string]> = {
  "Newest First": ["timestamp", "desc"],
  "Oldest First": ["timestamp", "asc"],
  "Highest Risk": ["risk_score", "desc"],
  "Lowest Risk": ["risk_score", "asc"],
};

const PAGE_SIZE = 25;

export default function ScanHistoryPage() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [sortChoice, setSortChoice] = useState("Newest First");
  const [selectedRecord, setSelectedRecord] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(true);

  const [sortBy, sortOrder] = SORT_OPTIONS[sortChoice] || ["timestamp", "desc"];
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
  const offset = (currentPage - 1) * PAGE_SIZE;

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [data, count] = await Promise.all([
        getScanHistory({
          limit: PAGE_SIZE, offset,
          search: search || undefined,
          category: categoryFilter.length ? categoryFilter : undefined,
          severity: severityFilter.length ? severityFilter : undefined,
          sort_by: sortBy, sort_order: sortOrder,
        }),
        getScanCount({
          search: search || undefined,
          category: categoryFilter.length ? categoryFilter : undefined,
          severity: severityFilter.length ? severityFilter : undefined,
        }),
      ]);
      setRecords(data);
      setTotalCount(count);
      if (data.length > 0) setSelectedRecord(data[0]);
    } catch (err) {
      console.error("Failed to load history:", err);
    } finally {
      setLoading(false);
    }
  }, [offset, search, categoryFilter, severityFilter, sortBy, sortOrder]);

  useEffect(() => { loadData(); }, [loadData]);

  const toggleFilter = (arr: string[], setArr: (v: string[]) => void, val: string) => {
    setArr(arr.includes(val) ? arr.filter(v => v !== val) : [...arr, val]);
    setCurrentPage(1);
  };

  const exportUrl = getExportURL({
    search: search || undefined,
    category: categoryFilter.length ? categoryFilter : undefined,
    severity: severityFilter.length ? severityFilter : undefined,
    sort_by: sortBy,
    sort_order: sortOrder,
  });

  return (
    <>
      <div className="page-header" style={{ position: "relative" }}>
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: "linear-gradient(90deg, #2ed573, #00d4ff, #7c3aed)" }} />
        <h1>📋 Scan History</h1>
        <p>Browse, search, and export all previous prompt scan results</p>
      </div>

      {/* Filters */}
      <div className="filter-card">
        <div className="filter-row">
          <div className="filter-field" style={{ flex: 2 }}>
            <label className="form-label">🔍 Search Prompts</label>
            <input
              className="input"
              placeholder="Type to search in prompt text..."
              value={search}
              onChange={e => { setSearch(e.target.value); setCurrentPage(1); }}
            />
          </div>
          <div className="filter-field" style={{ flex: 1.5 }}>
            <label className="form-label">🎯 Attack Category</label>
            <div className="chip-group">
              {ATTACK_CATEGORIES.map(cat => (
                <span
                  key={cat}
                  className={`chip ${categoryFilter.includes(cat) ? "selected" : ""}`}
                  onClick={() => toggleFilter(categoryFilter, setCategoryFilter, cat)}
                >
                  {cat}
                </span>
              ))}
            </div>
          </div>
          <div className="filter-field" style={{ flex: 1 }}>
            <label className="form-label">⚡ Severity</label>
            <div className="chip-group">
              {SEVERITY_LEVELS.map(sev => (
                <span
                  key={sev}
                  className={`chip ${severityFilter.includes(sev) ? "selected" : ""}`}
                  onClick={() => toggleFilter(severityFilter, setSeverityFilter, sev)}
                >
                  {sev}
                </span>
              ))}
            </div>
          </div>
          <div className="filter-field" style={{ flex: 0.8 }}>
            <label className="form-label">Sort By</label>
            <select className="select" value={sortChoice} onChange={e => setSortChoice(e.target.value)}>
              {Object.keys(SORT_OPTIONS).map(k => <option key={k} value={k}>{k}</option>)}
            </select>
          </div>
        </div>
      </div>

      {/* Summary */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", margin: "0.5rem 0 1rem" }}>
        <span style={{ color: "var(--text-label)", fontSize: "0.85rem" }}>
          Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, totalCount)} of <strong style={{ color: "var(--accent-cyan)" }}>{totalCount.toLocaleString()}</strong> records
        </span>
      </div>

      {loading ? (
        <div className="spinner-overlay"><div className="spinner" /> Loading records...</div>
      ) : records.length > 0 ? (
        <>
          {/* Table */}
          <div style={{ overflowX: "auto", borderRadius: "var(--radius-lg)", border: "1px solid var(--border-subtle)" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Prompt</th>
                  <th>Risk Score</th>
                  <th>Attack Type</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {records.map(rec => (
                  <tr
                    key={rec.id}
                    style={{ cursor: "pointer", background: selectedRecord?.id === rec.id ? "rgba(0,212,255,0.05)" : undefined }}
                    onClick={() => setSelectedRecord(rec)}
                  >
                    <td style={{ whiteSpace: "nowrap", fontSize: "0.8rem" }}>
                      {new Date(rec.timestamp).toLocaleString()}
                    </td>
                    <td style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {rec.prompt}
                    </td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        <div className="risk-bar-wrapper" style={{ width: 80 }}>
                          <div
                            className="risk-bar-fill"
                            style={{
                              width: `${rec.risk_score}%`,
                              background: rec.risk_score <= 25 ? "#2ed573" : rec.risk_score <= 50 ? "#ffd32a" : rec.risk_score <= 75 ? "#ff9f43" : "#ff4757",
                            }}
                          />
                        </div>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}>{rec.risk_score.toFixed(1)}</span>
                      </div>
                    </td>
                    <td>{rec.attack_type}</td>
                    <td><SeverityBadge severity={rec.severity} /></td>
                    <td style={{ fontFamily: "var(--font-mono)" }}>{rec.confidence.toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="pagination">
            <button disabled={currentPage <= 1} onClick={() => setCurrentPage(p => p - 1)}>← Prev</button>
            <span className="page-info">Page {currentPage} of {totalPages}</span>
            <button disabled={currentPage >= totalPages} onClick={() => setCurrentPage(p => p + 1)}>Next →</button>
          </div>

          {/* Detail View */}
          {selectedRecord && (
            <>
              <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", margin: "1rem 0" }} />
              <h3 style={{ color: "var(--text-secondary)", marginBottom: "1rem" }}>🔎 Record Details</h3>
              <div className="grid-2">
                <div>
                  <div style={{ marginBottom: "1rem" }}>
                    <strong style={{ color: "var(--text-muted)" }}>Full Prompt:</strong>
                    <pre style={{
                      background: "var(--bg-secondary)", border: "1px solid var(--border-subtle)",
                      borderRadius: "var(--radius-md)", padding: "0.75rem", marginTop: "0.5rem",
                      color: "var(--text-secondary)", fontSize: "0.85rem", whiteSpace: "pre-wrap",
                      maxHeight: 200, overflow: "auto",
                    }}>
                      {selectedRecord.prompt}
                    </pre>
                  </div>
                  <div>
                    <strong style={{ color: "var(--text-muted)" }}>Explanation:</strong>
                    {selectedRecord.explanation ? (
                      <ul style={{ listStyle: "none", padding: 0, marginTop: "0.5rem" }}>
                        {selectedRecord.explanation.split("; ").filter(Boolean).map((part, i) => (
                          <li key={i} style={{ color: "var(--text-secondary)", marginBottom: "0.3rem", paddingLeft: "1rem", position: "relative" }}>
                            <span style={{ position: "absolute", left: 0 }}>•</span> {part}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p style={{ color: "var(--text-dim)", fontStyle: "italic", marginTop: "0.5rem" }}>No explanation available</p>
                    )}
                  </div>
                </div>
                <div>
                  <div style={{
                    background: "rgba(26,31,46,0.8)", border: "1px solid rgba(0,212,255,0.1)",
                    borderRadius: 10, padding: "1rem",
                  }}>
                    <p style={{ color: "var(--text-label)", margin: "0 0 0.5rem" }}>Risk Score</p>
                    <p style={{
                      color: SEVERITY_COLORS[selectedRecord.severity] || "#8b95a5",
                      fontSize: "2rem", fontWeight: 700, fontFamily: "var(--font-mono)", margin: 0,
                    }}>
                      {selectedRecord.risk_score}
                    </p>
                    <p style={{ color: "var(--text-label)", margin: "0.75rem 0 0.25rem" }}>
                      Attack Type: <strong style={{ color: "var(--text-secondary)" }}>{selectedRecord.attack_type}</strong>
                    </p>
                    <p style={{ color: "var(--text-label)", margin: "0 0 0.25rem" }}>
                      Severity: <strong style={{ color: SEVERITY_COLORS[selectedRecord.severity] }}>{selectedRecord.severity}</strong>
                    </p>
                    <p style={{ color: "var(--text-label)", margin: "0 0 0.25rem" }}>
                      Confidence: <strong style={{ color: "var(--text-secondary)" }}>{selectedRecord.confidence}%</strong>
                    </p>
                    <p style={{ color: "var(--text-label)", margin: 0 }}>
                      Scanned: <strong style={{ color: "var(--text-secondary)" }}>{new Date(selectedRecord.timestamp).toLocaleString()}</strong>
                    </p>
                  </div>
                </div>
              </div>
            </>
          )}

          {/* Export */}
          <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", margin: "1.5rem 0" }} />
          <a href={exportUrl} download className="btn btn-primary btn-full" style={{ textDecoration: "none", textAlign: "center" }}>
            ⬇️ Export {totalCount} Records as CSV
          </a>
        </>
      ) : (
        <div className="empty-state">
          <div className="empty-icon">📋</div>
          <p style={{ fontSize: "1.1rem" }}>Your scan history will appear here</p>
          <p style={{ fontSize: "0.9rem" }}>Navigate to the <strong>Prompt Scanner</strong> page to start analyzing prompts</p>
        </div>
      )}
    </>
  );
}
