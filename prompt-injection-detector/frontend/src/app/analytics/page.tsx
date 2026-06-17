"use client";

import { useState, useEffect } from "react";
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, Area, AreaChart,
} from "recharts";
import {
  getDashboardStats, getDailyAttacks, getAttackCategories,
  getRiskDistribution, getSeverityData, getTopPatterns, getOWASPMapping,
  type DashboardStats, type DailyAttack, type CategoryData,
  type SeverityData, type PatternData, type OWASPData,
} from "@/lib/api";

const CATEGORY_COLORS: Record<string, string> = {
  Safe: "#2ed573", "Prompt Injection": "#ff4757", Jailbreak: "#ffd32a",
  "Role Hijacking": "#ff9f43", "System Prompt Extraction": "#00d4ff",
  "Data Exfiltration": "#7c3aed", "Indirect Prompt Injection": "#a4b0be",
  "Tool Abuse Attempt": "#ff6b81",
};

const SEVERITY_COLORS: Record<string, string> = {
  Low: "#2ed573", Medium: "#ffd32a", High: "#ff9f43", Critical: "#ff4757",
};

const SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"];

export default function AnalyticsPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [daily, setDaily] = useState<DailyAttack[]>([]);
  const [categories, setCategories] = useState<CategoryData[]>([]);
  const [riskData, setRiskData] = useState<Array<{ risk_score: number }>>([]);
  const [severity, setSeverity] = useState<SeverityData[]>([]);
  const [patterns, setPatterns] = useState<PatternData[]>([]);
  const [owasp, setOwasp] = useState<OWASPData[]>([]);
  const [daysRange, setDaysRange] = useState(30);

  const loadData = () => {
    getDashboardStats().then(setStats).catch(console.error);
    getDailyAttacks(daysRange).then(setDaily).catch(console.error);
    getAttackCategories().then(setCategories).catch(console.error);
    getRiskDistribution().then(setRiskData).catch(console.error);
    getSeverityData().then(setSeverity).catch(console.error);
    getTopPatterns(10).then(setPatterns).catch(console.error);
    getOWASPMapping().then(setOwasp).catch(console.error);
  };

  useEffect(() => { loadData(); }, [daysRange]);

  // Histogram bins
  const histBins = [
    { range: "0–25", count: riskData.filter(d => d.risk_score <= 25).length, color: "#2ed573" },
    { range: "26–50", count: riskData.filter(d => d.risk_score > 25 && d.risk_score <= 50).length, color: "#ffd32a" },
    { range: "51–75", count: riskData.filter(d => d.risk_score > 50 && d.risk_score <= 75).length, color: "#ff9f43" },
    { range: "76–100", count: riskData.filter(d => d.risk_score > 75).length, color: "#ff4757" },
  ];

  const sortedSeverity = [...severity].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <>
      <div className="page-header" style={{ position: "relative" }}>
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: "linear-gradient(90deg, #7c3aed, #00d4ff, #2ed573)" }} />
        <h1>📊 Security Analytics</h1>
        <p>Real-time security intelligence and threat analysis dashboard</p>
      </div>

      {/* Controls */}
      <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem", alignItems: "center" }}>
        <select className="select" value={daysRange} onChange={e => setDaysRange(Number(e.target.value))} style={{ width: 180 }}>
          {[7, 14, 30, 60, 90].map(d => <option key={d} value={d}>Last {d} days</option>)}
        </select>
        <button className="btn" onClick={loadData}>🔄 Refresh</button>
      </div>

      {/* Summary Stats */}
      <div className="grid-5" style={{ marginBottom: "1.5rem" }}>
        {[
          { label: "Total Scans", value: stats?.total_scans ?? 0, color: "var(--accent-cyan)" },
          { label: "Attacks Detected", value: stats?.attacks_detected ?? 0, color: "#ff4757" },
          { label: "High Risk", value: stats?.high_risk_count ?? 0, color: "#ff9f43" },
          { label: "Detection Rate", value: `${(stats?.detection_rate ?? 0).toFixed(1)}%`, color: "#2ed573" },
          { label: "Avg Risk Score", value: (stats?.avg_risk_score ?? 0).toFixed(1), color: "#7c3aed" },
        ].map((s, i) => (
          <div key={i} className="stat-mini">
            <div className="stat-label">{s.label}</div>
            <div className="stat-value" style={{ color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Row 1: Daily + Categories */}
      <div className="grid-2-1">
        <div className="chart-card">
          <h4>📈 Daily Attack Activity</h4>
          {daily.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={daily}>
                <XAxis dataKey="date" stroke="#8b95a5" fontSize={11} tickFormatter={d => d.slice(5)} />
                <YAxis stroke="#8b95a5" fontSize={11} />
                <Tooltip contentStyle={{ background: "#1a1f2e", border: "1px solid rgba(0,212,255,0.2)", borderRadius: 8, color: "#e0e6ed" }} />
                <Legend />
                <Area type="monotone" dataKey="total_scans" name="Total Scans" stroke="#00d4ff" fill="rgba(0,212,255,0.05)" strokeWidth={2} />
                <Area type="monotone" dataKey="attacks_detected" name="Attacks" stroke="#ff4757" fill="rgba(255,71,87,0.05)" strokeWidth={2} />
                <Line type="monotone" dataKey="high_risk_count" name="High Risk" stroke="#ff9f43" strokeWidth={2} strokeDasharray="5 5" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state"><p>No scan data available yet.</p></div>
          )}
        </div>

        <div className="chart-card">
          <h4>🎯 Attack Categories</h4>
          {categories.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={categories} dataKey="count" nameKey="attack_type"
                  cx="50%" cy="50%" innerRadius={60} outerRadius={100}
                  paddingAngle={2} stroke="#0a0e17" strokeWidth={2}
                  label={((props: Record<string, unknown>) => `${props.name || ''} ${((props.percent as number) * 100).toFixed(0)}%`) as never}
                  labelLine={{ stroke: "#8b95a5" }}
                  fontSize={10}
                >
                  {categories.map((c, i) => (
                    <Cell key={i} fill={CATEGORY_COLORS[c.attack_type] || "#8b95a5"} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#1a1f2e", border: "1px solid rgba(0,212,255,0.2)", borderRadius: 8, color: "#e0e6ed" }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state"><p>No category data yet.</p></div>
          )}
        </div>
      </div>

      {/* Row 2: Risk Distribution + Severity */}
      <div className="grid-2">
        <div className="chart-card">
          <h4>📊 Risk Score Distribution</h4>
          {riskData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={histBins}>
                <XAxis dataKey="range" stroke="#8b95a5" fontSize={12} />
                <YAxis stroke="#8b95a5" fontSize={11} />
                <Tooltip contentStyle={{ background: "#1a1f2e", border: "1px solid rgba(0,212,255,0.2)", borderRadius: 8, color: "#e0e6ed" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {histBins.map((b, i) => <Cell key={i} fill={b.color} opacity={0.85} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state"><p>No risk score data yet.</p></div>
          )}
        </div>

        <div className="chart-card">
          <h4>⚡ Severity Breakdown</h4>
          {sortedSeverity.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={sortedSeverity}>
                <XAxis dataKey="severity" stroke="#8b95a5" fontSize={12} />
                <YAxis stroke="#8b95a5" fontSize={11} />
                <Tooltip contentStyle={{ background: "#1a1f2e", border: "1px solid rgba(0,212,255,0.2)", borderRadius: 8, color: "#e0e6ed" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {sortedSeverity.map((s, i) => <Cell key={i} fill={SEVERITY_COLORS[s.severity] || "#8b95a5"} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state"><p>No severity data yet.</p></div>
          )}
        </div>
      </div>

      {/* Row 3: Top Patterns + OWASP */}
      <div className="grid-2">
        <div className="chart-card">
          <h4>🔥 Top Attack Patterns</h4>
          {patterns.length > 0 ? (
            <ResponsiveContainer width="100%" height={350}>
              <BarChart data={patterns} layout="vertical" margin={{ left: 10, right: 20 }}>
                <XAxis type="number" stroke="#8b95a5" fontSize={11} />
                <YAxis type="category" dataKey="description" stroke="#c0c8d4" fontSize={10} width={180} />
                <Tooltip contentStyle={{ background: "#1a1f2e", border: "1px solid rgba(0,212,255,0.2)", borderRadius: 8, color: "#e0e6ed" }} />
                <Bar dataKey="count" fill="#00d4ff" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state"><p>No attack patterns detected yet.</p></div>
          )}
        </div>

        <div className="chart-card">
          <h4>🏛️ OWASP LLM Top 10 Distribution</h4>
          {owasp.length > 0 ? (
            <div style={{ padding: "0.5rem" }}>
              {owasp.map((item, i) => (
                <div key={i} style={{
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  padding: "0.6rem 0.75rem", marginBottom: "0.4rem",
                  background: `${CATEGORY_COLORS[item.attack_type] || "#8b95a5"}10`,
                  border: `1px solid ${CATEGORY_COLORS[item.attack_type] || "#8b95a5"}30`,
                  borderRadius: 8,
                }}>
                  <div>
                    <div style={{ color: "var(--text-secondary)", fontSize: "0.85rem", fontWeight: 600 }}>{item.attack_type}</div>
                    <div style={{ color: "var(--text-dim)", fontSize: "0.75rem" }}>{item.owasp_id} — {item.owasp_name}</div>
                  </div>
                  <div style={{ color: CATEGORY_COLORS[item.attack_type] || "#8b95a5", fontFamily: "var(--font-mono)", fontWeight: 700, fontSize: "1.1rem" }}>
                    {item.count}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state"><p>No OWASP mapping data yet.</p></div>
          )}
        </div>
      </div>

      <div className="page-footer">
        Analytics last updated: {new Date().toLocaleString()}
      </div>
    </>
  );
}
