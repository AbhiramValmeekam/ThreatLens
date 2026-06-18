"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: "🏠" },
  { href: "/scanner", label: "Prompt Scanner", icon: "🔍" },
  { href: "/firewall", label: "LLM Firewall", icon: "🔥" },
  { href: "/heatmap", label: "Threat Heatmap", icon: "🌡️" },
  { href: "/analytics", label: "Analytics", icon: "📊" },
  { href: "/history", label: "Scan History", icon: "📋" },
  { href: "/batch", label: "Batch Scanner", icon: "📂" },
];

export default function Sidebar() {
  const pathname = usePathname();

  const engines = [
    { name: "DeBERTa-v3-base", active: true },
    { name: "TF-IDF + SVM", active: true },
    { name: "TF-IDF + LogReg", active: true },
    { name: "Regex Rule Engine", active: true },
  ];

  return (
    <aside className="sidebar">
      {/* Brand Logo */}
      <div className="sidebar-brand">
        <div className="brand-logo">🛡️</div>
        <div>
          <h2 className="brand-title">ThreatLens</h2>
          <span className="brand-subtitle">LLM Security Monitor</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <span className="sidebar-section-title">Navigation</span>
        {NAV_ITEMS.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`sidebar-link ${isActive ? "active" : ""}`}
            >
              <span className="sidebar-link-icon">{item.icon}</span>
              <span className="sidebar-link-label">{item.label}</span>
              {isActive && <span className="sidebar-active-indicator" />}
            </Link>
          );
        })}
      </nav>

      {/* Engine Status */}
      <div className="sidebar-engines">
        <span className="sidebar-section-title">Security Engines</span>
        {engines.map((engine) => (
          <div key={engine.name} className="engine-status-item">
            <span className="status-dot green" />
            <span className="engine-name">{engine.name}</span>
          </div>
        ))}
      </div>

      {/* Footer info */}
      <div className="sidebar-footer">
        <div className="footer-status">
          <span className="status-dot green pulse" />
          <span>System Protected</span>
        </div>
        <p className="footer-version">v2.0.0 (FastAPI + Next.js)</p>
      </div>
    </aside>
  );
}
