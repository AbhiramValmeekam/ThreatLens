"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export default function Sidebar() {
  const pathname = usePathname();

  const engines = [
    { name: "DeBERTa-v3-base (60%)", active: true },
    { name: "TF-IDF + Linear SVM (15%)", active: true },
    { name: "TF-IDF + Logistic Reg. (10%)", active: true },
    { name: "Regex Rule Engine (15%)", active: true },
  ];

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div style={{ textAlign: "center", padding: "1rem 0" }}>
        <div style={{ fontSize: "3rem", marginBottom: "0.5rem", animation: "pulse 3s infinite" }}>
          🛡️
        </div>
        <h2 style={{ margin: 0, fontSize: "1.4rem", letterSpacing: "-0.01em", color: "var(--accent-cyan)" }}>
          ThreatLens
        </h2>
        <p style={{ color: "var(--text-dim)", fontSize: "0.85rem", marginTop: "0.25rem" }}>
          LLM Security Monitor v2.0
        </p>
      </div>

      {/* Divider */}
      <div style={{ borderBottom: "1px solid rgba(255,255,255,0.06)", margin: "0.75rem 0" }} />

      {/* Engine Status */}
      <div style={{ padding: "0.5rem 0" }}>
        <p style={{
          color: "var(--text-label)",
          fontSize: "0.8rem",
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          marginBottom: "0.75rem",
          fontWeight: 600,
        }}>
          Detection Engine Status
        </p>
        {engines.map((engine) => (
          <div
            key={engine.name}
            style={{
              display: "flex",
              alignItems: "center",
              marginBottom: "0.5rem",
              transition: "transform 0.2s",
              cursor: "default",
            }}
          >
            <span className="status-dot" />
            <span style={{ color: "#c0c8d4", fontSize: "0.9rem" }}>{engine.name}</span>
          </div>
        ))}
      </div>

      {/* Divider */}
      <div style={{ borderBottom: "1px solid rgba(255,255,255,0.06)", margin: "0.75rem 0" }} />

      {/* Last Updated */}
      <p style={{ color: "var(--text-dim)", fontSize: "0.75rem", marginTop: "auto" }}>
        Last updated: {new Date().toLocaleString("en-US", { dateStyle: "short", timeStyle: "short" })}
      </p>
    </aside>
  );
}
