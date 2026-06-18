"use client";

import { useState, useEffect } from "react";
import { generateHeatmap, type HeatmapSegment, type HeatmapResult } from "@/lib/api";

const HEATMAP_COLORS: Record<string, { bg: string; text: string; border: string; glow: string }> = {
  safe:     { bg: "rgba(46,213,115,0.08)",   text: "#cbd5e1", border: "transparent",               glow: "none" },
  low:      { bg: "rgba(253,224,71,0.12)",    text: "#facc15", border: "rgba(253,224,71,0.25)",     glow: "0 0 8px rgba(253,224,71,0.15)" },
  medium:   { bg: "rgba(251,146,60,0.15)",    text: "#fb923c", border: "rgba(251,146,60,0.3)",      glow: "0 0 10px rgba(251,146,60,0.2)" },
  high:     { bg: "rgba(248,113,113,0.18)",   text: "#f87171", border: "rgba(248,113,113,0.3)",     glow: "0 0 12px rgba(248,113,113,0.25)" },
  critical: { bg: "rgba(239,68,68,0.28)",     text: "#ef4444", border: "rgba(239,68,68,0.4)",       glow: "0 0 15px rgba(239,68,68,0.3)" },
};

const LEVEL_LABELS: Record<string, string> = {
  safe: "Safe", low: "Low Risk", medium: "Medium Risk", high: "High Risk", critical: "Critical",
};

interface ThreatHeatmapProps {
  /** The prompt text to generate a heatmap for. If provided, auto-fetches from API */
  prompt?: string;
  /** Pre-computed heatmap segments (skip API call if provided) */
  segments?: HeatmapSegment[];
  /** Compact mode shows just the heatmap inline without charts/stats */
  compact?: boolean;
  /** Title override */
  title?: string;
}

export default function ThreatHeatmap({ prompt, segments: preloadedSegments, compact = false, title }: ThreatHeatmapProps) {
  const [segments, setSegments] = useState<HeatmapSegment[]>(preloadedSegments || []);
  const [riskySegments, setRiskySegments] = useState<HeatmapSegment[]>([]);
  const [loading, setLoading] = useState(false);
  const [hoveredSegment, setHoveredSegment] = useState<number | null>(null);

  useEffect(() => {
    if (preloadedSegments && preloadedSegments.length > 0) {
      setSegments(preloadedSegments);
      setRiskySegments(preloadedSegments.filter(s => ["medium", "high", "critical"].includes(s.level)));
      return;
    }
    if (!prompt?.trim()) {
      setSegments([]);
      setRiskySegments([]);
      return;
    }
    setLoading(true);
    generateHeatmap(prompt)
      .then((res) => {
        setSegments(res.segments);
        setRiskySegments(res.risky_segments_only);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [prompt, preloadedSegments]);

  if (loading) {
    return (
      <div className="chart-card">
        <h4>{title || "🌡️ Threat Risk Heatmap"}</h4>
        <div className="spinner-overlay">
          <div className="spinner" />
          <span>Generating heatmap...</span>
        </div>
      </div>
    );
  }

  if (segments.length === 0) return null;

  const maxScore = Math.max(...segments.map(s => s.score), 0);
  const avgScore = segments.reduce((sum, s) => sum + s.score, 0) / segments.length;

  // Coverage stats
  const totalChars = segments.reduce((sum, s) => sum + s.text.length, 0);
  const coverageStats = Object.entries(
    segments.reduce<Record<string, number>>((acc, seg) => {
      acc[seg.level] = (acc[seg.level] || 0) + seg.text.length;
      return acc;
    }, {})
  ).map(([level, chars]) => ({
    level,
    label: LEVEL_LABELS[level] || level,
    chars,
    percentage: totalChars > 0 ? (chars / totalChars) * 100 : 0,
    color: HEATMAP_COLORS[level]?.text || "#8b95a5",
  }));

  return (
    <div className="chart-card">
      <h4>{title || "🌡️ Threat Risk Heatmap"}</h4>

      {/* Inline Heatmap */}
      <div className="heatmap-display heatmap-interactive">
        {segments.map((seg, i) => {
          const style = HEATMAP_COLORS[seg.level] || HEATMAP_COLORS.safe;
          const isHovered = hoveredSegment === i;
          return (
            <span
              key={i}
              className={`heatmap-segment ${isHovered ? "heatmap-segment-hover" : ""}`}
              style={{
                backgroundColor: isHovered ? style.bg.replace(/[\d.]+\)$/, m => `${parseFloat(m) * 2.5})`) : style.bg,
                color: style.text,
                borderColor: isHovered ? style.text : style.border,
                borderWidth: seg.level !== "safe" ? "1px" : isHovered ? "1px" : "0",
                borderStyle: "solid",
                boxShadow: isHovered ? style.glow : "none",
                transform: isHovered ? "scale(1.03)" : "scale(1)",
              }}
              title={`Score: ${seg.score} | ${seg.severity} (${seg.badge})`}
              onMouseEnter={() => setHoveredSegment(i)}
              onMouseLeave={() => setHoveredSegment(null)}
            >
              {seg.text}
              {seg.level !== "safe" && (
                <span className="heatmap-score-tooltip">{seg.score}</span>
              )}
            </span>
          );
        })}
      </div>

      {/* Legend */}
      <div className="heatmap-legend">
        {Object.entries(HEATMAP_COLORS).map(([level, colors]) => (
          <div key={level} className="heatmap-legend-item">
            <span className="heatmap-legend-swatch" style={{ backgroundColor: colors.text }} />
            <span>{LEVEL_LABELS[level]}</span>
          </div>
        ))}
      </div>

      {/* Hover Detail */}
      {hoveredSegment !== null && segments[hoveredSegment] && (
        <div className="heatmap-detail-card" style={{ animation: "fadeInUp 0.2s ease forwards" }}>
          <div className="heatmap-detail-header">
            <span style={{ color: HEATMAP_COLORS[segments[hoveredSegment].level]?.text }}>
              Segment #{hoveredSegment + 1}
            </span>
            <span className={`firewall-action-badge action-${segments[hoveredSegment].score > 70 ? "block" : segments[hoveredSegment].score >= 40 ? "sanitize" : "allow"}`}>
              {segments[hoveredSegment].badge}
            </span>
          </div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--text-secondary)", marginTop: "0.5rem" }}>
            &ldquo;{segments[hoveredSegment].text}&rdquo;
          </div>
          <div style={{ display: "flex", gap: "1.5rem", marginTop: "0.75rem", fontSize: "0.8rem" }}>
            <div><span style={{ color: "var(--text-dim)" }}>Score: </span><span style={{ fontFamily: "var(--font-mono)", fontWeight: 700, color: HEATMAP_COLORS[segments[hoveredSegment].level]?.text }}>{segments[hoveredSegment].score}</span></div>
            <div><span style={{ color: "var(--text-dim)" }}>Severity: </span><span style={{ color: HEATMAP_COLORS[segments[hoveredSegment].level]?.text }}>{segments[hoveredSegment].severity}</span></div>
            <div><span style={{ color: "var(--text-dim)" }}>Chars: </span><span style={{ fontFamily: "var(--font-mono)" }}>{segments[hoveredSegment].start}-{segments[hoveredSegment].end}</span></div>
          </div>
        </div>
      )}

      {/* Extended Stats (non-compact mode) */}
      {!compact && (
        <div style={{ marginTop: "1rem" }}>
          {/* Coverage Bar */}
          <div className="heatmap-coverage-bar" style={{ marginBottom: "0.75rem" }}>
            {coverageStats.map((stat, i) => (
              <div
                key={i}
                className="heatmap-coverage-segment"
                style={{ width: `${stat.percentage}%`, backgroundColor: stat.color, opacity: 0.75 }}
                title={`${stat.label}: ${stat.percentage.toFixed(1)}%`}
              />
            ))}
          </div>

          {/* Inline stat chips */}
          <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", fontSize: "0.78rem" }}>
            <span style={{ color: "var(--text-dim)" }}>
              Segments: <strong style={{ color: "var(--accent-cyan)" }}>{segments.length}</strong>
            </span>
            <span style={{ color: "var(--text-dim)" }}>
              Risky: <strong style={{ color: "#ff4757" }}>{riskySegments.length}</strong>
            </span>
            <span style={{ color: "var(--text-dim)" }}>
              Peak: <strong style={{ color: maxScore > 70 ? "#ef4444" : maxScore > 40 ? "#fb923c" : "#2ed573" }}>{maxScore.toFixed(0)}</strong>
            </span>
            <span style={{ color: "var(--text-dim)" }}>
              Avg: <strong style={{ color: avgScore > 50 ? "#fb923c" : "#2ed573" }}>{avgScore.toFixed(1)}</strong>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
