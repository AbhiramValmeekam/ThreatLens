interface SeverityBadgeProps {
  severity: string;
}

const SEVERITY_MAP: Record<string, string> = {
  Low: "badge-safe",
  Medium: "badge-medium",
  High: "badge-high",
  Critical: "badge-critical",
};

export default function SeverityBadge({ severity }: SeverityBadgeProps) {
  const cls = SEVERITY_MAP[severity] || "badge-safe";
  return <span className={`badge ${cls}`}>{severity}</span>;
}
