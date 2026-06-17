interface MetricCardProps {
  icon: string;
  label: string;
  value: string | number;
  color: "blue" | "red" | "orange" | "green" | "purple" | "cyan";
  delay?: number;
}

export default function MetricCard({ icon, label, value, color, delay = 1 }: MetricCardProps) {
  return (
    <div className={`metric-card anim-delay-${delay}`}>
      <div className="metric-icon">{icon}</div>
      <div className="metric-label">{label}</div>
      <div className={`metric-value ${color}`}>{value}</div>
    </div>
  );
}
