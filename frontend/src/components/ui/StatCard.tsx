interface StatCardProps {
  icon?: string;
  label: string;
  value: number | string;
  change?: number;
  desc?: string;
  accent?: "blue" | "success" | "warning" | "danger";
}

export function StatCard({ icon, label, value, change, desc, accent }: StatCardProps) {
  const changeClass = change == null ? "" : change > 0 ? "up" : change < 0 ? "down" : "neutral";
  const changeText = change == null ? null : change > 0 ? `+${change}` : `${change}`;

  return (
    <div className={`stat-card${accent ? ` accent-${accent}` : ""}`}>
      <div className="stat-header">
        <span className="stat-label">
          {icon && <span className="stat-label-icon">{icon}</span>}
          {label}
        </span>
        {changeText != null && (
          <span className={`stat-change ${changeClass}`}>{changeText}</span>
        )}
      </div>
      <div className="stat-value">{typeof value === "number" ? value.toLocaleString() : value}</div>
      {desc && <div className="stat-desc">{desc}</div>}
    </div>
  );
}
