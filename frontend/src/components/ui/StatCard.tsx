interface StatCardProps {
  label: string;
  value: number | string;
  hint?: string;
  accent?: "blue" | "success" | "warning" | "danger";
}

export function StatCard({ label, value, hint, accent }: StatCardProps) {
  const cls = accent ? `stat-card accent-${accent}` : "stat-card";
  return (
    <div className={cls}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-change neutral">{hint}</div>}
    </div>
  );
}
