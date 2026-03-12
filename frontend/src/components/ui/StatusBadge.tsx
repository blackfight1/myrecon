import type { HealthStatus } from "../../types/models";

interface Props {
  status: HealthStatus | string;
}

export function StatusBadge({ status }: Props) {
  const normalized = String(status).toLowerCase();
  return <span className={`badge badge-${normalized}`}>{status}</span>;
}
