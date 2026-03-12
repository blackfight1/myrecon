interface StatusBadgeProps {
  status: string;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const s = status.toLowerCase();
  let cls = "badge badge-neutral";

  if (s.includes("ok") || s.includes("success") || s.includes("done") || s.includes("complete")) {
    cls = "badge badge-success";
  } else if (s.includes("running") || s.includes("pending") || s.includes("progress")) {
    cls = "badge badge-info";
  } else if (s.includes("fail") || s.includes("error")) {
    cls = "badge badge-danger";
  } else if (s.includes("warn")) {
    cls = "badge badge-warning";
  }

  return <span className={cls}>{status}</span>;
}
