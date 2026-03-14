interface StatusBadgeProps {
  status: string;
}

const STATUS_LABELS: Record<string, string> = {
  // 后端可能返回的英文状态 → 中文标签
  ok: "成功",
  success: "成功",
  done: "已完成",
  completed: "已完成",
  complete: "已完成",
  running: "运行中",
  pending: "等待中",
  queued: "排队中",
  in_progress: "进行中",
  failed: "失败",
  error: "错误",
  warning: "警告",
  cancelled: "已取消",
  canceled: "已取消",
  skipped: "已跳过",
  timeout: "超时",
};

function translateStatus(raw: string): string {
  const key = raw.toLowerCase().trim();
  if (STATUS_LABELS[key]) return STATUS_LABELS[key];
  // 尝试部分匹配
  for (const [k, v] of Object.entries(STATUS_LABELS)) {
    if (key.includes(k)) return v;
  }
  return raw;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const s = status.toLowerCase();
  let cls = "badge badge-neutral";

  if (s.includes("ok") || s.includes("success") || s.includes("done") || s.includes("complete")) {
    cls = "badge badge-success";
  } else if (s.includes("running") || s.includes("pending") || s.includes("progress") || s.includes("queue")) {
    cls = "badge badge-info";
  } else if (s.includes("fail") || s.includes("error")) {
    cls = "badge badge-danger";
  } else if (s.includes("warn")) {
    cls = "badge badge-warning";
  } else if (s.includes("cancel") || s.includes("skip") || s.includes("timeout")) {
    cls = "badge badge-warning";
  }

  return <span className={cls}>{translateStatus(status)}</span>;
}
