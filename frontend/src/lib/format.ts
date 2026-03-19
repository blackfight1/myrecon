/**
 * 通用格式化工具函数
 * 集中管理日期、时间、持续时间等格式化逻辑，避免各页面重复定义
 */

export function formatDate(input?: string | null): string {
  if (!input) return "—";
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) return input;
  return date.toLocaleString("zh-CN");
}

export function formatDateCompact(input?: string | null): string {
  if (!input) return "—";
  const d = new Date(input);
  if (Number.isNaN(d.getTime())) return "—";
  return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, "0")}/${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

export function formatDurationSec(seconds?: number | null, status?: string): string {
  const finished = status ? isFinished(status) : false;
  if (seconds === undefined || seconds === null) return finished ? "< 1s" : "—";
  if (seconds <= 0) return finished ? "< 1s" : "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

export function joinList(items?: string[], separator = ", "): string {
  if (!items || items.length === 0) return "—";
  return items.join(separator);
}

/** 检查任务状态是否已经结束 */
function isFinished(status: string): boolean {
  const l = status.toLowerCase();
  return (
    l.includes("success") ||
    l.includes("done") ||
    l.includes("ok") ||
    l.includes("completed") ||
    l.includes("fail") ||
    l.includes("error")
  );
}
