export function formatDate(input?: string): string {
  if (!input) return "-";
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) return input;
  return date.toLocaleString();
}

export function formatDurationSec(seconds?: number): string {
  if (seconds == null) return "-";
  if (seconds < 60) return `${seconds}s`;
  const mins = Math.floor(seconds / 60);
  const sec = seconds % 60;
  return `${mins}m ${sec}s`;
}

export function joinList(items?: string[], separator = ", "): string {
  if (!items || items.length === 0) return "-";
  return items.join(separator);
}
