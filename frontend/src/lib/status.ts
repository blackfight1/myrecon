/**
 * 通用状态工具函数
 * 集中管理任务状态和漏洞状态的 class、label、颜色等，避免各页面重复定义
 */

/* ── 任务状态 ── */

export type JobStatusClass = "completed" | "failed" | "running" | "pending" | "canceled";

export function jobStatusClass(status: string): JobStatusClass {
    const l = status.toLowerCase();
    if (l.includes("ok") || l.includes("success") || l.includes("done") || l.includes("completed")) return "completed";
    if (l.includes("fail") || l.includes("error")) return "failed";
    if (l.includes("cancel")) return "canceled";
    if (l.includes("running")) return "running";
    return "pending";
}

export function jobStatusLabel(status: string): string {
    const cls = jobStatusClass(status);
    switch (cls) {
        case "completed": return "已完成";
        case "failed": return "失败";
        case "running": return "运行中";
        case "canceled": return "已取消";
        default: return "等待中";
    }
}

export function isJobRunning(status: string): boolean {
    const s = status.toLowerCase();
    return s.includes("running") || s.includes("pending");
}

/* ── 漏洞状态 ── */

export type VulnStatus = "open" | "triaged" | "confirmed" | "accepted_risk" | "fixed" | "false_positive" | "duplicate";

export const VULN_STATUS_OPTIONS: { value: VulnStatus; label: string; color: string }[] = [
    { value: "open", label: "待处理", color: "#ef4444" },
    { value: "triaged", label: "已分类", color: "#f59e0b" },
    { value: "confirmed", label: "已确认", color: "#f97316" },
    { value: "accepted_risk", label: "接受风险", color: "#8b5cf6" },
    { value: "fixed", label: "已修复", color: "#22c55e" },
    { value: "false_positive", label: "误报", color: "#64748b" },
    { value: "duplicate", label: "重复", color: "#94a3b8" },
];

export function vulnStatusLabel(status?: string): string {
    const opt = VULN_STATUS_OPTIONS.find((o) => o.value === status);
    return opt?.label ?? "待处理";
}

export function vulnStatusColor(status?: string): string {
    const opt = VULN_STATUS_OPTIONS.find((o) => o.value === status);
    return opt?.color ?? "#ef4444";
}

/* ── 严重等级 ── */

export function severityClass(severity?: string): string {
    return `severity-${(severity || "unknown").toLowerCase()}`;
}

export function severityLabel(severity?: string): string {
    return (severity || "UNKNOWN").toUpperCase();
}
