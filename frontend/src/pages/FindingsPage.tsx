import { createColumnHelper, type SortingState } from "@tanstack/react-table";
import { useState, useCallback, useMemo } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { useWorkspace } from "../context/WorkspaceContext";
import { useVulnsPage, usePatchVulnStatus } from "../hooks/queries";
import { formatDate } from "../lib/format";
import type { VulnerabilityRecord } from "../types/models";
import type { VulnListQuery } from "../api/endpoints";

type VulnStatus = "open" | "triaged" | "confirmed" | "accepted_risk" | "fixed" | "false_positive" | "duplicate";

const STATUS_OPTIONS: { value: VulnStatus; label: string; color: string }[] = [
  { value: "open", label: "待处理", color: "#ef4444" },
  { value: "triaged", label: "已分类", color: "#f59e0b" },
  { value: "confirmed", label: "已确认", color: "#f97316" },
  { value: "accepted_risk", label: "接受风险", color: "#8b5cf6" },
  { value: "fixed", label: "已修复", color: "#22c55e" },
  { value: "false_positive", label: "误报", color: "#64748b" },
  { value: "duplicate", label: "重复", color: "#94a3b8" }
];

function statusLabel(s?: string): string {
  const opt = STATUS_OPTIONS.find((o) => o.value === s);
  return opt?.label ?? "待处理";
}

function statusColor(s?: string): string {
  const opt = STATUS_OPTIONS.find((o) => o.value === s);
  return opt?.color ?? "#ef4444";
}

const col = createColumnHelper<VulnerabilityRecord>();

const SORT_KEY_MAP: Record<string, VulnListQuery["sortBy"]> = {
  severity: "severity",
  status: "status",
  rootDomain: "domain",
  domain: "domain",
  templateId: "template_id",
  matchedAt: "created_at",
  lastSeen: "last_seen"
};

export function FindingsPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];
  const patchStatus = usePatchVulnStatus();

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [severity, setSeverity] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [sorting, setSorting] = useState<SortingState>([]);
  const [editingVuln, setEditingVuln] = useState<VulnerabilityRecord | null>(null);
  const [newStatus, setNewStatus] = useState<VulnStatus>("open");
  const [statusReason, setStatusReason] = useState("");

  const sortBy = sorting.length > 0 ? SORT_KEY_MAP[sorting[0].id] ?? "created_at" : "created_at";
  const sortDir = sorting.length > 0 && sorting[0].desc ? "desc" : sorting.length > 0 ? "asc" : "desc";

  const query: VulnListQuery = {
    rootDomain: rootDomains.length === 1 ? rootDomains[0] : undefined,
    severity: severity !== "all" ? severity : undefined,
    status: statusFilter !== "all" ? statusFilter : undefined,
    q: search.trim() || undefined,
    page,
    pageSize,
    sortBy: sortBy as VulnListQuery["sortBy"],
    sortDir: sortDir as VulnListQuery["sortDir"]
  };

  const { data, isLoading, isError } = useVulnsPage(projectId, query);

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  const handlePageChange = useCallback((p: number) => setPage(p + 1), []);
  const handlePageSizeChange = useCallback((s: number) => { setPageSize(s); setPage(1); }, []);
  const handleSortingChange = useCallback((s: SortingState) => { setSorting(s); setPage(1); }, []);

  const handleSeverityChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => { setSeverity(e.target.value); setPage(1); }, []);
  const handleStatusFilterChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => { setStatusFilter(e.target.value); setPage(1); }, []);
  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => { setSearch(e.target.value); setPage(1); }, []);

  // Severity counts — estimated from the current page data (server doesn't provide global counts)
  // For a truly accurate count, a separate summary API would be needed.
  // For now we show total from the server and note it's page-scoped.
  const sevCounts = useMemo(() => {
    const o = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
    for (const f of items) {
      const k = (f.severity ?? "unknown").toLowerCase();
      if (k === "critical" || k === "high" || k === "medium" || k === "low" || k === "info") o[k]++;
      else o.unknown++;
    }
    return o;
  }, [items]);

  const handleStatusChange = (vuln: VulnerabilityRecord) => {
    setEditingVuln(vuln);
    setNewStatus((vuln.status as VulnStatus) || "open");
    setStatusReason("");
  };

  const submitStatusChange = () => {
    if (!editingVuln || !projectId) return;
    patchStatus.mutate(
      {
        vulnId: editingVuln.id,
        projectId,
        status: newStatus,
        reason: statusReason || undefined,
        actor: "user"
      },
      { onSuccess: () => setEditingVuln(null) }
    );
  };

  const columns = [
    col.accessor("severity", {
      header: "严重等级",
      cell: (c) => {
        const s = (c.getValue() || "unknown").toLowerCase();
        return <span className={`severity-chip severity-${s}`}>{s.toUpperCase()}</span>;
      }
    }),
    col.display({
      id: "vulnStatus",
      header: "状态",
      cell: (c) => {
        const v = c.row.original;
        const st = v.status || "open";
        return (
          <button
            className="status-badge"
            style={{ background: statusColor(st) + "22", color: statusColor(st), border: `1px solid ${statusColor(st)}44`, cursor: "pointer", fontSize: 12, padding: "2px 8px", borderRadius: 4 }}
            onClick={() => handleStatusChange(v)}
            title="点击修改状态"
          >
            {statusLabel(st)}
          </button>
        );
      }
    }),
    col.accessor("rootDomain", { header: "根域名", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
    col.accessor("templateId", { header: "模板 ID", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
    col.accessor("cve", { header: "CVE", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
    col.accessor("domain", { header: "域名", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
    col.accessor("url", { header: "URL", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
    col.accessor("assignee", { header: "负责人", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
    col.accessor("matchedAt", { header: "匹配时间", cell: (c) => formatDate(c.getValue()) }),
    col.accessor("fingerprint", { header: "指纹", cell: (c) => <span className="cell-mono">{c.getValue()}</span> })
  ];

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">漏洞发现</h1>
        <p className="page-desc">基于项目范围的 Nuclei 漏洞分类，支持按严重等级、状态和指纹搜索，服务端分页。</p>
      </div>

      <ProjectScopeBanner title="漏洞范围" hint="服务端按项目范围过滤并分页返回。" />

      <div className="stats-row">
        <div className="stat-card accent-danger"><div className="stat-label">严重</div><div className="stat-value">{sevCounts.critical}</div></div>
        <div className="stat-card accent-warning"><div className="stat-label">高危</div><div className="stat-value">{sevCounts.high}</div></div>
        <div className="stat-card"><div className="stat-label">中危</div><div className="stat-value">{sevCounts.medium}</div></div>
        <div className="stat-card accent-success"><div className="stat-label">低危</div><div className="stat-value">{sevCounts.low}</div></div>
        <div className="stat-card accent-blue"><div className="stat-label">信息</div><div className="stat-value">{sevCounts.info}</div></div>
        <div className="stat-card"><div className="stat-label">未知</div><div className="stat-value">{sevCounts.unknown}</div></div>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>筛选条件</h2>
          <span className="panel-meta">共 {total} 条</span>
        </header>
        <div className="filter-bar">
          <select className="form-select" value={severity} onChange={handleSeverityChange}>
            <option value="all">全部等级</option>
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
            <option value="info">信息</option>
            <option value="unknown">未知</option>
          </select>
          <select className="form-select" value={statusFilter} onChange={handleStatusFilterChange}>
            <option value="all">全部状态</option>
            {STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <input className="form-input" value={search} onChange={handleSearchChange} placeholder="搜索根域名/域名/模板/CVE/URL/指纹..." />
          <span className="filter-summary">第 {page} 页，每页 {pageSize} 条</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>漏洞记录</h2>
          <span className="panel-meta">{total} 条记录</span>
        </header>
        {isLoading && <div className="empty-state">正在加载漏洞数据...</div>}
        {isError && <div className="empty-state">加载漏洞数据失败。</div>}
        {!isLoading && !isError && (
          <DataTable
            data={items}
            columns={columns}
            manualPagination
            manualSorting
            totalRows={total}
            pageIndex={page - 1}
            onPageIndexChange={handlePageChange}
            onPageSizeChange={handlePageSizeChange}
            sorting={sorting}
            onSortingChange={handleSortingChange}
            pageSize={pageSize}
          />
        )}
      </article>

      {/* Status Change Dialog */}
      {editingVuln && (
        <div style={{
          position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 9999
        }} onClick={() => setEditingVuln(null)}>
          <div style={{
            background: "#0f172a", border: "1px solid #1e2a42", borderRadius: 12, padding: 24, minWidth: 400, maxWidth: 500
          }} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ margin: "0 0 16px", color: "#e2e8f0" }}>修改漏洞状态</h3>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 13, color: "#94a3b8", marginBottom: 4 }}>漏洞</div>
              <div style={{ fontSize: 14, color: "#e2e8f0" }}>
                <span className={`severity-chip severity-${(editingVuln.severity || "unknown").toLowerCase()}`} style={{ marginRight: 8 }}>
                  {(editingVuln.severity || "UNKNOWN").toUpperCase()}
                </span>
                {editingVuln.templateId} — {editingVuln.domain || editingVuln.url || "N/A"}
              </div>
            </div>
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 13, color: "#94a3b8", display: "block", marginBottom: 4 }}>当前状态</label>
              <span style={{ color: statusColor(editingVuln.status || "open"), fontWeight: 600 }}>
                {statusLabel(editingVuln.status || "open")}
              </span>
            </div>
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 13, color: "#94a3b8", display: "block", marginBottom: 4 }}>新状态</label>
              <select className="form-select" value={newStatus} onChange={(e) => setNewStatus(e.target.value as VulnStatus)} style={{ width: "100%" }}>
                {STATUS_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 13, color: "#94a3b8", display: "block", marginBottom: 4 }}>原因（可选）</label>
              <input className="form-input" value={statusReason} onChange={(e) => setStatusReason(e.target.value)} placeholder="状态变更原因..." style={{ width: "100%" }} />
            </div>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button className="btn btn-ghost" onClick={() => setEditingVuln(null)}>取消</button>
              <button className="btn btn-primary" onClick={submitStatusChange} disabled={patchStatus.isPending || newStatus === (editingVuln.status || "open")}>
                {patchStatus.isPending ? "提交中..." : "确认修改"}
              </button>
            </div>
            {patchStatus.isError && (
              <div style={{ color: "#ef4444", fontSize: 12, marginTop: 8 }}>
                提交失败：{(patchStatus.error as Error).message}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
