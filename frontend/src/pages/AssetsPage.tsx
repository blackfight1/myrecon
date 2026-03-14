import { createColumnHelper } from "@tanstack/react-table";
import { useEffect, useMemo, useState } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { useWorkspace } from "../context/WorkspaceContext";
import { useAssetsPage } from "../hooks/queries";
import { formatDate, joinList } from "../lib/format";
import { matchesProjectDomain } from "../lib/projectScope";
import type { Asset } from "../types/models";

const col = createColumnHelper<Asset>();

const columns = [
  col.accessor("domain", { header: "域名" }),
  col.accessor("url", { header: "URL", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("ip", { header: "IP", cell: (c) => c.getValue() ? <span className="cell-mono">{c.getValue()}</span> : <span className="cell-muted">—</span> }),
  col.accessor("statusCode", { header: "状态码", cell: (c) => { const v = c.getValue(); if (!v) return <span className="cell-muted">—</span>; const cls = v >= 200 && v < 300 ? "badge badge-success" : v >= 400 ? "badge badge-danger" : "badge badge-warning"; return <span className={cls}>{v}</span>; } }),
  col.accessor("title", { header: "标题", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("technologies", { header: "技术栈", cell: (c) => joinList(c.getValue(), " · ") || <span className="cell-muted">—</span> }),
  col.accessor("lastSeen", { header: "最后发现", cell: (c) => formatDate(c.getValue()) })
];

function hostnameFromUrl(input?: string): string | undefined {
  if (!input) return undefined;
  try { return new URL(input).hostname; } catch { return undefined; }
}

export function AssetsPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];

  const [search, setSearch] = useState("");
  const [liveOnly, setLiveOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [sortBy, setSortBy] = useState<"created_at" | "updated_at" | "last_seen" | "domain" | "status_code">("last_seen");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  useEffect(() => {
    setPage(1);
  }, [projectId, search, liveOnly, pageSize, sortBy, sortDir]);

  const assetsQ = useAssetsPage(projectId, {
    q: search.trim() || undefined,
    liveOnly,
    page,
    pageSize,
    sortBy,
    sortDir
  });

  const scoped = useMemo(() => {
    return (assetsQ.data?.items ?? []).filter((a) =>
      matchesProjectDomain(a.domain, rootDomains) || matchesProjectDomain(hostnameFromUrl(a.url), rootDomains)
    );
  }, [assetsQ.data?.items, rootDomains]);

  const liveCount = useMemo(() => scoped.filter((a) => a.statusCode != null && a.statusCode > 0).length, [scoped]);
  const total = assetsQ.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">资产管理</h1>
        <p className="page-desc">项目范围内的 Web 资产清单，包含响应状态和技术栈详情。</p>
      </div>

      <ProjectScopeBanner title="资产范围" hint="按根域名后缀匹配过滤。" />

      <article className="panel">
        <header className="panel-header">
          <h2>筛选条件</h2>
          <span className="panel-meta">当前页存活: {liveCount} / 当前页: {scoped.length} / 总计: {total}</span>
        </header>
        <div className="filter-bar">
          <input
            className="form-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索域名、URL、IP、标题、技术栈..."
          />
          <label className="form-check">
            <input type="checkbox" checked={liveOnly} onChange={(e) => setLiveOnly(e.target.checked)} />
            仅显示存活
          </label>
          <select className="form-select" value={sortBy} onChange={(e) => setSortBy(e.target.value as typeof sortBy)}>
            <option value="last_seen">按最后发现</option>
            <option value="created_at">按创建时间</option>
            <option value="updated_at">按更新时间</option>
            <option value="domain">按域名</option>
            <option value="status_code">按状态码</option>
          </select>
          <select className="form-select" value={sortDir} onChange={(e) => setSortDir(e.target.value as typeof sortDir)}>
            <option value="desc">降序</option>
            <option value="asc">升序</option>
          </select>
          <select className="form-select" value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))}>
            <option value={25}>25/页</option>
            <option value={50}>50/页</option>
            <option value={100}>100/页</option>
          </select>
          <span className="filter-summary">第 {page} / {totalPages} 页</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>资产清单</h2>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <button className="btn btn-sm" onClick={() => setPage(1)} disabled={page <= 1}>« 首页</button>
            <button className="btn btn-sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>‹ 上一页</button>
            <span className="panel-meta">{scoped.length} 条记录</span>
            <button className="btn btn-sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>下一页 ›</button>
            <button className="btn btn-sm" onClick={() => setPage(totalPages)} disabled={page >= totalPages}>末页 »</button>
          </div>
        </header>
        {!projectId && <div className="empty-state">未选择项目，无法加载资产数据。</div>}
        {assetsQ.isLoading && <div className="empty-state">正在加载资产数据...</div>}
        {assetsQ.error && <div className="empty-state">加载资产失败。</div>}
        {!assetsQ.isLoading && !assetsQ.error && projectId && <DataTable data={scoped} columns={columns} pageSize={1000} />}
      </article>
    </section>
  );
}
