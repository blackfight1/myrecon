import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { useWorkspace } from "../context/WorkspaceContext";
import { useAssetsPage, useBulkDeleteAssets } from "../hooks/queries";
import { formatDate, joinList } from "../lib/format";
import type { Asset } from "../types/models";

function DomainLink({ asset }: { asset: Asset }) {
  const navigate = useNavigate();
  return (
    <button
      onClick={() => navigate(`/assets/${asset.id}`)}
      style={{
        background: "none",
        border: "none",
        color: "#60a5fa",
        cursor: "pointer",
        textDecoration: "underline",
        padding: 0,
        font: "inherit",
        textAlign: "left"
      }}
    >
      {asset.domain}
    </button>
  );
}

export function AssetsPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;

  const [search, setSearch] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [monitorNew, setMonitorNew] = useState<"all" | "open" | "recent24h">("all");
  const [sortBy, setSortBy] = useState<"created_at" | "updated_at" | "last_seen" | "domain" | "status_code">("last_seen");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const bulkDelete = useBulkDeleteAssets();

  useEffect(() => {
    setPage(1);
  }, [projectId, search, pageSize, monitorNew, sortBy, sortDir]);

  // 资产页统一口径：仅展示 httpx 验证存活资产。
  const assetsQ = useAssetsPage(projectId, {
    pool: "verified",
    q: search.trim() || undefined,
    liveOnly: true,
    monitorNew,
    page,
    pageSize,
    sortBy,
    sortDir
  });

  const items = assetsQ.data?.items ?? [];
  const total = assetsQ.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const liveCount = useMemo(() => items.filter((a) => (a.statusCode ?? 0) > 0).length, [items]);

  useEffect(() => {
    setSelectedIds(new Set());
  }, [page, search, monitorNew, sortBy, sortDir]);

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const toggleSelect = (id: number) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selectedIds.size === items.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(items.map((a) => a.id)));
    }
  };

  const handleBulkDelete = async () => {
    if (!projectId || selectedIds.size === 0) return;
    if (!confirm(`确认删除选中的 ${selectedIds.size} 条资产？此操作不可恢复。`)) return;
    try {
      await bulkDelete.mutateAsync({ projectId, ids: Array.from(selectedIds) });
      setSelectedIds(new Set());
    } catch (e) {
      alert("批量删除失败: " + (e instanceof Error ? e.message : String(e)));
    }
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">资产管理</h1>
        <p className="page-desc">统一展示 httpx 验证存活的 URL 资产，支持搜索、分页、排序和批量删除。</p>
      </div>

      <ProjectScopeBanner title="资产范围" hint="仅展示当前项目下已验证且存活（URL+状态码）的资产。" />

      <article className="panel">
        <header className="panel-header">
          <h2>筛选条件</h2>
          <span className="panel-meta">当前页存活 {liveCount} / 当前页 {items.length} / 总计 {total}</span>
        </header>
        <div className="filter-bar">
          <input
            className="form-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索域名、URL、IP、标题..."
          />
          <select className="form-select" value={sortBy} onChange={(e) => setSortBy(e.target.value as typeof sortBy)}>
            <option value="last_seen">按最后发现</option>
            <option value="created_at">按创建时间</option>
            <option value="updated_at">按更新时间</option>
            <option value="domain">按域名</option>
            <option value="status_code">按状态码</option>
          </select>
          <select className="form-select" value={monitorNew} onChange={(e) => setMonitorNew(e.target.value as typeof monitorNew)}>
            <option value="all">全部资产</option>
            <option value="open">监控新增（待处理）</option>
            <option value="recent24h">监控新增（24h）</option>
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
            {selectedIds.size > 0 && (
              <button className="btn btn-sm" style={{ background: "#dc2626", color: "#fff" }} onClick={handleBulkDelete} disabled={bulkDelete.isPending}>
                {bulkDelete.isPending ? "删除中..." : `批量删除 (${selectedIds.size})`}
              </button>
            )}
            <button className="btn btn-sm" onClick={() => setPage(1)} disabled={page <= 1}>« 首页</button>
            <button className="btn btn-sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>‹ 上一页</button>
            <span className="panel-meta">{items.length} 条记录</span>
            <button className="btn btn-sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>下一页 ›</button>
            <button className="btn btn-sm" onClick={() => setPage(totalPages)} disabled={page >= totalPages}>末页 »</button>
          </div>
        </header>

        {!projectId && <div className="empty-state">未选择项目，无法加载资产数据。</div>}
        {assetsQ.isLoading && <div className="empty-state">正在加载资产数据...</div>}
        {assetsQ.error && <div className="empty-state">加载资产失败。</div>}

        {!assetsQ.isLoading && !assetsQ.error && projectId && (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 36 }}>
                    <input type="checkbox" checked={items.length > 0 && selectedIds.size === items.length} onChange={toggleAll} />
                  </th>
                  <th>域名</th>
                  <th>URL</th>
                  <th>IP</th>
                  <th>新增</th>
                  <th>状态码</th>
                  <th>标题</th>
                  <th>技术栈</th>
                  <th>最后发现</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id} style={{ background: selectedIds.has(a.id) ? "rgba(96,165,250,0.08)" : undefined }}>
                    <td><input type="checkbox" checked={selectedIds.has(a.id)} onChange={() => toggleSelect(a.id)} /></td>
                    <td><DomainLink asset={a} /></td>
                    <td>{a.url || <span className="cell-muted">—</span>}</td>
                    <td>{a.ip ? <span className="cell-mono">{a.ip}</span> : <span className="cell-muted">—</span>}</td>
                    <td>{a.monitorNew ? <span className="badge badge-warning">新增</span> : <span className="cell-muted">-</span>}</td>
                    <td>
                      {a.statusCode ? (
                        <span className={a.statusCode >= 200 && a.statusCode < 300 ? "badge badge-success" : a.statusCode >= 400 ? "badge badge-danger" : "badge badge-warning"}>
                          {a.statusCode}
                        </span>
                      ) : (
                        <span className="cell-muted">—</span>
                      )}
                    </td>
                    <td>{a.title || <span className="cell-muted">—</span>}</td>
                    <td>{joinList(a.technologies, " · ") || <span className="cell-muted">—</span>}</td>
                    <td className="cell-muted">{formatDate(a.lastSeen)}</td>
                  </tr>
                ))}
                {items.length === 0 && (
                  <tr><td colSpan={9} style={{ textAlign: "center", padding: 32, color: "#888" }}>暂无数据</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </article>
    </section>
  );
}
