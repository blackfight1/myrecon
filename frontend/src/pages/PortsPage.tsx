import { createColumnHelper, type SortingState } from "@tanstack/react-table";
import { useState, useCallback } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { useWorkspace } from "../context/WorkspaceContext";
import { usePortsPage } from "../hooks/queries";
import { formatDate } from "../lib/format";
import type { PortRecord } from "../types/models";
import type { PortListQuery } from "../api/endpoints";

const col = createColumnHelper<PortRecord>();

const columns = [
  col.accessor("domain", { header: "域名", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("ip", { header: "IP", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
  col.accessor("port", { header: "端口", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
  col.accessor("protocol", { header: "协议", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("service", { header: "服务", cell: (c) => c.getValue() ? <span className="badge badge-info">{c.getValue()}</span> : <span className="cell-muted">—</span> }),
  col.accessor("version", { header: "版本", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("lastSeen", { header: "最后发现", cell: (c) => formatDate(c.getValue()) })
];

const SORT_KEY_MAP: Record<string, PortListQuery["sortBy"]> = {
  domain: "domain",
  ip: "ip",
  port: "port",
  service: "service",
  lastSeen: "last_seen",
  updatedAt: "updated_at"
};

export function PortsPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [search, setSearch] = useState("");
  const [sorting, setSorting] = useState<SortingState>([]);

  const sortBy = sorting.length > 0 ? SORT_KEY_MAP[sorting[0].id] ?? "created_at" : "created_at";
  const sortDir = sorting.length > 0 && sorting[0].desc ? "desc" : sorting.length > 0 ? "asc" : "desc";

  const query: PortListQuery = {
    rootDomain: rootDomains.length === 1 ? rootDomains[0] : undefined,
    q: search.trim() || undefined,
    page,
    pageSize,
    sortBy: sortBy as PortListQuery["sortBy"],
    sortDir: sortDir as PortListQuery["sortDir"]
  };

  const { data, isLoading, isError } = usePortsPage(projectId, query);

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  const handlePageChange = useCallback((p: number) => setPage(p + 1), []);
  const handlePageSizeChange = useCallback((s: number) => { setPageSize(s); setPage(1); }, []);
  const handleSortingChange = useCallback((s: SortingState) => { setSorting(s); setPage(1); }, []);
  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => { setSearch(e.target.value); setPage(1); }, []);

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">端口扫描</h1>
        <p className="page-desc">按项目根域名筛选的服务暴露记录，支持服务端分页与排序。</p>
      </div>

      <ProjectScopeBanner title="端口范围" hint="服务端按项目范围过滤，支持搜索域名/IP/服务/版本。" />

      <article className="panel">
        <header className="panel-header">
          <h2>筛选条件</h2>
          <span className="panel-meta">共 {total} 条</span>
        </header>
        <div className="filter-bar">
          <input
            className="form-input"
            value={search}
            onChange={handleSearchChange}
            placeholder="搜索域名/IP/服务/版本..."
          />
          <span className="filter-summary">第 {page} 页，每页 {pageSize} 条</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>开放端口记录</h2>
          <span className="panel-meta">{total} 条记录</span>
        </header>
        {isLoading && <div className="empty-state">正在加载端口数据...</div>}
        {isError && <div className="empty-state">加载端口数据失败。</div>}
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
    </section>
  );
}
