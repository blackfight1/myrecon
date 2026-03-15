import { createColumnHelper, type SortingState } from "@tanstack/react-table";
import { useState, useCallback, useMemo } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import { useJobsPage, useCancelJob } from "../hooks/queries";
import { formatDate } from "../lib/format";
import { endpoints } from "../api/endpoints";
import type { JobOverview } from "../types/models";
import type { JobListQuery } from "../api/endpoints";

const col = createColumnHelper<JobOverview>();

function isRunning(status: string): boolean {
  const s = status.toLowerCase();
  return s.includes("running") || s.includes("pending");
}

const QUICK_BASELINE_MODULES = ["subs", "httpx", "ports"];

const SORT_KEY_MAP: Record<string, JobListQuery["sortBy"]> = {
  startedAt: "started_at",
  finishedAt: "finished_at",
  durationSec: "duration_sec",
  status: "status",
  rootDomain: "root_domain"
};

export function JobsPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];
  const cancelJob = useCancelJob();

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [statusFilter, setStatusFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [sorting, setSorting] = useState<SortingState>([]);
  const [enableWitness, setEnableWitness] = useState(false);
  const [enableNuclei, setEnableNuclei] = useState(false);

  const sortBy = sorting.length > 0 ? SORT_KEY_MAP[sorting[0].id] ?? "started_at" : "started_at";
  const sortDir = sorting.length > 0 && sorting[0].desc ? "desc" : sorting.length > 0 ? "asc" : "desc";

  const query: JobListQuery = {
    rootDomain: rootDomains.length === 1 ? rootDomains[0] : undefined,
    status: statusFilter !== "all" ? statusFilter : undefined,
    q: search.trim() || undefined,
    page,
    pageSize,
    sortBy: sortBy as JobListQuery["sortBy"],
    sortDir: sortDir as JobListQuery["sortDir"]
  };

  const { data, isLoading, isError, refetch } = useJobsPage(projectId, query);

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  const handlePageChange = useCallback((p: number) => setPage(p + 1), []);
  const handlePageSizeChange = useCallback((s: number) => { setPageSize(s); setPage(1); }, []);
  const handleSortingChange = useCallback((s: SortingState) => { setSorting(s); setPage(1); }, []);
  const handleStatusFilterChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => { setStatusFilter(e.target.value); setPage(1); }, []);
  const handleSearchChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => { setSearch(e.target.value); setPage(1); }, []);

  const handleCancel = (jobId: string) => {
    if (!confirm("确认取消此任务？")) return;
    cancelJob.mutate({ jobId }, { onSuccess: () => refetch() });
  };

  const columns = [
    col.accessor("id", { header: "ID", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
    col.accessor("rootDomain", { header: "根域名" }),
    col.accessor("modules", { header: "模块", cell: (c) => (c.getValue() ?? []).join(", ") || <span className="cell-muted">—</span> }),
    col.accessor("status", { header: "状态", cell: (c) => <StatusBadge status={c.getValue()} /> }),
    col.accessor("startedAt", { header: "开始时间", cell: (c) => formatDate(c.getValue()) }),
    col.accessor("finishedAt", { header: "结束时间", cell: (c) => formatDate(c.getValue()) }),
    col.accessor("durationSec", { header: "耗时", cell: (c) => { const v = c.getValue(); return v != null ? `${v}s` : <span className="cell-muted">—</span>; } }),
    col.accessor("errorMessage", { header: "错误信息", cell: (c) => c.getValue() ? <span style={{ color: "var(--color-danger)", fontSize: 12 }}>{c.getValue()}</span> : <span className="cell-muted">—</span> }),
    col.display({
      id: "actions",
      header: "操作",
      cell: (c) => {
        const j = c.row.original;
        if (!isRunning(j.status)) return <span className="cell-muted">—</span>;
        return (
          <button
            className="btn btn-sm btn-danger"
            onClick={() => handleCancel(j.id)}
            disabled={cancelJob.isPending}
            style={{ fontSize: 11, padding: "2px 8px" }}
          >
            取消
          </button>
        );
      }
    })
  ];

  const previewModules = useMemo(
    () => [...QUICK_BASELINE_MODULES, ...(enableWitness ? ["witness"] : []), ...(enableNuclei ? ["nuclei"] : [])],
    [enableWitness, enableNuclei]
  );

  const launchScan = async () => {
    if (!activeProject || rootDomains.length === 0) return;
    const modules = [...QUICK_BASELINE_MODULES];
    if (enableWitness) modules.push("witness");
    if (enableNuclei) modules.push("nuclei");

    for (const rd of rootDomains) {
      try {
        await endpoints.createJob({
          projectId: activeProject.id,
          domain: rd,
          mode: "scan",
          modules,
          enableNuclei,
          activeSubs: false,
          dictSize: 1500,
          dryRun: false
        });
      } catch { /* ignore */ }
    }
    refetch();
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">扫描任务</h1>
        <p className="page-desc">流水线执行历史和快速启动控制，服务端分页与排序。</p>
      </div>

      <ProjectScopeBanner title="任务范围" hint="仅显示 root_domain 匹配项目范围的任务。" />

      <article className="panel">
        <header className="panel-header">
          <h2>快速启动（阶段逻辑）</h2>
          <span className="panel-meta">{rootDomains.join(", ")}</span>
        </header>
        <div className="filter-bar">
          <span className="panel-meta">固定流程: subs -&gt; httpx -&gt; ports</span>
          <button className={`btn btn-sm${enableWitness ? " btn-primary" : ""}`} onClick={() => setEnableWitness((v) => !v)}>
            Screenshot {enableWitness ? "ON" : "OFF"}
          </button>
          <button className={`btn btn-sm${enableNuclei ? " btn-primary" : ""}`} onClick={() => setEnableNuclei((v) => !v)}>
            Vulnerability {enableNuclei ? "ON" : "OFF"}
          </button>
          <button className="btn btn-sm" onClick={launchScan} disabled={rootDomains.length === 0}>
            启动快速扫描
          </button>
          <span className="filter-summary">执行: {previewModules.join(" -> ")}</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>筛选条件</h2>
          <span className="panel-meta">共 {total} 条</span>
        </header>
        <div className="filter-bar">
          <select className="form-select" value={statusFilter} onChange={handleStatusFilterChange}>
            <option value="all">全部</option>
            <option value="running">运行中</option>
            <option value="success">成功</option>
            <option value="failed">失败</option>
            <option value="canceled">已取消</option>
          </select>
          <input className="form-input" value={search} onChange={handleSearchChange} placeholder="搜索 ID/域名/状态/错误信息..." />
          <button className="btn btn-sm" onClick={() => refetch()}>刷新</button>
          <span className="filter-summary">第 {page} 页，每页 {pageSize} 条</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>任务历史</h2>
          <span className="panel-meta">{total} 条记录</span>
        </header>
        {isLoading && <div className="empty-state">正在加载任务数据...</div>}
        {isError && <div className="empty-state">加载任务数据失败。</div>}
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
