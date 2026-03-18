import { createColumnHelper, type SortingState } from "@tanstack/react-table";
import { useCallback, useEffect, useMemo, useState, type ChangeEvent } from "react";
import { useNavigate } from "react-router-dom";
import type { JobListQuery } from "../api/endpoints";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import { useCancelJob, useCreateJob, useDeleteJob, useJobsPage, useSettings } from "../hooks/queries";
import { errorMessage } from "../lib/errors";
import { formatDate } from "../lib/format";
import type { JobOverview } from "../types/models";

const col = createColumnHelper<JobOverview>();
const QUICK_BASELINE_MODULES = ["subs", "httpx", "ports"];

const SORT_KEY_MAP: Record<string, JobListQuery["sortBy"]> = {
  startedAt: "started_at",
  finishedAt: "finished_at",
  durationSec: "duration_sec",
  status: "status",
  rootDomain: "root_domain"
};

function isRunning(status: string): boolean {
  const s = status.toLowerCase();
  return s.includes("running") || s.includes("pending");
}

export function JobsPage() {
  const navigate = useNavigate();
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];
  const cancelJob = useCancelJob();
  const deleteJob = useDeleteJob();
  const createJob = useCreateJob();
  const settingsQuery = useSettings();
  const scannerDefaults = settingsQuery.data?.scanner;

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [statusFilter, setStatusFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [sorting, setSorting] = useState<SortingState>([]);
  const [enableWitness, setEnableWitness] = useState(false);
  const [enableNuclei, setEnableNuclei] = useState(false);
  const [enableCors, setEnableCors] = useState(false);
  const [enableActiveSubs, setEnableActiveSubs] = useState(false);
  const [enableBbotActive, setEnableBbotActive] = useState(false);
  const [enableNotify, setEnableNotify] = useState(true);
  const [defaultsLoaded, setDefaultsLoaded] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (defaultsLoaded || !scannerDefaults) return;
    setEnableNuclei(scannerDefaults.defaultNuclei);
    setEnableCors(scannerDefaults.defaultNuclei);
    setEnableActiveSubs(scannerDefaults.defaultActiveSubs);
    setDefaultsLoaded(true);
  }, [defaultsLoaded, scannerDefaults]);

  const sortBy = sorting.length > 0 ? SORT_KEY_MAP[sorting[0].id] ?? "started_at" : "started_at";
  const sortDir = sorting.length > 0 && sorting[0].desc ? "desc" : sorting.length > 0 ? "asc" : "desc";

  const query: JobListQuery = {
    rootDomain: rootDomains.length === 1 ? rootDomains[0] : undefined,
    status: statusFilter !== "all" ? statusFilter : undefined,
    q: search.trim() || undefined,
    page,
    pageSize,
    sortBy,
    sortDir
  };

  const { data, isLoading, isError, refetch } = useJobsPage(projectId, query);
  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  const handlePageChange = useCallback((p: number) => setPage(p + 1), []);
  const handlePageSizeChange = useCallback((s: number) => {
    setPageSize(s);
    setPage(1);
  }, []);
  const handleSortingChange = useCallback((s: SortingState) => {
    setSorting(s);
    setPage(1);
  }, []);
  const handleStatusFilterChange = useCallback((e: ChangeEvent<HTMLSelectElement>) => {
    setStatusFilter(e.target.value);
    setPage(1);
  }, []);
  const handleSearchChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value);
    setPage(1);
  }, []);

  const handleCancel = (jobId: string) => {
    if (!confirm("确认取消该任务吗？")) return;
    cancelJob.mutate(
      { jobId },
      {
        onSuccess: () => {
          setFeedback({ ok: true, text: `任务已取消：${jobId}` });
          void refetch();
        },
        onError: (err) => setFeedback({ ok: false, text: `取消失败：${errorMessage(err)}` })
      }
    );
  };

  const handleDelete = (jobId: string) => {
    if (!projectId) return;
    if (!confirm("确认删除该任务历史记录？此操作不可恢复。")) return;
    deleteJob.mutate(
      { projectId, jobId },
      {
        onSuccess: () => {
          setFeedback({ ok: true, text: `任务记录已删除：${jobId}` });
          void refetch();
        },
        onError: (err) => setFeedback({ ok: false, text: `删除失败：${errorMessage(err)}` })
      }
    );
  };

  const handleViewLogs = (jobId: string) => {
    navigate(`/jobs/${encodeURIComponent(jobId)}/logs`);
  };

  const columns = [
    col.accessor("id", { header: "ID", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
    col.accessor("rootDomain", { header: "根域名" }),
    col.accessor("modules", { header: "模块", cell: (c) => (c.getValue() ?? []).join(", ") || <span className="cell-muted">-</span> }),
    col.accessor("status", { header: "状态", cell: (c) => <StatusBadge status={c.getValue()} /> }),
    col.accessor("startedAt", { header: "开始时间", cell: (c) => formatDate(c.getValue()) }),
    col.accessor("finishedAt", { header: "结束时间", cell: (c) => formatDate(c.getValue()) }),
    col.accessor("durationSec", {
      header: "耗时",
      cell: (c) => {
        const v = c.getValue();
        return v != null ? `${v}s` : <span className="cell-muted">-</span>;
      }
    }),
    col.accessor("errorMessage", {
      header: "错误信息",
      cell: (c) =>
        c.getValue() ? (
          <span style={{ color: "var(--color-danger)", fontSize: 12 }}>{c.getValue()}</span>
        ) : (
          <span className="cell-muted">-</span>
        )
    }),
    col.display({
      id: "actions",
      header: "操作",
      cell: (c) => {
        const j = c.row.original;
        if (!projectId) return <span className="cell-muted">-</span>;

        return (
          <div style={{ display: "flex", gap: 6 }}>
            <button className="btn btn-sm" onClick={() => handleViewLogs(j.id)} style={{ fontSize: 11, padding: "2px 8px" }}>
              日志
            </button>
            {isRunning(j.status) ? (
              <button
                className="btn btn-sm btn-danger"
                onClick={() => handleCancel(j.id)}
                disabled={cancelJob.isPending || deleteJob.isPending}
                style={{ fontSize: 11, padding: "2px 8px" }}
              >
                取消
              </button>
            ) : (
              <button
                className="btn btn-sm btn-danger"
                onClick={() => handleDelete(j.id)}
                disabled={deleteJob.isPending || cancelJob.isPending}
                style={{ fontSize: 11, padding: "2px 8px" }}
              >
                删除
              </button>
            )}
          </div>
        );
      }
    })
  ];

  const previewModules = useMemo(
    () => [
      ...QUICK_BASELINE_MODULES,
      ...(enableActiveSubs ? ["dnsx_bruteforce"] : []),
      ...(enableBbotActive ? ["bbot_active"] : []),
      ...(enableWitness ? ["witness"] : []),
      ...(enableNuclei ? ["nuclei"] : []),
      ...(enableCors ? ["cors"] : [])
    ],
    [enableActiveSubs, enableBbotActive, enableWitness, enableNuclei, enableCors]
  );

  const launchScan = async () => {
    if (!activeProject || rootDomains.length === 0) {
      setFeedback({ ok: false, text: "当前项目没有可扫描的根域名。" });
      return;
    }

    setFeedback(null);
    const modules = [...QUICK_BASELINE_MODULES];
    if (enableActiveSubs) modules.push("dnsx_bruteforce");
    if (enableBbotActive) modules.push("bbot_active");
    if (enableWitness) modules.push("witness");
    if (enableNuclei) modules.push("nuclei");
    if (enableCors) modules.push("cors");

    const success: string[] = [];
    const failed: string[] = [];

    for (const rd of rootDomains) {
      try {
        const job = await createJob.mutateAsync({
          projectId: activeProject.id,
          domain: rd,
          mode: "scan",
          modules,
          enableNuclei,
          activeSubs: enableActiveSubs,
          dictSize: scannerDefaults?.defaultDictSize ?? 1500,
          dryRun: false,
          notify: enableNotify
        });
        success.push(`${rd} (${job.id})`);
      } catch (err) {
        failed.push(`${rd}: ${errorMessage(err)}`);
      }
    }

    if (failed.length === 0) {
      setFeedback({ ok: true, text: `已提交 ${success.length} 个扫描任务。` });
    } else {
      setFeedback({ ok: false, text: `部分任务提交失败：${failed.join(" | ")}` });
    }

    await refetch();
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">扫描任务</h1>
        <p className="page-desc">流水线执行历史和快速启动控制，支持服务端分页与排序。</p>
      </div>

      <ProjectScopeBanner title="任务范围" hint="仅显示当前项目范围内的任务记录。" />

      {feedback && (
        <div className="empty-state" style={{ color: feedback.ok ? "#16a34a" : "#dc2626", marginBottom: 12 }}>
          {feedback.text}
        </div>
      )}

      <article className="panel">
        <header className="panel-header">
          <h2>快速启动（阶段逻辑）</h2>
          <span className="panel-meta">{rootDomains.join(", ")}</span>
        </header>
        <div className="filter-bar">
          <span className="panel-meta">固定流程: subs -&gt; httpx -&gt; ports</span>
          <button className={`btn btn-sm${enableWitness ? " btn-primary" : ""}`} onClick={() => setEnableWitness((v) => !v)}>
            截图 {enableWitness ? "开启" : "关闭"}
          </button>
          <button className={`btn btn-sm${enableNuclei ? " btn-primary" : ""}`} onClick={() => setEnableNuclei((v) => !v)}>
            漏洞扫描 {enableNuclei ? "开启" : "关闭"}
          </button>
          <button className={`btn btn-sm${enableCors ? " btn-primary" : ""}`} onClick={() => setEnableCors((v) => !v)}>
            高危CORS {enableCors ? "开启" : "关闭"}
          </button>
          <button className={`btn btn-sm${enableActiveSubs ? " btn-primary" : ""}`} onClick={() => setEnableActiveSubs((v) => !v)}>
            主动子域 {enableActiveSubs ? "开启" : "关闭"}
          </button>
          <button className={`btn btn-sm${enableBbotActive ? " btn-primary" : ""}`} onClick={() => setEnableBbotActive((v) => !v)}>
            BBOT主动扩展 {enableBbotActive ? "开启" : "关闭"}
          </button>
          <button className={`btn btn-sm${enableNotify ? " btn-primary" : ""}`} onClick={() => setEnableNotify((v) => !v)}>
            通知 {enableNotify ? "开启" : "关闭"}
          </button>
          <button className="btn btn-sm" onClick={() => {
            void launchScan();
          }} disabled={rootDomains.length === 0 || createJob.isPending}>
            {createJob.isPending ? "提交中..." : "启动快速扫描"}
          </button>
          <span className="filter-summary">执行链路: {previewModules.join(" -> ")} | 通知: {enableNotify ? "开" : "关"}</span>
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
          <input className="form-input" value={search} onChange={handleSearchChange} placeholder="搜索 ID/根域名/状态/错误信息..." />
          <button className="btn btn-sm" onClick={() => {
            void refetch();
          }}>刷新</button>
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
