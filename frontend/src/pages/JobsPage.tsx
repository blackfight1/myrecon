import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import { useJobs } from "../hooks/queries";
import { formatDate } from "../lib/format";
import { matchesProjectDomain } from "../lib/projectScope";
import { endpoints } from "../api/endpoints";
import type { JobOverview } from "../types/models";

const col = createColumnHelper<JobOverview>();

const columns = [
  col.accessor("id", { header: "ID", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
  col.accessor("rootDomain", { header: "根域名" }),
  col.accessor("modules", { header: "模块", cell: (c) => (c.getValue() ?? []).join(", ") || <span className="cell-muted">—</span> }),
  col.accessor("status", { header: "状态", cell: (c) => <StatusBadge status={c.getValue()} /> }),
  col.accessor("startedAt", { header: "开始时间", cell: (c) => formatDate(c.getValue()) }),
  col.accessor("finishedAt", { header: "结束时间", cell: (c) => formatDate(c.getValue()) }),
  col.accessor("durationSec", { header: "耗时", cell: (c) => { const v = c.getValue(); return v != null ? `${v}s` : <span className="cell-muted">—</span>; } }),
  col.accessor("errorMessage", { header: "错误信息", cell: (c) => c.getValue() ? <span style={{ color: "var(--color-danger)", fontSize: 12 }}>{c.getValue()}</span> : <span className="cell-muted">—</span> })
];

export function JobsPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];
  const { data, isLoading, error, refetch } = useJobs();
  const [filter, setFilter] = useState("all");

  const scoped = useMemo(() => {
    return (data ?? []).filter((j) => matchesProjectDomain(j.rootDomain, rootDomains));
  }, [data, rootDomains]);

  const rows = useMemo(() => {
    if (filter === "all") return scoped;
    const f = filter.toLowerCase();
    return scoped.filter((j) => {
      const s = j.status.toLowerCase();
      if (f === "running") return s.includes("running") || s.includes("pending");
      if (f === "success") return s.includes("ok") || s.includes("success") || s.includes("done");
      if (f === "failed") return s.includes("fail") || s.includes("error");
      return true;
    });
  }, [scoped, filter]);

  const launchScan = async (modules: string[]) => {
    if (!activeProject) return;
    for (const rd of rootDomains) {
      try {
        await endpoints.createJob({
          domain: rd,
          mode: "scan",
          modules,
          enableNuclei: modules.includes("nuclei"),
          activeSubs: modules.includes("dnsx_bruteforce"),
          dictSize: 0,
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
        <p className="page-desc">流水线执行历史和快速启动控制，按当前项目范围筛选。</p>
      </div>

      <ProjectScopeBanner title="任务范围" hint="仅显示 root_domain 匹配项目范围的任务。" />

      <article className="panel">
        <header className="panel-header">
          <h2>快速启动</h2>
          <span className="panel-meta">{rootDomains.join(", ")}</span>
        </header>
        <div className="filter-bar">
          {["subfinder", "findomain", "bbot", "dictgen", "dnsx_bruteforce", "naabu", "nmap", "httpx", "gowitness", "nuclei"].map((p) => (
            <button key={p} className="btn btn-sm" onClick={() => launchScan([p])}>{p}</button>
          ))}
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>筛选条件</h2>
          <span className="panel-meta">共 {scoped.length} 条</span>
        </header>
        <div className="filter-bar">
          <select className="form-select" value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">全部</option>
            <option value="running">运行中</option>
            <option value="success">成功</option>
            <option value="failed">失败</option>
          </select>
          <button className="btn btn-sm" onClick={() => refetch()}>刷新</button>
          <span className="filter-summary">匹配 {rows.length} 条</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>任务历史</h2>
          <span className="panel-meta">{rows.length} 条记录</span>
        </header>
        {isLoading && <div className="empty-state">正在加载任务数据...</div>}
        {error && <div className="empty-state">加载任务数据失败。</div>}
        {!isLoading && !error && <DataTable data={rows} columns={columns} />}
      </article>
    </section>
  );
}
