import { createColumnHelper } from "@tanstack/react-table";
import { useMemo } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import { useMonitorChanges, useMonitorRuns, useMonitorTargets } from "../hooks/queries";
import { formatDate } from "../lib/format";
import { matchesProjectDomain } from "../lib/projectScope";
import type { MonitorChange, MonitorRun, MonitorTarget } from "../types/models";

/* ---------- 监控目标表 ---------- */
const tCol = createColumnHelper<MonitorTarget>();
const targetColumns = [
  tCol.accessor("rootDomain", { header: "根域名" }),
  tCol.accessor("enabled", { header: "启用状态", cell: (c) => c.getValue() ? <span className="badge badge-success">开启</span> : <span className="badge badge-danger">关闭</span> }),
  tCol.accessor("baselineDone", { header: "基线", cell: (c) => c.getValue() ? "✓" : "—" }),
  tCol.accessor("lastRunAt", { header: "上次运行", cell: (c) => formatDate(c.getValue()) }),
  tCol.accessor("updatedAt", { header: "更新时间", cell: (c) => formatDate(c.getValue()) })
];

/* ---------- 监控运行记录表 ---------- */
const rCol = createColumnHelper<MonitorRun>();
const runColumns = [
  rCol.accessor("id", { header: "ID" }),
  rCol.accessor("rootDomain", { header: "根域名" }),
  rCol.accessor("status", { header: "状态", cell: (c) => <StatusBadge status={c.getValue()} /> }),
  rCol.accessor("startedAt", { header: "开始时间", cell: (c) => formatDate(c.getValue()) }),
  rCol.accessor("durationSec", { header: "耗时", cell: (c) => `${c.getValue()}s` }),
  rCol.accessor("newLiveCount", { header: "新增存活" }),
  rCol.accessor("webChanged", { header: "Web 变更" }),
  rCol.accessor("portOpened", { header: "端口新增" }),
  rCol.accessor("portClosed", { header: "端口关闭" }),
  rCol.accessor("serviceChange", { header: "服务变更" }),
  rCol.accessor("errorMessage", { header: "错误信息", cell: (c) => c.getValue() || <span className="cell-muted">—</span> })
];

/* ---------- 变更事件表 ---------- */
const cCol = createColumnHelper<MonitorChange>();
const changeColumns = [
  cCol.accessor("runId", { header: "运行 ID" }),
  cCol.accessor("rootDomain", { header: "根域名" }),
  cCol.accessor("changeType", { header: "类型", cell: (c) => <span className="badge badge-info">{c.getValue()}</span> }),
  cCol.accessor("domain", { header: "域名", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  cCol.accessor("ip", { header: "IP", cell: (c) => c.getValue() ? <span className="cell-mono">{c.getValue()}</span> : <span className="cell-muted">—</span> }),
  cCol.accessor("port", { header: "端口", cell: (c) => c.getValue() ?? <span className="cell-muted">—</span> }),
  cCol.accessor("statusCode", { header: "状态码", cell: (c) => c.getValue() ?? <span className="cell-muted">—</span> }),
  cCol.accessor("title", { header: "标题", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  cCol.accessor("createdAt", { header: "时间", cell: (c) => formatDate(c.getValue()) })
];

export function MonitoringPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];

  const targetsQ = useMonitorTargets();
  const runsQ = useMonitorRuns();
  const changesQ = useMonitorChanges();

  const targets = useMemo(() => (targetsQ.data ?? []).filter((t) => matchesProjectDomain(t.rootDomain, rootDomains)), [targetsQ.data, rootDomains]);
  const runs = useMemo(() => (runsQ.data ?? []).filter((r) => matchesProjectDomain(r.rootDomain, rootDomains)), [runsQ.data, rootDomains]);
  const changes = useMemo(() => (changesQ.data ?? []).filter((c) => matchesProjectDomain(c.rootDomain, rootDomains)), [changesQ.data, rootDomains]);

  const loading = targetsQ.isLoading || runsQ.isLoading || changesQ.isLoading;

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">变更监控</h1>
        <p className="page-desc">漂移检测系统 — 追踪新主机、端口变更、服务变化和 Web 内容变动。</p>
      </div>

      <ProjectScopeBanner title="监控范围" hint="目标、运行记录和变更事件按项目根域名过滤。" />

      {loading && <div className="empty-state">正在加载监控数据...</div>}

      <article className="panel">
        <header className="panel-header">
          <h2>监控目标</h2>
          <span className="panel-meta">{targets.length} 个目标</span>
        </header>
        <DataTable data={targets} columns={targetColumns} />
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>最近运行</h2>
          <span className="panel-meta">{runs.length} 次运行</span>
        </header>
        <DataTable data={runs} columns={runColumns} />
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>变更事件</h2>
          <span className="panel-meta">{changes.length} 个事件</span>
        </header>
        <DataTable data={changes} columns={changeColumns} />
      </article>
    </section>
  );
}
