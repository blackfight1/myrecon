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

/* ---------- Monitor Targets table ---------- */
const tCol = createColumnHelper<MonitorTarget>();
const targetColumns = [
  tCol.accessor("rootDomain", { header: "Root Domain" }),
  tCol.accessor("enabled", { header: "Enabled", cell: (c) => c.getValue() ? <span className="badge badge-success">ON</span> : <span className="badge badge-danger">OFF</span> }),
  tCol.accessor("baselineDone", { header: "Baseline", cell: (c) => c.getValue() ? "✓" : "—" }),
  tCol.accessor("lastRunAt", { header: "Last Run", cell: (c) => formatDate(c.getValue()) }),
  tCol.accessor("updatedAt", { header: "Updated", cell: (c) => formatDate(c.getValue()) })
];

/* ---------- Monitor Runs table ---------- */
const rCol = createColumnHelper<MonitorRun>();
const runColumns = [
  rCol.accessor("id", { header: "ID" }),
  rCol.accessor("rootDomain", { header: "Root Domain" }),
  rCol.accessor("status", { header: "Status", cell: (c) => <StatusBadge status={c.getValue()} /> }),
  rCol.accessor("startedAt", { header: "Started", cell: (c) => formatDate(c.getValue()) }),
  rCol.accessor("durationSec", { header: "Duration", cell: (c) => `${c.getValue()}s` }),
  rCol.accessor("newLiveCount", { header: "New Live" }),
  rCol.accessor("webChanged", { header: "Web Δ" }),
  rCol.accessor("portOpened", { header: "Port +" }),
  rCol.accessor("portClosed", { header: "Port −" }),
  rCol.accessor("serviceChange", { header: "Svc Δ" }),
  rCol.accessor("errorMessage", { header: "Error", cell: (c) => c.getValue() || <span className="cell-muted">—</span> })
];

/* ---------- Monitor Changes table ---------- */
const cCol = createColumnHelper<MonitorChange>();
const changeColumns = [
  cCol.accessor("runId", { header: "Run" }),
  cCol.accessor("rootDomain", { header: "Root Domain" }),
  cCol.accessor("changeType", { header: "Type", cell: (c) => <span className="badge badge-info">{c.getValue()}</span> }),
  cCol.accessor("domain", { header: "Domain", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  cCol.accessor("ip", { header: "IP", cell: (c) => c.getValue() ? <span className="cell-mono">{c.getValue()}</span> : <span className="cell-muted">—</span> }),
  cCol.accessor("port", { header: "Port", cell: (c) => c.getValue() ?? <span className="cell-muted">—</span> }),
  cCol.accessor("statusCode", { header: "Status", cell: (c) => c.getValue() ?? <span className="cell-muted">—</span> }),
  cCol.accessor("title", { header: "Title", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  cCol.accessor("createdAt", { header: "Time", cell: (c) => formatDate(c.getValue()) })
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
        <h1 className="page-title">Monitoring</h1>
        <p className="page-desc">Drift detection system — tracks new hosts, port changes, service mutations and web content shifts.</p>
      </div>

      <ProjectScopeBanner title="Monitor Scope" hint="Targets, runs and change events filtered by project root domains." />

      {loading && <div className="empty-state">Loading monitoring data...</div>}

      <article className="panel">
        <header className="panel-header">
          <h2>Monitor Targets</h2>
          <span className="panel-meta">{targets.length} targets</span>
        </header>
        <DataTable data={targets} columns={targetColumns} />
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Recent Runs</h2>
          <span className="panel-meta">{runs.length} runs</span>
        </header>
        <DataTable data={runs} columns={runColumns} />
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Change Events</h2>
          <span className="panel-meta">{changes.length} events</span>
        </header>
        <DataTable data={changes} columns={changeColumns} />
      </article>
    </section>
  );
}
