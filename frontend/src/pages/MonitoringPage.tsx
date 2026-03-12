import { createColumnHelper } from "@tanstack/react-table";
import { useMemo } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import { useMonitorChanges, useMonitorRuns, useMonitorTargets } from "../hooks/queries";
import { formatDate, formatDurationSec } from "../lib/format";
import { matchesProjectDomain } from "../lib/projectScope";
import type { MonitorChange, MonitorRun, MonitorTarget } from "../types/models";

const targetHelper = createColumnHelper<MonitorTarget>();
const runHelper = createColumnHelper<MonitorRun>();
const changeHelper = createColumnHelper<MonitorChange>();

const targetColumns = [
  targetHelper.accessor("rootDomain", { header: "Root Domain" }),
  targetHelper.accessor("enabled", { header: "Enabled", cell: (ctx) => (ctx.getValue() ? "yes" : "no") }),
  targetHelper.accessor("baselineDone", { header: "Baseline", cell: (ctx) => (ctx.getValue() ? "ready" : "pending") }),
  targetHelper.accessor("lastRunAt", { header: "Last Run", cell: (ctx) => formatDate(ctx.getValue()) })
];

const runColumns = [
  runHelper.accessor("rootDomain", { header: "Root Domain" }),
  runHelper.accessor("status", { header: "Status", cell: (ctx) => <StatusBadge status={ctx.getValue()} /> }),
  runHelper.accessor("newLiveCount", { header: "New Live" }),
  runHelper.accessor("webChanged", { header: "Web Changed" }),
  runHelper.accessor("portOpened", { header: "Port Opened" }),
  runHelper.accessor("portClosed", { header: "Port Closed" }),
  runHelper.accessor("serviceChange", { header: "Service Changed" }),
  runHelper.accessor("durationSec", { header: "Duration", cell: (ctx) => formatDurationSec(ctx.getValue()) }),
  runHelper.accessor("startedAt", { header: "Started At", cell: (ctx) => formatDate(ctx.getValue()) })
];

const changeColumns = [
  changeHelper.accessor("rootDomain", { header: "Root Domain" }),
  changeHelper.accessor("changeType", { header: "Type" }),
  changeHelper.accessor("domain", { header: "Domain", cell: (ctx) => ctx.getValue() || "-" }),
  changeHelper.accessor("ip", { header: "IP", cell: (ctx) => ctx.getValue() || "-" }),
  changeHelper.accessor("port", { header: "Port", cell: (ctx) => ctx.getValue() ?? "-" }),
  changeHelper.accessor("createdAt", { header: "Created At", cell: (ctx) => formatDate(ctx.getValue()) })
];

export function MonitoringPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];

  const targets = useMonitorTargets();
  const runs = useMonitorRuns();
  const changes = useMonitorChanges();

  const scopedTargets = useMemo(
    () => (targets.data ?? []).filter((item) => matchesProjectDomain(item.rootDomain, rootDomains)),
    [targets.data, rootDomains]
  );
  const scopedRuns = useMemo(
    () => (runs.data ?? []).filter((item) => matchesProjectDomain(item.rootDomain, rootDomains)),
    [runs.data, rootDomains]
  );
  const scopedChanges = useMemo(
    () => (changes.data ?? []).filter((item) => matchesProjectDomain(item.rootDomain, rootDomains)),
    [changes.data, rootDomains]
  );

  return (
    <section className="page">
      <h1>Monitoring</h1>
      <p className="page-subtitle">Project-scoped monitor targets, run history, and change events.</p>

      <ProjectScopeBanner
        title="Monitoring Scope"
        hint="Rows are scoped by monitor root_domain so alerts align with one workspace at a time."
      />

      <article className="panel">
        <header className="panel-header">
          <h2>Targets</h2>
          <span>{scopedTargets.length} records</span>
        </header>
        {targets.isError ? <p className="empty-state">Failed to load monitor targets.</p> : null}
        {!targets.isError ? <DataTable data={scopedTargets} columns={targetColumns} /> : null}
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Runs</h2>
          <span>{scopedRuns.length} records</span>
        </header>
        {runs.isError ? <p className="empty-state">Failed to load monitor runs.</p> : null}
        {!runs.isError ? <DataTable data={scopedRuns} columns={runColumns} /> : null}
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Recent Changes</h2>
          <span>{scopedChanges.length} records</span>
        </header>
        {changes.isError ? <p className="empty-state">Failed to load monitor changes.</p> : null}
        {!changes.isError ? <DataTable data={scopedChanges} columns={changeColumns} /> : null}
      </article>
    </section>
  );
}
