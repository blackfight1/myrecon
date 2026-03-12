import { createColumnHelper } from "@tanstack/react-table";
import { DataTable } from "../components/ui/DataTable";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useMonitorChanges, useMonitorRuns, useMonitorTargets } from "../hooks/queries";
import type { MonitorChange, MonitorRun, MonitorTarget } from "../types/models";
import { formatDate, formatDurationSec } from "../lib/format";

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
  const targets = useMonitorTargets();
  const runs = useMonitorRuns();
  const changes = useMonitorChanges();

  return (
    <section className="page">
      <h1>Monitoring</h1>
      <p className="page-subtitle">Tracks monitor_targets, monitor_runs, and change events with debounce-aware signals.</p>

      <article className="panel">
        <header className="panel-header">
          <h2>Targets</h2>
          <span>{targets.data?.length ?? 0} records</span>
        </header>
        {targets.isError ? <p className="empty-state">Failed to load monitor targets.</p> : null}
        {!targets.isError ? <DataTable data={targets.data ?? []} columns={targetColumns} /> : null}
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Runs</h2>
          <span>{runs.data?.length ?? 0} records</span>
        </header>
        {runs.isError ? <p className="empty-state">Failed to load monitor runs.</p> : null}
        {!runs.isError ? <DataTable data={runs.data ?? []} columns={runColumns} /> : null}
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Recent Changes</h2>
          <span>{changes.data?.length ?? 0} records</span>
        </header>
        {changes.isError ? <p className="empty-state">Failed to load monitor changes.</p> : null}
        {!changes.isError ? <DataTable data={changes.data ?? []} columns={changeColumns} /> : null}
      </article>
    </section>
  );
}
