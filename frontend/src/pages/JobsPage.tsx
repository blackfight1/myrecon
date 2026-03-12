import { useMemo, useState } from "react";
import { createColumnHelper } from "@tanstack/react-table";
import { DataTable } from "../components/ui/DataTable";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useCreateJob, useJobs } from "../hooks/queries";
import type { JobOverview } from "../types/models";
import { formatDate, formatDurationSec } from "../lib/format";

const helper = createColumnHelper<JobOverview>();

const columns = [
  helper.accessor("rootDomain", { header: "Root Domain", cell: (ctx) => ctx.getValue() }),
  helper.accessor("mode", { header: "Mode", cell: (ctx) => ctx.getValue() }),
  helper.accessor("modules", { header: "Modules", cell: (ctx) => ctx.getValue().join(", ") }),
  helper.accessor("status", { header: "Status", cell: (ctx) => <StatusBadge status={ctx.getValue()} /> }),
  helper.accessor("startedAt", { header: "Started At", cell: (ctx) => formatDate(ctx.getValue()) }),
  helper.accessor("durationSec", { header: "Duration", cell: (ctx) => formatDurationSec(ctx.getValue()) })
];

export function JobsPage() {
  const { data, isLoading, error } = useJobs();
  const createJob = useCreateJob();

  const [domain, setDomain] = useState("");
  const [mode, setMode] = useState<"scan" | "monitor">("scan");
  const [enableNuclei, setEnableNuclei] = useState(false);
  const [activeSubs, setActiveSubs] = useState(false);
  const [dictSize, setDictSize] = useState(1500);
  const [dryRun, setDryRun] = useState(false);

  const rows = useMemo(() => data ?? [], [data]);

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!domain.trim()) return;

    await createJob.mutateAsync({
      domain: domain.trim(),
      mode,
      modules: ["subs", "ports", "witness"],
      enableNuclei,
      activeSubs,
      dictSize,
      dryRun
    });

    setDomain("");
  };

  return (
    <section className="page">
      <h1>Scan Jobs</h1>
      <p className="page-subtitle">Create and monitor scan jobs that map directly to your CLI workflow.</p>

      <form className="panel form-grid" onSubmit={onSubmit}>
        <label>
          Root Domain
          <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" />
        </label>
        <label>
          Mode
          <select value={mode} onChange={(e) => setMode(e.target.value as "scan" | "monitor")}>
            <option value="scan">scan</option>
            <option value="monitor">monitor</option>
          </select>
        </label>
        <label>
          Dict Size
          <input
            type="number"
            min={100}
            max={5000}
            value={dictSize}
            onChange={(e) => setDictSize(Number(e.target.value))}
          />
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={enableNuclei} onChange={(e) => setEnableNuclei(e.target.checked)} />
          Enable nuclei
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={activeSubs} onChange={(e) => setActiveSubs(e.target.checked)} />
          Enable active subs
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
          Dry run
        </label>
        <button type="submit" disabled={createJob.isPending}>
          {createJob.isPending ? "Creating..." : "Create Job"}
        </button>
      </form>

      <article className="panel">
        <header className="panel-header">
          <h2>Job List</h2>
          <span>{rows.length} records</span>
        </header>
        {isLoading ? <p className="empty-state">Loading jobs...</p> : null}
        {error ? <p className="empty-state">Failed to load jobs.</p> : null}
        {!isLoading && !error ? <DataTable data={rows} columns={columns} /> : null}
      </article>
    </section>
  );
}
