import { useEffect, useMemo, useState } from "react";
import { createColumnHelper } from "@tanstack/react-table";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import { useCreateJob, useJobs } from "../hooks/queries";
import type { JobOverview } from "../types/models";
import { formatDate, formatDurationSec } from "../lib/format";
import { matchesProjectDomain } from "../lib/projectScope";

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
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];
  const { data, isLoading, error } = useJobs();
  const createJob = useCreateJob();

  const [domain, setDomain] = useState(rootDomains[0] ?? "");
  const [mode, setMode] = useState<"scan" | "monitor">("scan");
  const [enableNuclei, setEnableNuclei] = useState(false);
  const [activeSubs, setActiveSubs] = useState(false);
  const [dictSize, setDictSize] = useState(1800);
  const [dryRun, setDryRun] = useState(false);

  useEffect(() => {
    if (!rootDomains.includes(domain)) {
      setDomain(rootDomains[0] ?? "");
    }
  }, [rootDomains, domain]);

  const rows = useMemo(() => {
    return (data ?? []).filter((item) => matchesProjectDomain(item.rootDomain, rootDomains));
  }, [data, rootDomains]);

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!domain.trim()) {
      return;
    }

    await createJob.mutateAsync({
      domain: domain.trim(),
      mode,
      modules: ["subs", "ports", "witness"],
      enableNuclei,
      activeSubs,
      dictSize,
      dryRun
    });
  };

  return (
    <section className="page">
      <h1>Scan Jobs</h1>
      <p className="page-subtitle">Launch and track pipeline jobs under the selected workspace scope.</p>

      <ProjectScopeBanner
        title="Job Scope"
        hint="Create job will target one root domain from this project. Back-end API integration remains unchanged."
      />

      <form className="panel form-grid" onSubmit={onSubmit}>
        <label>
          Root Domain
          <select value={domain} onChange={(e) => setDomain(e.target.value)} disabled={rootDomains.length === 0}>
            {rootDomains.map((root) => (
              <option key={root} value={root}>
                {root}
              </option>
            ))}
          </select>
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
            min={300}
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
          Enable active subdomain brute
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
          Dry run
        </label>
        <button type="submit" disabled={createJob.isPending || rootDomains.length === 0}>
          {createJob.isPending ? "Creating..." : "Create Job"}
        </button>
      </form>

      {rootDomains.length === 0 ? (
        <p className="empty-state">Active project has no roots. Create or edit roots in Projects page first.</p>
      ) : null}

      <article className="panel">
        <header className="panel-header">
          <h2>Job List</h2>
          <span>{rows.length} scoped records</span>
        </header>
        {isLoading ? <p className="empty-state">Loading jobs...</p> : null}
        {error ? <p className="empty-state">Failed to load jobs.</p> : null}
        {!isLoading && !error ? <DataTable data={rows} columns={columns} /> : null}
      </article>
    </section>
  );
}
