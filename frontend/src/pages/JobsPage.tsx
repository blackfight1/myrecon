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
  col.accessor("rootDomain", { header: "Root Domain" }),
  col.accessor("modules", { header: "Modules", cell: (c) => (c.getValue() ?? []).join(", ") || <span className="cell-muted">—</span> }),
  col.accessor("status", { header: "Status", cell: (c) => <StatusBadge status={c.getValue()} /> }),
  col.accessor("startedAt", { header: "Started", cell: (c) => formatDate(c.getValue()) }),
  col.accessor("finishedAt", { header: "Finished", cell: (c) => formatDate(c.getValue()) }),
  col.accessor("durationSec", { header: "Duration", cell: (c) => { const v = c.getValue(); return v != null ? `${v}s` : <span className="cell-muted">—</span>; } }),
  col.accessor("errorMessage", { header: "Error", cell: (c) => c.getValue() ? <span style={{ color: "var(--color-danger)", fontSize: 12 }}>{c.getValue()}</span> : <span className="cell-muted">—</span> })
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
        <h1 className="page-title">Jobs</h1>
        <p className="page-desc">Pipeline execution history and quick-launch controls for active project scope.</p>
      </div>

      <ProjectScopeBanner title="Job Scope" hint="Only jobs whose root_domain matches project scope." />

      <article className="panel">
        <header className="panel-header">
          <h2>Quick Launch</h2>
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
          <h2>Filters</h2>
          <span className="panel-meta">{scoped.length} total</span>
        </header>
        <div className="filter-bar">
          <select className="form-select" value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="running">Running</option>
            <option value="success">Success</option>
            <option value="failed">Failed</option>
          </select>
          <button className="btn btn-sm" onClick={() => refetch()}>Refresh</button>
          <span className="filter-summary">{rows.length} matched</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Job History</h2>
          <span className="panel-meta">{rows.length} records</span>
        </header>
        {isLoading && <div className="empty-state">Loading jobs...</div>}
        {error && <div className="empty-state">Failed to load jobs.</div>}
        {!isLoading && !error && <DataTable data={rows} columns={columns} />}
      </article>
    </section>
  );
}
