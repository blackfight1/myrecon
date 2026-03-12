import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { useWorkspace } from "../context/WorkspaceContext";
import { useAssets } from "../hooks/queries";
import { matchesProjectDomain } from "../lib/projectScope";
import type { Asset } from "../types/models";
import { formatDate, joinList } from "../lib/format";

const col = createColumnHelper<Asset>();

const columns = [
  col.accessor("domain", { header: "Domain" }),
  col.accessor("url", { header: "URL", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("ip", { header: "IP", cell: (c) => c.getValue() ? <span className="cell-mono">{c.getValue()}</span> : <span className="cell-muted">—</span> }),
  col.accessor("statusCode", { header: "Status", cell: (c) => { const v = c.getValue(); if (!v) return <span className="cell-muted">—</span>; const cls = v >= 200 && v < 300 ? "badge badge-success" : v >= 400 ? "badge badge-danger" : "badge badge-warning"; return <span className={cls}>{v}</span>; } }),
  col.accessor("title", { header: "Title", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("technologies", { header: "Tech Stack", cell: (c) => joinList(c.getValue(), " · ") || <span className="cell-muted">—</span> }),
  col.accessor("lastSeen", { header: "Last Seen", cell: (c) => formatDate(c.getValue()) })
];

function hostnameFromUrl(input?: string): string | undefined {
  if (!input) return undefined;
  try { return new URL(input).hostname; } catch { return undefined; }
}

export function AssetsPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];
  const { data, isLoading, error } = useAssets();
  const [search, setSearch] = useState("");
  const [liveOnly, setLiveOnly] = useState(false);

  const scoped = useMemo(() => {
    return (data ?? []).filter((a) =>
      matchesProjectDomain(a.domain, rootDomains) || matchesProjectDomain(hostnameFromUrl(a.url), rootDomains)
    );
  }, [data, rootDomains]);

  const rows = useMemo(() => {
    return scoped.filter((a) => {
      if (liveOnly && (!a.statusCode || a.statusCode <= 0)) return false;
      if (!search.trim()) return true;
      const q = search.trim().toLowerCase();
      return (
        a.domain.toLowerCase().includes(q) || (a.url ?? "").toLowerCase().includes(q) ||
        (a.ip ?? "").toLowerCase().includes(q) || (a.title ?? "").toLowerCase().includes(q) ||
        (a.technologies ?? []).join(",").toLowerCase().includes(q)
      );
    });
  }, [scoped, liveOnly, search]);

  const liveCount = useMemo(() => scoped.filter((a) => a.statusCode != null && a.statusCode > 0).length, [scoped]);

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">Assets</h1>
        <p className="page-desc">Project-scoped web asset inventory with response status and technology stack details.</p>
      </div>

      <ProjectScopeBanner title="Asset Scope" hint="Filtered by root domain suffix matching." />

      <article className="panel">
        <header className="panel-header">
          <h2>Filters</h2>
          <span className="panel-meta">live: {liveCount} / total: {scoped.length}</span>
        </header>
        <div className="filter-bar">
          <input
            className="form-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search domain, URL, IP, title, tech..."
          />
          <label className="form-check">
            <input type="checkbox" checked={liveOnly} onChange={(e) => setLiveOnly(e.target.checked)} />
            Live only
          </label>
          <span className="filter-summary">{rows.length} matched</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Asset Inventory</h2>
          <span className="panel-meta">{rows.length} records</span>
        </header>
        {isLoading && <div className="empty-state">Loading assets...</div>}
        {error && <div className="empty-state">Failed to load assets.</div>}
        {!isLoading && !error && <DataTable data={rows} columns={columns} />}
      </article>
    </section>
  );
}
