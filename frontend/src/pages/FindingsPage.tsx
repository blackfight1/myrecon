import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { useWorkspace } from "../context/WorkspaceContext";
import { useVulns } from "../hooks/queries";
import { formatDate } from "../lib/format";
import { matchesProjectDomain } from "../lib/projectScope";
import type { VulnerabilityRecord } from "../types/models";

const col = createColumnHelper<VulnerabilityRecord>();

const columns = [
  col.accessor("severity", {
    header: "Severity",
    cell: (c) => {
      const s = (c.getValue() || "unknown").toLowerCase();
      return <span className={`severity-chip severity-${s}`}>{s.toUpperCase()}</span>;
    }
  }),
  col.accessor("rootDomain", { header: "Root", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("templateId", { header: "Template ID", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
  col.accessor("cve", { header: "CVE", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("domain", { header: "Domain", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("url", { header: "URL", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("matchedAt", { header: "Matched", cell: (c) => formatDate(c.getValue()) }),
  col.accessor("fingerprint", { header: "Fingerprint", cell: (c) => <span className="cell-mono">{c.getValue()}</span> })
];

function hostnameFromUrl(input?: string): string | undefined {
  if (!input) return undefined;
  try { return new URL(input).hostname; } catch { return undefined; }
}

export function FindingsPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];
  const { data, isLoading, error } = useVulns();
  const [severity, setSeverity] = useState("all");
  const [search, setSearch] = useState("");

  const scoped = useMemo(() => {
    return (data ?? []).filter((v) =>
      matchesProjectDomain(v.rootDomain, rootDomains) || matchesProjectDomain(v.domain, rootDomains) ||
      matchesProjectDomain(v.host, rootDomains) || matchesProjectDomain(hostnameFromUrl(v.url), rootDomains)
    );
  }, [data, rootDomains]);

  const rows = useMemo(() => {
    return scoped.filter((f) => {
      const fs = (f.severity ?? "unknown").toLowerCase();
      if (severity !== "all" && fs !== severity) return false;
      if (!search.trim()) return true;
      const q = search.trim().toLowerCase();
      return (
        (f.rootDomain ?? "").toLowerCase().includes(q) || (f.domain ?? "").toLowerCase().includes(q) ||
        (f.templateId ?? "").toLowerCase().includes(q) || (f.cve ?? "").toLowerCase().includes(q) ||
        (f.url ?? "").toLowerCase().includes(q) || f.fingerprint.toLowerCase().includes(q)
      );
    });
  }, [scoped, search, severity]);

  const sevCounts = useMemo(() => {
    const o = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (const f of scoped) {
      const k = (f.severity ?? "unknown").toLowerCase();
      if (k === "critical" || k === "high" || k === "medium" || k === "low") o[k]++;
      else o.unknown++;
    }
    return o;
  }, [scoped]);

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">Findings</h1>
        <p className="page-desc">Project-aware nuclei triage with severity classification and fingerprint search.</p>
      </div>

      <ProjectScopeBanner title="Findings Scope" hint="Matched by root_domain, then fallback to host/domain/url suffix." />

      <div className="stats-row">
        <div className="stat-card accent-danger"><div className="stat-label">Critical</div><div className="stat-value">{sevCounts.critical}</div></div>
        <div className="stat-card accent-warning"><div className="stat-label">High</div><div className="stat-value">{sevCounts.high}</div></div>
        <div className="stat-card"><div className="stat-label">Medium</div><div className="stat-value">{sevCounts.medium}</div></div>
        <div className="stat-card accent-success"><div className="stat-label">Low</div><div className="stat-value">{sevCounts.low}</div></div>
        <div className="stat-card"><div className="stat-label">Unknown</div><div className="stat-value">{sevCounts.unknown}</div></div>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>Triage Controls</h2>
          <span className="panel-meta">{scoped.length} total</span>
        </header>
        <div className="filter-bar">
          <select className="form-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">All severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="unknown">Unknown</option>
          </select>
          <input className="form-input" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search root/domain/template/CVE/url/fingerprint..." />
          <span className="filter-summary">{rows.length} matched</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Vulnerability Records</h2>
          <span className="panel-meta">{rows.length} records</span>
        </header>
        {isLoading && <div className="empty-state">Loading findings...</div>}
        {error && <div className="empty-state">Failed to load findings.</div>}
        {!isLoading && !error && <DataTable data={rows} columns={columns} />}
      </article>
    </section>
  );
}
