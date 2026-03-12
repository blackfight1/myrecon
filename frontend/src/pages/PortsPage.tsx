import { createColumnHelper } from "@tanstack/react-table";
import { useMemo } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { useWorkspace } from "../context/WorkspaceContext";
import { useAssets, usePorts } from "../hooks/queries";
import { formatDate } from "../lib/format";
import { matchesProjectDomain } from "../lib/projectScope";
import type { PortRecord } from "../types/models";

const col = createColumnHelper<PortRecord>();

const columns = [
  col.accessor("domain", { header: "Domain", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("ip", { header: "IP", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
  col.accessor("port", { header: "Port", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
  col.accessor("protocol", { header: "Proto", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("service", { header: "Service", cell: (c) => c.getValue() ? <span className="badge badge-info">{c.getValue()}</span> : <span className="cell-muted">—</span> }),
  col.accessor("version", { header: "Version", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("lastSeen", { header: "Last Seen", cell: (c) => formatDate(c.getValue()) })
];

function hostnameFromUrl(input?: string): string | undefined {
  if (!input) return undefined;
  try { return new URL(input).hostname; } catch { return undefined; }
}

export function PortsPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];
  const ports = usePorts();
  const assets = useAssets();

  const scopedAssetIps = useMemo(() => {
    return new Set(
      (assets.data ?? [])
        .filter((a) => matchesProjectDomain(a.domain, rootDomains) || matchesProjectDomain(hostnameFromUrl(a.url), rootDomains))
        .map((a) => a.ip)
        .filter(Boolean)
    );
  }, [assets.data, rootDomains]);

  const rows = useMemo(() => {
    return (ports.data ?? []).filter((p) => matchesProjectDomain(p.domain, rootDomains) || (p.ip && scopedAssetIps.has(p.ip)));
  }, [ports.data, rootDomains, scopedAssetIps]);

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">Ports</h1>
        <p className="page-desc">Service exposure records scoped by project roots and correlated asset IPs.</p>
      </div>

      <ProjectScopeBanner title="Port Scope" hint="Port rows without domain are included when IP belongs to scoped assets." />

      <article className="panel">
        <header className="panel-header">
          <h2>Open Port Records</h2>
          <span className="panel-meta">{rows.length} records</span>
        </header>
        {ports.isLoading && <div className="empty-state">Loading ports...</div>}
        {ports.isError && <div className="empty-state">Failed to load ports.</div>}
        {!ports.isLoading && !ports.isError && <DataTable data={rows} columns={columns} />}
      </article>
    </section>
  );
}
