import { createColumnHelper } from "@tanstack/react-table";
import { useMemo } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { useWorkspace } from "../context/WorkspaceContext";
import { useAssets, usePorts } from "../hooks/queries";
import { formatDate } from "../lib/format";
import { matchesProjectDomain } from "../lib/projectScope";
import type { PortRecord } from "../types/models";

const helper = createColumnHelper<PortRecord>();

const columns = [
  helper.accessor("domain", { header: "Domain", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("ip", { header: "IP" }),
  helper.accessor("port", { header: "Port" }),
  helper.accessor("protocol", { header: "Proto", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("service", { header: "Service", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("version", { header: "Version", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("lastSeen", { header: "Last Seen", cell: (ctx) => formatDate(ctx.getValue()) })
];

function hostnameFromUrl(input?: string): string | undefined {
  if (!input) {
    return undefined;
  }
  try {
    return new URL(input).hostname;
  } catch {
    return undefined;
  }
}

export function PortsPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];
  const ports = usePorts();
  const assets = useAssets();

  const scopedAssetIps = useMemo(() => {
    return new Set(
      (assets.data ?? [])
        .filter(
          (item) =>
            matchesProjectDomain(item.domain, rootDomains) ||
            matchesProjectDomain(hostnameFromUrl(item.url), rootDomains)
        )
        .map((item) => item.ip)
        .filter(Boolean)
    );
  }, [assets.data, rootDomains]);

  const rows = useMemo(() => {
    return (ports.data ?? []).filter((item) => {
      if (matchesProjectDomain(item.domain, rootDomains)) {
        return true;
      }
      if (item.ip && scopedAssetIps.has(item.ip)) {
        return true;
      }
      return false;
    });
  }, [ports.data, rootDomains, scopedAssetIps]);

  return (
    <section className="page">
      <h1>Ports</h1>
      <p className="page-subtitle">Service exposure records scoped by project roots and correlated asset IPs.</p>

      <ProjectScopeBanner title="Port Scope" hint="Port rows without domain are included when IP belongs to scoped assets." />

      <article className="panel">
        <header className="panel-header">
          <h2>Open Port Records</h2>
          <span>{rows.length} records</span>
        </header>
        {ports.isLoading ? <p className="empty-state">Loading ports...</p> : null}
        {ports.isError ? <p className="empty-state">Failed to load ports.</p> : null}
        {!ports.isLoading && !ports.isError ? <DataTable data={rows} columns={columns} /> : null}
      </article>
    </section>
  );
}
