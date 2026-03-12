import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { useWorkspace } from "../context/WorkspaceContext";
import { useAssets } from "../hooks/queries";
import { matchesProjectDomain } from "../lib/projectScope";
import type { Asset } from "../types/models";
import { formatDate, joinList } from "../lib/format";

const helper = createColumnHelper<Asset>();

const columns = [
  helper.accessor("domain", { header: "Domain" }),
  helper.accessor("url", { header: "URL", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("ip", { header: "IP", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("statusCode", { header: "Status", cell: (ctx) => ctx.getValue() ?? "-" }),
  helper.accessor("title", { header: "Title", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("technologies", { header: "Technologies", cell: (ctx) => joinList(ctx.getValue(), " | ") }),
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

export function AssetsPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];
  const { data, isLoading, error } = useAssets();
  const [search, setSearch] = useState("");
  const [liveOnly, setLiveOnly] = useState(false);

  const scoped = useMemo(() => {
    return (data ?? []).filter((asset) => {
      return matchesProjectDomain(asset.domain, rootDomains) || matchesProjectDomain(hostnameFromUrl(asset.url), rootDomains);
    });
  }, [data, rootDomains]);

  const rows = useMemo(() => {
    return scoped.filter((asset) => {
      if (liveOnly && (!asset.statusCode || asset.statusCode <= 0)) {
        return false;
      }
      if (!search.trim()) {
        return true;
      }
      const q = search.trim().toLowerCase();
      return (
        asset.domain.toLowerCase().includes(q) ||
        (asset.url ?? "").toLowerCase().includes(q) ||
        (asset.ip ?? "").toLowerCase().includes(q) ||
        (asset.title ?? "").toLowerCase().includes(q) ||
        (asset.technologies ?? []).join(",").toLowerCase().includes(q)
      );
    });
  }, [scoped, liveOnly, search]);

  const liveCount = useMemo(
    () => scoped.filter((asset) => asset.statusCode != null && asset.statusCode > 0).length,
    [scoped]
  );

  return (
    <section className="page">
      <h1>Asset Surface</h1>
      <p className="page-subtitle">Project-scoped web asset inventory with response and stack details.</p>

      <ProjectScopeBanner title="Asset Scope" hint="Asset table is filtered by root domain suffix matching." />

      <article className="panel control-panel">
        <header className="panel-header">
          <h2>Asset Filters</h2>
          <span>
            live: {liveCount} / total: {scoped.length}
          </span>
        </header>
        <div className="filters-row">
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search domain, URL, IP, title, technology..."
          />
          <label className="checkbox">
            <input type="checkbox" checked={liveOnly} onChange={(event) => setLiveOnly(event.target.checked)} />
            Live only
          </label>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Asset Inventory</h2>
          <span>{rows.length} records matched</span>
        </header>
        {isLoading ? <p className="empty-state">Loading assets...</p> : null}
        {error ? <p className="empty-state">Failed to load assets.</p> : null}
        {!isLoading && !error ? <DataTable data={rows} columns={columns} /> : null}
      </article>
    </section>
  );
}
