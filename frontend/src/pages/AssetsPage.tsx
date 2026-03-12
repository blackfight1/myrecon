import { createColumnHelper } from "@tanstack/react-table";
import { DataTable } from "../components/ui/DataTable";
import { useAssets } from "../hooks/queries";
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

export function AssetsPage() {
  const { data, isLoading, error } = useAssets();
  const rows = data ?? [];

  return (
    <section className="page">
      <h1>Assets</h1>
      <p className="page-subtitle">Mapped from assets table. Focus on live URLs, titles, and technology fingerprints.</p>
      <article className="panel">
        <header className="panel-header">
          <h2>Asset Inventory</h2>
          <span>{rows.length} records</span>
        </header>
        {isLoading ? <p className="empty-state">Loading assets...</p> : null}
        {error ? <p className="empty-state">Failed to load assets.</p> : null}
        {!isLoading && !error ? <DataTable data={rows} columns={columns} /> : null}
      </article>
    </section>
  );
}
