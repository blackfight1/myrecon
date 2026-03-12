import { createColumnHelper } from "@tanstack/react-table";
import { DataTable } from "../components/ui/DataTable";
import { usePorts } from "../hooks/queries";
import type { PortRecord } from "../types/models";
import { formatDate } from "../lib/format";

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

export function PortsPage() {
  const { data, isLoading, error } = usePorts();
  const rows = data ?? [];

  return (
    <section className="page">
      <h1>Ports</h1>
      <p className="page-subtitle">Mapped from ports table, useful for exposure drift and service change review.</p>
      <article className="panel">
        <header className="panel-header">
          <h2>Open Port Records</h2>
          <span>{rows.length} records</span>
        </header>
        {isLoading ? <p className="empty-state">Loading ports...</p> : null}
        {error ? <p className="empty-state">Failed to load ports.</p> : null}
        {!isLoading && !error ? <DataTable data={rows} columns={columns} /> : null}
      </article>
    </section>
  );
}
