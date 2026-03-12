import { createColumnHelper } from "@tanstack/react-table";
import { DataTable } from "../components/ui/DataTable";
import { useVulns } from "../hooks/queries";
import type { VulnerabilityRecord } from "../types/models";
import { formatDate } from "../lib/format";

const helper = createColumnHelper<VulnerabilityRecord>();

const columns = [
  helper.accessor("severity", { header: "Severity", cell: (ctx) => (ctx.getValue() || "unknown").toUpperCase() }),
  helper.accessor("templateId", { header: "Template ID" }),
  helper.accessor("cve", { header: "CVE", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("domain", { header: "Domain", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("url", { header: "URL", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("matchedAt", { header: "Matched At", cell: (ctx) => formatDate(ctx.getValue()) }),
  helper.accessor("fingerprint", { header: "Fingerprint" })
];

export function FindingsPage() {
  const { data, isLoading, error } = useVulns();
  const rows = data ?? [];

  return (
    <section className="page">
      <h1>Findings</h1>
      <p className="page-subtitle">Nuclei candidates from vulnerabilities table. Use this page for triage and verification.</p>
      <article className="panel">
        <header className="panel-header">
          <h2>Vulnerability Candidates</h2>
          <span>{rows.length} records</span>
        </header>
        {isLoading ? <p className="empty-state">Loading findings...</p> : null}
        {error ? <p className="empty-state">Failed to load findings.</p> : null}
        {!isLoading && !error ? <DataTable data={rows} columns={columns} /> : null}
      </article>
    </section>
  );
}
