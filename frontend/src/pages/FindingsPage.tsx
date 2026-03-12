import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { DataTable } from "../components/ui/DataTable";
import { useVulns } from "../hooks/queries";
import type { VulnerabilityRecord } from "../types/models";
import { formatDate } from "../lib/format";

const helper = createColumnHelper<VulnerabilityRecord>();

const columns = [
  helper.accessor("severity", {
    header: "Severity",
    cell: (ctx) => {
      const severity = (ctx.getValue() || "unknown").toLowerCase();
      return <span className={`severity-chip severity-${severity}`}>{severity.toUpperCase()}</span>;
    }
  }),
  helper.accessor("rootDomain", { header: "Root", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("templateId", { header: "Template ID" }),
  helper.accessor("cve", { header: "CVE", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("domain", { header: "Domain", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("url", { header: "URL", cell: (ctx) => ctx.getValue() || "-" }),
  helper.accessor("matchedAt", { header: "Matched At", cell: (ctx) => formatDate(ctx.getValue()) }),
  helper.accessor("fingerprint", { header: "Fingerprint" })
];

export function FindingsPage() {
  const { data, isLoading, error } = useVulns();
  const [severity, setSeverity] = useState("all");
  const [search, setSearch] = useState("");

  const rows = useMemo(() => {
    const list = data ?? [];
    return list.filter((finding) => {
      const findingSeverity = (finding.severity ?? "unknown").toLowerCase();
      if (severity !== "all" && findingSeverity !== severity) {
        return false;
      }
      if (!search.trim()) {
        return true;
      }
      const q = search.trim().toLowerCase();
      return (
        (finding.rootDomain ?? "").toLowerCase().includes(q) ||
        (finding.domain ?? "").toLowerCase().includes(q) ||
        (finding.templateId ?? "").toLowerCase().includes(q) ||
        (finding.cve ?? "").toLowerCase().includes(q) ||
        (finding.url ?? "").toLowerCase().includes(q) ||
        finding.fingerprint.toLowerCase().includes(q)
      );
    });
  }, [data, search, severity]);

  const severityCounts = useMemo(() => {
    const output = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (const finding of data ?? []) {
      const key = (finding.severity ?? "unknown").toLowerCase();
      if (key === "critical" || key === "high" || key === "medium" || key === "low") {
        output[key] += 1;
      } else {
        output.unknown += 1;
      }
    }
    return output;
  }, [data]);

  return (
    <section className="page">
      <h1>Findings</h1>
      <p className="page-subtitle">Nuclei findings deduplicated by fingerprint and grouped by root domain.</p>
      <article className="panel control-panel">
        <header className="panel-header">
          <h2>Triage Controls</h2>
          <span>
            C:{severityCounts.critical} H:{severityCounts.high} M:{severityCounts.medium} L:{severityCounts.low} U:
            {severityCounts.unknown}
          </span>
        </header>
        <div className="filters-row">
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="all">All severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="unknown">Unknown</option>
          </select>
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search root/domain/template/CVE/url/fingerprint..."
          />
        </div>
      </article>
      <article className="panel">
        <header className="panel-header">
          <h2>Vulnerability Candidates</h2>
          <span>{rows.length} records matched</span>
        </header>
        {isLoading ? <p className="empty-state">Loading findings...</p> : null}
        {error ? <p className="empty-state">Failed to load findings.</p> : null}
        {!isLoading && !error ? <DataTable data={rows} columns={columns} /> : null}
      </article>
    </section>
  );
}
