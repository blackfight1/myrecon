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
    header: "严重等级",
    cell: (c) => {
      const s = (c.getValue() || "unknown").toLowerCase();
      return <span className={`severity-chip severity-${s}`}>{s.toUpperCase()}</span>;
    }
  }),
  col.accessor("rootDomain", { header: "根域名", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("templateId", { header: "模板 ID", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
  col.accessor("cve", { header: "CVE", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("domain", { header: "域名", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("url", { header: "URL", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("matchedAt", { header: "匹配时间", cell: (c) => formatDate(c.getValue()) }),
  col.accessor("fingerprint", { header: "指纹", cell: (c) => <span className="cell-mono">{c.getValue()}</span> })
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
        <h1 className="page-title">漏洞发现</h1>
        <p className="page-desc">基于项目范围的 Nuclei 漏洞分类，支持按严重等级和指纹搜索。</p>
      </div>

      <ProjectScopeBanner title="漏洞范围" hint="优先匹配 root_domain，然后回退到 host/domain/url 后缀匹配。" />

      <div className="stats-row">
        <div className="stat-card accent-danger"><div className="stat-label">严重</div><div className="stat-value">{sevCounts.critical}</div></div>
        <div className="stat-card accent-warning"><div className="stat-label">高危</div><div className="stat-value">{sevCounts.high}</div></div>
        <div className="stat-card"><div className="stat-label">中危</div><div className="stat-value">{sevCounts.medium}</div></div>
        <div className="stat-card accent-success"><div className="stat-label">低危</div><div className="stat-value">{sevCounts.low}</div></div>
        <div className="stat-card"><div className="stat-label">未知</div><div className="stat-value">{sevCounts.unknown}</div></div>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>筛选条件</h2>
          <span className="panel-meta">共 {scoped.length} 条</span>
        </header>
        <div className="filter-bar">
          <select className="form-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">全部等级</option>
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
            <option value="unknown">未知</option>
          </select>
          <input className="form-input" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="搜索根域名/域名/模板/CVE/URL/指纹..." />
          <span className="filter-summary">匹配 {rows.length} 条</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>漏洞记录</h2>
          <span className="panel-meta">{rows.length} 条记录</span>
        </header>
        {isLoading && <div className="empty-state">正在加载漏洞数据...</div>}
        {error && <div className="empty-state">加载漏洞数据失败。</div>}
        {!isLoading && !error && <DataTable data={rows} columns={columns} />}
      </article>
    </section>
  );
}
