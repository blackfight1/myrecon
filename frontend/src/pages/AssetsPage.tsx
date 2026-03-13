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
  col.accessor("domain", { header: "域名" }),
  col.accessor("url", { header: "URL", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("ip", { header: "IP", cell: (c) => c.getValue() ? <span className="cell-mono">{c.getValue()}</span> : <span className="cell-muted">—</span> }),
  col.accessor("statusCode", { header: "状态码", cell: (c) => { const v = c.getValue(); if (!v) return <span className="cell-muted">—</span>; const cls = v >= 200 && v < 300 ? "badge badge-success" : v >= 400 ? "badge badge-danger" : "badge badge-warning"; return <span className={cls}>{v}</span>; } }),
  col.accessor("title", { header: "标题", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("technologies", { header: "技术栈", cell: (c) => joinList(c.getValue(), " · ") || <span className="cell-muted">—</span> }),
  col.accessor("lastSeen", { header: "最后发现", cell: (c) => formatDate(c.getValue()) })
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
        <h1 className="page-title">资产管理</h1>
        <p className="page-desc">项目范围内的 Web 资产清单，包含响应状态和技术栈详情。</p>
      </div>

      <ProjectScopeBanner title="资产范围" hint="按根域名后缀匹配过滤。" />

      <article className="panel">
        <header className="panel-header">
          <h2>筛选条件</h2>
          <span className="panel-meta">存活: {liveCount} / 总计: {scoped.length}</span>
        </header>
        <div className="filter-bar">
          <input
            className="form-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索域名、URL、IP、标题、技术栈..."
          />
          <label className="form-check">
            <input type="checkbox" checked={liveOnly} onChange={(e) => setLiveOnly(e.target.checked)} />
            仅显示存活
          </label>
          <span className="filter-summary">匹配 {rows.length} 条</span>
        </div>
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>资产清单</h2>
          <span className="panel-meta">{rows.length} 条记录</span>
        </header>
        {isLoading && <div className="empty-state">正在加载资产数据...</div>}
        {error && <div className="empty-state">加载资产失败。</div>}
        {!isLoading && !error && <DataTable data={rows} columns={columns} />}
      </article>
    </section>
  );
}
