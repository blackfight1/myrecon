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
  col.accessor("domain", { header: "域名", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("ip", { header: "IP", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
  col.accessor("port", { header: "端口", cell: (c) => <span className="cell-mono">{c.getValue()}</span> }),
  col.accessor("protocol", { header: "协议", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("service", { header: "服务", cell: (c) => c.getValue() ? <span className="badge badge-info">{c.getValue()}</span> : <span className="cell-muted">—</span> }),
  col.accessor("version", { header: "版本", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  col.accessor("lastSeen", { header: "最后发现", cell: (c) => formatDate(c.getValue()) })
];

function hostnameFromUrl(input?: string): string | undefined {
  if (!input) return undefined;
  try { return new URL(input).hostname; } catch { return undefined; }
}

export function PortsPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];
  const ports = usePorts(projectId);
  const assets = useAssets(projectId);

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
        <h1 className="page-title">端口扫描</h1>
        <p className="page-desc">按项目根域名和关联资产 IP 筛选的服务暴露记录。</p>
      </div>

      <ProjectScopeBanner title="端口范围" hint="无域名的端口记录在其 IP 属于项目资产时也会被包含。" />

      <article className="panel">
        <header className="panel-header">
          <h2>开放端口记录</h2>
          <span className="panel-meta">{rows.length} 条记录</span>
        </header>
        {ports.isLoading && <div className="empty-state">正在加载端口数据...</div>}
        {ports.isError && <div className="empty-state">加载端口数据失败。</div>}
        {!ports.isLoading && !ports.isError && <DataTable data={rows} columns={columns} />}
      </article>
    </section>
  );
}
