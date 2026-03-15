import { useParams, useNavigate } from "react-router-dom";
import { useWorkspace } from "../context/WorkspaceContext";
import { useAssetDetail } from "../hooks/queries";
import { formatDate } from "../lib/format";

export function AssetDetailPage() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { activeProject } = useWorkspace();
    const projectId = activeProject?.id;

    const assetId = id ? parseInt(id, 10) : undefined;
    const detailQ = useAssetDetail(projectId, assetId ? { id: assetId } : undefined);
    const data = detailQ.data;
    const asset = data?.asset;
    const ports = data?.ports ?? [];
    const vulns = data?.vulns ?? [];

    const severityClass = (s?: string) => {
        switch (s?.toLowerCase()) {
            case "critical": return "badge badge-danger";
            case "high": return "badge badge-danger";
            case "medium": return "badge badge-warning";
            case "low": return "badge badge-success";
            case "info": return "badge badge-info";
            default: return "badge";
        }
    };

    const statusCodeClass = (code?: number) => {
        if (!code) return "badge";
        if (code >= 200 && code < 300) return "badge badge-success";
        if (code >= 400) return "badge badge-danger";
        return "badge badge-warning";
    };

    return (
        <section className="page">
            <div className="page-header" style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <button className="btn btn-sm" onClick={() => navigate("/assets")} style={{ marginRight: 8 }}>
                    ← 返回资产列表
                </button>
                <div>
                    <h1 className="page-title" style={{ marginBottom: 0 }}>
                        {asset?.domain || "资产详情"}
                    </h1>
                    <p className="page-desc" style={{ marginTop: 4 }}>
                        查看此资产的完整上下文：基本信息、关联端口和漏洞。
                    </p>
                </div>
            </div>

            {!projectId && <div className="empty-state">未选择项目。</div>}
            {detailQ.isLoading && <div className="empty-state">正在加载...</div>}
            {detailQ.error && <div className="empty-state">加载失败。</div>}

            {asset && (
                <>
                    {/* Basic Info */}
                    <article className="panel">
                        <header className="panel-header">
                            <h2>基本信息</h2>
                            {asset.statusCode ? (
                                <span className={statusCodeClass(asset.statusCode)}>HTTP {asset.statusCode}</span>
                            ) : (
                                <span className="badge">未探测</span>
                            )}
                        </header>
                        <div style={{ padding: 20 }}>
                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
                                <div>
                                    <div className="stat-label">域名</div>
                                    <div className="cell-mono" style={{ fontSize: 14 }}>{asset.domain}</div>
                                </div>
                                <div>
                                    <div className="stat-label">IP</div>
                                    <div className="cell-mono">{asset.ip || "—"}</div>
                                </div>
                                <div>
                                    <div className="stat-label">标题</div>
                                    <div>{asset.title || "—"}</div>
                                </div>
                                <div>
                                    <div className="stat-label">URL</div>
                                    <div style={{ wordBreak: "break-all", fontSize: 13 }}>
                                        {asset.url ? (
                                            <a href={asset.url} target="_blank" rel="noopener noreferrer" style={{ color: "#60a5fa" }}>
                                                {asset.url}
                                            </a>
                                        ) : "—"}
                                    </div>
                                </div>
                                <div>
                                    <div className="stat-label">技术栈</div>
                                    <div>
                                        {asset.technologies && asset.technologies.length > 0
                                            ? asset.technologies.map((t) => (
                                                <span key={t} className="summary-badge" style={{ marginRight: 4, marginBottom: 2 }}>{t}</span>
                                            ))
                                            : "—"}
                                    </div>
                                </div>
                                <div>
                                    <div className="stat-label">最后发现</div>
                                    <div className="cell-muted">{formatDate(asset.lastSeen)}</div>
                                </div>
                            </div>
                        </div>
                    </article>

                    {/* Ports */}
                    <article className="panel">
                        <header className="panel-header">
                            <h2>关联端口</h2>
                            <span className="panel-meta">{ports.length} 个端口</span>
                        </header>
                        {ports.length > 0 ? (
                            <div className="table-wrap">
                                <table className="data-table">
                                    <thead>
                                        <tr>
                                            <th>端口</th>
                                            <th>协议</th>
                                            <th>服务</th>
                                            <th>版本</th>
                                            <th>IP</th>
                                            <th>最后发现</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {ports.map((p) => (
                                            <tr key={p.id}>
                                                <td><span className="cell-mono" style={{ fontWeight: 600, color: "#60a5fa" }}>{p.port}</span></td>
                                                <td>{p.protocol || "tcp"}</td>
                                                <td>{p.service || "—"}</td>
                                                <td className="cell-muted">{p.version || "—"}</td>
                                                <td className="cell-mono">{p.ip}</td>
                                                <td className="cell-muted">{formatDate(p.lastSeen)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <div className="empty-state" style={{ padding: "30px 0" }}>
                                <div className="empty-state-icon">⊞</div>
                                <div className="empty-state-text">暂无关联端口数据</div>
                            </div>
                        )}
                    </article>

                    {/* Vulns */}
                    <article className="panel">
                        <header className="panel-header">
                            <h2>关联漏洞</h2>
                            <span className="panel-meta">{vulns.length} 个漏洞</span>
                        </header>
                        {vulns.length > 0 ? (
                            <div className="table-wrap">
                                <table className="data-table">
                                    <thead>
                                        <tr>
                                            <th>模板</th>
                                            <th>严重程度</th>
                                            <th>CVE</th>
                                            <th>状态</th>
                                            <th>匹配位置</th>
                                            <th>最后发现</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {vulns.map((v) => (
                                            <tr key={v.id}>
                                                <td>
                                                    <div style={{ fontWeight: 500 }}>{v.templateId}</div>
                                                    {v.templateName && <div className="cell-muted" style={{ fontSize: 11 }}>{v.templateName}</div>}
                                                </td>
                                                <td><span className={severityClass(v.severity)}>{v.severity || "—"}</span></td>
                                                <td className="cell-mono">{v.cve || "—"}</td>
                                                <td><span className={`status-badge ${v.status === "open" ? "running" : v.status === "fixed" ? "completed" : "pending"}`}>
                                                    <span className="status-indicator" />{v.status || "open"}
                                                </span></td>
                                                <td className="cell-muted" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={v.matchedAt}>
                                                    {v.matchedAt || "—"}
                                                </td>
                                                <td className="cell-muted">{formatDate(v.lastSeen)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <div className="empty-state" style={{ padding: "30px 0" }}>
                                <div className="empty-state-icon">⚑</div>
                                <div className="empty-state-text">暂无关联漏洞</div>
                            </div>
                        )}
                    </article>
                </>
            )}
        </section>
    );
}
