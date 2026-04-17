import { useEffect, useMemo, useState } from "react";
import { useWorkspace } from "../context/WorkspaceContext";
import { useScreenshotDomains, useScreenshots } from "../hooks/queries";
import { formatDate } from "../lib/format";
import type { ScreenshotItem } from "../types/models";
import { getToken } from "../api/client";

function statusCodeClass(code?: number) {
  if (!code) return "badge-neutral";
  if (code >= 200 && code < 300) return "badge-success";
  if (code >= 300 && code < 400) return "badge-info";
  if (code >= 400 && code < 500) return "badge-warning";
  return "badge-danger";
}

function normalizeText(v?: string): string {
  return (v ?? "").trim();
}

function withAuthToken(rawUrl?: string | null): string {
  const token = getToken();
  if (!rawUrl || !token) return rawUrl ?? "";
  try {
    const u = new URL(rawUrl, window.location.origin);
    if (!u.searchParams.has("token")) {
      u.searchParams.set("token", token);
    }
    return `${u.pathname}${u.search}${u.hash}`;
  } catch {
    const sep = rawUrl.includes("?") ? "&" : "?";
    return `${rawUrl}${sep}token=${encodeURIComponent(token)}`;
  }
}

export function ScreenshotsPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;

  const [selectedDomain, setSelectedDomain] = useState("");
  const [viewMode, setViewMode] = useState<"list" | "grid">("list");
  const [filterStatus, setFilterStatus] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [mappedOnly, setMappedOnly] = useState(true);
  const [lightboxUrl, setLightboxUrl] = useState<string | null>(null);

  const domainsQ = useScreenshotDomains(projectId);
  const domains = domainsQ.data ?? [];

  useEffect(() => {
    setSelectedDomain("");
    setSearchTerm("");
    setFilterStatus("all");
    setMappedOnly(true);
    setLightboxUrl(null);
  }, [projectId]);

  useEffect(() => {
    if (!selectedDomain && domains.length > 0) {
      setSelectedDomain(domains[0].rootDomain);
      return;
    }
    if (selectedDomain && !domains.some((d) => d.rootDomain === selectedDomain)) {
      setSelectedDomain(domains[0]?.rootDomain ?? "");
    }
  }, [domains, selectedDomain]);

  const screenshotsQ = useScreenshots(selectedDomain, projectId);
  const screenshots = screenshotsQ.data ?? [];

  const filtered = useMemo(() => {
    return screenshots.filter((item) => {
      const url = normalizeText(item.url);
      if (mappedOnly && !url) return false;

      if (filterStatus !== "all") {
        const code = item.statusCode ?? 0;
        if (filterStatus === "2xx" && (code < 200 || code >= 300)) return false;
        if (filterStatus === "3xx" && (code < 300 || code >= 400)) return false;
        if (filterStatus === "4xx" && (code < 400 || code >= 500)) return false;
        if (filterStatus === "5xx" && (code < 500 || code >= 600)) return false;
      }

      const q = searchTerm.trim().toLowerCase();
      if (!q) return true;
      const haystack = `${url} ${normalizeText(item.title)} ${normalizeText(item.filename)}`.toLowerCase();
      return haystack.includes(q);
    });
  }, [screenshots, mappedOnly, filterStatus, searchTerm]);

  const mappedCount = useMemo(
    () => screenshots.filter((item) => normalizeText(item.url) !== "").length,
    [screenshots]
  );

  const totalScreenshots = useMemo(
    () => domains.reduce((sum, d) => sum + d.screenshotCount, 0),
    [domains]
  );

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">截图浏览</h1>
        <p className="page-desc">按 URL 与截图进行匹配展示，方便定位具体资产页面。</p>
      </div>

      {!projectId && <div className="empty-state">未选择项目，截图请求已禁用。</div>}

      <div className="stats-row">
        <div className="stat-card">
          <div className="stat-label">截图总数</div>
          <div className="stat-value">{totalScreenshots}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">根域名数</div>
          <div className="stat-value">{domains.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">当前域名截图</div>
          <div className="stat-value">{screenshots.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">已关联 URL</div>
          <div className="stat-value">{mappedCount}</div>
        </div>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>域名列表</h2>
          <span className="panel-meta">{domains.length} 个域名有截图</span>
        </header>
        <div className="panel-body">
          {domainsQ.isLoading && <div className="empty-state">正在加载域名列表...</div>}
          {domainsQ.isError && <div className="empty-state">加载域名列表失败。</div>}
          {!domainsQ.isLoading && !domainsQ.isError && domains.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">📷</div>
              暂无截图数据，请先运行包含 `witness` 模块的任务。
            </div>
          )}
          {!domainsQ.isLoading && !domainsQ.isError && domains.length > 0 && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {domains.map((d) => (
                <button
                  key={d.rootDomain}
                  className={`btn btn-sm${selectedDomain === d.rootDomain ? " btn-active" : ""}`}
                  onClick={() => setSelectedDomain(d.rootDomain)}
                >
                  {d.rootDomain}
                  <span className="nav-badge">{d.screenshotCount}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </article>

      {selectedDomain && (
        <article className="panel">
          <header className="panel-header">
            <h2>URL + 截图映射 · {selectedDomain}</h2>
            <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
              <select className="form-select" value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} style={{ width: 110 }}>
                <option value="all">全部状态</option>
                <option value="2xx">2xx</option>
                <option value="3xx">3xx</option>
                <option value="4xx">4xx</option>
                <option value="5xx">5xx</option>
              </select>
              <input
                className="form-input"
                placeholder="搜索 URL / 标题 / 文件名"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ width: 240 }}
              />
              <button className={`btn btn-sm${mappedOnly ? " btn-primary" : ""}`} onClick={() => setMappedOnly((v) => !v)}>
                仅显示已关联 URL
              </button>
              <button className={`btn btn-sm${viewMode === "list" ? " btn-active" : ""}`} onClick={() => setViewMode("list")}>列表</button>
              <button className={`btn btn-sm${viewMode === "grid" ? " btn-active" : ""}`} onClick={() => setViewMode("grid")}>网格</button>
            </div>
          </header>

          {screenshotsQ.isLoading && (
            <div className="panel-body">
              <div className="empty-state">正在加载截图...</div>
            </div>
          )}

          {screenshotsQ.isError && (
            <div className="panel-body">
              <div className="empty-state">加载截图失败。</div>
            </div>
          )}

          {!screenshotsQ.isLoading && !screenshotsQ.isError && filtered.length === 0 && (
            <div className="panel-body">
              <div className="empty-state">没有符合条件的数据。</div>
            </div>
          )}

          {!screenshotsQ.isLoading && !screenshotsQ.isError && filtered.length > 0 && viewMode === "list" && (
            <div className="panel-body-flush">
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>URL</th>
                      <th>截图</th>
                      <th>标题</th>
                      <th>状态码</th>
                      <th>时间</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((item: ScreenshotItem) => (
                      <tr key={item.id}>
                        <td className="cell-mono" style={{ maxWidth: 520 }} title={item.url || item.filename}>
                          {normalizeText(item.url) || <span className="cell-muted">(未记录 URL)</span>}
                        </td>
                        <td>
                          <img
                            src={withAuthToken(item.thumbnailUrl)}
                            alt={item.title || item.url || item.filename}
                            className="screenshot-list-thumb"
                            onClick={() => setLightboxUrl(withAuthToken(item.fullUrl))}
                          />
                        </td>
                        <td>{normalizeText(item.title) || <span className="cell-muted">-</span>}</td>
                        <td>
                          <span className={`badge ${statusCodeClass(item.statusCode)}`}>{item.statusCode ?? "-"}</span>
                        </td>
                        <td>{formatDate(item.createdAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {!screenshotsQ.isLoading && !screenshotsQ.isError && filtered.length > 0 && viewMode === "grid" && (
            <div className="screenshot-grid">
              {filtered.map((item) => (
                <div key={item.id} className="screenshot-card" onClick={() => setLightboxUrl(withAuthToken(item.fullUrl))}>
                  <div className="screenshot-thumb">
                    <img src={withAuthToken(item.thumbnailUrl)} alt={item.title || item.url || item.filename} loading="lazy" />
                    {item.statusCode && (
                      <span className={`screenshot-status badge ${statusCodeClass(item.statusCode)}`}>{item.statusCode}</span>
                    )}
                  </div>
                  <div className="screenshot-info">
                    <div className="screenshot-url" title={item.url || item.filename}>
                      {normalizeText(item.url) || "(未记录 URL)"}
                    </div>
                    {normalizeText(item.title) && <div className="screenshot-title">{item.title}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </article>
      )}

      {lightboxUrl && (
        <div className="lightbox-overlay" onClick={() => setLightboxUrl(null)}>
          <div className="lightbox-content" onClick={(e) => e.stopPropagation()}>
            <button className="lightbox-close" onClick={() => setLightboxUrl(null)}>x</button>
            <img src={withAuthToken(lightboxUrl)} alt="截图预览" />
          </div>
        </div>
      )}
    </section>
  );
}
