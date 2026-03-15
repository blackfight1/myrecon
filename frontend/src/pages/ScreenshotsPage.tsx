import { useEffect, useMemo, useState } from "react";
import { useWorkspace } from "../context/WorkspaceContext";
import { useScreenshotDomains, useScreenshots } from "../hooks/queries";
import type { ScreenshotItem } from "../types/models";

export function ScreenshotsPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;

  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [lightboxUrl, setLightboxUrl] = useState<string | null>(null);

  useEffect(() => {
    setSelectedDomain("");
    setSearchTerm("");
    setFilterStatus("all");
    setLightboxUrl(null);
  }, [projectId]);

  const domainsQ = useScreenshotDomains(projectId);
  const domains = domainsQ.data ?? [];

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

  const filtered: ScreenshotItem[] = useMemo(() => {
    return screenshots.filter((s) => {
      if (filterStatus !== "all") {
        const code = s.statusCode ?? 0;
        if (filterStatus === "2xx" && (code < 200 || code >= 300)) return false;
        if (filterStatus === "3xx" && (code < 300 || code >= 400)) return false;
        if (filterStatus === "4xx" && (code < 400 || code >= 500)) return false;
        if (filterStatus === "5xx" && (code < 500 || code >= 600)) return false;
      }

      const q = searchTerm.trim().toLowerCase();
      if (!q) return true;
      const matchURL = (s.url ?? "").toLowerCase().includes(q);
      const matchTitle = (s.title ?? "").toLowerCase().includes(q);
      return matchURL || matchTitle;
    });
  }, [screenshots, filterStatus, searchTerm]);

  const totalScreenshots = useMemo(
    () => domains.reduce((sum, d) => sum + d.screenshotCount, 0),
    [domains]
  );

  const statusCodeClass = (code?: number) => {
    if (!code) return "badge-neutral";
    if (code >= 200 && code < 300) return "badge-success";
    if (code >= 300 && code < 400) return "badge-info";
    if (code >= 400 && code < 500) return "badge-warning";
    return "badge-danger";
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">截图浏览</h1>
        <p className="page-desc">按项目范围浏览 Web 截图资产，支持状态码与关键词筛选。</p>
      </div>

      {!projectId && (
        <div className="empty-state">未选择项目，截图请求已禁用。</div>
      )}

      <div className="stats-row">
        <div className="stat-card">
          <div className="stat-label">截图总数</div>
          <div className="stat-value">{totalScreenshots}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">域名数</div>
          <div className="stat-value">{domains.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">当前展示</div>
          <div className="stat-value">{filtered.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">当前域名</div>
          <div className="stat-value" style={{ fontSize: 14 }}>
            {selectedDomain || "—"}
          </div>
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
              暂无截图数据。请运行包含 `witness` 模块的扫描任务。
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
            <h2>截图画廊 · {selectedDomain}</h2>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <select
                className="form-select"
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                style={{ width: 100 }}
              >
                <option value="all">全部</option>
                <option value="2xx">2xx</option>
                <option value="3xx">3xx</option>
                <option value="4xx">4xx</option>
                <option value="5xx">5xx</option>
              </select>
              <input
                className="form-input"
                placeholder="搜索 URL 或标题..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ width: 220 }}
              />
              <button
                className={`btn btn-sm${viewMode === "grid" ? " btn-active" : ""}`}
                onClick={() => setViewMode("grid")}
              >
                网格
              </button>
              <button
                className={`btn btn-sm${viewMode === "list" ? " btn-active" : ""}`}
                onClick={() => setViewMode("list")}
              >
                列表
              </button>
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
              <div className="empty-state">
                <div className="empty-icon">🔍</div>
                没有符合筛选条件的截图。
              </div>
            </div>
          )}

          {!screenshotsQ.isLoading && !screenshotsQ.isError && filtered.length > 0 && viewMode === "grid" && (
            <div className="screenshot-grid">
              {filtered.map((s) => (
                <div
                  key={s.id}
                  className="screenshot-card"
                  onClick={() => setLightboxUrl(s.fullUrl)}
                >
                  <div className="screenshot-thumb">
                    <img
                      src={s.thumbnailUrl}
                      alt={s.title || s.url}
                      loading="lazy"
                    />
                    {s.statusCode && (
                      <span className={`screenshot-status badge ${statusCodeClass(s.statusCode)}`}>
                        {s.statusCode}
                      </span>
                    )}
                  </div>
                  <div className="screenshot-info">
                    <div className="screenshot-url" title={s.url}>
                      {s.url}
                    </div>
                    {s.title && (
                      <div className="screenshot-title">{s.title}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {!screenshotsQ.isLoading && !screenshotsQ.isError && filtered.length > 0 && viewMode === "list" && (
            <div className="panel-body-flush">
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>预览</th>
                      <th>URL</th>
                      <th>标题</th>
                      <th>状态码</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((s) => (
                      <tr key={s.id}>
                        <td>
                          <img
                            src={s.thumbnailUrl}
                            alt=""
                            className="screenshot-list-thumb"
                            onClick={() => setLightboxUrl(s.fullUrl)}
                          />
                        </td>
                        <td className="cell-mono">{s.url}</td>
                        <td>{s.title || "—"}</td>
                        <td>
                          <span className={`badge ${statusCodeClass(s.statusCode)}`}>
                            {s.statusCode ?? "—"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </article>
      )}

      {lightboxUrl && (
        <div className="lightbox-overlay" onClick={() => setLightboxUrl(null)}>
          <div className="lightbox-content" onClick={(e) => e.stopPropagation()}>
            <button className="lightbox-close" onClick={() => setLightboxUrl(null)}>x</button>
            <img src={lightboxUrl} alt="截图预览" />
          </div>
        </div>
      )}
    </section>
  );
}
