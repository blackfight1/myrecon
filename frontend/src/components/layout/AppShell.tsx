import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useTheme } from "../../context/ThemeContext";
import { useWorkspace } from "../../context/WorkspaceContext";
import { useCreateJob } from "../../hooks/queries";

const BASELINE_MODULES = ["subs", "httpx", "ports"];

export function AppShell() {
  const { projects, activeProject, setActiveProject } = useWorkspace();
  const { theme, themes, setTheme } = useTheme();
  const createJob = useCreateJob();

  const [showScanModal, setShowScanModal] = useState(false);
  const [scanDomain, setScanDomain] = useState("");
  const [enableWitness, setEnableWitness] = useState(false);
  const [enableNuclei, setEnableNuclei] = useState(false);
  const [scanSubmitting, setScanSubmitting] = useState(false);

  const handleQuickScan = async () => {
    const domain = scanDomain.trim();
    if (!domain) return;
    const modules = [...BASELINE_MODULES];
    if (enableWitness) modules.push("witness");
    if (enableNuclei) modules.push("nuclei");

    setScanSubmitting(true);
    try {
      await createJob.mutateAsync({
        domain,
        modules,
        mode: "scan",
        enableNuclei,
        activeSubs: false,
        dictSize: 1500,
        dryRun: false,
      });
      setShowScanModal(false);
      setScanDomain("");
    } catch (e) {
      console.error("Scan failed:", e);
    } finally {
      setScanSubmitting(false);
    }
  };

  const previewModules = [...BASELINE_MODULES, ...(enableWitness ? ["witness"] : []), ...(enableNuclei ? ["nuclei"] : [])];

  return (
    <div className="app-root">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">MR</div>
          <span className="brand-name">MyRecon</span>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-title">主要功能</div>
          <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <span className="nav-icon">◈</span> 仪表盘
          </NavLink>
          <NavLink to="/assets" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <span className="nav-icon">◎</span> 资产
          </NavLink>
          <NavLink to="/ports" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <span className="nav-icon">⊞</span> 端口
          </NavLink>
          <NavLink to="/findings" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <span className="nav-icon">⚑</span> 漏洞
          </NavLink>
          <NavLink to="/screenshots" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <span className="nav-icon">⎔</span> 截图
          </NavLink>

          <div className="nav-section-title">扫描</div>
          <NavLink to="/jobs" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <span className="nav-icon">▷</span> 扫描任务
          </NavLink>
          <NavLink to="/monitoring" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <span className="nav-icon">◉</span> 监控
          </NavLink>

          <div className="nav-section-title">系统设置</div>
          <NavLink to="/projects" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <span className="nav-icon">⊟</span> 项目管理
          </NavLink>
          <NavLink to="/settings" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <span className="nav-icon">⚙</span> 系统设置
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user">
            <div className="sidebar-avatar">A</div>
            <div className="sidebar-user-info">
              <div className="sidebar-user-name">admin</div>
              <div className="sidebar-user-role">管理员</div>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main Area ── */}
      <div className="main-area">
        {/* ── Topbar ── */}
        <header className="topbar">
          <div className="topbar-left">
            <div className="topbar-project-select">
              <select
                value={activeProject?.id ?? ""}
                onChange={(e) => setActiveProject(e.target.value)}
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="topbar-right">
            <button
              className="topbar-btn topbar-btn-scan"
              onClick={() => {
                setScanDomain(activeProject?.rootDomains?.[0] ?? "");
                setEnableWitness(false);
                setEnableNuclei(false);
                setShowScanModal(true);
              }}
            >
              ✦ 快速扫描
            </button>
            <div className="topbar-divider" />
            <div className="theme-switcher">
              {themes.map((t) => (
                <button
                  key={t.id}
                  className={`theme-btn${theme === t.id ? " active" : ""}`}
                  data-theme={t.id}
                  title={t.label}
                  onClick={() => setTheme(t.id)}
                />
              ))}
            </div>
            <div className="topbar-divider" />
            <div className="topbar-status">
              <span className="status-dot" />
              <span>在线</span>
            </div>
          </div>
        </header>

        {/* ── Content ── */}
        <main className="content">
          <Outlet />
        </main>
      </div>

      {/* ── Quick Scan Modal ── */}
      {showScanModal && (
        <div className="modal-overlay" onClick={() => setShowScanModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>✦ 快速扫描</h3>
              <button className="modal-close" onClick={() => setShowScanModal(false)}>✕</button>
            </div>
            <div className="modal-body">
              <label className="form-label">目标域名</label>
              <input
                className="form-input"
                type="text"
                placeholder="example.com"
                value={scanDomain}
                onChange={(e) => setScanDomain(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleQuickScan()}
              />
              <label className="form-label" style={{ marginTop: 16 }}>基础流程（固定）</label>
              <div className="module-grid">
                <span className="module-chip active">Passive Subs</span>
                <span className="module-chip active">Web Probe</span>
                <span className="module-chip active">Port Scan</span>
              </div>
              <label className="form-label" style={{ marginTop: 16 }}>可选阶段</label>
              <div className="module-grid">
                <label className={`module-chip${enableWitness ? " active" : ""}`}>
                  <input type="checkbox" checked={enableWitness} onChange={(e) => setEnableWitness(e.target.checked)} style={{ display: "none" }} />
                  Screenshot
                </label>
                <label className={`module-chip${enableNuclei ? " active" : ""}`}>
                  <input type="checkbox" checked={enableNuclei} onChange={(e) => setEnableNuclei(e.target.checked)} style={{ display: "none" }} />
                  Vulnerability
                </label>
              </div>
              <div className="panel-meta" style={{ marginTop: 12 }}>
                执行流程：{previewModules.join(" -> ")}
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowScanModal(false)}>取消</button>
              <button className="btn btn-primary" onClick={handleQuickScan} disabled={scanSubmitting || !scanDomain.trim()}>
                {scanSubmitting ? "提交中..." : "开始扫描"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
