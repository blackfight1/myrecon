import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useTheme } from "../../context/ThemeContext";
import { useWorkspace } from "../../context/WorkspaceContext";
import { useCreateJob } from "../../hooks/queries";

const ALL_MODULES = [
  { id: "subfinder", label: "Subfinder" },
  { id: "findomain", label: "Findomain" },
  { id: "bbot", label: "BBOT" },
  { id: "dictgen", label: "Dictgen" },
  { id: "dnsx_bruteforce", label: "DNSX暴破" },
  { id: "naabu", label: "Naabu" },
  { id: "nmap", label: "Nmap" },
  { id: "httpx", label: "HTTPX" },
  { id: "nuclei", label: "Nuclei" },
  { id: "gowitness", label: "Gowitness" },
];

export function AppShell() {
  const { projects, activeProject, setActiveProject } = useWorkspace();
  const { theme, themes, setTheme } = useTheme();
  const createJob = useCreateJob();

  const [showScanModal, setShowScanModal] = useState(false);
  const [scanDomain, setScanDomain] = useState("");
  const [scanModules, setScanModules] = useState<string[]>(["subfinder", "findomain", "httpx"]);
  const [scanSubmitting, setScanSubmitting] = useState(false);

  const toggleModule = (id: string) => {
    setScanModules((prev) => prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]);
  };

  const handleQuickScan = async () => {
    const domain = scanDomain.trim();
    if (!domain || scanModules.length === 0) return;
    setScanSubmitting(true);
    try {
      await createJob.mutateAsync({ domain, modules: scanModules, mode: "scan" });
      setShowScanModal(false);
      setScanDomain("");
    } catch (e) {
      console.error("Scan failed:", e);
    } finally {
      setScanSubmitting(false);
    }
  };

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
            <button className="topbar-btn topbar-btn-scan" onClick={() => { setScanDomain(activeProject?.rootDomains?.[0] ?? ""); setShowScanModal(true); }}>✦ 快速扫描</button>
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
              <label className="form-label" style={{ marginTop: 16 }}>选择模块</label>
              <div className="module-grid">
                {ALL_MODULES.map((m) => (
                  <label key={m.id} className={`module-chip${scanModules.includes(m.id) ? " active" : ""}`}>
                    <input type="checkbox" checked={scanModules.includes(m.id)} onChange={() => toggleModule(m.id)} style={{ display: "none" }} />
                    {m.label}
                  </label>
                ))}
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowScanModal(false)}>取消</button>
              <button className="btn btn-primary" onClick={handleQuickScan} disabled={scanSubmitting || !scanDomain.trim() || scanModules.length === 0}>
                {scanSubmitting ? "提交中..." : "开始扫描"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
