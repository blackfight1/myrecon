import { NavLink, Outlet } from "react-router-dom";
import { useTheme } from "../../context/ThemeContext";
import { useWorkspace } from "../../context/WorkspaceContext";

export function AppShell() {
  const { projects, activeProject, setActiveProject } = useWorkspace();
  const { theme, themes, setTheme } = useTheme();

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
            <button className="topbar-btn topbar-btn-scan">⚡ 快速扫描</button>
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
    </div>
  );
}
