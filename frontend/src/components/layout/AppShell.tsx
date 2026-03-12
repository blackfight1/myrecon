import { NavLink, Outlet } from "react-router-dom";
import { useTheme } from "../../context/ThemeContext";
import { useWorkspace } from "../../context/WorkspaceContext";

export function AppShell() {
  const { projects, activeProject, setActiveProject } = useWorkspace();
  const { theme, themes, setTheme } = useTheme();

  return (
    <div className="app-root">
      {/* ── Topbar ── */}
      <header className="topbar">
        <div className="topbar-left">
          <div className="brand">
            <div className="brand-icon">MR</div>
            <span className="brand-name">MyRecon</span>
          </div>
          <div className="topbar-divider" />
          <div className="topbar-project-select">
            <span className="topbar-project-label">Project</span>
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
            <span>Online</span>
          </div>
        </div>
      </header>

      {/* ── Body ── */}
      <div className="layout">
        {/* ── Sidebar ── */}
        <aside className="sidebar">
          <nav className="sidebar-nav">
            <div className="nav-section-title">Overview</div>
            <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
              <span className="nav-icon">◈</span> Dashboard
            </NavLink>

            <div className="nav-section-title">Discovery</div>
            <NavLink to="/assets" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
              <span className="nav-icon">◎</span> Assets
            </NavLink>
            <NavLink to="/ports" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
              <span className="nav-icon">⊞</span> Ports
            </NavLink>
            <NavLink to="/findings" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
              <span className="nav-icon">⚑</span> Findings
            </NavLink>
            <NavLink to="/screenshots" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
              <span className="nav-icon">⎔</span> Screenshots
            </NavLink>

            <div className="nav-section-title">Operations</div>
            <NavLink to="/jobs" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
              <span className="nav-icon">▷</span> Jobs
            </NavLink>
            <NavLink to="/monitoring" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
              <span className="nav-icon">◉</span> Monitoring
            </NavLink>

            <div className="nav-section-title">Settings</div>
            <NavLink to="/projects" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
              <span className="nav-icon">⊟</span> Projects
            </NavLink>
            <NavLink to="/settings" className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
              <span className="nav-icon">⚙</span> Settings
            </NavLink>
          </nav>

          {activeProject && (
            <div className="sidebar-footer">
              <div className="sidebar-project-info">
                <div className="info-label">Active Scope</div>
                <div className="info-name">{activeProject.name}</div>
                <div className="sidebar-roots-list">
                  {activeProject.rootDomains.map((d) => (
                    <span key={d} className="root-tag">{d}</span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </aside>

        {/* ── Main Content ── */}
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
