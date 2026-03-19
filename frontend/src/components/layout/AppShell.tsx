import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { Breadcrumb } from "../ui/Breadcrumb";
import { useTheme } from "../../context/ThemeContext";
import { useWorkspace } from "../../context/WorkspaceContext";
import { useAuth } from "../../context/AuthContext";
import { GlobalSearch } from "../ui/GlobalSearch";

export function AppShell() {
  const { projects, activeProject, setActiveProject, loading } = useWorkspace();
  const { theme, themes, setTheme } = useTheme();
  const { username, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="app-root">
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
          <NavLink to="/quick-scan" className={({ isActive }) => `nav-link nav-link-quick${isActive ? " active" : ""}`}>
            <span className="nav-icon">✦</span> 快速扫描
          </NavLink>
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
            <div className="sidebar-avatar">{(username || "A").charAt(0).toUpperCase()}</div>
            <div className="sidebar-user-info">
              <div className="sidebar-user-name">{username || "admin"}</div>
              <div className="sidebar-user-role">管理员</div>
            </div>
            <button className="sidebar-logout-btn" title="退出登录" onClick={logout}>
              ⏻
            </button>
          </div>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <div className="topbar-project-select">
              <select
                value={activeProject?.id ?? ""}
                onChange={(e) => setActiveProject(e.target.value)}
                disabled={loading || projects.length === 0}
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="topbar-center" style={{ flex: 1, display: "flex", justifyContent: "center", padding: "0 16px" }}>
            <GlobalSearch />
          </div>
          <div className="topbar-right">
            <button className="topbar-btn topbar-btn-neon" onClick={() => navigate("/quick-scan")}>
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

        <main className="content">
          <Breadcrumb />
          <Outlet />
        </main>
      </div>
    </div>
  );
}
