import { NavLink, Outlet } from "react-router-dom";

const navItems = [
  { to: "/", label: "Dashboard" },
  { to: "/jobs", label: "Jobs" },
  { to: "/assets", label: "Assets" },
  { to: "/ports", label: "Ports" },
  { to: "/findings", label: "Findings" },
  { to: "/monitoring", label: "Monitoring" }
];

export function AppShell() {
  return (
    <div className="app-root">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">MYRECON</span>
          <span className="brand-text">Recon Command Console</span>
        </div>
        <p className="topbar-hint">
          Passive discovery, active expansion, service exposure, and vulnerability triage in one view.
        </p>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <nav>
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </aside>

        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
