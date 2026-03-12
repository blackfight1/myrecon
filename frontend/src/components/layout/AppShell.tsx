import { NavLink, Outlet } from "react-router-dom";

const navItems = [
  { to: "/", label: "Overview", code: "OVR" },
  { to: "/jobs", label: "Jobs", code: "JOB" },
  { to: "/assets", label: "Assets", code: "AST" },
  { to: "/ports", label: "Ports", code: "PRT" },
  { to: "/findings", label: "Findings", code: "VUL" },
  { to: "/monitoring", label: "Monitoring", code: "MON" }
];

export function AppShell() {
  return (
    <div className="app-root">
      <header className="topbar">
        <div className="topbar-main">
          <div className="brand">
            <span className="brand-mark">MYRECON::OPS</span>
            <span className="brand-text">Recon Command Grid</span>
          </div>
          <div className="topbar-meta">
            <span className="live-dot" />
            <span>Realtime Polling</span>
            <span className="mono-subtle">10s / 20s</span>
          </div>
        </div>
        <p className="topbar-hint">
          Passive discovery, active expansion, service exposure, vulnerability triage, and monitor deltas in one dark
          console.
        </p>
        <div className="pipeline-strip">
          <span className="pipeline-chip">subs</span>
          <span className="pipeline-sep">-&gt;</span>
          <span className="pipeline-chip">ports</span>
          <span className="pipeline-sep">-&gt;</span>
          <span className="pipeline-chip">witness</span>
          <span className="pipeline-sep">-&gt;</span>
          <span className="pipeline-chip danger">nuclei</span>
          <span className="pipeline-sep">-&gt;</span>
          <span className="pipeline-chip">monitor</span>
        </div>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <section className="sidebar-block">
            <h4 className="sidebar-title">Control Surface</h4>
            <p className="sidebar-note">Switch views by pipeline stage. Every panel maps to your DB-backed workflow.</p>
          </section>
          <nav>
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
              >
                <span className="nav-code">{item.code}</span>
                <span>{item.label}</span>
              </NavLink>
            ))}
          </nav>
          <section className="sidebar-block sidebar-foot">
            <div className="tiny-label">Data Source</div>
            <div className="tiny-value">PostgreSQL + local recon tools</div>
          </section>
        </aside>

        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
