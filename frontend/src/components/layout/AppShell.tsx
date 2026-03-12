import { NavLink, Outlet } from "react-router-dom";
import { useWorkspace } from "../../context/WorkspaceContext";

const navItems = [
  { to: "/", label: "Overview", code: "OVR" },
  { to: "/projects", label: "Projects", code: "PRJ" },
  { to: "/jobs", label: "Jobs", code: "JOB" },
  { to: "/assets", label: "Assets", code: "AST" },
  { to: "/ports", label: "Ports", code: "PRT" },
  { to: "/findings", label: "Findings", code: "VUL" },
  { to: "/monitoring", label: "Monitoring", code: "MON" }
];

export function AppShell() {
  const { projects, activeProject, setActiveProject } = useWorkspace();

  return (
    <div className="app-root">
      <header className="topbar">
        <div className="topbar-main">
          <div className="brand">
            <span className="brand-mark">MYRECON::OPS</span>
            <span className="brand-text">Recon Mission Console</span>
          </div>
          <div className="topbar-controls">
            <label className="project-picker">
              <span>Workspace</span>
              <select
                value={activeProject?.id ?? ""}
                onChange={(event) => setActiveProject(event.target.value)}
                aria-label="Select active project"
              >
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </label>
            <div className="topbar-meta">
              <span className="live-dot" />
              <span>Realtime Polling</span>
              <span className="mono-subtle">5s / 10s / 20s</span>
            </div>
          </div>
        </div>
        <p className="topbar-hint">
          Project-scoped recon workflow: passive subdomain collection, optional active expansion, service mapping,
          vulnerability triage, and monitor delta tracking.
        </p>
        <div className="pipeline-strip">
          <span className="pipeline-chip">passive subs</span>
          <span className="pipeline-sep">-&gt;</span>
          <span className="pipeline-chip">dictgen</span>
          <span className="pipeline-sep">-&gt;</span>
          <span className="pipeline-chip">active brute</span>
          <span className="pipeline-sep">-&gt;</span>
          <span className="pipeline-chip">ports/services</span>
          <span className="pipeline-sep">-&gt;</span>
          <span className="pipeline-chip danger">nuclei</span>
          <span className="pipeline-sep">-&gt;</span>
          <span className="pipeline-chip">monitor</span>
        </div>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <section className="sidebar-block workspace-mini">
            <h4 className="sidebar-title">Active Workspace</h4>
            <strong>{activeProject?.name ?? "No project"}</strong>
            <p className="sidebar-note">{activeProject?.description || "Create project and set root domains."}</p>
            <div className="sidebar-roots">
              {(activeProject?.rootDomains ?? []).slice(0, 4).map((root) => (
                <span key={root}>{root}</span>
              ))}
            </div>
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
            <div className="tiny-label">Pipeline Scope</div>
            <div className="tiny-value">{activeProject?.rootDomains.length ?? 0} root domains in current project</div>
          </section>
        </aside>

        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
