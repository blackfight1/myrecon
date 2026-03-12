import { useState } from "react";
import { useWorkspace } from "../context/WorkspaceContext";
import { formatDate } from "../lib/format";

export function ProjectsPage() {
  const { projects, activeProject, setActiveProject, createProject, updateProject, deleteProject } = useWorkspace();

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rootDomainsRaw, setRootDomainsRaw] = useState("");
  const [tagsRaw, setTagsRaw] = useState("");

  const handleCreate = () => {
    if (!name.trim() || !rootDomainsRaw.trim()) return;
    createProject({
      name: name.trim(),
      description: description.trim() || undefined,
      rootDomainsRaw: rootDomainsRaw.trim(),
      tagsRaw: tagsRaw.trim() || undefined
    });
    setName("");
    setDescription("");
    setRootDomainsRaw("");
    setTagsRaw("");
    setShowForm(false);
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">Projects</h1>
        <p className="page-desc">Manage project scopes. The active project filters all pipeline views across the application.</p>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>Project Registry</h2>
          <button className="btn btn-sm" onClick={() => setShowForm(!showForm)}>
            {showForm ? "Cancel" : "+ New Project"}
          </button>
        </header>

        {showForm && (
          <div className="form-section">
            <div className="form-group">
              <label className="form-label">Name</label>
              <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. ACME Corp" />
            </div>
            <div className="form-group">
              <label className="form-label">Description</label>
              <input className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional description" />
            </div>
            <div className="form-group">
              <label className="form-label">Root Domains (comma or newline separated)</label>
              <textarea className="form-input" value={rootDomainsRaw} onChange={(e) => setRootDomainsRaw(e.target.value)} placeholder="example.com, example.org" rows={3} />
            </div>
            <div className="form-group">
              <label className="form-label">Tags (comma separated)</label>
              <input className="form-input" value={tagsRaw} onChange={(e) => setTagsRaw(e.target.value)} placeholder="bug-bounty, client" />
            </div>
            <button className="btn" onClick={handleCreate} disabled={!name.trim() || !rootDomainsRaw.trim()}>
              Create Project
            </button>
          </div>
        )}

        {projects.length === 0 && !showForm && (
          <div className="empty-state">No projects yet. Create one to start scoping your recon pipeline.</div>
        )}

        <div className="project-grid">
          {projects.map((p) => {
            const isActive = activeProject?.id === p.id;
            return (
              <div key={p.id} className={`project-card ${isActive ? "project-card-active" : ""}`}>
                <div className="project-card-header">
                  <h3>{p.name}</h3>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button className={`btn btn-sm ${isActive ? "btn-active" : ""}`} onClick={() => setActiveProject(p.id)}>
                      {isActive ? "✓ Active" : "Set Active"}
                    </button>
                    {projects.length > 1 && (
                      <button className="btn btn-sm btn-danger" onClick={() => deleteProject(p.id)}>✕</button>
                    )}
                  </div>
                </div>
                {p.description && <p className="project-card-desc">{p.description}</p>}
                <div className="project-card-meta">
                  <div>
                    <strong>Roots:</strong>{" "}
                    {p.rootDomains.map((d) => (
                      <span key={d} className="badge badge-info">{d}</span>
                    ))}
                  </div>
                  {p.tags.length > 0 && (
                    <div>
                      <strong>Tags:</strong>{" "}
                      {p.tags.map((t) => (
                        <span key={t} className="badge">{t}</span>
                      ))}
                    </div>
                  )}
                  <div className="project-card-dates">
                    <span>Created: {formatDate(p.createdAt)}</span>
                    {p.lastScanAt && <span>Last Scan: {formatDate(p.lastScanAt)}</span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </article>
    </section>
  );
}
