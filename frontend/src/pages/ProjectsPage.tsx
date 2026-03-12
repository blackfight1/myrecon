import { useMemo, useState } from "react";
import { useWorkspace } from "../context/WorkspaceContext";
import { parseDomainList } from "../lib/projectScope";
import { useAssets, useJobs, useVulns } from "../hooks/queries";

function includesRoot(value: string | undefined, roots: string[]): boolean {
  if (!value || roots.length === 0) {
    return false;
  }
  const domain = value.toLowerCase();
  return roots.some((root) => domain === root || domain.endsWith(`.${root}`));
}

export function ProjectsPage() {
  const { projects, activeProject, setActiveProject, createProject, updateProject, deleteProject } = useWorkspace();
  const jobs = useJobs();
  const assets = useAssets();
  const vulns = useVulns();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [domainsRaw, setDomainsRaw] = useState("");
  const [tagsRaw, setTagsRaw] = useState("");

  const [editProjectId, setEditProjectId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editDomainsRaw, setEditDomainsRaw] = useState("");
  const [editTagsRaw, setEditTagsRaw] = useState("");

  const projectStats = useMemo(() => {
    const jobsList = jobs.data ?? [];
    const assetsList = assets.data ?? [];
    const vulnsList = vulns.data ?? [];

    return projects.map((project) => {
      const roots = project.rootDomains;
      const jobsCount = jobsList.filter((item) => includesRoot(item.rootDomain, roots)).length;
      const assetsCount = assetsList.filter((item) => includesRoot(item.domain, roots)).length;
      const vulnsCount = vulnsList.filter((item) => includesRoot(item.rootDomain ?? item.domain, roots)).length;
      return {
        id: project.id,
        jobsCount,
        assetsCount,
        vulnsCount
      };
    });
  }, [projects, jobs.data, assets.data, vulns.data]);

  const onCreate = (event: React.FormEvent) => {
    event.preventDefault();
    if (!name.trim()) {
      return;
    }
    const domains = parseDomainList(domainsRaw);
    if (domains.length === 0) {
      return;
    }

    createProject({
      name,
      description,
      rootDomainsRaw: domainsRaw,
      tagsRaw
    });

    setName("");
    setDescription("");
    setDomainsRaw("");
    setTagsRaw("");
  };

  const openEdit = (projectId: string) => {
    const item = projects.find((project) => project.id === projectId);
    if (!item) {
      return;
    }
    setEditProjectId(projectId);
    setEditName(item.name);
    setEditDescription(item.description ?? "");
    setEditDomainsRaw(item.rootDomains.join("\n"));
    setEditTagsRaw(item.tags.join(", "));
  };

  const submitEdit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!editProjectId) {
      return;
    }
    if (!editName.trim()) {
      return;
    }
    if (parseDomainList(editDomainsRaw).length === 0) {
      return;
    }

    updateProject(editProjectId, {
      name: editName,
      description: editDescription,
      rootDomainsRaw: editDomainsRaw,
      tagsRaw: editTagsRaw
    });
    setEditProjectId(null);
  };

  const onDelete = (projectId: string, projectName: string) => {
    if (projects.length <= 1) {
      return;
    }
    const confirmed = window.confirm(`Delete project "${projectName}"? This only removes local workspace data.`);
    if (!confirmed) {
      return;
    }
    if (editProjectId === projectId) {
      setEditProjectId(null);
    }
    deleteProject(projectId);
  };

  return (
    <section className="page">
      <h1>Projects</h1>
      <p className="page-subtitle">
        Build recon workspaces by root domain scope. All pipeline pages can be viewed per project before backend API
        integration.
      </p>

      <div className="workspace-grid">
        <article className="panel panel-flat">
          <header className="panel-header">
            <h2>Create Project</h2>
            <span>{projects.length} total</span>
          </header>
          <form className="form-grid project-form" onSubmit={onCreate}>
            <label>
              Project Name
              <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Bugcrowd Program" />
            </label>
            <label>
              Tags
              <input
                value={tagsRaw}
                onChange={(event) => setTagsRaw(event.target.value)}
                placeholder="bugbounty, external, p1"
              />
            </label>
            <label className="span-2">
              Description
              <input
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="Scope, notes, operator handoff"
              />
            </label>
            <label className="span-2">
              Root Domains
              <textarea
                value={domainsRaw}
                onChange={(event) => setDomainsRaw(event.target.value)}
                placeholder={"example.com\nexample.org"}
                rows={5}
              />
            </label>
            <button type="submit" className="btn btn-neon btn-pill">
              Create Project
            </button>
          </form>
        </article>

        <article className="panel panel-flat">
          <header className="panel-header">
            <h2>Active Project</h2>
            <span>{activeProject?.name ?? "none"}</span>
          </header>
          {activeProject ? (
            <div className="project-active-box">
              <div className="project-active-header">
                <strong>{activeProject.name}</strong>
                <span className="status-chip">{activeProject.rootDomains.length} roots</span>
              </div>
              <p>{activeProject.description || "No description."}</p>
              <div className="tag-row">
                {activeProject.tags.length > 0 ? activeProject.tags.map((tag) => <span key={tag}>#{tag}</span>) : <span>#untagged</span>}
              </div>
              <small>Updated: {new Date(activeProject.updatedAt).toLocaleString()}</small>
            </div>
          ) : (
            <p className="empty-state">No active project.</p>
          )}
        </article>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>Workspace Catalog</h2>
          <span>Switch/edit project scopes</span>
        </header>

        <div className="project-cards">
          {projects.map((project) => {
            const stats = projectStats.find((item) => item.id === project.id);
            const isEditing = editProjectId === project.id;

            return (
              <section key={project.id} className={project.id === activeProject?.id ? "project-card active" : "project-card"}>
                <div className="project-card-head">
                  <div>
                    <strong>{project.name}</strong>
                    <p>{project.description || "No description."}</p>
                  </div>
                  <div className="project-card-actions">
                    <button type="button" className="btn btn-ghost" onClick={() => setActiveProject(project.id)}>
                      {project.id === activeProject?.id ? "In Use" : "Switch"}
                    </button>
                    <button type="button" className="btn btn-ghost" onClick={() => openEdit(project.id)}>
                      Edit
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger"
                      onClick={() => onDelete(project.id, project.name)}
                      disabled={projects.length <= 1}
                      title={projects.length <= 1 ? "At least one project must remain." : "Delete this project"}
                    >
                      Delete
                    </button>
                  </div>
                </div>

                <div className="project-metrics">
                  <span>Roots: {project.rootDomains.length}</span>
                  <span>Jobs: {stats?.jobsCount ?? 0}</span>
                  <span>Assets: {stats?.assetsCount ?? 0}</span>
                  <span>Findings: {stats?.vulnsCount ?? 0}</span>
                </div>

                <div className="project-domain-list mono-subtle">{project.rootDomains.join("  |  ")}</div>

                {isEditing ? (
                  <form className="edit-project-form" onSubmit={submitEdit}>
                    <label>
                      Project Name
                      <input value={editName} onChange={(event) => setEditName(event.target.value)} placeholder="Workspace name" />
                    </label>
                    <label>
                      Description
                      <input
                        value={editDescription}
                        onChange={(event) => setEditDescription(event.target.value)}
                        placeholder="Update notes"
                      />
                    </label>
                    <label>
                      Root Domains
                      <textarea
                        rows={4}
                        value={editDomainsRaw}
                        onChange={(event) => setEditDomainsRaw(event.target.value)}
                        placeholder={"example.com\nexample.net"}
                      />
                    </label>
                    <label>
                      Tags
                      <input
                        value={editTagsRaw}
                        onChange={(event) => setEditTagsRaw(event.target.value)}
                        placeholder="critical, monitor"
                      />
                    </label>
                    <div className="edit-actions">
                      <button type="submit" className="btn btn-neon">
                        Save
                      </button>
                      <button type="button" className="btn btn-neutral" onClick={() => setEditProjectId(null)}>
                        Cancel
                      </button>
                    </div>
                  </form>
                ) : null}
              </section>
            );
          })}
        </div>
      </article>
    </section>
  );
}
