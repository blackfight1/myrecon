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

  // 编辑状态
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editDomains, setEditDomains] = useState("");
  const [editTags, setEditTags] = useState("");

  const startEdit = (p: typeof projects[0]) => {
    setEditingId(p.id);
    setEditName(p.name);
    setEditDesc(p.description ?? "");
    setEditDomains(p.rootDomains.join(", "));
    setEditTags(p.tags.join(", "));
  };

  const saveEdit = () => {
    if (!editingId || !editName.trim() || !editDomains.trim()) return;
    updateProject(editingId, {
      name: editName.trim(),
      description: editDesc.trim() || undefined,
      rootDomainsRaw: editDomains.trim(),
      tagsRaw: editTags.trim() || undefined,
    });
    setEditingId(null);
  };

  const cancelEdit = () => setEditingId(null);

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
        <h1 className="page-title">项目管理</h1>
        <p className="page-desc">管理项目范围，当前激活的项目会筛选所有页面中的数据展示。</p>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>项目列表</h2>
          <button className="btn btn-sm" onClick={() => setShowForm(!showForm)}>
            {showForm ? "取消" : "+ 新建项目"}
          </button>
        </header>

        {showForm && (
          <div className="form-section">
            <div className="form-row form-row-2">
              <div className="form-group">
                <label className="form-label">项目名称</label>
                <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="例如：XX公司" />
              </div>
              <div className="form-group">
                <label className="form-label">描述（可选）</label>
                <input className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="项目描述信息" />
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">根域名（逗号或换行分隔）</label>
              <textarea className="form-input form-textarea" value={rootDomainsRaw} onChange={(e) => setRootDomainsRaw(e.target.value)} placeholder="example.com, example.org" rows={3} />
            </div>
            <div className="form-group">
              <label className="form-label">标签（逗号分隔，可选）</label>
              <input className="form-input" value={tagsRaw} onChange={(e) => setTagsRaw(e.target.value)} placeholder="漏洞赏金, 客户项目" />
            </div>
            <div className="form-actions">
              <button className="btn" onClick={handleCreate} disabled={!name.trim() || !rootDomainsRaw.trim()}>
                创建项目
              </button>
              <button className="btn btn-ghost" onClick={() => setShowForm(false)}>
                取消
              </button>
            </div>
          </div>
        )}

        {projects.length === 0 && !showForm && (
          <div className="empty-state">
            <div className="empty-state-icon">⊟</div>
            <div className="empty-state-text">暂无项目，创建一个项目以开始您的侦察工作。</div>
          </div>
        )}

        <div className="project-grid">
          {projects.map((p) => {
            const isActive = activeProject?.id === p.id;
            return (
              <div key={p.id} className={`project-card${isActive ? " project-card-active" : ""}`}>
                {editingId === p.id ? (
                  /* 编辑模式 */
                  <div className="form-section" style={{ margin: 0, padding: 0, border: "none" }}>
                    <div className="form-group">
                      <label className="form-label">项目名称</label>
                      <input className="form-input" value={editName} onChange={(e) => setEditName(e.target.value)} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">描述</label>
                      <input className="form-input" value={editDesc} onChange={(e) => setEditDesc(e.target.value)} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">根域名（逗号分隔）</label>
                      <textarea className="form-input form-textarea" value={editDomains} onChange={(e) => setEditDomains(e.target.value)} rows={2} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">标签（逗号分隔）</label>
                      <input className="form-input" value={editTags} onChange={(e) => setEditTags(e.target.value)} />
                    </div>
                    <div className="form-actions">
                      <button className="btn btn-primary btn-sm" onClick={saveEdit} disabled={!editName.trim() || !editDomains.trim()}>保存</button>
                      <button className="btn btn-sm" onClick={cancelEdit}>取消</button>
                    </div>
                  </div>
                ) : (
                  /* 展示模式 */
                  <>
                    <div className="project-card-header">
                      <h3 className="project-card-title">{p.name}</h3>
                      <div className="project-card-actions">
                        <button className="btn btn-sm" onClick={() => startEdit(p)}>编辑</button>
                        <button
                          className={`btn btn-sm${isActive ? " btn-active" : ""}`}
                          onClick={() => setActiveProject(p.id)}
                        >
                          {isActive ? "✓ 已激活" : "设为活跃"}
                        </button>
                        {projects.length > 1 && (
                          <button className="btn btn-sm btn-danger" onClick={() => { if (confirm(`确定要删除项目"${p.name}"吗？`)) deleteProject(p.id); }}>删除</button>
                        )}
                      </div>
                    </div>

                    {p.description && <p className="project-card-desc">{p.description}</p>}

                    <div className="project-card-meta">
                      <div className="project-card-field">
                        <span className="project-card-label">根域名</span>
                        <div className="project-card-badges">
                          {p.rootDomains.map((d) => (
                            <span key={d} className="badge badge-info">{d}</span>
                          ))}
                        </div>
                      </div>

                      {p.tags.length > 0 && (
                        <div className="project-card-field">
                          <span className="project-card-label">标签</span>
                          <div className="project-card-badges">
                            {p.tags.map((t) => (
                              <span key={t} className="badge">{t}</span>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="project-card-dates">
                        <span>创建时间：{formatDate(p.createdAt)}</span>
                        {p.lastScanAt && <span>上次扫描：{formatDate(p.lastScanAt)}</span>}
                      </div>
                    </div>
                  </>
                )}
              </div>
            );
          })}
        </div>
      </article>
    </section>
  );
}
