import { useState } from "react";
import { useWorkspace } from "../context/WorkspaceContext";
import { errorMessage } from "../lib/errors";
import { formatDate } from "../lib/format";
import type { ProjectRecord } from "../types/models";

export function ProjectsPage() {
  const { projects, activeProject, setActiveProject, createProject, updateProject, deleteProject, loading } = useWorkspace();

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rootDomainsRaw, setRootDomainsRaw] = useState("");
  const [tagsRaw, setTagsRaw] = useState("");

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editDomains, setEditDomains] = useState("");
  const [editTags, setEditTags] = useState("");

  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const startEdit = (p: ProjectRecord) => {
    setFeedback(null);
    setEditingId(p.id);
    setEditName(p.name);
    setEditDesc(p.description ?? "");
    setEditDomains(p.rootDomains.join(", "));
    setEditTags(p.tags.join(", "));
  };

  const saveEdit = async () => {
    if (!editingId || !editName.trim() || !editDomains.trim() || busy) return;
    setBusy(true);
    setFeedback(null);
    try {
      await updateProject(editingId, {
        name: editName.trim(),
        description: editDesc.trim() || undefined,
        rootDomainsRaw: editDomains.trim(),
        tagsRaw: editTags.trim() || undefined
      });
      setEditingId(null);
      setFeedback({ ok: true, text: "项目已更新" });
    } catch (err) {
      setFeedback({ ok: false, text: `更新失败：${errorMessage(err)}` });
    } finally {
      setBusy(false);
    }
  };

  const cancelEdit = () => {
    setEditingId(null);
    setFeedback(null);
  };

  const handleCreate = async () => {
    if (!name.trim() || !rootDomainsRaw.trim() || busy) return;
    setBusy(true);
    setFeedback(null);
    try {
      await createProject({
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
      setFeedback({ ok: true, text: "项目创建成功" });
    } catch (err) {
      setFeedback({ ok: false, text: `创建失败：${errorMessage(err)}` });
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (p: ProjectRecord) => {
    if (busy) return;
    if (!confirm(`确定要归档项目 "${p.name}" 吗？归档后项目将不再显示。`)) return;
    setBusy(true);
    setFeedback(null);
    try {
      await deleteProject(p.id);
      setFeedback({ ok: true, text: "项目已归档" });
    } catch (err) {
      setFeedback({ ok: false, text: `归档失败：${errorMessage(err)}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">项目管理</h1>
        <p className="page-desc">项目数据来自后端，项目隔离由 projectId 强制约束。</p>
      </div>

      {loading && <div className="empty-state">正在加载项目...</div>}

      {feedback && (
        <div className="empty-state" style={{ color: feedback.ok ? "#16a34a" : "#dc2626", marginBottom: 12 }}>
          {feedback.text}
        </div>
      )}

      <article className="panel">
        <header className="panel-header">
          <h2>项目列表</h2>
          <button className="btn btn-sm" onClick={() => setShowForm((v) => !v)} disabled={busy}>
            {showForm ? "取消" : "+ 新建项目"}
          </button>
        </header>

        {showForm && (
          <div className="form-section">
            <div className="form-row form-row-2">
              <div className="form-group">
                <label className="form-label">项目名称</label>
                <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="例如：Acme Corp" />
              </div>
              <div className="form-group">
                <label className="form-label">描述（可选）</label>
                <input className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="项目说明" />
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">根域名（支持逗号/中文逗号/分号/换行）</label>
              <textarea className="form-input form-textarea" value={rootDomainsRaw} onChange={(e) => setRootDomainsRaw(e.target.value)} placeholder="example.com, example.org" rows={3} />
            </div>
            <div className="form-group">
              <label className="form-label">标签（可选）</label>
              <input className="form-input" value={tagsRaw} onChange={(e) => setTagsRaw(e.target.value)} placeholder="内网, 客户项目" />
            </div>
            <div className="form-actions">
              <button className="btn" onClick={() => { void handleCreate(); }} disabled={busy || !name.trim() || !rootDomainsRaw.trim()}>
                {busy ? "创建中..." : "创建项目"}
              </button>
              <button className="btn btn-ghost" onClick={() => setShowForm(false)} disabled={busy}>
                取消
              </button>
            </div>
          </div>
        )}

        {projects.length === 0 && !showForm && !loading && (
          <div className="empty-state">
            <div className="empty-state-icon">⊟</div>
            <div className="empty-state-text">暂无项目，创建一个项目以开始侦查。</div>
          </div>
        )}

        <div className="project-grid">
          {projects.map((p) => {
            const isActive = activeProject?.id === p.id;
            return (
              <div key={p.id} className={`project-card${isActive ? " project-card-active" : ""}`}>
                {editingId === p.id ? (
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
                      <label className="form-label">根域名（支持逗号/中文逗号/分号/换行）</label>
                      <textarea className="form-input form-textarea" value={editDomains} onChange={(e) => setEditDomains(e.target.value)} rows={2} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">标签（可选）</label>
                      <input className="form-input" value={editTags} onChange={(e) => setEditTags(e.target.value)} />
                    </div>
                    <div className="form-actions">
                      <button className="btn btn-primary btn-sm" onClick={() => { void saveEdit(); }} disabled={busy || !editName.trim() || !editDomains.trim()}>保存</button>
                      <button className="btn btn-sm" onClick={cancelEdit} disabled={busy}>取消</button>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="project-card-header">
                      <h3 className="project-card-title">{p.name}</h3>
                      <div className="project-card-actions">
                        <button className="btn btn-sm" onClick={() => startEdit(p)} disabled={busy}>编辑</button>
                        <button
                          className={`btn btn-sm${isActive ? " btn-active" : ""}`}
                          onClick={() => setActiveProject(p.id)}
                          disabled={busy}
                        >
                          {isActive ? "已激活" : "设为活跃"}
                        </button>
                        {projects.length > 1 && (
                          <button className="btn btn-sm btn-danger" onClick={() => { void handleDelete(p); }} disabled={busy}>归档</button>
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
