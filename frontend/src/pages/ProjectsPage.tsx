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
  const [aiEnabled, setAIEnabled] = useState(true);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editDomains, setEditDomains] = useState("");
  const [editTags, setEditTags] = useState("");
  const [editAIEnabled, setEditAIEnabled] = useState(true);

  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [deleteCandidate, setDeleteCandidate] = useState<ProjectRecord | null>(null);
  const [deleteWithData, setDeleteWithData] = useState(false);

  const startEdit = (p: ProjectRecord) => {
    setFeedback(null);
    setEditingId(p.id);
    setEditName(p.name);
    setEditDesc(p.description ?? "");
    setEditDomains(p.rootDomains.join(", "));
    setEditTags(p.tags.join(", "));
    setEditAIEnabled(p.aiEnabled !== false);
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
        tagsRaw: editTags.trim() || undefined,
        aiEnabled: editAIEnabled
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
        tagsRaw: tagsRaw.trim() || undefined,
        aiEnabled
      });
      setName("");
      setDescription("");
      setRootDomainsRaw("");
      setTagsRaw("");
      setAIEnabled(true);
      setShowForm(false);
      setFeedback({ ok: true, text: "项目创建成功" });
    } catch (err) {
      setFeedback({ ok: false, text: `创建失败：${errorMessage(err)}` });
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = (p: ProjectRecord) => {
    if (busy) return;
    setDeleteCandidate(p);
    setDeleteWithData(false);
  };

  const closeDeleteModal = () => {
    if (busy) return;
    setDeleteCandidate(null);
    setDeleteWithData(false);
  };

  const confirmDelete = async () => {
    const target = deleteCandidate;
    if (!target || busy) return;
    setBusy(true);
    setFeedback(null);
    try {
      await deleteProject(target.id, deleteWithData);
      setFeedback({ ok: true, text: deleteWithData ? "项目及相关数据已删除" : "项目已归档" });
      setDeleteCandidate(null);
      setDeleteWithData(false);
    } catch (err) {
      setFeedback({ ok: false, text: `删除失败：${errorMessage(err)}` });
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
            <div className="form-group">
              <label className="form-checkbox">
                <input type="checkbox" checked={aiEnabled} onChange={(e) => setAIEnabled(e.target.checked)} />
                允许该项目使用 AI 能力（建议开启）
              </label>
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
                    <div className="form-group">
                      <label className="form-checkbox">
                        <input type="checkbox" checked={editAIEnabled} onChange={(e) => setEditAIEnabled(e.target.checked)} />
                        允许该项目使用 AI 能力
                      </label>
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
                          <button className="btn btn-sm btn-danger" onClick={() => { void handleDelete(p); }} disabled={busy}>删除</button>
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
                      <div className="project-card-field">
                        <span className="project-card-label">AI 开关</span>
                        <div className="project-card-badges">
                          <span className={`badge ${p.aiEnabled ? "badge-success" : "badge-neutral"}`}>
                            {p.aiEnabled ? "已开启" : "已关闭"}
                          </span>
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

      {deleteCandidate && (
        <div className="modal-overlay" onClick={closeDeleteModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>删除项目</h3>
              <button className="modal-close" onClick={closeDeleteModal} disabled={busy}>✕</button>
            </div>
            <div className="modal-body">
              <p style={{ marginTop: 0, marginBottom: 10 }}>
                你正在删除项目 <strong>{deleteCandidate.name}</strong>。
              </p>
              <p style={{ marginTop: 0, marginBottom: 14, color: "var(--text-secondary)", fontSize: 13 }}>
                默认仅归档项目（可恢复）；勾选后会彻底删除该项目的资产、端口、漏洞、任务、监控与日志数据。
              </p>
              <label className="form-checkbox">
                <input
                  type="checkbox"
                  checked={deleteWithData}
                  disabled={busy}
                  onChange={(e) => setDeleteWithData(e.target.checked)}
                />
                同时删除该项目所有数据（不可恢复）
              </label>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={closeDeleteModal} disabled={busy}>取消</button>
              <button className="btn btn-danger" onClick={() => { void confirmDelete(); }} disabled={busy}>
                {busy ? "处理中..." : deleteWithData ? "删除项目和数据" : "仅归档项目"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
