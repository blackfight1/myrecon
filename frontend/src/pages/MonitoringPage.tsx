import { createColumnHelper } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { DataTable } from "../components/ui/DataTable";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import { useMonitorEvents, useMonitorRuns, useMonitorTargets, useCreateMonitorTarget, useStopMonitorTarget, useDeleteMonitorTarget } from "../hooks/queries";
import { errorMessage } from "../lib/errors";
import { formatDate } from "../lib/format";
import { matchesProjectDomain, normalizeRootDomain } from "../lib/projectScope";
import type { MonitorEvent, MonitorRun } from "../types/models";

const rCol = createColumnHelper<MonitorRun>();
const runColumns = [
  rCol.accessor("id", { header: "ID" }),
  rCol.accessor("rootDomain", { header: "根域名" }),
  rCol.accessor("status", { header: "状态", cell: (c) => <StatusBadge status={c.getValue()} /> }),
  rCol.accessor("startedAt", { header: "开始时间", cell: (c) => formatDate(c.getValue()) }),
  rCol.accessor("durationSec", { header: "耗时", cell: (c) => `${c.getValue()}s` }),
  rCol.accessor("newLiveCount", { header: "新增存活" }),
  rCol.accessor("webChanged", { header: "Web 变更" }),
  rCol.accessor("portOpened", { header: "端口新增" }),
  rCol.accessor("portClosed", { header: "端口关闭" }),
  rCol.accessor("serviceChange", { header: "服务变更" }),
  rCol.accessor("errorMessage", { header: "错误信息", cell: (c) => c.getValue() || <span className="cell-muted">—</span> })
];

const eCol = createColumnHelper<MonitorEvent>();
const eventColumns = [
  eCol.accessor("id", { header: "事件 ID" }),
  eCol.accessor("rootDomain", { header: "根域名" }),
  eCol.accessor("eventType", { header: "类型", cell: (c) => <span className="badge badge-info">{c.getValue()}</span> }),
  eCol.accessor("status", { header: "状态", cell: (c) => <StatusBadge status={c.getValue()} /> }),
  eCol.accessor("domain", { header: "域名", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  eCol.accessor("ip", { header: "IP", cell: (c) => c.getValue() ? <span className="cell-mono">{c.getValue()}</span> : <span className="cell-muted">—</span> }),
  eCol.accessor("port", { header: "端口", cell: (c) => c.getValue() ?? <span className="cell-muted">—</span> }),
  eCol.accessor("service", { header: "服务", cell: (c) => c.getValue() || <span className="cell-muted">—</span> }),
  eCol.accessor("statusCode", { header: "状态码", cell: (c) => c.getValue() ?? <span className="cell-muted">—</span> }),
  eCol.accessor("occurrenceCount", { header: "出现次数" }),
  eCol.accessor("firstSeenAt", { header: "首次出现", cell: (c) => formatDate(c.getValue()) }),
  eCol.accessor("lastSeenAt", { header: "最后出现", cell: (c) => formatDate(c.getValue()) }),
  eCol.accessor("lastChangedAt", { header: "最后变更", cell: (c) => formatDate(c.getValue()) })
];

export function MonitoringPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];

  const targetsQ = useMonitorTargets(projectId);
  const runsQ = useMonitorRuns(projectId);
  const eventsQ = useMonitorEvents(projectId);
  const createMonitor = useCreateMonitorTarget();
  const stopMonitor = useStopMonitorTarget();
  const deleteMonitor = useDeleteMonitorTarget();

  const [showAddModal, setShowAddModal] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const handleAddMonitor = async () => {
    const domain = normalizeRootDomain(newDomain);
    if (!domain || !projectId) return;

    if (!matchesProjectDomain(domain, rootDomains)) {
      setFeedback({ ok: false, text: "目标域名不在当前项目范围内，请先在项目中补充根域名。" });
      return;
    }

    setSubmitting(true);
    setFeedback(null);
    try {
      await createMonitor.mutateAsync({ projectId, domain });
      setShowAddModal(false);
      setNewDomain("");
      setFeedback({ ok: true, text: `监控已添加：${domain}` });
    } catch (err) {
      setFeedback({ ok: false, text: `添加失败：${errorMessage(err)}` });
    } finally {
      setSubmitting(false);
    }
  };

  const handleStop = async (domain: string) => {
    if (!projectId) return;
    if (!confirm(`确定要停止监控 ${domain} 吗？`)) return;
    setFeedback(null);
    try {
      await stopMonitor.mutateAsync({ projectId, domain });
      setFeedback({ ok: true, text: `已停止监控：${domain}` });
    } catch (err) {
      setFeedback({ ok: false, text: `停止失败：${errorMessage(err)}` });
    }
  };

  const handleReEnable = async (domain: string) => {
    if (!projectId) return;
    setFeedback(null);
    try {
      await createMonitor.mutateAsync({ projectId, domain });
      setFeedback({ ok: true, text: `已重新启用：${domain}` });
    } catch (err) {
      setFeedback({ ok: false, text: `启用失败：${errorMessage(err)}` });
    }
  };

  const handleDelete = async (domain: string) => {
    if (!projectId) return;
    if (!confirm(`确定要删除 ${domain} 的所有监控数据吗？此操作不可恢复。`)) return;
    setFeedback(null);
    try {
      await deleteMonitor.mutateAsync({ projectId, domain });
      setFeedback({ ok: true, text: `已删除监控数据：${domain}` });
    } catch (err) {
      setFeedback({ ok: false, text: `删除失败：${errorMessage(err)}` });
    }
  };

  const targets = useMemo(() => (targetsQ.data ?? []).filter((t) => matchesProjectDomain(t.rootDomain, rootDomains)), [targetsQ.data, rootDomains]);
  const runs = useMemo(() => (runsQ.data ?? []).filter((r) => matchesProjectDomain(r.rootDomain, rootDomains)), [runsQ.data, rootDomains]);
  const events = useMemo(() => (eventsQ.data ?? []).filter((e) => matchesProjectDomain(e.rootDomain, rootDomains)), [eventsQ.data, rootDomains]);

  const loading = targetsQ.isLoading || runsQ.isLoading || eventsQ.isLoading;

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">变更监控</h1>
        <p className="page-desc">漂移检测系统，追踪新主机、端口变更、服务变化和 Web 内容变动。</p>
      </div>

      <ProjectScopeBanner title="监控范围" hint="目标、运行记录和变更事件按项目根域名过滤。" />

      {feedback && (
        <div className="empty-state" style={{ color: feedback.ok ? "#16a34a" : "#dc2626", marginBottom: 12 }}>
          {feedback.text}
        </div>
      )}

      {loading && <div className="empty-state">正在加载监控数据...</div>}

      <article className="panel">
        <header className="panel-header">
          <h2>监控目标</h2>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span className="panel-meta">{targets.length} 个目标</span>
            <button className="btn btn-primary btn-sm" onClick={() => { setNewDomain(rootDomains[0] ?? ""); setShowAddModal(true); }} disabled={!projectId}>+ 添加监控</button>
          </div>
        </header>
        {targets.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>根域名</th>
                  <th>启用状态</th>
                  <th>基线</th>
                  <th>上次运行</th>
                  <th>更新时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => (
                  <tr key={t.id}>
                    <td>{t.rootDomain}</td>
                    <td>{t.enabled ? <span className="badge badge-success">开启</span> : <span className="badge badge-danger">关闭</span>}</td>
                    <td>{t.baselineDone ? "✓" : "—"}</td>
                    <td className="cell-muted">{formatDate(t.lastRunAt)}</td>
                    <td className="cell-muted">{formatDate(t.updatedAt)}</td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        {t.enabled ? (
                          <button className="btn btn-sm btn-warning" onClick={() => { void handleStop(t.rootDomain); }} disabled={stopMonitor.isPending}>停止</button>
                        ) : (
                          <button className="btn btn-sm btn-primary" onClick={() => { void handleReEnable(t.rootDomain); }} disabled={createMonitor.isPending}>重新启用</button>
                        )}
                        <button className="btn btn-sm btn-danger" onClick={() => { void handleDelete(t.rootDomain); }} disabled={deleteMonitor.isPending}>删除</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon">◉</div>
            <div className="empty-state-text">暂无监控目标，点击“+ 添加监控”开始。</div>
          </div>
        )}
      </article>

      {showAddModal && (
        <div className="modal-overlay" onClick={() => setShowAddModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header"><h3>添加监控目标</h3><button className="modal-close" onClick={() => setShowAddModal(false)}>✕</button></div>
            <div className="modal-body">
              <label className="form-label">目标域名</label>
              <input className="form-input" type="text" placeholder="example.com" value={newDomain} onChange={(e) => setNewDomain(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void handleAddMonitor()} />
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowAddModal(false)}>取消</button>
              <button className="btn btn-primary" onClick={() => { void handleAddMonitor(); }} disabled={submitting || !newDomain.trim()}>{submitting ? "提交中..." : "确认添加"}</button>
            </div>
          </div>
        </div>
      )}

      <article className="panel">
        <header className="panel-header">
          <h2>最近运行</h2>
          <span className="panel-meta">{runs.length} 次运行</span>
        </header>
        <DataTable data={runs} columns={runColumns} />
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>事件生命周期</h2>
          <span className="panel-meta">{events.length} 个事件</span>
        </header>
        <DataTable data={events} columns={eventColumns} />
      </article>
    </section>
  );
}
