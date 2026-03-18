import { useMemo, useState } from "react";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatCard } from "../components/ui/StatCard";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import {
  useBulkMonitorEventStatus,
  useCreateMonitorTarget,
  useDeleteMonitorTarget,
  useMonitorChanges,
  useMonitorEvents,
  useMonitorRuns,
  useMonitorTargets,
  usePatchMonitorEventStatus,
  useStopMonitorTarget,
  useUpdateMonitorTarget
} from "../hooks/queries";
import { formatDate } from "../lib/format";
import { matchesProjectDomain, normalizeRootDomain } from "../lib/projectScope";
import type { MonitorChange, MonitorEvent, MonitorRun, MonitorTarget } from "../types/models";

const EVENT_TABS = [
  { key: "all", label: "全部事件" },
  { key: "new_live", label: "新资产" },
  { key: "port_opened", label: "端口变化" }
] as const;

const STATUS_OPTIONS = [
  { value: "", label: "全部状态" },
  { value: "open", label: "Open" },
  { value: "ack", label: "已确认" },
  { value: "resolved", label: "已解决" },
  { value: "ignored", label: "已忽略" }
] as const;

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

function changeTypeLabel(t: string): string {
  const m: Record<string, string> = {
    new_live: "新增存活",
    web_changed: "Web变化",
    live_resolved: "存活消失",
    opened: "端口开放",
    closed: "端口关闭",
    service_changed: "服务变更"
  };
  return m[t] || t;
}

function monitorPolicySummary(t: MonitorTarget): string {
  if (!t.enableVulnScan) return "仅资产变更监控";
  const engines: string[] = [];
  if (t.enableNuclei) engines.push("Nuclei");
  if (t.enableCors) engines.push("CORS");
  const triggers: string[] = [];
  if (t.vulnOnNewLive !== false) triggers.push("new_live");
  if (t.vulnOnWebChanged) triggers.push("web_changed");
  const maxUrls = t.vulnMaxUrls ?? 50;
  const cooldown = t.vulnCooldownMin ?? 30;
  return `增量漏扫: ${engines.join("+") || "未选引擎"} | 触发: ${triggers.join("+") || "none"} | Max ${maxUrls} | CD ${cooldown}m`;
}

export function MonitoringPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];

  const [eventTab, setEventTab] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState("");
  const [searchQ, setSearchQ] = useState("");

  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [editingTarget, setEditingTarget] = useState<MonitorTarget | null>(null);

  const [newDomain, setNewDomain] = useState("");
  const [newInterval, setNewInterval] = useState(21600);
  const [newEnableVulnScan, setNewEnableVulnScan] = useState(false);
  const [newEnableNuclei, setNewEnableNuclei] = useState(false);
  const [newEnableCors, setNewEnableCors] = useState(false);
  const [newVulnOnNewLive, setNewVulnOnNewLive] = useState(true);
  const [newVulnOnWebChanged, setNewVulnOnWebChanged] = useState(false);
  const [newVulnMaxUrls, setNewVulnMaxUrls] = useState(50);
  const [newVulnCooldownMin, setNewVulnCooldownMin] = useState(30);

  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const eventTypeParam = eventTab === "all" ? undefined : eventTab;
  const statusParam = statusFilter || undefined;
  const searchParam = searchQ.trim() || undefined;

  const targetsQ = useMonitorTargets(projectId);
  const runsQ = useMonitorRuns(projectId);
  const changesQ = useMonitorChanges(projectId);
  const eventsQ = useMonitorEvents(projectId, undefined, statusParam, eventTypeParam, searchParam);

  const createMonitor = useCreateMonitorTarget();
  const updateMonitor = useUpdateMonitorTarget();
  const stopMonitor = useStopMonitorTarget();
  const deleteMonitor = useDeleteMonitorTarget();
  const patchStatus = usePatchMonitorEventStatus();
  const bulkStatus = useBulkMonitorEventStatus();

  const targets = useMemo(
    () => (targetsQ.data ?? []).filter((t: MonitorTarget) => matchesProjectDomain(t.rootDomain, rootDomains)),
    [targetsQ.data, rootDomains]
  );
  const runs = useMemo(
    () => (runsQ.data ?? []).filter((r: MonitorRun) => matchesProjectDomain(r.rootDomain, rootDomains)),
    [runsQ.data, rootDomains]
  );
  const changes = useMemo(
    () => (changesQ.data ?? []).filter((c: MonitorChange) => matchesProjectDomain(c.rootDomain, rootDomains)),
    [changesQ.data, rootDomains]
  );
  const events = useMemo(
    () => (eventsQ.data ?? []).filter((e: MonitorEvent) => matchesProjectDomain(e.rootDomain, rootDomains)),
    [eventsQ.data, rootDomains]
  );

  const openEvents = useMemo(() => events.filter((e) => e.status === "open").length, [events]);
  const recentChanges = useMemo(() => {
    const cutoff = Date.now() - 24 * 3600 * 1000;
    return changes.filter((c) => (c.createdAt ? new Date(c.createdAt).getTime() : 0) > cutoff).length;
  }, [changes]);
  const activeTargets = useMemo(() => targets.filter((t) => t.enabled).length, [targets]);
  const lastRunStatus = useMemo(() => {
    if (runs.length === 0) return "无";
    return runs[0].status;
  }, [runs]);

  const resetPolicyForm = () => {
    setEditingTarget(null);
    setNewDomain(rootDomains[0] ?? "");
    setNewInterval(21600);
    setNewEnableVulnScan(false);
    setNewEnableNuclei(false);
    setNewEnableCors(false);
    setNewVulnOnNewLive(true);
    setNewVulnOnWebChanged(false);
    setNewVulnMaxUrls(50);
    setNewVulnCooldownMin(30);
  };

  const openCreateModal = () => {
    resetPolicyForm();
    setShowPolicyModal(true);
  };

  const openEditModal = (target: MonitorTarget) => {
    setEditingTarget(target);
    setNewDomain(target.rootDomain);
    setNewInterval(21600);
    setNewEnableVulnScan(Boolean(target.enableVulnScan));
    setNewEnableNuclei(Boolean(target.enableNuclei));
    setNewEnableCors(Boolean(target.enableCors));
    setNewVulnOnNewLive(target.vulnOnNewLive !== false);
    setNewVulnOnWebChanged(Boolean(target.vulnOnWebChanged));
    setNewVulnMaxUrls(Math.min(1000, Math.max(1, target.vulnMaxUrls ?? 50)));
    setNewVulnCooldownMin(Math.min(1440, Math.max(1, target.vulnCooldownMin ?? 30)));
    setShowPolicyModal(true);
  };

  const closePolicyModal = () => {
    setShowPolicyModal(false);
    setEditingTarget(null);
  };

  const validatePolicyForm = (): boolean => {
    const domain = normalizeRootDomain(newDomain);
    if (!domain || !projectId) {
      setFeedback({ ok: false, text: "项目或域名不能为空" });
      return false;
    }
    if (!matchesProjectDomain(domain, rootDomains)) {
      setFeedback({ ok: false, text: "域名不在当前项目范围内" });
      return false;
    }
    if (newEnableVulnScan && !newEnableNuclei && !newEnableCors) {
      setFeedback({ ok: false, text: "已开启增量漏扫时，至少选择一个扫描引擎（Nuclei/CORS）" });
      return false;
    }
    if (newEnableVulnScan && !newVulnOnNewLive && !newVulnOnWebChanged) {
      setFeedback({ ok: false, text: "已开启增量漏扫时，至少选择一个触发条件（new_live/web_changed）" });
      return false;
    }
    return true;
  };

  const buildPolicyPayload = () => {
    const safeVulnMaxUrls = Math.min(1000, Math.max(1, newVulnMaxUrls || 50));
    const safeCooldownMin = Math.min(1440, Math.max(1, newVulnCooldownMin || 30));
    return {
      enableVulnScan: newEnableVulnScan,
      enableNuclei: newEnableVulnScan ? newEnableNuclei : false,
      enableCors: newEnableVulnScan ? newEnableCors : false,
      vulnOnNewLive: newEnableVulnScan ? newVulnOnNewLive : true,
      vulnOnWebChanged: newEnableVulnScan ? newVulnOnWebChanged : false,
      vulnMaxUrls: newEnableVulnScan ? safeVulnMaxUrls : 50,
      vulnCooldownMin: newEnableVulnScan ? safeCooldownMin : 30
    };
  };

  const handleSubmitPolicy = async () => {
    if (!validatePolicyForm() || !projectId) return;
    const domain = normalizeRootDomain(newDomain);
    const payload = buildPolicyPayload();
    setSubmitting(true);
    setFeedback(null);
    try {
      if (editingTarget) {
        await updateMonitor.mutateAsync({
          projectId,
          domain,
          ...payload
        });
        setFeedback({ ok: true, text: `策略已更新: ${domain}` });
      } else {
        await createMonitor.mutateAsync({
          projectId,
          domain,
          intervalSec: newInterval,
          ...payload
        });
        setFeedback({ ok: true, text: `监控目标已添加: ${domain}` });
      }
      closePolicyModal();
      resetPolicyForm();
    } catch (e) {
      setFeedback({ ok: false, text: `${editingTarget ? "更新策略" : "添加目标"}失败: ${errMsg(e)}` });
    } finally {
      setSubmitting(false);
    }
  };

  const handleEventAction = async (eventId: number, status: string) => {
    if (!projectId) return;
    try {
      await patchStatus.mutateAsync({ projectId, eventId, status });
      setFeedback({ ok: true, text: `事件 #${eventId} 已更新为 ${status}` });
    } catch (e) {
      setFeedback({ ok: false, text: `状态更新失败: ${errMsg(e)}` });
    }
  };

  const handleBulkResolved = async () => {
    if (!projectId) return;
    const openIDs = events
      .filter((e) => e.status === "open")
      .slice(0, 200)
      .map((e) => e.id);
    if (openIDs.length === 0) return;
    try {
      await bulkStatus.mutateAsync({ projectId, eventIds: openIDs, status: "resolved" });
      setFeedback({ ok: true, text: `已批量关闭 ${openIDs.length} 条 Open 事件` });
    } catch (e) {
      setFeedback({ ok: false, text: `批量操作失败: ${errMsg(e)}` });
    }
  };

  const handleStop = async (domain: string) => {
    if (!projectId || !confirm(`确认停止监控 ${domain} ?`)) return;
    try {
      await stopMonitor.mutateAsync({ projectId, domain });
      setFeedback({ ok: true, text: `已停止: ${domain}` });
    } catch (e) {
      setFeedback({ ok: false, text: `停止失败: ${errMsg(e)}` });
    }
  };

  const handleReEnable = async (domain: string) => {
    if (!projectId) return;
    try {
      await createMonitor.mutateAsync({ projectId, domain });
      setFeedback({ ok: true, text: `已启用: ${domain}` });
    } catch (e) {
      setFeedback({ ok: false, text: `启用失败: ${errMsg(e)}` });
    }
  };

  const handleDelete = async (domain: string) => {
    if (!projectId || !confirm(`确认删除 ${domain} 的全部监控数据？`)) return;
    try {
      await deleteMonitor.mutateAsync({ projectId, domain });
      setFeedback({ ok: true, text: `已删除: ${domain}` });
    } catch (e) {
      setFeedback({ ok: false, text: `删除失败: ${errMsg(e)}` });
    }
  };

  const loading = targetsQ.isLoading || runsQ.isLoading || eventsQ.isLoading;

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">变更监控</h1>
        <p className="page-desc">监控新资产与端口变化，并支持对增量 URL 自动触发 Nuclei/CORS 漏扫。</p>
      </div>

      <ProjectScopeBanner title="监控范围" hint="按当前项目根域名过滤显示。" />

      {feedback && (
        <div
          style={{
            color: feedback.ok ? "#16a34a" : "#dc2626",
            marginBottom: 12,
            padding: "8px 16px",
            background: "var(--bg-secondary)",
            borderRadius: 8
          }}
        >
          {feedback.text}
          <button
            style={{ marginLeft: 12, cursor: "pointer", background: "none", border: "none", color: "inherit" }}
            onClick={() => setFeedback(null)}
          >
            ×
          </button>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, marginBottom: 24 }}>
        <StatCard label="Open 事件" value={openEvents} icon="●" />
        <StatCard label="24h 变化" value={recentChanges} icon="Δ" />
        <StatCard label="监控目标" value={`${activeTargets} / ${targets.length}`} icon="◎" />
        <StatCard label="最近运行" value={lastRunStatus} icon="↻" />
      </div>

      {loading && <div className="empty-state">正在加载...</div>}

      <article className="panel" style={{ marginBottom: 24 }}>
        <header className="panel-header">
          <h2>监控目标</h2>
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <span className="panel-meta">{targets.length} 个</span>
            <button className="btn btn-primary btn-sm" onClick={openCreateModal} disabled={!projectId}>
              + 添加
            </button>
          </div>
        </header>

        {targets.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>根域名</th>
                  <th>状态</th>
                  <th>策略</th>
                  <th>基线</th>
                  <th>最近运行</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => (
                  <tr key={t.id}>
                    <td>{t.rootDomain}</td>
                    <td>{t.enabled ? <span className="badge badge-success">启用</span> : <span className="badge badge-danger">停用</span>}</td>
                    <td style={{ fontSize: 12, maxWidth: 420 }}>{monitorPolicySummary(t)}</td>
                    <td>{t.baselineDone ? `v${Math.max(1, t.baselineVersion ?? 0)}` : "—"}</td>
                    <td className="cell-muted">{formatDate(t.lastRunAt)}</td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button className="btn btn-sm btn-secondary" onClick={() => openEditModal(t)}>
                          策略
                        </button>
                        {t.enabled ? (
                          <button className="btn btn-sm btn-warning" onClick={() => void handleStop(t.rootDomain)}>
                            停止
                          </button>
                        ) : (
                          <button className="btn btn-sm btn-primary" onClick={() => void handleReEnable(t.rootDomain)}>
                            启用
                          </button>
                        )}
                        <button className="btn btn-sm btn-danger" onClick={() => void handleDelete(t.rootDomain)}>
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-text">暂无监控目标</div>
          </div>
        )}
      </article>

      <article className="panel" style={{ marginBottom: 24 }}>
        <header className="panel-header">
          <h2>运行记录</h2>
          <span className="panel-meta">{runs.length} 条</span>
        </header>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>根域名</th>
                <th>状态</th>
                <th>开始</th>
                <th>耗时</th>
                <th>new_live</th>
                <th>web_changed</th>
                <th>port_opened</th>
                <th>port_closed</th>
              </tr>
            </thead>
            <tbody>
              {runs.slice(0, 100).map((run) => (
                <tr key={run.id}>
                  <td>{run.id}</td>
                  <td>{run.rootDomain}</td>
                  <td>
                    <StatusBadge status={run.status} />
                  </td>
                  <td>{formatDate(run.startedAt)}</td>
                  <td>{run.durationSec}s</td>
                  <td>{run.newLiveCount}</td>
                  <td>{run.webChanged}</td>
                  <td>{run.portOpened}</td>
                  <td>{run.portClosed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </article>

      <article className="panel" style={{ marginBottom: 24 }}>
        <header className="panel-header">
          <h2>事件生命周期</h2>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn-sm" onClick={() => void handleBulkResolved()}>
              批量关闭 Open
            </button>
            <span className="panel-meta">{events.length} 条</span>
          </div>
        </header>

        <div style={{ padding: "12px 20px", borderBottom: "1px solid var(--border)", display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" }}>
          <div style={{ display: "flex", gap: 4 }}>
            {EVENT_TABS.map((tab) => (
              <button key={tab.key} className={`btn btn-sm ${eventTab === tab.key ? "btn-primary" : "btn-secondary"}`} onClick={() => setEventTab(tab.key)}>
                {tab.label}
              </button>
            ))}
          </div>
          <select className="form-input" style={{ width: 140, padding: "4px 8px", fontSize: 13 }} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            {STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <input
            className="form-input"
            style={{ width: 220, padding: "4px 8px", fontSize: 13 }}
            placeholder="搜索域名/IP/标题..."
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
          />
        </div>

        {events.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-text">暂无事件</div>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>状态</th>
                  <th>类型</th>
                  <th>域名</th>
                  <th>IP</th>
                  <th>端口</th>
                  <th>服务</th>
                  <th>标题</th>
                  <th>首见</th>
                  <th>末见</th>
                  <th>次数</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id}>
                    <td>
                      <StatusBadge status={ev.status} />
                    </td>
                    <td>{changeTypeLabel(ev.eventType)}</td>
                    <td className="cell-mono">{ev.domain || "—"}</td>
                    <td className="cell-mono">{ev.ip || "—"}</td>
                    <td>{(ev.port ?? 0) > 0 ? ev.port : "—"}</td>
                    <td>{ev.service || "—"}</td>
                    <td>{ev.title || "—"}</td>
                    <td className="cell-muted">{formatDate(ev.firstSeenAt)}</td>
                    <td className="cell-muted">{formatDate(ev.lastSeenAt)}</td>
                    <td>{ev.occurrenceCount}</td>
                    <td>
                      <div style={{ display: "flex", gap: 4 }}>
                        {ev.status === "open" && (
                          <button className="btn btn-sm btn-primary" onClick={() => void handleEventAction(ev.id, "ack")}>
                            确认
                          </button>
                        )}
                        {ev.status !== "resolved" && (
                          <button className="btn btn-sm btn-success" onClick={() => void handleEventAction(ev.id, "resolved")}>
                            解决
                          </button>
                        )}
                        {ev.status !== "ignored" && (
                          <button className="btn btn-sm btn-secondary" onClick={() => void handleEventAction(ev.id, "ignored")}>
                            忽略
                          </button>
                        )}
                        {ev.status !== "open" && (
                          <button className="btn btn-sm btn-warning" onClick={() => void handleEventAction(ev.id, "open")}>
                            重开
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </article>

      {showPolicyModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 2000, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ background: "var(--bg-primary)", borderRadius: 12, padding: 24, width: 500 }}>
            <h3 style={{ marginBottom: 16 }}>{editingTarget ? "编辑监控策略" : "添加监控目标"}</h3>

            <label style={{ display: "block", marginBottom: 8, fontSize: 13 }}>根域名</label>
            <input
              className="form-input"
              style={{ width: "100%", marginBottom: 12, padding: "8px 12px" }}
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="example.com"
              readOnly={Boolean(editingTarget)}
            />

            {!editingTarget && (
              <>
                <label style={{ display: "block", marginBottom: 8, fontSize: 13 }}>检测间隔</label>
                <select className="form-input" style={{ width: "100%", marginBottom: 16, padding: "8px 12px" }} value={newInterval} onChange={(e) => setNewInterval(Number(e.target.value))}>
                  <option value={3600}>每 1 小时</option>
                  <option value={7200}>每 2 小时</option>
                  <option value={14400}>每 4 小时</option>
                  <option value={21600}>每 6 小时 (默认)</option>
                  <option value={43200}>每 12 小时</option>
                  <option value={86400}>每 24 小时</option>
                </select>
              </>
            )}

            <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, marginBottom: 16, display: "grid", gap: 8 }}>
              <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <input type="checkbox" checked={newEnableVulnScan} onChange={(e) => setNewEnableVulnScan(e.target.checked)} />
                <span>开启变更后增量漏扫</span>
              </label>

              {newEnableVulnScan && (
                <>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
                    <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <input type="checkbox" checked={newEnableNuclei} onChange={(e) => setNewEnableNuclei(e.target.checked)} />
                      <span>Nuclei</span>
                    </label>
                    <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <input type="checkbox" checked={newEnableCors} onChange={(e) => setNewEnableCors(e.target.checked)} />
                      <span>High-risk CORS</span>
                    </label>
                  </div>

                  <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
                    <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <input type="checkbox" checked={newVulnOnNewLive} onChange={(e) => setNewVulnOnNewLive(e.target.checked)} />
                      <span>new_live 触发</span>
                    </label>
                    <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <input type="checkbox" checked={newVulnOnWebChanged} onChange={(e) => setNewVulnOnWebChanged(e.target.checked)} />
                      <span>web_changed 触发</span>
                    </label>
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
                      <span>每轮最大 URL</span>
                      <input className="form-input" type="number" min={1} max={1000} value={newVulnMaxUrls} onChange={(e) => setNewVulnMaxUrls(Number(e.target.value) || 50)} />
                    </label>
                    <label style={{ display: "grid", gap: 4, fontSize: 12 }}>
                      <span>冷却分钟</span>
                      <input className="form-input" type="number" min={1} max={1440} value={newVulnCooldownMin} onChange={(e) => setNewVulnCooldownMin(Number(e.target.value) || 30)} />
                    </label>
                  </div>
                </>
              )}
            </div>

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button className="btn btn-secondary" onClick={closePolicyModal} disabled={submitting}>
                取消
              </button>
              <button className="btn btn-primary" onClick={() => void handleSubmitPolicy()} disabled={submitting || !newDomain.trim()}>
                {submitting ? "提交中..." : editingTarget ? "保存策略" : "确认"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

