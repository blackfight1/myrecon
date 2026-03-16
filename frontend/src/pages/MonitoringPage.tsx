import { useMemo, useState, useCallback } from "react";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatCard } from "../components/ui/StatCard";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import {
  useMonitorEvents,
  useMonitorRuns,
  useMonitorChanges,
  useMonitorTargets,
  useCreateMonitorTarget,
  useStopMonitorTarget,
  useDeleteMonitorTarget,
  usePatchMonitorEventStatus,
  useBulkMonitorEventStatus
} from "../hooks/queries";
import { formatDate } from "../lib/format";
import { matchesProjectDomain, normalizeRootDomain } from "../lib/projectScope";
import type { MonitorEvent, MonitorRun, MonitorChange, MonitorTarget } from "../types/models";

const EVENT_TABS = [
  { key: "all", label: "全部事件" },
  { key: "new_live", label: "🌐 新子域" },
  { key: "port_opened", label: "🔌 端口变更" }
] as const;

const STATUS_OPTIONS = [
  { value: "", label: "全部状态" },
  { value: "open", label: "🔴 Open" },
  { value: "ack", label: "🟡 已确认" },
  { value: "resolved", label: "🟢 已解决" },
  { value: "ignored", label: "⚪ 已忽略" }
];

function changeTypeLabel(t: string) {
  const m: Record<string, string> = {
    new_live: "新增存活", web_changed: "Web变更", live_resolved: "存活消失",
    opened: "端口开放", closed: "端口关闭", service_changed: "服务变更"
  };
  return m[t] || t;
}

function changeTypeBadge(t: string) {
  if (t === "new_live" || t === "opened") return "badge badge-success";
  if (t === "live_resolved" || t === "closed") return "badge badge-danger";
  return "badge badge-warning";
}

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

export function MonitoringPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];

  const [eventTab, setEventTab] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState("");
  const [searchQ, setSearchQ] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [expandedRunId, setExpandedRunId] = useState<number | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [newInterval, setNewInterval] = useState(21600);
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [drawerEvent, setDrawerEvent] = useState<MonitorEvent | null>(null);

  const eventTypeParam = eventTab === "all" ? undefined : eventTab;
  const statusParam = statusFilter || undefined;
  const searchParam = searchQ.trim() || undefined;

  const targetsQ = useMonitorTargets(projectId);
  const runsQ = useMonitorRuns(projectId);
  const changesQ = useMonitorChanges(projectId);
  const eventsQ = useMonitorEvents(projectId, undefined, statusParam, eventTypeParam, searchParam);
  const createMonitor = useCreateMonitorTarget();
  const stopMonitor = useStopMonitorTarget();
  const deleteMonitor = useDeleteMonitorTarget();
  const patchStatus = usePatchMonitorEventStatus();
  const bulkStatus = useBulkMonitorEventStatus();

  const targets = useMemo(() => (targetsQ.data ?? []).filter((t: MonitorTarget) => matchesProjectDomain(t.rootDomain, rootDomains)), [targetsQ.data, rootDomains]);
  const runs = useMemo(() => (runsQ.data ?? []).filter((r: MonitorRun) => matchesProjectDomain(r.rootDomain, rootDomains)), [runsQ.data, rootDomains]);
  const changes = useMemo(() => (changesQ.data ?? []).filter((c: MonitorChange) => matchesProjectDomain(c.rootDomain, rootDomains)), [changesQ.data, rootDomains]);
  const events = useMemo(() => (eventsQ.data ?? []).filter((e: MonitorEvent) => matchesProjectDomain(e.rootDomain, rootDomains)), [eventsQ.data, rootDomains]);

  const openEvents = useMemo(() => events.filter((e: MonitorEvent) => e.status === "open").length, [events]);
  const recentChanges = useMemo(() => {
    const cutoff = Date.now() - 86400000;
    return changes.filter((c: MonitorChange) => new Date(c.createdAt).getTime() > cutoff).length;
  }, [changes]);
  const activeTargets = useMemo(() => targets.filter((t: MonitorTarget) => t.enabled).length, [targets]);
  const lastRunStatus = useMemo(() => {
    if (runs.length === 0) return "无";
    return runs[0].status === "success" ? "✅ 成功" : runs[0].status === "running" ? "⏳ 运行中" : "❌ " + runs[0].status;
  }, [runs]);

  const trendData = useMemo(() => {
    const days: { date: string; count: number }[] = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      const ds = d.toISOString().slice(0, 10);
      days.push({ date: ds, count: changes.filter((c: MonitorChange) => (c.createdAt || "").startsWith(ds)).length });
    }
    return days;
  }, [changes]);
  const maxTrend = Math.max(1, ...trendData.map((d) => d.count));

  const expandedChanges = useMemo(() => expandedRunId == null ? [] : changes.filter((c: MonitorChange) => c.runId === expandedRunId), [changes, expandedRunId]);

  const handleEventAction = useCallback(async (eventId: number, status: string) => {
    if (!projectId) return;
    try { await patchStatus.mutateAsync({ projectId, eventId, status }); }
    catch (e) { setFeedback({ ok: false, text: "操作失败：" + errMsg(e) }); }
  }, [projectId, patchStatus]);

  const handleBulkAction = useCallback(async (status: string) => {
    if (!projectId || selectedIds.size === 0) return;
    try {
      await bulkStatus.mutateAsync({ projectId, eventIds: Array.from(selectedIds), status });
      setSelectedIds(new Set());
      setFeedback({ ok: true, text: "已批量更新 " + selectedIds.size + " 个事件" });
    } catch (e) { setFeedback({ ok: false, text: "批量操作失败：" + errMsg(e) }); }
  }, [projectId, selectedIds, bulkStatus]);

  const toggleSel = (id: number) => setSelectedIds((p) => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const toggleAll = () => setSelectedIds(selectedIds.size === events.length ? new Set() : new Set(events.map((e: MonitorEvent) => e.id)));

  const handleAdd = async () => {
    const domain = normalizeRootDomain(newDomain);
    if (!domain || !projectId) return;
    if (!matchesProjectDomain(domain, rootDomains)) { setFeedback({ ok: false, text: "域名不在项目范围内" }); return; }
    setSubmitting(true); setFeedback(null);
    try {
      await createMonitor.mutateAsync({ projectId, domain, intervalSec: newInterval });
      setShowAddModal(false); setNewDomain("");
      setFeedback({ ok: true, text: "监控已添加：" + domain });
    } catch (e) { setFeedback({ ok: false, text: "添加失败：" + errMsg(e) }); }
    finally { setSubmitting(false); }
  };

  const handleStop = async (domain: string) => {
    if (!projectId || !confirm("确定停止监控 " + domain + "？")) return;
    try { await stopMonitor.mutateAsync({ projectId, domain }); setFeedback({ ok: true, text: "已停止：" + domain }); }
    catch (e) { setFeedback({ ok: false, text: "停止失败：" + errMsg(e) }); }
  };

  const handleReEnable = async (domain: string) => {
    if (!projectId) return;
    try { await createMonitor.mutateAsync({ projectId, domain }); setFeedback({ ok: true, text: "已启用：" + domain }); }
    catch (e) { setFeedback({ ok: false, text: "启用失败：" + errMsg(e) }); }
  };

  const handleDelete = async (domain: string) => {
    if (!projectId || !confirm("确定删除 " + domain + " 的所有监控数据？不可恢复。")) return;
    try { await deleteMonitor.mutateAsync({ projectId, domain }); setFeedback({ ok: true, text: "已删除：" + domain }); }
    catch (e) { setFeedback({ ok: false, text: "删除失败：" + errMsg(e) }); }
  };

  const loading = targetsQ.isLoading || runsQ.isLoading || eventsQ.isLoading;

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">变更监控</h1>
        <p className="page-desc">漂移检测：追踪新主机、端口变更、服务变化和 Web 内容变动。</p>
      </div>
      <ProjectScopeBanner title="监控范围" hint="按项目根域名过滤。" />

      {feedback && (
        <div style={{ color: feedback.ok ? "#16a34a" : "#dc2626", marginBottom: 12, padding: "8px 16px", background: "var(--bg-secondary)", borderRadius: 8 }}>
          {feedback.text}
          <button style={{ marginLeft: 12, cursor: "pointer", background: "none", border: "none", color: "inherit" }} onClick={() => setFeedback(null)}>✕</button>
        </div>
      )}

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, marginBottom: 24 }}>
        <StatCard label="Open 事件" value={openEvents} icon="🔴" />
        <StatCard label="24h 变更" value={recentChanges} icon="📊" />
        <StatCard label="监控目标" value={activeTargets + " / " + targets.length} icon="🎯" />
        <StatCard label="最近运行" value={lastRunStatus} icon="⏱️" />
      </div>

      {/* Trend */}
      <article className="panel" style={{ marginBottom: 24 }}>
        <header className="panel-header"><h2>📈 7 日变更趋势</h2></header>
        <div style={{ padding: "16px 20px", display: "flex", alignItems: "flex-end", gap: 8, height: 120 }}>
          {trendData.map((d) => (
            <div key={d.date} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{d.count}</span>
              <div style={{ width: "100%", maxWidth: 48, height: Math.max(4, (d.count / maxTrend) * 64), background: d.count > 0 ? "var(--accent)" : "var(--border)", borderRadius: 4 }} />
              <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{d.date.slice(5)}</span>
            </div>
          ))}
        </div>
      </article>

      {loading && <div className="empty-state">正在加载...</div>}

      {/* Targets */}
      <article className="panel" style={{ marginBottom: 24 }}>
        <header className="panel-header">
          <h2>监控目标</h2>
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <span className="panel-meta">{targets.length} 个</span>
            <button className="btn btn-primary btn-sm" onClick={() => { setNewDomain(rootDomains[0] ?? ""); setShowAddModal(true); }} disabled={!projectId}>+ 添加</button>
          </div>
        </header>
        {targets.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>根域名</th><th>状态</th><th>基线</th><th>上次运行</th><th>操作</th></tr></thead>
              <tbody>
                {targets.map((t: MonitorTarget) => (
                  <tr key={t.id}>
                    <td>{t.rootDomain}</td>
                    <td>{t.enabled ? <span className="badge badge-success">开启</span> : <span className="badge badge-danger">关闭</span>}</td>
                    <td>{t.baselineDone ? "✓" : "—"}</td>
                    <td className="cell-muted">{formatDate(t.lastRunAt)}</td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        {t.enabled
                          ? <button className="btn btn-sm btn-warning" onClick={() => void handleStop(t.rootDomain)}>停止</button>
                          : <button className="btn btn-sm btn-primary" onClick={() => void handleReEnable(t.rootDomain)}>启用</button>}
                        <button className="btn btn-sm btn-danger" onClick={() => void handleDelete(t.rootDomain)}>删除</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="empty-state"><div className="empty-state-text">暂无监控目标</div></div>}
      </article>

      {/* Runs (expandable) */}
      <article className="panel" style={{ marginBottom: 24 }}>
        <header className="panel-header"><h2>运行记录</h2><span className="panel-meta">{runs.length} 次</span></header>
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th style={{ width: 28 }}></th><th>ID</th><th>根域名</th><th>状态</th><th>开始</th><th>耗时</th><th>新存活</th><th>Web变</th><th>端口+</th><th>端口-</th></tr></thead>
            <tbody>
              {runs.slice(0, 50).map((run: MonitorRun) => {
                const expanded = expandedRunId === run.id;
                const total = run.newLiveCount + run.webChanged + run.portOpened + run.portClosed + run.serviceChange;
                return [
                  <tr key={run.id} style={{ cursor: total > 0 ? "pointer" : "default" }} onClick={() => total > 0 && setExpandedRunId(expanded ? null : run.id)}>
                    <td>{total > 0 ? (expanded ? "▼" : "▶") : "·"}</td>
                    <td>{run.id}</td><td>{run.rootDomain}</td>
                    <td><StatusBadge status={run.status} /></td>
                    <td>{formatDate(run.startedAt)}</td><td>{run.durationSec}s</td>
                    <td>{run.newLiveCount || "—"}</td><td>{run.webChanged || "—"}</td>
                    <td>{run.portOpened || "—"}</td><td>{run.portClosed || "—"}</td>
                  </tr>,
                  expanded && (
                    <tr key={run.id + "-d"}>
                      <td colSpan={10} style={{ background: "var(--bg-secondary)", padding: "12px 20px" }}>
                        <strong>Run #{run.id} 变更 ({expandedChanges.length})</strong>
                        {expandedChanges.length === 0 ? <p className="cell-muted">无记录</p> : (
                          <table className="data-table" style={{ fontSize: 13, marginTop: 8 }}>
                            <thead><tr><th>类型</th><th>域名</th><th>IP</th><th>端口</th><th>状态码</th><th>标题</th><th>时间</th></tr></thead>
                            <tbody>
                              {expandedChanges.map((c: MonitorChange, ci: number) => (
                                <tr key={ci}>
                                  <td><span className={changeTypeBadge(c.changeType)}>{changeTypeLabel(c.changeType)}</span></td>
                                  <td className="cell-mono">{c.domain || "—"}</td>
                                  <td className="cell-mono">{c.ip || "—"}</td>
                                  <td>{c.port > 0 ? c.port : "—"}</td>
                                  <td>{c.statusCode > 0 ? c.statusCode : "—"}</td>
                                  <td>{c.title || "—"}</td>
                                  <td className="cell-muted">{formatDate(c.createdAt)}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        )}
                      </td>
                    </tr>
                  )
                ];
              })}
            </tbody>
          </table>
        </div>
      </article>

      {/* Events lifecycle */}
      <article className="panel" style={{ marginBottom: 24 }}>
        <header className="panel-header"><h2>事件生命周期</h2><span className="panel-meta">{events.length} 个</span></header>

        <div style={{ padding: "12px 20px", borderBottom: "1px solid var(--border)", display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" }}>
          <div style={{ display: "flex", gap: 4 }}>
            {EVENT_TABS.map((tab) => (
              <button key={tab.key} className={"btn btn-sm " + (eventTab === tab.key ? "btn-primary" : "btn-secondary")} onClick={() => setEventTab(tab.key)}>{tab.label}</button>
            ))}
          </div>
          <select className="form-input" style={{ width: 140, padding: "4px 8px", fontSize: 13 }} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            {STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <input className="form-input" style={{ width: 200, padding: "4px 8px", fontSize: 13 }} placeholder="🔍 搜索..." value={searchQ} onChange={(e) => setSearchQ(e.target.value)} />
          {selectedIds.size > 0 && (
            <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
              <span style={{ fontSize: 13, color: "var(--text-muted)", alignSelf: "center" }}>已选 {selectedIds.size}</span>
              <button className="btn btn-sm btn-primary" onClick={() => void handleBulkAction("ack")}>确认</button>
              <button className="btn btn-sm btn-success" onClick={() => void handleBulkAction("resolved")}>解决</button>
              <button className="btn btn-sm btn-secondary" onClick={() => void handleBulkAction("ignored")}>忽略</button>
            </div>
          )}
        </div>

        {events.length === 0 ? (
          <div className="empty-state"><div className="empty-state-text">暂无事件</div></div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 32 }}><input type="checkbox" checked={selectedIds.size === events.length && events.length > 0} onChange={toggleAll} /></th>
                  <th>状态</th><th>类型</th><th>域名</th><th>IP</th><th>端口</th><th>服务</th><th>标题</th><th>首次</th><th>末次</th><th>次数</th><th>操作</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev: MonitorEvent) => (
                  <tr key={ev.id} style={{ cursor: "pointer" }} onClick={() => setDrawerEvent(ev)}>
                    <td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={selectedIds.has(ev.id)} onChange={() => toggleSel(ev.id)} /></td>
                    <td><StatusBadge status={ev.status} /></td>
                    <td><span className={changeTypeBadge(ev.eventType)}>{changeTypeLabel(ev.eventType)}</span></td>
                    <td className="cell-mono">{ev.domain || "—"}</td>
                    <td className="cell-mono">{ev.ip || "—"}</td>
                    <td>{ev.port > 0 ? ev.port : "—"}</td>
                    <td>{ev.service || "—"}</td>
                    <td>{ev.title || "—"}</td>
                    <td className="cell-muted">{formatDate(ev.firstSeenAt)}</td>
                    <td className="cell-muted">{formatDate(ev.lastSeenAt)}</td>
                    <td>{ev.occurrenceCount}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div style={{ display: "flex", gap: 4 }}>
                        {ev.status === "open" && <button className="btn btn-sm btn-primary" onClick={() => void handleEventAction(ev.id, "ack")}>确认</button>}
                        {ev.status !== "resolved" && <button className="btn btn-sm btn-success" onClick={() => void handleEventAction(ev.id, "resolved")}>解决</button>}
                        {ev.status !== "ignored" && <button className="btn btn-sm btn-secondary" onClick={() => void handleEventAction(ev.id, "ignored")}>忽略</button>}
                        {ev.status !== "open" && <button className="btn btn-sm btn-warning" onClick={() => void handleEventAction(ev.id, "open")}>重开</button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </article>

      {/* Event Detail Drawer */}
      {drawerEvent && (
        <div style={{ position: "fixed", top: 0, right: 0, bottom: 0, width: 420, background: "var(--bg-primary)", borderLeft: "1px solid var(--border)", boxShadow: "-4px 0 24px rgba(0,0,0,0.15)", zIndex: 1000, overflow: "auto", padding: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
            <h3>事件详情 #{drawerEvent.id}</h3>
            <button className="btn btn-sm btn-secondary" onClick={() => setDrawerEvent(null)}>✕</button>
          </div>
          <div style={{ display: "grid", gap: 8, fontSize: 14 }}>
            <div><strong>状态：</strong><StatusBadge status={drawerEvent.status} /></div>
            <div><strong>类型：</strong><span className={changeTypeBadge(drawerEvent.eventType)}>{changeTypeLabel(drawerEvent.eventType)}</span></div>
            <div><strong>域名：</strong>{drawerEvent.domain || "—"}</div>
            <div><strong>URL：</strong>{drawerEvent.url || "—"}</div>
            <div><strong>IP：</strong>{drawerEvent.ip || "—"}</div>
            <div><strong>端口：</strong>{drawerEvent.port > 0 ? drawerEvent.port : "—"}</div>
            <div><strong>协议：</strong>{drawerEvent.protocol || "—"}</div>
            <div><strong>服务：</strong>{drawerEvent.service || "—"} {drawerEvent.version || ""}</div>
            <div><strong>标题：</strong>{drawerEvent.title || "—"}</div>
            <div><strong>HTTP：</strong>{drawerEvent.statusCode > 0 ? drawerEvent.statusCode : "—"}</div>
            <div><strong>首次发现：</strong>{formatDate(drawerEvent.firstSeenAt)}</div>
            <div><strong>末次发现：</strong>{formatDate(drawerEvent.lastSeenAt)}</div>
            <div><strong>末次变更：</strong>{formatDate(drawerEvent.lastChangedAt)}</div>
            <div><strong>出现次数：</strong>{drawerEvent.occurrenceCount}</div>
            {drawerEvent.resolvedAt && <div><strong>解决时间：</strong>{formatDate(drawerEvent.resolvedAt)}</div>}
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 20 }}>
            {drawerEvent.status === "open" && <button className="btn btn-primary" onClick={() => { void handleEventAction(drawerEvent.id, "ack"); setDrawerEvent(null); }}>确认</button>}
            {drawerEvent.status !== "resolved" && <button className="btn btn-success" onClick={() => { void handleEventAction(drawerEvent.id, "resolved"); setDrawerEvent(null); }}>解决</button>}
            {drawerEvent.status !== "ignored" && <button className="btn btn-secondary" onClick={() => { void handleEventAction(drawerEvent.id, "ignored"); setDrawerEvent(null); }}>忽略</button>}
            {drawerEvent.status !== "open" && <button className="btn btn-warning" onClick={() => { void handleEventAction(drawerEvent.id, "open"); setDrawerEvent(null); }}>重开</button>}
          </div>
        </div>
      )}

      {/* Add Monitor Modal */}
      {showAddModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 2000, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ background: "var(--bg-primary)", borderRadius: 12, padding: 24, width: 400 }}>
            <h3 style={{ marginBottom: 16 }}>添加监控目标</h3>
            <label style={{ display: "block", marginBottom: 8, fontSize: 13 }}>根域名</label>
            <input className="form-input" style={{ width: "100%", marginBottom: 12, padding: "8px 12px" }} value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="example.com" />
            <label style={{ display: "block", marginBottom: 8, fontSize: 13 }}>检查间隔</label>
            <select className="form-input" style={{ width: "100%", marginBottom: 16, padding: "8px 12px" }} value={newInterval} onChange={(e) => setNewInterval(Number(e.target.value))}>
              <option value={3600}>每 1 小时</option>
              <option value={7200}>每 2 小时</option>
              <option value={14400}>每 4 小时</option>
              <option value={21600}>每 6 小时 (默认)</option>
              <option value={43200}>每 12 小时</option>
              <option value={86400}>每 24 小时</option>
            </select>
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button className="btn btn-secondary" onClick={() => setShowAddModal(false)} disabled={submitting}>取消</button>
              <button className="btn btn-primary" onClick={() => void handleAdd()} disabled={submitting || !newDomain.trim()}>{submitting ? "添加中..." : "确定"}</button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
