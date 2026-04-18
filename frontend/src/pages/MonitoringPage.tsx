import { useEffect, useMemo, useState } from "react";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatCard } from "../components/ui/StatCard";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import {
  useBulkMonitorEventStatus,
  useCreateMonitorTarget,
  useDeleteMonitorTarget,
  useMonitorDiff,
  useMonitorEvents,
  useMonitorRuns,
  useMonitorTargets,
  usePatchMonitorEventStatus,
  useStopMonitorTarget,
  useUpdateMonitorTarget
} from "../hooks/queries";
import { formatDate, formatDateYMD } from "../lib/format";
import { matchesProjectDomain, normalizeRootDomain } from "../lib/projectScope";
import type { MonitorEvent, MonitorRun, MonitorTarget } from "../types/models";

const EVENT_TYPE_OPTIONS = [
  { key: "all", label: "All Types" },
  { key: "new_live", label: "New Live" },
  { key: "web_changed", label: "Web Changed" },
  { key: "live_resolved", label: "Live Resolved" },
  { key: "port_opened", label: "Port Opened" },
  { key: "port_closed", label: "Port Closed" },
  { key: "service_changed", label: "Service Changed" }
] as const;

const STATUS_OPTIONS = [
  { value: "", label: "All Status" },
  { value: "open", label: "Open" },
  { value: "ack", label: "Ack" },
  { value: "resolved", label: "Resolved" },
  { value: "ignored", label: "Ignored" }
] as const;

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

function toTs(val?: string): number {
  if (!val) return 0;
  const ts = new Date(val).getTime();
  return Number.isFinite(ts) ? ts : 0;
}

function changeTypeLabel(t?: string): string {
  const k = (t || "").toLowerCase();
  const m: Record<string, string> = {
    new_live: "New Live",
    web_changed: "Web Changed",
    live_resolved: "Live Resolved",
    port_opened: "Port Opened",
    port_closed: "Port Closed",
    opened: "Port Opened",
    closed: "Port Closed",
    service_changed: "Service Changed"
  };
  return m[k] || (t || "-");
}

function summarizePolicy(t: MonitorTarget): string {
  const scope = t.monitorPorts === false ? "Asset only" : "Asset + Port";
  if (!t.enableVulnScan) return `${scope} | Incremental vuln scan: OFF`;

  const engines: string[] = [];
  if (t.enableNuclei) engines.push("Nuclei");
  if (t.enableCors) engines.push("CORS");
  if (t.enableSubtakeover) engines.push("SubTakeover");

  const triggers: string[] = [];
  if (t.vulnOnNewLive !== false) triggers.push("new_live");
  if (t.vulnOnWebChanged) triggers.push("web_changed");

  return `${scope} | Engines: ${engines.join("+") || "none"} | Triggers: ${triggers.join("+") || "none"} | Max ${t.vulnMaxUrls ?? 50} | CD ${t.vulnCooldownMin ?? 30}m`;
}

function latestRunByDomain(runs: MonitorRun[]): Map<string, MonitorRun> {
  const sorted = [...runs].sort((a, b) => toTs(b.startedAt) - toTs(a.startedAt));
  const map = new Map<string, MonitorRun>();
  for (const r of sorted) {
    if (!map.has(r.rootDomain)) map.set(r.rootDomain, r);
  }
  return map;
}

export function MonitoringPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const rootDomains = activeProject?.rootDomains ?? [];

  const [targetSearch, setTargetSearch] = useState("");
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [selectedRunID, setSelectedRunID] = useState<number | undefined>(undefined);
  const [selectedEventID, setSelectedEventID] = useState<number | undefined>(undefined);
  const [eventType, setEventType] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("open");
  const [eventSearch, setEventSearch] = useState("");

  const [showPolicyModal, setShowPolicyModal] = useState(false);
  const [editingTarget, setEditingTarget] = useState<MonitorTarget | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const [newDomain, setNewDomain] = useState("");
  const [newInterval, setNewInterval] = useState(21600);
  const [newMonitorPorts, setNewMonitorPorts] = useState(true);
  const [newNotifyAISummary, setNewNotifyAISummary] = useState(false);
  const [newEnableVulnScan, setNewEnableVulnScan] = useState(false);
  const [newEnableNuclei, setNewEnableNuclei] = useState(false);
  const [newEnableCors, setNewEnableCors] = useState(false);
  const [newEnableSubtakeover, setNewEnableSubtakeover] = useState(false);
  const [newVulnOnNewLive, setNewVulnOnNewLive] = useState(true);
  const [newVulnOnWebChanged, setNewVulnOnWebChanged] = useState(false);
  const [newVulnMaxUrls, setNewVulnMaxUrls] = useState(50);
  const [newVulnCooldownMin, setNewVulnCooldownMin] = useState(30);

  const targetsQ = useMonitorTargets(projectId);
  const runsQ = useMonitorRuns(projectId);
  const openEventsAllQ = useMonitorEvents(projectId, undefined, "open");
  const eventsQ = useMonitorEvents(
    projectId,
    selectedDomain || undefined,
    statusFilter || undefined,
    eventType === "all" ? undefined : eventType,
    eventSearch.trim() || undefined
  );
  const diffQ = useMonitorDiff(projectId, selectedRunID, selectedDomain || undefined, 150);

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
  const openEventsAll = useMemo(
    () => (openEventsAllQ.data ?? []).filter((e: MonitorEvent) => matchesProjectDomain(e.rootDomain, rootDomains)),
    [openEventsAllQ.data, rootDomains]
  );
  const events = useMemo(
    () => (eventsQ.data ?? []).filter((e: MonitorEvent) => matchesProjectDomain(e.rootDomain, rootDomains)),
    [eventsQ.data, rootDomains]
  );

  const targetList = useMemo(() => {
    const q = targetSearch.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter((t) => t.rootDomain.toLowerCase().includes(q));
  }, [targets, targetSearch]);

  const latestRunMap = useMemo(() => latestRunByDomain(runs), [runs]);
  const openCountMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const e of openEventsAll) map.set(e.rootDomain, (map.get(e.rootDomain) || 0) + 1);
    return map;
  }, [openEventsAll]);
  const new24hMap = useMemo(() => {
    const map = new Map<string, number>();
    const cutoff = Date.now() - 24 * 3600 * 1000;
    for (const r of runs) {
      if (toTs(r.startedAt) < cutoff) continue;
      map.set(r.rootDomain, (map.get(r.rootDomain) || 0) + (r.newLiveCount || 0));
    }
    return map;
  }, [runs]);

  const selectedTarget = useMemo(() => targets.find((t) => t.rootDomain === selectedDomain), [targets, selectedDomain]);
  const selectedRuns = useMemo(
    () => runs.filter((r) => r.rootDomain === selectedDomain).sort((a, b) => toTs(b.startedAt) - toTs(a.startedAt)),
    [runs, selectedDomain]
  );
  const selectedEvent = useMemo(() => events.find((e) => e.id === selectedEventID) || events[0], [events, selectedEventID]);

  useEffect(() => {
    if (!targets.length) {
      setSelectedDomain("");
      return;
    }
    if (!selectedDomain || !targets.some((t) => t.rootDomain === selectedDomain)) {
      const preferred = targets.find((t) => t.enabled) || targets[0];
      setSelectedDomain(preferred.rootDomain);
    }
  }, [targets, selectedDomain]);

  useEffect(() => {
    if (!selectedRuns.length) {
      setSelectedRunID(undefined);
      return;
    }
    if (!selectedRunID || !selectedRuns.some((r) => r.id === selectedRunID)) {
      setSelectedRunID(selectedRuns[0].id);
    }
  }, [selectedRuns, selectedRunID]);

  useEffect(() => {
    if (!events.length) {
      setSelectedEventID(undefined);
      return;
    }
    if (!selectedEventID || !events.some((e) => e.id === selectedEventID)) {
      setSelectedEventID(events[0].id);
    }
  }, [events, selectedEventID]);

  const totalOpenEvents = openEventsAll.length;
  const totalNew24h = Array.from(new24hMap.values()).reduce((acc, n) => acc + n, 0);
  const activeTargets = targets.filter((t) => t.enabled).length;
  const selectedOpenCount = selectedDomain ? openCountMap.get(selectedDomain) || 0 : 0;

  const resetPolicyForm = () => {
    setEditingTarget(null);
    setNewDomain(rootDomains[0] ?? "");
    setNewInterval(21600);
    setNewMonitorPorts(true);
    setNewNotifyAISummary(false);
    setNewEnableVulnScan(false);
    setNewEnableNuclei(false);
    setNewEnableCors(false);
    setNewEnableSubtakeover(false);
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
    setNewInterval(target.intervalSec || 21600);
    setNewMonitorPorts(target.monitorPorts !== false);
    setNewNotifyAISummary(Boolean(target.notifyAiSummary));
    setNewEnableVulnScan(Boolean(target.enableVulnScan));
    setNewEnableNuclei(Boolean(target.enableNuclei));
    setNewEnableCors(Boolean(target.enableCors));
    setNewEnableSubtakeover(Boolean(target.enableSubtakeover));
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
    if (!projectId || !domain) {
      setFeedback({ ok: false, text: "Project and domain are required." });
      return false;
    }
    if (!matchesProjectDomain(domain, rootDomains)) {
      setFeedback({ ok: false, text: "Domain is outside current project scope." });
      return false;
    }
    if (newEnableVulnScan && !newEnableNuclei && !newEnableCors && !newEnableSubtakeover) {
      setFeedback({ ok: false, text: "Enable at least one engine when incremental vuln scan is ON." });
      return false;
    }
    if (newEnableVulnScan && !newVulnOnNewLive && !newVulnOnWebChanged) {
      setFeedback({ ok: false, text: "Enable at least one trigger (new_live / web_changed)." });
      return false;
    }
    return true;
  };

  const buildPolicyPayload = () => {
    const maxUrls = Math.min(1000, Math.max(1, newVulnMaxUrls || 50));
    const cooldownMin = Math.min(1440, Math.max(1, newVulnCooldownMin || 30));
    return {
      monitorPorts: newMonitorPorts,
      notifyAiSummary: newNotifyAISummary,
      enableVulnScan: newEnableVulnScan,
      enableNuclei: newEnableVulnScan ? newEnableNuclei : false,
      enableCors: newEnableVulnScan ? newEnableCors : false,
      enableSubtakeover: newEnableVulnScan ? newEnableSubtakeover : false,
      vulnOnNewLive: newEnableVulnScan ? newVulnOnNewLive : true,
      vulnOnWebChanged: newEnableVulnScan ? newVulnOnWebChanged : false,
      vulnMaxUrls: newEnableVulnScan ? maxUrls : 50,
      vulnCooldownMin: newEnableVulnScan ? cooldownMin : 30
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
        await updateMonitor.mutateAsync({ projectId, domain, ...payload });
        setFeedback({ ok: true, text: `Policy updated: ${domain}` });
      } else {
        await createMonitor.mutateAsync({ projectId, domain, intervalSec: newInterval, ...payload });
        setFeedback({ ok: true, text: `Target created: ${domain}` });
      }
      closePolicyModal();
      resetPolicyForm();
    } catch (e) {
      setFeedback({ ok: false, text: `Save failed: ${errMsg(e)}` });
    } finally {
      setSubmitting(false);
    }
  };

  const handleEventAction = async (eventId: number, status: string) => {
    if (!projectId) return;
    try {
      await patchStatus.mutateAsync({ projectId, eventId, status });
      setFeedback({ ok: true, text: `Event #${eventId} => ${status}` });
    } catch (e) {
      setFeedback({ ok: false, text: `Event update failed: ${errMsg(e)}` });
    }
  };

  const handleBulkAction = async (status: "ack" | "resolved" | "ignored") => {
    if (!projectId) return;
    const ids = events.filter((e) => e.status === "open").slice(0, 200).map((e) => e.id);
    if (!ids.length) return;
    try {
      await bulkStatus.mutateAsync({ projectId, eventIds: ids, status });
      setFeedback({ ok: true, text: `Bulk updated ${ids.length} open events => ${status}` });
    } catch (e) {
      setFeedback({ ok: false, text: `Bulk action failed: ${errMsg(e)}` });
    }
  };

  const handleStop = async (domain: string) => {
    if (!projectId || !confirm(`Stop monitor for ${domain}?`)) return;
    try {
      await stopMonitor.mutateAsync({ projectId, domain });
      setFeedback({ ok: true, text: `Stopped: ${domain}` });
    } catch (e) {
      setFeedback({ ok: false, text: `Stop failed: ${errMsg(e)}` });
    }
  };

  const handleEnable = async (domain: string) => {
    if (!projectId) return;
    try {
      await createMonitor.mutateAsync({ projectId, domain });
      setFeedback({ ok: true, text: `Enabled: ${domain}` });
    } catch (e) {
      setFeedback({ ok: false, text: `Enable failed: ${errMsg(e)}` });
    }
  };

  const handleDelete = async (domain: string) => {
    if (!projectId || !confirm(`Delete monitor data for ${domain}?`)) return;
    try {
      await deleteMonitor.mutateAsync({ projectId, domain });
      setFeedback({ ok: true, text: `Deleted: ${domain}` });
    } catch (e) {
      setFeedback({ ok: false, text: `Delete failed: ${errMsg(e)}` });
    }
  };

  const loading = targetsQ.isLoading || runsQ.isLoading || eventsQ.isLoading;

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">Monitoring Workbench</h1>
        <p className="page-desc">Left: targets. Center: event queue. Right: context and run diff.</p>
      </div>

      <ProjectScopeBanner title="Scope" hint="Only resources in current project scope are displayed." />

      {feedback && (
        <div className={`inline-feedback ${feedback.ok ? "ok" : "error"}`}>
          <span>{feedback.text}</span>
          <button className="btn btn-ghost btn-sm" onClick={() => setFeedback(null)}>
            Close
          </button>
        </div>
      )}

      <div className="stats-row">
        <StatCard label="Open Events" value={totalOpenEvents} icon="!" accent="danger" />
        <StatCard label="New Assets (24h)" value={totalNew24h} icon="+" accent="blue" />
        <StatCard label="Targets" value={`${activeTargets}/${targets.length}`} icon="*" />
        <StatCard label="Open (Selected)" value={selectedOpenCount} icon="*" accent="warning" />
      </div>

      {loading && <div className="empty-state">Loading monitoring data...</div>}

      <div className="monitor-workbench">
        <aside className="panel monitor-pane">
          <header className="panel-header">
            <h2>Targets</h2>
            <div className="toolbar-group">
              <span className="panel-meta">{targets.length}</span>
              <button className="btn btn-primary btn-sm" onClick={openCreateModal} disabled={!projectId}>
                + New
              </button>
            </div>
          </header>
          <div className="panel-body">
            <input className="form-input" placeholder="Search root domain..." value={targetSearch} onChange={(e) => setTargetSearch(e.target.value)} />
            <div className="monitor-target-list">
              {targetList.map((t) => {
                const latest = latestRunMap.get(t.rootDomain);
                const openCnt = openCountMap.get(t.rootDomain) || 0;
                const new24h = new24hMap.get(t.rootDomain) || 0;
                return (
                  <button key={t.id} className={`monitor-target-item ${selectedDomain === t.rootDomain ? "active" : ""}`} onClick={() => setSelectedDomain(t.rootDomain)}>
                    <div className="monitor-target-row">
                      <span className="monitor-target-domain">{t.rootDomain}</span>
                      <span className={`badge ${t.enabled ? "badge-success" : "badge-danger"}`}>{t.enabled ? "Enabled" : "Disabled"}</span>
                    </div>
                    <div className="monitor-target-meta">
                      <span>Open: {openCnt}</span>
                      <span>New24h: {new24h}</span>
                      <span>Last: {formatDate(latest?.startedAt || t.lastRunAt)}</span>
                    </div>
                  </button>
                );
              })}
              {targetList.length === 0 && <div className="empty-state empty-state-compact">No targets</div>}
            </div>
          </div>
        </aside>

        <section className="panel monitor-pane">
          <header className="panel-header">
            <h2>Event Queue</h2>
            <div className="toolbar-group">
              <span className="panel-meta">{selectedDomain || "All targets"}</span>
              <span className="panel-meta">{events.length} rows</span>
            </div>
          </header>
          <div className="panel-body panel-body-flush">
            <div className="filter-bar monitor-filter-bar monitor-queue-toolbar">
              <select className="form-select" value={eventType} onChange={(e) => setEventType(e.target.value)}>
                {EVENT_TYPE_OPTIONS.map((o) => (
                  <option key={o.key} value={o.key}>
                    {o.label}
                  </option>
                ))}
              </select>
              <select className="form-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
                {STATUS_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
              <input className="form-input" placeholder="Search domain/ip/title..." value={eventSearch} onChange={(e) => setEventSearch(e.target.value)} />
              <div className="toolbar-group">
                <button className="btn btn-sm btn-secondary" onClick={() => void handleBulkAction("ack")}>
                  Bulk Ack
                </button>
                <button className="btn btn-sm btn-success" onClick={() => void handleBulkAction("resolved")}>
                  Bulk Resolve
                </button>
                <button className="btn btn-sm btn-warning" onClick={() => void handleBulkAction("ignored")}>
                  Bulk Ignore
                </button>
              </div>
            </div>

            {events.length === 0 ? (
              <div className="empty-state empty-state-compact">No events under current filters</div>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Type</th>
                      <th>Asset</th>
                      <th>Port</th>
                      <th>Title/Service</th>
                      <th>Discovered</th>
                      <th>Last Seen</th>
                      <th>Count</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((ev) => {
                      const active = selectedEvent?.id === ev.id;
                      return (
                        <tr key={ev.id} className={active ? "monitor-event-row-active" : ""} onClick={() => setSelectedEventID(ev.id)} style={{ cursor: "pointer" }}>
                          <td>
                            <StatusBadge status={ev.status} />
                          </td>
                          <td>{changeTypeLabel(ev.eventType)}</td>
                          <td className="cell-mono">{ev.url || ev.domain || "-"}</td>
                          <td>{ev.port ? `${ev.protocol || "tcp"}/${ev.port}` : "-"}</td>
                          <td>{ev.title || ev.service || "-"}</td>
                          <td className="cell-muted">{formatDateYMD(ev.firstSeenAt)}</td>
                          <td className="cell-muted">{formatDate(ev.lastSeenAt)}</td>
                          <td>{ev.occurrenceCount}</td>
                          <td>
                            <div className="row-actions">
                              {ev.status === "open" && (
                                <button
                                  className="btn btn-sm btn-primary"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    void handleEventAction(ev.id, "ack");
                                  }}
                                >
                                  Ack
                                </button>
                              )}
                              {ev.status !== "resolved" && (
                                <button
                                  className="btn btn-sm btn-success"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    void handleEventAction(ev.id, "resolved");
                                  }}
                                >
                                  Resolve
                                </button>
                              )}
                              {ev.status !== "ignored" && (
                                <button
                                  className="btn btn-sm btn-secondary"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    void handleEventAction(ev.id, "ignored");
                                  }}
                                >
                                  Ignore
                                </button>
                              )}
                              {ev.status !== "open" && (
                                <button
                                  className="btn btn-sm btn-warning"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    void handleEventAction(ev.id, "open");
                                  }}
                                >
                                  Reopen
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>

        <aside className="panel monitor-pane">
          <header className="panel-header">
            <h2>Context</h2>
            <div className="toolbar-group">
              {selectedTarget && (
                <>
                  <button className="btn btn-sm btn-secondary" onClick={() => openEditModal(selectedTarget)}>
                    Policy
                  </button>
                  {selectedTarget.enabled ? (
                    <button className="btn btn-sm btn-warning" onClick={() => void handleStop(selectedTarget.rootDomain)}>
                      Stop
                    </button>
                  ) : (
                    <button className="btn btn-sm btn-primary" onClick={() => void handleEnable(selectedTarget.rootDomain)}>
                      Enable
                    </button>
                  )}
                  <button className="btn btn-sm btn-danger" onClick={() => void handleDelete(selectedTarget.rootDomain)}>
                    Delete
                  </button>
                </>
              )}
            </div>
          </header>
          <div className="panel-body">
            {!selectedTarget && <div className="empty-state empty-state-compact">Please select a target</div>}
            {selectedTarget && (
              <div className="monitor-context-stack">
                <div className="monitor-context-card">
                  <div className="monitor-context-title">{selectedTarget.rootDomain}</div>
                  <div className="monitor-context-desc">{summarizePolicy(selectedTarget)}</div>
                  <div className="monitor-context-kv">
                    <span>Status</span>
                    <span className={selectedTarget.enabled ? "text-success" : "text-danger"}>{selectedTarget.enabled ? "Enabled" : "Disabled"}</span>
                  </div>
                  <div className="monitor-context-kv">
                    <span>Baseline</span>
                    <span>{selectedTarget.baselineDone ? `v${Math.max(1, selectedTarget.baselineVersion || 1)}` : "Not built"}</span>
                  </div>
                  <div className="monitor-context-kv">
                    <span>Last Run</span>
                    <span>{formatDate(selectedTarget.lastRunAt)}</span>
                  </div>
                </div>

                <div className="monitor-context-card">
                  <div className="monitor-context-title">Selected Event</div>
                  {selectedEvent ? (
                    <>
                      <div className="monitor-context-kv">
                        <span>Type</span>
                        <span>{changeTypeLabel(selectedEvent.eventType)}</span>
                      </div>
                      <div className="monitor-context-kv">
                        <span>Status</span>
                        <span>
                          <StatusBadge status={selectedEvent.status} />
                        </span>
                      </div>
                      <div className="monitor-context-kv">
                        <span>Asset</span>
                        <span className="cell-mono">{selectedEvent.url || selectedEvent.domain || "-"}</span>
                      </div>
                      <div className="monitor-context-kv">
                        <span>IP/Port</span>
                        <span className="cell-mono">
                          {selectedEvent.ip || "-"} {selectedEvent.port ? `:${selectedEvent.port}` : ""}
                        </span>
                      </div>
                      <div className="monitor-context-kv">
                        <span>Title/Service</span>
                        <span>{selectedEvent.title || selectedEvent.service || "-"}</span>
                      </div>
                      <div className="monitor-context-kv">
                        <span>First Seen</span>
                        <span>{formatDateYMD(selectedEvent.firstSeenAt)}</span>
                      </div>
                      <div className="monitor-context-kv">
                        <span>Last Seen</span>
                        <span>{formatDate(selectedEvent.lastSeenAt)}</span>
                      </div>
                    </>
                  ) : (
                    <div className="monitor-context-desc">No selected event</div>
                  )}
                </div>

                <div className="monitor-context-card">
                  <div className="monitor-context-title">Run Diff</div>
                  <div className="form-group">
                    <label className="form-label">Run</label>
                    <select className="form-select" value={selectedRunID ?? ""} onChange={(e) => setSelectedRunID(e.target.value ? Number(e.target.value) : undefined)}>
                      <option value="">Auto latest</option>
                      {selectedRuns.slice(0, 100).map((run) => (
                        <option key={run.id} value={run.id}>
                          #{run.id} | {formatDate(run.startedAt)}
                        </option>
                      ))}
                    </select>
                  </div>
                  {diffQ.isLoading && <div className="monitor-context-desc">Loading diff...</div>}
                  {!diffQ.isLoading && !diffQ.data?.runId && <div className="monitor-context-desc">No diff data</div>}
                  {!diffQ.isLoading && diffQ.data?.runId && (
                    <>
                      <div className="monitor-context-kv">
                        <span>Compare</span>
                        <span>
                          #{diffQ.data.runId} {diffQ.data.prevRunId ? `vs #${diffQ.data.prevRunId}` : "(first run)"}
                        </span>
                      </div>
                      <div className="monitor-context-kv">
                        <span>Assets</span>
                        <span>
                          {diffQ.data.snapshot.assetCount} ({diffQ.data.delta.assetCount >= 0 ? "+" : ""}
                          {diffQ.data.delta.assetCount})
                        </span>
                      </div>
                      <div className="monitor-context-kv">
                        <span>Ports</span>
                        <span>
                          {diffQ.data.snapshot.portCount} ({diffQ.data.delta.portCount >= 0 ? "+" : ""}
                          {diffQ.data.delta.portCount})
                        </span>
                      </div>
                      <div className="monitor-context-kv">
                        <span>Open Events</span>
                        <span>
                          {diffQ.data.snapshot.openEventCount} ({diffQ.data.delta.openEventCount >= 0 ? "+" : ""}
                          {diffQ.data.delta.openEventCount})
                        </span>
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}
          </div>
        </aside>
      </div>

      {showPolicyModal && (
        <div className="modal-overlay" onClick={closePolicyModal}>
          <div className="modal-content monitor-policy-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editingTarget ? "Edit Monitor Policy" : "Create Monitor Target"}</h3>
              <button className="modal-close" onClick={closePolicyModal} disabled={submitting}>
                x
              </button>
            </div>

            <div className="modal-body">
              <div className="form-group">
                <label className="form-label">Root Domain</label>
                <input className="form-input" value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="example.com" readOnly={Boolean(editingTarget)} />
              </div>

              {!editingTarget && (
                <div className="form-group">
                  <label className="form-label">Interval</label>
                  <select className="form-select" value={newInterval} onChange={(e) => setNewInterval(Number(e.target.value))}>
                    <option value={3600}>Every 1h</option>
                    <option value={7200}>Every 2h</option>
                    <option value={14400}>Every 4h</option>
                    <option value={21600}>Every 6h (default)</option>
                    <option value={43200}>Every 12h</option>
                    <option value={86400}>Every 24h</option>
                  </select>
                </div>
              )}

              <div className="monitor-policy-box">
                <label className="form-checkbox">
                  <input type="checkbox" checked={newMonitorPorts} onChange={(e) => setNewMonitorPorts(e.target.checked)} />
                  Monitor port changes
                </label>
                <label className="form-checkbox">
                  <input type="checkbox" checked={newNotifyAISummary} onChange={(e) => setNewNotifyAISummary(e.target.checked)} />
                  Enable AI summary in notifications
                </label>
                <label className="form-checkbox">
                  <input type="checkbox" checked={newEnableVulnScan} onChange={(e) => setNewEnableVulnScan(e.target.checked)} />
                  Enable incremental vuln scan
                </label>

                {newEnableVulnScan && (
                  <>
                    <div className="monitor-policy-toggle-row">
                      <label className="form-checkbox">
                        <input type="checkbox" checked={newEnableNuclei} onChange={(e) => setNewEnableNuclei(e.target.checked)} />
                        Nuclei
                      </label>
                      <label className="form-checkbox">
                        <input type="checkbox" checked={newEnableCors} onChange={(e) => setNewEnableCors(e.target.checked)} />
                        CORS
                      </label>
                      <label className="form-checkbox">
                        <input type="checkbox" checked={newEnableSubtakeover} onChange={(e) => setNewEnableSubtakeover(e.target.checked)} />
                        SubTakeover
                      </label>
                    </div>
                    <div className="monitor-policy-toggle-row">
                      <label className="form-checkbox">
                        <input type="checkbox" checked={newVulnOnNewLive} onChange={(e) => setNewVulnOnNewLive(e.target.checked)} />
                        Trigger on new_live
                      </label>
                      <label className="form-checkbox">
                        <input type="checkbox" checked={newVulnOnWebChanged} onChange={(e) => setNewVulnOnWebChanged(e.target.checked)} />
                        Trigger on web_changed
                      </label>
                    </div>
                    <div className="form-row form-row-2">
                      <div className="form-group">
                        <label className="form-label">Max URLs / run</label>
                        <input className="form-input" type="number" min={1} max={1000} value={newVulnMaxUrls} onChange={(e) => setNewVulnMaxUrls(Number(e.target.value) || 50)} />
                      </div>
                      <div className="form-group">
                        <label className="form-label">Cooldown (min)</label>
                        <input className="form-input" type="number" min={1} max={1440} value={newVulnCooldownMin} onChange={(e) => setNewVulnCooldownMin(Number(e.target.value) || 30)} />
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={closePolicyModal} disabled={submitting}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={() => void handleSubmitPolicy()} disabled={submitting || !newDomain.trim()}>
                {submitting ? "Saving..." : editingTarget ? "Save Policy" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
