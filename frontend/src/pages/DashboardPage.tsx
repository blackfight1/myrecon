import ReactECharts from "echarts-for-react";
import { useMemo } from "react";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatCard } from "../components/ui/StatCard";
import { useWorkspace } from "../context/WorkspaceContext";
import { useAssets, useJobs, useMonitorChanges, usePorts, useVulns } from "../hooks/queries";
import { matchesProjectDomain } from "../lib/projectScope";

function hostnameFromUrl(input?: string): string | undefined {
  if (!input) return undefined;
  try { return new URL(input).hostname; } catch { return undefined; }
}

function isWithinHours(input: string | undefined, hours: number): boolean {
  if (!input) return false;
  const d = new Date(input);
  if (Number.isNaN(d.getTime())) return false;
  return Date.now() - d.getTime() <= hours * 3600 * 1000;
}

function keyByDay(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

export function DashboardPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];

  const jobsQ = useJobs();
  const assetsQ = useAssets();
  const portsQ = usePorts();
  const vulnsQ = useVulns();
  const monitorQ = useMonitorChanges();

  const scoped = useMemo(() => {
    const jobs = (jobsQ.data ?? []).filter((j) => matchesProjectDomain(j.rootDomain, rootDomains));
    const assets = (assetsQ.data ?? []).filter((a) =>
      matchesProjectDomain(a.domain, rootDomains) || matchesProjectDomain(hostnameFromUrl(a.url), rootDomains)
    );
    const assetIps = new Set(assets.map((a) => a.ip).filter(Boolean));
    const ports = (portsQ.data ?? []).filter((p) =>
      matchesProjectDomain(p.domain, rootDomains) || (p.ip && assetIps.has(p.ip))
    );
    const vulns = (vulnsQ.data ?? []).filter((v) =>
      matchesProjectDomain(v.rootDomain, rootDomains) || matchesProjectDomain(v.domain, rootDomains) ||
      matchesProjectDomain(v.host, rootDomains) || matchesProjectDomain(hostnameFromUrl(v.url), rootDomains)
    );
    const changes = (monitorQ.data ?? []).filter((c) => matchesProjectDomain(c.rootDomain, rootDomains));
    return { jobs, assets, ports, vulns, changes };
  }, [jobsQ.data, assetsQ.data, portsQ.data, vulnsQ.data, monitorQ.data, rootDomains]);

  const metrics = useMemo(() => {
    const st = (s: string) => String(s).toLowerCase();
    const running = scoped.jobs.filter((j) => { const s = st(j.status); return s.includes("running") || s.includes("pending"); }).length;
    const success24h = scoped.jobs.filter((j) => { const s = st(j.status); return (s.includes("ok") || s.includes("success") || s.includes("done")) && isWithinHours(j.finishedAt ?? j.startedAt, 24); }).length;
    const failed24h = scoped.jobs.filter((j) => { const s = st(j.status); return (s.includes("fail") || s.includes("error")) && isWithinHours(j.finishedAt ?? j.startedAt, 24); }).length;
    const newSubs24h = scoped.assets.filter((a) => isWithinHours(a.createdAt ?? a.updatedAt, 24)).length;
    const newPorts24h = scoped.ports.filter((p) => isWithinHours(p.lastSeen ?? p.updatedAt, 24)).length;
    const newVulns24h = scoped.vulns.filter((v) => isWithinHours(v.matchedAt ?? v.lastSeen, 24)).length;
    const monitorSignals24h = scoped.changes.filter((c) => isWithinHours(c.createdAt, 24)).length;
    const riskIndex = Math.min(100, newVulns24h * 12 + failed24h * 8 + running * 4 + Math.round(monitorSignals24h * 1.5));
    return { running, success24h, failed24h, newSubs24h, newPorts24h, newVulns24h, monitorSignals24h, riskIndex };
  }, [scoped]);

  const trend = useMemo(() => {
    const buckets: Record<string, { label: string; subdomains: number; ports: number; vulns: number }> = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
      const k = keyByDay(d);
      buckets[k] = { label: `${d.getMonth() + 1}/${d.getDate()}`, subdomains: 0, ports: 0, vulns: 0 };
    }
    for (const a of scoped.assets) { const b = a.lastSeen ?? a.updatedAt ?? a.createdAt; if (!b) continue; const d = new Date(b); if (!Number.isNaN(d.getTime())) { const k = keyByDay(d); if (buckets[k]) buckets[k].subdomains++; } }
    for (const p of scoped.ports) { const b = p.lastSeen ?? p.updatedAt; if (!b) continue; const d = new Date(b); if (!Number.isNaN(d.getTime())) { const k = keyByDay(d); if (buckets[k]) buckets[k].ports++; } }
    for (const v of scoped.vulns) { const b = v.matchedAt ?? v.lastSeen; const d = new Date(b); if (!Number.isNaN(d.getTime())) { const k = keyByDay(d); if (buckets[k]) buckets[k].vulns++; } }
    return Object.values(buckets);
  }, [scoped.assets, scoped.ports, scoped.vulns]);

  const loading = jobsQ.isLoading || assetsQ.isLoading || portsQ.isLoading || vulnsQ.isLoading;

  const chartOption = {
    tooltip: { trigger: "axis" as const },
    legend: { textStyle: { color: "#9398a8" } },
    grid: { left: 16, right: 18, top: 42, bottom: 20, containLabel: true },
    xAxis: { type: "category" as const, data: trend.map((t) => t.label), axisLabel: { color: "#6b7080" }, axisLine: { lineStyle: { color: "#2a2e3a" } } },
    yAxis: { type: "value" as const, axisLabel: { color: "#6b7080" }, splitLine: { lineStyle: { color: "#1c1f2a" } } },
    series: [
      { name: "Subdomains", type: "line" as const, smooth: true, data: trend.map((t) => t.subdomains), itemStyle: { color: "#34d399" }, lineStyle: { color: "#34d399" } },
      { name: "Ports", type: "line" as const, smooth: true, data: trend.map((t) => t.ports), itemStyle: { color: "#60a5fa" }, lineStyle: { color: "#60a5fa" } },
      { name: "Vulns", type: "line" as const, smooth: true, data: trend.map((t) => t.vulns), itemStyle: { color: "#f87171" }, lineStyle: { color: "#f87171" } }
    ]
  };

  const sevCounts = useMemo(() => {
    const out = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of scoped.vulns) { const s = (v.severity ?? "").toLowerCase(); if (s in out) out[s as keyof typeof out]++; }
    return out;
  }, [scoped.vulns]);

  const sevPieOption = {
    tooltip: { trigger: "item" as const },
    legend: { show: false },
    series: [{
      type: "pie" as const, radius: ["45%", "70%"], center: ["50%", "50%"],
      label: { color: "#9398a8", fontSize: 11 },
      data: [
        { value: sevCounts.critical, name: "Critical", itemStyle: { color: "#ef4444" } },
        { value: sevCounts.high, name: "High", itemStyle: { color: "#f97316" } },
        { value: sevCounts.medium, name: "Medium", itemStyle: { color: "#eab308" } },
        { value: sevCounts.low, name: "Low", itemStyle: { color: "#22c55e" } }
      ].filter((d) => d.value > 0)
    }]
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <p className="page-desc">Project-level control plane — metrics computed from pipeline data filtered by active project scope.</p>
      </div>

      <ProjectScopeBanner title="Scope" hint={`Viewing data for ${rootDomains.length} root domain(s) in ${activeProject?.name ?? "—"}`} />

      {loading && <div className="empty-state">Loading scoped metrics...</div>}

      <div className="stats-row">
        <StatCard label="Risk Index" value={metrics.riskIndex} accent={metrics.riskIndex >= 70 ? "danger" : metrics.riskIndex >= 40 ? "warning" : "blue"} hint="Composite score" />
        <StatCard label="Jobs Running" value={metrics.running} accent="blue" hint="Active queue" />
        <StatCard label="Success (24h)" value={metrics.success24h} accent="success" hint="Completed OK" />
        <StatCard label="Failed (24h)" value={metrics.failed24h} accent="danger" hint="Needs attention" />
        <StatCard label="New Subdomains" value={metrics.newSubs24h} accent="success" hint="Last 24h" />
        <StatCard label="New Ports" value={metrics.newPorts24h} accent="warning" hint="Exposure drift" />
        <StatCard label="New Vulns" value={metrics.newVulns24h} accent="danger" hint="Triage queue" />
        <StatCard label="Monitor Signals" value={metrics.monitorSignals24h} accent="blue" hint="Last 24h" />
      </div>

      <div className="two-col">
        <article className="panel">
          <header className="panel-header">
            <h2>7-Day Signal Trend</h2>
            <span className="panel-meta">{activeProject?.name ?? "No project"}</span>
          </header>
          <div className="chart-container">
            <ReactECharts option={chartOption} style={{ height: 280 }} />
          </div>
        </article>

        <article className="panel">
          <header className="panel-header">
            <h2>Severity Distribution</h2>
            <span className="panel-meta">{scoped.vulns.length} total findings</span>
          </header>
          <div className="chart-container">
            {scoped.vulns.length > 0 ? (
              <ReactECharts option={sevPieOption} style={{ height: 280 }} />
            ) : (
              <div className="empty-state">No vulnerability data</div>
            )}
          </div>
        </article>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>Pipeline Flow</h2>
          <span className="panel-meta">project → subs → dictgen → brute → ports → nuclei → monitor</span>
        </header>
        <div className="workflow-grid">
          <div className="workflow-step">
            <span className="workflow-step-tag">project</span>
            <p>Every view scoped to selected project root domains.</p>
          </div>
          <div className="workflow-step">
            <span className="workflow-step-tag">passive subs</span>
            <p>Findomain / Subfinder / BBOT feed baseline target map.</p>
          </div>
          <div className="workflow-step">
            <span className="workflow-step-tag">dictgen + brute</span>
            <p>Generate custom dictionaries, run active expansion.</p>
          </div>
          <div className="workflow-step">
            <span className="workflow-step-tag">ports</span>
            <p>Naabu + Nmap identify service exposure.</p>
          </div>
          <div className="workflow-step">
            <span className="workflow-step-tag danger">nuclei</span>
            <p>Findings tied to root domain for triage.</p>
          </div>
          <div className="workflow-step">
            <span className="workflow-step-tag">monitor</span>
            <p>Debounced change events for drift detection.</p>
          </div>
        </div>
      </article>
    </section>
  );
}
