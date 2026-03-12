import ReactECharts from "echarts-for-react";
import { useMemo } from "react";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatCard } from "../components/ui/StatCard";
import { useWorkspace } from "../context/WorkspaceContext";
import { useAssets, useJobs, useMonitorChanges, usePorts, useVulns } from "../hooks/queries";
import { matchesProjectDomain } from "../lib/projectScope";

function hostnameFromUrl(input?: string): string | undefined {
  if (!input) {
    return undefined;
  }
  try {
    return new URL(input).hostname;
  } catch {
    return undefined;
  }
}

function isWithinHours(input: string | undefined, hours: number): boolean {
  if (!input) {
    return false;
  }
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) {
    return false;
  }
  return Date.now() - date.getTime() <= hours * 3600 * 1000;
}

function keyByDay(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

export function DashboardPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];

  const jobsQuery = useJobs();
  const assetsQuery = useAssets();
  const portsQuery = usePorts();
  const vulnsQuery = useVulns();
  const monitorQuery = useMonitorChanges();

  const scoped = useMemo(() => {
    const jobs = (jobsQuery.data ?? []).filter((job) => matchesProjectDomain(job.rootDomain, rootDomains));

    const assets = (assetsQuery.data ?? []).filter((item) => {
      return matchesProjectDomain(item.domain, rootDomains) || matchesProjectDomain(hostnameFromUrl(item.url), rootDomains);
    });

    const assetIps = new Set(assets.map((item) => item.ip).filter(Boolean));

    const ports = (portsQuery.data ?? []).filter((item) => {
      if (matchesProjectDomain(item.domain, rootDomains)) {
        return true;
      }
      if (item.ip && assetIps.has(item.ip)) {
        return true;
      }
      return false;
    });

    const vulns = (vulnsQuery.data ?? []).filter((item) => {
      return (
        matchesProjectDomain(item.rootDomain, rootDomains) ||
        matchesProjectDomain(item.domain, rootDomains) ||
        matchesProjectDomain(item.host, rootDomains) ||
        matchesProjectDomain(hostnameFromUrl(item.url), rootDomains)
      );
    });

    const changes = (monitorQuery.data ?? []).filter((item) => matchesProjectDomain(item.rootDomain, rootDomains));

    return { jobs, assets, ports, vulns, changes };
  }, [jobsQuery.data, assetsQuery.data, portsQuery.data, vulnsQuery.data, monitorQuery.data, rootDomains]);

  const metrics = useMemo(() => {
    const running = scoped.jobs.filter((job) => {
      const status = String(job.status).toLowerCase();
      return status.includes("running") || status.includes("pending");
    }).length;

    const success24h = scoped.jobs.filter((job) => {
      const status = String(job.status).toLowerCase();
      return (status.includes("ok") || status.includes("success") || status.includes("done")) && isWithinHours(job.finishedAt ?? job.startedAt, 24);
    }).length;

    const failed24h = scoped.jobs.filter((job) => {
      const status = String(job.status).toLowerCase();
      return (status.includes("fail") || status.includes("error")) && isWithinHours(job.finishedAt ?? job.startedAt, 24);
    }).length;

    const newSubdomains24h = scoped.assets.filter((asset) => isWithinHours(asset.createdAt ?? asset.updatedAt, 24)).length;
    const newPorts24h = scoped.ports.filter((port) => isWithinHours(port.lastSeen ?? port.updatedAt, 24)).length;
    const newVulns24h = scoped.vulns.filter((item) => isWithinHours(item.matchedAt ?? item.lastSeen, 24)).length;
    const monitorSignals24h = scoped.changes.filter((item) => isWithinHours(item.createdAt, 24)).length;

    const avgDuration = (() => {
      const values = scoped.jobs.map((item) => item.durationSec).filter((item): item is number => typeof item === "number" && item > 0);
      if (values.length === 0) {
        return 0;
      }
      const total = values.reduce((sum, current) => sum + current, 0);
      return Math.round(total / values.length);
    })();

    const riskIndex = Math.min(100, newVulns24h * 12 + failed24h * 8 + running * 4 + Math.round(monitorSignals24h * 1.5));

    return {
      running,
      success24h,
      failed24h,
      newSubdomains24h,
      newPorts24h,
      newVulns24h,
      monitorSignals24h,
      avgDuration,
      riskIndex
    };
  }, [scoped]);

  const trend = useMemo(() => {
    const buckets: Record<string, { label: string; subdomains: number; ports: number; vulnerabilities: number }> = {};

    for (let i = 6; i >= 0; i -= 1) {
      const day = new Date();
      day.setHours(0, 0, 0, 0);
      day.setDate(day.getDate() - i);
      const key = keyByDay(day);
      buckets[key] = {
        label: `${day.getMonth() + 1}/${day.getDate()}`,
        subdomains: 0,
        ports: 0,
        vulnerabilities: 0
      };
    }

    for (const item of scoped.assets) {
      const base = item.lastSeen ?? item.updatedAt ?? item.createdAt;
      if (!base) {
        continue;
      }
      const date = new Date(base);
      if (Number.isNaN(date.getTime())) {
        continue;
      }
      const key = keyByDay(date);
      if (buckets[key]) {
        buckets[key].subdomains += 1;
      }
    }

    for (const item of scoped.ports) {
      const base = item.lastSeen ?? item.updatedAt;
      if (!base) {
        continue;
      }
      const date = new Date(base);
      if (Number.isNaN(date.getTime())) {
        continue;
      }
      const key = keyByDay(date);
      if (buckets[key]) {
        buckets[key].ports += 1;
      }
    }

    for (const item of scoped.vulns) {
      const base = item.matchedAt ?? item.lastSeen;
      const date = new Date(base);
      if (Number.isNaN(date.getTime())) {
        continue;
      }
      const key = keyByDay(date);
      if (buckets[key]) {
        buckets[key].vulnerabilities += 1;
      }
    }

    return Object.values(buckets);
  }, [scoped.assets, scoped.ports, scoped.vulns]);

  const loading = jobsQuery.isLoading || assetsQuery.isLoading || portsQuery.isLoading || vulnsQuery.isLoading;
  const hasTargets = rootDomains.length > 0;

  const chartOption = {
    tooltip: { trigger: "axis" },
    legend: { textStyle: { color: "#9fc4b2" } },
    grid: { left: 16, right: 18, top: 42, bottom: 20, containLabel: true },
    xAxis: {
      type: "category",
      data: trend.map((item) => item.label),
      axisLabel: { color: "#80a9a4" },
      axisLine: { lineStyle: { color: "#24403f" } }
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "#80a9a4" },
      splitLine: { lineStyle: { color: "#1a2f32" } }
    },
    series: [
      {
        name: "Subdomains",
        type: "line",
        smooth: true,
        data: trend.map((item) => item.subdomains),
        lineStyle: { color: "#31f2a9" }
      },
      {
        name: "Ports",
        type: "line",
        smooth: true,
        data: trend.map((item) => item.ports),
        lineStyle: { color: "#56c9ff" }
      },
      {
        name: "Vulns",
        type: "line",
        smooth: true,
        data: trend.map((item) => item.vulnerabilities),
        lineStyle: { color: "#ff5f86" }
      }
    ]
  };

  return (
    <section className="page">
      <h1>Command Overview</h1>
      <p className="page-subtitle">Project-level control plane for your recon workflow.</p>

      <ProjectScopeBanner
        title="Current Dataset Scope"
        hint="Dashboard metrics are computed from existing pipeline tables filtered by active project roots."
      />

      {!hasTargets ? <p className="empty-state">No root domains in this project. Go to Projects and add at least one target.</p> : null}
      {loading ? <p className="empty-state">Loading scoped metrics...</p> : null}

      <div className="ops-strip">
        <article className="ops-cell">
          <span className="ops-label">Risk Index</span>
          <strong className={metrics.riskIndex >= 70 ? "ops-value danger" : "ops-value"}>{metrics.riskIndex}</strong>
        </article>
        <article className="ops-cell">
          <span className="ops-label">Monitor Signals (24h)</span>
          <strong className="ops-value">{metrics.monitorSignals24h}</strong>
        </article>
        <article className="ops-cell">
          <span className="ops-label">Avg Job Duration</span>
          <strong className="ops-value">{metrics.avgDuration}s</strong>
        </article>
      </div>

      <div className="stats-grid">
        <StatCard label="Jobs Running" value={metrics.running} hint="Current active queue" />
        <StatCard label="Success (24h)" value={metrics.success24h} hint="Completed without error" />
        <StatCard label="Failed (24h)" value={metrics.failed24h} hint="Operator intervention needed" />
        <StatCard label="New Subdomains (24h)" value={metrics.newSubdomains24h} hint="Freshly observed hosts" />
        <StatCard label="New Ports (24h)" value={metrics.newPorts24h} hint="Exposure drift" />
        <StatCard label="New Vulns (24h)" value={metrics.newVulns24h} hint="Triage queue" />
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>7-Day Project Signal</h2>
          <span>{activeProject?.name ?? "No project selected"}</span>
        </header>
        <ReactECharts option={chartOption} style={{ height: 320 }} />
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Flow Map</h2>
          <span>project -&gt; subs -&gt; dictgen -&gt; brute -&gt; ports -&gt; nuclei -&gt; monitor</span>
        </header>
        <div className="workflow-grid">
          <div className="workflow-item">
            <span className="wf-tag">project</span>
            <p>Every view is scoped to selected project root domains.</p>
          </div>
          <div className="workflow-item">
            <span className="wf-tag">passive subs</span>
            <p>Findomain/Subfinder/BBOT feed baseline target map.</p>
          </div>
          <div className="workflow-item">
            <span className="wf-tag">dictgen + brute</span>
            <p>Generate small custom dictionaries, then run active expansion.</p>
          </div>
          <div className="workflow-item">
            <span className="wf-tag">ports/services</span>
            <p>Naabu + Nmap identify service exposure with protocol details.</p>
          </div>
          <div className="workflow-item">
            <span className="wf-tag danger">nuclei</span>
            <p>Findings tied to root domain for project-aware triage and display.</p>
          </div>
          <div className="workflow-item">
            <span className="wf-tag">monitor</span>
            <p>Debounced change events highlight new assets and service drift.</p>
          </div>
        </div>
      </article>
    </section>
  );
}
