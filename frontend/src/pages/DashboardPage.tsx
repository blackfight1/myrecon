import ReactECharts from "echarts-for-react";
import { StatCard } from "../components/ui/StatCard";
import { useDashboard } from "../hooks/queries";

export function DashboardPage() {
  const { data, isLoading, error } = useDashboard();

  if (isLoading) return <p className="empty-state">Loading dashboard...</p>;
  if (error) return <p className="empty-state">Failed to load dashboard data.</p>;
  if (!data) return <p className="empty-state">No dashboard data.</p>;

  const riskIndex = Math.min(
    100,
    data.summary.newVulns24h * 12 + data.summary.jobsFailed24h * 8 + Math.round(data.summary.jobsRunning * 4)
  );
  const exposurePulse = Math.max(0, data.summary.newPorts24h + data.summary.newSubdomains24h - data.summary.newVulns24h);
  const trendLast = data.trend[data.trend.length - 1];

  const chartOption = {
    tooltip: { trigger: "axis" },
    legend: {
      textStyle: { color: "#9db2c8" }
    },
    grid: { left: 16, right: 16, top: 40, bottom: 16, containLabel: true },
    xAxis: {
      type: "category",
      data: data.trend.map((item) => item.date),
      axisLabel: { color: "#95a2b2" }
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "#95a2b2" },
      splitLine: { lineStyle: { color: "#1e2733" } }
    },
    series: [
      {
        name: "Subdomains",
        type: "line",
        smooth: true,
        data: data.trend.map((item) => item.subdomains)
      },
      {
        name: "Ports",
        type: "line",
        smooth: true,
        data: data.trend.map((item) => item.ports)
      },
      {
        name: "Vulns",
        type: "line",
        smooth: true,
        data: data.trend.map((item) => item.vulnerabilities)
      }
    ]
  };

  return (
    <section className="page">
      <h1>Command Overview</h1>
      <p className="page-subtitle">Live operational matrix mapped to your recon pipeline and PostgreSQL records.</p>

      <div className="ops-strip">
        <article className="ops-cell">
          <span className="ops-label">Risk Index</span>
          <strong className={riskIndex >= 70 ? "ops-value danger" : "ops-value"}>{riskIndex}</strong>
        </article>
        <article className="ops-cell">
          <span className="ops-label">Exposure Pulse</span>
          <strong className="ops-value">{exposurePulse}</strong>
        </article>
        <article className="ops-cell">
          <span className="ops-label">Latest Trend Snapshot</span>
          <strong className="ops-value">
            {trendLast ? `${trendLast.subdomains} / ${trendLast.ports} / ${trendLast.vulnerabilities}` : "-"}
          </strong>
        </article>
      </div>

      <div className="stats-grid">
        <StatCard label="Jobs Running" value={data.summary.jobsRunning} hint="Current active queue" />
        <StatCard label="Success (24h)" value={data.summary.jobsSuccess24h} hint="Completed without error" />
        <StatCard label="Failed (24h)" value={data.summary.jobsFailed24h} hint="Need operator review" />
        <StatCard label="New Subdomains (24h)" value={data.summary.newSubdomains24h} hint="Surface expansion" />
        <StatCard label="New Ports (24h)" value={data.summary.newPorts24h} hint="Exposure drift" />
        <StatCard label="New Vulns (24h)" value={data.summary.newVulns24h} hint="Triaging queue" />
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>7-Day Recon Signal</h2>
          <span>Average duration: {data.summary.scanDurationAvgSec24h}s</span>
        </header>
        <ReactECharts option={chartOption} style={{ height: 320 }} />
      </article>

      <article className="panel">
        <header className="panel-header">
          <h2>Workflow Mapping</h2>
          <span>subs -&gt; ports -&gt; witness -&gt; nuclei -&gt; monitor</span>
        </header>
        <div className="workflow-grid">
          <div className="workflow-item">
            <span className="wf-tag">subs</span>
            <p>Passive and optional active expansion feed the domain pool.</p>
          </div>
          <div className="workflow-item">
            <span className="wf-tag">ports</span>
            <p>Naabu + Nmap characterize externally reachable services.</p>
          </div>
          <div className="workflow-item">
            <span className="wf-tag">witness</span>
            <p>Screenshots map visual attack surface and response drift.</p>
          </div>
          <div className="workflow-item">
            <span className="wf-tag danger">nuclei</span>
            <p>Template findings are deduplicated and pinned by fingerprint.</p>
          </div>
          <div className="workflow-item">
            <span className="wf-tag">monitor</span>
            <p>Change stream captures new live assets and service transitions.</p>
          </div>
        </div>
      </article>
    </section>
  );
}
