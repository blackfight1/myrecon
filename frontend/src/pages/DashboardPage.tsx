import ReactECharts from "echarts-for-react";
import { StatCard } from "../components/ui/StatCard";
import { useDashboard } from "../hooks/queries";

export function DashboardPage() {
  const { data, isLoading, error } = useDashboard();

  if (isLoading) return <p className="empty-state">Loading dashboard...</p>;
  if (error) return <p className="empty-state">Failed to load dashboard data.</p>;
  if (!data) return <p className="empty-state">No dashboard data.</p>;

  const chartOption = {
    tooltip: { trigger: "axis" },
    legend: {
      textStyle: { color: "#c8d0d9" }
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
      <h1>Dashboard</h1>
      <p className="page-subtitle">Operational view mapped to your recon pipeline and database records.</p>

      <div className="stats-grid">
        <StatCard label="Jobs Running" value={data.summary.jobsRunning} />
        <StatCard label="Success (24h)" value={data.summary.jobsSuccess24h} />
        <StatCard label="Failed (24h)" value={data.summary.jobsFailed24h} />
        <StatCard label="New Subdomains (24h)" value={data.summary.newSubdomains24h} />
        <StatCard label="New Ports (24h)" value={data.summary.newPorts24h} />
        <StatCard label="New Vulns (24h)" value={data.summary.newVulns24h} />
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>7-Day Recon Trend</h2>
          <span>Average duration: {data.summary.scanDurationAvgSec24h}s</span>
        </header>
        <ReactECharts option={chartOption} style={{ height: 320 }} />
      </article>
    </section>
  );
}
