import ReactECharts from "echarts-for-react";
import { useMemo } from "react";
import { StatCard } from "../components/ui/StatCard";
import { useWorkspace } from "../context/WorkspaceContext";
import { useDashboard, useJobs, useAssets, usePorts, useVulns } from "../hooks/queries";
import { matchesProjectDomain } from "../lib/projectScope";

function hostnameFromUrl(input?: string): string | undefined {
  if (!input) return undefined;
  try { return new URL(input).hostname; } catch { return undefined; }
}

export function DashboardPage() {
  const { activeProject } = useWorkspace();
  const rootDomains = activeProject?.rootDomains ?? [];

  // Use backend dashboard summary API for trend and 24h stats
  const dashQ = useDashboard();
  const jobsQ = useJobs();
  const assetsQ = useAssets();
  const portsQ = usePorts();
  const vulnsQ = useVulns();

  // Scoped data for totals and severity breakdown
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
    return { jobs, assets, ports, vulns };
  }, [jobsQ.data, assetsQ.data, portsQ.data, vulnsQ.data, rootDomains]);

  // Dashboard summary from backend
  const summary = dashQ.data?.summary;
  const trend = dashQ.data?.trend ?? [];

  // Count unique IPs
  const uniqueIps = useMemo(() => {
    const s = new Set<string>();
    for (const a of scoped.assets) if (a.ip) s.add(a.ip);
    for (const p of scoped.ports) if (p.ip) s.add(p.ip);
    return s.size;
  }, [scoped.assets, scoped.ports]);

  // Count web services (assets with URL)
  const webCount = useMemo(() => scoped.assets.filter((a) => a.url).length, [scoped.assets]);

  // Severity breakdown
  const sevCounts = useMemo(() => {
    const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of scoped.vulns) {
      const s = (v.severity ?? "").toLowerCase();
      if (s in out) out[s as keyof typeof out]++;
    }
    return out;
  }, [scoped.vulns]);

  // Running jobs count - prefer backend summary if available
  const runningJobs = summary?.jobsRunning ?? useMemo(() =>
    scoped.jobs.filter((j) => {
      const s = String(j.status).toLowerCase();
      return s.includes("running") || s.includes("pending");
    }).length
    , [scoped.jobs]);

  const loading = dashQ.isLoading || jobsQ.isLoading || assetsQ.isLoading || portsQ.isLoading || vulnsQ.isLoading;

  // Format trend dates for display
  const trendLabels = useMemo(() => {
    return trend.map((t) => {
      const parts = t.date.split("-");
      if (parts.length === 3) return `${parseInt(parts[1])}/${parseInt(parts[2])}`;
      return t.date;
    });
  }, [trend]);

  // Trend chart - use server-side computed data
  const trendOption = {
    tooltip: { trigger: "axis" as const, backgroundColor: "#1a2035", borderColor: "rgba(255,255,255,0.08)", textStyle: { color: "#e2e8f0" } },
    legend: { textStyle: { color: "#64748b" }, bottom: 0 },
    grid: { left: 40, right: 20, top: 20, bottom: 40 },
    xAxis: {
      type: "category" as const,
      data: trendLabels,
      axisLabel: { color: "#64748b" },
      axisLine: { lineStyle: { color: "#1e2a42" } },
    },
    yAxis: {
      type: "value" as const,
      axisLabel: { color: "#64748b" },
      splitLine: { lineStyle: { color: "#1e2a42" } },
    },
    series: [
      { name: "子域名", type: "line" as const, smooth: true, symbol: "circle", symbolSize: 6, data: trend.map((t) => t.subdomains), itemStyle: { color: "#f59e0b" }, lineStyle: { color: "#f59e0b", width: 2 }, areaStyle: { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: "rgba(245,158,11,0.15)" }, { offset: 1, color: "rgba(245,158,11,0)" }] } } },
      { name: "端口", type: "line" as const, smooth: true, symbol: "circle", symbolSize: 6, data: trend.map((t) => t.ports), itemStyle: { color: "#22c55e" }, lineStyle: { color: "#22c55e", width: 2 }, areaStyle: { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: "rgba(34,197,94,0.1)" }, { offset: 1, color: "rgba(34,197,94,0)" }] } } },
      { name: "漏洞", type: "line" as const, smooth: true, symbol: "circle", symbolSize: 6, data: trend.map((t) => t.vulnerabilities), itemStyle: { color: "#ef4444" }, lineStyle: { color: "#ef4444", width: 2 } },
    ],
  };

  // Severity donut
  const totalVulns = scoped.vulns.length;
  const sevPieOption = {
    tooltip: { trigger: "item" as const, backgroundColor: "#1a2035", borderColor: "rgba(255,255,255,0.08)", textStyle: { color: "#e2e8f0" } },
    legend: { show: false },
    graphic: [{
      type: "text" as const,
      left: "center",
      top: "40%",
      style: { text: String(totalVulns), fill: "#e2e8f0", fontSize: 28, fontWeight: "bold" as const, textAlign: "center" as const },
    }, {
      type: "text" as const,
      left: "center",
      top: "55%",
      style: { text: "漏洞", fill: "#64748b", fontSize: 12, textAlign: "center" as const },
    }],
    series: [{
      type: "pie" as const,
      radius: ["55%", "78%"],
      center: ["50%", "50%"],
      avoidLabelOverlap: false,
      label: { show: false },
      data: [
        { value: sevCounts.critical, name: "严重", itemStyle: { color: "#ef4444" } },
        { value: sevCounts.high, name: "高危", itemStyle: { color: "#f97316" } },
        { value: sevCounts.medium, name: "中危", itemStyle: { color: "#eab308" } },
        { value: sevCounts.low, name: "低危", itemStyle: { color: "#22c55e" } },
        { value: sevCounts.info, name: "信息", itemStyle: { color: "#64748b" } },
      ].filter((d) => d.value > 0),
    }],
  };

  // Recent jobs for table
  const recentJobs = useMemo(() => scoped.jobs.slice(0, 10), [scoped.jobs]);

  const formatTime = (s?: string | null) => {
    if (!s) return "—";
    const d = new Date(s);
    if (Number.isNaN(d.getTime())) return "—";
    return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, "0")}/${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  };

  const formatDuration = (sec?: number) => {
    if (!sec || sec <= 0) return "—";
    if (sec < 60) return `${sec}s`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
    return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
  };

  const statusClass = (s: string) => {
    const l = s.toLowerCase();
    if (l.includes("ok") || l.includes("success") || l.includes("done") || l.includes("completed")) return "completed";
    if (l.includes("fail") || l.includes("error")) return "failed";
    if (l.includes("running")) return "running";
    return "pending";
  };

  const statusLabel = (s: string) => {
    const cls = statusClass(s);
    if (cls === "completed") return "已完成";
    if (cls === "failed") return "失败";
    if (cls === "running") return "运行中";
    return "等待中";
  };

  return (
    <section className="page">
      {loading && <div className="empty-state">加载中...</div>}

      {/* ── 4 Stat Cards ── */}
      <div className="stats-row">
        <StatCard icon="◎" label="发现资产" value={scoped.assets.length} change={summary?.newSubdomains24h} desc={`子域名 ${scoped.assets.length} · IP ${uniqueIps} · 端口 ${scoped.ports.length} · 网站 ${webCount}`} />
        <StatCard icon="⚑" label="发现漏洞" value={totalVulns} change={summary?.newVulns24h} accent="danger" desc="所有扫描发现的漏洞" />
        <StatCard icon="◉" label="监控目标" value={uniqueIps} accent="blue" desc="已添加的目标总数" />
        <StatCard icon="▷" label="正在扫描" value={runningJobs} accent="blue" desc="当前进行中的任务" />
      </div>

      {/* ── Trend + Severity ── */}
      <div className="two-col">
        <article className="panel">
          <header className="panel-header">
            <h2>资产趋势</h2>
            <span className="panel-meta">近7天资产变化，点击折线或圆点可隐藏/显示</span>
          </header>
          <div className="chart-container">
            <ReactECharts option={trendOption} style={{ height: 280 }} />
          </div>
          <div style={{ display: "flex", gap: 16, padding: "0 20px 16px", flexWrap: "wrap" }}>
            <span style={{ fontSize: 12, color: "#64748b" }}>总计</span>
            <span style={{ fontSize: 12, color: "#f59e0b" }}>● 子域名 {scoped.assets.length}</span>
            <span style={{ fontSize: 12, color: "#ef4444" }}>● IP {uniqueIps}</span>
            <span style={{ fontSize: 12, color: "#22c55e" }}>● 端口 {scoped.ports.length}</span>
            <span style={{ fontSize: 12, color: "#3b82f6" }}>● 网站 {webCount}</span>
          </div>
        </article>

        <article className="panel">
          <header className="panel-header">
            <h2>漏洞分布</h2>
            <span className="panel-meta">按严重程度统计</span>
          </header>
          <div className="chart-container">
            {totalVulns > 0 ? (
              <ReactECharts option={sevPieOption} style={{ height: 240 }} />
            ) : (
              <div className="empty-state" style={{ padding: "40px 0" }}>
                <div className="empty-state-icon">⚑</div>
                <div className="empty-state-text">暂无漏洞数据</div>
              </div>
            )}
          </div>
          {totalVulns > 0 && (
            <div style={{ display: "flex", gap: 12, padding: "0 20px 16px", justifyContent: "center", flexWrap: "wrap" }}>
              <span className="summary-badge critical">严重 {sevCounts.critical}</span>
              <span className="summary-badge high">高危 {sevCounts.high}</span>
              <span className="summary-badge medium">中危 {sevCounts.medium}</span>
              <span className="summary-badge low">低危 {sevCounts.low}</span>
              <span style={{ fontSize: 11, color: "#64748b", padding: "2px 8px" }}>信息 {sevCounts.info}</span>
            </div>
          )}
        </article>
      </div>

      {/* ── Scan History Table ── */}
      <article className="panel">
        <header className="panel-header">
          <h2>扫描历史</h2>
          <span className="panel-meta">{scoped.jobs.length} 条记录</span>
        </header>
        {recentJobs.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>目标</th>
                  <th>模式</th>
                  <th>模块</th>
                  <th>创建时间</th>
                  <th>耗时</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                {recentJobs.map((j) => {
                  const cls = statusClass(j.status);
                  return (
                    <tr key={j.id}>
                      <td className="cell-mono">{j.rootDomain || "—"}</td>
                      <td>
                        <span className={`summary-badge ${j.mode === "monitor" ? "info" : "subs"}`}>
                          {j.mode === "monitor" ? "监控" : "扫描"}
                        </span>
                      </td>
                      <td>
                        <div className="summary-badges">
                          {(j.modules ?? []).map((m) => (
                            <span key={m} className="summary-badge" style={{ fontSize: 11 }}>{m}</span>
                          ))}
                        </div>
                      </td>
                      <td className="cell-muted">{formatTime(j.startedAt)}</td>
                      <td className="cell-muted">{formatDuration(j.durationSec)}</td>
                      <td>
                        <span className={`status-badge ${cls}`}>
                          <span className="status-indicator" />
                          {statusLabel(j.status)}
                        </span>
                        {j.errorMessage && (
                          <div style={{ fontSize: 11, color: "#ef4444", marginTop: 2, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={j.errorMessage}>
                            {j.errorMessage}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon">▷</div>
            <div className="empty-state-text">暂无扫描记录</div>
          </div>
        )}
      </article>

      <div style={{ textAlign: "right", fontSize: 12, color: "#475569", marginTop: 8 }}>
        统计更新于 {new Date().toLocaleString("zh-CN")}
      </div>
    </section>
  );
}
