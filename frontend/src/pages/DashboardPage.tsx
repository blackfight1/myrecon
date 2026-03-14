import ReactECharts from "echarts-for-react";
import { useMemo } from "react";
import { StatCard } from "../components/ui/StatCard";
import { useWorkspace } from "../context/WorkspaceContext";
import { useDashboard, useJobs, useMonitorTargets } from "../hooks/queries";

export function DashboardPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;

  const dashQ = useDashboard(projectId);
  const jobsQ = useJobs(projectId);
  const monTargetsQ = useMonitorTargets(projectId);

  const summary = dashQ.data?.summary;
  const trend = dashQ.data?.trend ?? [];
  const jobs = jobsQ.data ?? [];
  const monitorTargetCount = (monTargetsQ.data ?? []).length;

  const loading = dashQ.isLoading;
  const error = dashQ.error || jobsQ.error;

  const recentJobs = useMemo(() => jobs.slice(0, 10), [jobs]);

  const trendLabels = useMemo(() => {
    return trend.map((t) => {
      const parts = t.date.split("-");
      if (parts.length === 3) return `${parseInt(parts[1], 10)}/${parseInt(parts[2], 10)}`;
      return t.date;
    });
  }, [trend]);

  const totalVulns24h = summary?.newVulns24h ?? 0;

  // Compute severity from jobs if available (we no longer pull full vulns list)
  // The dashboard API doesn't return severity breakdown, so we show summary stats only

  const trendOption = {
    tooltip: {
      trigger: "axis" as const,
      backgroundColor: "#1a2035",
      borderColor: "rgba(255,255,255,0.08)",
      textStyle: { color: "#e2e8f0" }
    },
    legend: { textStyle: { color: "#64748b" }, bottom: 0 },
    grid: { left: 40, right: 20, top: 20, bottom: 40 },
    xAxis: {
      type: "category" as const,
      data: trendLabels,
      axisLabel: { color: "#64748b" },
      axisLine: { lineStyle: { color: "#1e2a42" } }
    },
    yAxis: {
      type: "value" as const,
      axisLabel: { color: "#64748b" },
      splitLine: { lineStyle: { color: "#1e2a42" } }
    },
    series: [
      {
        name: "子域名",
        type: "line" as const,
        smooth: true,
        symbol: "circle",
        symbolSize: 6,
        data: trend.map((t) => t.subdomains),
        itemStyle: { color: "#f59e0b" },
        lineStyle: { color: "#f59e0b", width: 2 },
        areaStyle: {
          color: {
            type: "linear",
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: "rgba(245,158,11,0.15)" },
              { offset: 1, color: "rgba(245,158,11,0)" }
            ]
          }
        }
      },
      {
        name: "端口",
        type: "line" as const,
        smooth: true,
        symbol: "circle",
        symbolSize: 6,
        data: trend.map((t) => t.ports),
        itemStyle: { color: "#22c55e" },
        lineStyle: { color: "#22c55e", width: 2 },
        areaStyle: {
          color: {
            type: "linear",
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: "rgba(34,197,94,0.1)" },
              { offset: 1, color: "rgba(34,197,94,0)" }
            ]
          }
        }
      },
      {
        name: "漏洞",
        type: "line" as const,
        smooth: true,
        symbol: "circle",
        symbolSize: 6,
        data: trend.map((t) => t.vulnerabilities),
        itemStyle: { color: "#ef4444" },
        lineStyle: { color: "#ef4444", width: 2 }
      }
    ]
  };

  const formatTime = (s?: string | null) => {
    if (!s) return "—";
    const d = new Date(s);
    if (Number.isNaN(d.getTime())) return "—";
    return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, "0")}/${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  };

  const formatDuration = (sec?: number, status?: string) => {
    const st = (status ?? "").toLowerCase();
    const finished = st.includes("success") || st.includes("done") || st.includes("ok") || st.includes("completed") || st.includes("fail") || st.includes("error");
    if (sec === undefined || sec === null) return finished ? "< 1s" : "—";
    if (sec <= 0) return finished ? "< 1s" : "—";
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
      {loading && (
        <div className="loading-skeleton">
          <div className="stats-row">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="skeleton-card" />
            ))}
          </div>
          <div className="two-col">
            <div className="skeleton-panel" style={{ height: 320 }} />
            <div className="skeleton-panel" style={{ height: 320 }} />
          </div>
          <div className="skeleton-panel" style={{ height: 200 }} />
        </div>
      )}

      {error && (
        <div className="empty-state" style={{ color: "#ef4444" }}>
          <div className="empty-state-icon">⚠</div>
          <div className="empty-state-text">加载数据失败：{(error as Error).message}</div>
        </div>
      )}

      <div className="stats-row">
        <StatCard
          icon="◎"
          label="新增资产 (24h)"
          value={summary?.newSubdomains24h ?? 0}
          change={summary?.newPorts24h ?? 0}
          desc={`新端口 ${summary?.newPorts24h ?? 0} · 平均耗时 ${summary?.scanDurationAvgSec24h ?? 0}s`}
        />
        <StatCard
          icon="⚑"
          label="新增漏洞 (24h)"
          value={totalVulns24h}
          change={totalVulns24h}
          accent="danger"
          desc={`成功任务 ${summary?.jobsSuccess24h ?? 0} · 失败 ${summary?.jobsFailed24h ?? 0}`}
        />
        <StatCard
          icon="◉"
          label="监控目标"
          value={monitorTargetCount}
          accent="blue"
          desc="已添加的监控目标总数"
        />
        <StatCard
          icon="▷"
          label="正在运行"
          value={summary?.jobsRunning ?? 0}
          accent="blue"
          desc="当前进行中的任务"
        />
      </div>

      <div className="two-col">
        <article className="panel">
          <header className="panel-header">
            <h2>资产趋势</h2>
            <span className="panel-meta">近7天资产变化</span>
          </header>
          <div className="chart-container">
            {trend.length > 0 ? (
              <ReactECharts option={trendOption} style={{ height: 280 }} />
            ) : (
              <div className="empty-state" style={{ padding: "40px 0" }}>
                <div className="empty-state-icon">📊</div>
                <div className="empty-state-text">暂无趋势数据</div>
              </div>
            )}
          </div>
        </article>

        <article className="panel">
          <header className="panel-header">
            <h2>24h 概览</h2>
            <span className="panel-meta">最近24小时汇总</span>
          </header>
          <div style={{ padding: "20px" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div className="stat-card">
                <div className="stat-label">成功任务</div>
                <div className="stat-value" style={{ color: "#22c55e" }}>{summary?.jobsSuccess24h ?? 0}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">失败任务</div>
                <div className="stat-value" style={{ color: "#ef4444" }}>{summary?.jobsFailed24h ?? 0}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">新子域名</div>
                <div className="stat-value" style={{ color: "#f59e0b" }}>{summary?.newSubdomains24h ?? 0}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">新端口</div>
                <div className="stat-value" style={{ color: "#3b82f6" }}>{summary?.newPorts24h ?? 0}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">新漏洞</div>
                <div className="stat-value" style={{ color: "#ef4444" }}>{summary?.newVulns24h ?? 0}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">平均扫描耗时</div>
                <div className="stat-value">{formatDuration(summary?.scanDurationAvgSec24h, "success")}</div>
              </div>
            </div>
          </div>
        </article>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>扫描历史</h2>
          <span className="panel-meta">{jobs.length} 条记录</span>
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
                            <span key={m} className="summary-badge" style={{ fontSize: 11 }}>
                              {m}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="cell-muted">{formatTime(j.startedAt)}</td>
                      <td className="cell-muted">{formatDuration(j.durationSec, j.status)}</td>
                      <td>
                        <span className={`status-badge ${cls}`}>
                          <span className="status-indicator" />
                          {statusLabel(j.status)}
                        </span>
                        {j.errorMessage && (
                          <div
                            style={{ fontSize: 11, color: "#ef4444", marginTop: 2, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                            title={j.errorMessage}
                          >
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
