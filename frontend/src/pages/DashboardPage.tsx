import ReactECharts from "echarts-for-react";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { StatCard } from "../components/ui/StatCard";
import { useWorkspace } from "../context/WorkspaceContext";
import { useDashboard, useJobsPage, useMonitorTargets } from "../hooks/queries";
import { formatDateCompact, formatDurationSec } from "../lib/format";
import { jobStatusClass, jobStatusLabel } from "../lib/status";

export function DashboardPage() {
  const { activeProject } = useWorkspace();
  const projectId = activeProject?.id;
  const navigate = useNavigate();

  const dashQ = useDashboard(projectId);
  const jobsQ = useJobsPage(projectId, {
    page: 1,
    pageSize: 10,
    sortBy: "started_at",
    sortDir: "desc",
  });
  const monTargetsQ = useMonitorTargets(projectId);

  const summary = dashQ.data?.summary;
  const trend = dashQ.data?.trend ?? [];
  const jobs = jobsQ.data?.items ?? [];
  const jobsTotal = jobsQ.data?.total ?? 0;
  const monitorTargetCount = (monTargetsQ.data ?? []).length;

  const loading = dashQ.isLoading || jobsQ.isLoading || monTargetsQ.isLoading;
  const error = dashQ.error || jobsQ.error || monTargetsQ.error;

  const trendLabels = useMemo(() => {
    return trend.map((t) => {
      const parts = t.date.split("-");
      if (parts.length === 3) return `${parseInt(parts[1], 10)}/${parseInt(parts[2], 10)}`;
      return t.date;
    });
  }, [trend]);

  const totalVulns24h = summary?.newVulns24h ?? 0;

  // 端口服务分布 Top 10（后端全量统计）
  const serviceDistribution = useMemo(() => summary?.serviceDistribution ?? [], [summary]);

  // 漏洞严重等级分布（后端全量统计）
  const severityDistribution = useMemo(() => {
    const byName = new Map<string, number>();
    for (const item of summary?.severityDistribution ?? []) {
      byName.set((item.name || "unknown").toLowerCase(), item.value || 0);
    }
    return [
      { name: "严重", value: byName.get("critical") ?? 0, color: "#ef4444" },
      { name: "高危", value: byName.get("high") ?? 0, color: "#f97316" },
      { name: "中危", value: byName.get("medium") ?? 0, color: "#f59e0b" },
      { name: "低危", value: byName.get("low") ?? 0, color: "#22c55e" },
      { name: "信息", value: byName.get("info") ?? 0, color: "#3b82f6" },
      { name: "未知", value: byName.get("unknown") ?? 0, color: "#64748b" },
    ].filter((d) => d.value > 0);
  }, [summary]);

  const trendOption = {
    tooltip: {
      trigger: "axis" as const,
      backgroundColor: "#1a2035",
      borderColor: "rgba(255,255,255,0.08)",
      textStyle: { color: "#e2e8f0" },
    },
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
              { offset: 1, color: "rgba(245,158,11,0)" },
            ],
          },
        },
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
              { offset: 1, color: "rgba(34,197,94,0)" },
            ],
          },
        },
      },
      {
        name: "漏洞",
        type: "line" as const,
        smooth: true,
        symbol: "circle",
        symbolSize: 6,
        data: trend.map((t) => t.vulnerabilities),
        itemStyle: { color: "#ef4444" },
        lineStyle: { color: "#ef4444", width: 2 },
      },
    ],
  };

  const serviceBarOption = {
    tooltip: {
      trigger: "axis" as const,
      backgroundColor: "#1a2035",
      borderColor: "rgba(255,255,255,0.08)",
      textStyle: { color: "#e2e8f0" },
    },
    grid: { left: 80, right: 20, top: 10, bottom: 30 },
    xAxis: {
      type: "value" as const,
      axisLabel: { color: "#64748b" },
      splitLine: { lineStyle: { color: "#1e2a42" } },
    },
    yAxis: {
      type: "category" as const,
      data: serviceDistribution.map((d) => d.name).reverse(),
      axisLabel: { color: "#94a3b8", fontSize: 12 },
      axisLine: { lineStyle: { color: "#1e2a42" } },
    },
    series: [
      {
        type: "bar" as const,
        data: serviceDistribution.map((d) => d.value).reverse(),
        barWidth: 16,
        itemStyle: {
          color: {
            type: "linear",
            x: 0, y: 0, x2: 1, y2: 0,
            colorStops: [
              { offset: 0, color: "#3b82f6" },
              { offset: 1, color: "#06b6d4" },
            ],
          },
          borderRadius: [0, 4, 4, 0],
        },
      },
    ],
  };

  const severityPieOption = {
    tooltip: {
      trigger: "item" as const,
      backgroundColor: "#1a2035",
      borderColor: "rgba(255,255,255,0.08)",
      textStyle: { color: "#e2e8f0" },
    },
    legend: {
      bottom: 0,
      textStyle: { color: "#64748b", fontSize: 12 },
    },
    series: [
      {
        type: "pie" as const,
        radius: ["45%", "70%"],
        center: ["50%", "45%"],
        avoidLabelOverlap: true,
        itemStyle: { borderRadius: 4, borderColor: "#0f172a", borderWidth: 2 },
        label: { show: false },
        emphasis: {
          label: { show: true, color: "#e2e8f0", fontSize: 14, fontWeight: "bold" as const },
        },
        data: severityDistribution.map((d) => ({
          name: d.name,
          value: d.value,
          itemStyle: { color: d.color },
        })),
      },
    ],
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
        <div className="empty-state empty-state-error">
          <div className="empty-state-icon">⚠</div>
          <div className="empty-state-text">加载数据失败：{(error as Error).message}</div>
        </div>
      )}

      <div className="stats-row">
        <div className="clickable-stat" onClick={() => navigate("/assets")}>
          <StatCard
            icon="◎"
            label="新增资产 (24h)"
            value={summary?.newSubdomains24h ?? 0}
            change={summary?.newPorts24h ?? 0}
            desc={`新端口 ${summary?.newPorts24h ?? 0} · 平均耗时 ${formatDurationSec(summary?.scanDurationAvgSec24h, "success")}`}
          />
        </div>
        <div className="clickable-stat" onClick={() => navigate("/findings")}>
          <StatCard
            icon="⚑"
            label="新增漏洞 (24h)"
            value={totalVulns24h}
            change={totalVulns24h}
            accent="danger"
            desc={`成功任务 ${summary?.jobsSuccess24h ?? 0} · 失败 ${summary?.jobsFailed24h ?? 0}`}
          />
        </div>
        <div className="clickable-stat" onClick={() => navigate("/monitoring")}>
          <StatCard
            icon="◉"
            label="监控目标"
            value={monitorTargetCount}
            accent="blue"
            desc="已添加的监控目标总数"
          />
        </div>
        <div className="clickable-stat" onClick={() => navigate("/jobs")}>
          <StatCard
            icon="▷"
            label="正在运行"
            value={summary?.jobsRunning ?? 0}
            accent="blue"
            desc="当前进行中的任务"
          />
        </div>
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
              <div className="empty-state empty-state-compact">
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
          <div className="dashboard-overview-grid">
            <div className="stat-card">
              <div className="stat-label">成功任务</div>
              <div className="stat-value color-success">{summary?.jobsSuccess24h ?? 0}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">失败任务</div>
              <div className="stat-value color-danger">{summary?.jobsFailed24h ?? 0}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">新子域名</div>
              <div className="stat-value color-warning">{summary?.newSubdomains24h ?? 0}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">新端口</div>
              <div className="stat-value color-blue">{summary?.newPorts24h ?? 0}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">新漏洞</div>
              <div className="stat-value color-danger">{summary?.newVulns24h ?? 0}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">平均扫描耗时</div>
              <div className="stat-value">{formatDurationSec(summary?.scanDurationAvgSec24h, "success")}</div>
            </div>
          </div>
        </article>
      </div>

      {/* 新增：服务分布和漏洞等级分布 */}
      <div className="two-col">
        <article className="panel">
          <header className="panel-header">
            <h2>端口服务分布</h2>
            <span className="panel-meta">Top 10 服务类型（全量）</span>
          </header>
          <div className="chart-container">
            {serviceDistribution.length > 0 ? (
              <ReactECharts option={serviceBarOption} style={{ height: 280 }} />
            ) : (
              <div className="empty-state empty-state-compact">
                <div className="empty-state-icon">⊞</div>
                <div className="empty-state-text">暂无端口数据</div>
              </div>
            )}
          </div>
        </article>

        <article className="panel">
          <header className="panel-header">
            <h2>漏洞等级分布</h2>
            <span className="panel-meta">按严重程度统计（全量）</span>
          </header>
          <div className="chart-container">
            {severityDistribution.length > 0 ? (
              <ReactECharts option={severityPieOption} style={{ height: 280 }} />
            ) : (
              <div className="empty-state empty-state-compact">
                <div className="empty-state-icon">⚑</div>
                <div className="empty-state-text">暂无漏洞数据</div>
              </div>
            )}
          </div>
        </article>
      </div>

      <article className="panel">
        <header className="panel-header">
          <h2>扫描历史</h2>
          <span className="panel-meta">{jobsTotal} 条记录</span>
        </header>
        {jobs.length > 0 ? (
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
                {jobs.map((j) => {
                  const cls = jobStatusClass(j.status);
                  return (
                    <tr key={j.id} className="table-row-clickable" onClick={() => navigate(`/jobs/${encodeURIComponent(j.id)}/logs`)}>
                      <td className="cell-mono">{j.rootDomain || "—"}</td>
                      <td>
                        <span className={`summary-badge ${j.mode === "monitor" ? "info" : "subs"}`}>
                          {j.mode === "monitor" ? "监控" : "扫描"}
                        </span>
                      </td>
                      <td>
                        <div className="summary-badges">
                          {(j.modules ?? []).map((m) => (
                            <span key={m} className="summary-badge summary-badge-sm">{m}</span>
                          ))}
                        </div>
                      </td>
                      <td className="cell-muted">{formatDateCompact(j.startedAt)}</td>
                      <td className="cell-muted">{formatDurationSec(j.durationSec, j.status)}</td>
                      <td>
                        <span className={`status-badge ${cls}`}>
                          <span className="status-indicator" />
                          {jobStatusLabel(j.status)}
                        </span>
                        {j.errorMessage && (
                          <div className="error-hint" title={j.errorMessage}>
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
          <div className="empty-state empty-state-action">
            <div className="empty-state-icon">▷</div>
            <div className="empty-state-text">暂无扫描记录</div>
            <button className="btn btn-primary btn-sm" onClick={() => navigate("/quick-scan")}>
              立即扫描
            </button>
          </div>
        )}
      </article>

      <div className="dashboard-footer">
        统计更新于 {new Date().toLocaleString("zh-CN")}
      </div>
    </section>
  );
}
