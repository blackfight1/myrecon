import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import { useJobLogs } from "../hooks/queries";
import { formatDate } from "../lib/format";
import type { JobLogLine } from "../types/models";

function normalizeLevel(level: string): "debug" | "info" | "warn" | "error" {
  const lv = level.toLowerCase();
  if (lv === "debug" || lv === "warn" || lv === "error") return lv;
  return "info";
}

export function JobLogsPage() {
  const navigate = useNavigate();
  const { jobId: rawJobID } = useParams<{ jobId: string }>();
  const jobID = useMemo(() => decodeURIComponent((rawJobID ?? "").trim()), [rawJobID]);

  const { activeProject } = useWorkspace();
  const projectID = activeProject?.id;

  const [sinceID, setSinceID] = useState(0);
  const [initialized, setInitialized] = useState(false);
  const [follow, setFollow] = useState(true);
  const [lines, setLines] = useState<JobLogLine[]>([]);
  const viewerRef = useRef<HTMLDivElement | null>(null);

  const logsQ = useJobLogs(projectID, jobID || undefined, { sinceId: sinceID, limit: 200 });
  const jobStatus = logsQ.data?.jobStatus ?? "unknown";

  useEffect(() => {
    setSinceID(0);
    setInitialized(false);
    setLines([]);
  }, [projectID, jobID]);

  useEffect(() => {
    if (!logsQ.data) return;
    setSinceID((prev) => (logsQ.data!.sinceId > prev ? logsQ.data!.sinceId : prev));
    setLines((prev) => {
      if (!initialized) {
        return logsQ.data!.items.slice(-1000);
      }
      if (logsQ.data!.items.length === 0) {
        return prev;
      }
      const seen = new Set(prev.map((item) => item.id));
      const merged = [...prev];
      for (const item of logsQ.data!.items) {
        if (!seen.has(item.id)) merged.push(item);
      }
      if (merged.length > 1000) {
        return merged.slice(merged.length - 1000);
      }
      return merged;
    });
    if (!initialized) setInitialized(true);
  }, [logsQ.data, initialized]);

  useEffect(() => {
    if (!follow) return;
    const el = viewerRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [lines, follow]);

  const refreshLogs = () => {
    setSinceID(0);
    setInitialized(false);
    setLines([]);
    void logsQ.refetch();
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">任务日志</h1>
        <p className="page-desc">按任务查看 Worker 执行日志，支持实时轮询与历史回看。</p>
      </div>

      <ProjectScopeBanner title="日志范围" hint="仅显示当前项目下该任务的执行日志。" />

      {!projectID ? (
        <article className="panel">
          <div className="empty-state">请先选择项目后再查看任务日志。</div>
        </article>
      ) : !jobID ? (
        <article className="panel">
          <div className="empty-state">缺少任务 ID，无法加载日志。</div>
        </article>
      ) : (
        <article className="panel">
          <header className="panel-header">
            <h2>日志详情</h2>
            <span className="panel-meta">
              <span className="cell-mono">{jobID}</span>
            </span>
          </header>

          <div className="filter-bar">
            <button className="btn btn-sm" onClick={() => navigate("/jobs")}>返回任务列表</button>
            <button className="btn btn-sm" onClick={refreshLogs}>重新加载</button>
            <button className={`btn btn-sm${follow ? " btn-primary" : ""}`} onClick={() => setFollow((v) => !v)}>
              自动滚动: {follow ? "开" : "关"}
            </button>
            <span className="filter-summary">
              状态: <StatusBadge status={jobStatus} /> | 已加载 {lines.length} 行 | 游标 {sinceID}
            </span>
          </div>

          {logsQ.isLoading && lines.length === 0 && (
            <div className="empty-state">正在加载日志...</div>
          )}
          {logsQ.isError && (
            <div className="empty-state">日志加载失败，请稍后重试。</div>
          )}

          <div className="job-log-viewer" ref={viewerRef}>
            {lines.length === 0 && !logsQ.isLoading ? (
              <div className="empty-state" style={{ margin: 0 }}>暂无日志，任务可能尚未开始或历史日志已清理。</div>
            ) : (
              lines.map((line) => {
                const level = normalizeLevel(line.level);
                return (
                  <div className="job-log-line" key={line.id}>
                    <span className="job-log-time">[{formatDate(line.createdAt)}]</span>
                    <span className={`job-log-level job-log-level-${level}`}>[{level.toUpperCase()}]</span>
                    <span className="job-log-msg">{line.message}</span>
                  </div>
                );
              })
            )}
          </div>
        </article>
      )}
    </section>
  );
}

