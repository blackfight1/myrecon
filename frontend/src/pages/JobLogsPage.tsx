import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { endpoints } from "../api/endpoints";
import { ProjectScopeBanner } from "../components/ui/ProjectScopeBanner";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useWorkspace } from "../context/WorkspaceContext";
import { useJobLogs } from "../hooks/queries";
import { formatDate } from "../lib/format";
import type { JobLogLine } from "../types/models";

type LogLevel = "all" | "debug" | "info" | "warn" | "error";

function normalizeLevel(level: string): "debug" | "info" | "warn" | "error" {
  const lv = level.toLowerCase();
  if (lv === "debug" || lv === "warn" || lv === "error") return lv;
  return "info";
}

function formatLogText(line: JobLogLine): string {
  const lv = normalizeLevel(line.level).toUpperCase();
  return `[${formatDate(line.createdAt)}] [${lv}] ${line.message}`;
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
  const [hasMoreBefore, setHasMoreBefore] = useState<boolean>(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [levelFilter, setLevelFilter] = useState<LogLevel>("all");
  const [keyword, setKeyword] = useState("");
  const [copied, setCopied] = useState<string>("");
  const viewerRef = useRef<HTMLDivElement | null>(null);

  const logsQ = useJobLogs(projectID, jobID || undefined, { sinceId: sinceID, limit: 500 });
  const jobStatus = logsQ.data?.jobStatus ?? "unknown";

  useEffect(() => {
    setSinceID(0);
    setInitialized(false);
    setLines([]);
    setHasMoreBefore(false);
    setLevelFilter("all");
    setKeyword("");
  }, [projectID, jobID]);

  useEffect(() => {
    if (!logsQ.data) return;
    setSinceID((prev) => (logsQ.data!.sinceId > prev ? logsQ.data!.sinceId : prev));
    setLines((prev) => {
      if (!initialized) {
        return logsQ.data!.items;
      }
      if (logsQ.data!.items.length === 0) {
        return prev;
      }
      const seen = new Set(prev.map((item) => item.id));
      const merged = [...prev];
      for (const item of logsQ.data!.items) {
        if (!seen.has(item.id)) merged.push(item);
      }
      if (merged.length > 20000) {
        return merged.slice(merged.length - 20000);
      }
      return merged;
    });
    if (!initialized) {
      setHasMoreBefore(Boolean(logsQ.data.hasMoreBefore));
      setInitialized(true);
    }
  }, [logsQ.data, initialized]);

  useEffect(() => {
    if (!follow) return;
    const el = viewerRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [lines, follow]);

  const filteredLines = useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    return lines.filter((line) => {
      const lv = normalizeLevel(line.level);
      if (levelFilter !== "all" && lv !== levelFilter) {
        return false;
      }
      if (!kw) return true;
      const text = `${line.message} ${line.level} ${line.id}`.toLowerCase();
      return text.includes(kw);
    });
  }, [lines, levelFilter, keyword]);

  const counts = useMemo(() => {
    let debug = 0;
    let info = 0;
    let warn = 0;
    let error = 0;
    for (const line of lines) {
      const lv = normalizeLevel(line.level);
      if (lv === "debug") debug++;
      else if (lv === "warn") warn++;
      else if (lv === "error") error++;
      else info++;
    }
    return { debug, info, warn, error };
  }, [lines]);

  const refreshLogs = () => {
    setSinceID(0);
    setInitialized(false);
    setLines([]);
    setHasMoreBefore(false);
    void logsQ.refetch();
  };

  const loadOlder = async () => {
    if (!projectID || !jobID || lines.length === 0 || loadingOlder || !hasMoreBefore) return;
    setLoadingOlder(true);
    try {
      const beforeId = lines[0].id;
      const resp = await endpoints.getJobLogs(projectID, jobID, { beforeId, limit: 500 });
      if (resp.items.length > 0) {
        setLines((prev) => {
          const seen = new Set(prev.map((item) => item.id));
          const older = resp.items.filter((item) => !seen.has(item.id));
          return [...older, ...prev];
        });
      }
      setHasMoreBefore(Boolean(resp.hasMoreBefore));
    } finally {
      setLoadingOlder(false);
    }
  };

  const loadAllOlder = async () => {
    if (!projectID || !jobID || lines.length === 0 || loadingOlder || !hasMoreBefore) return;
    setLoadingOlder(true);
    try {
      let beforeId = lines[0].id;
      const merged = [...lines];
      const seen = new Set(merged.map((item) => item.id));
      let hasMore: boolean = hasMoreBefore;
      let guard = 0;
      for (; hasMore && guard < 60; guard++) {
        const resp = await endpoints.getJobLogs(projectID, jobID, { beforeId, limit: 500 });
        const older = resp.items.filter((item) => !seen.has(item.id));
        if (older.length > 0) {
          for (const item of older) seen.add(item.id);
          merged.unshift(...older);
          beforeId = merged[0].id;
        }
        hasMore = Boolean(resp.hasMoreBefore) && resp.items.length > 0;
        if (resp.items.length === 0) break;
      }
      setLines(merged);
      setHasMoreBefore(hasMore);
    } finally {
      setLoadingOlder(false);
    }
  };

  const copyVisibleLogs = async () => {
    const content = filteredLines.map(formatLogText).join("\n");
    if (!content) return;
    try {
      await navigator.clipboard.writeText(content);
      setCopied(`已复制 ${filteredLines.length} 行`);
      setTimeout(() => setCopied(""), 1800);
    } catch {
      setCopied("复制失败，请检查浏览器权限");
      setTimeout(() => setCopied(""), 1800);
    }
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">任务日志</h1>
        <p className="page-desc">支持实时追踪、历史回翻、级别筛选和关键词过滤，便于完整排障。</p>
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
            <button className="btn btn-sm btn-secondary" onClick={() => navigate("/jobs")}>
              返回任务列表
            </button>
            <button className="btn btn-sm" onClick={refreshLogs}>
              重新加载
            </button>
            <button className="btn btn-sm" onClick={() => void loadOlder()} disabled={loadingOlder || !hasMoreBefore}>
              {loadingOlder ? "加载中..." : "加载更早日志"}
            </button>
            <button className="btn btn-sm" onClick={() => void loadAllOlder()} disabled={loadingOlder || !hasMoreBefore}>
              加载全部历史
            </button>
            <button className="btn btn-sm" onClick={copyVisibleLogs} disabled={filteredLines.length === 0}>
              复制可见日志
            </button>
            <button className={`btn btn-sm${follow ? " btn-primary" : ""}`} onClick={() => setFollow((v) => !v)}>
              自动滚动: {follow ? "开" : "关"}
            </button>
            <span className="filter-summary">
              状态: <StatusBadge status={jobStatus} /> | 总行数 {lines.length} | 游标 {sinceID}
            </span>
          </div>

          <div className="filter-bar job-log-controls">
            <select className="form-select" value={levelFilter} onChange={(e) => setLevelFilter(e.target.value as LogLevel)}>
              <option value="all">全部级别</option>
              <option value="debug">DEBUG ({counts.debug})</option>
              <option value="info">INFO ({counts.info})</option>
              <option value="warn">WARN ({counts.warn})</option>
              <option value="error">ERROR ({counts.error})</option>
            </select>
            <input className="form-input" placeholder="搜索日志关键词..." value={keyword} onChange={(e) => setKeyword(e.target.value)} />
            <span className="panel-meta">当前显示 {filteredLines.length} 行</span>
            {copied && <span className="panel-meta">{copied}</span>}
          </div>

          {logsQ.isLoading && lines.length === 0 && <div className="empty-state">正在加载日志...</div>}
          {logsQ.isError && <div className="empty-state">日志加载失败，请稍后重试。</div>}

          <div className="job-log-viewer" ref={viewerRef}>
            {filteredLines.length === 0 && !logsQ.isLoading ? (
              <div className="empty-state" style={{ margin: 0 }}>
                暂无日志，任务可能尚未开始或历史日志已清理。
              </div>
            ) : (
              filteredLines.map((line) => {
                const level = normalizeLevel(line.level);
                return (
                  <div className="job-log-line" key={line.id}>
                    <span className="job-log-time">[{formatDate(line.createdAt)}]</span>
                    <span className="job-log-id">#{line.id}</span>
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
