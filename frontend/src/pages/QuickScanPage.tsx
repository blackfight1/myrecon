import { useEffect, useMemo, useState } from "react";
import { useWorkspace } from "../context/WorkspaceContext";
import { useCreateJob, useSettings } from "../hooks/queries";
import { errorMessage } from "../lib/errors";
import { matchesProjectDomain, parseDomainList } from "../lib/projectScope";

const BASELINE_MODULES = ["subs", "httpx", "ports"];

export function QuickScanPage() {
  const { activeProject } = useWorkspace();
  const createJob = useCreateJob();
  const settingsQuery = useSettings();
  const scannerDefaults = settingsQuery.data?.scanner;
  const projectRootDomains = activeProject?.rootDomains ?? [];
  const projectRootDomainsKey = projectRootDomains.join("\n");

  const [scanTargetsRaw, setScanTargetsRaw] = useState(projectRootDomainsKey);
  const [enableWitness, setEnableWitness] = useState(false);
  const [enableNuclei, setEnableNuclei] = useState(false);
  const [enableCors, setEnableCors] = useState(false);
  const [enableSubtakeover, setEnableSubtakeover] = useState(false);
  const [enableActiveSubs, setEnableActiveSubs] = useState(false);
  const [enableBbotActive, setEnableBbotActive] = useState(false);
  const [enableNotify, setEnableNotify] = useState(true);
  const [defaultsLoaded, setDefaultsLoaded] = useState(false);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const previewModules = useMemo(
    () => [
      ...BASELINE_MODULES,
      ...(enableActiveSubs ? ["dnsx_bruteforce"] : []),
      ...(enableBbotActive ? ["bbot_active"] : []),
      ...(enableWitness ? ["witness"] : []),
      ...(enableNuclei ? ["nuclei"] : []),
      ...(enableCors ? ["cors"] : []),
      ...(enableSubtakeover ? ["subtakeover"] : [])
    ],
    [enableActiveSubs, enableBbotActive, enableWitness, enableNuclei, enableCors, enableSubtakeover]
  );

  const scanTargets = useMemo(() => parseDomainList(scanTargetsRaw), [scanTargetsRaw]);

  useEffect(() => {
    setScanTargetsRaw(projectRootDomainsKey);
  }, [activeProject?.id, projectRootDomainsKey]);

  useEffect(() => {
    if (defaultsLoaded || !scannerDefaults) return;
    setEnableNuclei(scannerDefaults.defaultNuclei);
    setEnableCors(scannerDefaults.defaultNuclei);
    setEnableActiveSubs(scannerDefaults.defaultActiveSubs);
    setDefaultsLoaded(true);
  }, [defaultsLoaded, scannerDefaults]);

  const handleQuickScan = async () => {
    if (!activeProject?.id) return;

    setFeedback(null);
    if (scanTargets.length === 0) {
      setFeedback({ ok: false, text: "请至少输入一个扫描目标。" });
      return;
    }

    const outOfScope = scanTargets.filter((domain) => !matchesProjectDomain(domain, projectRootDomains));
    if (outOfScope.length > 0) {
      setFeedback({ ok: false, text: `以下目标不在当前项目范围内：${outOfScope.join(", ")}` });
      return;
    }

    const modules = [...BASELINE_MODULES];
    if (enableActiveSubs) modules.push("dnsx_bruteforce");
    if (enableBbotActive) modules.push("bbot_active");
    if (enableWitness) modules.push("witness");
    if (enableNuclei) modules.push("nuclei");
    if (enableCors) modules.push("cors");
    if (enableSubtakeover) modules.push("subtakeover");

    const success: string[] = [];
    const failed: string[] = [];

    for (const domain of scanTargets) {
      try {
        const job = await createJob.mutateAsync({
          projectId: activeProject.id,
          domain,
          modules,
          mode: "scan",
          enableNuclei,
          activeSubs: enableActiveSubs,
          dictSize: scannerDefaults?.defaultDictSize ?? 1500,
          dryRun: false,
          notify: enableNotify
        });
        success.push(`${domain} (${job.id})`);
      } catch (err) {
        failed.push(`${domain}: ${errorMessage(err)}`);
      }
    }

    if (failed.length === 0) {
      setFeedback({ ok: true, text: `已提交 ${success.length} 个扫描任务。` });
      return;
    }

    if (success.length === 0) {
      setFeedback({ ok: false, text: `任务提交失败：${failed.join(" | ")}` });
      return;
    }

    setFeedback({
      ok: false,
      text: `已提交 ${success.length} 个任务，${failed.length} 个失败：${failed.join(" | ")}`
    });
  };

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">快速扫描</h1>
        <p className="page-desc">固定流程：子域发现 + Web 探测 + 端口扫描，可选截图与漏洞扫描。</p>
      </div>

      {feedback && (
        <div className="empty-state" style={{ color: feedback.ok ? "#16a34a" : "#dc2626", marginBottom: 12 }}>
          {feedback.text}
        </div>
      )}

      <article className="panel">
        <header className="panel-header">
          <h2>扫描参数</h2>
          <span className="panel-meta">项目: {activeProject?.name ?? "未选择项目"}</span>
        </header>

        <div className="panel-body">
          <div className="form-group">
            <label className="form-label">扫描目标</label>
            <textarea
              className="form-input form-textarea"
              placeholder="example.com&#10;example.org"
              value={scanTargetsRaw}
              onChange={(e) => setScanTargetsRaw(e.target.value)}
              rows={4}
            />
          </div>

          {activeProject && projectRootDomains.length > 0 && (
            <div className="panel-meta" style={{ marginTop: 8 }}>
              项目范围: {projectRootDomains.join(", ")}
            </div>
          )}

          <div className="panel-meta" style={{ marginTop: 8 }}>
            当前将提交 {scanTargets.length} 个目标，支持换行、空格或逗号分隔。
          </div>

          <label className="form-label" style={{ marginTop: 16 }}>基础流程（固定）</label>
          <div className="module-grid">
            <span className="module-chip active">子域发现</span>
            <span className="module-chip active">Web 探测</span>
            <span className="module-chip active">端口扫描</span>
          </div>

          <label className="form-label" style={{ marginTop: 16 }}>可选阶段</label>
          <div className="module-grid">
            <button className={`module-chip ${enableWitness ? "active" : ""}`} onClick={() => setEnableWitness((v) => !v)}>
              截图 {enableWitness ? "ON" : "OFF"}
            </button>
            <button className={`module-chip ${enableNuclei ? "active" : ""}`} onClick={() => setEnableNuclei((v) => !v)}>
              漏洞扫描 {enableNuclei ? "ON" : "OFF"}
            </button>
            <button className={`module-chip ${enableCors ? "active" : ""}`} onClick={() => setEnableCors((v) => !v)}>
              高危CORS {enableCors ? "ON" : "OFF"}
            </button>
            <button className={`module-chip ${enableSubtakeover ? "active" : ""}`} onClick={() => setEnableSubtakeover((v) => !v)}>
              子域接管 {enableSubtakeover ? "ON" : "OFF"}
            </button>
            <button className={`module-chip ${enableActiveSubs ? "active" : ""}`} onClick={() => setEnableActiveSubs((v) => !v)}>
              主动子域 {enableActiveSubs ? "ON" : "OFF"}
            </button>
            <button className={`module-chip ${enableBbotActive ? "active" : ""}`} onClick={() => setEnableBbotActive((v) => !v)}>
              BBOT主动扩展 {enableBbotActive ? "ON" : "OFF"}
            </button>
            <button className={`module-chip ${enableNotify ? "active" : ""}`} onClick={() => setEnableNotify((v) => !v)}>
              通知 {enableNotify ? "ON" : "OFF"}
            </button>
          </div>

          <div className="panel-meta" style={{ marginTop: 12 }}>
            执行流程: {previewModules.join(" -> ")} | 通知: {enableNotify ? "开启" : "关闭"}
          </div>

          <div style={{ marginTop: 20 }}>
            <button
              className="btn btn-primary btn-neon"
              onClick={() => { void handleQuickScan(); }}
              disabled={createJob.isPending || !activeProject?.id || scanTargets.length === 0}
            >
              {createJob.isPending ? "提交中..." : "开始快速扫描"}
            </button>
          </div>
        </div>
      </article>
    </section>
  );
}
