import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useWorkspace } from "../context/WorkspaceContext";
import { useCreateJob, useSettings } from "../hooks/queries";
import { errorMessage } from "../lib/errors";
import { matchesProjectDomain, parseDomainList } from "../lib/projectScope";

const BASELINE_MODULES = ["subs", "httpx", "ports"];

type ToggleOption = {
  key: string;
  title: string;
  desc: string;
  value: boolean;
  setValue: (v: boolean) => void;
};

export function QuickScanPage() {
  const { activeProject } = useWorkspace();
  const createJob = useCreateJob();
  const settingsQuery = useSettings();
  const navigate = useNavigate();

  const settings = settingsQuery.data;
  const scannerDefaults = settings?.scanner;
  const aiSettings = settings?.ai;
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

  const scanTargets = useMemo(() => parseDomainList(scanTargetsRaw), [scanTargetsRaw]);

  const aiSubdictReady = !!(
    aiSettings?.enabled &&
    aiSettings?.configured &&
    aiSettings?.subdictEnabled &&
    activeProject?.aiEnabled
  );

  const aiBlockedReason = useMemo(() => {
    if (!activeProject) return "请先选择项目";
    if (!aiSettings) return "系统设置加载中";
    if (!aiSettings.enabled) return "系统 AI 开关已关闭";
    if (!aiSettings.configured) return "系统 AI 未配置可用密钥";
    if (!aiSettings.subdictEnabled) return "系统设置中未启用 AI 子域名字典生成";
    if (!activeProject.aiEnabled) return "当前项目已关闭 AI";
    return "可用";
  }, [activeProject, aiSettings]);

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

  const applyBasicPreset = () => {
    setEnableWitness(false);
    setEnableNuclei(false);
    setEnableCors(false);
    setEnableSubtakeover(false);
    setEnableActiveSubs(false);
    setEnableBbotActive(false);
    setEnableNotify(true);
  };

  const applyAIEnhancedPreset = () => {
    setEnableWitness(false);
    setEnableNuclei(false);
    setEnableCors(false);
    setEnableSubtakeover(false);
    setEnableActiveSubs(true);
    setEnableBbotActive(true);
    setEnableNotify(true);
  };

  const applyFullPreset = () => {
    setEnableWitness(true);
    setEnableNuclei(true);
    setEnableCors(true);
    setEnableSubtakeover(true);
    setEnableActiveSubs(true);
    setEnableBbotActive(true);
    setEnableNotify(true);
  };

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
    const willUseAISubdict = enableActiveSubs && aiSubdictReady;

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
      setFeedback({
        ok: true,
        text: `已提交 ${success.length} 个扫描任务。${willUseAISubdict ? "本次将启用 AI 子域字典增强。" : ""}`
      });
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

  const toggles: ToggleOption[] = [
    {
      key: "active-subs",
      title: "主动子域（AI字典增强）",
      desc: aiSubdictReady ? "可用：会自动融合 AI 词表进行爆破" : `未就绪：${aiBlockedReason}`,
      value: enableActiveSubs,
      setValue: setEnableActiveSubs
    },
    {
      key: "bbot-active",
      title: "BBOT 主动扩展",
      desc: "额外主动发现子域，速度较慢但覆盖更广",
      value: enableBbotActive,
      setValue: setEnableBbotActive
    },
    {
      key: "nuclei",
      title: "漏洞扫描",
      desc: "启用 Nuclei 模板扫描",
      value: enableNuclei,
      setValue: setEnableNuclei
    },
    {
      key: "cors",
      title: "高危 CORS",
      desc: "执行高风险 CORS 检测",
      value: enableCors,
      setValue: setEnableCors
    },
    {
      key: "subtakeover",
      title: "子域接管",
      desc: "检查常见接管风险",
      value: enableSubtakeover,
      setValue: setEnableSubtakeover
    },
    {
      key: "witness",
      title: "截图",
      desc: "对存活 Web 资产进行截图",
      value: enableWitness,
      setValue: setEnableWitness
    },
    {
      key: "notify",
      title: "通知",
      desc: "任务完成后发送通知",
      value: enableNotify,
      setValue: setEnableNotify
    }
  ];

  return (
    <section className="page">
      <div className="page-header">
        <h1 className="page-title">快速扫描</h1>
        <p className="page-desc">固定基础链路（子域发现 + Web 探测 + 端口扫描），并支持一键开启 AI 增强与扩展模块。</p>
      </div>

      {feedback && (
        <div className={`tool-feedback ${feedback.ok ? "ok" : "error"}`} style={{ marginBottom: 12 }}>
          {feedback.text}
        </div>
      )}

      <article className="panel">
        <header className="panel-header">
          <h2>扫描参数</h2>
          <span className="panel-meta">项目：{activeProject?.name ?? "未选择项目"}</span>
        </header>

        <div className="panel-body">
          <div className="qs-status-grid">
            <div className="qs-status-card">
              <div className="qs-status-label">AI 字典状态</div>
              <div className={`qs-status-value ${aiSubdictReady ? "ok" : "warn"}`}>
                {aiSubdictReady ? "已就绪" : "未就绪"}
              </div>
              <div className="qs-status-desc">{aiBlockedReason}</div>
            </div>

            <div className="qs-status-card">
              <div className="qs-status-label">提交目标数</div>
              <div className="qs-status-value">{scanTargets.length}</div>
              <div className="qs-status-desc">支持换行、空格、逗号分隔</div>
            </div>

            <div className="qs-status-card">
              <div className="qs-status-label">主动字典大小</div>
              <div className="qs-status-value">{scannerDefaults?.defaultDictSize ?? 1500}</div>
              <div className="qs-status-desc">来自系统设置默认值</div>
            </div>
          </div>

          <div className="qs-action-row">
            <button type="button" className="qs-preset-btn" onClick={applyBasicPreset}>基础模式</button>
            <button type="button" className="qs-preset-btn qs-preset-btn-accent" onClick={applyAIEnhancedPreset}>AI增强推荐</button>
            <button type="button" className="qs-preset-btn" onClick={applyFullPreset}>全面模式</button>
            <button type="button" className="qs-link-btn" onClick={() => navigate("/settings")}>去系统设置</button>
          </div>

          <div className="form-group" style={{ marginTop: 14 }}>
            <label className="form-label">扫描目标</label>
            <textarea
              className="form-input form-textarea"
              placeholder={"example.com\nexample.org"}
              value={scanTargetsRaw}
              onChange={(e) => setScanTargetsRaw(e.target.value)}
              rows={4}
            />
          </div>

          {activeProject && projectRootDomains.length > 0 && (
            <div className="panel-meta" style={{ marginTop: 8 }}>
              项目范围：{projectRootDomains.join(", ")}
            </div>
          )}

          <label className="form-label" style={{ marginTop: 16 }}>基础流程（固定）</label>
          <div className="module-grid">
            <span className="module-chip active">子域发现</span>
            <span className="module-chip active">Web 探测</span>
            <span className="module-chip active">端口扫描</span>
          </div>

          <label className="form-label" style={{ marginTop: 16 }}>可选阶段</label>
          <div className="qs-toggle-grid">
            {toggles.map((item) => (
              <button
                key={item.key}
                type="button"
                className={`qs-toggle-card ${item.value ? "active" : ""}`}
                onClick={() => item.setValue(!item.value)}
              >
                <div className="qs-toggle-head">
                  <span className="qs-toggle-title">{item.title}</span>
                  <span className={`qs-toggle-state ${item.value ? "on" : "off"}`}>{item.value ? "ON" : "OFF"}</span>
                </div>
                <div className="qs-toggle-desc">{item.desc}</div>
              </button>
            ))}
          </div>

          <div className="panel-meta" style={{ marginTop: 12 }}>
            执行流程：{previewModules.join(" -> ")} | 通知：{enableNotify ? "开启" : "关闭"}
          </div>

          {enableActiveSubs && !aiSubdictReady && (
            <div className="tool-config-hint" style={{ marginTop: 12 }}>
              当前已开启主动子域，但 AI 字典未就绪，将退化为基础词表爆破。若需 AI 增强，请在系统设置中开启并配置完整。
            </div>
          )}

          <div style={{ marginTop: 20 }}>
            <button
              className="btn btn-primary btn-neon qs-submit-btn"
              onClick={() => {
                void handleQuickScan();
              }}
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
