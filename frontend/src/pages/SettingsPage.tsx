import { useState } from "react";
import type { SystemSettings } from "../types/models";
import { useNavigate } from "react-router-dom";
import { useSettings, useTestAI, useTestNotification, useUpdateSettings } from "../hooks/queries";
import { errorMessage } from "../lib/errors";
import { useWorkspace } from "../context/WorkspaceContext";

export function SettingsPage() {
  const [testNotifyResult, setTestNotifyResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testAIResult, setTestAIResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const [editScanner, setEditScanner] = useState(false);
  const [screenshotDir, setScreenshotDir] = useState("");
  const [dnsResolvers, setDnsResolvers] = useState("");
  const [dictSize, setDictSize] = useState(1500);
  const [activeSubs, setActiveSubs] = useState(false);
  const [nuclei, setNuclei] = useState(false);

  const [editAI, setEditAI] = useState(false);
  const [aiEnabled, setAIEnabled] = useState(true);
  const [aiBaseURL, setAIBaseURL] = useState("");
  const [aiAPIKey, setAIAPIKey] = useState("");
  const [aiModel, setAIModel] = useState("");
  const [aiTimeoutSec, setAITimeoutSec] = useState(30);
  const [aiMaxRetries, setAIMaxRetries] = useState(2);
  const [aiRPM, setAIRPM] = useState(60);
  const [aiSubdictEnabled, setAISubdictEnabled] = useState(false);
  const [aiSubdictMaxWords, setAISubdictMaxWords] = useState(300);
  const [aiSubdictSampleSize, setAISubdictSampleSize] = useState(200);

  const settingsQuery = useSettings();
  const updateMutation = useUpdateSettings();
  const testNotifyMutation = useTestNotification();
  const testAIMutation = useTestAI();
  const navigate = useNavigate();
  const { activeProject } = useWorkspace();
  const settings = settingsQuery.data;

  const maskValue = (val: string) => {
    if (!val) return "未设置";
    if (val.length <= 10) return "********";
    return `${val.substring(0, 6)}****${val.substring(val.length - 4)}`;
  };

  const startEditScanner = () => {
    if (!settings) return;
    setScreenshotDir(settings.scanner.screenshotDir);
    setDnsResolvers(settings.scanner.dnsResolvers);
    setDictSize(settings.scanner.defaultDictSize);
    setActiveSubs(settings.scanner.defaultActiveSubs);
    setNuclei(settings.scanner.defaultNuclei);
    setEditScanner(true);
    setFeedback(null);
  };

  const saveScanner = () => {
    const payload: Partial<SystemSettings> = {
      scanner: {
        screenshotDir: screenshotDir.trim(),
        dnsResolvers: dnsResolvers.trim(),
        defaultDictSize: dictSize,
        defaultActiveSubs: activeSubs,
        defaultNuclei: nuclei
      }
    };
    setFeedback(null);
    updateMutation.mutate(payload, {
      onSuccess: () => {
        setEditScanner(false);
        setFeedback({ ok: true, text: "扫描器默认配置已保存" });
      },
      onError: (err) => setFeedback({ ok: false, text: `保存失败：${errorMessage(err)}` })
    });
  };

  const startEditAI = () => {
    if (!settings) return;
    setAIEnabled(settings.ai.enabled);
    setAIBaseURL(settings.ai.baseUrl);
    setAIModel(settings.ai.model);
    setAITimeoutSec(settings.ai.timeoutSec);
    setAIMaxRetries(settings.ai.maxRetries);
    setAIRPM(settings.ai.requestsPerMinute);
    setAISubdictEnabled(settings.ai.subdictEnabled);
    setAISubdictMaxWords(settings.ai.subdictMaxWords);
    setAISubdictSampleSize(settings.ai.subdictSampleSize);
    setAIAPIKey("");
    setTestAIResult(null);
    setEditAI(true);
    setFeedback(null);
  };

  const saveAI = () => {
    const aiPatch: {
      enabled: boolean;
      baseUrl: string;
      model: string;
      timeoutSec: number;
      maxRetries: number;
      requestsPerMinute: number;
      subdictEnabled: boolean;
      subdictMaxWords: number;
      subdictSampleSize: number;
      apiKey?: string;
    } = {
      enabled: aiEnabled,
      baseUrl: aiBaseURL.trim(),
      model: aiModel.trim(),
      timeoutSec: aiTimeoutSec,
      maxRetries: aiMaxRetries,
      requestsPerMinute: aiRPM,
      subdictEnabled: aiSubdictEnabled,
      subdictMaxWords: aiSubdictMaxWords,
      subdictSampleSize: aiSubdictSampleSize
    };
    if (aiAPIKey.trim() !== "") {
      aiPatch.apiKey = aiAPIKey.trim();
    }
    const payload = { ai: aiPatch } as Partial<SystemSettings>;
    setFeedback(null);
    updateMutation.mutate(payload, {
      onSuccess: () => {
        setEditAI(false);
        setAIAPIKey("");
        setFeedback({ ok: true, text: "AI 配置已保存" });
      },
      onError: (err) => setFeedback({ ok: false, text: `AI 保存失败：${errorMessage(err)}` })
    });
  };

  const testAI = (opts?: { useDraft?: boolean }) => {
    if (!settings && !opts?.useDraft) return;
    setTestAIResult(null);
    const body = opts?.useDraft
      ? {
          projectId: activeProject?.id,
          enabled: aiEnabled,
          baseUrl: aiBaseURL.trim(),
          apiKey: aiAPIKey.trim() || undefined,
          model: aiModel.trim() || undefined,
          prompt: "Reply with pong only."
        }
      : {
          projectId: activeProject?.id
        };
    testAIMutation.mutate(body, {
      onSuccess: (data) => setTestAIResult({ ok: true, msg: `连接成功（${data.endpoint}）：${data.reply}` }),
      onError: (err) => setTestAIResult({ ok: false, msg: errorMessage(err) })
    });
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">系统设置</h1>
        <p className="page-desc">查看系统状态，调整扫描默认参数，并配置 AI 中转站。</p>
      </div>

      {feedback && (
        <div className="empty-state" style={{ color: feedback.ok ? "#16a34a" : "#dc2626", marginBottom: 12 }}>
          {feedback.text}
        </div>
      )}

      {settingsQuery.isLoading ? (
        <div className="empty-state">正在加载设置...</div>
      ) : !settings ? (
        <div className="empty-state">加载设置失败，请检查后端连接。</div>
      ) : (
        <>
          <div className="panel">
            <div className="panel-header">
              <h2>数据库</h2>
              <span className={`badge ${settings.database.connected ? "badge-success" : "badge-danger"}`}>
                {settings.database.connected ? "已连接" : "未连接"}
              </span>
            </div>
            <div className="panel-body">
              <div className="settings-grid">
                <div className="setting-row">
                  <span className="setting-label">主机</span>
                  <span className="setting-value">{settings.database.host}:{settings.database.port}</span>
                </div>
                <div className="setting-row">
                  <span className="setting-label">用户</span>
                  <span className="setting-value">{settings.database.user}</span>
                </div>
                <div className="setting-row">
                  <span className="setting-label">数据库</span>
                  <span className="setting-value">{settings.database.dbname}</span>
                </div>
                <div className="setting-row">
                  <span className="setting-label">SSL 模式</span>
                  <span className="setting-value">{settings.database.sslmode}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h2>飞书通知（环境变量）</h2>
              <span className={`badge ${settings.notifications.enabled ? "badge-success" : "badge-neutral"}`}>
                {settings.notifications.enabled ? "已启用" : "未启用"}
              </span>
            </div>
            <div className="panel-body">
              <div className="settings-grid">
                <div className="setting-row">
                  <span className="setting-label">Webhook</span>
                  <span className="setting-value cell-mono">{maskValue(settings.notifications.feishuWebhook)}</span>
                </div>
              </div>
              <div className="setting-note">该模块读取环境变量 `FEISHU_WEBHOOK`。</div>
              <div style={{ marginTop: 12 }}>
                <button
                  className="btn btn-sm"
                  onClick={() => {
                    setTestNotifyResult(null);
                    testNotifyMutation.mutate(undefined, {
                      onSuccess: (data) => setTestNotifyResult({ ok: data.success, msg: data.message }),
                      onError: (err) => setTestNotifyResult({ ok: false, msg: errorMessage(err) })
                    });
                  }}
                  disabled={testNotifyMutation.isPending || !settings.notifications.enabled}
                >
                  {testNotifyMutation.isPending ? "发送中..." : "发送测试通知"}
                </button>
                {testNotifyResult && (
                  <span className={`badge ${testNotifyResult.ok ? "badge-success" : "badge-danger"}`} style={{ marginLeft: 8 }}>
                    {testNotifyResult.msg}
                  </span>
                )}
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h2>AI Provider（中转站）</h2>
              {!editAI && (
                <button className="btn btn-sm" onClick={startEditAI}>
                  编辑
                </button>
              )}
            </div>
            <div className="panel-body">
              {editAI ? (
                <div className="settings-form">
                  <div className="form-group">
                    <label className="form-checkbox">
                      <input type="checkbox" checked={aiEnabled} onChange={(e) => setAIEnabled(e.target.checked)} />
                      启用 AI 调用（全局）
                    </label>
                  </div>
                  <div className="form-group">
                    <label className="form-label">API 请求地址</label>
                    <input
                      className="form-input"
                      type="text"
                      value={aiBaseURL}
                      onChange={(e) => setAIBaseURL(e.target.value)}
                      placeholder="https://code.rayinai.com/v1"
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">API Key</label>
                    <input
                      className="form-input"
                      type="password"
                      value={aiAPIKey}
                      onChange={(e) => setAIAPIKey(e.target.value)}
                      placeholder="留空表示保持当前密钥"
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">模型名称</label>
                    <input
                      className="form-input"
                      type="text"
                      value={aiModel}
                      onChange={(e) => setAIModel(e.target.value)}
                      placeholder="gpt-5.3-codex"
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">超时（秒）</label>
                    <input className="form-input" type="number" min={5} max={120} value={aiTimeoutSec} onChange={(e) => setAITimeoutSec(Number(e.target.value) || 5)} />
                  </div>
                  <div className="form-group">
                    <label className="form-label">失败重试次数</label>
                    <input className="form-input" type="number" min={0} max={5} value={aiMaxRetries} onChange={(e) => setAIMaxRetries(Number(e.target.value) || 0)} />
                  </div>
                  <div className="form-group">
                    <label className="form-label">速率限制（次/分钟，0=不限制）</label>
                    <input className="form-input" type="number" min={0} max={600} value={aiRPM} onChange={(e) => setAIRPM(Number(e.target.value) || 0)} />
                  </div>
                  <div className="form-group">
                    <label className="form-checkbox">
                      <input type="checkbox" checked={aiSubdictEnabled} onChange={(e) => setAISubdictEnabled(e.target.checked)} />
                      启用 AI 子域名字典生成（用于主动爆破）
                    </label>
                  </div>
                  <div className="form-group">
                    <label className="form-label">AI 字典词数上限</label>
                    <input className="form-input" type="number" min={20} max={5000} value={aiSubdictMaxWords} onChange={(e) => setAISubdictMaxWords(Number(e.target.value) || 20)} />
                  </div>
                  <div className="form-group">
                    <label className="form-label">AI 样本子域名数量</label>
                    <input className="form-input" type="number" min={20} max={2000} value={aiSubdictSampleSize} onChange={(e) => setAISubdictSampleSize(Number(e.target.value) || 20)} />
                  </div>
                  <div className="form-actions">
                    <button className="btn btn-sm" onClick={() => testAI({ useDraft: true })} disabled={testAIMutation.isPending}>
                      {testAIMutation.isPending ? "测试中..." : "测试连接"}
                    </button>
                    <button className="btn btn-primary" onClick={saveAI} disabled={updateMutation.isPending}>
                      {updateMutation.isPending ? "保存中..." : "保存"}
                    </button>
                    <button className="btn btn-sm" onClick={() => setEditAI(false)} disabled={updateMutation.isPending || testAIMutation.isPending}>
                      取消
                    </button>
                  </div>
                  {testAIResult && (
                    <div className="setting-note" style={{ color: testAIResult.ok ? "#16a34a" : "#dc2626" }}>
                      {testAIResult.msg}
                    </div>
                  )}
                </div>
              ) : (
                <>
                  <div className="settings-grid">
                    <div className="setting-row">
                      <span className="setting-label">配置状态</span>
                      <span className={`badge ${settings.ai.configured ? "badge-success" : "badge-neutral"}`}>
                        {settings.ai.configured ? "已配置" : "未配置"}
                      </span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">全局开关</span>
                      <span className={`badge ${settings.ai.enabled ? "badge-success" : "badge-neutral"}`}>
                        {settings.ai.enabled ? "已启用" : "已关闭"}
                      </span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">API 地址</span>
                      <span className="setting-value cell-mono">{settings.ai.baseUrl || "-"}</span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">模型</span>
                      <span className="setting-value">{settings.ai.model || "-"}</span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">API Key</span>
                      <span className="setting-value cell-mono">{maskValue(settings.ai.apiKey)}</span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">超时</span>
                      <span className="setting-value">{settings.ai.timeoutSec}s</span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">重试</span>
                      <span className="setting-value">{settings.ai.maxRetries}</span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">速率限制</span>
                      <span className="setting-value">{settings.ai.requestsPerMinute}/min</span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">子域名字典 AI</span>
                      <span className={`badge ${settings.ai.subdictEnabled ? "badge-success" : "badge-neutral"}`}>
                        {settings.ai.subdictEnabled ? "已启用" : "未启用"}
                      </span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">子域名字典词数上限</span>
                      <span className="setting-value">{settings.ai.subdictMaxWords}</span>
                    </div>
                    <div className="setting-row">
                      <span className="setting-label">子域名字典样本上限</span>
                      <span className="setting-value">{settings.ai.subdictSampleSize}</span>
                    </div>
                    {activeProject && (
                      <div className="setting-row">
                        <span className="setting-label">当前项目</span>
                        <span className="setting-value">{activeProject.name}（AI {activeProject.aiEnabled ? "开启" : "关闭"}）</span>
                      </div>
                    )}
                  </div>
                  <div style={{ marginTop: 12 }}>
                    <button
                      className="btn btn-sm"
                      onClick={() => testAI()}
                      disabled={testAIMutation.isPending || !settings.ai.configured || !settings.ai.enabled}
                    >
                      {testAIMutation.isPending ? "测试中..." : "测试 AI 连接"}
                    </button>
                    <button className="btn btn-sm" style={{ marginLeft: 8 }} onClick={() => navigate("/tools")}>
                      打开工具中心
                    </button>
                    {testAIResult && (
                      <span className={`badge ${testAIResult.ok ? "badge-success" : "badge-danger"}`} style={{ marginLeft: 8 }}>
                        {testAIResult.msg}
                      </span>
                    )}
                  </div>
                  <div className="setting-note">AI 子域名字典生成测试已迁移到「工具中心」，便于后续统一扩展更多工具能力。</div>
                </>
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h2>扫描器默认配置</h2>
              {!editScanner && (
                <button className="btn btn-sm" onClick={startEditScanner}>
                  编辑
                </button>
              )}
            </div>
            <div className="panel-body">
              {editScanner ? (
                <div className="settings-form">
                  <div className="form-group">
                    <label className="form-label">截图目录</label>
                    <input className="form-input" type="text" value={screenshotDir} onChange={(e) => setScreenshotDir(e.target.value)} placeholder="screenshots" />
                  </div>
                  <div className="form-group">
                    <label className="form-label">DNS 解析器文件</label>
                    <input className="form-input" type="text" value={dnsResolvers} onChange={(e) => setDnsResolvers(e.target.value)} placeholder="留空使用系统默认" />
                  </div>
                  <div className="form-group">
                    <label className="form-label">主动爆破字典大小</label>
                    <input className="form-input" type="number" min={100} max={5000} value={dictSize} onChange={(e) => setDictSize(Number(e.target.value) || 100)} />
                  </div>
                  <div className="form-group" style={{ display: "flex", gap: 16 }}>
                    <label className="form-checkbox">
                      <input type="checkbox" checked={activeSubs} onChange={(e) => setActiveSubs(e.target.checked)} />
                      默认启用主动子域爆破
                    </label>
                    <label className="form-checkbox">
                      <input type="checkbox" checked={nuclei} onChange={(e) => setNuclei(e.target.checked)} />
                      默认启用 Nuclei 漏扫
                    </label>
                  </div>
                  <div className="form-actions">
                    <button className="btn btn-primary" onClick={saveScanner} disabled={updateMutation.isPending}>
                      {updateMutation.isPending ? "保存中..." : "保存"}
                    </button>
                    <button className="btn btn-sm" onClick={() => setEditScanner(false)} disabled={updateMutation.isPending}>
                      取消
                    </button>
                  </div>
                </div>
              ) : (
                <div className="settings-grid">
                  <div className="setting-row">
                    <span className="setting-label">截图目录</span>
                    <span className="setting-value cell-mono">{settings.scanner.screenshotDir}</span>
                  </div>
                  <div className="setting-row">
                    <span className="setting-label">DNS 解析器</span>
                    <span className="setting-value">{settings.scanner.dnsResolvers || "系统默认"}</span>
                  </div>
                  <div className="setting-row">
                    <span className="setting-label">字典大小</span>
                    <span className="setting-value">{settings.scanner.defaultDictSize}</span>
                  </div>
                  <div className="setting-row">
                    <span className="setting-label">主动子域爆破</span>
                    <span className={`badge ${settings.scanner.defaultActiveSubs ? "badge-success" : "badge-neutral"}`}>
                      {settings.scanner.defaultActiveSubs ? "已启用" : "未启用"}
                    </span>
                  </div>
                  <div className="setting-row">
                    <span className="setting-label">Nuclei</span>
                    <span className={`badge ${settings.scanner.defaultNuclei ? "badge-success" : "badge-neutral"}`}>
                      {settings.scanner.defaultNuclei ? "已启用" : "未启用"}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
