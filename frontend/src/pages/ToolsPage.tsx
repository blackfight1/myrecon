import { useEffect, useMemo, useState } from "react";
import type { TestAISubdictResponse } from "../api/endpoints";
import { useSettings, useTestAISubdict } from "../hooks/queries";
import { useWorkspace } from "../context/WorkspaceContext";
import { errorMessage } from "../lib/errors";

function splitSubdomains(raw: string): string[] {
  return raw
    .split(/\r?\n|,|;/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function ToolsPage() {
  const { activeProject } = useWorkspace();
  const settingsQuery = useSettings();
  const testMutation = useTestAISubdict();

  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [result, setResult] = useState<TestAISubdictResponse | null>(null);
  const [rootDomain, setRootDomain] = useState("");
  const [sampleRaw, setSampleRaw] = useState("");

  const settings = settingsQuery.data;
  const activeRootDefault = activeProject?.rootDomains?.[0] ?? "";
  const parsedSubdomains = useMemo(() => splitSubdomains(sampleRaw), [sampleRaw]);
  const aiReady = !!settings?.ai.configured && !!settings?.ai.enabled;
  const subdictEnabled = !!settings?.ai.subdictEnabled;

  useEffect(() => {
    if (rootDomain.trim() === "" && activeRootDefault) {
      setRootDomain(activeRootDefault);
    }
  }, [activeRootDefault, rootDomain]);

  const runSubdictTest = () => {
    const projectId = activeProject?.id;
    const domain = rootDomain.trim() || activeRootDefault;

    if (!projectId) {
      setFeedback({ ok: false, text: "请先选择项目后再测试。" });
      return;
    }
    if (!domain) {
      setFeedback({ ok: false, text: "请先填写根域名。" });
      return;
    }
    if (!aiReady) {
      setFeedback({ ok: false, text: "当前系统 AI 未配置完成，请先到系统设置中完成 AI 配置。" });
      return;
    }
    if (!subdictEnabled) {
      setFeedback({ ok: false, text: "当前系统已关闭“子域名字典 AI”，请先在系统设置中开启后再测试。" });
      return;
    }

    setFeedback(null);
    setResult(null);

    testMutation.mutate(
      {
        projectId,
        rootDomain: domain,
        subdomains: parsedSubdomains.length > 0 ? parsedSubdomains : undefined
      },
      {
        onSuccess: (data) => {
          setResult(data);
          setFeedback({
            ok: true,
            text: `生成成功：基线 ${data.baselineCount}，AI ${data.aiCount}，融合 ${data.mergedCount}，AI 命中 ${data.aiWordsUsed}`
          });
        },
        onError: (err) => setFeedback({ ok: false, text: `测试失败：${errorMessage(err)}` })
      }
    );
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">工具中心</h1>
        <p className="page-desc">
          将平台能力按工具模块组织。当前已接入 AI 子域名字典生成器，后续功能点也会统一扩展到这里。
        </p>
      </div>

      <div className="tools-grid">
        <div className="tool-card tool-card-active">
          <div className="tool-card-head">
            <div>
              <div className="tool-card-title">AI 子域名字典生成器</div>
              <div className="tool-card-desc">
                基于已有子域样本生成更贴近目标业务的主动爆破词表，降低无效请求和噪声。
              </div>
            </div>
            <span className="badge badge-success">已上线</span>
          </div>
          <div className="tool-card-tags">
            <span className="badge badge-info">AI</span>
            <span className="badge badge-neutral">Subdomain</span>
            <span className="badge badge-neutral">Bruteforce</span>
          </div>
        </div>

        <div className="tool-card">
          <div className="tool-card-head">
            <div>
              <div className="tool-card-title">URL 画像增强</div>
              <div className="tool-card-desc">规划中：按技术栈和路径特征打标，辅助后续任务策略选择。</div>
            </div>
            <span className="badge badge-neutral">规划中</span>
          </div>
        </div>

        <div className="tool-card">
          <div className="tool-card-head">
            <div>
              <div className="tool-card-title">模板策略模拟</div>
              <div className="tool-card-desc">规划中：模拟不同模板组合的命中率与噪声比。</div>
            </div>
            <span className="badge badge-neutral">规划中</span>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h2>AI 字典生成测试</h2>
          <div className="panel-meta" style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {activeProject ? (
              <span className="badge badge-info">项目：{activeProject.name}</span>
            ) : (
              <span className="badge badge-danger">未选择项目</span>
            )}
            <span className={`badge ${subdictEnabled ? "badge-success" : "badge-neutral"}`}>
              子域字典 AI：{subdictEnabled ? "开启" : "关闭"}
            </span>
            <span className={`badge ${aiReady ? "badge-success" : "badge-danger"}`}>
              系统 AI：{aiReady ? "可用" : "不可用"}
            </span>
          </div>
        </div>

        <div className="panel-body">
          <div className="settings-form">
            <div className="form-group">
              <label className="form-label">根域名</label>
              <input
                className="form-input"
                value={rootDomain}
                onChange={(e) => setRootDomain(e.target.value)}
                placeholder={activeRootDefault || "example.com"}
              />
            </div>

            <div className="form-group">
              <label className="form-label">被动子域样本（可选，每行一个）</label>
              <textarea
                className="form-input form-textarea"
                rows={7}
                value={sampleRaw}
                onChange={(e) => setSampleRaw(e.target.value)}
                placeholder={"api.example.com\nadmin.example.com\ndev.example.com"}
              />
              <div className="setting-note">当前输入样本：{parsedSubdomains.length} 条。留空时将尝试从当前项目历史资产中采样。</div>
            </div>

            <div className="tool-config-hint">
              测试默认使用系统已配置的 AI 中转参数（BaseURL / Model / API Key）。如需修改，请前往「系统设置」。
            </div>

            <div className="form-actions">
              <button
                className="btn btn-primary"
                onClick={runSubdictTest}
                disabled={testMutation.isPending || !activeProject || !aiReady || !subdictEnabled}
              >
                {testMutation.isPending ? "生成中..." : "开始测试"}
              </button>
            </div>

            {feedback && <div className={`tool-feedback ${feedback.ok ? "ok" : "error"}`}>{feedback.text}</div>}

            {result && (
              <div className="tool-result-wrap">
                <div className="tool-result-head">
                  <div>
                    <div className="tool-result-main-title">生成结果</div>
                    <div className="tool-result-subtitle">根域：{result.rootDomain}</div>
                  </div>
                  <span className="badge badge-info">AI 接口：{result.endpoint}</span>
                </div>

                <div className="tool-metric-grid">
                  <div className="tool-metric-card">
                    <div className="tool-metric-title">基线词数</div>
                    <div className="tool-metric-value">{result.baselineCount}</div>
                    <div className="tool-metric-meta">系统默认字典</div>
                  </div>
                  <div className="tool-metric-card">
                    <div className="tool-metric-title">AI 新增词</div>
                    <div className="tool-metric-value">{result.aiCount}</div>
                    <div className="tool-metric-meta">模型返回词项</div>
                  </div>
                  <div className="tool-metric-card">
                    <div className="tool-metric-title">融合词数</div>
                    <div className="tool-metric-value">{result.mergedCount}</div>
                    <div className="tool-metric-meta">去重后总词表</div>
                  </div>
                  <div className="tool-metric-card">
                    <div className="tool-metric-title">AI 命中数</div>
                    <div className="tool-metric-value">{result.aiWordsUsed}</div>
                    <div className="tool-metric-meta">最终被采用的 AI 词</div>
                  </div>
                  <div className="tool-metric-card">
                    <div className="tool-metric-title">输入样本</div>
                    <div className="tool-metric-value">{result.sourceSubdomainCnt}</div>
                    <div className="tool-metric-meta">手动输入或自动抽样源</div>
                  </div>
                  <div className="tool-metric-card">
                    <div className="tool-metric-title">实际采样</div>
                    <div className="tool-metric-value">{result.sampledSubdomainCnt}</div>
                    <div className="tool-metric-meta">实际送入 AI 的样本数</div>
                  </div>
                </div>

                <div className="tool-result-block">
                  <div className="tool-result-title">融合词表预览（前 60 个）</div>
                  <div className="tool-chip-list">
                    {result.mergedWords.slice(0, 60).map((word) => (
                      <span key={word} className="tool-chip">
                        {word}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="tool-result-columns">
                  <div className="tool-result-block">
                    <div className="tool-result-title">Prompt 预览</div>
                    <pre className="tool-pre">{result.promptPreview || "-"}</pre>
                  </div>
                  <div className="tool-result-block">
                    <div className="tool-result-title">模型回复预览</div>
                    <pre className="tool-pre">{result.replyPreview || "-"}</pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
