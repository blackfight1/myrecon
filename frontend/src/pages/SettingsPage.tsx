import { useState } from "react";
import type { SystemSettings } from "../types/models";
import { useSettings, useTestNotification, useUpdateSettings } from "../hooks/queries";
import { errorMessage } from "../lib/errors";

export function SettingsPage() {
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [editScanner, setEditScanner] = useState(false);
  const [screenshotDir, setScreenshotDir] = useState("");
  const [dnsResolvers, setDnsResolvers] = useState("");
  const [dictSize, setDictSize] = useState(1500);
  const [activeSubs, setActiveSubs] = useState(false);
  const [nuclei, setNuclei] = useState(false);

  const settingsQuery = useSettings();
  const updateMutation = useUpdateSettings();
  const testNotifyMutation = useTestNotification();

  const settings = settingsQuery.data;

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
        setFeedback({ ok: true, text: "扫描器配置已保存" });
      },
      onError: (err) => setFeedback({ ok: false, text: `保存失败：${errorMessage(err)}` })
    });
  };

  const maskValue = (val: string) => {
    if (!val) return "Not set";
    if (val.length <= 10) return "********";
    return `${val.substring(0, 6)}****${val.substring(val.length - 4)}`;
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">系统设置</h1>
        <p className="page-desc">数据库连接状态、通知配置状态（环境变量）和扫描默认参数。</p>
      </div>

      {feedback && (
        <div className="empty-state" style={{ color: feedback.ok ? "#16a34a" : "#dc2626", marginBottom: 12 }}>
          {feedback.text}
        </div>
      )}

      {settingsQuery.isLoading ? (
        <div className="empty-state">正在加载设置...</div>
      ) : !settings ? (
        <div className="empty-state">
          <div className="empty-icon">⚿</div>
          加载设置失败，请检查后端连接。
        </div>
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
              <h2>钉钉通知（环境变量）</h2>
              <span className={`badge ${settings.notifications.enabled ? "badge-success" : "badge-neutral"}`}>
                {settings.notifications.enabled ? "已启用" : "未启用"}
              </span>
            </div>
            <div className="panel-body">
              <div className="settings-grid">
                <div className="setting-row">
                  <span className="setting-label">Webhook</span>
                  <span className="setting-value cell-mono">{maskValue(settings.notifications.dingtalkWebhook)}</span>
                </div>
                <div className="setting-row">
                  <span className="setting-label">Secret</span>
                  <span className="setting-value">{settings.notifications.dingtalkSecret ? "已设置" : "未设置"}</span>
                </div>
              </div>
              <div className="setting-note">
                该模块只读取环境变量：<code>DINGTALK_WEBHOOK</code> / <code>DINGTALK_SECRET</code>。如需修改，请在服务环境中更新并重启后端。
              </div>
              <div style={{ marginTop: 12 }}>
                <button
                  className="btn btn-sm"
                  onClick={() => {
                    setTestResult(null);
                    testNotifyMutation.mutate(undefined, {
                      onSuccess: (data) => setTestResult({ ok: data.success, msg: data.message }),
                      onError: (err) => setTestResult({ ok: false, msg: errorMessage(err) })
                    });
                  }}
                  disabled={testNotifyMutation.isPending || !settings.notifications.enabled}
                >
                  {testNotifyMutation.isPending ? "发送中..." : "发送测试通知"}
                </button>
                {testResult && (
                  <span className={`badge ${testResult.ok ? "badge-success" : "badge-danger"}`} style={{ marginLeft: 8 }}>
                    {testResult.msg}
                  </span>
                )}
              </div>
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
                    <input
                      className="form-input"
                      type="text"
                      value={screenshotDir}
                      onChange={(e) => setScreenshotDir(e.target.value)}
                      placeholder="screenshots"
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">DNS 解析器文件</label>
                    <input
                      className="form-input"
                      type="text"
                      value={dnsResolvers}
                      onChange={(e) => setDnsResolvers(e.target.value)}
                      placeholder="留空使用系统默认"
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">主动爆破字典大小（100-5000）</label>
                    <input
                      className="form-input"
                      type="number"
                      min={100}
                      max={5000}
                      value={dictSize}
                      onChange={(e) => setDictSize(Number(e.target.value) || 100)}
                    />
                  </div>
                  <div className="form-group" style={{ display: "flex", gap: 16 }}>
                    <label className="form-checkbox">
                      <input
                        type="checkbox"
                        checked={activeSubs}
                        onChange={(e) => setActiveSubs(e.target.checked)}
                      />
                      默认启用主动子域名爆破
                    </label>
                    <label className="form-checkbox">
                      <input
                        type="checkbox"
                        checked={nuclei}
                        onChange={(e) => setNuclei(e.target.checked)}
                      />
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
                    <span className="setting-label">主动子域名</span>
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
