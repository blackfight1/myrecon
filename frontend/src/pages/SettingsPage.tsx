import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { endpoints } from "../api/endpoints";
import type { SystemSettings, ToolStatus } from "../types/models";

export function SettingsPage() {
    const queryClient = useQueryClient();
    const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);

    const settingsQuery = useQuery({
        queryKey: ["settings"],
        queryFn: endpoints.getSettings,
    });

    const toolsQuery = useQuery({
        queryKey: ["tool-status"],
        queryFn: endpoints.getToolStatus,
    });

    const updateMutation = useMutation({
        mutationFn: (body: Partial<SystemSettings>) => endpoints.updateSettings(body),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["settings"] });
        },
    });

    const testNotifyMutation = useMutation({
        mutationFn: () => endpoints.testNotification(),
        onSuccess: (data) => setTestResult({ ok: data.success, msg: data.message }),
        onError: (err: Error) => setTestResult({ ok: false, msg: err.message }),
    });

    const settings = settingsQuery.data;
    const tools: ToolStatus[] = toolsQuery.data ?? [];

    const [editNotify, setEditNotify] = useState(false);
    const [webhook, setWebhook] = useState("");
    const [secret, setSecret] = useState("");

    const [editScanner, setEditScanner] = useState(false);
    const [screenshotDir, setScreenshotDir] = useState("");
    const [dnsResolvers, setDnsResolvers] = useState("");
    const [dictSize, setDictSize] = useState(1500);
    const [activeSubs, setActiveSubs] = useState(false);
    const [nuclei, setNuclei] = useState(false);

    const startEditNotify = () => {
        if (settings) {
            setWebhook(settings.notifications.dingtalkWebhook);
            // Never preload masked secret from API; keep empty means "unchanged".
            setSecret("");
        }
        setEditNotify(true);
    };

    const saveNotify = () => {
        updateMutation.mutate({
            notifications: {
                dingtalkWebhook: webhook,
                dingtalkSecret: secret,
                enabled: webhook.trim() !== "",
            },
        });
        setEditNotify(false);
    };

    const startEditScanner = () => {
        if (settings) {
            setScreenshotDir(settings.scanner.screenshotDir);
            setDnsResolvers(settings.scanner.dnsResolvers);
            setDictSize(settings.scanner.defaultDictSize);
            setActiveSubs(settings.scanner.defaultActiveSubs);
            setNuclei(settings.scanner.defaultNuclei);
        }
        setEditScanner(true);
    };

    const saveScanner = () => {
        updateMutation.mutate({
            scanner: {
                screenshotDir,
                dnsResolvers,
                defaultDictSize: dictSize,
                defaultActiveSubs: activeSubs,
                defaultNuclei: nuclei,
            },
        });
        setEditScanner(false);
    };

    const maskValue = (val: string) => {
        if (!val) return "—";
        if (val.length <= 10) return "••••••";
        return val.substring(0, 8) + "••••" + val.substring(val.length - 4);
    };

    return (
        <div className="page">
            <div className="page-header">
                <h1 className="page-title">⊟ 系统设置</h1>
                <p className="page-desc">
                    系统配置 — 数据库、通知、扫描器默认值和工具状态
                </p>
            </div>

            {settingsQuery.isLoading ? (
                <div className="empty-state">正在加载设置…</div>
            ) : !settings ? (
                <div className="empty-state">
                    <div className="empty-icon">⚠</div>
                    加载设置失败，请检查后端连接。
                </div>
            ) : (
                <>
                    {/* ── 数据库 ── */}
                    <div className="panel">
                        <div className="panel-header">
                            <h2>🗄 数据库</h2>
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
                                    <span className="setting-label">数据库名</span>
                                    <span className="setting-value">{settings.database.dbname}</span>
                                </div>
                                <div className="setting-row">
                                    <span className="setting-label">SSL 模式</span>
                                    <span className="setting-value">{settings.database.sslmode}</span>
                                </div>
                            </div>
                            <div className="setting-note">
                                数据库连接通过环境变量或命令行参数配置。更改后需重启后端服务生效。
                            </div>
                        </div>
                    </div>

                    {/* ── 通知 ── */}
                    <div className="panel">
                        <div className="panel-header">
                            <h2>🔔 钉钉通知</h2>
                            <div style={{ display: "flex", gap: 6 }}>
                                <span className={`badge ${settings.notifications.enabled ? "badge-success" : "badge-neutral"}`}>
                                    {settings.notifications.enabled ? "已启用" : "未启用"}
                                </span>
                                {!editNotify && (
                                    <button className="btn btn-sm" onClick={startEditNotify}>
                                        编辑
                                    </button>
                                )}
                            </div>
                        </div>
                        <div className="panel-body">
                            {editNotify ? (
                                <div className="settings-form">
                                    <div className="form-group">
                                        <label className="form-label">Webhook 地址</label>
                                        <input
                                            className="form-input"
                                            type="text"
                                            value={webhook}
                                            onChange={(e) => setWebhook(e.target.value)}
                                            placeholder="https://oapi.dingtalk.com/robot/send?access_token=…"
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label className="form-label">Secret（可选，签名模式）</label>
                                        <input
                                            className="form-input"
                                            type="password"
                                            value={secret}
                                            onChange={(e) => setSecret(e.target.value)}
                                            placeholder="留空则保持现有 Secret 不变"
                                        />
                                    </div>
                                    <div className="form-actions">
                                        <button className="btn btn-primary" onClick={saveNotify} disabled={updateMutation.isPending}>
                                            保存
                                        </button>
                                        <button className="btn btn-sm" onClick={() => setEditNotify(false)}>
                                            取消
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <div className="settings-grid">
                                    <div className="setting-row">
                                        <span className="setting-label">Webhook</span>
                                        <span className="setting-value cell-mono">
                                            {maskValue(settings.notifications.dingtalkWebhook)}
                                        </span>
                                    </div>
                                    <div className="setting-row">
                                        <span className="setting-label">Secret</span>
                                        <span className="setting-value">
                                            {settings.notifications.dingtalkSecret ? "••••••••" : "未设置"}
                                        </span>
                                    </div>
                                </div>
                            )}

                            <div style={{ marginTop: 12 }}>
                                <button
                                    className="btn btn-sm"
                                    onClick={() => { setTestResult(null); testNotifyMutation.mutate(); }}
                                    disabled={testNotifyMutation.isPending || !settings.notifications.enabled}
                                >
                                    {testNotifyMutation.isPending ? "发送中…" : "🔔 发送测试通知"}
                                </button>
                                {testResult && (
                                    <span className={`badge ${testResult.ok ? "badge-success" : "badge-danger"}`} style={{ marginLeft: 8 }}>
                                        {testResult.msg}
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* ── 扫描器默认值 ── */}
                    <div className="panel">
                        <div className="panel-header">
                            <h2>⚙ 扫描器默认配置</h2>
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
                                        <label className="form-label">截图存储目录</label>
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
                                        <label className="form-label">主动爆破字典大小（100–5000）</label>
                                        <input
                                            className="form-input"
                                            type="number"
                                            min={100}
                                            max={5000}
                                            value={dictSize}
                                            onChange={(e) => setDictSize(Number(e.target.value))}
                                        />
                                    </div>
                                    <div className="form-group" style={{ display: "flex", gap: 16 }}>
                                        <label className="form-checkbox">
                                            <input
                                                type="checkbox"
                                                checked={activeSubs}
                                                onChange={(e) => setActiveSubs(e.target.checked)}
                                            />
                                            启用主动子域名爆破
                                        </label>
                                        <label className="form-checkbox">
                                            <input
                                                type="checkbox"
                                                checked={nuclei}
                                                onChange={(e) => setNuclei(e.target.checked)}
                                            />
                                            启用 Nuclei 漏洞扫描
                                        </label>
                                    </div>
                                    <div className="form-actions">
                                        <button className="btn btn-primary" onClick={saveScanner} disabled={updateMutation.isPending}>
                                            保存
                                        </button>
                                        <button className="btn btn-sm" onClick={() => setEditScanner(false)}>
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

                    {/* ── 工具状态 ── */}
                    <div className="panel">
                        <div className="panel-header">
                            <h2>🔧 侦察工具状态</h2>
                            <button className="btn btn-sm" onClick={() => toolsQuery.refetch()}>
                                刷新
                            </button>
                        </div>
                        {toolsQuery.isLoading ? (
                            <div className="panel-body">
                                <div className="empty-state">正在检测工具…</div>
                            </div>
                        ) : tools.length === 0 ? (
                            <div className="panel-body">
                                <div className="empty-state">
                                    <div className="empty-icon">🔧</div>
                                    暂无工具数据。
                                </div>
                            </div>
                        ) : (
                            <div className="panel-body-flush">
                                <div className="table-wrap">
                                    <table className="data-table">
                                        <thead>
                                            <tr>
                                                <th>工具</th>
                                                <th>状态</th>
                                                <th>版本</th>
                                                <th>路径</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {tools.map((t) => (
                                                <tr key={t.name}>
                                                    <td style={{ fontWeight: 600 }}>{t.name}</td>
                                                    <td>
                                                        <span className={`badge ${t.installed ? "badge-success" : "badge-danger"}`}>
                                                            {t.installed ? "✓ 已安装" : "✕ 缺失"}
                                                        </span>
                                                    </td>
                                                    <td className="cell-mono">{t.version || "—"}</td>
                                                    <td className="cell-mono">{t.path || "—"}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}
                        <div className="panel-body">
                            <div className="setting-note">
                                这些工具必须已安装并在 PATH 中可访问，才能实现完整的扫描功能。
                                必需：<code>subfinder</code>、<code>findomain</code>、<code>bbot</code>、
                                <code>shosubgo</code>、<code>httpx</code>、<code>naabu</code>、<code>nmap</code>、
                                <code>gowitness</code>。可选：<code>nuclei</code>、<code>dnsx</code>、<code>dictgen</code>。
                            </div>
                        </div>
                    </div>
                </>
            )}
        </div>
    );
}
