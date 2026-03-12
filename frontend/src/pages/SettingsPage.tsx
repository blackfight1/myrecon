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
            setSecret(settings.notifications.dingtalkSecret);
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
                <h1 className="page-title">⊟ Settings</h1>
                <p className="page-desc">
                    System configuration — database, notifications, scanner defaults, and tool status
                </p>
            </div>

            {settingsQuery.isLoading ? (
                <div className="empty-state">Loading settings…</div>
            ) : !settings ? (
                <div className="empty-state">
                    <div className="empty-icon">⚠</div>
                    Failed to load settings. Check backend connection.
                </div>
            ) : (
                <>
                    {/* ── Database ── */}
                    <div className="panel">
                        <div className="panel-header">
                            <h2>🗄 Database</h2>
                            <span className={`badge ${settings.database.connected ? "badge-success" : "badge-danger"}`}>
                                {settings.database.connected ? "Connected" : "Disconnected"}
                            </span>
                        </div>
                        <div className="panel-body">
                            <div className="settings-grid">
                                <div className="setting-row">
                                    <span className="setting-label">Host</span>
                                    <span className="setting-value">{settings.database.host}:{settings.database.port}</span>
                                </div>
                                <div className="setting-row">
                                    <span className="setting-label">User</span>
                                    <span className="setting-value">{settings.database.user}</span>
                                </div>
                                <div className="setting-row">
                                    <span className="setting-label">Database</span>
                                    <span className="setting-value">{settings.database.dbname}</span>
                                </div>
                                <div className="setting-row">
                                    <span className="setting-label">SSL Mode</span>
                                    <span className="setting-value">{settings.database.sslmode}</span>
                                </div>
                            </div>
                            <div className="setting-note">
                                Database connection is configured via environment or CLI flags. Restart backend to apply changes.
                            </div>
                        </div>
                    </div>

                    {/* ── Notifications ── */}
                    <div className="panel">
                        <div className="panel-header">
                            <h2>🔔 DingTalk Notifications</h2>
                            <div style={{ display: "flex", gap: 6 }}>
                                <span className={`badge ${settings.notifications.enabled ? "badge-success" : "badge-neutral"}`}>
                                    {settings.notifications.enabled ? "Enabled" : "Disabled"}
                                </span>
                                {!editNotify && (
                                    <button className="btn btn-sm" onClick={startEditNotify}>
                                        Edit
                                    </button>
                                )}
                            </div>
                        </div>
                        <div className="panel-body">
                            {editNotify ? (
                                <div className="settings-form">
                                    <div className="form-group">
                                        <label className="form-label">Webhook URL</label>
                                        <input
                                            className="form-input"
                                            type="text"
                                            value={webhook}
                                            onChange={(e) => setWebhook(e.target.value)}
                                            placeholder="https://oapi.dingtalk.com/robot/send?access_token=…"
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label className="form-label">Secret (optional, for signed mode)</label>
                                        <input
                                            className="form-input"
                                            type="password"
                                            value={secret}
                                            onChange={(e) => setSecret(e.target.value)}
                                            placeholder="SEC…"
                                        />
                                    </div>
                                    <div className="form-actions">
                                        <button className="btn btn-primary" onClick={saveNotify} disabled={updateMutation.isPending}>
                                            Save
                                        </button>
                                        <button className="btn btn-sm" onClick={() => setEditNotify(false)}>
                                            Cancel
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
                                            {settings.notifications.dingtalkSecret ? "••••••••" : "Not set"}
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
                                    {testNotifyMutation.isPending ? "Sending…" : "🔔 Test Notification"}
                                </button>
                                {testResult && (
                                    <span className={`badge ${testResult.ok ? "badge-success" : "badge-danger"}`} style={{ marginLeft: 8 }}>
                                        {testResult.msg}
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* ── Scanner Defaults ── */}
                    <div className="panel">
                        <div className="panel-header">
                            <h2>⚙ Scanner Defaults</h2>
                            {!editScanner && (
                                <button className="btn btn-sm" onClick={startEditScanner}>
                                    Edit
                                </button>
                            )}
                        </div>
                        <div className="panel-body">
                            {editScanner ? (
                                <div className="settings-form">
                                    <div className="form-group">
                                        <label className="form-label">Screenshot Directory</label>
                                        <input
                                            className="form-input"
                                            type="text"
                                            value={screenshotDir}
                                            onChange={(e) => setScreenshotDir(e.target.value)}
                                            placeholder="screenshots"
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label className="form-label">DNS Resolvers File</label>
                                        <input
                                            className="form-input"
                                            type="text"
                                            value={dnsResolvers}
                                            onChange={(e) => setDnsResolvers(e.target.value)}
                                            placeholder="Leave empty for system default"
                                        />
                                    </div>
                                    <div className="form-group">
                                        <label className="form-label">Active Bruteforce Dict Size (100–5000)</label>
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
                                            Enable Active Subdomain Bruteforce
                                        </label>
                                        <label className="form-checkbox">
                                            <input
                                                type="checkbox"
                                                checked={nuclei}
                                                onChange={(e) => setNuclei(e.target.checked)}
                                            />
                                            Enable Nuclei Scanning
                                        </label>
                                    </div>
                                    <div className="form-actions">
                                        <button className="btn btn-primary" onClick={saveScanner} disabled={updateMutation.isPending}>
                                            Save
                                        </button>
                                        <button className="btn btn-sm" onClick={() => setEditScanner(false)}>
                                            Cancel
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <div className="settings-grid">
                                    <div className="setting-row">
                                        <span className="setting-label">Screenshot Dir</span>
                                        <span className="setting-value cell-mono">{settings.scanner.screenshotDir}</span>
                                    </div>
                                    <div className="setting-row">
                                        <span className="setting-label">DNS Resolvers</span>
                                        <span className="setting-value">{settings.scanner.dnsResolvers || "System default"}</span>
                                    </div>
                                    <div className="setting-row">
                                        <span className="setting-label">Dict Size</span>
                                        <span className="setting-value">{settings.scanner.defaultDictSize}</span>
                                    </div>
                                    <div className="setting-row">
                                        <span className="setting-label">Active Subs</span>
                                        <span className={`badge ${settings.scanner.defaultActiveSubs ? "badge-success" : "badge-neutral"}`}>
                                            {settings.scanner.defaultActiveSubs ? "Enabled" : "Disabled"}
                                        </span>
                                    </div>
                                    <div className="setting-row">
                                        <span className="setting-label">Nuclei</span>
                                        <span className={`badge ${settings.scanner.defaultNuclei ? "badge-success" : "badge-neutral"}`}>
                                            {settings.scanner.defaultNuclei ? "Enabled" : "Disabled"}
                                        </span>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* ── Tool Status ── */}
                    <div className="panel">
                        <div className="panel-header">
                            <h2>🔧 Recon Tool Status</h2>
                            <button className="btn btn-sm" onClick={() => toolsQuery.refetch()}>
                                Refresh
                            </button>
                        </div>
                        {toolsQuery.isLoading ? (
                            <div className="panel-body">
                                <div className="empty-state">Checking tools…</div>
                            </div>
                        ) : tools.length === 0 ? (
                            <div className="panel-body">
                                <div className="empty-state">
                                    <div className="empty-icon">🔧</div>
                                    No tool data available.
                                </div>
                            </div>
                        ) : (
                            <div className="panel-body-flush">
                                <div className="table-wrap">
                                    <table className="data-table">
                                        <thead>
                                            <tr>
                                                <th>Tool</th>
                                                <th>Status</th>
                                                <th>Version</th>
                                                <th>Path</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {tools.map((t) => (
                                                <tr key={t.name}>
                                                    <td style={{ fontWeight: 600 }}>{t.name}</td>
                                                    <td>
                                                        <span className={`badge ${t.installed ? "badge-success" : "badge-danger"}`}>
                                                            {t.installed ? "✓ Installed" : "✕ Missing"}
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
                                These tools must be installed and accessible in PATH for full scanning capability.
                                Required: <code>subfinder</code>, <code>findomain</code>, <code>bbot</code>,
                                <code>shosubgo</code>, <code>httpx</code>, <code>naabu</code>, <code>nmap</code>,
                                <code>gowitness</code>. Optional: <code>nuclei</code>, <code>dnsx</code>, <code>dictgen</code>.
                            </div>
                        </div>
                    </div>
                </>
            )}
        </div>
    );
}
