import { useState, useRef, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useWorkspace } from "../../context/WorkspaceContext";
import { useGlobalSearch } from "../../hooks/queries";

export function GlobalSearch() {
    const [query, setQuery] = useState("");
    const [open, setOpen] = useState(false);
    const ref = useRef<HTMLDivElement>(null);
    const navigate = useNavigate();
    const { activeProject } = useWorkspace();
    const projectId = activeProject?.id;

    const { data, isLoading } = useGlobalSearch(projectId, query, 10);

    const totalResults = (data?.assets?.length ?? 0) + (data?.ports?.length ?? 0) + (data?.vulns?.length ?? 0);

    useEffect(() => {
        const handler = (e: MouseEvent) => {
            if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
        };
        document.addEventListener("mousedown", handler);
        return () => document.removeEventListener("mousedown", handler);
    }, []);

    const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
        if (e.key === "Escape") { setOpen(false); setQuery(""); }
    }, []);

    const goToAsset = (id: number) => { setOpen(false); setQuery(""); navigate(`/assets/${id}`); };
    const goToPage = (page: string) => { setOpen(false); setQuery(""); navigate(page); };

    return (
        <div ref={ref} style={{ position: "relative", width: "100%", maxWidth: 420 }}>
            <div style={{
                display: "flex", alignItems: "center", background: "var(--bg-secondary, #1e1e2e)",
                border: "1px solid var(--border, #2e2e3e)", borderRadius: 8, padding: "6px 12px", gap: 8
            }}>
                <span style={{ color: "#888", fontSize: 14 }}>🔍</span>
                <input
                    type="text"
                    value={query}
                    onChange={(e) => { setQuery(e.target.value); setOpen(true); }}
                    onFocus={() => { if (query.trim().length >= 2) setOpen(true); }}
                    onKeyDown={handleKeyDown}
                    placeholder="搜索域名、IP、CVE、端口..."
                    style={{
                        flex: 1, background: "transparent", border: "none", outline: "none",
                        color: "var(--text-primary, #e0e0e0)", fontSize: 13
                    }}
                />
                {query && (
                    <button onClick={() => { setQuery(""); setOpen(false); }}
                        style={{ background: "none", border: "none", color: "#888", cursor: "pointer", fontSize: 14 }}>✕</button>
                )}
            </div>

            {open && query.trim().length >= 2 && (
                <div style={{
                    position: "absolute", top: "calc(100% + 4px)", left: 0, right: 0,
                    background: "var(--bg-secondary, #1e1e2e)", border: "1px solid var(--border, #2e2e3e)",
                    borderRadius: 8, maxHeight: 400, overflowY: "auto", zIndex: 1000,
                    boxShadow: "0 8px 32px rgba(0,0,0,0.4)"
                }}>
                    {isLoading && <div style={{ padding: 16, textAlign: "center", color: "#888" }}>搜索中...</div>}
                    {!isLoading && totalResults === 0 && (
                        <div style={{ padding: 16, textAlign: "center", color: "#888" }}>无匹配结果</div>
                    )}

                    {data?.assets && data.assets.length > 0 && (
                        <div>
                            <div style={{ padding: "8px 12px", fontSize: 11, color: "#888", fontWeight: 600, textTransform: "uppercase", borderBottom: "1px solid var(--border, #2e2e3e)" }}>
                                资产 ({data.assets.length})
                            </div>
                            {data.assets.map((a) => (
                                <div key={a.id} onClick={() => goToAsset(a.id)}
                                    style={{ padding: "8px 12px", cursor: "pointer", borderBottom: "1px solid var(--border, #1a1a2a)" }}
                                    onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover, #252535)")}
                                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                                    <div style={{ fontWeight: 500, fontSize: 13 }}>{a.domain}</div>
                                    <div style={{ fontSize: 11, color: "#888" }}>{a.ip || ""} {a.title ? `· ${a.title}` : ""}</div>
                                </div>
                            ))}
                        </div>
                    )}

                    {data?.ports && data.ports.length > 0 && (
                        <div>
                            <div style={{ padding: "8px 12px", fontSize: 11, color: "#888", fontWeight: 600, textTransform: "uppercase", borderBottom: "1px solid var(--border, #2e2e3e)" }}>
                                端口 ({data.ports.length})
                            </div>
                            {data.ports.map((p) => (
                                <div key={p.id} onClick={() => goToPage("/ports")}
                                    style={{ padding: "8px 12px", cursor: "pointer", borderBottom: "1px solid var(--border, #1a1a2a)" }}
                                    onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover, #252535)")}
                                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                                    <div style={{ fontWeight: 500, fontSize: 13 }}>{p.ip}:{p.port}</div>
                                    <div style={{ fontSize: 11, color: "#888" }}>{p.service || ""} {p.domain || ""}</div>
                                </div>
                            ))}
                        </div>
                    )}

                    {data?.vulns && data.vulns.length > 0 && (
                        <div>
                            <div style={{ padding: "8px 12px", fontSize: 11, color: "#888", fontWeight: 600, textTransform: "uppercase", borderBottom: "1px solid var(--border, #2e2e3e)" }}>
                                漏洞 ({data.vulns.length})
                            </div>
                            {data.vulns.map((v) => (
                                <div key={v.id} onClick={() => goToPage("/findings")}
                                    style={{ padding: "8px 12px", cursor: "pointer", borderBottom: "1px solid var(--border, #1a1a2a)" }}
                                    onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover, #252535)")}
                                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                                    <div style={{ fontWeight: 500, fontSize: 13 }}>{v.templateId} <span style={{ fontSize: 11, color: v.severity === "critical" || v.severity === "high" ? "#ef4444" : "#f59e0b" }}>[{v.severity}]</span></div>
                                    <div style={{ fontSize: 11, color: "#888" }}>{v.domain || v.host || ""} {v.cve || ""}</div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
