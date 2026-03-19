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
  const showDropdown = open && query.trim().length >= 2;

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      setOpen(false);
      setQuery("");
    }
  }, []);

  const goToAsset = (id: number) => {
    setOpen(false);
    setQuery("");
    navigate(`/assets/${id}`);
  };

  const goToPage = (page: string) => {
    setOpen(false);
    setQuery("");
    navigate(page);
  };

  return (
    <div ref={ref} className="global-search">
      <span className="global-search-icon" aria-hidden="true">
        🔍
      </span>
      <input
        className="global-search-input"
        type="text"
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
        }}
        onFocus={() => {
          if (query.trim().length >= 2) {
            setOpen(true);
          }
        }}
        onKeyDown={handleKeyDown}
        placeholder="搜索域名、IP、CVE、端口..."
      />
      {query && (
        <button
          type="button"
          className="global-search-clear"
          onClick={() => {
            setQuery("");
            setOpen(false);
          }}
          aria-label="清空搜索"
        >
          ×
        </button>
      )}

      {showDropdown && (
        <div className="global-search-dropdown">
          {isLoading && <div className="global-search-empty">搜索中...</div>}
          {!isLoading && totalResults === 0 && <div className="global-search-empty">无匹配结果</div>}

          {!isLoading && data?.assets && data.assets.length > 0 && (
            <div className="global-search-group">
              <div className="global-search-group-title">资产 ({data.assets.length})</div>
              {data.assets.map((a) => (
                <button key={a.id} type="button" className="global-search-item" onClick={() => goToAsset(a.id)}>
                  <span className="global-search-item-type">资产</span>
                  <span className="global-search-item-main">
                    <span className="global-search-item-text">{a.domain}</span>
                    <span className="global-search-item-sub">{[a.ip || "", a.title || ""].filter(Boolean).join(" · ")}</span>
                  </span>
                </button>
              ))}
            </div>
          )}

          {!isLoading && data?.ports && data.ports.length > 0 && (
            <div className="global-search-group">
              <div className="global-search-group-title">端口 ({data.ports.length})</div>
              {data.ports.map((p) => (
                <button key={p.id} type="button" className="global-search-item" onClick={() => goToPage("/ports")}>
                  <span className="global-search-item-type">端口</span>
                  <span className="global-search-item-main">
                    <span className="global-search-item-text">{p.ip}:{p.port}</span>
                    <span className="global-search-item-sub">{[p.service || "", p.domain || ""].filter(Boolean).join(" · ")}</span>
                  </span>
                </button>
              ))}
            </div>
          )}

          {!isLoading && data?.vulns && data.vulns.length > 0 && (
            <div className="global-search-group">
              <div className="global-search-group-title">漏洞 ({data.vulns.length})</div>
              {data.vulns.map((v) => (
                <button key={v.id} type="button" className="global-search-item" onClick={() => goToPage("/findings")}>
                  <span className="global-search-item-type">漏洞</span>
                  <span className="global-search-item-main">
                    <span className="global-search-item-text">{v.templateId} [{v.severity}]</span>
                    <span className="global-search-item-sub">{[v.domain || v.host || "", v.cve || ""].filter(Boolean).join(" · ")}</span>
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
