import { Link, useLocation } from "react-router-dom";

interface BreadcrumbItem {
  label: string;
  path?: string;
}

const ROUTE_LABELS: Record<string, string> = {
  "": "仪表盘",
  projects: "项目管理",
  "quick-scan": "快速扫描",
  jobs: "扫描任务",
  assets: "资产管理",
  ports: "端口",
  findings: "漏洞",
  screenshots: "截图",
  monitoring: "监控",
  tools: "工具",
  settings: "系统设置",
  logs: "日志"
};

export function Breadcrumb() {
  const location = useLocation();
  const segments = location.pathname.split("/").filter(Boolean);

  if (segments.length === 0) return null;

  const items: BreadcrumbItem[] = [{ label: "仪表盘", path: "/" }];
  let currentPath = "";

  for (let i = 0; i < segments.length; i += 1) {
    const seg = segments[i];
    currentPath += `/${seg}`;
    const label = ROUTE_LABELS[seg] ?? decodeURIComponent(seg);
    const isLast = i === segments.length - 1;
    items.push({
      label,
      path: isLast ? undefined : currentPath
    });
  }

  return (
    <nav className="breadcrumb" aria-label="breadcrumb">
      {items.map((item, idx) => (
        <span key={idx} className="breadcrumb-item">
          {idx > 0 && <span className="breadcrumb-sep">/</span>}
          {item.path ? (
            <Link to={item.path} className="breadcrumb-link">
              {item.label}
            </Link>
          ) : (
            <span className="breadcrumb-current">{item.label}</span>
          )}
        </span>
      ))}
    </nav>
  );
}
