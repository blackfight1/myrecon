import { apiDelete, apiGet, apiPost, apiPut } from "./client";
import type {
  Asset,
  DashboardSummary,
  JobOverview,
  MonitorChange,
  MonitorRun,
  MonitorTarget,
  PortRecord,
  ProjectRecord,
  RelationEdge,
  ScreenshotDomain,
  ScreenshotItem,
  SystemSettings,
  TrendPoint,
  VulnEvent,
  VulnerabilityRecord,
  PagedAssets
} from "../types/models";

export interface NewScanJobRequest {
  projectId: string;
  domain: string;
  mode: "scan" | "monitor";
  modules: string[];
  enableNuclei?: boolean;
  activeSubs?: boolean;
  dictSize?: number;
  dnsResolvers?: string;
  dryRun?: boolean;
}

export interface CancelJobRequest {
  jobId: string;
}

export interface CreateMonitorTargetRequest {
  projectId: string;
  domain: string;
  intervalSec?: number;
}

export interface ProjectUpsertRequest {
  id?: string;
  name: string;
  description?: string;
  owner?: string;
  tags?: string[];
  rootDomains: string[];
  archived?: boolean;
}

export interface PatchVulnStatusRequest {
  vulnId: number;
  projectId: string;
  status: "open" | "triaged" | "confirmed" | "accepted_risk" | "fixed" | "false_positive" | "duplicate";
  reason?: string;
  actor?: string;
  assignee?: string;
  ticketRef?: string;
}

export interface DashboardResponse {
  summary: DashboardSummary;
  trend: TrendPoint[];
}

export interface AssetListQuery {
  rootDomain?: string;
  q?: string;
  liveOnly?: boolean;
  page?: number;
  pageSize?: number;
  sortBy?: "created_at" | "updated_at" | "last_seen" | "domain" | "status_code";
  sortDir?: "asc" | "desc";
}

function withQuery(path: string, query: Record<string, string | undefined>): string {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([k, v]) => {
    if (v && v.trim()) params.set(k, v.trim());
  });
  const suffix = params.toString();
  if (!suffix) return path;
  return `${path}?${suffix}`;
}

export const endpoints = {
  getProjects: () => apiGet<ProjectRecord[]>("/projects"),
  createProject: (body: ProjectUpsertRequest) => apiPost<ProjectUpsertRequest, { status: string; id: string }>("/projects", body),
  updateProject: (body: ProjectUpsertRequest) => apiPut<ProjectUpsertRequest, { status: string; id: string }>("/projects", body),
  deleteProject: (id: string) => apiDelete<{ status: string; id: string }>(`/projects?id=${encodeURIComponent(id)}`),

  getDashboard: (projectId: string, rootDomain?: string) =>
    apiGet<DashboardResponse>(withQuery("/dashboard/summary", { project_id: projectId, root_domain: rootDomain })),
  getJobs: (projectId: string, rootDomain?: string) =>
    apiGet<JobOverview[]>(withQuery("/jobs", { project_id: projectId, root_domain: rootDomain })),
  createJob: (body: NewScanJobRequest) => apiPost<NewScanJobRequest, JobOverview>("/jobs", body),
  getAssets: (projectId: string, rootDomain?: string) =>
    apiGet<Asset[]>(withQuery("/assets", { project_id: projectId, root_domain: rootDomain })),
  getAssetsPage: (projectId: string, q: AssetListQuery) =>
    apiGet<PagedAssets>(
      withQuery("/assets", {
        project_id: projectId,
        root_domain: q.rootDomain,
        q: q.q,
        live_only: q.liveOnly ? "1" : undefined,
        page: q.page ? String(q.page) : undefined,
        page_size: q.pageSize ? String(q.pageSize) : undefined,
        sort_by: q.sortBy,
        sort_dir: q.sortDir,
        paged: "1"
      })
    ),
  getPorts: (projectId: string, rootDomain?: string) =>
    apiGet<PortRecord[]>(withQuery("/ports", { project_id: projectId, root_domain: rootDomain })),
  getVulns: (projectId: string, rootDomain?: string) =>
    apiGet<VulnerabilityRecord[]>(withQuery("/vulns", { project_id: projectId, root_domain: rootDomain })),
  patchVulnStatus: (body: PatchVulnStatusRequest) =>
    apiPost<PatchVulnStatusRequest, { status: string; vulnId: number; from: string; to: string }>("/vulns/status", body),
  getVulnEvents: (projectId: string, vulnId?: string) =>
    apiGet<VulnEvent[]>(withQuery("/vulns/events", { project_id: projectId, vuln_id: vulnId })),
  getRelations: (projectId: string, rootDomain?: string) =>
    apiGet<RelationEdge[]>(withQuery("/graph/relations", { project_id: projectId, root_domain: rootDomain })),
  cancelJob: (body: CancelJobRequest) =>
    apiPost<CancelJobRequest, { status: string; jobId: string }>("/jobs/cancel", body),
  getMonitorTargets: (projectId?: string) =>
    apiGet<MonitorTarget[]>(withQuery("/monitor/targets", { project_id: projectId })),
  createMonitorTarget: (body: CreateMonitorTargetRequest) =>
    apiPost<CreateMonitorTargetRequest, { status: string; domain: string; intervalSec: number }>("/monitor/targets", body),
  stopMonitorTarget: (projectId: string, domain: string) =>
    apiDelete<{ status: string; domain: string }>(
      withQuery("/monitor/targets", { project_id: projectId, domain, action: "stop" })
    ),
  deleteMonitorTarget: (projectId: string, domain: string) =>
    apiDelete<{ status: string; domain: string }>(
      withQuery("/monitor/targets", { project_id: projectId, domain, action: "delete" })
    ),
  getMonitorRuns: (projectId?: string, rootDomain?: string) =>
    apiGet<MonitorRun[]>(withQuery("/monitor/runs", { project_id: projectId, root_domain: rootDomain })),
  getMonitorChanges: (projectId?: string, rootDomain?: string) =>
    apiGet<MonitorChange[]>(withQuery("/monitor/changes", { project_id: projectId, root_domain: rootDomain })),

  // Screenshots
  getScreenshotDomains: (projectId?: string) =>
    apiGet<ScreenshotDomain[]>(withQuery("/screenshots/domains", { project_id: projectId })),
  getScreenshots: (rootDomain: string, projectId?: string) =>
    apiGet<ScreenshotItem[]>(
      withQuery(`/screenshots/${encodeURIComponent(rootDomain)}`, { project_id: projectId })
    ),

  // Settings
  getSettings: () => apiGet<SystemSettings>("/settings"),
  updateSettings: (body: Partial<SystemSettings>) => apiPut<Partial<SystemSettings>, SystemSettings>("/settings", body),
  testNotification: () => apiPost<object, { success: boolean; message: string }>("/settings/test-notify", {})
};
