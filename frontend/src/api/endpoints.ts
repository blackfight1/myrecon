import { apiDelete, apiGet, apiPost, apiPut } from "./client";
import type {
  Asset,
  AssetDetail,
  DashboardSummary,
  GlobalSearchResult,
  JobLogsPayload,
  JobOverview,
  PagedJobs,
  MonitorChange,
  MonitorEvent,
  MonitorRun,
  MonitorTarget,
  PagedPorts,
  PortRecord,
  ProjectRecord,
  RelationEdge,
  ScreenshotDomain,
  ScreenshotItem,
  SystemSettings,
  TrendPoint,
  VulnEvent,
  VulnerabilityRecord,
  PagedAssets,
  PagedVulns
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
  notify?: boolean;
}

export interface CancelJobRequest {
  jobId: string;
}

export interface DeleteJobRequest {
  projectId: string;
  jobId: string;
}

export interface CreateMonitorTargetRequest {
  projectId: string;
  domain: string;
  intervalSec?: number;
  enableVulnScan?: boolean;
  enableNuclei?: boolean;
  enableCors?: boolean;
  enableSubtakeover?: boolean;
  vulnOnNewLive?: boolean;
  vulnOnWebChanged?: boolean;
  vulnMaxUrls?: number;
  vulnCooldownMin?: number;
}

export interface UpdateMonitorTargetRequest {
  projectId: string;
  domain: string;
  enableVulnScan?: boolean;
  enableNuclei?: boolean;
  enableCors?: boolean;
  enableSubtakeover?: boolean;
  vulnOnNewLive?: boolean;
  vulnOnWebChanged?: boolean;
  vulnMaxUrls?: number;
  vulnCooldownMin?: number;
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

export interface BulkDeleteAssetsRequest {
  projectId: string;
  ids: number[];
}

export interface BulkVulnStatusRequest {
  projectId: string;
  ids: number[];
  status: string;
  reason?: string;
  actor?: string;
}

export interface BulkDeleteVulnsRequest {
  projectId: string;
  ids: number[];
}

export interface BulkDeleteScreenshotsRequest {
  projectId: string;
  rootDomain: string;
  filenames: string[];
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
  pool?: "verified" | "candidate";
  rootDomain?: string;
  q?: string;
  liveOnly?: boolean;
  monitorNew?: "all" | "open" | "recent24h";
  page?: number;
  pageSize?: number;
  sortBy?: "created_at" | "updated_at" | "last_seen" | "domain" | "status_code";
  sortDir?: "asc" | "desc";
}

export interface PortListQuery {
  rootDomain?: string;
  q?: string;
  page?: number;
  pageSize?: number;
  sortBy?: "created_at" | "updated_at" | "last_seen" | "domain" | "ip" | "port" | "service";
  sortDir?: "asc" | "desc";
}

export interface VulnListQuery {
  rootDomain?: string;
  severity?: string;
  status?: string;
  q?: string;
  page?: number;
  pageSize?: number;
  sortBy?: "created_at" | "updated_at" | "last_seen" | "severity" | "status" | "domain" | "template_id";
  sortDir?: "asc" | "desc";
}

export interface JobListQuery {
  rootDomain?: string;
  status?: string;
  q?: string;
  page?: number;
  pageSize?: number;
  sortBy?: "started_at" | "finished_at" | "duration_sec" | "status" | "root_domain";
  sortDir?: "asc" | "desc";
}

export interface JobLogsQuery {
  sinceId?: number;
  beforeId?: number;
  limit?: number;
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
  deleteProject: (id: string, purgeData?: boolean) =>
    apiDelete<{ status: string; id: string; purgeData?: boolean }>(
      withQuery("/projects", {
        id,
        purge_data: purgeData ? "1" : undefined
      })
    ),

  getDashboard: (projectId: string, rootDomain?: string) =>
    apiGet<DashboardResponse>(withQuery("/dashboard/summary", { project_id: projectId, root_domain: rootDomain })),
  getJobs: (projectId: string, rootDomain?: string) =>
    apiGet<JobOverview[]>(withQuery("/jobs", { project_id: projectId, root_domain: rootDomain })),
  getJobsPage: (projectId: string, q: JobListQuery) =>
    apiGet<PagedJobs>(
      withQuery("/jobs", {
        project_id: projectId,
        root_domain: q.rootDomain,
        status: q.status,
        q: q.q,
        page: q.page ? String(q.page) : undefined,
        page_size: q.pageSize ? String(q.pageSize) : undefined,
        sort_by: q.sortBy,
        sort_dir: q.sortDir,
        paged: "1"
      })
    ),
  getJobLogs: (projectId: string, jobId: string, q?: JobLogsQuery) =>
    apiGet<JobLogsPayload>(
      withQuery("/jobs/logs", {
        project_id: projectId,
        job_id: jobId,
        since_id: q?.sinceId != null ? String(q.sinceId) : undefined,
        before_id: q?.beforeId != null ? String(q.beforeId) : undefined,
        limit: q?.limit != null ? String(q.limit) : undefined
      })
    ),
  createJob: (body: NewScanJobRequest) => apiPost<NewScanJobRequest, JobOverview>("/jobs", body),
  getAssets: (projectId: string, rootDomain?: string) =>
    apiGet<Asset[]>(withQuery("/assets", { project_id: projectId, root_domain: rootDomain })),
  getAssetsPage: (projectId: string, q: AssetListQuery) =>
    apiGet<PagedAssets>(
      withQuery("/assets", {
        project_id: projectId,
        pool: q.pool,
        root_domain: q.rootDomain,
        q: q.q,
        live_only: q.liveOnly ? "1" : undefined,
        monitor_new: q.monitorNew && q.monitorNew !== "all" ? q.monitorNew : undefined,
        page: q.page ? String(q.page) : undefined,
        page_size: q.pageSize ? String(q.pageSize) : undefined,
        sort_by: q.sortBy,
        sort_dir: q.sortDir,
        paged: "1"
      })
    ),
  getPorts: (projectId: string, rootDomain?: string) =>
    apiGet<PortRecord[]>(withQuery("/ports", { project_id: projectId, root_domain: rootDomain })),
  getPortsPage: (projectId: string, q: PortListQuery) =>
    apiGet<PagedPorts>(
      withQuery("/ports", {
        project_id: projectId,
        root_domain: q.rootDomain,
        q: q.q,
        page: q.page ? String(q.page) : undefined,
        page_size: q.pageSize ? String(q.pageSize) : undefined,
        sort_by: q.sortBy,
        sort_dir: q.sortDir,
        paged: "1"
      })
    ),
  getVulns: (projectId: string, rootDomain?: string) =>
    apiGet<VulnerabilityRecord[]>(withQuery("/vulns", { project_id: projectId, root_domain: rootDomain })),
  getVulnsPage: (projectId: string, q: VulnListQuery) =>
    apiGet<PagedVulns>(
      withQuery("/vulns", {
        project_id: projectId,
        root_domain: q.rootDomain,
        severity: q.severity,
        status: q.status,
        q: q.q,
        page: q.page ? String(q.page) : undefined,
        page_size: q.pageSize ? String(q.pageSize) : undefined,
        sort_by: q.sortBy,
        sort_dir: q.sortDir,
        paged: "1"
      })
    ),
  patchVulnStatus: (body: PatchVulnStatusRequest) =>
    apiPost<PatchVulnStatusRequest, { status: string; vulnId: number; from: string; to: string }>("/vulns/status", body),
  getVulnEvents: (projectId: string, vulnId?: string) =>
    apiGet<VulnEvent[]>(withQuery("/vulns/events", { project_id: projectId, vuln_id: vulnId })),
  getRelations: (projectId: string, rootDomain?: string) =>
    apiGet<RelationEdge[]>(withQuery("/graph/relations", { project_id: projectId, root_domain: rootDomain })),
  cancelJob: (body: CancelJobRequest) =>
    apiPost<CancelJobRequest, { status: string; jobId: string }>("/jobs/cancel", body),
  deleteJob: (projectId: string, jobId: string) =>
    apiDelete<{ status: string; jobId: string }>(
      withQuery("/jobs/delete", { project_id: projectId, job_id: jobId })
    ),
  getMonitorTargets: (projectId?: string) =>
    apiGet<MonitorTarget[]>(withQuery("/monitor/targets", { project_id: projectId })),
  createMonitorTarget: (body: CreateMonitorTargetRequest) =>
    apiPost<CreateMonitorTargetRequest, { status: string; domain: string; intervalSec: number; jobId?: string }>("/monitor/targets", body),
  updateMonitorTarget: (body: UpdateMonitorTargetRequest) =>
    apiPut<UpdateMonitorTargetRequest, { status: string; domain: string }>("/monitor/targets", body),
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
  getMonitorEvents: (projectId?: string, rootDomain?: string, status?: string, eventType?: string, q?: string) =>
    apiGet<MonitorEvent[]>(
      withQuery("/monitor/events", {
        project_id: projectId,
        root_domain: rootDomain,
        status,
        event_type: eventType,
        q
      })
    ),
  patchMonitorEventStatus: (body: { projectId: string; eventId: number; status: string }) =>
    apiPost<{ projectId: string; eventId: number; status: string }, { status: string; eventId: number; newStatus: string }>("/monitor/events/status", body),
  bulkMonitorEventStatus: (body: { projectId: string; eventIds: number[]; status: string }) =>
    apiPost<{ projectId: string; eventIds: number[]; status: string }, { status: string; updated: number; newStatus: string }>("/monitor/events/bulk-status", body),

  // Screenshots
  getScreenshotDomains: (projectId: string) =>
    apiGet<ScreenshotDomain[]>(withQuery("/screenshots/domains", { project_id: projectId })),
  getScreenshots: (rootDomain: string, projectId: string) =>
    apiGet<ScreenshotItem[]>(
      withQuery(`/screenshots/${encodeURIComponent(rootDomain)}`, { project_id: projectId })
    ),
  bulkDeleteScreenshots: (body: BulkDeleteScreenshotsRequest) =>
    apiPost<BulkDeleteScreenshotsRequest, { status: string; deleted: number; requested: number; skipped?: string[] }>("/screenshots/delete", body),

  // Asset Detail
  getAssetDetail: (projectId: string, params: { id?: number; domain?: string }) =>
    apiGet<AssetDetail>(withQuery("/assets/detail", { project_id: projectId, id: params.id ? String(params.id) : undefined, domain: params.domain })),

  // Global Search
  globalSearch: (projectId: string, q: string, limit?: number) =>
    apiGet<GlobalSearchResult>(withQuery("/search", { project_id: projectId, q, limit: limit ? String(limit) : undefined })),

  // Bulk Operations
  bulkDeleteAssets: (body: BulkDeleteAssetsRequest) =>
    apiPost<BulkDeleteAssetsRequest, { status: string; deleted: number }>("/bulk/assets/delete", body),
  bulkVulnStatus: (body: BulkVulnStatusRequest) =>
    apiPost<BulkVulnStatusRequest, { status: string; updated: number }>("/vulns/bulk-status", body),
  bulkDeleteVulns: (body: BulkDeleteVulnsRequest) =>
    apiPost<BulkDeleteVulnsRequest, { status: string; deleted: number; deletedEvents: number }>("/vulns/bulk-delete", body),

  // Settings
  getSettings: () => apiGet<SystemSettings>("/settings"),
  updateSettings: (body: Partial<SystemSettings>) => apiPut<Partial<SystemSettings>, SystemSettings>("/settings", body),
  testNotification: () => apiPost<object, { success: boolean; message: string }>("/settings/test-notify", {})
};
