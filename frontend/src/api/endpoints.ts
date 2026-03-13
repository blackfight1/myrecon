import { apiGet, apiPost, apiDelete } from "./client";
import type {
  Asset,
  DashboardSummary,
  JobOverview,
  MonitorChange,
  MonitorRun,
  MonitorTarget,
  PortRecord,
  ScreenshotDomain,
  ScreenshotItem,
  SystemSettings,
  ToolStatus,
  TrendPoint,
  VulnerabilityRecord
} from "../types/models";

export interface NewScanJobRequest {
  domain: string;
  mode: "scan" | "monitor";
  modules: string[];
  enableNuclei: boolean;
  activeSubs: boolean;
  dictSize: number;
  dnsResolvers?: string;
  dryRun: boolean;
}

export interface CancelJobRequest {
  jobId: string;
}

export interface CreateMonitorTargetRequest {
  domain: string;
  intervalSec?: number;
}

export interface DashboardResponse {
  summary: DashboardSummary;
  trend: TrendPoint[];
}

function withRd(path: string, rootDomain?: string): string {
  if (!rootDomain) return path;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}root_domain=${encodeURIComponent(rootDomain)}`;
}

export const endpoints = {
  getDashboard: (rd?: string) => apiGet<DashboardResponse>(withRd("/dashboard/summary", rd)),
  getJobs: (rd?: string) => apiGet<JobOverview[]>(withRd("/jobs", rd)),
  createJob: (body: NewScanJobRequest) => apiPost<NewScanJobRequest, JobOverview>("/jobs", body),
  getAssets: (rd?: string) => apiGet<Asset[]>(withRd("/assets", rd)),
  getPorts: (rd?: string) => apiGet<PortRecord[]>(withRd("/ports", rd)),
  getVulns: (rd?: string) => apiGet<VulnerabilityRecord[]>(withRd("/vulns", rd)),
  cancelJob: (body: CancelJobRequest) =>
    apiPost<CancelJobRequest, { status: string; jobId: string }>("/jobs/cancel", body),
  getMonitorTargets: () => apiGet<MonitorTarget[]>("/monitor/targets"),
  createMonitorTarget: (body: CreateMonitorTargetRequest) =>
    apiPost<CreateMonitorTargetRequest, { status: string; domain: string; intervalSec: number }>("/monitor/targets", body),
  stopMonitorTarget: (domain: string) =>
    apiDelete<{ status: string; domain: string }>(`/monitor/targets?domain=${encodeURIComponent(domain)}&action=stop`),
  deleteMonitorTarget: (domain: string) =>
    apiDelete<{ status: string; domain: string }>(`/monitor/targets?domain=${encodeURIComponent(domain)}&action=delete`),
  getMonitorRuns: (rd?: string) => apiGet<MonitorRun[]>(withRd("/monitor/runs", rd)),
  getMonitorChanges: (rd?: string) => apiGet<MonitorChange[]>(withRd("/monitor/changes", rd)),

  // Screenshots
  getScreenshotDomains: () => apiGet<ScreenshotDomain[]>("/screenshots/domains"),
  getScreenshots: (rootDomain: string) => apiGet<ScreenshotItem[]>(`/screenshots/${encodeURIComponent(rootDomain)}`),

  // Settings
  getSettings: () => apiGet<SystemSettings>("/settings"),
  updateSettings: (body: Partial<SystemSettings>) => apiPost<Partial<SystemSettings>, SystemSettings>("/settings", body),
  getToolStatus: () => apiGet<ToolStatus[]>("/settings/tools"),
  testNotification: () => apiPost<object, { success: boolean; message: string }>("/settings/test-notify", {})
};
