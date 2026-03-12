import { apiGet, apiPost } from "./client";
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

export interface DashboardResponse {
  summary: DashboardSummary;
  trend: TrendPoint[];
}

export const endpoints = {
  getDashboard: () => apiGet<DashboardResponse>("/dashboard/summary"),
  getJobs: () => apiGet<JobOverview[]>("/jobs"),
  createJob: (body: NewScanJobRequest) => apiPost<NewScanJobRequest, JobOverview>("/jobs", body),
  getAssets: () => apiGet<Asset[]>("/assets"),
  getPorts: () => apiGet<PortRecord[]>("/ports"),
  getVulns: () => apiGet<VulnerabilityRecord[]>("/vulns"),
  getMonitorTargets: () => apiGet<MonitorTarget[]>("/monitor/targets"),
  getMonitorRuns: () => apiGet<MonitorRun[]>("/monitor/runs"),
  getMonitorChanges: () => apiGet<MonitorChange[]>("/monitor/changes"),

  // Screenshots
  getScreenshotDomains: () => apiGet<ScreenshotDomain[]>("/screenshots/domains"),
  getScreenshots: (rootDomain: string) => apiGet<ScreenshotItem[]>(`/screenshots/${encodeURIComponent(rootDomain)}`),

  // Settings
  getSettings: () => apiGet<SystemSettings>("/settings"),
  updateSettings: (body: Partial<SystemSettings>) => apiPost<Partial<SystemSettings>, SystemSettings>("/settings", body),
  getToolStatus: () => apiGet<ToolStatus[]>("/settings/tools"),
  testNotification: () => apiPost<object, { success: boolean; message: string }>("/settings/test-notify", {})
};
