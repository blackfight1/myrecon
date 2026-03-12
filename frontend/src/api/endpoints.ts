import { apiGet, apiPost } from "./client";
import type {
  Asset,
  DashboardSummary,
  JobOverview,
  MonitorChange,
  MonitorRun,
  MonitorTarget,
  PortRecord,
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
  getMonitorChanges: () => apiGet<MonitorChange[]>("/monitor/changes")
};
