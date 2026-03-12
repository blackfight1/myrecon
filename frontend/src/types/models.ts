export type HealthStatus = "ok" | "error" | "running" | "pending" | "unknown";

export interface DashboardSummary {
  jobsRunning: number;
  jobsSuccess24h: number;
  jobsFailed24h: number;
  newSubdomains24h: number;
  newPorts24h: number;
  newVulns24h: number;
  scanDurationAvgSec24h: number;
}

export interface TrendPoint {
  date: string;
  subdomains: number;
  ports: number;
  vulnerabilities: number;
}

export interface JobOverview {
  id: string;
  rootDomain: string;
  mode: "scan" | "monitor";
  modules: string[];
  status: HealthStatus;
  startedAt: string;
  finishedAt?: string;
  durationSec?: number;
  errorMessage?: string;
}

export interface PluginStatus {
  scanner: string;
  status: HealthStatus;
  successCount: number;
  failureCount: number;
  timeoutCount: number;
  durationMs: number;
  error?: string;
}

export interface Asset {
  id: number;
  domain: string;
  url?: string;
  ip?: string;
  statusCode?: number;
  title?: string;
  technologies?: string[];
  createdAt?: string;
  updatedAt?: string;
  lastSeen?: string;
}

export interface PortRecord {
  id: number;
  assetId?: number;
  domain?: string;
  ip: string;
  port: number;
  protocol?: string;
  service?: string;
  version?: string;
  banner?: string;
  lastSeen?: string;
  updatedAt?: string;
}

export interface VulnerabilityRecord {
  id: number;
  domain?: string;
  host?: string;
  url?: string;
  ip?: string;
  templateId: string;
  templateName?: string;
  severity?: string;
  cve?: string;
  matcherName?: string;
  description?: string;
  reference?: string;
  matchedAt: string;
  fingerprint: string;
  lastSeen?: string;
}

export interface MonitorTarget {
  id: number;
  rootDomain: string;
  enabled: boolean;
  baselineDone: boolean;
  lastRunAt?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface MonitorRun {
  id: number;
  rootDomain: string;
  status: string;
  startedAt: string;
  finishedAt?: string;
  durationSec: number;
  errorMessage?: string;
  newLiveCount: number;
  webChanged: number;
  portOpened: number;
  portClosed: number;
  serviceChange: number;
}

export interface MonitorChange {
  runId: number;
  rootDomain: string;
  changeType: string;
  domain?: string;
  ip?: string;
  port?: number;
  statusCode?: number;
  title?: string;
  createdAt?: string;
}
