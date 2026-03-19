export type HealthStatus = "success" | "failed" | "running" | "pending" | "canceled" | "unknown";

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
  projectId?: string;
  rootDomain: string;
  mode: "scan" | "monitor";
  modules: string[];
  status: HealthStatus;
  startedAt: string;
  finishedAt?: string;
  durationSec?: number;
  errorMessage?: string;
  subdomainCnt?: number;
  portCnt?: number;
  vulnCnt?: number;
}

export interface PagedJobs {
  items: JobOverview[];
  page: number;
  pageSize: number;
  total: number;
}

export interface JobLogLine {
  id: number;
  level: "debug" | "info" | "warn" | "error" | string;
  message: string;
  createdAt: string;
}

export interface JobLogsPayload {
  items: JobLogLine[];
  sinceId: number;
  jobStatus: HealthStatus | string;
  hasMoreBefore?: boolean;
}

export interface Asset {
  id: number;
  projectId?: string;
  rootDomain?: string;
  domain: string;
  url?: string;
  ip?: string;
  pool?: "verified" | "candidate";
  verifyStatus?: "pending" | "verified" | string;
  statusCode?: number;
  title?: string;
  technologies?: string[];
  createdAt?: string;
  updatedAt?: string;
  lastSeen?: string;
}

export interface PagedAssets {
  items: Asset[];
  page: number;
  pageSize: number;
  total: number;
}

export interface PortRecord {
  id: number;
  projectId?: string;
  rootDomain?: string;
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

export interface PagedPorts {
  items: PortRecord[];
  page: number;
  pageSize: number;
  total: number;
}

export interface VulnerabilityRecord {
  id: number;
  projectId?: string;
  rootDomain?: string;
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
  status?: "open" | "triaged" | "confirmed" | "accepted_risk" | "fixed" | "false_positive" | "duplicate";
  assignee?: string;
  ticketRef?: string;
  dueAt?: string;
  fixedAt?: string;
  verifiedAt?: string;
  reopenCount?: number;
  lastTransitionAt?: string;
  lastSeen?: string;
}

export interface PagedVulns {
  items: VulnerabilityRecord[];
  page: number;
  pageSize: number;
  total: number;
}

export interface MonitorTarget {
  id: number;
  projectId?: string;
  rootDomain: string;
  enabled: boolean;
  enableVulnScan?: boolean;
  enableNuclei?: boolean;
  enableCors?: boolean;
  enableSubtakeover?: boolean;
  vulnOnNewLive?: boolean;
  vulnOnWebChanged?: boolean;
  vulnMaxUrls?: number;
  vulnCooldownMin?: number;
  lastVulnScanAt?: string;
  baselineDone: boolean;
  baselineVersion?: number;
  baselineAt?: string;
  lastRunAt?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface MonitorRun {
  id: number;
  projectId?: string;
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
  projectId?: string;
  rootDomain: string;
  changeType: string;
  domain?: string;
  ip?: string;
  port?: number;
  statusCode?: number;
  title?: string;
  createdAt?: string;
}

export interface MonitorEvent {
  id: number;
  projectId?: string;
  rootDomain: string;
  eventKey: string;
  eventType: string;
  status: "open" | "resolved" | "ack" | "ignored";
  domain?: string;
  url?: string;
  ip?: string;
  port?: number;
  protocol?: string;
  service?: string;
  version?: string;
  title?: string;
  statusCode?: number;
  firstSeenAt?: string;
  lastSeenAt?: string;
  lastChangedAt?: string;
  resolvedAt?: string;
  occurrenceCount: number;
  lastRunId?: number;
}

export interface ProjectRecord {
  id: string;
  name: string;
  description?: string;
  owner?: string;
  rootDomains: string[];
  tags: string[];
  archived?: boolean;
  active: boolean;
  createdAt: string;
  updatedAt: string;
  lastScanAt?: string;
}

export interface VulnEvent {
  id: number;
  projectId: string;
  vulnId: number;
  action: string;
  fromStatus?: string;
  toStatus?: string;
  actor?: string;
  reason?: string;
  createdAt: string;
}

export interface RelationEdge {
  srcType: string;
  srcId: string;
  dstType: string;
  dstId: string;
  relation: string;
}

/* Screenshots */
export interface ScreenshotDomain {
  projectId?: string;
  rootDomain: string;
  screenshotCount: number;
  screenshotDir: string;
  databasePath: string;
}

export interface ScreenshotItem {
  id: number;
  projectId?: string;
  url: string;
  filename: string;
  title?: string;
  statusCode?: number;
  rootDomain: string;
  thumbnailUrl: string;
  fullUrl: string;
  createdAt?: string;
}

/* Asset Detail */
export interface AssetDetail {
  asset: Asset;
  ports: PortRecord[];
  vulns: VulnerabilityRecord[];
}

/* Global Search */
export interface GlobalSearchResult {
  assets: Asset[];
  ports: PortRecord[];
  vulns: VulnerabilityRecord[];
}

/* Settings */
export interface SystemSettings {
  database: {
    host: string;
    port: number;
    user: string;
    dbname: string;
    sslmode: string;
    connected: boolean;
  };
  notifications: {
    dingtalkWebhook: string;
    dingtalkSecret: string;
    enabled: boolean;
  };
  scanner: {
    screenshotDir: string;
    dnsResolvers: string;
    defaultDictSize: number;
    defaultActiveSubs: boolean;
    defaultNuclei: boolean;
  };
}
