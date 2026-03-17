import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  endpoints,
  type NewScanJobRequest,
  type CancelJobRequest,
  type DeleteJobRequest,
  type CreateMonitorTargetRequest,
  type AssetListQuery,
  type JobLogsQuery,
  type JobListQuery,
  type PortListQuery,
  type VulnListQuery,
  type PatchVulnStatusRequest,
  type BulkDeleteAssetsRequest,
  type BulkVulnStatusRequest
} from "../api/endpoints";

function requiredProjectId(projectId?: string): string {
  const value = (projectId ?? "").trim();
  if (!value) throw new Error("projectId is required");
  return value;
}

export function useDashboard(projectId?: string, rootDomain?: string) {
  return useQuery({
    queryKey: ["dashboard", projectId ?? "", rootDomain ?? ""],
    queryFn: () => endpoints.getDashboard(requiredProjectId(projectId), rootDomain),
    enabled: !!projectId,
    refetchInterval: 10000
  });
}

export function useJobs(projectId?: string, rootDomain?: string) {
  return useQuery({
    queryKey: ["jobs", projectId ?? "", rootDomain ?? ""],
    queryFn: () => endpoints.getJobs(requiredProjectId(projectId), rootDomain),
    enabled: !!projectId,
    refetchInterval: 5000
  });
}

export function useJobsPage(projectId: string | undefined, q: JobListQuery) {
  return useQuery({
    queryKey: ["jobs-page", projectId ?? "", q.rootDomain ?? "", q.status ?? "", q.q ?? "", String(q.page ?? 1), String(q.pageSize ?? 50), q.sortBy ?? "", q.sortDir ?? ""],
    queryFn: () => endpoints.getJobsPage(requiredProjectId(projectId), q),
    enabled: !!projectId,
    refetchInterval: 5000
  });
}

export function useJobLogs(projectId: string | undefined, jobId: string | undefined, q?: JobLogsQuery) {
  const sinceId = q?.sinceId ?? 0;
  const limit = q?.limit ?? 200;
  return useQuery({
    queryKey: ["job-logs", projectId ?? "", jobId ?? ""],
    queryFn: () => endpoints.getJobLogs(requiredProjectId(projectId), jobId ?? "", { sinceId, limit }),
    enabled: !!projectId && !!jobId,
    refetchInterval: 3000
  });
}

export function useCreateJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: NewScanJobRequest) => endpoints.createJob(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["jobs"] });
      await qc.invalidateQueries({ queryKey: ["jobs-page"] });
      await qc.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useCancelJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CancelJobRequest) => endpoints.cancelJob(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["jobs"] });
      await qc.invalidateQueries({ queryKey: ["jobs-page"] });
      await qc.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useDeleteJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: DeleteJobRequest) => endpoints.deleteJob(body.projectId, body.jobId),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["jobs"] });
      await qc.invalidateQueries({ queryKey: ["jobs-page"] });
      await qc.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useAssets(projectId?: string, rootDomain?: string) {
  return useQuery({
    queryKey: ["assets", projectId ?? "", rootDomain ?? ""],
    queryFn: () => endpoints.getAssets(requiredProjectId(projectId), rootDomain),
    enabled: !!projectId,
    refetchInterval: 20000
  });
}

export function useAssetsPage(projectId: string | undefined, q: AssetListQuery) {
  return useQuery({
    queryKey: ["assets-page", projectId ?? "", q.rootDomain ?? "", q.q ?? "", q.liveOnly ? "1" : "0", q.monitorNew ?? "all", String(q.page ?? 1), String(q.pageSize ?? 50), q.sortBy ?? "", q.sortDir ?? ""],
    queryFn: () => endpoints.getAssetsPage(requiredProjectId(projectId), q),
    enabled: !!projectId,
    refetchInterval: 20000
  });
}

export function usePorts(projectId?: string, rootDomain?: string) {
  return useQuery({
    queryKey: ["ports", projectId ?? "", rootDomain ?? ""],
    queryFn: () => endpoints.getPorts(requiredProjectId(projectId), rootDomain),
    enabled: !!projectId,
    refetchInterval: 20000
  });
}

export function usePortsPage(projectId: string | undefined, q: PortListQuery) {
  return useQuery({
    queryKey: ["ports-page", projectId ?? "", q.rootDomain ?? "", q.q ?? "", String(q.page ?? 1), String(q.pageSize ?? 50), q.sortBy ?? "", q.sortDir ?? ""],
    queryFn: () => endpoints.getPortsPage(requiredProjectId(projectId), q),
    enabled: !!projectId,
    refetchInterval: 20000
  });
}

export function useVulns(projectId?: string, rootDomain?: string) {
  return useQuery({
    queryKey: ["vulns", projectId ?? "", rootDomain ?? ""],
    queryFn: () => endpoints.getVulns(requiredProjectId(projectId), rootDomain),
    enabled: !!projectId,
    refetchInterval: 20000
  });
}

export function useVulnsPage(projectId: string | undefined, q: VulnListQuery) {
  return useQuery({
    queryKey: ["vulns-page", projectId ?? "", q.rootDomain ?? "", q.severity ?? "", q.status ?? "", q.q ?? "", String(q.page ?? 1), String(q.pageSize ?? 50), q.sortBy ?? "", q.sortDir ?? ""],
    queryFn: () => endpoints.getVulnsPage(requiredProjectId(projectId), q),
    enabled: !!projectId,
    refetchInterval: 20000
  });
}

export function useMonitorTargets(projectId?: string) {
  return useQuery({
    queryKey: ["monitor-targets", projectId ?? ""],
    queryFn: () => endpoints.getMonitorTargets(projectId),
    enabled: !!projectId,
    refetchInterval: 10000
  });
}

export function useCreateMonitorTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateMonitorTargetRequest) => endpoints.createMonitorTarget(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["monitor-targets"] });
      await qc.invalidateQueries({ queryKey: ["jobs"] });
      await qc.invalidateQueries({ queryKey: ["jobs-page"] });
    }
  });
}

export function useStopMonitorTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, domain }: { projectId: string; domain: string }) =>
      endpoints.stopMonitorTarget(projectId, domain),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["monitor-targets"] });
      await qc.invalidateQueries({ queryKey: ["jobs"] });
      await qc.invalidateQueries({ queryKey: ["jobs-page"] });
    }
  });
}

export function useDeleteMonitorTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, domain }: { projectId: string; domain: string }) =>
      endpoints.deleteMonitorTarget(projectId, domain),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["monitor-targets"] });
      await qc.invalidateQueries({ queryKey: ["monitor-runs"] });
      await qc.invalidateQueries({ queryKey: ["monitor-changes"] });
      await qc.invalidateQueries({ queryKey: ["monitor-events"] });
      await qc.invalidateQueries({ queryKey: ["jobs"] });
      await qc.invalidateQueries({ queryKey: ["jobs-page"] });
    }
  });
}

export function useMonitorRuns(projectId?: string, rootDomain?: string) {
  return useQuery({
    queryKey: ["monitor-runs", projectId ?? "", rootDomain ?? ""],
    queryFn: () => endpoints.getMonitorRuns(projectId, rootDomain),
    enabled: !!projectId,
    refetchInterval: 10000
  });
}

export function useMonitorChanges(projectId?: string, rootDomain?: string) {
  return useQuery({
    queryKey: ["monitor-changes", projectId ?? "", rootDomain ?? ""],
    queryFn: () => endpoints.getMonitorChanges(projectId, rootDomain),
    enabled: !!projectId,
    refetchInterval: 10000
  });
}

export function useMonitorEvents(projectId?: string, rootDomain?: string, status?: string, eventType?: string, q?: string) {
  return useQuery({
    queryKey: ["monitor-events", projectId ?? "", rootDomain ?? "", status ?? "", eventType ?? "", q ?? ""],
    queryFn: () => endpoints.getMonitorEvents(projectId, rootDomain, status, eventType, q),
    enabled: !!projectId,
    refetchInterval: 10000
  });
}

export function usePatchMonitorEventStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { projectId: string; eventId: number; status: string }) =>
      endpoints.patchMonitorEventStatus(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["monitor-events"] });
    }
  });
}

export function useBulkMonitorEventStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { projectId: string; eventIds: number[]; status: string }) =>
      endpoints.bulkMonitorEventStatus(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["monitor-events"] });
    }
  });
}

/* ── Vuln Status Management ── */

export function usePatchVulnStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: PatchVulnStatusRequest) =>
      endpoints.patchVulnStatus(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["vulns"] });
      await qc.invalidateQueries({ queryKey: ["vuln-events"] });
      await qc.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useVulnEvents(projectId?: string, vulnId?: number) {
  return useQuery({
    queryKey: ["vuln-events", projectId ?? "", vulnId ?? ""],
    queryFn: () => endpoints.getVulnEvents(projectId!, vulnId != null ? String(vulnId) : undefined),
    enabled: !!projectId
  });
}

/* ── Enable Monitor Target ── */

export function useEnableMonitorTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateMonitorTargetRequest) => endpoints.createMonitorTarget(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["monitor-targets"] });
      await qc.invalidateQueries({ queryKey: ["jobs"] });
      await qc.invalidateQueries({ queryKey: ["jobs-page"] });
    }
  });
}

/* ── Screenshots ── */

export function useScreenshotDomains(projectId?: string) {
  return useQuery({
    queryKey: ["screenshot-domains", projectId ?? ""],
    queryFn: () => endpoints.getScreenshotDomains(requiredProjectId(projectId)),
    enabled: !!projectId,
    refetchInterval: 30000
  });
}

export function useScreenshots(rootDomain: string, projectId?: string) {
  return useQuery({
    queryKey: ["screenshots", projectId ?? "", rootDomain],
    queryFn: () => endpoints.getScreenshots(rootDomain, requiredProjectId(projectId)),
    enabled: !!projectId && !!rootDomain,
    refetchInterval: 30000
  });
}

/* ── Asset Detail ── */

export function useAssetDetail(projectId?: string, params?: { id?: number; domain?: string }) {
  return useQuery({
    queryKey: ["asset-detail", projectId ?? "", params?.id ?? "", params?.domain ?? ""],
    queryFn: () => endpoints.getAssetDetail(projectId!, params ?? {}),
    enabled: !!projectId && !!(params?.id || params?.domain)
  });
}

/* ── Global Search ── */

export function useGlobalSearch(projectId?: string, q?: string, limit?: number) {
  const trimmed = (q ?? "").trim();
  return useQuery({
    queryKey: ["global-search", projectId ?? "", trimmed, limit ?? 20],
    queryFn: () => endpoints.globalSearch(projectId!, trimmed, limit),
    enabled: !!projectId && trimmed.length >= 2,
    staleTime: 5000
  });
}

/* ── Bulk Operations ── */

export function useBulkDeleteAssets() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkDeleteAssetsRequest) => endpoints.bulkDeleteAssets(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["assets"] });
      await qc.invalidateQueries({ queryKey: ["assets-page"] });
      await qc.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useBulkVulnStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkVulnStatusRequest) => endpoints.bulkVulnStatus(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["vulns"] });
      await qc.invalidateQueries({ queryKey: ["vulns-page"] });
      await qc.invalidateQueries({ queryKey: ["vuln-events"] });
      await qc.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

/* ── Settings ── */

export function useSettings() {
  return useQuery({
    queryKey: ["settings"],
    queryFn: endpoints.getSettings
  });
}

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: endpoints.updateSettings,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["settings"] });
    }
  });
}

export function useTestNotification() {
  return useMutation({
    mutationFn: endpoints.testNotification
  });
}
