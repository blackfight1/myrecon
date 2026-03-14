import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { endpoints, type NewScanJobRequest, type CancelJobRequest, type CreateMonitorTargetRequest, type AssetListQuery, type PatchVulnStatusRequest } from "../api/endpoints";

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

export function useCreateJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: NewScanJobRequest) => endpoints.createJob(body),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["jobs"] });
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
    queryKey: ["assets-page", projectId ?? "", q.rootDomain ?? "", q.q ?? "", q.liveOnly ? "1" : "0", String(q.page ?? 1), String(q.pageSize ?? 50), q.sortBy ?? "", q.sortDir ?? ""],
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

export function useVulns(projectId?: string, rootDomain?: string) {
  return useQuery({
    queryKey: ["vulns", projectId ?? "", rootDomain ?? ""],
    queryFn: () => endpoints.getVulns(requiredProjectId(projectId), rootDomain),
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
      await qc.invalidateQueries({ queryKey: ["jobs"] });
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
    }
  });
}

/* ── Screenshots ── */

export function useScreenshotDomains(projectId?: string) {
  return useQuery({
    queryKey: ["screenshot-domains", projectId ?? ""],
    queryFn: () => endpoints.getScreenshotDomains(projectId),
    refetchInterval: 30000
  });
}

export function useScreenshots(rootDomain: string, projectId?: string) {
  return useQuery({
    queryKey: ["screenshots", projectId ?? "", rootDomain],
    queryFn: () => endpoints.getScreenshots(rootDomain, projectId),
    enabled: !!rootDomain,
    refetchInterval: 30000
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
