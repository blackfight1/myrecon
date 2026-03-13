import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { endpoints, type NewScanJobRequest, type CancelJobRequest, type CreateMonitorTargetRequest } from "../api/endpoints";

export function useDashboard(rootDomain?: string) {
  return useQuery({
    queryKey: ["dashboard", rootDomain ?? ""],
    queryFn: () => endpoints.getDashboard(rootDomain),
    refetchInterval: 10000
  });
}

export function useJobs(rootDomain?: string) {
  return useQuery({
    queryKey: ["jobs", rootDomain ?? ""],
    queryFn: () => endpoints.getJobs(rootDomain),
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

export function useAssets(rootDomain?: string) {
  return useQuery({
    queryKey: ["assets", rootDomain ?? ""],
    queryFn: () => endpoints.getAssets(rootDomain),
    refetchInterval: 20000
  });
}

export function usePorts(rootDomain?: string) {
  return useQuery({
    queryKey: ["ports", rootDomain ?? ""],
    queryFn: () => endpoints.getPorts(rootDomain),
    refetchInterval: 20000
  });
}

export function useVulns(rootDomain?: string) {
  return useQuery({
    queryKey: ["vulns", rootDomain ?? ""],
    queryFn: () => endpoints.getVulns(rootDomain),
    refetchInterval: 20000
  });
}

export function useMonitorTargets() {
  return useQuery({
    queryKey: ["monitor-targets"],
    queryFn: endpoints.getMonitorTargets,
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
    mutationFn: (domain: string) => endpoints.stopMonitorTarget(domain),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["monitor-targets"] });
      await qc.invalidateQueries({ queryKey: ["jobs"] });
    }
  });
}

export function useDeleteMonitorTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (domain: string) => endpoints.deleteMonitorTarget(domain),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["monitor-targets"] });
      await qc.invalidateQueries({ queryKey: ["monitor-runs"] });
      await qc.invalidateQueries({ queryKey: ["monitor-changes"] });
      await qc.invalidateQueries({ queryKey: ["jobs"] });
    }
  });
}

export function useMonitorRuns(rootDomain?: string) {
  return useQuery({
    queryKey: ["monitor-runs", rootDomain ?? ""],
    queryFn: () => endpoints.getMonitorRuns(rootDomain),
    refetchInterval: 10000
  });
}

export function useMonitorChanges(rootDomain?: string) {
  return useQuery({
    queryKey: ["monitor-changes", rootDomain ?? ""],
    queryFn: () => endpoints.getMonitorChanges(rootDomain),
    refetchInterval: 10000
  });
}

/* ── Screenshots ── */

export function useScreenshotDomains() {
  return useQuery({
    queryKey: ["screenshot-domains"],
    queryFn: endpoints.getScreenshotDomains,
    refetchInterval: 30000
  });
}

export function useScreenshots(rootDomain: string) {
  return useQuery({
    queryKey: ["screenshots", rootDomain],
    queryFn: () => endpoints.getScreenshots(rootDomain),
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

export function useToolStatus() {
  return useQuery({
    queryKey: ["tool-status"],
    queryFn: endpoints.getToolStatus,
    refetchInterval: 60000
  });
}

export function useTestNotification() {
  return useMutation({
    mutationFn: endpoints.testNotification
  });
}
