import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { endpoints, type NewScanJobRequest } from "../api/endpoints";

export function useDashboard() {
  return useQuery({
    queryKey: ["dashboard"],
    queryFn: endpoints.getDashboard,
    refetchInterval: 10000
  });
}

export function useJobs() {
  return useQuery({
    queryKey: ["jobs"],
    queryFn: endpoints.getJobs,
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

export function useAssets() {
  return useQuery({
    queryKey: ["assets"],
    queryFn: endpoints.getAssets,
    refetchInterval: 20000
  });
}

export function usePorts() {
  return useQuery({
    queryKey: ["ports"],
    queryFn: endpoints.getPorts,
    refetchInterval: 20000
  });
}

export function useVulns() {
  return useQuery({
    queryKey: ["vulns"],
    queryFn: endpoints.getVulns,
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

export function useMonitorRuns() {
  return useQuery({
    queryKey: ["monitor-runs"],
    queryFn: endpoints.getMonitorRuns,
    refetchInterval: 10000
  });
}

export function useMonitorChanges() {
  return useQuery({
    queryKey: ["monitor-changes"],
    queryFn: endpoints.getMonitorChanges,
    refetchInterval: 10000
  });
}
