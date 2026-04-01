import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { endpoints } from "../api/endpoints";
import type { ProjectRecord } from "../types/models";
import { parseDomainList } from "../lib/projectScope";
import { useAuth } from "./AuthContext";

const ACTIVE_PROJECT_KEY = "myrecon.activeProjectId.v2";

interface WorkspaceState {
  projects: ProjectRecord[];
  activeProject: ProjectRecord | null;
  loading: boolean;
  refresh: () => Promise<void>;
  setActiveProject: (id: string) => void;
  createProject: (input: {
    name: string;
    description?: string;
    owner?: string;
    rootDomainsRaw: string;
    tagsRaw?: string;
    aiEnabled?: boolean;
  }) => Promise<void>;
  updateProject: (id: string, patch: {
    name?: string;
    description?: string;
    owner?: string;
    rootDomainsRaw?: string;
    tagsRaw?: string;
    archived?: boolean;
    aiEnabled?: boolean;
  }) => Promise<void>;
  deleteProject: (id: string, purgeData?: boolean) => Promise<void>;
}

const WorkspaceContext = createContext<WorkspaceState | null>(null);

export const WORKSPACE_ACTIVE_PROJECT_KEY = ACTIVE_PROJECT_KEY;

function loadActiveProjectId(): string {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(ACTIVE_PROJECT_KEY) ?? "";
}

function saveActiveProjectId(id: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(ACTIVE_PROJECT_KEY, id);
}

function parseTags(raw?: string): string[] {
  if (!raw) return [];
  return Array.from(
    new Set(
      raw
        .split(/[\n,]+/)
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );
}

async function ensureDefaultProject(): Promise<void> {
  const projects = await endpoints.getProjects();
  if (projects.length > 0) return;
  await endpoints.createProject({
    name: "Default Workspace",
    description: "Initial project scope",
    rootDomains: ["example.com"],
    tags: ["baseline"]
  });
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const { authenticated, loading: authLoading } = useAuth();
  const [projects, setProjects] = useState<ProjectRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeProjectId, setActiveProjectId] = useState<string>(() => loadActiveProjectId());

  const refresh = async () => {
    if (!authenticated) {
      setProjects([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      await ensureDefaultProject();
      const list = await endpoints.getProjects();
      const normalized = list.map((p) => ({ ...p, active: false }));
      setProjects(normalized);
      if (!normalized.some((p) => p.id === activeProjectId)) {
        const fallback = normalized[0]?.id ?? "";
        setActiveProjectId(fallback);
        saveActiveProjectId(fallback);
      }
    } catch (err) {
      console.error("Failed to load projects:", err);
      setProjects([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (authLoading) return;
    if (!authenticated) {
      setProjects([]);
      setLoading(false);
      return;
    }
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authenticated, authLoading]);

  const setActiveProject = (id: string) => {
    setActiveProjectId(id);
    saveActiveProjectId(id);
  };

  const createProject: WorkspaceState["createProject"] = async (input) => {
    const result = await endpoints.createProject({
      name: input.name.trim(),
      description: input.description?.trim() || "",
      owner: input.owner?.trim() || "",
      rootDomains: parseDomainList(input.rootDomainsRaw),
      tags: parseTags(input.tagsRaw),
      aiEnabled: input.aiEnabled ?? true
    });
    await refresh();
    if (result?.id) {
      setActiveProject(result.id);
    }
  };

  const updateProject: WorkspaceState["updateProject"] = async (id, patch) => {
    const current = projects.find((p) => p.id === id);
    if (!current) return;
    await endpoints.updateProject({
      id,
      name: patch.name?.trim() || current.name,
      description: patch.description?.trim() ?? current.description ?? "",
      owner: patch.owner?.trim() ?? current.owner ?? "",
      rootDomains: patch.rootDomainsRaw ? parseDomainList(patch.rootDomainsRaw) : current.rootDomains,
      tags: patch.tagsRaw ? parseTags(patch.tagsRaw) : current.tags,
      archived: patch.archived,
      aiEnabled: patch.aiEnabled ?? current.aiEnabled
    });
    await refresh();
  };

  const deleteProject: WorkspaceState["deleteProject"] = async (id, purgeData) => {
    await endpoints.deleteProject(id, purgeData);
    await refresh();
  };

  const activeProject = useMemo(
    () => projects.find((item) => item.id === activeProjectId) ?? projects[0] ?? null,
    [activeProjectId, projects]
  );

  const value = useMemo<WorkspaceState>(
    () => ({ projects, activeProject, loading, refresh, setActiveProject, createProject, updateProject, deleteProject }),
    [projects, activeProject, loading]
  );

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceState {
  const ctx = useContext(WorkspaceContext);
  if (!ctx) {
    throw new Error("useWorkspace must be used inside WorkspaceProvider");
  }
  return ctx;
}
