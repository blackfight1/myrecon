import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import type { ProjectRecord } from "../types/models";
import { parseDomainList } from "../lib/projectScope";

const STORAGE_KEY = "myrecon.workspace.v1";

interface WorkspaceState {
  projects: ProjectRecord[];
  activeProject: ProjectRecord | null;
  setActiveProject: (id: string) => void;
  createProject: (input: {
    name: string;
    description?: string;
    rootDomainsRaw: string;
    tagsRaw?: string;
  }) => ProjectRecord;
  updateProject: (id: string, patch: { name?: string; description?: string; rootDomainsRaw?: string; tagsRaw?: string; active?: boolean }) => void;
  deleteProject: (id: string) => void;
}

const WorkspaceContext = createContext<WorkspaceState | null>(null);

function nowISO(): string {
  return new Date().toISOString();
}

function makeId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

function parseTags(raw?: string): string[] {
  if (!raw) {
    return [];
  }
  return Array.from(
    new Set(
      raw
        .split(/[\n,]+/)
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );
}

function seedProjects(): ProjectRecord[] {
  const ts = nowISO();
  return [
    {
      id: "project_default",
      name: "Default Workspace",
      description: "Create projects here and scope recon by root domains.",
      rootDomains: ["example.com"],
      tags: ["baseline"],
      active: true,
      createdAt: ts,
      updatedAt: ts
    }
  ];
}

function loadProjects(): ProjectRecord[] {
  if (typeof window === "undefined") {
    return seedProjects();
  }

  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return seedProjects();
  }

  try {
    const parsed = JSON.parse(raw) as ProjectRecord[];
    if (!Array.isArray(parsed) || parsed.length === 0) {
      return seedProjects();
    }
    return parsed;
  } catch {
    return seedProjects();
  }
}

function saveProjects(projects: ProjectRecord[]): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(projects));
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [projects, setProjects] = useState<ProjectRecord[]>(() => loadProjects());
  const [activeProjectId, setActiveProjectId] = useState<string>(() => {
    const current = loadProjects().find((item) => item.active);
    return current?.id ?? loadProjects()[0]?.id ?? "";
  });

  const createProject: WorkspaceState["createProject"] = (input) => {
    const timestamp = nowISO();
    const item: ProjectRecord = {
      id: makeId("project"),
      name: input.name.trim(),
      description: input.description?.trim(),
      rootDomains: parseDomainList(input.rootDomainsRaw),
      tags: parseTags(input.tagsRaw),
      active: true,
      createdAt: timestamp,
      updatedAt: timestamp
    };

    setProjects((prev) => {
      const next = prev.map((p) => ({ ...p, active: false })).concat(item);
      saveProjects(next);
      return next;
    });
    setActiveProjectId(item.id);
    return item;
  };

  const updateProject: WorkspaceState["updateProject"] = (id, patch) => {
    setProjects((prev) => {
      let switched = false;
      const next = prev.map((item) => {
        if (item.id !== id) {
          return patch.active ? { ...item, active: false } : item;
        }

        switched = Boolean(patch.active);
        return {
          ...item,
          name: patch.name != null ? patch.name.trim() || item.name : item.name,
          description: patch.description ?? item.description,
          rootDomains: patch.rootDomainsRaw != null ? parseDomainList(patch.rootDomainsRaw) : item.rootDomains,
          tags: patch.tagsRaw != null ? parseTags(patch.tagsRaw) : item.tags,
          active: patch.active ?? item.active,
          updatedAt: nowISO()
        };
      });

      saveProjects(next);
      if (switched) {
        setActiveProjectId(id);
      }
      return next;
    });
  };

  const deleteProject: WorkspaceState["deleteProject"] = (id) => {
    setProjects((prev) => {
      if (prev.length <= 1) {
        return prev;
      }

      const nextRaw = prev.filter((item) => item.id !== id);
      if (nextRaw.length === prev.length) {
        return prev;
      }

      const fallbackActiveId =
        activeProjectId === id ? nextRaw[0]?.id ?? "" : nextRaw.find((item) => item.id === activeProjectId)?.id ?? nextRaw[0]?.id ?? "";
      const next = nextRaw.map((item) => ({ ...item, active: item.id === fallbackActiveId }));

      setActiveProjectId(fallbackActiveId);
      saveProjects(next);
      return next;
    });
  };

  const setActiveProject = (id: string) => {
    setActiveProjectId(id);
    setProjects((prev) => {
      const next = prev.map((item) => ({ ...item, active: item.id === id }));
      saveProjects(next);
      return next;
    });
  };

  const activeProject = useMemo(
    () => projects.find((item) => item.id === activeProjectId) ?? projects[0] ?? null,
    [activeProjectId, projects]
  );

  const value = useMemo<WorkspaceState>(
    () => ({ projects, activeProject, setActiveProject, createProject, updateProject, deleteProject }),
    [projects, activeProject]
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
