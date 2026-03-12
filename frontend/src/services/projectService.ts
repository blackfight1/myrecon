import type { ProjectRecord } from "../types/models";

export interface CreateProjectInput {
  name: string;
  description?: string;
  rootDomains: string[];
  tags?: string[];
}

// Placeholder service: keep local first, replace with backend APIs later.
export const projectService = {
  async list(): Promise<ProjectRecord[]> {
    return [];
  },
  async create(_input: CreateProjectInput): Promise<ProjectRecord | null> {
    void _input;
    return null;
  },
  async update(_id: string, _patch: Partial<ProjectRecord>): Promise<ProjectRecord | null> {
    void _id;
    void _patch;
    return null;
  }
};
