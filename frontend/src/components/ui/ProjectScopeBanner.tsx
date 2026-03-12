import { useWorkspace } from "../../context/WorkspaceContext";

interface Props {
  title: string;
  hint?: string;
}

export function ProjectScopeBanner({ title, hint }: Props) {
  const { activeProject } = useWorkspace();
  const roots = activeProject?.rootDomains ?? [];

  return (
    <article className="scope-banner">
      <div>
        <span className="scope-label">Project Scope</span>
        <h3>{title}</h3>
      </div>
      <div className="scope-values">
        <strong>{activeProject?.name ?? "No active project"}</strong>
        <span>{roots.length > 0 ? roots.join(" | ") : "Add root domains in Projects page"}</span>
      </div>
      {hint ? <p>{hint}</p> : null}
    </article>
  );
}
