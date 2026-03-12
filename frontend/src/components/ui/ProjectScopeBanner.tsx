interface ProjectScopeBannerProps {
  title: string;
  hint: string;
}

export function ProjectScopeBanner({ title, hint }: ProjectScopeBannerProps) {
  return (
    <div className="scope-banner">
      <span className="scope-icon">⊙</span>
      <span>
        <strong>{title}</strong> — {hint}
      </span>
    </div>
  );
}
