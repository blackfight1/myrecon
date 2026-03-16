function extractHost(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  try {
    const url = new URL(withScheme);
    return url.hostname || "";
  } catch {
    const withoutPath = trimmed.split(/[/?#]/, 1)[0];
    const withoutAuth = withoutPath.includes("@") ? withoutPath.split("@").pop() ?? "" : withoutPath;
    return withoutAuth.split(":", 1)[0] ?? "";
  }
}

export function normalizeRootDomain(input: string): string {
  return extractHost(input)
    .trim()
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/\.$/, "");
}

export function parseDomainList(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[\n,\s，；;、]+/)
        .map((item) => normalizeRootDomain(item))
        .filter(Boolean)
    )
  );
}

export function matchesProjectDomain(candidate: string | undefined, rootDomains: string[]): boolean {
  if (!candidate || rootDomains.length === 0) {
    return false;
  }

  const value = normalizeRootDomain(candidate);
  if (!value) {
    return false;
  }

  return rootDomains.some((root) => value === root || value.endsWith(`.${root}`));
}
