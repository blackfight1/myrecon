export function normalizeRootDomain(input: string): string {
  return input.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
}

export function parseDomainList(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[\n,\s]+/)
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
