export function errorMessage(err: unknown): string {
  if (err instanceof Error) {
    const msg = err.message?.trim();
    if (msg) return msg;
  }
  if (typeof err === "string" && err.trim()) return err.trim();
  return "Request failed, please try again.";
}
