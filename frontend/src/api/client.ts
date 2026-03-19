const API_BASE = "/api";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

// ── Token management ──

const TOKEN_KEY = "myrecon_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  if (token) {
    return { Authorization: `Bearer ${token}` };
  }
  return {};
}

// ── Error parsing ──

async function parseApiErrorMessage(response: Response): Promise<string> {
  const raw = await response.text();
  if (!raw) return `Request failed (${response.status})`;

  try {
    const parsed = JSON.parse(raw) as { error?: string; message?: string };
    const msg = (parsed.error ?? parsed.message ?? "").trim();
    if (msg) return msg;
  } catch {
    // Fall back to plain text.
  }

  return raw;
}

function handleUnauthorized(status: number): void {
  if (status === 401) {
    clearToken();
    // Redirect to login if not already there
    if (!window.location.pathname.includes("/login")) {
      window.location.href = "/login";
    }
  }
}

// ── API methods ──

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers: { Accept: "application/json", ...authHeaders() },
  });

  if (!response.ok) {
    handleUnauthorized(response.status);
    throw new ApiError(await parseApiErrorMessage(response), response.status);
  }

  return (await response.json()) as T;
}

export async function apiPost<TReq extends object, TResp>(
  path: string,
  body: TReq
): Promise<TResp> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...authHeaders(),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    handleUnauthorized(response.status);
    throw new ApiError(await parseApiErrorMessage(response), response.status);
  }

  return (await response.json()) as TResp;
}

export async function apiPut<TReq extends object, TResp>(
  path: string,
  body: TReq
): Promise<TResp> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...authHeaders(),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    handleUnauthorized(response.status);
    throw new ApiError(await parseApiErrorMessage(response), response.status);
  }

  return (await response.json()) as TResp;
}

export async function apiDelete<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "DELETE",
    headers: { Accept: "application/json", ...authHeaders() },
  });

  if (!response.ok) {
    handleUnauthorized(response.status);
    throw new ApiError(await parseApiErrorMessage(response), response.status);
  }

  return (await response.json()) as T;
}
