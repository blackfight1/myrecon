const API_BASE = "/api";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

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

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers: { Accept: "application/json" }
  });

  if (!response.ok) {
    throw new ApiError(await parseApiErrorMessage(response), response.status);
  }

  return (await response.json()) as T;
}

export async function apiPost<TReq extends object, TResp>(path: string, body: TReq): Promise<TResp> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    throw new ApiError(await parseApiErrorMessage(response), response.status);
  }

  return (await response.json()) as TResp;
}

export async function apiPut<TReq extends object, TResp>(path: string, body: TReq): Promise<TResp> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    throw new ApiError(await parseApiErrorMessage(response), response.status);
  }

  return (await response.json()) as TResp;
}

export async function apiDelete<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "DELETE",
    headers: { Accept: "application/json" }
  });

  if (!response.ok) {
    throw new ApiError(await parseApiErrorMessage(response), response.status);
  }

  return (await response.json()) as T;
}
