const API_BASE = "/api";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "GET",
    headers: { Accept: "application/json" }
  });

  if (!response.ok) {
    const raw = await response.text();
    throw new ApiError(raw || `Request failed (${response.status})`, response.status);
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
    const raw = await response.text();
    throw new ApiError(raw || `Request failed (${response.status})`, response.status);
  }

  return (await response.json()) as TResp;
}

export async function apiDelete<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "DELETE",
    headers: { Accept: "application/json" }
  });

  if (!response.ok) {
    const raw = await response.text();
    throw new ApiError(raw || `Request failed (${response.status})`, response.status);
  }

  return (await response.json()) as T;
}
