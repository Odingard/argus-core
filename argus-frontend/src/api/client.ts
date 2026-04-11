const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8765";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem("argus_token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const res = await fetch(`${API_URL}${path}`, { ...options, headers: { ...headers, ...options?.headers } });
  if (res.status === 401) {
    localStorage.removeItem("argus_token");
    if (window.location.pathname !== "/login") {
      window.location.href = "/login";
    }
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed: ${res.status}`);
  }
  return res.json();
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};

// Auth — token is passed as Authorization header (not yet in localStorage)
export const login = (token: string) =>
  request<{ status: string }>("/api/auth/login", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });

// Dashboard
export const getDashboardStats = () => api.get<Record<string, unknown>>("/api/dashboard/stats");

// Scans
export const getScans = () => api.get<{ scans: unknown[] }>("/api/scans");
export const getScan = (id: string) => api.get<Record<string, unknown>>(`/api/scans/${id}`);
export const startScan = (body: unknown) => api.post<Record<string, unknown>>("/api/scan/start", body);
export const cancelScan = () => api.post<Record<string, unknown>>("/api/scan/stop");

// Targets
export const getTargets = () => api.get<{ targets: unknown[] }>("/api/targets");
export const createTarget = (body: unknown) => api.post<Record<string, unknown>>("/api/targets", body);
export const deleteTarget = (id: string) => api.delete<Record<string, unknown>>(`/api/targets/${id}`);

// Findings
export const getFindings = (params?: string) => api.get<{ findings: unknown[] }>(`/api/findings${params ? `?${params}` : ""}`);
export const getFinding = (id: string) => api.get<Record<string, unknown>>(`/api/findings/${id}`);
export const updateFindingStatus = (id: string, status: string) =>
  api.put<Record<string, unknown>>(`/api/findings/${id}/status`, { status });

// Health
export const getHealth = () => api.get<{ status: string }>("/api/health");
export const getAgentStatus = () => api.get<{ agents: unknown[] }>("/api/agents/status");
