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

// Auth
export const login = (token: string) =>
  request<{ status: string; role: string; key_name: string }>("/api/auth/login", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });

// Dashboard
export const getDashboardStats = () =>
  api.get<{
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    active_targets: number;
    compound_chains: number;
    total_scans: number;
    completed_scans: number;
    severity_distribution: { name: string; value: number; color: string }[];
    trend: { date: string; findings: number }[];
  }>("/api/dashboard/stats");

// Agents
export const getAgentStatus = () =>
  api.get<{
    agents: {
      code: string;
      name: string;
      type: string;
      techniques: number;
      status: string;
      findings: number;
      last_run: string | null;
    }[];
  }>("/api/agents/status");

// Alerts
export const getAlerts = (limit = 20) =>
  api.get<{
    alerts: {
      id: string;
      type: string;
      title: string;
      time: string;
      severity: string;
      source: string;
    }[];
  }>(`/api/alerts?limit=${limit}`);

// Scans
export const getScans = (params?: string) =>
  api.get<{ scans: Record<string, unknown>[]; total: number }>(`/api/scans${params ? `?${params}` : ""}`);
export const getScan = (id: string) =>
  api.get<{ scan: Record<string, unknown>; agents: Record<string, unknown>[] }>(`/api/scans/${id}`);
export const startScan = (body: unknown) =>
  api.post<Record<string, unknown>>("/api/scan/start", body);
export const cancelScan = () =>
  api.post<Record<string, unknown>>("/api/scan/stop");
export const getPendingScans = () =>
  api.get<{ scans: Record<string, unknown>[]; total: number }>("/api/scans/pending");
export const getScheduledScans = () =>
  api.get<{ schedules: Record<string, unknown>[]; total: number }>("/api/scans/scheduled");
export const createScheduledScan = (body: unknown) =>
  api.post<{ schedule: Record<string, unknown> }>("/api/scans/scheduled", body);
export const updateScheduledScan = (id: string, body: unknown) =>
  api.put<{ schedule: Record<string, unknown> }>(`/api/scans/scheduled/${id}`, body);
export const deleteScheduledScan = (id: string) =>
  api.delete<{ status: string }>(`/api/scans/scheduled/${id}`);

// Targets
export const getTargets = () =>
  api.get<{ targets: Record<string, unknown>[]; total: number }>("/api/targets");
export const createTarget = (body: unknown) =>
  api.post<{ target: Record<string, unknown> }>("/api/targets", body);
export const deleteTarget = (id: string) =>
  api.delete<{ status: string }>(`/api/targets/${id}`);

// Findings
export const getFindings = (params?: string) =>
  api.get<{ findings: Record<string, unknown>[]; total: number }>(`/api/findings${params ? `?${params}` : ""}`);
export const getFindingsGroupedByScan = (params?: string) =>
  api.get<{
    scan_groups: {
      scan: { scan_id: string; target_name: string; status: string; created_at: string; completed_at: string | null; total_findings: number; agents_deployed: number };
      findings: Record<string, unknown>[];
    }[];
    total: number;
    total_scans: number;
  }>(`/api/findings?group_by_scan=true${params ? `&${params}` : ""}`);
export const getScanFindings = (scanId: string, params?: string) =>
  api.get<{ scan_id: string; findings: Record<string, unknown>[]; total: number }>(`/api/scans/${scanId}/findings${params ? `?${params}` : ""}`);
export const getFinding = (id: string) =>
  api.get<{ finding: Record<string, unknown> }>(`/api/findings/${id}`);
export const updateFindingStatus = (id: string, status: string) =>
  api.put<Record<string, unknown>>(`/api/findings/${id}/status`, { status });

// Compound paths
export const getCompoundPaths = (limit = 50) =>
  api.get<{ compound_paths: Record<string, unknown>[]; total: number }>(`/api/compound-paths?limit=${limit}`);
export const getScanCompoundPaths = (scanId: string) =>
  api.get<{ compound_paths: Record<string, unknown>[]; total: number }>(`/api/scans/${scanId}/compound-paths`);

// Monitoring
export const getMonitoringMetrics = () =>
  api.get<{
    platform_status: string;
    total_scans: number;
    total_findings: number;
    agents_health: {
      code: string;
      name: string;
      status: string;
      last_run: string | null;
      avg_duration: string;
    }[];
    system: Record<string, unknown>;
  }>("/api/monitoring/metrics");

// OWASP
export const getOWASPCoverage = () =>
  api.get<{
    categories: {
      id: string;
      name: string;
      coverage: number;
      findings: number;
      critical: number;
      high: number;
      agents: string[];
      status: string;
    }[];
  }>("/api/owasp/coverage");

// Gauntlet
export const getGauntletScenarios = () =>
  api.get<{
    scenarios: {
      id: string;
      name: string;
      agent: string;
      category: string;
      status: string;
      score: number;
      maxScore: number;
      description: string;
    }[];
  }>("/api/gauntlet/scenarios");

// Corpus
export const getCorpusPatterns = (search?: string) =>
  api.get<{
    patterns: {
      id: string;
      name: string;
      category: string;
      agent: string;
      effectiveness: number;
      timesUsed: number;
      lastUsed: string | null;
      description: string;
    }[];
    total: number;
  }>(`/api/corpus/patterns${search ? `?search=${encodeURIComponent(search)}` : ""}`);

// Live scan status (in-memory state from server.py, NOT DB historical data)
export const getLiveScanStatus = () =>
  api.get<{
    scan_id: string | null;
    target_name: string;
    status: string;
    elapsed_seconds: number;
    total_findings: number;
    validated_findings: number;
    agents_running: number;
    agents_completed: number;
    agents_total: number;
    agents: Record<string, {
      type: string;
      status: string;
      findings_count: number;
      validated_count: number;
      current_action: string;
      techniques_attempted: number;
    }>;
  }>("/api/status");

// Health
export const getHealth = () => api.get<{ status: string }>("/api/health");

// System
export const getDbStatus = () =>
  api.get<{ status: string; tables: Record<string, number> }>("/api/system/db-status");

// API Keys
export const getApiKeys = () =>
  api.get<{ api_keys: Record<string, unknown>[]; total: number }>("/api/auth/keys");
export const createApiKey = (body: { name: string; role: string }) =>
  api.post<{ api_key: Record<string, unknown> }>("/api/auth/keys", body);
export const revokeApiKey = (id: string) =>
  api.delete<{ status: string }>(`/api/auth/keys/${id}`);

// Settings
export const getSettings = () =>
  api.get<{ settings: Record<string, unknown> }>("/api/settings");
export const saveSettings = (section: string, body: unknown) =>
  api.put<{ status: string }>(`/api/settings/${section}`, body);
