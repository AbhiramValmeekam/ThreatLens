// ============================================================
// API Client — Fetch wrapper for ThreatLens FastAPI backend
// ============================================================

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  const headers = new Headers(options?.headers);
  
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    if (typeof window !== "undefined") {
      localStorage.removeItem("token");
      const currentPath = window.location.pathname;
      if (currentPath !== "/login" && currentPath !== "/register") {
        window.location.href = "/login";
      }
    }
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `API Error ${res.status}`);
  }
  return res.json();
}

// ─── Types ───────────────────────────────────────────────────

export interface ScanResult {
  risk_score: number;
  attack_type: string;
  attack_category_id: number;
  severity: string;
  confidence: number;
  is_injection: boolean;
  model_scores: Record<string, number>;
  matched_patterns: Array<{
    description?: string;
    category_name?: string;
    severity_weight?: number;
    pattern?: string;
  }>;
  reasons: string[];
  explanation: {
    keywords: Array<{ keyword: string; weight: number; direction: string }>;
    shap_values: Array<{ feature: string; shap_value: number }>;
    highlighted_segments: Array<{ text: string; description: string }>;
    reasons: string[];
    risk_factors: unknown[];
  };
}

export interface BatchResult {
  results: Array<{
    prompt: string;
    risk_score: number;
    attack_type: string;
    severity: string;
    confidence: number;
    is_injection: boolean;
    reasons: string;
  }>;
  total: number;
}

export interface DashboardStats {
  total_scans: number;
  attacks_detected: number;
  high_risk_count: number;
  detection_rate: number;
  avg_risk_score: number;
  trend: {
    direction: string;
    change: number;
    description: string;
  };
}

export interface DailyAttack {
  date: string;
  total_scans: number;
  attacks_detected: number;
  high_risk_count: number;
  avg_risk_score: number;
}

export interface CategoryData {
  attack_type: string;
  count: number;
}

export interface SeverityData {
  severity: string;
  count: number;
}

export interface PatternData {
  description: string;
  count: number;
  category: string;
  pattern: string;
}

export interface OWASPData {
  attack_type: string;
  owasp_id: string;
  owasp_name: string;
  owasp_description: string;
  owasp_severity: string;
  count: number;
}

export interface ScanRecord {
  id: number;
  prompt: string;
  risk_score: number;
  attack_type: string;
  attack_category_id: number;
  severity: string;
  confidence: number;
  explanation: string | null;
  matched_patterns: string | null;
  model_scores: string | null;
  timestamp: string;
}

// ─── API Functions ───────────────────────────────────────────

export async function scanPrompt(prompt: string): Promise<ScanResult> {
  return apiFetch<ScanResult>("/api/scan", {
    method: "POST",
    body: JSON.stringify({ prompt }),
  });
}

export async function batchScan(prompts: string[]): Promise<BatchResult> {
  return apiFetch<BatchResult>("/api/batch-scan", {
    method: "POST",
    body: JSON.stringify({ prompts }),
  });
}

export async function batchScanUpload(file: File): Promise<BatchResult> {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_BASE}/api/batch-scan/upload`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Upload Error ${res.status}`);
  }
  return res.json();
}

export async function getDashboardStats(): Promise<DashboardStats> {
  return apiFetch<DashboardStats>("/api/stats");
}

export async function getDailyAttacks(days: number = 30): Promise<DailyAttack[]> {
  const res = await apiFetch<{ data: DailyAttack[] }>(`/api/analytics/daily?days=${days}`);
  return res.data;
}

export async function getAttackCategories(): Promise<CategoryData[]> {
  const res = await apiFetch<{ data: CategoryData[] }>("/api/analytics/categories");
  return res.data;
}

export async function getRiskDistribution(): Promise<Array<{ risk_score: number }>> {
  const res = await apiFetch<{ data: Array<{ risk_score: number }> }>("/api/analytics/risk-distribution");
  return res.data;
}

export async function getSeverityData(): Promise<SeverityData[]> {
  const res = await apiFetch<{ data: SeverityData[] }>("/api/analytics/severity");
  return res.data;
}

export async function getTopPatterns(limit: number = 10): Promise<PatternData[]> {
  const res = await apiFetch<{ data: PatternData[] }>(`/api/analytics/patterns?limit=${limit}`);
  return res.data;
}

export async function getOWASPMapping(): Promise<OWASPData[]> {
  const res = await apiFetch<{ data: OWASPData[] }>("/api/analytics/owasp");
  return res.data;
}

export async function getScanHistory(params: {
  limit?: number;
  offset?: number;
  search?: string;
  category?: string[];
  severity?: string[];
  sort_by?: string;
  sort_order?: string;
}): Promise<ScanRecord[]> {
  const query = new URLSearchParams();
  if (params.limit) query.set("limit", String(params.limit));
  if (params.offset) query.set("offset", String(params.offset));
  if (params.search) query.set("search", params.search);
  if (params.category?.length) query.set("category", params.category.join(","));
  if (params.severity?.length) query.set("severity", params.severity.join(","));
  if (params.sort_by) query.set("sort_by", params.sort_by);
  if (params.sort_order) query.set("sort_order", params.sort_order);

  const res = await apiFetch<{ data: ScanRecord[] }>(`/api/history?${query}`);
  return res.data;
}

export async function getScanCount(params: {
  search?: string;
  category?: string[];
  severity?: string[];
}): Promise<number> {
  const query = new URLSearchParams();
  if (params.search) query.set("search", params.search);
  if (params.category?.length) query.set("category", params.category.join(","));
  if (params.severity?.length) query.set("severity", params.severity.join(","));

  const res = await apiFetch<{ count: number }>(`/api/history/count?${query}`);
  return res.count;
}

export function getExportURL(params: {
  search?: string;
  category?: string[];
  severity?: string[];
  sort_by?: string;
  sort_order?: string;
}): string {
  const query = new URLSearchParams();
  if (params.search) query.set("search", params.search);
  if (params.category?.length) query.set("category", params.category.join(","));
  if (params.severity?.length) query.set("severity", params.severity.join(","));
  if (params.sort_by) query.set("sort_by", params.sort_by);
  if (params.sort_order) query.set("sort_order", params.sort_order);
  return `${API_BASE}/api/history/export?${query}`;
}

export interface User {
  id: number;
  email: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export async function loginUser(email: string, password: string): Promise<AuthResponse> {
  const res = await apiFetch<AuthResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  if (res.token) {
    localStorage.setItem("token", res.token);
  }
  return res;
}

export async function registerUser(email: string, password: string): Promise<AuthResponse> {
  const res = await apiFetch<AuthResponse>("/api/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  if (res.token) {
    localStorage.setItem("token", res.token);
  }
  return res;
}

export async function getCurrentUser(): Promise<User> {
  return apiFetch<User>("/api/auth/me");
}

export async function loginGoogleUser(idToken: string): Promise<AuthResponse> {
  const res = await apiFetch<AuthResponse>("/api/auth/google", {
    method: "POST",
    body: JSON.stringify({ id_token: idToken }),
  });
  if (res.token) {
    localStorage.setItem("token", res.token);
  }
  return res;
}
