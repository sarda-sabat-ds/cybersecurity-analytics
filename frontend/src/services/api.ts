/**
 * API service layer — all calls go through the Vite proxy to http://localhost:8000
 */
import type {
  DashboardSummary, PaginatedLogs, Alert, Incident,
  PaginatedCompliance, ComplianceMapping, Report, UploadResponse,
} from '../types';

const BASE = '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`;
    try {
      const err = await resp.json();
      detail = err.detail ?? detail;
    } catch {}
    throw new Error(detail);
  }
  return resp.json() as Promise<T>;
}

// ---- Dashboard ----
export const getDashboard = () =>
  request<DashboardSummary>(`${BASE}/dashboard/summary`);

// ---- Logs ----
export const getLogs = (params?: {
  page?: number; page_size?: number;
  event_type?: string; severity?: string; source_ip?: string;
}) => {
  const q = new URLSearchParams();
  if (params?.page) q.set('page', String(params.page));
  if (params?.page_size) q.set('page_size', String(params.page_size));
  if (params?.event_type) q.set('event_type', params.event_type);
  if (params?.severity) q.set('severity', params.severity);
  if (params?.source_ip) q.set('source_ip', params.source_ip);
  return request<PaginatedLogs>(`${BASE}/logs?${q}`);
};

export const uploadLogs = async (file: File): Promise<UploadResponse> => {
  const form = new FormData();
  form.append('file', file);
  const resp = await fetch(`${BASE}/logs/upload`, { method: 'POST', body: form });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: `HTTP ${resp.status}` }));
    throw new Error(err.detail ?? `HTTP ${resp.status}`);
  }
  return resp.json();
};

// ---- Detection ----
export const detectLogs = (records: Record<string, unknown>[]) =>
  request(`${BASE}/detect`, {
    method: 'POST',
    body: JSON.stringify({ records }),
  });

// ---- Alerts ----
export const getAlerts = (params?: { page?: number; page_size?: number; severity?: string }) => {
  const q = new URLSearchParams();
  if (params?.page) q.set('page', String(params.page));
  if (params?.page_size) q.set('page_size', String(params.page_size));
  if (params?.severity) q.set('severity', params.severity);
  return request<Alert[]>(`${BASE}/alerts?${q}`);
};

// ---- Incidents ----
export const getIncidents = (params?: { page?: number; page_size?: number }) => {
  const q = new URLSearchParams();
  if (params?.page) q.set('page', String(params.page));
  if (params?.page_size) q.set('page_size', String(params.page_size));
  return request<Incident[]>(`${BASE}/incidents?${q}`);
};

// ---- Compliance ----
export const getCompliance = (params?: {
  page?: number;
  page_size?: number;
  framework?: string;
  risk_level?: string;
}) => {
  const q = new URLSearchParams();
  if (params?.page) q.set('page', String(params.page));
  if (params?.page_size) q.set('page_size', String(params.page_size));
  if (params?.framework) q.set('framework', params.framework);
  if (params?.risk_level) q.set('risk_level', params.risk_level);
  return request<PaginatedCompliance>(`${BASE}/compliance?${q}`);
};

export const getComplianceSummary = () =>
  request<Record<string, number>>(`${BASE}/compliance/summary`);

// ---- Reports ----
export const getReports = () => request<Report[]>(`${BASE}/reports`);

export const generateReport = (title?: string) =>
  request<Report>(`${BASE}/reports/generate`, {
    method: 'POST',
    body: JSON.stringify({ title: title ?? 'Security Assessment Report' }),
  });

export const downloadReport = (reportId: string) => {
  window.open(`${BASE}/reports/${reportId}/download`, '_blank');
};

// ---- Health ----
export const getHealth = () => request<{ status: string; model_loaded: boolean; model_name: string }>('/health');
