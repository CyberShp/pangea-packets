export const API_BASE = '/api/v1';

export type ScenarioMode = 'direct' | 'listen';
export type ExecutionStatus = 'pending' | 'running' | 'success' | 'failed' | 'cancelled';
export type MatchMode = 'outer_five_tuple' | 'vxlan_inner_five_tuple' | 'custom';

export interface ScenarioSummary {
  id: string;
  name: string;
  description?: string;
  mode: ScenarioMode;
  packets?: unknown[];
  updatedAt?: string;
}

export interface PacketTemplateSummary {
  id: string;
  name: string;
  builtin: boolean;
  description?: string;
  layers: Array<{ id: string; type: string; role: string; fields: Record<string, unknown> }>;
}

export interface RemoteHostSummary {
  id: string;
  name: string;
  address: string;
  sshPort: number;
  lastCheck?: Record<string, unknown>;
}

export interface NicInfo {
  name: string;
  mac: string;
  ips: string[];
  link: string;
  speed: string;
  driver: string;
  pci: string;
}

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) throw new Error(`API ${path} failed: ${response.status}`);
  return response.json() as Promise<T>;
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return apiWrite<T>('POST', path, body);
}

export async function apiPut<T>(path: string, body: unknown): Promise<T> {
  return apiWrite<T>('PUT', path, body);
}

async function apiWrite<T>(method: 'POST' | 'PUT', path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => null);
    const detail = error?.detail;
    const message = typeof detail === 'string' ? detail
      : Array.isArray(detail) ? detail.map((item: { msg?: string }) => item.msg).join('；')
      : detail?.message;
    throw new Error(message || `请求失败：${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function executionStreamUrl(executionId: string): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}${API_BASE}/executions/${executionId}/stream`;
}
