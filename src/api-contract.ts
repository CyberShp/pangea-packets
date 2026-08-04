export const API_BASE = '/api/v1';

export type ScenarioMode = 'direct' | 'listen';
export type ExecutionStatus = 'pending' | 'running' | 'success' | 'failed' | 'cancelled';

export interface PacketLayer {
  id: string;
  type: string;
  role: 'outer' | 'inner' | 'tunnel' | 'payload' | 'meta';
  fields: Record<string, unknown>;
  autoCalculate?: Record<string, boolean>;
}

export interface MutationRule {
  id: string;
  name: string;
  enabled: boolean;
  target: { packetId?: string | null; layerId?: string | null; fieldPath?: string | null };
  type: string;
  strategy: string;
  value?: unknown;
  applyOrder: number;
  scope: string;
  options?: Record<string, unknown>;
}

export interface PacketModel {
  id: string;
  name: string;
  enabled: boolean;
  templateId?: string | null;
  sendCount: number;
  intervalMs: number;
  layers: PacketLayer[];
  mutations: MutationRule[];
}

export interface ScenarioModel {
  id: string;
  name: string;
  description: string;
  version: string;
  mode: ScenarioMode;
  target: { hostId?: string | null; interface?: string | null };
  sendOptions: { loopCount: number; stopOnFailure: boolean };
  listenConfig?: {
    interface?: string | null;
    match: Record<string, unknown>;
    trigger: Record<string, unknown>;
    direction: Record<string, unknown>;
    cachePolicy: Record<string, unknown>;
  } | null;
  packets: PacketModel[];
  createdAt?: string;
  updatedAt?: string;
}

export interface PacketTemplateSummary {
  id: string;
  name: string;
  builtin: boolean;
  description?: string;
  layers: PacketLayer[];
}

export interface RemoteHostSummary {
  id: string;
  name: string;
  address: string;
  sshPort: number;
  auth?: { type: 'password'; username: string; password?: string | null };
  privilege?: { mode: 'su_root'; rootPassword?: string | null };
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

export interface PacketPreview {
  hex: string;
  length: number;
  fieldOffsets: Array<{ fieldPath: string; startOffset: number; endOffset: number; valueHex: string; layerId?: string | null; fieldName?: string | null; truncated?: boolean }>;
  warnings: Array<{ code: string; message: string; path?: string | null }>;
}

export interface ValidationResult {
  valid: boolean;
  errors: Array<{ code: string; message: string; path?: string | null }>;
  warnings: Array<{ code: string; message: string; path?: string | null }>;
}

export interface ExecutionResult {
  id: string;
  scenarioId: string;
  mode: ScenarioMode;
  hostId?: string | null;
  interface?: string | null;
  status: ExecutionStatus;
  startedAt?: string;
  finishedAt?: string | null;
  level0: Record<string, unknown>;
  level1: Record<string, unknown>;
  logs: Array<Record<string, unknown>>;
}

async function parseError(response: Response, path: string): Promise<Error> {
  let detail = '';
  try {
    const body = await response.json();
    detail = typeof body?.detail === 'string' ? body.detail : JSON.stringify(body?.detail ?? body);
  } catch {
    detail = await response.text();
  }
  return new Error(`API ${path} failed: ${response.status}${detail ? ` ${detail}` : ''}`);
}

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) throw await parseError(response, path);
  return response.json() as Promise<T>;
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  if (!response.ok) throw await parseError(response, path);
  return response.json() as Promise<T>;
}

export async function apiPut<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  if (!response.ok) throw await parseError(response, path);
  return response.json() as Promise<T>;
}

export function executionStreamUrl(executionId: string): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}${API_BASE}/executions/${executionId}/stream`;
}
