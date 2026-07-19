import type {
  Project,
  Report,
  Scan,
  ScanResult,
  ScannerInfo,
  CreateProjectRequest,
  UpdateProjectRequest,
  SeverityBreakdown,
  AuthResponse,
  User,
  LoginRequest,
  RegisterRequest,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL ?? '/api';

function getToken(): string | null {
  return localStorage.getItem('auth_token');
}

export function setToken(token: string | null): void {
  if (token) {
    localStorage.setItem('auth_token', token);
  } else {
    localStorage.removeItem('auth_token');
  }
}

export function getStoredUser(): User | null {
  const raw = localStorage.getItem('auth_user');
  return raw ? JSON.parse(raw) : null;
}

export function setStoredUser(user: User | null): void {
  if (user) {
    localStorage.setItem('auth_user', JSON.stringify(user));
  } else {
    localStorage.removeItem('auth_user');
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };

  const token = getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config: RequestInit = {
    headers: { ...headers, ...(options.headers as Record<string, string>) },
    ...options,
  };

  const response = await fetch(url, config);

  if (response.status === 401) {
    setToken(null);
    setStoredUser(null);
    window.location.href = '/login';
    throw new Error('Session expired');
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: response.statusText }));
    throw new Error(error.message ?? `HTTP ${response.status}`);
  }

  const json = await response.json();
  return (json as Record<string, unknown>)?.data ?? json;
}

export const authApi = {
  register: (data: RegisterRequest) =>
    request<AuthResponse>('/register', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  login: (data: LoginRequest) =>
    request<AuthResponse>('/login', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  logout: () =>
    request<{ message: string }>('/logout', {
      method: 'POST',
    }),

  me: () => request<User>('/me'),
};

export const projectsApi = {
  list: () => request<Project[]>('/projects'),

  get: (id: number) => request<Project>(`/projects/${id}`),

  create: (data: CreateProjectRequest) =>
    request<Project>('/projects', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: number, data: UpdateProjectRequest) =>
    request<Project>(`/projects/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  delete: (id: number) =>
    request<{ message: string }>(`/projects/${id}`, {
      method: 'DELETE',
    }),

  scan: (id: number) =>
    request<{ message: string; scan_id: number }>(`/projects/${id}/scan`, {
      method: 'POST',
    }),
};

export const scansApi = {
  list: (projectId: number) => request<Scan[]>(`/projects/${projectId}/scans`),

  get: (id: number) => request<Scan>(`/scans/${id}`),

  cancel: (id: number) =>
    request<{ message: string }>(`/scans/${id}/cancel`, {
      method: 'POST',
    }),

  results: (scanId: number) => request<ScanResult[]>(`/scans/${scanId}/results`),

  severityBreakdown: (scanId: number) =>
    request<SeverityBreakdown>(`/scans/${scanId}/results/severity`),
};

export const scannersApi = {
  list: () => request<ScannerInfo[]>('/scanners'),
};

export const reportsApi = {
  all: () => request<Report[]>('/reports'),

  list: (scanId: number) => request<Report[]>(`/scans/${scanId}/reports`),

  get: (id: number) => request<Report>(`/reports/${id}`),

  generate: (scanId: number, format = 'html') =>
    request<{ message: string; report: Report }>(`/scans/${scanId}/reports`, {
      method: 'POST',
      body: JSON.stringify({ format }),
    }),

  regenerate: (id: number, format = 'html') =>
    request<{ message: string; report: Report }>(`/reports/${id}/regenerate`, {
      method: 'POST',
      body: JSON.stringify({ format }),
    }),

  downloadUrl: (id: number, format: string) =>
    `${API_BASE}/reports/${id}/download?format=${format}`,

  delete: (id: number) =>
    request<{ message: string }>(`/reports/${id}`, {
      method: 'DELETE',
    }),

  formats: () => request<string[]>('/reports/formats'),
};
