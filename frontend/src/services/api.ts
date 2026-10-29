import type {
  Approval,
  AuthResponse,
  CreateProjectRequest,
  InitiateScanResponse,
  LoginRequest,
  PolicySnapshot,
  Project,
  RegisterRequest,
  Report,
  Scan,
  ScanResult,
  ScannerInfo,
  SeverityBreakdown,
  UpdateProjectRequest,
  User,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL ?? '/api';

/**
 * An API failure with enough structure for the UI to act on it.
 *
 * `code` is the machine-readable value the API returns (`target_not_allowed`,
 * `approval_required`, `unauthenticated`, …). The UI must render `message` and
 * branch on `code` — never invent its own wording for a failure.
 */
export class ApiError extends Error {
  // Declared as fields (not constructor parameter properties) because the build
  // uses `erasableSyntaxOnly`.
  readonly status: number;
  readonly code: string | null;
  readonly details: Record<string, unknown>;

  constructor(
    message: string,
    status: number,
    code: string | null = null,
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }

  get isUnauthenticated(): boolean {
    return this.status === 401;
  }

  get isForbidden(): boolean {
    return this.status === 403;
  }

  get isTargetBlocked(): boolean {
    return this.code?.startsWith('target_') ?? false;
  }

  get requiresApproval(): boolean {
    return this.code === 'approval_required' || this.code === 'approval_expired';
  }
}

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
  if (!raw) return null;
  try {
    return JSON.parse(raw) as User;
  } catch {
    return null;
  }
}

export function setStoredUser(user: User | null): void {
  if (user) {
    localStorage.setItem('auth_user', JSON.stringify(user));
  } else {
    localStorage.removeItem('auth_user');
  }
}

const AUTH_ENDPOINTS = ['/login', '/register'];

/**
 * Redirect on session expiry, but never while the user is *on* the auth pages:
 * a failed login is a bad password, not an expired session.
 */
function handleSessionExpiry(path: string): void {
  const isAuthAttempt = AUTH_ENDPOINTS.some((endpoint) => path.startsWith(endpoint));
  if (isAuthAttempt) return;

  setToken(null);
  setStoredUser(null);

  if (!window.location.pathname.startsWith('/login')) {
    window.location.assign('/login?expired=1');
  }
}

async function parseError(response: Response): Promise<ApiError> {
  let body: Record<string, unknown> = {};

  try {
    body = (await response.json()) as Record<string, unknown>;
  } catch {
    // Non-JSON error page (proxy, gateway): keep the status text.
  }

  const message =
    (typeof body.message === 'string' && body.message) ||
    (typeof body.error === 'string' && body.error) ||
    response.statusText ||
    `HTTP ${response.status}`;

  const code = typeof body.code === 'string' ? body.code : null;

  return new ApiError(message, response.status, code, body);
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };

  const token = getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  let response: Response;

  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: { ...headers, ...(options.headers as Record<string, string>) },
    });
  } catch {
    // Network failure is not an auth failure and must not log the user out.
    throw new ApiError('The server could not be reached. Check your connection.', 0, 'network_error');
  }

  if (response.status === 401) {
    handleSessionExpiry(path);
    throw await parseError(response);
  }

  if (!response.ok) {
    throw await parseError(response);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const json = await response.json();
  return ((json as Record<string, unknown>)?.data ?? json) as T;
}

/**
 * Authenticated file download.
 *
 * A plain `<a href>` cannot carry the bearer token, which is why report
 * downloads used to fail with 401. The bytes are fetched with the same headers
 * as every other call and handed to the browser as a Blob.
 */
async function download(path: string, filenameHint: string): Promise<void> {
  const token = getToken();

  let response: Response;

  try {
    response = await fetch(`${API_BASE}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  } catch {
    throw new ApiError('The server could not be reached. Check your connection.', 0, 'network_error');
  }

  if (response.status === 401) {
    handleSessionExpiry(path);
    throw await parseError(response);
  }

  if (!response.ok) {
    throw await parseError(response);
  }

  const disposition = response.headers.get('content-disposition') ?? '';
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  const filename = match?.[1] ?? filenameHint;

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);

  try {
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    // Release the object URL whether or not the click worked.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

export const authApi = {
  register: (data: RegisterRequest) =>
    request<AuthResponse>('/register', { method: 'POST', body: JSON.stringify(data) }),

  login: (data: LoginRequest) =>
    request<AuthResponse>('/login', { method: 'POST', body: JSON.stringify(data) }),

  logout: () => request<{ message: string }>('/logout', { method: 'POST' }),

  me: () => request<User>('/me'),
};

export const projectsApi = {
  list: () => request<Project[]>('/projects'),

  get: (id: number) => request<Project>(`/projects/${id}`),

  create: (data: CreateProjectRequest) =>
    request<Project>('/projects', { method: 'POST', body: JSON.stringify(data) }),

  update: (id: number, data: UpdateProjectRequest) =>
    request<Project>(`/projects/${id}`, { method: 'PUT', body: JSON.stringify(data) }),

  delete: (id: number) => request<{ message: string }>(`/projects/${id}`, { method: 'DELETE' }),

  /**
   * Start a scan. May return `status: 'awaiting_approval'` when the requested
   * tool set includes an active scanner — the caller must surface that rather
   * than pretending the scan is running.
   */
  scan: (id: number, options: { tools?: string[]; ports?: number[] } = {}) =>
    request<InitiateScanResponse>(`/projects/${id}/scan`, {
      method: 'POST',
      body: JSON.stringify(options),
    }),
};

export const scansApi = {
  list: (projectId: number) => request<Scan[]>(`/projects/${projectId}/scans`),

  get: (id: number) => request<Scan>(`/scans/${id}`),

  cancel: (id: number) =>
    request<{ message: string; status: string; confirmed: boolean }>(`/scans/${id}/cancel`, {
      method: 'POST',
    }),

  results: (scanId: number) => request<ScanResult[]>(`/scans/${scanId}/results`),

  severityBreakdown: (scanId: number) =>
    request<SeverityBreakdown>(`/scans/${scanId}/results/severity`),
};

export const approvalsApi = {
  list: (status?: string) =>
    request<Approval[]>(`/approvals${status ? `?status=${encodeURIComponent(status)}` : ''}`),

  get: (id: number) => request<Approval>(`/approvals/${id}`),

  approve: (id: number, note?: string) =>
    request<{ message: string; approval: Approval; scan_status: string }>(`/approvals/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ note: note ?? null }),
    }),

  reject: (id: number, note?: string) =>
    request<{ message: string; approval: Approval }>(`/approvals/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify({ note: note ?? null }),
    }),
};

export const scannersApi = {
  list: () => request<ScannerInfo[]>('/scanners'),
};

export const policyApi = {
  get: () => request<PolicySnapshot>('/policy'),
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

  /** Authenticated download; throws ApiError with a usable message. */
  download: (id: number, format: string) =>
    download(`/reports/${id}/download?format=${encodeURIComponent(format)}`, `report-${id}.${format}`),

  delete: (id: number) => request<{ message: string }>(`/reports/${id}`, { method: 'DELETE' }),

  formats: () => request<string[]>('/reports/formats'),
};
