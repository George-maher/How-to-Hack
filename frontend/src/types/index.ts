export interface User {
  id: number;
  name: string;
  email: string;
}

export interface AuthResponse {
  user: User;
  token: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  name: string;
  email: string;
  password: string;
}

export interface Project {
  id: number;
  user_id: number;
  name: string;
  target_url: string;
  description: string | null;
  status: string;
  scans_count: number;
  latest_scan: Scan | null;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: number;
  project_id: number;
  status: ScanStatus;
  status_label?: string;
  is_terminal?: boolean;
  outcome_reason: ScanOutcomeReason | null;
  outcome_label?: string | null;
  failure_detail: string | null;
  degraded: boolean;
  ai_reasoning: ReasoningEntry[] | null;
  completed_scanners: string[] | null;
  results_count: number;
  target_host: string | null;
  target_ports: number[] | null;
  plan: { tools: string[]; active_tools?: string[]; requires_approval?: boolean } | null;
  started_at: string | null;
  heartbeat_at?: string | null;
  cancel_requested_at?: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
  scanner_runs?: ScannerRun[];
  approval?: Approval | null;
  results?: ScanResult[];
  project?: Project;
}

/** Mirrors App\Enums\ScanStatus. */
export type ScanStatus =
  | 'queued'
  | 'awaiting_approval'
  | 'running'
  | 'cancel_requested'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'timed_out';

export const IN_FLIGHT_STATUSES: ScanStatus[] = [
  'queued',
  'awaiting_approval',
  'running',
  'cancel_requested',
];

/** Mirrors App\Enums\ScanOutcomeReason: why a scan ended the way it did. */
export type ScanOutcomeReason =
  | 'completed'
  | 'no_findings'
  | 'partial'
  | 'approval_expired'
  | 'approval_rejected'
  | 'target_not_allowed'
  | 'scanner_unavailable'
  | 'runner_unavailable'
  | 'scanner_timeout'
  | 'scan_timeout'
  | 'scanner_failed'
  | 'output_invalid'
  | 'worker_lost'
  | 'cancelled'
  | 'internal_error';

/** Per-scanner outcome. Never conflate `unavailable` with "no findings". */
export type ScannerRunOutcome =
  | 'completed'
  | 'invalid_output'
  | 'failed'
  | 'timed_out'
  | 'unavailable'
  | 'blocked'
  | 'cancelled'
  | 'skipped';

export interface ScannerRun {
  scanner: string;
  intrusiveness: 'passive' | 'active';
  outcome: ScannerRunOutcome;
  inconclusive: boolean;
  findings_count: number;
  exit_code: number | null;
  duration_ms: number | null;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface Approval {
  id: number;
  scan_id: number;
  project_id: number;
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'consumed';
  target_host: string;
  target_ports: number[];
  tools: string[];
  options: Record<string, unknown> | null;
  fingerprint: string;
  scope_rule: string | null;
  requested_at: string;
  expires_at: string | null;
  expired: boolean;
  decided_at: string | null;
  decision_note: string | null;
}

export interface InitiateScanResponse {
  message: string;
  scan_id: number;
  status: ScanStatus;
  requires_approval: boolean;
  approval_id?: number;
  approval?: Pick<Approval, 'id' | 'status' | 'target_host' | 'target_ports' | 'tools' | 'expires_at'>;
}

export interface PolicySnapshot {
  allowlist: Array<{ id: string; host: string; ports: number[] | null; note: string | null }>;
  lab_exceptions: Array<{ id: string; host: string; ports: number[] | null; expires_at: string | null }>;
  runner_configured: boolean;
  approval_ttl_minutes: number;
  max_scan_duration_seconds: number;
}

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  queued: 'Queued',
  awaiting_approval: 'Awaiting approval',
  running: 'Running',
  cancel_requested: 'Cancelling',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
  timed_out: 'Timed out',
};

export interface ReasoningEntry {
  timestamp: string;
  /** The current shape written by the planner. */
  message?: string;
  /** Legacy field names accepted by the API. */
  reason?: string;
  scanner?: string;
}

export interface ScanResult {
  id: number;
  scan_id: number;
  scanner_name: string;
  severity: SeverityLevel;
  title: string;
  description: string;
  details: Record<string, unknown> | null;
  created_at: string;
}

export type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type ScannerCategory =
  | 'reconnaissance'
  | 'network'
  | 'web_application'
  | 'infrastructure'
  | 'information_disclosure'
  | 'vulnerability_assessment'
  | 'api_assessment'
  | 'specialized_assessment';

export interface ScannerInfo {
  name: string;
  description: string;
  category: ScannerCategory;
  severity: string;
  dependencies: string[];
  intrusiveness?: 'passive' | 'active';
  requires_approval?: boolean;
  runner_tool?: string | null;
}

export interface CreateProjectRequest {
  name: string;
  target_url: string;
  description?: string;
}

export interface UpdateProjectRequest {
  name?: string;
  target_url?: string;
  description?: string;
  status?: string;
}

export interface ApiResponse<T> {
  data: T;
  message?: string;
}

export interface SeverityBreakdown {
  severities?: Record<string, number>;
  scanners?: ScannerRun[];
  inconclusive_scanners?: string[];
  /** False when at least one scanner was inconclusive: an empty result set then proves nothing. */
  authoritative?: boolean;
  [key: string]: unknown;
}

export interface Report {
  id: number;
  scan_id: number;
  title: string;
  executive_summary: string | null;
  technical_summary: string | null;
  recommendations: string | null;
  scan_data: Record<string, unknown> | null;
  ai_analysis: Record<string, unknown> | null;
  format: string;
  status: string;
  created_at: string;
  updated_at: string;
  scan?: Scan;
}

export const SCANNER_CATEGORY_LABELS: Record<ScannerCategory, string> = {
  reconnaissance: 'Reconnaissance',
  network: 'Network',
  web_application: 'Web Application',
  infrastructure: 'Infrastructure',
  information_disclosure: 'Information Disclosure',
  vulnerability_assessment: 'Vulnerability Assessment',
  api_assessment: 'API Assessment',
  specialized_assessment: 'Specialized Assessment',
};

export const SCANNER_CATEGORY_ORDER: ScannerCategory[] = [
  'network',
  'reconnaissance',
  'information_disclosure',
  'web_application',
  'infrastructure',
  'api_assessment',
  'vulnerability_assessment',
  'specialized_assessment',
];
