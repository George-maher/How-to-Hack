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
  ai_reasoning: ReasoningEntry[] | null;
  completed_scanners: string[] | null;
  results_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
  results?: ScanResult[];
  project?: Project;
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ReasoningEntry {
  timestamp: string;
  message: string;
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
  [key: string]: number;
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
