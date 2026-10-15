export interface DashboardSummary {
  total_logs: number;
  total_alerts: number;
  total_incidents: number;
  high_severity_alerts: number;
  critical_alerts: number;
  model_name: string;
  model_loaded: boolean;
  model_metrics: ModelMetrics | null;
  event_type_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  detection_method_distribution: Record<string, number>;
  recent_alerts: RecentAlert[];
}

export interface ModelMetrics {
  best_model: string;
  accuracy: number;
  f1_suspicious: number;
  recall_suspicious: number;
  precision_suspicious: number;
  false_positive_rate: number;
  trained_at: string;
  all_models: Record<string, { accuracy: number; f1_suspicious: number; recall_suspicious: number }>;
}

export interface RecentAlert {
  alert_id: string;
  timestamp: string;
  event_type: string;
  severity: string;
  source_ip: string;
  affected_asset: string;
  detection_method: string;
}

export interface LogRecord {
  id: number;
  log_id: string;
  timestamp: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  event_type: string;
  severity: string;
  failed_login_count: number;
  request_count: number;
  port: number | null;
  affected_asset: string | null;
  label: string | null;
}

export interface PaginatedLogs {
  total: number;
  page: number;
  page_size: number;
  items: LogRecord[];
}

export interface Alert {
  alert_id: string;
  log_id: string | null;
  timestamp: string | null;
  event_type: string;
  source_ip: string | null;
  affected_asset: string | null;
  severity: string;
  ml_prediction: string | null;
  confidence_score: number | null;
  detection_reason: string;
  evidence: Record<string, unknown>[];
  recommended_action: string;
  detection_method: string;
}

export interface Incident {
  incident_id: string;
  category: string;
  first_seen: string;
  last_seen: string;
  affected_assets: string[];
  severity: string;
  alert_ids: string[];
  evidence_summary: string;
  remediation: string;
  status: string;
  alert_count: number;
}

export interface ComplianceMapping {
  mapping_id: string;
  alert_id: string;
  framework: string;
  framework_version: string;
  control_id: string;
  control_title: string;
  finding_description: string;
  evidence: string;
  risk_level: string;
  remediation: string;
  disclaimer: string;
}

export interface PaginatedCompliance {
  total: number;
  page: number;
  page_size: number;
  items: ComplianceMapping[];
}

export interface Report {
  report_id: string;
  title: string;
  generated_at: string;
  file_path: string;
  summary: Record<string, unknown>;
  status: string;
}

export interface UploadResponse {
  message: string;
  records_imported: number;
  records_skipped: number;
  warnings: string[];
}
