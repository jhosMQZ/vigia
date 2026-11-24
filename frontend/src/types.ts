export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'confirmed' | 'likely' | 'suspected' | 'false_positive'

export interface User { id: number; username: string; role: 'admin' | 'analyst' | 'viewer'; is_active: boolean }
export interface Project { id: number; name: string; description: string; created_at: string; role: string | null }
export interface Authorization { valid: boolean; attested_at: string | null; reference: string | null; valid_until: string | null; statement: string | null }
export interface Scope {
  id: number; project_id: number; name: string; targets: string[]; exclusions: string[]; allow_private: boolean
  lab_mode: boolean; allowed_ports: number[] | null; max_rps: number; authorization: Authorization
}
export interface Source { id: number; kind: string; origin: string; files: number; size_bytes: number; sha256: string; created_at: string }
export interface Credential { id: number; name: string; kind: string; created_at: string }
export interface Profile {
  key: string; name: string; description: string; modules: string[]; tools: string[]; intensity: string
  needs_target: boolean; needs_source: boolean; max_duration_min: number; max_requests: number; rps: number
  concurrency: number; crawl_depth: number; crawl_max_pages: number; port_set: string
}
export interface ModuleProgress { status: string; pct?: number; detail?: string; updated?: string }
export interface Scan {
  id: number; project_id: number; scope_id: number | null; source_id: number | null; profile: string; profile_name: string
  status: string; config: Record<string, unknown>; progress: Record<string, ModuleProgress>
  summary: { findings?: number; risk_score?: number; chains?: number; by_severity?: Partial<Record<Severity, number>>; confirmed?: number; requests?: number; stop_reason?: string | null }
  stats: { requests?: number; findings?: number; urls?: number; elapsed_s?: number }
  error: string | null; cancel_requested: boolean; created_at: string; started_at: string | null; finished_at: string | null
}
export interface ScanEvent { id: number; ts: string; level: string; module: string; message: string; data: Record<string, unknown> | null }
export interface Plain { title: string; summary: string; impact: string; action: string }
export interface Finding {
  id: number; scan_id: number; project_id: number; fingerprint: string; title: string; category: string; module: string
  severity: Severity; confidence: Confidence; cvss_score: number | null; cvss_vector: string | null; cwe: string | null
  cve: string[]; owasp: string[]; asset: string; endpoint: string | null; method: string | null; parameter: string | null
  file: string | null; line: number | null; priority: number; validation_status: string; remediation_status: string
  sources: string[]; chain_ids: number[]; plain: Plain
  function?: string | null; snippet?: string | null; description?: string; evidence?: Record<string, unknown>; impact?: string
  likelihood?: string; recommendation?: string; references?: string[]; analyst_notes?: string
}
export interface Chain { id: number; rule: string; title: string; severity: Severity; narrative: string; recommendation: string
  steps: { finding_id: number; title: string; severity: Severity; confidence: Confidence; endpoint: string | null; file: string | null }[] }
export interface ToolRun { id: number; tool: string; version: string | null; status: string; duration: number; max_rss_mb: number | null; findings: number; error: string | null }
export interface Engine { name: string; title: string; category: string; license: string; kind: string; status: string; version: string | null; reason: string | null; notes: string; lab_only: boolean }

export interface Dashboard {
  projects: number; scans: number; running: number; fixed: number; open_by_severity: Record<Severity, number>
  per_project: { project_id: number; name: string; last_scan: number; risk: number | null; open: Partial<Record<Severity, number>> }[]
  recent: { id: number; project_id: number; project: string; profile: string; status: string; created_at: string; findings: number | null; risk: number | null }[]
  trend: { scan_id: number; date: string; risk: number | null }[]
  top_open: { id: number; scan_id: number; project_id: number; project: string; severity: Severity; title: string; where: string; status: string }[]
}

export interface CheckResult { ok: boolean; detail: string; kind?: string }
export interface PrivacyCheck { ts: number; ok: boolean; isolation: boolean | { ok: boolean }; egress: CheckResult | null; dns: CheckResult | null; observed_ip: string | null }
export interface PrivacyStatus {
  egress: { configured: boolean; proxy: string | null; reachable: boolean | null; detail: string; require_proxy: boolean; observed_ip: string | null; transport: string }
  dns: { resolution: string; remote: boolean; resolver?: string; detail: string }
  visibility: { isp: string; egress_provider: string; dns_resolver: string; target: string }
  engines_egress: { engine: string; states: number[]; state_labels: string[]; detail: string; isolation: string; evidence: string }[]
  isolation: { mode: string; preventive: boolean; verified: boolean; worker_confined: boolean; scope: string; detail: string
    last_check: { ok: boolean; ts: number; results?: Record<string, string>; detail: string } | null }
  tunnel: { configured: boolean; destination?: string; known_hosts?: string; known_hosts_exists?: boolean; host_key_registered?: boolean; identity?: boolean; ssh_client?: boolean; ok?: boolean; detail?: string }
  last_check: PrivacyCheck | null
  kill_switch: { enabled: boolean; detail: string }
  leaks: { count: number; recent: { scan_id: number; ts: string | null; message: string }[] }
  last_audit: { ts?: number; target_connections?: number; home_ip_seen_by_target?: number; names_sent_to_egress_provider?: number; local_lookups_of_target_names?: number } | null
  protection: { level: 'none' | 'weak' | 'partial' | 'complete'; label: string; limitations: string[] }
  worker_isolation: { platform: string; process: string; filesystem: string; environment: string; cleanup: string }
  network_scope: { always_blocked: string[]; private_targets: string; every_request_checked: boolean; egress_gateway?: string; connection_trace: string }
  data_protection: { redaction: boolean; redacted: string[]; credentials_at_rest: string; identity_to_model: string }
  browser: { available: boolean; detail: string; enabled: boolean }
  identity_note: string
}
export interface SettingRow { key: string; value: string | boolean | null; source: 'env' | 'ui' | 'default'; editable: boolean }
