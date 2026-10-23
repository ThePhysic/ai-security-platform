export type Page<T> = { items: T[]; next_cursor: string | null };
export type Project = { id: string; name: string; created_at: string };
export type Scanner = { id: string; scanner_id: string; status: string; synthetic: boolean;
  adapter_version: string; error_code: string | null;
  coverage: Record<string, unknown>; provenance: Record<string, unknown> };
export type Scan = { id: string; project_id: string; snapshot_id: string; profile_id: string;
  profile_digest: string; status: string; created_at: string; started_at: string | null;
  completed_at: string | null; scanner_runs: Scanner[] };
export type Finding = { id: string; scan_run_id: string; scanner_run_id: string; rule_id: string;
  severity: string; original_severity: string; category: string; description: string;
  filepath: string; start_line: number; end_line: number; synthetic: boolean;
  tracking_fingerprint: string; evidence: Record<string, string | number> };
export type Disposition = 'confirmed' | 'false_positive' | 'investigate' | 'accepted_risk' | 'remediation_planned';
export const DISPOSITIONS: Disposition[] = ['confirmed', 'false_positive', 'investigate', 'accepted_risk', 'remediation_planned'];
export type Feedback = 'agree' | 'disagree' | 'uncertain';
export type Review = { finding_id?: string; revision: number; disposition: Disposition | null; note?: string;
  reviewer?: string; triage_run_id?: string | null; feedback?: Feedback | null; created_at?: string };
export type RevisionPage = { items: Review[]; next_before_revision: number | null };
export type Citation = { evidence_id: string; kind: string; snapshot_id: string; manifest_digest: string;
  filepath: string; start_line: number; end_line: number; content_digest: string };
export type Assessment = { assessment: 'needs_review' | 'likely_false_positive' | 'abstain';
  confidence: number; summary: string; remediation: string; reason: string; citations: Citation[] };
export type Triage = { id: string; finding_id: string; scan_run_id: string; snapshot_id: string;
  manifest_digest: string; provider: string; status: string; error_code: string | null;
  assessment: Assessment | null; prompt_version: string; tools_version: string; policy_version: string;
  config_digest: string; human_decision: false };
export type Detail = { finding: Finding; scanner_id: string; coverage: Record<string, unknown>;
  provenance: Record<string, unknown>; snapshot_id: string; manifest_digest: string;
  scan_status: string; latest_triage: { id: string; status: string } | null; review: Review };
export type Filters = { severity: string; scanner: string; rule_id: string; review: string };
export const EMPTY_FILTERS: Filters = { severity: '', scanner: '', rule_id: '', review: '' };

export function label(value: string): string { return value.replaceAll('_', ' '); }
export function date(value: string | null): string {
  if (!value) return 'Not recorded';
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toLocaleString() : 'Unavailable';
}
export function coverage(scanner: Scanner): string {
  if (scanner.status === 'queued' || scanner.status === 'running') return 'Awaiting coverage';
  if (scanner.status !== 'succeeded' || scanner.coverage.complete_execution !== true ||
      scanner.coverage.unavailable || Number(scanner.coverage.warning_count || 0) > 0 ||
      (Array.isArray(scanner.coverage.warnings) && scanner.coverage.warnings.length > 0)) return 'Incomplete coverage';
  return 'Complete execution · limited detection coverage';
}
