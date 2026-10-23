import type { Detail, Disposition, Feedback, Filters, Finding, Page, Project, Review, RevisionPage, Scan, Triage } from './contracts';

const ORIGIN = 'http://127.0.0.1:18081';
export class ApiError extends Error {
  constructor(public readonly status = 0) { super('Local API request unavailable'); }
}
export function id(value: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new ApiError(422);
  return value.toLowerCase();
}
const KNOWN_SECRET = /AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|SYNTHETIC_SECRET_[A-Za-z0-9_-]+/g;

export class Api {
  #token: string;
  #active = true;
  #pending = new Set<AbortController>();
  constructor(token: string, private readonly unauthorized: () => void) {
    if (!/^[A-Za-z0-9_-]{43,256}$/.test(token)) throw new ApiError(401);
    this.#token = token;
  }
  close(): void {
    this.#active = false; this.#token = '';
    for (const controller of this.#pending) controller.abort();
    this.#pending.clear();
  }
  private async request<T>(path: string, method = 'GET', body?: object, key?: string): Promise<T> {
    if (!this.#active) throw new ApiError(401);
    const controller = new AbortController(); this.#pending.add(controller);
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const headers: Record<string, string> = { Authorization: `Bearer ${this.#token}` };
      if (body) headers['Content-Type'] = 'application/json';
      if (key) headers['Idempotency-Key'] = key;
      const response = await fetch(ORIGIN + path, { method, headers, body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal, mode: 'cors', credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer' });
      if (!response.ok) {
        if (response.status === 401) { this.close(); this.unauthorized(); }
        throw new ApiError(response.status);
      }
      if (!response.body) throw new ApiError();
      const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let bytes = 0;
      while (true) {
        const chunk = await reader.read(); if (chunk.done) break;
        bytes += chunk.value.length;
        if (bytes > 4194304) { await reader.cancel(); throw new ApiError(); }
        chunks.push(chunk.value);
      }
      if (!this.#active) throw new ApiError(401);
      const combined = new Uint8Array(bytes); let offset = 0;
      for (const chunk of chunks) { combined.set(chunk, offset); offset += chunk.length; }
      const sanitize = (value: unknown, depth = 0): unknown => {
        if (depth > 20) throw new ApiError();
        if (typeof value === 'string') return value.split(this.#token).join('[redacted]').replace(KNOWN_SECRET, '[redacted]').slice(0, 8192);
        if (Array.isArray(value)) { if (value.length > 1000) throw new ApiError(); return value.map(v => sanitize(v, depth + 1)); }
        if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 256).map(([k,v]) => [String(sanitize(k, depth + 1)), sanitize(v, depth + 1)]));
        return value;
      };
      return sanitize(JSON.parse(new TextDecoder().decode(combined))) as T;
    } catch (error) { throw error instanceof ApiError ? error : new ApiError(); }
    finally { clearTimeout(timer); this.#pending.delete(controller); }
  }
  authenticate(): Promise<unknown> { return this.request('/api/v1/triage-config'); }
  project(value: string): Promise<Project> { return this.request(`/api/v1/projects/${id(value)}`); }
  scans(project: string, cursor?: string): Promise<Page<Scan>> {
    return this.request('/api/v1/scan-runs?' + new URLSearchParams({ project: id(project), limit: '3', ...(cursor ? { cursor } : {}) }));
  }
  scan(value: string): Promise<Scan> { return this.request(`/api/v1/scan-runs/${id(value)}`); }
  findings(scan: string, filters: Filters, cursor?: string): Promise<Page<Finding>> {
    const query = new URLSearchParams({ limit: '10' });
    for (const [key, value] of Object.entries(filters)) if (value) query.set(key, value);
    if (cursor) query.set('cursor', cursor);
    return this.request(`/api/v1/scan-runs/${id(scan)}/findings?${query}`);
  }
  finding(value: string): Promise<Detail> { return this.request(`/api/v1/findings/${id(value)}`); }
  triage(value: string): Promise<Triage> { return this.request(`/api/v1/triage-runs/${id(value)}`); }
  investigate(finding: string, key: string): Promise<{ id: string; status: string }> {
    return this.request(`/api/v1/findings/${id(finding)}/triage`, 'POST', { provider: 'deterministic-v1' }, key);
  }
  review(value: string): Promise<Review> { return this.request(`/api/v1/findings/${id(value)}/review`); }
  revisions(value: string, before?: number): Promise<RevisionPage> {
    return this.request(`/api/v1/findings/${id(value)}/review-revisions?` + new URLSearchParams({ limit: '5', ...(before ? { before_revision: String(before) } : {}) }));
  }
  saveReview(value: string, expected_revision: number, disposition: Disposition, note: string,
      triage?: string, feedback?: Feedback): Promise<Review> {
    return this.request(`/api/v1/findings/${id(value)}/review`, 'PUT', { expected_revision, disposition, note,
      ...(triage && feedback ? { triage_run_id: id(triage), feedback } : {}) });
  }
}

export function message(error: unknown): string {
  const status = error instanceof ApiError ? error.status : 0;
  if (status === 401) return 'Authentication failed. Reconnect with a valid local token.';
  if (status === 403) return 'Access denied. Use the approved local dashboard origin.';
  if (status === 404) return 'This record is unavailable. Check the identifier or refresh.';
  if (status === 409) return 'The record changed or is unavailable. Refresh before trying again.';
  if (status === 422) return 'Check the identifier, filter or review form and try again.';
  return 'Local API unavailable. Check the service and retry. No successful save is assumed.';
}
