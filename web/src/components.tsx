import { useEffect, useState, type ReactNode } from 'react';
import { Api, message } from './api';
import { coverage, date, label, type Scanner } from './contracts';

export function Badge({ value }: { value: string }) {
  const color = ['failed', 'CRITICAL', 'HIGH'].includes(value) ? 'danger'
    : ['partial', 'unavailable', 'MEDIUM', 'investigate'].includes(value) ? 'warning'
    : ['succeeded', 'confirmed', 'LOW'].includes(value) ? 'success' : 'neutral';
  return <span className={`badge ${color}`}>{label(value)}</span>;
}
export function Notice({ children, error = false }: { children: ReactNode; error?: boolean }) {
  return <div className={`notice ${error ? 'error' : ''}`} role={error ? 'alert' : 'status'}>{children}</div>;
}
export function Loading({ text = 'Loading records…' }: { text?: string }) {
  return <div className="loading" role="status"><span className="loading-dot" />{text}</div>;
}
export function Field({ title, children }: { title: string; children: ReactNode }) {
  return <div className="metadata-row"><dt>{title}</dt><dd>{children}</dd></div>;
}
export function DateText({ value }: { value: string | null }) {
  return <time dateTime={value ?? undefined}>{date(value)}</time>;
}
export function Pager({ previous, next, page, name }: {
  previous?: () => void; next?: () => void; page: number; name: string;
}) {
  return <nav className="pager" aria-label={name}>
    <button type="button" onClick={previous} disabled={!previous} aria-label={`Previous ${name}`}>← Previous</button>
    <span>Page {page}</span>
    <button type="button" onClick={next} disabled={!next} aria-label={`Next ${name}`}>Next →</button>
  </nav>;
}
export function ScannerCard({ scanner }: { scanner: Scanner }) {
  return <article className="scanner-card">
    <div className="row between"><h3>{scanner.scanner_id}</h3><Badge value={scanner.status} /></div>
    <p className="coverage">{coverage(scanner)}</p>
    {scanner.synthetic && <p className="diagnostic">Synthetic diagnostic · no vulnerability detection</p>}
    <dl className="metadata">
      <Field title="Adapter">{scanner.adapter_version}</Field>
      <Field title="Error">{scanner.error_code ?? 'None recorded'}</Field>
      <Field title="Files checked">{String(scanner.coverage.files_scanned ?? 'Not reported')}</Field>
      <Field title="Snapshot files">{String(scanner.coverage.source_files ?? 'Not reported')}</Field>
      <Field title="Files not checked">{String(scanner.coverage.files_not_scanned ?? 'Not reported')}</Field>
    </dl>
    <details><summary>Coverage details</summary><dl className="metadata">
      {Object.entries(scanner.coverage).map(([key, value]) => <Field key={key} title={label(key)}>
        {Array.isArray(value) ? value.join(', ') || 'None' : String(value)}
      </Field>)}
    </dl></details>
    <details><summary>Scanner provenance</summary><dl className="metadata">
      {Object.entries(scanner.provenance).map(([key, value]) => <Field key={key} title={label(key)}>{String(value)}</Field>)}
      {!Object.keys(scanner.provenance).length && <p>No scanner provenance recorded yet.</p>}
    </dl></details>
  </article>;
}

// Effect ownership rejects stale view responses; closing the session aborts transport too.
export function useRecord<T>(api: Api, fetcher: () => Promise<T>, dependencies: readonly unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [version, setVersion] = useState(0);
  const identity = JSON.stringify([version, ...dependencies]);
  const [startedIdentity, setStartedIdentity] = useState(identity);
  useEffect(() => {
    let active = true; setStartedIdentity(identity); setLoading(true); setError(''); setData(null);
    fetcher().then(value => { if (active) setData(value); }).catch(reason => {
      if (active) setError(message(reason));
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
    // The caller supplies the complete record identity; fetcher closures are intentionally ephemeral.
  }, [api, version, ...dependencies]);
  const current = startedIdentity === identity;
  return { data: current ? data : null, loading: !current || loading, error: current ? error : '',
    reload: () => setVersion(value => value + 1) };
}
