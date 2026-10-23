import { Component, useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Api, id, message } from './api';
import { Badge, DateText, Field, Loading, Notice, Pager, ScannerCard, useRecord } from './components';
import { EMPTY_FILTERS, DISPOSITIONS, label, type Filters, type Finding, type Scan, type Triage } from './contracts';
import { Investigation } from './Investigation';
import { Review } from './Review';

class SafeBoundary extends Component<{ children: ReactNode; disconnect: () => void }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    return this.state.failed ? <Notice error>Dashboard response unavailable. Disconnect and retry the local session.
      <button onClick={this.props.disconnect}>Disconnect session</button></Notice> : this.props.children;
  }
}

export default function App() {
  const [api, setApi] = useState<Api | null>(null);
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const session = useRef<Api | null>(null);
  const disconnect = useCallback(() => {
    session.current?.close(); session.current = null; setApi(null); setToken(''); setNotice('Session disconnected. Credentials and loaded records were cleared.');
  }, []);
  useEffect(() => () => { session.current?.close(); }, []);
  async function connect() {
    setBusy(true); setNotice('');
    let candidate: Api | null = null;
    try {
      candidate = new Api(token, disconnect); setToken('');
      await candidate.authenticate(); session.current = candidate; setApi(candidate);
    } catch (reason) { candidate?.close(); setNotice(message(reason)); }
    finally { setToken(''); setBusy(false); }
  }
  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#main"><svg viewBox="0 0 32 36" aria-hidden="true"><path d="M16 2 29 7v11c0 8-8 13-13 16C11 31 3 26 3 18V7z" fill="none" stroke="currentColor" strokeWidth="2"/><path d="m10 18 4 4 8-10" fill="none" stroke="currentColor" strokeWidth="2"/></svg><span>ASP<span className="brand-sub">Security workspace</span></span></a>
      <p className="sidebar-label">APPLICATION SECURITY</p>
      <div className="nav-current">▦ &nbsp; Investigation workspace</div>
      <div className="sidebar-bottom"><span className="local-indicator" /> Local environment
        <p>Read-only automation.<br />Human decisions.</p><p className="small">Scanner coverage is limited. A completed scan is not proof of security.</p></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><span className="breadcrumb">Application security / Reporting</span>
        <div className="row"><span className="session-indicator">{api ? 'Local session connected' : 'Disconnected'}</span>{api && <button onClick={disconnect}>Disconnect</button>}</div></header>
      <main id="main">
        <div className="page-heading"><div><p className="eyebrow">Developer guardrails</p><h1>Security workspace</h1><p>Investigate scanner evidence. Make explicit, accountable review decisions.</p></div><span className="environment-tag">LOCAL ONLY</span></div>
        {!api ? <section className="panel connect-panel" aria-labelledby="connect-heading"><p className="eyebrow">Private local access</p><h2 id="connect-heading">Connect to your platform</h2>
          <p>Enter the local API bearer token supplied by your operator. It stays in this page's memory and is cleared on disconnect or reload.</p>
          {notice && <Notice>{notice}</Notice>}
          <form onSubmit={event => { event.preventDefault(); void connect(); }} autoComplete="off">
            <label htmlFor="bearer">Local API bearer token</label><input id="bearer" type="password" required minLength={43} maxLength={256} autoComplete="off" autoCapitalize="none" spellCheck={false}
              value={token} onChange={event => setToken(event.target.value)} disabled={busy} />
            <button className="primary" disabled={busy}>{busy ? 'Connecting…' : 'Connect locally'}</button>
          </form><p className="small muted">API: 127.0.0.1:18081 · No browser credential storage · No hosted model calls</p>
        </section> : <SafeBoundary key="session" disconnect={disconnect}><Workspace api={api} /></SafeBoundary>}
      </main><footer>Security engineering platform · AI advice requires human verification</footer>
    </div>
  </div>;
}

function Workspace({ api }: { api: Api }) {
  const [draft, setDraft] = useState('');
  const [projectId, setProjectId] = useState('');
  const [error, setError] = useState('');
  return <>
    <section className="panel project-picker"><form onSubmit={event => {
      event.preventDefault(); setError(''); try { setProjectId(id(draft.trim())); } catch (reason) { setError(message(reason)); }
    }}><div><label htmlFor="project-id">Project identifier</label><input id="project-id" value={draft} onChange={event => setDraft(event.target.value)} placeholder="Project UUID from your CLI" required maxLength={36} autoComplete="off" spellCheck={false} /></div>
      <button type="submit">Open project</button></form><p className="small muted">Use an existing authorized project's UUID. No source upload or scan submission happens from this dashboard.</p></section>
    {error && <Notice error>{error}</Notice>}
    {projectId ? <ProjectWorkspace key={projectId} api={api} projectId={projectId} /> : <section className="empty-state"><span aria-hidden="true">▦</span><h2>Choose a project to begin</h2><p>Scan history, findings and human reviews will appear here.</p></section>}
  </>;
}

function ProjectWorkspace({ api, projectId }: { api: Api; projectId: string }) {
  const project = useRecord(api, () => api.project(projectId), [projectId]);
  const [selected, setSelected] = useState('');
  if (project.loading) return <Loading text="Loading project…" />;
  if (project.error) return <Notice error>{project.error} <button onClick={project.reload}>Retry project</button></Notice>;
  if (!project.data) return null;
  return <><div className="project-heading"><h2>{project.data.name}</h2><span className="identifier">{project.data.id}</span></div>
    {selected ? <ScanWorkspace key={selected} api={api} scanId={selected} projectId={projectId} back={() => setSelected('')} />
      : <ScanHistory api={api} projectId={projectId} open={setSelected} />}</>;
}

function ScanHistory({ api, projectId, open }: { api: Api; projectId: string; open: (id: string) => void }) {
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const cursor = cursors[cursors.length - 1];
  const records = useRecord(api, () => api.scans(projectId, cursor), [projectId, cursor]);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  return <section aria-labelledby="history-heading">
    <div className="section-heading"><div><p className="eyebrow">Persisted activity</p><h2 id="history-heading" ref={heading} tabIndex={-1}>Recent scans</h2></div><button onClick={records.reload}>Refresh scans</button></div>
    {records.loading && <Loading />}{records.error && <Notice error>{records.error} <button onClick={records.reload}>Retry scan history</button></Notice>}
    {records.data && <>
      <div className="metrics"><Metric title="Scans loaded" value={records.data.items.length} /><Metric title="Completed on this page" value={records.data.items.filter(s => s.status === 'succeeded').length} />
        <Metric title="Partial or failed on this page" value={records.data.items.filter(s => ['partial', 'failed'].includes(s.status)).length} /></div>
      <p className="scope">Metrics cover this loaded history page only (up to 3 scans), not project totals. Completed does not mean vulnerability-free.</p>
      {!records.data.items.length ? <div className="panel empty-state"><h3>No scans found</h3><p>Submit an authorized scan with the existing CLI to populate this project.</p></div>
        : <div className="table-wrap panel"><table><caption>Persisted scan history · newest first</caption><thead><tr><th>Scan / profile</th><th>Created</th><th>Status</th><th>Action</th></tr></thead><tbody>{records.data.items.map(scan => <tr key={scan.id}>
          <td><strong>{scan.id.slice(0, 8)}</strong><span className="table-sub">{scan.profile_id}</span></td><td><DateText value={scan.created_at} /></td><td><Badge value={scan.status} /></td><td><button onClick={() => open(scan.id)} aria-label={`Open scan ${scan.id.slice(0, 8)}`}>Open scan →</button></td>
        </tr>)}</tbody></table></div>}
      <Pager name="scan history" page={cursors.length} previous={cursors.length > 1 ? () => setCursors(v => v.slice(0, -1)) : undefined}
        next={records.data.next_cursor ? () => setCursors(v => [...v, records.data!.next_cursor!]) : undefined} />
    </>}
  </section>;
}

function Metric({ title, value }: { title: string; value: number }) {
  return <div className="metric"><span>{title}</span><strong>{value}</strong></div>;
}

function ScanWorkspace({ api, scanId, projectId, back }: { api: Api; scanId: string; projectId: string; back: () => void }) {
  const record = useRecord(api, async () => { const scan = await api.scan(scanId); if (scan.project_id !== projectId) throw new Error(); return scan; }, [scanId, projectId]);
  const [previous, setPrevious] = useState<Scan | null>(null);
  const data = record.data ?? previous;
  const heading = useRef<HTMLHeadingElement>(null);
  const focused = useRef(false);
  const pollingStart = useRef(Date.now());
  useEffect(() => {
    if (record.data) {
      setPrevious(record.data);
      if (!focused.current) { heading.current?.focus(); focused.current = true; }
    }
  }, [record.data]);
  useEffect(() => {
    if (record.data && ['queued', 'running'].includes(record.data.status) && Date.now() - pollingStart.current < 120000) {
      const timer = setTimeout(record.reload, 5000); return () => clearTimeout(timer);
    }
  }, [record.data, record.reload]);
  return <section><button className="back" onClick={back}>← Scan history</button>
    {record.loading && <Loading text={data ? 'Refreshing scan lifecycle…' : 'Loading scan lifecycle…'} />}
    {record.error && <Notice error>{record.error} <button onClick={record.reload}>Retry scan</button></Notice>}
    {record.error && data && <Notice>Showing previously loaded scan metadata. Refresh is unavailable; do not assume the displayed status is current.</Notice>}
    {data && <>
      <div className="section-heading"><div><p className="eyebrow">Scan lifecycle</p><h2 ref={heading} tabIndex={-1}>Scan {data.id.slice(0, 8)}</h2></div><div className="row"><Badge value={data.status} /><button onClick={() => { pollingStart.current = Date.now(); record.reload(); }}>Refresh scan</button></div></div>
      {data.status === 'partial' && <Notice>Partial scan: available findings are preserved, but one or more scanners did not complete. Inspect coverage before relying on results.</Notice>}
      {data.status === 'failed' && <Notice error>Scan failed. A missing result is not a clean result.</Notice>}
      {['queued', 'running'].includes(data.status) && <Notice>Scan pending. Automatic refresh is bounded to two minutes; use Refresh scan afterward.</Notice>}
      <div className="panel"><dl className="metadata scan-metadata"><Field title="Scan ID">{data.id}</Field><Field title="Snapshot">{data.snapshot_id}</Field><Field title="Profile">{data.profile_id}</Field>
        <Field title="Created"><DateText value={data.created_at} /></Field><Field title="Started"><DateText value={data.started_at} /></Field><Field title="Completed"><DateText value={data.completed_at} /></Field></dl></div>
      <h3>Scanner execution and coverage</h3><div className="scanner-grid">{data.scanner_runs.map(scanner => <ScannerCard key={scanner.id} scanner={scanner} />)}</div>
      {!data.scanner_runs.length && <Notice>Scanner execution details are not yet available. Coverage is unknown.</Notice>}
      <FindingWorkspace api={api} scan={data} />
    </>}
  </section>;
}

function FindingWorkspace({ api, scan }: { api: Api; scan: Scan }) {
  const [draft, setDraft] = useState<Filters>({ ...EMPTY_FILTERS });
  const [filters, setFilters] = useState<Filters>({ ...EMPTY_FILTERS });
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [selected, setSelected] = useState('');
  const cursor = cursors[cursors.length - 1];
  const records = useRecord(api, () => api.findings(scan.id, filters, cursor), [scan.id, JSON.stringify(filters), cursor]);
  function apply(value: Filters) { setFilters({ ...value }); setDraft({ ...value }); setCursors([undefined]); setSelected(''); }
  function filter(key: keyof Filters, value: string) { setDraft(v => ({ ...v, [key]: value })); }
  return <section className="findings-workspace" aria-labelledby="findings-heading">
    <div className="section-heading"><div><p className="eyebrow">Scanner observations</p><h2 id="findings-heading">Findings</h2></div><button onClick={records.reload}>Refresh finding page</button></div>
    <form className="filter-form panel" onSubmit={event => { event.preventDefault(); apply(draft); }}>
      <div><label htmlFor="severity-filter">Severity</label><select id="severity-filter" value={draft.severity} onChange={e => filter('severity', e.target.value)}><option value="">All severities</option>{['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'].map(v => <option key={v}>{v}</option>)}</select></div>
      <div><label htmlFor="scanner-filter">Scanner</label><select id="scanner-filter" value={draft.scanner} onChange={e => filter('scanner', e.target.value)}><option value="">All scanners</option>{scan.scanner_runs.map(s => <option key={s.id} value={s.scanner_id}>{s.scanner_id}</option>)}</select></div>
      <div><label htmlFor="rule-filter">Rule ID</label><input id="rule-filter" maxLength={128} value={draft.rule_id} onChange={e => filter('rule_id', e.target.value)} autoComplete="off" /></div>
      <div><label htmlFor="review-filter">Human review</label><select id="review-filter" value={draft.review} onChange={e => filter('review', e.target.value)}><option value="">All reviews</option><option value="unreviewed">unreviewed</option>{DISPOSITIONS.map(v => <option key={v} value={v}>{label(v)}</option>)}</select></div>
      <div className="row filter-actions"><button className="primary" type="submit">Apply filters</button><button type="button" onClick={() => apply(EMPTY_FILTERS)}>Reset filters</button></div>
    </form>
    {records.loading && <Loading />}{records.error && <Notice error>{records.error} <button onClick={records.reload}>Retry findings</button></Notice>}
    {records.data && <>
      <div className="metrics"><Metric title="Findings loaded" value={records.data.items.length} /><Metric title="High / critical on this page" value={records.data.items.filter(f => ['HIGH','CRITICAL'].includes(f.severity)).length} /><Metric title="Synthetic on this page" value={records.data.items.filter(f => f.synthetic).length} /></div>
      <p className="scope">Finding metrics cover this loaded, filtered page only (up to 10). Refresh after human review changes; filter membership can change.</p>
      <dl className="severity-summary" aria-label="Severity counts on loaded finding page">{['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'].map(value => <div key={value}><dt>{value}</dt><dd>{records.data!.items.filter(f => f.severity === value).length}</dd></div>)}</dl>
      {!records.data.items.length && <div className="panel empty-state"><h3>No findings match this page</h3><p>Check filters and scanner coverage. No returned findings is not a guarantee of security.</p></div>}
      <div className={`finding-layout ${selected ? 'with-detail' : ''}`}><div>
        <ul className="finding-list">{records.data.items.map(finding => <FindingRow key={finding.id} finding={finding} selected={selected === finding.id} select={() => setSelected(finding.id)} />)}</ul>
        <Pager name="findings" page={cursors.length} previous={cursors.length > 1 ? () => { setCursors(v => v.slice(0, -1)); setSelected(''); } : undefined}
          next={records.data.next_cursor ? () => { setCursors(v => [...v, records.data!.next_cursor!]); setSelected(''); } : undefined} />
      </div>{selected && <FindingDetail key={selected} api={api} scan={scan} findingId={selected} close={() => setSelected('')} />}</div>
    </>}
  </section>;
}

function FindingRow({ finding, selected, select }: { finding: Finding; selected: boolean; select: () => void }) {
  return <li className={`finding-row ${selected ? 'selected' : ''}`}><div className="row between"><Badge value={finding.severity} /><span className={finding.synthetic ? 'diagnostic' : 'muted'}>{finding.synthetic ? 'Synthetic diagnostic' : 'Real scanner finding'}</span></div>
    <button className="finding-link" onClick={select} aria-current={selected ? 'true' : undefined}>Inspect {finding.rule_id}</button>
    <p className="location">{finding.filepath}:{finding.start_line}–{finding.end_line}</p><p>{finding.description}</p></li>;
}

function FindingDetail({ api, scan, findingId, close }: { api: Api; scan: Scan; findingId: string; close: () => void }) {
  const record = useRecord(api, async () => {
    const detail = await api.finding(findingId);
    if (detail.finding.id !== findingId || detail.finding.scan_run_id !== scan.id || detail.snapshot_id !== scan.snapshot_id) throw new Error();
    return detail;
  }, [findingId, scan.id, scan.snapshot_id]);
  const [triage, setTriage] = useState<Triage | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (record.data) heading.current?.focus(); }, [record.data]);
  return <div className="finding-detail"><div className="row between"><h2 ref={heading} tabIndex={-1}>Finding investigation</h2><button onClick={close}>Close finding</button></div>
    {record.loading && <Loading text="Loading finding evidence…" />}{record.error && <Notice error>{record.error} <button onClick={record.reload}>Retry finding</button></Notice>}
    {record.data && <><section className="panel"><div className="row wrap"><Badge value={record.data.finding.severity} /><strong>{record.data.finding.synthetic ? 'Synthetic diagnostic · not a genuine detection' : 'Real scanner finding'}</strong></div>
      <h3>{record.data.finding.rule_id}</h3><p>{record.data.finding.description}</p><dl className="metadata">
        <Field title="Source location">{record.data.finding.filepath}:{record.data.finding.start_line}–{record.data.finding.end_line}</Field>
        <Field title="Scanner">{record.data.scanner_id}</Field><Field title="Original severity">{record.data.finding.original_severity}</Field><Field title="Category">{record.data.finding.category}</Field>
        <Field title="Snapshot ID">{record.data.snapshot_id}</Field><Field title="Manifest digest">{record.data.manifest_digest}</Field><Field title="Tracking identity">{record.data.finding.tracking_fingerprint}</Field>
      </dl><p className="small muted">Server-scoped immutable snapshot reference. Investigation citations are verified against source bytes by the evidence service; source code is not loaded into this page.</p>
      {record.data.finding.evidence.manifest_digest && record.data.finding.evidence.manifest_digest !== record.data.manifest_digest && <Notice error>Finding evidence identity mismatch. Do not rely on this reference.</Notice>}
    </section><Investigation api={api} detail={record.data} onResult={setTriage} /><Review api={api} detail={record.data} triage={triage} /></>}
  </div>;
}
