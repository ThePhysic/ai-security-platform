import { useEffect, useRef, useState } from 'react';
import { Api, message } from './api';
import { Badge, Field, Loading, Notice } from './components';
import { label, type Citation, type Detail, type Triage } from './contracts';

function scoped(citation: Citation, detail: Detail): boolean {
  return citation.snapshot_id === detail.snapshot_id && citation.manifest_digest === detail.manifest_digest &&
    citation.filepath === detail.finding.filepath && /^[0-9a-f]{64}$/.test(citation.evidence_id) &&
    /^[0-9a-f]{64}$/.test(citation.content_digest) &&
    ['finding', 'source', 'rule', 'coverage', 'context'].includes(citation.kind) &&
    citation.filepath.length <= 240 && citation.filepath.split('/').every(part =>
      /^[A-Za-z0-9_.-]+$/.test(part) && !['.', '..', ''].includes(part) && !part.endsWith('.')) &&
    Number.isInteger(citation.start_line) && Number.isInteger(citation.end_line) &&
    citation.start_line >= 1 && citation.end_line >= citation.start_line && citation.end_line <= 1048576;
}

export function Investigation({ api, detail, onResult }: {
  api: Api; detail: Detail; onResult: (value: Triage | null) => void;
}) {
  const [triageId, setTriageId] = useState(detail.latest_triage?.id ?? '');
  const [triage, setTriage] = useState<Triage | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [paused, setPaused] = useState(false);
  const [version, setVersion] = useState(0);
  const key = useRef<string | null>(null);
  useEffect(() => {
    if (!triageId) return;
    let active = true; let timer: ReturnType<typeof setTimeout>;
    const deadline = Date.now() + 120000; setPaused(false); setError('');
    const load = async () => {
      try {
        const value = await api.triage(triageId);
        if (!active) return;
        if (value.finding_id !== detail.finding.id || value.snapshot_id !== detail.snapshot_id ||
            value.manifest_digest !== detail.manifest_digest) throw new Error();
        setTriage(value); onResult(value);
        if (['queued', 'running'].includes(value.status)) {
          if (Date.now() < deadline) timer = setTimeout(load, 1000);
          else setPaused(true);
        }
      } catch (reason) { if (active) setError(message(reason)); }
    };
    void load();
    return () => { active = false; clearTimeout(timer); };
  }, [api, triageId, detail.finding.id, detail.snapshot_id, detail.manifest_digest, version, onResult]);

  async function investigate() {
    setBusy(true); setError('');
    key.current ??= crypto.randomUUID();
    try {
      const result = await api.investigate(detail.finding.id, key.current);
      key.current = null; setTriage(null); onResult(null); setTriageId(result.id); setVersion(v => v + 1);
    } catch (reason) { setError(message(reason)); }
    finally { setBusy(false); }
  }
  const active = busy || (!!triageId && !triage) || (triage !== null && ['queued', 'running'].includes(triage.status));
  return <section className="panel investigation" aria-labelledby="investigation-heading">
    <div className="section-heading"><div><p className="eyebrow">Read-only investigation</p><h2 id="investigation-heading">AI-assisted triage</h2></div>
      <Badge value={triage?.status ?? 'not_requested'} /></div>
    <p className="muted">Deterministic offline baseline. Limited rule support; no live hosted reasoning or automatic decisions.</p>
    <button className="primary" type="button" onClick={() => void investigate()} disabled={active}>Investigate offline</button>
    {busy && <Loading text="Accepting investigation…" />}
    {error && <Notice error>{error} <button onClick={() => setVersion(v => v + 1)}>Retry investigation status</button></Notice>}
    {!triageId && !busy && <p className="empty">No investigation requested. A human must start each investigation.</p>}
    {triageId && !triage && !error && !busy && <Loading text="Loading investigation…" />}
    {paused && <Notice>Automatic refresh paused after two minutes. <button onClick={() => setVersion(v => v + 1)}>Refresh investigation</button></Notice>}
    {triage && <>
      <dl className="metadata">
        <Field title="Provider">{triage.provider === 'deterministic-v1' ? 'Deterministic / offline' : `${triage.provider} · historical provider result`}</Field>
        <Field title="Investigation">{triage.id}</Field>
        <Field title="Prompt / tools">{triage.prompt_version} / {triage.tools_version}</Field>
        <Field title="Confidentiality policy">{triage.policy_version}</Field>
      </dl>
      {['queued', 'running'].includes(triage.status) && <Notice>Investigation pending. Scanner results remain independent.</Notice>}
      {['failed', 'unavailable'].includes(triage.status) && <Notice error>Investigation {triage.status}: {triage.error_code ?? 'result unavailable'}. Scanner results are unchanged.</Notice>}
      {triage.assessment && <div className="assessment">
        <h3>{triage.assessment.assessment === 'abstain' ? 'Abstained · human investigation needed' : label(triage.assessment.assessment)}</h3>
        {triage.assessment.assessment === 'abstain' && <p>Evidence may be insufficient or the rule family unsupported by the offline provider. A human must investigate.</p>}
        <p>{triage.assessment.summary}</p>
        <p><strong>Reason:</strong> {label(triage.assessment.reason)}</p>
        <p><strong>Confidence:</strong> {Number.isFinite(triage.assessment.confidence) ? Math.round(triage.assessment.confidence * 100) : 'Unavailable'}% · uncalibrated provider estimate, not exploit probability</p>
        <div className="advisory"><h3>Advisory remediation · verify before acting</h3><p>{triage.assessment.remediation}</p>
          <p>No source editing or automatic remediation is available. Valid citations do not establish that advice is semantically supported.</p></div>
        <h3>Validated evidence references</h3>
        {!triage.assessment.citations.length && <p>No sufficient evidence citations. Do not treat abstention as a clean result.</p>}
        <ul className="citations">{triage.assessment.citations.map((citation, index) => <li key={index}>
          {scoped(citation, detail) ? <><strong>{citation.kind}: {citation.filepath}:{citation.start_line}–{citation.end_line}</strong>
            <p>Identity matches this snapshot. Validated by the evidence service during investigation.</p>
            <dl className="metadata"><Field title="Snapshot">{citation.snapshot_id}</Field><Field title="Manifest">{citation.manifest_digest}</Field>
              <Field title="Evidence digest">{citation.content_digest}</Field><Field title="Evidence ID">{citation.evidence_id}</Field></dl></>
            : <Notice error>Citation rejected: identity or location does not match the selected finding.</Notice>}
        </li>)}</ul>
      </div>}
    </>}
  </section>;
}
