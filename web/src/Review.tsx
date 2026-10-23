import { useEffect, useState } from 'react';
import { Api, ApiError, message } from './api';
import { Badge, DateText, Loading, Notice, Pager, useRecord } from './components';
import { DISPOSITIONS, label, type Detail, type Disposition, type Feedback, type Review as ReviewRecord, type Triage } from './contracts';

export function Review({ api, detail, triage }: { api: Api; detail: Detail; triage: Triage | null }) {
  const [current, setCurrent] = useState<ReviewRecord>(detail.review);
  const [expected, setExpected] = useState(detail.review.revision);
  const [disposition, setDisposition] = useState<Disposition | ''>(detail.review.disposition ?? '');
  const [note, setNote] = useState(detail.review.note ?? '');
  const [feedback, setFeedback] = useState<Feedback | ''>('');
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [conflictResolved, setConflictResolved] = useState(false);
  const [cursors, setCursors] = useState<(number | undefined)[]>([undefined]);
  const cursor = cursors[cursors.length - 1];
  const history = useRecord(api, () => api.revisions(detail.finding.id, cursor), [detail.finding.id, cursor, current.revision]);
  useEffect(() => { setFeedback(''); }, [triage?.id]);

  async function save() {
    if (!disposition || conflict) return;
    setBusy(true); setConfirming(false); setError(''); setSaved(false);
    try {
      const value = await api.saveReview(detail.finding.id, expected, disposition, note,
        triage?.status === 'succeeded' && feedback ? triage.id : undefined, feedback || undefined);
      setCurrent(value); setExpected(value.revision); setCursors([undefined]); setSaved(true);
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 409) {
        setConflict(true); setConflictResolved(false);
        try { setCurrent(await api.review(detail.finding.id)); setConflictResolved(true); }
        catch (refreshError) { setError(message(refreshError)); }
      } else setError(message(reason));
    } finally { setBusy(false); }
  }
  function reconsider(loadServer: boolean) {
    setExpected(current.revision); setConflict(false); setFeedback(''); setSaved(false);
    if (loadServer) { setNote(current.note ?? ''); setDisposition(current.disposition ?? ''); }
  }
  return <section className="panel" aria-labelledby="human-heading">
    <div className="section-heading"><div><p className="eyebrow">Explicit human decision</p><h2 id="human-heading">Review finding</h2></div><Badge value={current.disposition ?? 'unreviewed'} /></div>
    <p>Current review revision <strong data-testid="review-revision">{current.revision}</strong>. AI opinions never set a disposition automatically.</p>
    {conflict && <div className="conflict" role="alert">
      <h3>Review conflict · newer revision preserved</h3>
      {conflictResolved ? <><p>Server revision {current.revision}: {label(current.disposition ?? 'unreviewed')}</p>
        <p className="plain-text">Server note: {current.note || 'No explanation'}</p>
        <p>Your draft remains below. Read the current decision before choosing how to continue.</p>
        <div className="row wrap"><button onClick={() => reconsider(true)}>Load server review</button>
          <button onClick={() => reconsider(false)}>Reconsider draft with current revision</button></div></>
        : <><p>Current server review unavailable. Saving remains blocked.</p><button onClick={async () => {
          try { setCurrent(await api.review(detail.finding.id)); setConflictResolved(true); setError(''); }
          catch (reason) { setError(message(reason)); }
        }}>Refresh current review</button></>}
    </div>}
    {error && <Notice error>{error}</Notice>}
    {saved && <Notice>Human review saved as revision {current.revision}.</Notice>}
    <form onSubmit={event => { event.preventDefault(); if (!conflict) setConfirming(true); }}>
      <label htmlFor="disposition">Human disposition</label>
      <select id="disposition" required value={disposition} onChange={event => { setDisposition(event.target.value as Disposition); setSaved(false); }} disabled={busy}>
        <option value="">Choose a decision</option>{DISPOSITIONS.map(value => <option key={value} value={value}>{label(value)}</option>)}
      </select>
      <label htmlFor="review-note">Reviewer explanation <span className="muted">optional · 2,000 characters maximum</span></label>
      <textarea id="review-note" value={note} maxLength={2000} rows={4} onChange={event => { setNote(event.target.value); setSaved(false); }} disabled={busy} />
      <label htmlFor="feedback">Feedback on completed triage <span className="muted">optional</span></label>
      <select id="feedback" value={feedback} onChange={event => setFeedback(event.target.value as Feedback | '')} disabled={busy || triage?.status !== 'succeeded'}>
        <option value="">No AI feedback</option><option value="agree">Agree</option><option value="disagree">Disagree</option><option value="uncertain">Uncertain</option>
      </select>
      <p className="muted">Saving will append an immutable revision using expected revision {expected}.</p>
      <button className="primary" type="submit" disabled={busy || conflict || !disposition}>Review and save</button>
    </form>
    {confirming && <div className="confirmation" role="region" aria-label="Confirm human review">
      <h3>Confirm your human decision</h3><p>Append {label(disposition)} as revision {expected + 1}?</p>
      <p className="plain-text">{note || 'No explanation supplied.'}</p>
      <div className="row"><button className="primary" autoFocus onClick={() => void save()}>Confirm review</button>
        <button onClick={() => setConfirming(false)}>Keep editing</button></div>
    </div>}
    {busy && <Loading text="Saving immutable review revision…" />}
    <div className="history-heading"><h3>Immutable review history</h3><button onClick={history.reload}>Refresh review history</button></div>
    {history.loading && <Loading />}{history.error && <Notice error>{history.error}</Notice>}
    {history.data && <>
      {!history.data.items.length && <p className="empty">No human review revisions yet.</p>}
      <ol className="revision-list">{history.data.items.map(row => <li key={row.revision}>
        <div className="row between"><strong>Revision {row.revision} · {label(row.disposition ?? 'unreviewed')}</strong><DateText value={row.created_at ?? null} /></div>
        <p className="plain-text">{row.note || 'No explanation'}</p><p className="muted">{row.reviewer ?? 'local_operator'}{row.feedback ? ` · AI feedback: ${row.feedback}` : ''}</p>
        {row.triage_run_id && <p className="identifier">Triage reference {row.triage_run_id}</p>}
      </li>)}</ol>
      <Pager page={cursors.length} name="review history" previous={cursors.length > 1 ? () => setCursors(v => v.slice(0, -1)) : undefined}
        next={history.data.next_before_revision ? () => setCursors(v => [...v, history.data!.next_before_revision!]) : undefined} />
    </>}
  </section>;
}
