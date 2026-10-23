import { expect, test } from '@playwright/test';
import { api, API, connect, detail, finding, evidencePhase, fixture, FRONT, project, scan } from './helpers';
import type { Detail, Page as ApiPage, Finding, Scan, Triage } from '../src/contracts';

test('[security] exact API origin, frontend origin and Host denials enforce local boundary', async ({ request, page }) => {
  for (const origin of ['http://127.0.0.1:18083', 'http://localhost:18082', 'null', 'https://untrusted.invalid']) {
    const response = await request.get(API + '/api/v1/triage-config', { headers: { Origin: origin } });
    expect(response.status()).toBe(403);
    expect(response.headers()['access-control-allow-origin']).toBeUndefined();
  }
  const missing = await request.get(API + '/api/v1/triage-config', { headers: { Origin: FRONT } });
  expect(missing.status()).toBe(401);
  const host = await request.get(FRONT, { headers: { Host: 'untrusted.invalid' } });
  expect(host.status()).toBe(403);
  const origin = await request.get(FRONT, { headers: { Origin: 'http://127.0.0.1:18083' } });
  expect(origin.status()).toBe(403);
  const normal = await request.get(FRONT);
  expect(normal.headers()['content-security-policy']).toContain("script-src 'self'");
  expect(normal.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
  expect(normal.headers()['cache-control']).toBe('no-store');
  await page.goto('data:text/html,<title>Controlled null-origin check</title>');
  const denied = await page.evaluate(async url => {
    try { await fetch(url, { headers: { Authorization: 'Bearer synthetic-denied-origin-token' } }); return false; }
    catch { return true; }
  }, API + '/api/v1/triage-config');
  expect(denied).toBe(true);
});

test('[scripted] hostile finding, path, Markdown and agent content remain inert and redacted', async ({ page }) => {
  const original = await detail();
  const injection = '<img src="https://untrusted.invalid/x" onerror="window.phase6Injected=1">';
  const path = '<svg onload="window.phase6Injected=1">';
  const synthetic = 'AKIA' + 'Z'.repeat(16);
  const malicious: Detail = structuredClone(original);
  malicious.finding.description = injection + ' ' + synthetic;
  malicious.finding.filepath = path;
  const triageId = 'f6666666-6666-4666-8666-666666666666';
  malicious.latest_triage = { id: triageId, status: 'succeeded' };
  const mocked: Triage = {
    id: triageId, finding_id: fixture.finding, scan_run_id: fixture.scan, snapshot_id: fixture.snapshot,
    manifest_digest: original.manifest_digest, provider: 'deterministic-v1', status: 'succeeded', error_code: null,
    prompt_version: 'triage-prompt-1', tools_version: 'evidence-tools-1', policy_version: 'confidentiality-1',
    config_digest: 'a'.repeat(64), human_decision: false,
    assessment: { assessment: 'needs_review', confidence: 0.1, summary: '# Markdown <script>window.phase6Injected=1</script> ' + synthetic,
      remediation: '[unsafe link](https://untrusted.invalid) ' + injection, reason: 'evidence_supported',
      citations: [{ evidence_id: 'b'.repeat(64), content_digest: 'c'.repeat(64), kind: 'source',
        snapshot_id: '00000000-0000-0000-0000-000000000000', manifest_digest: original.manifest_digest,
        filepath: path, start_line: 1, end_line: 1 }] }
  };
  await page.route(API + '/api/v1/findings/' + fixture.finding, route => route.fulfill({ json: malicious }));
  await page.route(API + '/api/v1/triage-runs/' + triageId, route => route.fulfill({ json: mocked }));
  await page.route(API + '/api/v1/scan-runs/' + fixture.scan + '/findings?*', route => route.fulfill({
    json: { items: [malicious.finding], next_cursor: null } satisfies ApiPage<Finding>
  }));
  let external = 0;
  page.on('request', request => { if (request.url().startsWith('https://untrusted.invalid')) external++; });
  await connect(page); await project(page); await scan(page); await finding(page);
  await expect(page.locator('.finding-row')).toContainText(injection);
  await expect(page.locator('.assessment')).toContainText('# Markdown <script>');
  await expect(page.locator('.assessment')).toContainText('[unsafe link](https://untrusted.invalid)');
  await expect(page.locator('.assessment')).toContainText('Citation rejected');
  expect((await page.locator('body').innerText()).includes(synthetic)).toBe(false);
  await expect(page.locator('img, iframe, .finding-detail a')).toHaveCount(0);
  expect(await page.evaluate(() => 'phase6Injected' in window)).toBe(false);
  expect(external).toBe(0);
});

test('[scripted] pending triage polling reports actual states and safe provider failure', async ({ page }) => {
  const original = await detail();
  const triageId = 'f7777777-7777-4777-8777-777777777777';
  original.latest_triage = { id: triageId, status: 'queued' };
  let calls = 0;
  await page.route(API + '/api/v1/findings/' + fixture.finding, route => route.fulfill({ json: original }));
  await page.route(API + '/api/v1/triage-runs/' + triageId, route => {
    const status = ['queued', 'running', 'failed'][Math.min(calls++, 2)];
    return route.fulfill({ json: { id: triageId, finding_id: fixture.finding, snapshot_id: fixture.snapshot,
      manifest_digest: original.manifest_digest, status, provider: 'deterministic-v1', error_code: status === 'failed' ? 'provider_timeout' : null,
      assessment: null, prompt_version: 'triage-prompt-1', tools_version: 'evidence-tools-1', policy_version: 'confidentiality-1' } });
  });
  await connect(page); await project(page); await scan(page); await finding(page);
  await expect(page.locator('.investigation .badge')).toHaveText('queued');
  await expect(page.getByRole('button', { name: 'Investigate offline', exact: true })).toBeDisabled();
  await expect(page.locator('.investigation .badge')).toHaveText('failed');
  await expect(page.locator('.investigation')).toContainText('provider_timeout');
  await expect(page.locator('.investigation')).toContainText('Scanner results are unchanged');
  expect(calls).toBe(3);
});

test('[scripted] unavailable triage and failed scanner never appear clean', async ({ page }) => {
  const original = await detail();
  const triageId = 'f8888888-8888-4888-8888-888888888888';
  original.latest_triage = { id: triageId, status: 'unavailable' };
  const current = await api<Scan>('/api/v1/scan-runs/' + fixture.scan);
  current.status = 'failed';
  for (const scanner of current.scanner_runs) { scanner.status = 'failed'; scanner.error_code = 'execution_timeout'; scanner.coverage.complete_execution = false; }
  await page.route(API + '/api/v1/scan-runs/' + fixture.scan, route => route.fulfill({ json: current }));
  await page.route(API + '/api/v1/findings/' + fixture.finding, route => route.fulfill({ json: original }));
  await page.route(API + '/api/v1/triage-runs/' + triageId, route => route.fulfill({ json: {
    id: triageId, finding_id: fixture.finding, snapshot_id: fixture.snapshot, manifest_digest: original.manifest_digest,
    provider: 'deterministic-v1', status: 'unavailable', error_code: 'provider_unavailable', assessment: null,
    prompt_version: 'triage-prompt-1', tools_version: 'evidence-tools-1', policy_version: 'confidentiality-1'
  } }));
  await connect(page); await project(page); await scan(page); await finding(page);
  await expect(page.getByText('Scan failed. A missing result is not a clean result.', { exact: true })).toBeVisible();
  await expect(page.locator('.scanner-card .coverage').filter({ hasText: 'Incomplete coverage' })).toHaveCount(2);
  await expect(page.locator('.investigation')).toContainText('provider_unavailable');
});

test('[scripted] loading, unavailable API retry and empty filtered finding states', async ({ page }) => {
  let requests = 0;
  await page.route(API + '/api/v1/scan-runs?*', async route => {
    if (requests++ === 0) { await new Promise(resolve => setTimeout(resolve, 400)); return route.fulfill({ status: 503, json: { message: 'Untrusted raw exception must not be shown' } }); }
    return route.continue();
  });
  await connect(page); await project(page);
  await expect(page.getByText('Loading records…', { exact: true })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('Local API unavailable');
  await expect(page.getByText('Untrusted raw exception must not be shown', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Retry scan history', exact: true }).click();
  await scan(page);
  await page.getByLabel('Rule ID', { exact: true }).fill('platform.no-such-rule');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'No findings match this page', exact: true })).toBeVisible();
});

test('[security] frontend modules and artifacts cannot read private configuration or persist credentials', async ({ page, request }) => {
  const denied = await request.get(FRONT + `/.env.${evidencePhase}-probe`);
  expect(denied.status()).not.toBe(200);
  expect((await denied.text()).includes(`${evidencePhase}-controlled-private-probe`)).toBe(false);
  expect((await request.get(FRONT + '/tests/helpers.ts')).status()).not.toBe(200);
  await page.goto(FRONT);
  const checked = await page.evaluate(async () => {
    const modulePath = '/src/api.ts';
    const { Api } = await import(modulePath);
    const client = new Api('synthetic-browser-' + 'x'.repeat(43), () => {});
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(client));
    client.close();
    let rejected = false;
    try { await client.project('00000000-0000-0000-0000-000000000000'); } catch { rejected = true; }
    return { rejected, hasDockerOrShell: methods.some(v => /docker|shell|remediat|hosted|consent/i.test(v)) };
  });
  expect(checked).toEqual({ rejected: true, hasDockerOrShell: false });
});

test('[security] malformed and oversized API responses fail visibly within bounds', async ({ page }) => {
  await connect(page); await project(page);
  await page.route(API + '/api/v1/scan-runs/' + fixture.scan, route => route.fulfill({
    contentType: 'application/json', body: '{"padding":"' + 'x'.repeat(4194304) + '"}'
  }));
  await page.getByRole('button', { name: `Open scan ${fixture.scan.slice(0, 8)}`, exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Local API unavailable');
  await page.unroute(API + '/api/v1/scan-runs/' + fixture.scan);
  await page.route(API + '/api/v1/scan-runs/' + fixture.scan, route => route.fulfill({
    contentType: 'application/json', body: '{broken'
  }));
  await page.getByRole('button', { name: 'Retry scan', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Local API unavailable');
});

test('[scripted] background pending-scan refresh preserves unsaved human draft and focus', async ({ page }) => {
  const value = await api<Scan>('/api/v1/scan-runs/' + fixture.scan);
  value.status = 'running'; value.completed_at = null;
  const trivy = value.scanner_runs.find(scanner => scanner.scanner_id === 'trivy')!;
  trivy.status = 'running'; trivy.coverage.complete_execution = false;
  let refreshes = 0; let writes = 0;
  page.on('request', request => { if (request.method() === 'PUT') writes++; });
  await page.route(API + '/api/v1/scan-runs/' + fixture.scan, route => {
    refreshes++; return route.fulfill({ json: value });
  });
  await connect(page); await project(page); await scan(page); await finding(page);
  const note = page.getByLabel('Reviewer explanation', { exact: false });
  await note.fill('Unsaved human draft must survive background status refresh');
  await note.focus();
  await expect.poll(() => refreshes, { timeout: 15000 }).toBeGreaterThanOrEqual(2);
  await expect(page.getByText('Refreshing scan lifecycle…', { exact: true })).toHaveCount(0);
  await expect(note).toHaveValue('Unsaved human draft must survive background status refresh');
  await expect(note).toBeFocused();
  expect(writes).toBe(0);
});
