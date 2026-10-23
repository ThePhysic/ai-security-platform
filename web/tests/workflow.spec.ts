import { expect, test } from '@playwright/test';
import { api, bearer, connect, currentReview, finding, firstPage, fixture, investigate, project, scan, workspace, API } from './helpers';
import type { RevisionPage, Review } from '../src/contracts';

test('[live] memory-only authentication, disconnect, reload and no implicit writes', async ({ page, context }) => {
  const writes: string[] = []; const destinations: string[] = []; let disclosed = false;
  page.on('console', entry => { if (entry.text().includes(bearer)) disclosed = true; });
  page.on('request', request => {
    if (request.method() !== 'GET' && request.method() !== 'OPTIONS') writes.push(request.method());
    if (request.headers().authorization) destinations.push(new URL(request.url()).origin);
    if (request.url().includes(bearer)) disclosed = true;
  });
  await connect(page); await project(page); await scan(page); await finding(page);
  await expect(page.getByRole('heading', { name: 'AI-assisted triage', exact: true })).toBeVisible();
  expect(writes.length).toBe(0);
  expect(destinations.every(value => value === API)).toBe(true);
  expect((await page.locator('body').innerText()).includes(bearer)).toBe(false);
  const storage = await page.evaluate(async () => ({ local: localStorage.length, session: sessionStorage.length,
    db: (await indexedDB.databases()).length, cache: (await caches.keys()).length,
    serviceWorkers: (await navigator.serviceWorker.getRegistrations()).length }));
  expect(Object.values(storage).every(value => value === 0)).toBe(true);
  expect((await context.storageState()).cookies.length).toBe(0);
  expect(disclosed).toBe(false);
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await expect(page.getByLabel('Local API bearer token')).toHaveValue('');
  await expect(page.getByLabel('Project identifier')).toHaveCount(0);
  await connect(page); await page.reload();
  await expect(page.getByRole('heading', { name: 'Connect to your platform' })).toBeVisible();
  await expect(page.getByLabel('Local API bearer token')).toHaveValue('');
});

test('[live] invalid bearer is denied without exposing credentials', async ({ page }) => {
  await connect(page, 'synthetic-invalid-local-token-' + 'x'.repeat(43));
  await expect(page.getByText('Authentication failed. Reconnect with a valid local token.', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Project identifier')).toHaveCount(0);
  await expect(page.getByLabel('Local API bearer token')).toHaveValue('');
});

test('[live] history pagination, exact filters and metrics from loaded persisted records', async ({ page }) => {
  await connect(page); await project(page);
  await expect(page.locator('tbody tr')).toHaveCount(3);
  await page.getByRole('button', { name: 'Next scan history', exact: true }).click();
  await expect(page.locator('tbody tr')).toHaveCount(1);
  await page.getByRole('button', { name: 'Previous scan history', exact: true }).click();
  await scan(page);
  const data = await firstPage();
  await expect(page.locator('.finding-row')).toHaveCount(data.items.length);
  const critical = data.items.filter(f => ['HIGH','CRITICAL'].includes(f.severity)).length;
  await expect(page.locator('.metric').filter({ hasText: 'Findings loaded' }).locator('strong')).toHaveText(String(data.items.length));
  await expect(page.locator('.metric').filter({ hasText: 'High / critical on this page' }).locator('strong')).toHaveText(String(critical));
  await page.getByRole('button', { name: 'Next findings', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'findings', exact: true })).toContainText('Page 2');
  await expect(page.locator('.finding-row')).toHaveCount(10);
  await page.getByRole('button', { name: 'Previous findings', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'findings', exact: true })).toContainText('Page 1');
  await page.getByLabel('Severity', { exact: true }).selectOption('HIGH');
  await page.getByLabel('Scanner', { exact: true }).selectOption('semgrep');
  await page.getByLabel('Human review', { exact: true }).selectOption('unreviewed');
  await finding(page);
  await expect(page.locator('.finding-row')).toHaveCount(1);
  await expect(page.locator('.finding-detail')).toContainText('Real scanner finding');
  await expect(page.locator('.finding-detail')).toContainText(fixture.snapshot);
  await expect(page.locator('.scanner-card')).toHaveCount(2);
  await expect(page.locator('.scanner-card .coverage')).toHaveText([
    'Complete execution · limited detection coverage', 'Complete execution · limited detection coverage'
  ]);
  await page.getByRole('button', { name: 'Reset filters', exact: true }).click();
  await expect(page.locator('.finding-row')).toHaveCount(10);
});

test('[live] partial scan preserves findings and exposes incomplete scanner coverage', async ({ page }) => {
  await connect(page); await project(page, fixture.partial_project); await scan(page, fixture.partial_scan);
  await expect(page.getByText(/Partial scan: available findings/)).toBeVisible();
  await expect(page.locator('.scanner-card .coverage').filter({ hasText: 'Incomplete coverage' })).toHaveCount(1);
  await expect(page.locator('.finding-row').first()).toBeVisible();
});

test('[live] empty project and invalid identifiers have usable safe states', async ({ page }) => {
  await connect(page); await project(page, fixture.empty_project);
  await expect(page.getByRole('heading', { name: 'No scans found' })).toBeVisible();
  await page.getByLabel('Project identifier').fill('invalid-project');
  await page.getByRole('button', { name: 'Open project', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Check the identifier');
});

test('[live] explicit deterministic triage has genuine evidence and no automatic human decision', async ({ page }) => {
  await workspace(page);
  const before = await api<Review>('/api/v1/findings/' + fixture.finding + '/review');
  await investigate(page);
  await expect(page.locator('.investigation')).toContainText('Deterministic / offline');
  await expect(page.locator('.assessment')).toContainText('needs review');
  await expect(page.locator('.assessment')).toContainText('Advisory remediation');
  expect(await page.locator('.citations li').count()).toBeGreaterThanOrEqual(2);
  await expect(page.locator('.citations')).toContainText(fixture.snapshot);
  await expect(page.locator('.citations')).toContainText('source:');
  const after = await api<Review>('/api/v1/findings/' + fixture.finding + '/review');
  expect(after.revision).toBe(before.revision);
  expect(after.disposition).toBe(before.disposition);
});

test('[live] synthetic diagnostic and insufficient-evidence abstention stay explicit', async ({ page }) => {
  await connect(page); await project(page); await scan(page, fixture.fake_scan);
  await expect(page.locator('.scanner-card').first()).toContainText('Synthetic diagnostic');
  await page.locator('.finding-link').first().click();
  await expect(page.locator('.finding-detail')).toContainText('not a genuine detection');
  await investigate(page);
  await expect(page.locator('.assessment')).toContainText('Abstained · human investigation needed');
  await expect(page.locator('.assessment')).toContainText('insufficient evidence');
});

test('[live] unsupported real vulnerability family abstains without inflating reasoning coverage', async ({ page }) => {
  await workspace(page, fixture.unsupported_rule);
  await investigate(page);
  await expect(page.locator('.assessment')).toContainText('Abstained · human investigation needed');
  await expect(page.locator('.assessment')).toContainText('rule family unsupported');
  await expect(page.locator('.finding-detail')).toContainText('Real scanner finding');
});

test('[live] two sessions preserve conflicts, confirmed revisions, feedback and paginated immutable history', async ({ browser }) => {
  const a = await browser.newContext(); const b = await browser.newContext();
  const first = await a.newPage(); const stale = await b.newPage();
  try {
    await workspace(first, fixture.review_rule); await workspace(stale, fixture.review_rule);
    expect((await currentReview()).revision).toBe(0);
    await investigate(first);
    await first.getByLabel('Human disposition', { exact: true }).selectOption('confirmed');
    await first.getByLabel('Reviewer explanation', { exact: false }).fill('Phase 6 explicit human review A');
    await first.getByLabel('Feedback on completed triage', { exact: false }).selectOption('agree');
    await first.getByRole('button', { name: 'Review and save', exact: true }).click();
    expect((await currentReview()).revision).toBe(0);
    await first.getByRole('button', { name: 'Confirm review', exact: true }).click();
    await expect(first.getByTestId('review-revision')).toHaveText('1');
    await stale.getByLabel('Human disposition', { exact: true }).selectOption('investigate');
    await stale.getByLabel('Reviewer explanation', { exact: false }).fill('Phase 6 reconsidered human draft B');
    await stale.getByRole('button', { name: 'Review and save', exact: true }).click();
    await stale.getByRole('button', { name: 'Confirm review', exact: true }).click();
    await expect(stale.getByRole('heading', { name: 'Review conflict · newer revision preserved' })).toBeVisible();
    await expect(stale.locator('.conflict')).toContainText('Phase 6 explicit human review A');
    await expect(stale.getByLabel('Reviewer explanation', { exact: false })).toHaveValue('Phase 6 reconsidered human draft B');
    await expect(stale.getByRole('button', { name: 'Review and save', exact: true })).toBeDisabled();
    expect((await currentReview()).revision).toBe(1);
    await stale.getByRole('button', { name: 'Reconsider draft with current revision', exact: true }).click();
    await stale.getByRole('button', { name: 'Review and save', exact: true }).click();
    await stale.getByRole('button', { name: 'Confirm review', exact: true }).click();
    await expect(stale.getByTestId('review-revision')).toHaveText('2');
    const initial = await api<RevisionPage>('/api/v1/findings/' + fixture.review_finding + '/review-revisions');
    expect(initial.items.map(row => row.revision)).toEqual([2, 1]);
    expect(initial.items[1]?.feedback).toBe('agree');
    expect(typeof initial.items[1]?.triage_run_id).toBe('string');
    for (let revision = 2; revision < 7; revision++) {
      await api<Review>('/api/v1/findings/' + fixture.review_finding + '/review', 'PUT', {
        expected_revision: revision, disposition: 'investigate', note: `Phase 6 controlled history revision ${revision + 1}`
      });
    }
    await stale.getByRole('button', { name: 'Refresh review history', exact: true }).click();
    await expect(stale.locator('.revision-list li')).toHaveCount(5);
    await stale.getByRole('button', { name: 'Next review history', exact: true }).click();
    await expect(stale.locator('.revision-list li')).toHaveCount(2);
    await expect(stale.locator('.revision-list')).toContainText('Phase 6 explicit human review A');
    await stale.getByRole('button', { name: 'Previous review history', exact: true }).click();
    await expect(stale.locator('.revision-list li')).toHaveCount(5);
  } finally { await a.close(); await b.close(); }
});

test('[live] responsive keyboard workflow and labels remain usable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await connect(page);
  await page.getByLabel('Project identifier', { exact: true }).fill(fixture.project);
  await page.getByLabel('Project identifier', { exact: true }).press('Enter');
  await expect(page.getByRole('heading', { name: 'Recent scans', exact: true })).toBeFocused();
  await scan(page); await finding(page);
  await expect(page.getByRole('heading', { name: 'Finding investigation', exact: true })).toBeFocused();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(overflow).toBe(false);
  await page.getByLabel('Human disposition', { exact: true }).focus();
  await page.keyboard.press('ArrowDown'); await page.keyboard.press('Tab');
  await expect(page.getByLabel('Reviewer explanation', { exact: false })).toBeFocused();
});

test('[live] hosted execution remains denied and no provider key is exposed', async ({ request }) => {
  const config = await api<{ hosted_enabled: boolean }>('/api/v1/triage-config');
  expect(config.hosted_enabled).toBe(false);
  const denied = await request.post(API + '/api/v1/findings/' + fixture.finding + '/triage', {
    headers: { Authorization: 'Bearer ' + bearer, 'Idempotency-Key': crypto.randomUUID() }, data: { provider: 'openai-v1' }
  });
  expect(denied.status()).toBe(403);
});
