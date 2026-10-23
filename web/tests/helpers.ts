import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, type Page } from '@playwright/test';
import type { Detail, Finding, Page as ApiPage, Review, Triage } from '../src/contracts';

export const FRONT = 'http://127.0.0.1:18082';
export const API = 'http://127.0.0.1:18081';
export const root = resolve(import.meta.dirname, '../..');
const configuration = readFileSync(resolve(root, '.env'), 'utf8');
export const bearer = /^ASP_API_TOKEN=(.+)$/m.exec(configuration)?.[1]?.trim().replace(/^(['"])(.*)\1$/, '$2') ?? '';
if (!/^[A-Za-z0-9_-]{43,256}$/.test(bearer)) throw new Error('Local browser test credentials unavailable');
export const evidencePhase = process.env.ASP_EVIDENCE_PHASE === 'phase7' ? 'phase7' : 'phase6';
export const fixture = JSON.parse(readFileSync(resolve(root, `.cache/${evidencePhase}-browser-fixture.json`), 'utf8')) as {
  project: string; scan: string; finding: string; rule: string; snapshot: string;
  review_finding: string; review_rule: string; fake_scan: string; empty_project: string;
  unsupported_rule: string;
  partial_scan: string; partial_project: string;
};

export async function api<T>(path: string, method = 'GET', body?: object): Promise<T> {
  const response = await fetch(API + path, { method, headers: { Authorization: 'Bearer ' + bearer,
    ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000), redirect: 'error' });
  if (!response.ok) throw new Error(`Controlled test API unavailable (${response.status})`);
  return await response.json() as T;
}

export async function connect(page: Page, value = bearer) {
  await page.goto(FRONT);
  // Avoid credential-bearing fill/type action logs and disable all traces/artifacts.
  await page.getByLabel('Local API bearer token').evaluate((element, token) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(element, token);
    element.dispatchEvent(new Event('input', { bubbles: true }));
  }, value);
  await page.getByRole('button', { name: 'Connect locally', exact: true }).click();
  if (value === bearer) await expect(page.getByText('Local session connected', { exact: true })).toBeVisible();
}
export async function project(page: Page, value = fixture.project) {
  await page.getByLabel('Project identifier', { exact: true }).fill(value);
  await page.getByRole('button', { name: 'Open project', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Recent scans', exact: true })).toBeVisible();
}
export async function scan(page: Page, value = fixture.scan) {
  await expect(page.getByRole('navigation', { name: 'scan history', exact: true })).toBeVisible();
  const button = page.getByRole('button', { name: `Open scan ${value.slice(0, 8)}`, exact: true });
  for (let index = 0; index < 10; index++) {
    if (await button.count()) break;
    const next = page.getByRole('button', { name: 'Next scan history', exact: true });
    await expect(next).toBeVisible();
    if (!(await next.isEnabled())) break;
    await next.click();
    await expect(page.getByRole('table')).toBeVisible();
  }
  await button.click();
  await expect(page.getByRole('heading', { name: `Scan ${value.slice(0, 8)}`, exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply filters', exact: true })).toBeVisible();
}
export async function finding(page: Page, rule = fixture.rule) {
  await page.getByLabel('Rule ID', { exact: true }).fill(rule);
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await page.getByRole('button', { name: `Inspect ${rule}`, exact: true }).first().click();
  await expect(page.getByRole('heading', { name: 'Finding investigation', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Review finding', exact: true })).toBeVisible();
}
export async function workspace(page: Page, rule = fixture.rule) {
  await connect(page); await project(page); await scan(page); await finding(page, rule);
}
export async function investigate(page: Page) {
  await expect(page.getByRole('button', { name: 'Investigate offline', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Investigate offline', exact: true }).click();
  await expect(page.locator('.investigation .badge')).toHaveText('succeeded', { timeout: 30000 });
}
export async function firstPage(): Promise<ApiPage<Finding>> {
  return api(`/api/v1/scan-runs/${fixture.scan}/findings?limit=10`);
}
export async function detail(): Promise<Detail> { return api('/api/v1/findings/' + fixture.finding); }
export async function currentReview(): Promise<Review> { return api('/api/v1/findings/' + fixture.review_finding + '/review'); }
export async function latestTriage(): Promise<Triage | null> {
  const data = await detail();
  return data.latest_triage ? api('/api/v1/triage-runs/' + data.latest_triage.id) : null;
}
