import { expect, test } from '@playwright/test';
import { bearer, connect, finding, FRONT, project, scan } from './helpers';

test('[live] compiled production preview uses persisted records and a strict CSP without credential storage', async ({ page, request }) => {
  const response = await request.get(FRONT);
  const csp = response.headers()['content-security-policy'] ?? '';
  expect(csp.includes('unsafe-inline')).toBe(false);
  expect(csp.includes('unsafe-eval')).toBe(false);
  expect(response.headers()['cache-control']).toBe('no-store');
  const errors: string[] = [];
  page.on('console', message => { if (message.type() === 'error') errors.push('browser_console_error'); });
  await connect(page); await project(page);
  await expect(page.getByRole('columnheader', { name: 'Created', exact: true })).toBeVisible();
  await scan(page); await finding(page);
  await expect(page.locator('.scanner-card')).toHaveCount(2);
  await page.locator('.scanner-card').first().getByText('Coverage details', { exact: true }).click();
  await expect(page.locator('.scanner-card').first()).toContainText('complete detection claim');
  await expect(page.locator('.finding-detail')).toContainText('Real scanner finding');
  expect((await page.locator('body').innerText()).includes(bearer)).toBe(false);
  expect(errors.length).toBe(0);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await expect(page.getByLabel('Local API bearer token')).toHaveValue('');
});
