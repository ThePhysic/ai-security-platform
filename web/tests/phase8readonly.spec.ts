import { expect, test } from '@playwright/test';
import { connect, project, scan, firstPage } from './helpers';

test('[live] optional-module regression preserves page-scoped metrics without writes', async ({ page }) => {
  const writes: string[] = [];
  page.on('request', request => {
    if (!['GET', 'OPTIONS'].includes(request.method())) writes.push(request.method());
  });
  await connect(page); await project(page); await scan(page);
  const data = await firstPage();
  const critical = data.items.filter(finding => ['HIGH', 'CRITICAL'].includes(finding.severity)).length;
  await expect(page.locator('.finding-row')).toHaveCount(data.items.length);
  await expect(page.locator('.metric').filter({ hasText: 'Findings loaded' }).locator('strong'))
    .toHaveText(String(data.items.length));
  await expect(page.locator('.metric').filter({ hasText: 'High / critical on this page' }).locator('strong'))
    .toHaveText(String(critical));
  await page.getByRole('button', { name: 'Next findings', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'findings', exact: true })).toContainText('Page 2');
  expect(writes).toEqual([]);
});
