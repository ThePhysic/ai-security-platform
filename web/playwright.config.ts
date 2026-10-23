import { defineConfig } from '@playwright/test';

const preview = process.env.ASP_TEST_PREVIEW === 'true';

export default defineConfig({
  testDir: './tests',
  testMatch: preview ? '**/preview.spec.ts' : process.env.ASP_EVIDENCE_PHASE === 'phase8'
    ? '**/{workflow,security,phase8readonly}.spec.ts' : '**/{workflow,security}.spec.ts',
  timeout: 45000,
  expect: { timeout: 10000 },
  workers: 1,
  fullyParallel: false,
  retries: 0,
  forbidOnly: true,
  preserveOutput: 'never',
  outputDir: process.env.ASP_EVIDENCE_PHASE === 'phase8' ? '../.cache/phase8-browser-output'
    : process.env.ASP_EVIDENCE_PHASE === 'phase7' ? '../.cache/phase7-browser-output' : '../.cache/phase6-browser-output',
  reporter: [['./tests/reporter.ts']],
  use: {
    baseURL: 'http://127.0.0.1:18082',
    browserName: 'chromium', headless: true,
    screenshot: 'off', trace: 'off', video: 'off',
    viewport: { width: 1440, height: 1000 },
    launchOptions: { args: ['--disable-background-networking'] },
  },
  webServer: {
    cwd: preview ? process.env.ASP_TEST_CLEAN_WEB : undefined,
    command: 'node node_modules/vite/bin/vite.js' + (preview ? ' preview' : ''),
    url: 'http://127.0.0.1:18082',
    reuseExistingServer: false,
    timeout: 30000,
    stdout: 'ignore', stderr: 'ignore',
  },
});
