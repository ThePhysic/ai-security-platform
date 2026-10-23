import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { FullResult, Reporter, TestCase, TestResult, TestStep } from '@playwright/test/reporter';
import { bearer, root, evidencePhase } from './helpers';

export default class SafeReporter implements Reporter {
  private cases: { name: string; status: string; mode: string; diagnostic?: string }[] = [];
  private steps = new Map<string, string>();
  onStepBegin(test: TestCase, _result: TestResult, step: TestStep) {
    if (step.category === 'pw:api' && !/close|teardown/i.test(step.title)) {
      this.steps.set(test.id, step.title.split(bearer).join('[redacted]').slice(0, 300));
    }
  }
  onTestEnd(test: TestCase, result: TestResult) {
    const mode = test.title.startsWith('[live]') ? 'actual API/PostgreSQL/browser'
      : test.title.startsWith('[scripted]') ? 'scripted transport in actual browser' : 'browser/security contract';
    const diagnostic = result.status === 'passed' ? undefined : ((result.error?.message ?? 'Browser check failed') + '\nLast step: ' + this.steps.get(test.id))
      .split(bearer).join('[redacted]').replace(/AKIA[0-9A-Z]{16}|SYNTHETIC_SECRET_[A-Za-z0-9_-]+/g, '[redacted]')
      .replace(/\u001b\[[0-9;]*m/g, '').slice(0, 2000);
    this.cases.push({ name: test.title, status: result.status, mode, ...(diagnostic ? { diagnostic } : {}) });
    process.stdout.write(JSON.stringify({ test: test.title, status: result.status }) + '\n');
  }
  onError() { process.stdout.write('{"error":"browser_runner_failure"}\n'); }
  onEnd(result: FullResult) {
    const record = { scope: `${evidencePhase} Chromium; live and scripted modes separated`, status: result.status,
      passed: this.cases.filter(c => c.status === 'passed').length,
      failed: this.cases.filter(c => ['failed','timedOut','interrupted'].includes(c.status)).length,
      skipped: this.cases.filter(c => c.status === 'skipped').length,
      browser: 'Chromium 156.0.8078.4 / Playwright 1.64.1',
      compiled_clean_context: process.env.ASP_TEST_PREVIEW === 'true' && !!process.env.ASP_TEST_CLEAN_WEB,
      credential_capture: false, screenshots: false, traces: false, videos: false, cases: this.cases };
    mkdirSync(resolve(root, `docs/${evidencePhase}`), { recursive: true });
    const target = process.env.ASP_TEST_PREVIEW === 'true' ? 'preview-evidence.json'
      : process.env.ASP_TEST_SUPPLEMENTAL === 'true' ? 'layout-evidence.json' : 'browser-evidence.json';
    writeFileSync(resolve(root, `docs/${evidencePhase}`, target), JSON.stringify(record, null, 2) + '\n');
    process.stdout.write(JSON.stringify({ passed: record.passed, failed: record.failed, skipped: record.skipped }) + '\n');
  }
}
