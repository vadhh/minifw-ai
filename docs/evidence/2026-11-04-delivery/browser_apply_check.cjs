// Reads lab credentials from stdin; never writes or prints them.
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

(async () => {
  const credentials = JSON.parse(fs.readFileSync(0, 'utf8'));
  const base = process.env.MINIFW_BROWSER_URL || 'https://127.0.0.1:18443';
  const browser = await chromium.launch({ headless: true, executablePath: process.env.MINIFW_BROWSER_EXECUTABLE });
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
    const response = await context.request.post(base + '/auth/login', { form: credentials });
    if (!response.ok()) throw new Error('Lab login failed: ' + response.status());
    const page = await context.newPage();
    await page.goto(base + '/admin/policy');
    const button = page.getByRole('button', { name: 'Apply saved changes', exact: true });
    await button.waitFor();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(__dirname, 'policy-desktop.png'), fullPage: false });
    await button.focus();
    await button.press('Enter');
    await page.waitForFunction(() => document.getElementById('apply-status').textContent.startsWith('Engine restarted'), null, { timeout: 20000 });
    const result = { candidate: 'C18', browser_version: browser.version(), apply_status: await page.locator('#apply-status').innerText(), desktop: { width: 1280, height: 900 } };
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: path.join(__dirname, 'policy-mobile.png'), fullPage: false });
    const bounds = await button.boundingBox();
    if (!bounds || bounds.x < 0 || bounds.x + bounds.width > 390) throw new Error('Apply button overflows mobile viewport');
    result.mobile = { width: 390, height: 844, apply_button_bounds: bounds };
    fs.writeFileSync(path.join(__dirname, 'browser-check.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
    await context.close();
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
