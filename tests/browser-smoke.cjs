const { chromium } = require('playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const width of [390, 1440]) {
      const page = await browser.newPage({ viewport: { width, height: 900 } });
      const errors = [];
      page.on('pageerror', e => errors.push(e.message));
      const res = await page.goto('http://127.0.0.1:18880/', { waitUntil: 'domcontentloaded' });
      assert.equal(res.status(), 200);
      assert.match(await page.locator('h1').innerText(), /Suhoput local/);
      await page.goto('http://127.0.0.1:18880/?page_id=0');
      assert.equal(errors.length, 0, 'No browser JavaScript exceptions');
      await page.close();
    }
    console.log('PASS: desktop/mobile local WordPress smoke (theme scaffold only)');
  } finally { await browser.close(); }
})().catch(() => { console.error('FAIL: browser smoke; inspect local environment.'); process.exitCode = 1; });
