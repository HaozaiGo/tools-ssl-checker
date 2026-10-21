const { test, before, after, mock } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const dns = require('node:dns').promises;
const tls = require('node:tls');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE_PATH || 'playwright');
const handler = require('../api/check');
const config = require('../vercel.json');

let server;
let browser;
let origin;
let requests = 0;
const root = path.join(__dirname, '..');

before(async () => {
  // No DNS or TLS probes: browser requests use the real handler with network mocks.
  mock.method(dns, 'lookup', async hostname => [{
    address: hostname === 'private.example' ? '127.0.0.1' : '93.184.216.34', family: 4,
  }]);
  mock.method(tls, 'connect', options => {
    const name = options.servername;
    const now = Date.now();
    const socket = new EventEmitter();
    socket.authorized = name !== 'untrusted.example';
    socket.authorizationError = socket.authorized ? null : 'DEPTH_ZERO_SELF_SIGNED_CERT';
    socket.getPeerCertificate = () => ({
      subject: { CN: name }, issuer: { O: 'Test CA' },
      subjectaltname: `DNS:${name === 'wrong.example' ? 'different.example' : name}`,
      valid_from: new Date(now + (name === 'future.example' ? 86400000 : -86400000)).toISOString(),
      valid_to: new Date(now + (name === 'expired.example' ? -1000 : name === 'soon.example' ? 86400000 : 90 * 86400000)).toISOString(),
      serialNumber: '01', fingerprint256: 'AA:BB:CC', bits: 2048,
    });
    socket.getCipher = () => ({ name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1.3' });
    socket.getProtocol = () => 'TLSv1.3';
    socket.destroy = () => socket.emit('close');
    queueMicrotask(() => socket.emit(name === 'early.example' ? 'close' : 'secureConnect'));
    return socket;
  });
  server = http.createServer(async (req, res) => {
    try {
      const pathname = new URL(req.url, 'http://localhost').pathname;
      let destination;
      for (const route of config.routes) {
        const pattern = new RegExp(`^(?:${route.src})$`);
        if (pattern.test(pathname)) {
          destination = pathname.replace(pattern, route.dest);
          break;
        }
      }
      if (destination === '/api/check.js') {
        requests++;
        let body = '';
        for await (const chunk of req) body += chunk;
        req.body = JSON.parse(body || '{}');
        res.status = code => { res.statusCode = code; return res; };
        res.json = data => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(data)); };
        await handler(req, res);
        return;
      }
      const allowed = ['/index.html', '/zh/index.html', '/js/app.js', '/css/style.css'];
      if (!allowed.includes(destination)) { res.writeHead(404); res.end(); return; }
      res.setHeader('Content-Type', destination.endsWith('.js') ? 'text/javascript' : destination.endsWith('.css') ? 'text/css' : 'text/html');
      res.end(await fs.readFile(path.join(root, destination)));
    } catch (error) {
      res.writeHead(500);
      res.end(error.message);
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ channel: 'chrome', headless: true });
});

after(async () => {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
  mock.restoreAll();
});

async function openPage(locale, viewport) {
  const context = await browser.newContext({ viewport });
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) return route.abort();
    if (url.pathname.startsWith('/_vercel/')) return route.fulfill({ status: 200, body: '' });
    return route.continue();
  });
  const page = await context.newPage();
  await page.goto(`${origin}${locale === 'zh' ? '/zh/' : '/'}`);
  return { page, context };
}

async function submit(page, domain) {
  await page.locator('#domain-input').fill(domain);
  await page.locator('#domain-input').press('Enter');
  await page.waitForFunction(() => document.querySelector('#loading-section').style.display === 'none');
}

for (const locale of ['en', 'zh']) {
  for (const viewport of [{ width: 1280, height: 900 }, { width: 375, height: 812 }, { width: 320, height: 740 }]) {
    test(`${locale} at ${viewport.width}px: real handler flow, validation states, example and history`, async () => {
      const beforeRequests = requests;
      const { page, context } = await openPage(locale, viewport);
      try {
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        assert.equal(await page.locator('#domain-input').inputValue(), '');
        assert.equal(requests, beforeRequests, 'page load must not auto-check');
        await page.locator('.btn-secondary').click();
        assert.equal(await page.locator('#domain-input').inputValue(), 'example.com');
        assert.equal(requests, beforeRequests, 'Example must not auto-check');
        await page.locator('.btn-primary').click();
        await page.locator('.valid-badge').waitFor();
        assert.equal(await page.locator('.valid-badge').textContent(), locale === 'zh' ? '\u6709\u6548' : 'Valid');
        assert.match(await page.locator('#result-section').textContent(), /TLSv1.3/);
        for (const [domain, english, chinese, badge] of [
          ['untrusted.example', 'Validation failed', '\u9a8c\u8bc1\u5931\u8d25', '.error-badge'],
          ['wrong.example', 'Validation failed', '\u9a8c\u8bc1\u5931\u8d25', '.error-badge'],
          ['future.example', 'Not yet valid', '\u5c1a\u672a\u751f\u6548', '.error-badge'],
          ['expired.example', 'Expired', '\u5df2\u8fc7\u671f', '.expired-badge'],
          ['soon.example', 'Expires soon', '\u5373\u5c06\u8fc7\u671f', '.warning-badge'],
        ]) {
          await submit(page, domain);
          assert.equal(await page.locator(badge).textContent(), locale === 'zh' ? chinese : english);
          assert.equal(await page.locator('.valid-badge').count(), 0);
        }
        for (const domain of ['private.example', 'early.example', 'example.com:443']) {
          await submit(page, domain);
          assert.equal(await page.locator('.error-section').count(), 1);
          assert.equal(await page.locator('.valid-badge').count(), 0);
        }
        const privateHistory = await page.locator('.history-item').allTextContents();
        assert.ok(!privateHistory.includes('private.example'));
        await page.locator('.history-item', { hasText: 'example.com' }).click();
        await page.locator('.valid-badge').waitFor();
        assert.equal(await page.locator('.domain-display').textContent(), 'example.com');

        const longName = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.example.com`;
        await submit(page, longName);
        const overflows = await page.evaluate(() => {
          const selectors = ['.input-row input', '.input-row button', '.status-badge', '.domain-display', '.history-item', '.san-tag', '.detail-item'];
          return selectors.flatMap(selector => [...document.querySelectorAll(selector)]).filter(element => {
            const box = element.getBoundingClientRect();
            const clippedText = element.tagName !== 'INPUT' && element.scrollWidth > element.clientWidth + 1;
            return box.left < -1 || box.right > innerWidth + 1 || clippedText;
          }).map(element => element.className);
        });
        assert.deepEqual(overflows, []);
        if (process.env.SSL_SCREENSHOTS) {
          await fs.mkdir(process.env.SSL_SCREENSHOTS, { recursive: true });
          await page.screenshot({ path: path.join(process.env.SSL_SCREENSHOTS, `${locale}-${viewport.width}.png`), fullPage: true });
        }
        await page.locator('.history-header button').click();
        assert.equal(await page.locator('.history-item').count(), 0);
        assert.equal(await page.evaluate(() => localStorage.getItem('ssl_history')), null);
        assert.deepEqual(errors, []);
      } finally {
        await context.close();
      }
    });
  }
}

test('history cannot inject markup or inline JavaScript, and malformed storage is ignored', async () => {
  const { page, context } = await openPage('en', { width: 375, height: 812 });
  try {
    const payload = "');window.historyInjected=true;//<img src=x onerror=window.historyInjected=true>";
    await page.evaluate(value => localStorage.setItem('ssl_history', JSON.stringify([value, null, 3, {}])), payload);
    await page.reload();
    assert.equal(await page.locator('.history-item').count(), 1);
    assert.equal(await page.locator('.history-item').textContent(), payload);
    assert.equal(await page.locator('.history-item').getAttribute('onclick'), null);
    assert.equal(await page.locator('#history-list img').count(), 0);
    await page.locator('.history-item').click();
    await page.locator('.error-section').waitFor();
    assert.equal(await page.evaluate(() => window.historyInjected), undefined);
    for (const stored of ['{}', 'null', '"string"', 'broken-json']) {
      await page.evaluate(value => localStorage.setItem('ssl_history', value), stored);
      await page.reload();
      assert.equal(await page.locator('.history-item').count(), 0);
      await submit(page, 'example.com');
      assert.equal(await page.locator('.valid-badge').count(), 1);
    }
  } finally { await context.close(); }
});

test('blocked storage does not hide a successful result or break Clear', async () => {
  const { page, context } = await openPage('en', { width: 1280, height: 900 });
  try {
    await page.evaluate(() => {
      for (const name of ['getItem', 'setItem', 'removeItem']) {
        Storage.prototype[name] = () => { throw new DOMException('Storage disabled', 'SecurityError'); };
      }
    });
    await submit(page, 'example.com');
    assert.equal(await page.locator('.valid-badge').count(), 1);
    await page.locator('.history-header button').click();
    assert.equal(await page.locator('.valid-badge').count(), 1);
  } finally { await context.close(); }
});

test('HTTP errors are localized and older requests cannot overwrite newer results', async () => {
  const { page, context } = await openPage('zh', { width: 375, height: 812 });
  try {
    await page.route('**/api/check', route => route.fulfill({ status: 404, contentType: 'text/html', body: '<h1>Not Found</h1>' }));
    await submit(page, 'example.com');
    assert.match(await page.locator('.error-section').textContent(), /\u65e0\u6cd5\u8fde\u63a5\u68c0\u67e5\u670d\u52a1/);
    await page.unroute('**/api/check');
    await page.evaluate(() => {
      const originalFetch = window.fetch;
      window.fetch = (url, options) => {
        if (JSON.parse(options.body).domain === 'slow.example') {
          // Deliberately ignore AbortSignal to exercise the stale-response guard too.
          return new Promise(resolve => { window.finishOldRequest = () => resolve(new Response(JSON.stringify({ error: 'OLD_RESULT' }))); });
        }
        return originalFetch(url, options);
      };
    });
    await page.locator('#domain-input').fill('slow.example');
    await page.locator('#domain-input').press('Enter');
    await submit(page, 'example.com');
    await page.evaluate(() => window.finishOldRequest());
    assert.equal(await page.locator('.valid-badge').count(), 1);
    assert.equal(await page.locator('.domain-display').textContent(), 'example.com');
    assert.doesNotMatch(await page.locator('#result-section').textContent(), /OLD_RESULT/);
  } finally { await context.close(); }
});

test('client deadline settles a stalled fetch', async () => {
  const { page, context } = await openPage('en', { width: 375, height: 812 });
  try {
    await page.clock.install();
    await page.evaluate(() => {
      window.fetch = (_url, options) => new Promise((_, reject) => {
        options.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
      });
    });
    await page.locator('#domain-input').fill('example.com');
    await page.locator('#domain-input').press('Enter');
    await page.clock.fastForward(15000);
    await page.locator('.error-section').waitFor();
    assert.match(await page.locator('.error-section').textContent(), /check timed out/);
    assert.equal(await page.locator('#loading-section').isVisible(), false);
  } finally { await context.close(); }
});
