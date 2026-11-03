const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const config = require('../vercel.json');

function destination(url) {
  for (const route of config.routes) {
    const pattern = new RegExp(`^(?:${route.src})$`);
    if (pattern.test(url)) return url.replace(pattern, route.dest);
  }
}

for (const url of ['/api/check', '/api/check/', '/api/check.js', '/api/check.js/']) {
  test(`${url} explicitly maps to the deployed function, not an extensionless file`, () => {
    assert.equal(destination(url), '/api/check.js');
    assert.equal(config.builds.find(build => build.src === 'api/*.js').use, '@vercel/node');
  });
}

test('unrelated API paths do not map to the check handler', () => {
  for (const url of ['/api/check-other', '/api/check.js/extra', '/api/other']) {
    assert.notEqual(destination(url), '/api/check.js');
  }
});

for (const [url, file] of [
  ['/', '/index.html'], ['/zh', '/zh/index.html'], ['/zh/', '/zh/index.html'],
  ['/zh/index.html', '/zh/index.html'], ['/js/app.js', '/js/app.js'],
  ['/privacy-controls.js', '/privacy-controls.js'],
  ['/css/style.css', '/css/style.css'], ['/robots.txt', '/robots.txt'],
  ['/ads.txt', '/ads.txt'], ['/sitemap.xml', '/sitemap.xml'], ['/og.png', '/og.png'],
]) {
  test(`${url} resolves to an existing static asset`, () => {
    assert.equal(destination(url), file);
    assert.ok(fs.existsSync(path.join(__dirname, '..', file)));
    const built = config.builds.some(build => {
      if (build.use !== '@vercel/static') return false;
      const pattern = build.src.split('*').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
      return new RegExp(`^${pattern}$`).test(file.slice(1));
    });
    assert.ok(built, `${file} must be included in static build output`);
  });
}
