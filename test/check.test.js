const { test, beforeEach, afterEach, mock } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const dns = require('node:dns').promises;
const tls = require('node:tls');
const handler = require('../api/check');

const NOW = Date.parse('2026-10-20T12:00:00Z');
let certificate;
let socket;
let lookup;
let connect;
let event;

beforeEach(() => {
  mock.method(Date, 'now', () => NOW);
  certificate = {
    subject: { CN: 'example.com' }, issuer: { O: 'Test CA' },
    subjectaltname: 'DNS:example.com, DNS:*.example.com',
    valid_from: '2026-10-01T00:00:00Z', valid_to: '2027-10-01T00:00:00Z',
    serialNumber: '01', fingerprint256: 'AA:BB', bits: 2048,
  };
  socket = new EventEmitter();
  socket.authorized = true;
  socket.getPeerCertificate = () => certificate;
  socket.getCipher = () => ({ name: 'TLS_AES_256_GCM_SHA384', version: 'TLSv1.3' });
  socket.getProtocol = () => 'TLSv1.3';
  socket.destroy = mock.fn(() => socket.emit('close'));
  event = () => socket.emit('secureConnect');
  lookup = mock.method(dns, 'lookup', async () => [{ address: '93.184.216.34', family: 4 }]);
  connect = mock.method(tls, 'connect', () => {
    queueMicrotask(() => event());
    return socket;
  });
});

afterEach(() => mock.restoreAll());

async function request(body = { domain: 'example.com' }, method = 'POST') {
  const response = {
    headers: {}, writes: 0,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; this.writes++; return this; },
    end() { this.writes++; },
  };
  await handler({ method, body }, response);
  assert.equal(response.writes, 1);
  assert.equal(response.headers['Cache-Control'], 'no-store');
  return response;
}

test('POST pins the checked address, retains SNI, and verifies a trusted certificate', async () => {
  const response = await request({ domain: ' Example.COM. ' });
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.domain, 'example.com');
  assert.equal(response.body.valid, true);
  assert.equal(response.body.isWildcard, true);
  assert.equal(response.body.details.publicKey, '2048 bits');
  assert.equal(response.body.details.validTo, '2027-10-01T00:00:00.000Z');
  assert.deepEqual(response.body.validation, { authorized: true, hostnameMatches: true, errors: [] });
  assert.equal(lookup.mock.callCount(), 1);
  assert.deepEqual(lookup.mock.calls[0].arguments, ['example.com', { all: true, verbatim: true }]);
  assert.deepEqual(connect.mock.calls[0].arguments, [{
    port: 443, host: '93.184.216.34', servername: 'example.com', rejectUnauthorized: false,
  }]);
  assert.equal(socket.destroy.mock.callCount(), 1);
});

test('a second DNS answer cannot rebind TLS to a private address', async () => {
  lookup.mock.mockImplementationOnce(async () => [{ address: '93.184.216.34', family: 4 }]);
  lookup.mock.mockImplementation(async () => [{ address: '127.0.0.1', family: 4 }]);
  assert.equal((await request()).body.valid, true);
  assert.equal(lookup.mock.callCount(), 1);
  assert.equal(connect.mock.calls[0].arguments[0].host, '93.184.216.34');
});

test('IDN hostnames are normalized using the standard URL implementation', async () => {
  certificate.subjectaltname = 'DNS:xn--bcher-kva.example';
  const response = await request({ domain: 'b\u00fccher.example' });
  assert.equal(response.body.domain, 'xn--bcher-kva.example');
  assert.equal(response.body.valid, true);
});

for (const method of ['GET', 'PUT', 'DELETE', 'OPTIONS']) {
  test(`${method} does not perform DNS or TLS work`, async () => {
    const response = await request(undefined, method);
    assert.equal(response.statusCode, method === 'OPTIONS' ? 200 : 405);
    if (method !== 'OPTIONS') assert.equal(response.headers.Allow, 'POST, OPTIONS');
    assert.equal(lookup.mock.callCount(), 0);
    assert.equal(connect.mock.callCount(), 0);
  });
}

for (const domain of [undefined, null, '', 123, [], {}]) {
  test(`missing or non-string domain: ${JSON.stringify(domain)}`, async () => {
    const response = await request({ domain });
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.errorCode, 'DOMAIN_REQUIRED');
    assert.equal(lookup.mock.callCount(), 0);
  });
}

for (const domain of [
  ' ', 'localhost', '127.0.0.1', '127.1', '2130706433', '0x7f000001',
  '0177.0.0.1', '0x7f.0.0.1', '::1', '[::1]', 'example.123',
  'https://example.com', 'example.com:443', 'example.com/path', 'user@example.com',
  'example.com?x=1', 'example.com#x', 'example.com\\path', 'example%2ecom',
  'example.com\u0000', 'ex ample.com', '-bad.example', 'bad-.example', '_srv.example',
  '.example.com', 'example..com', 'example.com..', '*.example.com',
  `${'a'.repeat(64)}.com`, `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(63)}`,
]) {
  test(`rejects malformed/non-hostname input: ${JSON.stringify(domain)}`, async () => {
    const response = await request({ domain });
    assert.equal(response.statusCode, 400);
    assert.equal(response.body.errorCode, 'INVALID_DOMAIN');
    assert.equal(lookup.mock.callCount(), 0);
    assert.equal(connect.mock.callCount(), 0);
  });
}

for (const address of [
  '0.0.0.0', '0.1.2.3', '10.255.255.255', '100.64.0.1', '100.127.255.255',
  '127.0.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255',
  '192.0.0.8', '192.0.0.170', '192.0.2.1', '192.31.196.1', '192.52.193.1',
  '192.88.99.1', '192.168.1.1', '192.175.48.1', '198.18.0.1', '198.19.255.255',
  '198.51.100.1', '203.0.113.1', '224.0.0.1', '239.255.255.255', '240.0.0.1',
  '255.255.255.255', '::', '::1', '0:0:0:0:0:0:0:1', '::127.0.0.1',
  '::ffff:127.0.0.1', '0:0:0:0:0:ffff:7f00:1', '::ffff:8.8.8.8',
  '64:ff9b::7f00:1', '64:ff9b:1::a00:1', '100::1', '100:0:0:1::1',
  '2001::1', '2001:2::1', '2001:20::1', '2001:db8::1', '2001:0db8:0:0:0:0:0:1',
  '2002:7f00:1::1', '2620:4f:8000::1', '3fff::1', '3fff:fff::1', '5f00::1',
  'fc00::1', 'FD00::1', 'fe80::1', 'fe80::1%eth0', 'fec0::1', 'ff02::1',
  '4000::1', 'not-an-ip', '8.8.8.999', '2001:4860::1%eth0',
]) {
  test(`blocks special-use/reserved/invalid DNS result: ${address}`, async () => {
    lookup.mock.mockImplementation(async () => [{ address }]);
    const response = await request();
    assert.equal(response.body.errorCode, 'PRIVATE_ADDRESS');
    assert.equal(connect.mock.callCount(), 0);
  });
}

for (const address of ['8.8.8.8', '192.0.1.1', '172.32.0.1', '100.128.0.1', '2001:4860:4860::8888', '2606:4700:4700::1111']) {
  test(`allows ordinary public address: ${address}`, async () => {
    lookup.mock.mockImplementation(async () => [{ address }]);
    assert.equal((await request()).body.valid, true);
    assert.equal(connect.mock.calls[0].arguments[0].host, address);
  });
}

test('rejects mixed public/private DNS results before any connection', async () => {
  lookup.mock.mockImplementation(async () => [{ address: '8.8.8.8' }, { address: '::1' }]);
  assert.equal((await request()).body.errorCode, 'PRIVATE_ADDRESS');
  assert.equal(connect.mock.callCount(), 0);
});

test('prefers the first validated IPv4 address when IPv6 appears first', async () => {
  lookup.mock.mockImplementation(async () => [
    { address: '2606:4700:4700::1111', family: 6 },
    { address: '93.184.216.34', family: 4 },
    { address: '8.8.8.8', family: 4 },
  ]);
  assert.equal((await request()).body.valid, true);
  assert.equal(connect.mock.calls[0].arguments[0].host, '93.184.216.34');
  assert.equal(lookup.mock.callCount(), 1);
});

test('rejects empty DNS results', async () => {
  lookup.mock.mockImplementation(async () => []);
  assert.equal((await request()).body.errorCode, 'PRIVATE_ADDRESS');
  assert.equal(connect.mock.callCount(), 0);
});

for (const code of ['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE']) {
  test(`never labels ${code} as valid`, async () => {
    socket.authorized = false;
    socket.authorizationError = code;
    const { body } = await request();
    assert.equal(body.valid, false);
    assert.equal(body.expired, false);
    assert.equal(body.expiresSoon, false);
    assert.equal(body.validation.hostnameMatches, true);
    assert.ok(body.validation.errors.includes(code));
  });
}

test('explicit identity verification catches a wrong hostname even on an authorized mock socket', async () => {
  certificate.subjectaltname = 'DNS:wrong.example';
  const { body } = await request();
  assert.equal(body.valid, false);
  assert.equal(body.validation.hostnameMatches, false);
  assert.ok(body.validation.errors.includes('ERR_TLS_CERT_ALTNAME_INVALID'));
});

test('identity verification still runs for an untrusted chain', async () => {
  socket.authorized = false;
  socket.authorizationError = 'DEPTH_ZERO_SELF_SIGNED_CERT';
  certificate.subjectaltname = 'DNS:wrong.example';
  const { body } = await request();
  assert.equal(body.validation.errors.length, 2);
  assert.equal(body.valid, false);
});

test('undefined authorization fails closed', async () => {
  delete socket.authorized;
  assert.equal((await request()).body.valid, false);
});

for (const offset of [-1000, 0, 1000, 86400000, 30 * 86400000, 30 * 86400000 + 1]) {
  test(`expiry uses exact timestamps at offset ${offset}ms`, async () => {
    certificate.valid_to = new Date(NOW + offset).toISOString();
    const { body } = await request();
    assert.equal(body.expired, offset <= 0);
    assert.equal(body.valid, offset > 0);
    assert.equal(body.expiresSoon, offset > 0 && offset <= 30 * 86400000);
    assert.equal(body.daysRemaining, Math.floor(offset / 86400000));
  });
}

test('future notBefore prevents valid status', async () => {
  certificate.valid_from = new Date(NOW + 1000).toISOString();
  const { body } = await request();
  assert.equal(body.valid, false);
  assert.equal(body.notYetValid, true);
  assert.ok(body.validation.errors.includes('CERT_NOT_YET_VALID'));
});

test('counts issuer chains with repeated serial numbers and terminates cycles', async () => {
  certificate.issuerCertificate = { serialNumber: '01' };
  certificate.issuerCertificate.issuerCertificate = certificate;
  assert.equal((await request()).body.chainLength, 2);
});

for (const cert of [{}, null, { valid_from: 'bad', valid_to: 'bad' }, { valid_from: '2027-01-01', valid_to: '2026-01-01' }]) {
  test(`handles missing/malformed certificate: ${JSON.stringify(cert)}`, async () => {
    certificate = cert;
    assert.equal((await request()).body.errorCode, 'CHECK_FAILED');
    assert.equal(socket.destroy.mock.callCount(), 1);
  });
}

test('certificate extraction exceptions settle and destroy the socket', async () => {
  socket.getPeerCertificate = () => { throw new Error('certificate read failed'); };
  assert.equal((await request()).body.errorCode, 'CHECK_FAILED');
  assert.equal(socket.destroy.mock.callCount(), 1);
});

test('DNS failure returns a structured error without connecting', async () => {
  lookup.mock.mockImplementation(async () => { throw new Error('ENOTFOUND'); });
  assert.equal((await request()).body.errorCode, 'CHECK_FAILED');
  assert.equal(connect.mock.callCount(), 0);
});

test('synchronous TLS connection failure is handled', async () => {
  connect.mock.mockImplementation(() => { throw new Error('connect failed'); });
  assert.equal((await request()).body.errorCode, 'CHECK_FAILED');
});

test('early close settles instead of leaving the handler pending', { timeout: 1000 }, async () => {
  event = () => socket.emit('close');
  const { body } = await request();
  assert.equal(body.errorCode, 'CHECK_FAILED');
  assert.match(body.error, /closed before TLS handshake/);
  assert.equal(socket.destroy.mock.callCount(), 1);
});

test('socket errors settle once, including late error/close/secureConnect events', async () => {
  event = () => {
    socket.emit('error', new Error('ECONNRESET'));
    socket.emit('error', new Error('late error'));
    socket.emit('secureConnect');
    socket.emit('close');
  };
  assert.equal((await request()).body.errorCode, 'CHECK_FAILED');
  assert.equal(socket.destroy.mock.callCount(), 1);
});

test('DNS deadline settles and ignores a late answer', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let resolveDNS;
  lookup.mock.mockImplementation(() => new Promise(resolve => { resolveDNS = resolve; }));
  const pending = request();
  t.mock.timers.tick(10000);
  assert.equal((await pending).body.errorCode, 'CHECK_FAILED');
  resolveDNS([{ address: '8.8.8.8' }]);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(connect.mock.callCount(), 0);
});

test('TLS deadline destroys a stalled socket', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  event = () => {};
  const pending = request();
  await new Promise(resolve => setImmediate(resolve));
  t.mock.timers.tick(10000);
  assert.equal((await pending).body.errorCode, 'CHECK_FAILED');
  assert.equal(socket.destroy.mock.callCount(), 1);
});

test('DNS and TLS share the same ten-second budget', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  lookup.mock.mockImplementation(async () => {
    Date.now.mock.mockImplementation(() => NOW + 9000);
    return [{ address: '8.8.8.8' }];
  });
  event = () => {};
  const pending = request();
  await new Promise(resolve => setImmediate(resolve));
  t.mock.timers.tick(1000);
  assert.equal((await pending).body.errorCode, 'CHECK_FAILED');
  assert.equal(socket.destroy.mock.callCount(), 1);
});
