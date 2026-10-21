const tls = require('tls');
const dns = require('dns').promises;
const net = require('net');
const { domainToASCII } = require('url');

const CHECK_TIMEOUT_MS = 10000;
const DAY_MS = 86400000;
const reserved = new net.BlockList();
// Conservatively exclude all IANA special-purpose ranges, including public exceptions.
// https://www.iana.org/assignments/iana-ipv4-special-registry/
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.31.196.0', 24], ['192.52.193.0', 24], ['192.88.99.0', 24],
  ['192.168.0.0', 16], ['192.175.48.0', 24], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) reserved.addSubnet(address, prefix, 'ipv4');

// Only ordinary global-unicast IPv6 is eligible; translation/tunnel ranges stay blocked.
// https://www.iana.org/assignments/iana-ipv6-special-registry/
const globalIPv6 = new net.BlockList();
globalIPv6.addSubnet('2000::', 3, 'ipv6');
for (const [address, prefix] of [
  ['2001::', 23], ['2001:db8::', 32], ['2002::', 16],
  ['2620:4f:8000::', 48], ['3fff::', 20],
]) reserved.addSubnet(address, prefix, 'ipv6');

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return res.status(405).json({ errorCode: 'METHOD_NOT_ALLOWED', error: 'Method not allowed' });
  }

  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string') {
    return res.status(400).json({ errorCode: 'DOMAIN_REQUIRED', error: 'Domain is required' });
  }

  const hostname = normalizeHostname(domain);
  if (!hostname) {
    return res.status(400).json({ errorCode: 'INVALID_DOMAIN', error: 'Invalid domain format' });
  }

  try {
    const deadline = Date.now() + CHECK_TIMEOUT_MS;
    const address = await resolvePublicHostname(hostname, deadline);
    const result = await checkSSL(hostname, address, deadline);
    res.status(200).json(result);
  } catch (err) {
    const errorCode = err.code === 'PRIVATE_ADDRESS' ? 'PRIVATE_ADDRESS' : 'CHECK_FAILED';
    res.status(200).json({ errorCode, error: err.message });
  }
};

function normalizeHostname(domain) {
  const input = domain.trim();
  // Accept a bare DNS hostname only, never silently discard URL credentials/ports/paths.
  if (!input || input.length > 1024 || /[\s\x00-\x1f\x7f/:@?#%\\\[\]]/.test(input)) return null;
  const hostname = domainToASCII(input).toLowerCase().replace(/\.$/, '');
  const labels = hostname.split('.');
  if (!hostname || hostname.length > 253 || labels.length < 2 || net.isIP(hostname)) return null;
  if (!/[a-z]/.test(labels.at(-1))) return null;
  if (labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
  return hostname;
}

async function resolvePublicHostname(hostname, deadline) {
  let timeout;
  let addresses;
  try {
    addresses = await Promise.race([
      dns.lookup(hostname, { all: true, verbatim: true }),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error('DNS lookup timed out')), Math.max(1, deadline - Date.now()));
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    const error = new Error('Only publicly routable domains can be checked');
    error.code = 'PRIVATE_ADDRESS';
    throw error;
  }
  return (addresses.find(({ address }) => net.isIPv4(address)) || addresses[0]).address;
}

function isPublicAddress(address) {
  const version = net.isIP(address);
  if (version === 4) return !reserved.check(address, 'ipv4');
  if (version === 6 && !address.includes('%')) {
    return globalIPv6.check(address, 'ipv6') && !reserved.check(address, 'ipv6');
  }
  return false;
}

function checkSSL(hostname, address, deadline) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    if (startTime >= deadline) return reject(new Error('Check timed out after 10 seconds'));
    // Pin the validated literal address. SNI and identity checks still use the hostname.
    const socket = tls.connect({
      port: 443,
      host: address,
      servername: hostname,
      // Inspect invalid certificates too, but never equate inspection with validation.
      rejectUnauthorized: false,
    });
    let settled = false;
    const timeout = setTimeout(() => finish(new Error('Check timed out after 10 seconds')), deadline - startTime);
    function finish(error, result) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.destroy();
      if (error) reject(error);
      else resolve(result);
    }

    socket.once('secureConnect', () => {
      if (settled) return;
      try {
        const cert = socket.getPeerCertificate(true);
        if (!cert || !Object.keys(cert).length) throw new Error('No peer certificate received');
        const cipher = socket.getCipher() || {};
        const protocol = socket.getProtocol();

        const now = Date.now();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        if (!Number.isFinite(validFrom.getTime()) || !Number.isFinite(validTo.getTime()) || validFrom > validTo) {
          throw new Error('Certificate validity dates are missing or invalid');
        }
        const daysRemaining = Math.floor((validTo - now) / DAY_MS);
        const expired = validTo.getTime() <= now;
        const notYetValid = validFrom.getTime() > now;
        const identityError = tls.checkServerIdentity(hostname, cert);
        const authorized = socket.authorized === true;
        const validationErrors = [];
        if (!authorized) validationErrors.push(String(socket.authorizationError?.code || socket.authorizationError || 'UNTRUSTED_CERTIFICATE'));
        if (identityError) validationErrors.push(identityError.code || 'ERR_TLS_CERT_ALTNAME_INVALID');
        if (expired) validationErrors.push('CERT_HAS_EXPIRED');
        if (notYetValid) validationErrors.push('CERT_NOT_YET_VALID');
        const valid = authorized && !identityError && !expired && !notYetValid;

        // Parse subject
        const subject = parseDN(cert.subject || {});
        const issuer = parseDN(cert.issuer || {});

        // SANs
        const sans = [];
        if (cert.subjectaltname) {
          const parts = cert.subjectaltname.split(', ');
          parts.forEach(p => {
            if (p.startsWith('DNS:')) sans.push(p.substring(4));
            // Skip 'IP Address:' entries for cleanliness
          });
        }

        // Certificate chain info
        const chainLength = getChainLength(cert);

        // Check if it's a wildcard cert
        const isWildcard = Boolean(subject.commonName?.startsWith('*.') || sans.some(name => name.startsWith('*.')));

        // Signature algorithm
        const sigAlg = cert.sigalg || 'N/A';

        finish(null, {
          domain: hostname,
          valid,
          daysRemaining,
          expired,
          notYetValid,
          expiresSoon: valid && validTo - now <= 30 * DAY_MS,
          validation: {
            authorized,
            hostnameMatches: !identityError,
            errors: [...new Set(validationErrors)],
          },
          details: {
            subject: subject,
            issuer: issuer,
            validFrom: validFrom.toISOString(),
            validTo: validTo.toISOString(),
            daysRemaining: daysRemaining,
            serialNumber: cert.serialNumber || 'N/A',
            fingerprint: cert.fingerprint || 'N/A',
            fingerprint256: cert.fingerprint256 || 'N/A',
            signatureAlgorithm: sigAlg,
            publicKey: cert.bits ? `${cert.bits} bits${cert.asn1Curve ? ` (${cert.asn1Curve})` : ''}` : 'N/A',
          },
          connection: {
            protocol: protocol,
            cipherName: cipher.name || 'N/A',
            cipherVersion: cipher.version || 'N/A',
            tlsVersion: protocol,
          },
          sans: sans,
          chainLength: chainLength,
          isWildcard: isWildcard,
          responseTime: Date.now() - startTime,
        });
      } catch (error) {
        finish(error);
      }
    });

    socket.on('error', finish);
    socket.once('close', () => finish(new Error('Connection closed before TLS handshake completed')));
  });
}

function parseDN(dn) {
  const result = {};
  const map = {
    'C': 'country',
    'ST': 'state',
    'L': 'locality',
    'O': 'organization',
    'OU': 'organizationalUnit',
    'CN': 'commonName',
    'emailAddress': 'email',
  };
  for (const [key, val] of Object.entries(dn)) {
    const name = map[key] || key;
    result[name] = typeof val === 'string' ? val : String(val);
  }
  return result;
}

function getChainLength(cert) {
  let current = cert;
  let length = 0;
  const seen = new Set();
  while (current) {
    if (seen.has(current)) break;
    seen.add(current);
    length += 1;
    if (!current.issuerCertificate || current.issuerCertificate === current) break;
    current = current.issuerCertificate;
  }
  return Math.max(1, length);
}
