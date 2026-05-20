const https = require('https');
const tls = require('tls');
const { URL } = require('url');

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { domain } = req.body || {};
  if (!domain || typeof domain !== 'string') {
    return res.status(400).json({ error: '请提供域名' });
  }

  // Clean domain
  let hostname = domain.trim().toLowerCase();
  // Remove protocol and path
  hostname = hostname.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

  if (!hostname || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i.test(hostname)) {
    return res.status(400).json({ error: '无效的域名格式' });
  }

  try {
    const result = await checkSSL(hostname);
    res.status(200).json(result);
  } catch (err) {
    res.status(200).json({ error: `SSL 检查失败: ${err.message}` });
  }
};

function checkSSL(hostname) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const socket = tls.connect(443, hostname, {
      servername: hostname,
      rejectUnauthorized: false,
    });

    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error('连接超时（10秒）'));
    }, 10000);

    socket.once('secureConnect', () => {
      clearTimeout(timeout);
      const cert = socket.getPeerCertificate(true);
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();

      const now = new Date();
      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

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
      const isWildcard = subject.commonName && subject.commonName.startsWith('*.');

      // Signature algorithm
      const sigAlg = cert.sigalg || 'N/A';

      socket.end();

      resolve({
        domain: hostname,
        valid: daysRemaining >= 0,
        daysRemaining: Math.max(-1, daysRemaining),
        expired: daysRemaining < 0,
        expiresSoon: daysRemaining >= 0 && daysRemaining <= 30,
        details: {
          subject: subject,
          issuer: issuer,
          validFrom: validFrom.toISOString().split('T')[0],
          validTo: validTo.toISOString().split('T')[0],
          daysRemaining: daysRemaining,
          serialNumber: cert.serialNumber || 'N/A',
          fingerprint: cert.fingerprint || 'N/A',
          fingerprint256: cert.fingerprint256 || 'N/A',
          signatureAlgorithm: sigAlg,
          publicKey: cert.pubkey ? getKeyBits(cert.pubkey) : 'N/A',
        },
        connection: {
          protocol: protocol,
          cipherName: cipher.name,
          cipherVersion: cipher.version,
          tlsVersion: protocol,
        },
        sans: sans,
        chainLength: chainLength,
        isWildcard: isWildcard,
        responseTime: Date.now() - startTime,
      });
    });

    socket.once('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    socket.once('close', () => {
      clearTimeout(timeout);
    });
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

function getChainLength(cert, depth = 0) {
  return depth + 1; // Simplified - we just know the leaf
}

function getKeyBits(pubKey) {
  // Try to determine key size from the public key DER
  try {
    const buf = Buffer.isBuffer(pubKey) ? pubKey : Buffer.from(pubKey);
    // Simple heuristic: larger buffer = larger key
    if (buf.length > 290) return '4096 bits';
    if (buf.length > 220) return '2048 bits';
    if (buf.length > 160) return '1024 bits';
    return `${buf.length * 8} bits (approx)`;
  } catch {
    return 'N/A';
  }
}
