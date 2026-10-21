/* === SSL Checker - App Logic === */

const isZh = document.documentElement.lang.toLowerCase().startsWith('zh');
const copy = {
  noHistory: isZh ? '暂无检查记录' : 'No recent checks',
  domainRequired: isZh ? '请输入公开域名' : 'Enter a public domain',
  connectionFailed: isZh ? '无法连接检查服务' : 'Could not reach the check service',
  valid: isZh ? '有效' : 'Valid',
  invalid: isZh ? '验证失败' : 'Validation failed',
  notYetValid: isZh ? '尚未生效' : 'Not yet valid',
  validation: isZh ? '证书验证' : 'Certificate validation',
  trust: isZh ? '信任和身份验证' : 'Trust and identity verification',
  hostname: isZh ? '域名匹配' : 'Hostname match',
  passed: isZh ? '通过' : 'Passed',
  failed: isZh ? '未通过' : 'Failed',
  validationErrors: isZh ? '验证错误' : 'Validation errors',
  timeout: isZh ? '检查超时，请重试' : 'The check timed out. Please try again.',
  expired: isZh ? '已过期' : 'Expired',
  expiresSoon: isZh ? '即将过期' : 'Expires soon',
  days: isZh ? '天' : 'days',
  certificate: isZh ? '证书信息' : 'Certificate details',
  issuedTo: isZh ? '颁发给 (CN)' : 'Issued to (CN)',
  issuer: isZh ? '颁发机构 (CA)' : 'Issuer (CA)',
  organization: isZh ? '组织' : 'Organization',
  validFrom: isZh ? '生效日期' : 'Valid from',
  validTo: isZh ? '到期日期' : 'Valid to',
  remaining: isZh ? '剩余天数' : 'Days remaining',
  signature: isZh ? '签名算法' : 'Signature algorithm',
  publicKey: isZh ? '公钥' : 'Public key',
  wildcard: isZh ? '通配符证书' : 'Wildcard certificate',
  serial: isZh ? '序列号' : 'Serial number',
  yes: isZh ? '是' : 'Yes',
  no: isZh ? '否' : 'No',
  connection: isZh ? '连接信息' : 'Connection details',
  protocol: isZh ? 'TLS 协议' : 'TLS protocol',
  cipher: isZh ? '加密套件' : 'Cipher suite',
  sans: isZh ? '主题备用名称 (SANs)' : 'Subject alternative names (SANs)',
  fingerprint: isZh ? '指纹' : 'Fingerprint',
  checkFailed: isZh ? '检查失败' : 'Check failed',
  reasons: isZh
    ? '可能原因：域名不存在、443 端口不可达、证书配置异常或连接超时。'
    : 'Possible causes: the domain does not exist, port 443 is unreachable, the certificate is misconfigured, or the connection timed out.',
  invalidDomain: isZh ? '域名格式无效' : 'Invalid domain format',
  privateAddress: isZh ? '只能检查解析到公网地址的域名' : 'Only domains that resolve to public addresses can be checked',
  serverFailure: isZh ? '服务端无法完成 TLS 检查' : 'The server could not complete the TLS check'
};

document.addEventListener('DOMContentLoaded', () => {
  initEnterKey();
  loadHistory();
});

function initEnterKey() {
  document.getElementById('domain-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') checkSSL();
  });
}

function loadExample() {
  document.getElementById('domain-input').value = 'example.com';
  document.getElementById('domain-input').focus();
}

function loadHistory() {
  const history = getHistory();
  const list = document.getElementById('history-list');
  if (history.length === 0) {
    list.innerHTML = `<span style="font-size:.78rem;color:var(--text-dim)">${copy.noHistory}</span>`;
    return;
  }
  list.replaceChildren();
  history.forEach((domain) => {
    const button = document.createElement('button');
    button.className = 'history-item';
    button.type = 'button';
    button.textContent = domain;
    button.addEventListener('click', () => checkDomain(domain));
    list.appendChild(button);
  });
}

function getHistory() {
  try {
    const history = JSON.parse(localStorage.getItem('ssl_history') || '[]');
    return Array.isArray(history)
      ? history.filter(item => typeof item === 'string' && item.length > 0 && item.length <= 253).slice(0, 10)
      : [];
  } catch {
    return [];
  }
}

function addToHistory(domain) {
  let history = getHistory().filter((item) => item !== domain);
  history.unshift(domain);
  if (history.length > 10) history = history.slice(0, 10);
  try {
    localStorage.setItem('ssl_history', JSON.stringify(history));
  } catch {
    // Storage may be disabled or full; the certificate result remains usable.
  }
}

function clearHistory() {
  try {
    localStorage.removeItem('ssl_history');
  } catch {
    // Storage is optional.
  }
  loadHistory();
}

function checkDomain(domain) {
  document.getElementById('domain-input').value = domain;
  checkSSL();
}

let activeCheck = null;

async function checkSSL() {
  const domain = document.getElementById('domain-input').value.trim();
  if (!domain) {
    showToast(copy.domainRequired);
    return;
  }
  if (activeCheck) activeCheck.abort();
  const controller = new AbortController();
  activeCheck = controller;
  const timeout = setTimeout(() => controller.abort(), 15000);
  document.getElementById('loading-section').style.display = 'block';
  document.getElementById('result-section').style.display = 'none';
  document.getElementById('checking-domain').textContent = domain;

  try {
    const response = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
      signal: controller.signal
    });
    const data = await response.json().catch(() => null);
    if (activeCheck !== controller) return;
    if (!data || (!response.ok && !data.error)) throw new Error(copy.serverFailure);
    if (data.error) {
      renderError(localizeServerError(data));
    } else {
      renderResult(data);
      addToHistory(data.domain);
      loadHistory();
    }
  } catch (error) {
    if (activeCheck !== controller) return;
    renderError(error.name === 'AbortError' ? copy.timeout : copy.connectionFailed);
  } finally {
    clearTimeout(timeout);
    if (activeCheck === controller) {
      activeCheck = null;
      document.getElementById('loading-section').style.display = 'none';
      document.getElementById('result-section').style.display = 'flex';
    }
  }
}

function localizeServerError(data) {
  if (data.errorCode === 'DOMAIN_REQUIRED') return copy.domainRequired;
  if (data.errorCode === 'INVALID_DOMAIN') return copy.invalidDomain;
  if (data.errorCode === 'PRIVATE_ADDRESS') return copy.privateAddress;
  if (data.errorCode === 'CHECK_FAILED') return `${copy.serverFailure}: ${data.error}`;
  return data.error;
}

function renderResult(data) {
  const container = document.getElementById('result-section');
  const { details, connection, sans } = data;
  let badgeClass = 'valid-badge';
  let statusText = copy.valid;
  if (data.expired) {
    badgeClass = 'expired-badge';
    statusText = copy.expired;
  } else if (data.notYetValid) {
    badgeClass = 'error-badge';
    statusText = copy.notYetValid;
  } else if (data.valid !== true) {
    badgeClass = 'error-badge';
    statusText = copy.invalid;
  } else if (data.expiresSoon) {
    badgeClass = 'warning-badge';
    statusText = copy.expiresSoon;
  }
  const daysText = data.daysRemaining >= 0
    ? `<span class="${data.daysRemaining <= 30 ? 'expired' : ''}">${data.daysRemaining} ${copy.days}</span>`
    : `<span class="expired">${copy.expired}</span>`;

  let html = `
    <div class="result-header">
      <span class="status-badge ${badgeClass}">${statusText}</span>
      <span class="domain-display">${escapeHtml(data.domain)}</span>
      <span class="response-time">${escapeHtml(data.responseTime)} ms</span>
    </div>
    <div>
      <div class="section-title">${copy.validation}</div>
      <div class="detail-grid">
        ${detail(copy.trust, data.validation?.authorized === true ? copy.passed : copy.failed)}
        ${detail(copy.hostname, data.validation?.hostnameMatches === true ? copy.passed : copy.failed)}
        ${data.validation?.errors?.length ? detail(copy.validationErrors, data.validation.errors.join(', '), 'expired') : ''}
      </div>
    </div>
    <div>
      <div class="section-title">${copy.certificate}</div>
      <div class="detail-grid">
        ${detail(copy.issuedTo, details.subject.commonName || 'N/A')}
        ${detail(copy.issuer, details.issuer.organization || details.issuer.commonName || 'N/A')}
        ${detail(copy.organization, details.subject.organization || 'N/A')}
        ${detail(copy.validFrom, details.validFrom)}
        ${detail(copy.validTo, details.validTo, data.expired ? 'expired' : '')}
        <div class="detail-item"><span class="detail-label">${copy.remaining}</span><span class="detail-value">${daysText}</span></div>
        ${detail(copy.signature, details.signatureAlgorithm)}
        ${detail(copy.publicKey, details.publicKey)}
        ${detail(copy.wildcard, data.isWildcard ? copy.yes : copy.no)}
        ${detail(copy.serial, details.serialNumber, '', 'font-size:.7rem')}
      </div>
    </div>
    <div>
      <div class="section-title">${copy.connection}</div>
      <div class="detail-grid">${detail(copy.protocol, connection.protocol)}${detail(copy.cipher, connection.cipherName)}</div>
    </div>`;

  if (sans && sans.length > 0) {
    html += `<div><div class="section-title">${copy.sans} - ${sans.length}</div><div class="san-list">${sans.map((name) => `<span class="san-tag">${escapeHtml(name)}</span>`).join('')}</div></div>`;
  }
  html += `<div><div class="section-title">${copy.fingerprint}</div><div class="detail-grid">${detail('SHA-256', details.fingerprint256, '', 'font-size:.72rem;word-break:break-all')}</div></div>`;
  container.innerHTML = html;
}

function detail(label, value, className = '', style = '') {
  return `<div class="detail-item"><span class="detail-label">${escapeHtml(label)}</span><span class="detail-value ${className}"${style ? ` style="${style}"` : ''}>${escapeHtml(value)}</span></div>`;
}

function renderError(message) {
  document.getElementById('result-section').innerHTML = `
    <div class="error-section"><div style="font-size:1rem;margin-bottom:8px">${copy.checkFailed}</div>
    <div style="font-size:.85rem;color:var(--text-muted)">${escapeHtml(message)}</div>
    <div style="margin-top:12px;font-size:.78rem;color:var(--text-dim)">${copy.reasons}</div></div>`;
}

function escapeHtml(value) {
  const div = document.createElement('div');
  div.textContent = String(value);
  return div.innerHTML;
}

function showToast(message) {
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity .3s';
    setTimeout(() => toast.remove(), 300);
  }, 2000);
}
