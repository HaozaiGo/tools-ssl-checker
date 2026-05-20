/* === SSL Checker - App Logic === */

document.addEventListener('DOMContentLoaded', () => {
  initEnterKey();
  loadHistory();
  // Auto-check default domain
  checkSSL();
});

/* ---- Enter Key ---- */
function initEnterKey() {
  document.getElementById('domain-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') checkSSL();
  });
}

/* ---- History (localStorage) ---- */
function loadHistory() {
  const history = getHistory();
  const list = document.getElementById('history-list');
  if (history.length === 0) {
    list.innerHTML = '<span style="font-size:.78rem;color:var(--text-dim)">暂无检查记录</span>';
    return;
  }
  list.innerHTML = history.map(d => `<span class="history-item" onclick="checkDomain('${escapeAttr(d)}')">${escapeHtml(d)}</span>`).join('');
  document.getElementById('history-section').style.display = 'block';
}

function getHistory() {
  try {
    return JSON.parse(localStorage.getItem('ssl_history') || '[]');
  } catch { return []; }
}

function addToHistory(domain) {
  let history = getHistory().filter(d => d !== domain);
  history.unshift(domain);
  if (history.length > 10) history = history.slice(0, 10);
  localStorage.setItem('ssl_history', JSON.stringify(history));
}

function clearHistory() {
  localStorage.removeItem('ssl_history');
  loadHistory();
}

function checkDomain(domain) {
  document.getElementById('domain-input').value = domain;
  checkSSL();
}

/* ---- Main Check ---- */
async function checkSSL() {
  const domain = document.getElementById('domain-input').value.trim();
  if (!domain) {
    showToast('❌ 请输入域名');
    return;
  }

  // Show loading
  document.getElementById('loading-section').style.display = 'block';
  document.getElementById('result-section').style.display = 'none';
  document.getElementById('checking-domain').textContent = domain;

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();

    if (data.error) {
      renderError(data.error);
    } else {
      renderResult(data);
      addToHistory(domain);
      loadHistory();
    }
  } catch (err) {
    renderError(`连接服务器失败: ${err.message}`);
  } finally {
    document.getElementById('loading-section').style.display = 'none';
    document.getElementById('result-section').style.display = 'block';
  }
}

/* ---- Render Result ---- */
function renderResult(data) {
  const container = document.getElementById('result-section');
  const { details, connection, sans } = data;

  // Status badge
  let badgeClass = 'valid-badge';
  let statusText = '✅ 有效';
  if (data.expired) { badgeClass = 'expired-badge'; statusText = '❌ 已过期'; }
  else if (data.expiresSoon) { badgeClass = 'warning-badge'; statusText = '⚠️ 即将过期'; }

  const daysText = data.daysRemaining >= 0
    ? `<span class="${data.daysRemaining <= 30 ? 'expired' : ''}">${data.daysRemaining} 天</span>`
    : '<span class="expired">已过期</span>';

  let html = `
    <div class="result-header">
      <span class="status-badge ${badgeClass}">${statusText}</span>
      <span class="domain-display">${escapeHtml(data.domain)}</span>
      <span class="response-time">⚡ ${data.responseTime}ms</span>
    </div>

    <div>
      <div class="section-title">📋 证书信息</div>
      <div class="detail-grid">
        <div class="detail-item"><span class="detail-label">颁发给 (CN)</span><span class="detail-value">${escapeHtml(details.subject.commonName || 'N/A')}</span></div>
        <div class="detail-item"><span class="detail-label">颁发机构 (CA)</span><span class="detail-value">${escapeHtml(details.issuer.organization || details.issuer.commonName || 'N/A')}</span></div>
        <div class="detail-item"><span class="detail-label">组织</span><span class="detail-value">${escapeHtml(details.subject.organization || 'N/A')}</span></div>
        <div class="detail-item"><span class="detail-label">生效日期</span><span class="detail-value">${escapeHtml(details.validFrom)}</span></div>
        <div class="detail-item"><span class="detail-label">到期日期</span><span class="detail-value ${data.expired ? 'expired' : ''}">${escapeHtml(details.validTo)}</span></div>
        <div class="detail-item"><span class="detail-label">剩余天数</span><span class="detail-value">${daysText}</span></div>
        <div class="detail-item"><span class="detail-label">签名算法</span><span class="detail-value">${escapeHtml(details.signatureAlgorithm)}</span></div>
        <div class="detail-item"><span class="detail-label">公钥</span><span class="detail-value">${escapeHtml(details.publicKey)}</span></div>
        <div class="detail-item"><span class="detail-label">通配符证书</span><span class="detail-value">${data.isWildcard ? '✅ 是' : '否'}</span></div>
        <div class="detail-item"><span class="detail-label">序列号</span><span class="detail-value" style="font-size:.7rem">${escapeHtml(details.serialNumber)}</span></div>
      </div>
    </div>

    <div>
      <div class="section-title">🔌 连接信息</div>
      <div class="detail-grid">
        <div class="detail-item"><span class="detail-label">TLS 协议</span><span class="detail-value">${escapeHtml(connection.protocol)}</span></div>
        <div class="detail-item"><span class="detail-label">加密套件</span><span class="detail-value">${escapeHtml(connection.cipherName)}</span></div>
      </div>
    </div>`;

  // SANs
  if (sans && sans.length > 0) {
    html += `
    <div>
      <div class="section-title">🌐 主题备用名称 (SANs) — ${sans.length} 个</div>
      <div class="san-list">
        ${sans.map(s => `<span class="san-tag">${escapeHtml(s)}</span>`).join('')}
      </div>
    </div>`;
  }

  // Fingerprint
  html += `
    <div>
      <div class="section-title">🖨️ 指纹</div>
      <div class="detail-grid">
        <div class="detail-item" style="grid-column:1/-1"><span class="detail-label">SHA-256 指纹</span><span class="detail-value" style="font-size:.72rem;word-break:break-all">${escapeHtml(details.fingerprint256)}</span></div>
      </div>
    </div>`;

  container.innerHTML = html;
}

/* ---- Render Error ---- */
function renderError(msg) {
  document.getElementById('result-section').innerHTML = `
    <div class="error-section">
      <div style="font-size:1rem;margin-bottom:8px">❌ 检查失败</div>
      <div style="font-size:.85rem;color:var(--text-muted)">${escapeHtml(msg)}</div>
      <div style="margin-top:12px;font-size:.78rem;color:var(--text-dim)">可能的原因：域名不存在、无法连接、非标准的 SSL 端口</div>
    </div>`;
}

/* ---- Utilities ---- */
function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
function escapeAttr(s) {
  return s.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function showToast(msg) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, 2000);
}
