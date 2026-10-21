# 🔒 SSL Checker

> SSL/TLS 证书检查工具 — 验证域名证书有效期 · 颁发机构 · 协议版本 · 加密套件

## ✨ 功能

| 功能 | 说明 |
|---|---|
| ✅ **证书验证** | 检查 SSL 证书是否有效、是否过期 |
| 📅 **有效期检查** | 显示生效日期、到期日期、剩余天数，30天内即将过期预警 |
| 🏛️ **颁发机构** | 显示证书颁发者（CA）、颁发给的组织信息 |
| 🌐 **SANs** | 列出证书涵盖的所有主题备用名称 |
| 🔌 **TLS 协议** | 检测 TLS 版本（TLS 1.2、1.3 等）和加密套件 |
| 🖨️ **指纹** | 显示 SHA-256 证书指纹 |
| 📋 **检查历史** | 最近检查的域名自动保存，一键重新检查 |

## 🛠 技术栈

- 前端：HTML5 + CSS3 + JavaScript
- 后端：Node.js (Vercel Serverless Function)
- TLS 检查：Node.js 内置 `tls` 模块
- 部署：Vercel

## 🚀 部署

```bash
# 安装 Vercel CLI
npm install -g vercel

# 部署
cd ssl-checker
vercel --prod
```

## 🔒 隐私

域名通过 API 发送到服务端以检查公开证书。应用不在服务端持久化查询；最近检查的域名保存在当前浏览器的 localStorage，可通过“清空”删除。托管平台的日志与数据处理以其配置和隐私政策为准。

## Verification

The API accepts bare public DNS hostnames (including IDNs), not URLs, IP literals,
credentials, paths, or custom ports. It checks every DNS answer before connecting
to one validated literal address on port 443 (preferring IPv4), preserving the
hostname for SNI and certificate identity verification. DNS and TLS share a
ten-second deadline.

Address policy uses Node's `net.BlockList` with the IANA special-purpose IPv4 and
IPv6 registries. It intentionally blocks special-purpose public exceptions too;
IPv6 must be ordinary global unicast in `2000::/3`, outside special-purpose ranges.
Review the registry lists when maintaining this policy:
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and
[IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/).

Invalid certificates remain inspectable. `valid` requires Node's TLS authorization,
an explicit hostname match, and current validity dates. The API returns validation
error codes separately from certificate details. This is one connection from the
server's network, not a revocation check, browser-specific trust guarantee, complete
multi-address availability test, or full TLS security audit.

`vercel.json` explicitly maps `/api/check` (also `/api/check.js`, with optional
trailing slash) to `/api/check.js`. Root and Chinese pages have explicit mappings.
The routing tests check local configuration, not deployed Vercel behavior; verify
the extensionless POST endpoint after the parent-reviewed deployment.

### Tests

Node 22+; no application dependencies or package installation are needed:

```sh
node --test test/check.test.js test/routing.test.js
```

Browser regression tests require an existing Playwright installation and Chrome.
They start and stop a loopback test server, run the actual handler with mocked
DNS/TLS, and block external browser requests (including ads and analytics):

```sh
PLAYWRIGHT_MODULE_PATH=/absolute/path/to/node_modules/playwright node --test test/browser.cjs
```

Set `SSL_SCREENSHOTS` to a local output directory to retain desktop/mobile EN/ZH
screenshots. The tests do not probe public or private TLS endpoints.

## 📄 许可

MIT
