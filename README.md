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

域名通过加密 API 传输，仅用于 SSL 证书检查，不记录或存储。

## 📄 许可

MIT
