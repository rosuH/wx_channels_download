# wx_channels_download 源码审计 Handoff

> 审计日期: 2026-04-27
> 审计范围: 全量 Go 源码 + 配置文件 + CI/CD 流程
> 原始仓库: https://github.com/ltaoo/wx_channels_download

---

## 1. 项目概述

这是一个**微信视频号下载工具**，通过本地 HTTPS 代理拦截微信 PC 端网页流量，注入 JS 脚本添加下载按钮，截获加密视频流并下载解密。

**工作原理:**
1. 启动本地代理服务器 (`127.0.0.1:2023`)
2. 自动安装自签名 CA 证书到系统信任库
3. 修改系统代理，将微信网页版流量导入本地代理
4. 拦截并修改 `channels.weixin.qq.com` / `res.wx.qq.com` 的响应
5. 注入下载按钮和下载逻辑
6. 多线程下载视频，ISAAC64 算法解密

---

## 2. 源码审计结果

### 2.1 未发现明显恶意行为 ✅

| 检查项 | 结果 | 说明 |
|--------|------|------|
| 隐蔽数据上报/遥测 | ❌ 未发现 | 无第三方统计、无用户行为追踪 |
| 窃取 Cookie/Token 外传 | ❌ 未发现 | 微信凭证仅本地代理转发使用 |
| 键盘记录/屏幕监控 | ❌ 未发现 | |
| 加密货币挖矿 | ❌ 未发现 | |
| 勒索/文件加密 | ❌ 未发现 | |
| 后门/远程控制 | ❌ 未发现 | |

### 2.2 网络通信全量审计

代码中所有对外 HTTP 请求分类：

| 目标 | 触发条件 | 用途 |
|------|---------|------|
| `api.github.com` | `update` 命令 | 检查版本、下载 Release 更新包 |
| `api.cloudflare.com` | `deploy` 命令 | 部署 Cloudflare Worker（需手动配置 Token） |
| `*.weixin.qq.com` | 运行时 | 视频号 API、文件传输助手登录同步 |
| `127.0.0.1:2022/2023` | 运行时 | 本地 Web 管理界面 + 代理服务 |

**结论: 无隐蔽数据外传。**

### 2.3 高风险功能点

1. **MITM 代理 + CA 证书** → 详见第 3 节（核心风险）
2. **系统代理自动修改** → 程序崩溃可能残留代理配置
3. **前端 JS 注入** → 向微信网页注入脚本，理论上可窃取凭证（当前源码未滥用）
4. **Windows 版需管理员权限** → 用于安装证书和设置系统代理

---

## 3. CA 证书安全问题（核心风险）⚠️⚠️⚠️

### 3.1 证书是完全固定的

证书和私钥通过 `//go:embed` 编译进二进制：

```go
// pkg/certificate/certificate.go
//go:embed certs/SunnyRoot.cer
var cert_file []byte

//go:embed certs/private.key
var private_key_file []byte
```

- **所有用户、所有版本使用完全相同的 CA 证书和私钥**
- 私钥文件公开在仓库: `pkg/certificate/certs/private.key`
- 证书名: **SunnyNet**（国产 SunnyNet 抓包库的默认根证书）

### 3.2 证书详情

```
Issuer:  C=CN, ST=BeiJing, L=BeiJing, O=SunnyNet, OU=SunnyNet, CN=SunnyNet
Subject: C=CN, ST=BeiJing, L=BeiJing, O=SunnyNet, OU=SunnyNet, CN=SunnyNet
Validity: 2022-11-04 ~ 2122-10-11 (100年)
Serial:   01:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
Key:      RSA 2048-bit
CA:       TRUE
```

### 3.3 安全风险

由于**私钥是公开的**，任何人都能：
1. 从 GitHub 仓库下载 `private.key`
2. 用这把私钥签发任意域名的伪造证书（`*.bank.com`, `*.wechat.com` 等）
3. 如果用户系统信任了 SunnyNet CA，攻击者即可对该用户实施**完美的 HTTPS 中间人攻击**

**攻击场景:** 同一局域网内，攻击者知道这把私钥 → 伪造银行证书 → ARP/DNS 劫持 → 用户浏览器显示绿色小锁 → 密码/凭证全部暴露。

### 3.4 自定义证书支持（已存在）

好消息是源码**已支持自定义证书**，只是默认 fallback 到内嵌证书：

**配置项** (`config.template.yaml`):
```yaml
cert:
  file: ""      # 自定义证书绝对路径
  key: ""       # 自定义私钥绝对路径
  name: "Echo"  # 自定义证书名称
```

**加载优先级** (`internal/config/config.go` → `LoadCertFiles()`):
1. 查找用户本地的 mitmproxy 证书 (`~/.mitmproxy/`)
2. 查找配置的自定义证书 (`cert.file` + `cert.key`)
3. fallback 到内嵌的 SunnyNet 默认证书

### 3.5 建议修复方案

**方案 A（最简单）: 替换证书文件**

Fork 后重新生成唯一 CA 证书对，替换 `pkg/certificate/certs/` 下的两个文件：

```bash
openssl genrsa -out pkg/certificate/certs/private.key 2048
openssl req -new -x509 -key pkg/certificate/certs/private.key \
  -out pkg/certificate/certs/SunnyRoot.cer \
  -days 3650 \
  -subj "/C=CN/ST=YourCity/L=YourCity/O=YourName/OU=YourName/CN=WxChannelsProxyCA"
```

**方案 B（更安全）: 编译时动态生成**

修改 `certificate.go`，在 `init()` 或首次运行时动态生成唯一 CA 证书对，避免私钥出现在仓库中。

---

## 4. GitHub Actions 构建可行性

### 4.1 结论: ✅ 完全可行

项目已有成熟的 CI/CD 配置：
- `.github/workflows/release.yml` —— GitHub Actions 工作流
- `.goreleaser.yaml` —— GoReleaser 跨平台构建配置

### 4.2 Fork 后需要修改的事项

#### (1) 去掉 macOS 代码签名（必须）

原仓库使用 `rcodesign` 进行 macOS 代码签名和苹果公证，需要 Secrets：
- `MAC_CERT_P12` / `MAC_CERT_PASSWORD`
- `NOTARY_PRIVATE_KEY` / `NOTARY_KEY_ID` / `NOTARY_ISSUER_ID`

Fork 后没有这些证书，构建会失败。

**修改 `.goreleaser.yaml`:**
删除/注释 macOS build 的 post hooks 签名步骤。

**修改 `.github/workflows/release.yml`:**
删除/注释以下步骤：
- `Install rcodesign`
- `Prepare secrets`
- `Create API key JSON for notarization`
- `Notarize macOS archives`

> 去掉签名后的 macOS 版本会被 Gatekeeper 拦截，需要用户右键"打开"放行。

#### (2) 关闭/调整 UPX 压缩（可选）

`.goreleaser.yaml` 中启用了 UPX，但 `ubuntu-latest` 默认没有 upx。GoReleaser 会跳过并报警告，不会中断构建。如需确保压缩，在 workflow 中加：
```yaml
- name: Install UPX
  run: sudo apt-get install -y upx
```
或直接 `enabled: false`。

#### (3) 修改自动更新指向（强烈建议）

`cmd/update.go` 中硬编码了原仓库：
```go
releases, err := fetch_releases("ltaoo/wx_channels_download")
```

Fork 后应改为指向自己的仓库，或禁用自动更新功能。

#### (4) 版本号注入（可选）

`main.go` 中 `AppVer = "260330"` 是硬编码。GoReleaser 已注入 `main.Mode=release`，建议同时注入版本号：
```yaml
ldflags:
  - -X main.AppVer={{.Version}}
  - -X main.Mode=release
```

### 4.3 触发构建

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions 自动编译并发布 Draft Release，包含：
- `wx_video_download_safe_v1.0.0_windows_x86_64.zip`
- `wx_video_download_v1.0.0_darwin_arm64.zip`
- `wx_video_download_v1.0.0_linux_x86_64.tar.gz`
- ...

---

## 5. 关键文件索引

| 文件路径 | 说明 |
|---------|------|
| `main.go` | 入口，版本号硬编码 |
| `cmd/root.go` | 主命令，代理/API 服务启动逻辑 |
| `cmd/update.go` | 自动更新，硬编码原仓库名 |
| `cmd/download.go` | CLI 下载命令 |
| `cmd/deploy.go` | Cloudflare Worker 部署 |
| `internal/interceptor/interceptor.go` | 代理拦截器核心 |
| `internal/interceptor/plugin.go` | 微信网页 JS 注入逻辑 |
| `internal/api/` | 本地 API 服务 (gin) |
| `internal/channels/client.go` | 视频号 WebSocket API 客户端 |
| `pkg/certificate/certificate.go` | CA 证书加载（内嵌固定证书） |
| `pkg/certificate/certs/SunnyRoot.cer` | **内嵌 CA 证书（公开）** |
| `pkg/certificate/certs/private.key` | **内嵌 CA 私钥（公开）⚠️** |
| `pkg/decrypt/decrypt.go` | ISAAC64 视频解密算法 |
| `pkg/download/download.go` | 多线程下载器 |
| `pkg/filehelper/filehelper.go` | 微信文件传输助手自动登录/同步 |
| `internal/config/config.go` | 配置加载，含 `LoadCertFiles()` |
| `internal/config/config.template.yaml` | 默认配置模板 |
| `.goreleaser.yaml` | 跨平台构建配置 |
| `.github/workflows/release.yml` | GitHub Actions Release 工作流 |
| `pkg/gopeed/` | 本地替换的下载库（需审计） |

---

## 6. 后续 TODO 清单

- [ ] **替换 CA 证书**: 重新生成唯一 CA 证书对，替换 `pkg/certificate/certs/*`
- [ ] **修改 update.go**: 将 `ltaoo/wx_channels_download` 改为 fork 后的仓库名
- [ ] **简化 release.yml**: 去掉 macOS 代码签名/公证相关步骤
- [ ] **简化 .goreleaser.yaml**: 去掉 macOS 签名 post hook
- [ ] **版本号注入**: 让 GoReleaser 通过 ldflags 注入 `main.AppVer`
- [ ] **审计 pkg/gopeed**: 这是本地替换的下载库，需确认无额外风险
- [ ] **可选: 编译时动态生成证书**: 避免私钥出现在仓库中
- [ ] **可选: 禁用自动更新**: 如需完全控制分发渠道
- [ ] **可选: 配置模板调整**: 默认 `cert.name` 从 "Echo" 改为自定义名称

---

## 7. 快速参考

**本地开发运行:**
```bash
go run main.go
# 或
CGO_ENABLED=0 go build -ldflags="-s -w -X main.Mode=release"
```

**交叉编译:**
```bash
# macOS
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w"

# Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w"

# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w"
```

**SunnyNet 版本（Windows 驱动级代理）:**
- 原仓库已注释掉相关构建
- 需要 CGO + MinGW，复杂度高，建议不启用
