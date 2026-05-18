# Sienne-idp

[![Go](https://img.shields.io/badge/Go-1.26.3-00ADD8?logo=go&logoColor=white)](idp-server/go.mod)
[![Gin](https://img.shields.io/badge/Gin-1.12.0-008ECF?logo=gin&logoColor=white)](https://github.com/gin-gonic/gin)
[![MySQL](https://img.shields.io/badge/MySQL-8+-4479A1?logo=mysql&logoColor=white)](#项目结构)
[![Redis](https://img.shields.io/badge/Redis-7+-DC382D?logo=redis&logoColor=white)](#项目结构)
[![OAuth2](https://img.shields.io/badge/OAuth-2.0-2F2F2F?logo=oauth&logoColor=white)](#核心能力)
[![OpenID Connect](https://img.shields.io/badge/OpenID-Connect-F78C40?logo=openid&logoColor=white)](#核心能力)
[![MFA](https://img.shields.io/badge/MFA-TOTP%20%7C%20Passkey-5A2CA0)](#核心能力)
[![WebAuthn](https://img.shields.io/badge/WebAuthn-Passkey-0A66C2)](#核心能力)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](compose.quickstart.yaml)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-326CE5?logo=kubernetes&logoColor=white)](idp-server/deploy)
[![License](https://img.shields.io/badge/License-Apache%202.0-D22128?logo=apache&logoColor=white)](LICENSE)

语言: [English](README.md) | [简体中文](README.zh-CN.md)

`Sienne-idp` 是一个基于 Go 的 Identity Provider，实现 OAuth2 与 OpenID Connect。项目采用无状态应用节点 + MySQL + Redis 的架构，覆盖会话状态、令牌生命周期、防重放、MFA、审计日志和签名密钥轮转等生产向能力。

## 核心能力

- OAuth2 Authorization Code + PKCE、Client Credentials、Device Code、Refresh Token 轮转，以及兼容旧客户端的 Password Grant。
- OIDC Discovery、JWKS、UserInfo、Introspection、End Session 等标准端点。
- 本地注册、登录、登出、全端登出，以及联邦 OIDC 登录。
- 浏览器会话持久化在 MySQL，并通过 Redis 缓存支撑授权与后台校验热路径。
- MFA 支持 TOTP、Passkey/WebAuthn 第二因素、Push 审批、强制绑定和 TOTP step 防重放。
- Redis 承载限流、OAuth state/nonce、设备码、MFA challenge、token 撤销缓存，并通过 Lua 保证原子状态转换。
- RBAC 后台权限、审计事件、签名密钥轮转。

## 项目结构

- `idp-server/cmd/idp`: 应用入口。
- `idp-server/internal/application`: 用例编排和业务流程。
- `idp-server/internal/interfaces/http`: HTTP handler、中间件、DTO 与路由。
- `idp-server/internal/infrastructure`: MySQL、Redis、密码学、审计流和外部 OIDC 集成。
- `idp-server/internal/plugins`: 可插拔的认证、客户端认证和 grant 处理器。
- `idp-server/scripts`: 数据库迁移和 Redis Lua 脚本。
- `idp-server/deploy`: Kubernetes 与 Podman 部署示例。

## 代码入口

- HTTP 路由：`idp-server/internal/interfaces/http/router.go`。
- 配置加载：`idp-server/internal/bootstrap/config.go`。
- 依赖装配：`idp-server/internal/bootstrap/providers.go`。
- OAuth 授权：`idp-server/internal/application/authz`。
- Token grants：`idp-server/internal/application/token` 和 `idp-server/internal/plugins/grant`。
- 登录与 MFA 编排：`idp-server/internal/application/authn`, `idp-server/internal/application/mfa`, `idp-server/internal/application/passkey`。
- Redis 缓存适配器：`idp-server/internal/infrastructure/cache/redis`。
- MySQL schema 与本地 fixture：`idp-server/scripts/migrate.sql`。

## 快速开始

使用预构建镜像栈：

```bash
docker compose -f compose.quickstart.yaml up -d
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/.well-known/openid-configuration
```

本地源码构建：

```bash
cd idp-server
docker compose up -d --build
curl -sS http://localhost:8080/healthz
```

运行测试：

```bash
cd idp-server
go test ./...
```

## 本地 Fixture

迁移文件中包含用于本地开发的演示用户、OAuth client 和协议样本数据。所有 fixture 凭据都应视为公开测试数据，不能在本地开发以外复用，也不应作为真实环境的 secret、签名密钥或加密密钥。

## 配置

配置可以来自 YAML 文件和环境变量。公开仓库只应提交示例配置；真实 `.env`、私钥和部署 secret 必须留在 git 之外。

常用配置：

- 运行时：`ISSUER`, `TOTP_ISSUER`, `LISTEN_ADDR`, `SESSION_TTL`, `APP_ENV`。
- MySQL：`MYSQL_DSN`，或 `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`。
- Redis：`REDIS_ADDR`，或 `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB`, `REDIS_KEY_PREFIX`。
- 安全策略：`FORCE_MFA_ENROLLMENT`, `LOGIN_FAILURE_WINDOW`, `LOGIN_MAX_FAILURES_PER_IP`, `LOGIN_MAX_FAILURES_PER_USER`, `LOGIN_USER_LOCK_THRESHOLD`, `LOGIN_USER_LOCK_TTL`。
- 签名与密码学：`TOTP_SECRET_ENCRYPTION_KEY`, `JWT_KEY_ID`, `SIGNING_KEY_DIR`, `SIGNING_KEY_BITS`, `SIGNING_KEY_CHECK_INTERVAL`, `SIGNING_KEY_ROTATE_BEFORE`, `SIGNING_KEY_RETIRE_AFTER`。
- 联邦 OIDC：`FEDERATED_OIDC_ISSUER`, `FEDERATED_OIDC_CLIENT_ID`, `FEDERATED_OIDC_CLIENT_SECRET`, `FEDERATED_OIDC_REDIRECT_URI`, `FEDERATED_OIDC_PROVIDER_NAME`。

如果要本地测试 Google OIDC，请在 Google Cloud Console 创建 Web Application OAuth Client，将回调配置为本地 issuer 下的 `/login`，然后通过私有 shell 环境或未跟踪的 `.env` 注入 client 参数。

## Public 前检查

发布前请确认：

- `.env`, `.env.*`, 本地 YAML override、私钥、证书、构建产物都不进入 git。
- 任何曾经提交、发给他人或用于公开演示的凭据都要轮换。
- 每个环境独立生成签名密钥，并存放在 KMS、Vault 或受保护的运行时卷中。
- `compose.quickstart.yaml` 中的默认值只用于启动演示，生产使用前必须逐项替换。

## 端点

- UI/认证：`/register`, `/login`, `/login/totp`, `/mfa/totp/setup`, `/mfa/passkey/setup`, `/consent`, `/device`。
- 会话：`/logout`, `/logout/all`, `/connect/logout`。
- OAuth2/OIDC：`/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/device/authorize`, `/oauth2/introspect`, `/oauth2/userinfo`, `/oauth2/jwks`。
- Admin/RBAC：`/admin`, `/admin/rbac/roles`, `/admin/rbac/usage`, `/admin/rbac/bootstrap`, `/admin/users/:user_id/role`, `/admin/users/:user_id/logout-all`。

## 生产提示

应用支持文件型签名密钥，适合本地开发；多副本部署建议使用 KMS、Vault 或受保护的共享存储，并明确密钥轮转的执行者。不要公开私钥或真实环境文件。

## 许可证

本项目采用 [Apache 2.0 许可证](LICENSE) 进行开源。
