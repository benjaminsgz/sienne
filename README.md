# Sienne-idp

[![Go](https://img.shields.io/badge/Go-1.26.3-00ADD8?logo=go&logoColor=white)](idp-server/go.mod)
[![Gin](https://img.shields.io/badge/Gin-1.12.0-008ECF?logo=gin&logoColor=white)](https://github.com/gin-gonic/gin)
[![MySQL](https://img.shields.io/badge/MySQL-8+-4479A1?logo=mysql&logoColor=white)](#architecture)
[![Redis](https://img.shields.io/badge/Redis-7+-DC382D?logo=redis&logoColor=white)](#architecture)
[![OAuth2](https://img.shields.io/badge/OAuth-2.0-2F2F2F?logo=oauth&logoColor=white)](#highlights)
[![OpenID Connect](https://img.shields.io/badge/OpenID-Connect-F78C40?logo=openid&logoColor=white)](#highlights)
[![MFA](https://img.shields.io/badge/MFA-TOTP%20%7C%20Passkey-5A2CA0)](#highlights)
[![WebAuthn](https://img.shields.io/badge/WebAuthn-Passkey-0A66C2)](#highlights)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](compose.quickstart.yaml)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-326CE5?logo=kubernetes&logoColor=white)](idp-server/deploy)
[![License](https://img.shields.io/badge/License-Apache%202.0-D22128?logo=apache&logoColor=white)](LICENSE)

Language: [English](README.md) | [简体中文](README.zh-CN.md)

`Sienne-idp` is a Go-based Identity Provider implementing OAuth2 and OpenID Connect. It is designed around stateless application nodes backed by MySQL and Redis, with production-oriented controls for session state, token lifecycle, replay protection, MFA, audit logging, and signing-key rotation.

## Highlights

- OAuth2 Authorization Code + PKCE, Client Credentials, Device Code, Refresh Token rotation, and legacy Password grant support.
- OIDC Discovery, JWKS, UserInfo, Introspection, and End Session endpoints.
- Local login, registration, logout, logout-all, and federated OIDC login.
- Browser sessions stored durably in MySQL and cached in Redis for hot-path authorization and admin checks.
- MFA with TOTP, Passkey/WebAuthn as a second factor, push approval, forced enrollment, and TOTP step replay protection.
- Redis-backed rate limiting, OAuth state/nonce storage, device codes, MFA challenges, token revocation caches, and Lua-based atomic state transitions.
- RBAC-protected admin APIs, audit events, and signing-key rotation.

## Architecture

- `idp-server/cmd/idp`: application entrypoint.
- `idp-server/internal/application`: use-case orchestration.
- `idp-server/internal/interfaces/http`: HTTP handlers, middleware, DTOs, and router.
- `idp-server/internal/infrastructure`: MySQL, Redis, crypto, audit stream, and external OIDC integrations.
- `idp-server/internal/plugins`: pluggable authn, client-auth, and grant handlers.
- `idp-server/scripts`: database migration and Redis Lua scripts.
- `idp-server/deploy`: Kubernetes and Podman deployment examples.

## Code Map

- HTTP routes: `idp-server/internal/interfaces/http/router.go`.
- Configuration loading: `idp-server/internal/bootstrap/config.go`.
- Dependency wiring: `idp-server/internal/bootstrap/providers.go`.
- OAuth authorization: `idp-server/internal/application/authz`.
- Token grants: `idp-server/internal/application/token` and `idp-server/internal/plugins/grant`.
- Login and MFA orchestration: `idp-server/internal/application/authn`, `idp-server/internal/application/mfa`, and `idp-server/internal/application/passkey`.
- Redis cache adapters: `idp-server/internal/infrastructure/cache/redis`.
- MySQL schema and fixtures: `idp-server/scripts/migrate.sql`.

## Quick Start

Prebuilt image stack:

```bash
docker compose -f compose.quickstart.yaml up -d
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/.well-known/openid-configuration
```

Build locally:

```bash
cd idp-server
docker compose up -d --build
curl -sS http://localhost:8080/healthz
```

Run tests:

```bash
cd idp-server
go test ./...
```

## Local Fixtures

The migration file contains local demo users, OAuth clients, and sample protocol data for development. Treat every fixture credential as public test data only. Do not reuse fixture users, client secrets, signing keys, or encryption keys outside local development.

## Configuration

Configuration can be supplied by YAML files and environment variables. Public commits should include examples only; real `.env` files, private keys, and deployment secrets must stay outside git.

Common settings:

- Runtime: `ISSUER`, `TOTP_ISSUER`, `LISTEN_ADDR`, `SESSION_TTL`, `APP_ENV`.
- MySQL: `MYSQL_DSN` or `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`.
- Redis: `REDIS_ADDR` or `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB`, `REDIS_KEY_PREFIX`.
- Security: `FORCE_MFA_ENROLLMENT`, `LOGIN_FAILURE_WINDOW`, `LOGIN_MAX_FAILURES_PER_IP`, `LOGIN_MAX_FAILURES_PER_USER`, `LOGIN_USER_LOCK_THRESHOLD`, `LOGIN_USER_LOCK_TTL`.
- Signing and crypto: `TOTP_SECRET_ENCRYPTION_KEY`, `JWT_KEY_ID`, `SIGNING_KEY_DIR`, `SIGNING_KEY_BITS`, `SIGNING_KEY_CHECK_INTERVAL`, `SIGNING_KEY_ROTATE_BEFORE`, `SIGNING_KEY_RETIRE_AFTER`.
- Federated OIDC: `FEDERATED_OIDC_ISSUER`, `FEDERATED_OIDC_CLIENT_ID`, `FEDERATED_OIDC_CLIENT_SECRET`, `FEDERATED_OIDC_REDIRECT_URI`, `FEDERATED_OIDC_PROVIDER_NAME`.

For local Google OIDC testing, create a Web Application OAuth client in Google Cloud Console, set the callback to `/login` on your local issuer, and inject the client values through your private shell environment or an untracked `.env` file.

## Public Repository Hygiene

Before publishing:

- Keep `.env`, `.env.*`, local YAML overrides, private keys, certificates, and build outputs out of git.
- Rotate any credential that was ever committed, shared in chat, or used in a public demo.
- Generate signing keys per environment and store them in KMS, Vault, or a protected runtime volume.
- Review `compose.quickstart.yaml` defaults before production use; placeholders are for bootstrapping only.

## Endpoints

- UI/Auth: `/register`, `/login`, `/login/totp`, `/mfa/totp/setup`, `/mfa/passkey/setup`, `/consent`, `/device`.
- Session: `/logout`, `/logout/all`, `/connect/logout`.
- OAuth2/OIDC: `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/device/authorize`, `/oauth2/introspect`, `/oauth2/userinfo`, `/oauth2/jwks`.
- Admin/RBAC: `/admin`, `/admin/rbac/roles`, `/admin/rbac/usage`, `/admin/rbac/bootstrap`, `/admin/users/:user_id/role`, `/admin/users/:user_id/logout-all`.

## Production Note

The application supports file-backed signing keys for local development, but multi-replica deployments should use KMS, Vault, or protected shared storage with clear rotation ownership. Never publish private signing keys or real environment files.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).
