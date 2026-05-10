# OAuth2 密钥轮转与安全 Refresh Token 的优雅实现

在分布式系统和 OAuth2 架构中，Identity Provider (IdP) 如何在更新签名密钥的同时，确保下游服务（资源服务器、网关）能够无缝感知且不失去控制？这是一个关乎系统可用性与安全性的核心问题。

本文从 JWKS 动态发现的基本原理讲起，逐步深入到多实例环境下的状态一致性挑战，再到 Refresh Token 轮转中的 "Grace Replay" 防护机制，并结合本项目（Oauth2-sienne）的实现进行深度解析。

---

## 1. 密钥轮转：下游如何"无感知"同步？

当 IdP 轮转签名私钥时，下游服务如果还持有旧的公钥，就会把合法的 Token 判为无效。这是密钥轮转面临的最基本问题：**签名端的密钥已经变了，但验证端还不知道**。

### 1.1 JWKS 机制的核心思路

业界标准方案（RFC 7517 / RFC 7518）通过三个要素解决这个问题：

- **kid (Key ID)**：IdP 在每个 JWT 的 Header 中带上 `kid` 字段，标识"这个 Token 是用哪把密钥签的"。
- **JWKS 端点**：IdP 暴露一个标准端点（本项目实现于 `/oauth2/jwks`），返回当前所有有效公钥的集合。
- **动态拉取**：下游服务在验签时，若本地缓存中找不到 `kid` 对应的公钥，则触发一次对 JWKS 端点的拉取。

在本项目中，JWKS 接口的实现非常简洁，它直接从注入的密钥提供方获取公钥集：

```go
// idp-server/internal/application/oidc/service.go

func (s *Service) JWKS(ctx context.Context) (*JSONWebKeySet, error) {
	_ = ctx
	// 如果没有注入密钥提供方，返回空集合而不是报错
	if s.keys == nil {
		return &JSONWebKeySet{}, nil
	}
	// PublicJWKS() 返回当前 KeyManager 中所有活跃和待下线的公钥
	return &JSONWebKeySet{Keys: s.keys.PublicJWKS()}, nil
}
```

### 1.2 平滑过渡策略（Grace Period）

为了避免"惊群效应"和瞬时切换导致的抖动，本项目在密钥轮转逻辑中内置了宽限期（Grace Period）设计。

通过配置 `RotateBefore` 和 `RetireAfter`，我们可以实现以下平滑过程：
1. **预发布**：新 Key 生成后立即进入 JWKS。
2. **观察期**：旧 Key 依然保留在 JWKS 中，且作为备选验证 Key。
3. **下线**：只有当旧 Key 彻底过期后，才从内存中移除。

```go
// idp-server/internal/infrastructure/crypto/key_rotation.go

func rotateKey(ctx context.Context, repo rotationRepository, cfg RotationConfig, force bool) (bool, error) {
	// ... 配置默认值
	if cfg.RotateBefore <= 0 {
		cfg.RotateBefore = 24 * time.Hour // 提前 24 小时生成新密钥
	}
	if cfg.RetireAfter <= 0 {
		cfg.RetireAfter = 24 * time.Hour  // 旧密钥失效后保留 24 小时供验证
	}

	records, err := repo.ListCurrent(ctx)
	// ... 检查是否需要轮换的具体逻辑
}
```

---

## 2. 多实例部署下的一致性挑战

当 IdP 自身是多实例部署时，各实例之间的 JWKS 内存状态可能不一致。

### 2.1 解决方案：Redis Pub/Sub + Ticker 兜底

本项目引入了 `KeySyncBroadcaster`，利用 Redis Pub/Sub 实现秒级的实例间同步。

1. **发布**：任意实例完成轮换后，向 Redis 频道发布通知。
2. **订阅**：所有实例监听到消息后，立即重载内存中的 KeyManager。

```go
// idp-server/internal/infrastructure/crypto/key_sync.go

func (b *KeySyncBroadcaster) Subscribe(ctx context.Context, manager *KeyManager, repo rotationRepository, workingDir string) {
	go func() {
		pubsub := b.rdb.Subscribe(ctx, b.channel)
		ch := pubsub.Channel()
		for {
			select {
			case _, ok := <-ch:
				// 收到消息后，触发一次完整的 key 重载
				refreshed, err := LoadKeyManagerFromRepository(loadCtx, repo, workingDir)
				if err == nil {
					manager.ReplaceWith(refreshed)
				}
			// ...
			}
		}
	}()
}
```

---

## 3. 失去控制？Refresh Token 是最后的补救

即使下游同步失败，IdP 依然可以通过 **短有效期 Access Token + Refresh Token 轮转** 夺回控制权。Access Token 过期后，客户端必须发起刷新请求，此时 IdP 会签发带有**新私钥签名**和**新 kid** 的 Token，从而强迫下游进行 JWKS 同步。

---

## 4. 进阶安全：Refresh Token 轮转与 Grace Replay

为了极致安全，Refresh Token 应该是**一次性的（One-time use）**。

### 4.1 Grace Replay 机制

为了解决网络闪断导致的重试失败问题，本项目实现了 "Grace Replay"：
1. **原子轮转**：在数据库事务中完成 Token 的更替。
2. **缓存最近结果**：在 Redis 中短期记录轮转结果。
3. **优雅重放**：如果在宽限期内（本项目默认 10s）收到已失效 Token 的相同指纹请求，直接返回缓存结果。

```go
// idp-server/internal/application/token/service.go

func (s *Service) exchangeRefreshToken(ctx context.Context, input ExchangeInput) (*ExchangeResult, error) {
	// 1. 先查缓存层的重放检测
	replay, _ := s.tokenCache.CheckRefreshTokenReplay(ctx, oldSHA, strings.TrimSpace(input.ReplayFingerprint))
	if result := refreshReplayToExchangeResult(replay); result != nil {
		return result, nil // 如果命中了 Grace Replay，直接返回上次的结果
	}

	// 2. 数据库原子轮转
	if err := s.tokens.RotateRefreshToken(ctx, oldSHA, now, newRefresh); err != nil {
		// 如果主旋转失败（可能是并发冲突），尝试第二次 Grace Replay 检查
		if replayResult, _ := s.tryRefreshTokenGraceReplay(ctx, oldSHA, input.ReplayFingerprint); replayResult != nil {
			return replayResult, nil
		}
		return nil, ErrInvalidRefreshToken
	}
	// ...
}
```

---

## 5. 实现底层的原子性保证

### 5.1 数据库事务

Refresh Token 的安全性建立在数据库的原子操作之上，防止"双花"（Double Spending）：

```go
// idp-server/internal/infrastructure/persistence/token_repo.go

func (r *TokenRepository) RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, revokedAt time.Time, newToken *tokendomain.RefreshToken) error {
	tx, _ := r.db.writer().BeginTx(ctx, nil)
	// 使用 FOR UPDATE 锁住旧 Token
	oldToken, _ := scanRefreshToken(tx.QueryRowContext(ctx, sqlRotateFindOldForUpdate, oldTokenSHA256))
	
	// 校验旧 Token 状态：未撤销、未被替换、未过期
	if oldToken == nil || oldToken.RevokedAt != nil || oldToken.ReplacedByTokenID != nil {
		return sql.ErrNoRows // 触发上层的重放/攻击检测逻辑
	}

	// 插入新 Token 并关联旧 Token
	tx.ExecContext(ctx, sqlRotateInsertNewRefresh, ...)
	tx.ExecContext(ctx, sqlRotateUpdateOldRefresh, revokedAt, newToken.ID, oldToken.ID)
	
	return tx.Commit()
}
```

---

## 6. 总结

IdP 对下游的控制力由多层防线构成：
1. **JWKS + kid**：标准化的公钥自动同步。
2. **KeySyncBroadcaster**：分布式实例间的快速状态收敛。
3. **Grace Replay**：在一次性 Token 严苛安全策略下的高可用容错。

好的安全架构不是追求某一层做到完美，而是接受每一层都可能失败，然后确保总有下一层在兜底。
