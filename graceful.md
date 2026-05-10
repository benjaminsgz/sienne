# OAuth2 密钥轮转与安全 Refresh Token 的优雅实现

在分布式系统和 OAuth2 架构中，Identity Provider (IdP) 如何在更新签名密钥的同时，确保下游服务（资源服务器、网关）能够无缝感知且不失去控制？这是一个关乎系统可用性与安全性的核心问题。

本文从 JWKS 动态发现的基本原理讲起，逐步深入到多实例环境下的状态一致性挑战，再到 Refresh Token 轮转中的 "Grace Replay" 防护机制，力求呈现一个完整的技术图景。

---

## 1. 密钥轮转：下游如何"无感知"同步？

当 IdP 轮转签名私钥时，下游服务如果还持有旧的公钥，就会把合法的 Token 判为无效。这是密钥轮转面临的最基本问题：**签名端的密钥已经变了，但验证端还不知道**。

### 1.1 JWKS 机制的核心思路

业界标准方案（RFC 7517 / RFC 7518）通过三个要素解决这个问题：

- **kid (Key ID)**：IdP 在每个 JWT 的 Header 中带上 `kid` 字段，标识"这个 Token 是用哪把密钥签的"。`kid` 本身不包含密钥材料，只是一个标识符——可以是 UUID、时间戳哈希、或任何唯一字符串。
- **JWKS 端点**：IdP 暴露一个标准端点 `/.well-known/jwks.json`，返回当前所有有效公钥的集合。这个端点的响应是一个 JSON 对象，包含一个 `keys` 数组，每个元素是一个 JWK（JSON Web Key）。
- **动态拉取**：下游服务在验签时执行一个简单的 logic——先在本地缓存中查找 `kid` 对应的公钥。如果命中，直接验签。如果未命中（说明 IdP 可能已经轮转了密钥），则触发一次对 JWKS 端点的 HTTP 调用，拉取最新的公钥集合，更新本地缓存，再用新公钥验签。

这个机制的精巧之处在于：下游服务不需要任何主动配置或通知，密钥的同步完全由验签过程中的 `kid` miss 驱动。只要 IdP 的 JWKS 端点在轮转后包含了新公钥，下游就能自动适应。

本项目中，JWKS 端点的实现位于 `idp-server/internal/application/oidc/service.go`：

```go
func (s *Service) JWKS(ctx context.Context) (*JSONWebKeySet, error) {
	_ = ctx
	// 如果没有注入密钥提供方，返回空集合
	if s.keys == nil {
		return &JSONWebKeySet{}, nil
	}
	// PublicJWKS() 从 KeyManager 中提取当前所有的公钥（包含活跃和待下线的）
	return &JSONWebKeySet{Keys: s.keys.PublicJWKS()}, nil
}
```

### 1.2 平滑过渡策略（Grace Period）

尽管 JWKS 的动态拉取机制解决了"能不能同步"的问题，但"什么时候同步"仍然需要精心设计。如果 IdP 在同一时刻完成"开始用新密钥签名"和"发布新公钥"，那么在新公钥发布到下游缓存更新完成的这段时间里，下游会拿到一个带着新 `kid` 的 Token，但本地缓存里还没有对应的公钥——于是触发一次 JWKS 拉取。

这在正常情况下没问题，但在高并发场景下，大量请求同时触发 JWKS 拉取，可能会给 IdP 的 JWKS 端点带来瞬时压力（"惊群效应"）。更严重的是，如果 JWKS 端点此刻刚好不可用（网络抖动、部署重启），这批请求就会全部验签失败。

推荐的做法是将轮转拆分为四个阶段：

1. **预发布（Pre-publish）**：将新公钥加入 JWKS 端点的响应，但此时 IdP 仍然使用旧私钥签名。这一步让下游有机会在正常的缓存刷新周期中"自然地"拿到新公钥，而不是被 `kid` miss 强制触发。
2. **观察期（Soak）**：等待一段时间，确保绝大多数下游服务已经完成缓存更新。这个等待时间通常应大于下游 JWKS 缓存的 TTL。如果下游的缓存 TTL 是 24 小时，那这个观察期至少应该是 24 小时。
3. **正式切换（Activate）**：IdP 开始用新私钥签名新 Token。此时 JWKS 端点同时包含新旧两个公钥，确保无论客户端拿到的是旧 Token 还是新 Token，下游都能验通过。
4. **下线旧钥（Decommission）**：等待所有旧 Token 自然过期（即旧 Token 的最长 `exp` 时间已过），再从 JWKS 中移除旧公钥。在此之前，旧公钥必须保留，否则仍在流通的旧 Token 会验签失败。

这四个阶段的核心思想是**先让验证端准备好，再让签名端切换**，而不是反过来。这是分布式系统中常见的"宽进严出"原则的体现。

本项目在 `idp-server/internal/infrastructure/crypto/key_rotation.go` 中通过配置实现了这一逻辑：

```go
func rotateKey(ctx context.Context, repo rotationRepository, cfg RotationConfig, force bool) (bool, error) {
	// ...
	if cfg.RotateBefore <= 0 {
		cfg.RotateBefore = 24 * time.Hour // 提前 24 小时生成新密钥并发布到 JWKS
	}
	if cfg.RetireAfter <= 0 {
		cfg.RetireAfter = 24 * time.Hour  // 旧密钥在被替换后继续保留 24 小时以供验证
	}
	// ...
}
```

---

## 2. 多实例部署下的一致性挑战

上面描述的 JWKS 机制在架构上是优美的，但在工程实现中隐藏着一个容易被忽视的问题：**当 IdP 自身是多实例部署时，各实例之间的 JWKS 内存状态可能不一致**。

### 2.1 问题根因

典型的实现（例如基于 `StartRotationLoop()` 的后台 ticker 模式）在每个实例上独立运行一个定时任务，按固定间隔（如 `CheckInterval = 1 小时`）检查是否需要轮转密钥，并在必要时从共享存储（数据库、etcd、Vault 等）加载最新的密钥集合到进程内存中的 `KeyManager`。

问题出在这里：轮转这个动作只会在一个实例上发生（通常由分布式锁保证），但其他实例的 `KeyManager` 刷新依赖各自的 ticker。假设实例 A 在 T=0 时刻完成了轮转，写入了新密钥到共享存储，并更新了自己的内存。实例 B 的 ticker 如果刚在 T=-5min 跑过，那它要等到 T=55min 才会再次检查并刷新。

在这 55 分钟的窗口期内：

- 如果客户端请求 JWKS 端点，负载均衡器随机转发到实例 A 或 B，返回的公钥集合是不同的。
- 如果实例 A 签发了一个带有新 `kid` 的 Token，而客户端随后将这个 Token 发送到一个由实例 B 服务的资源服务器进行验证，实例 B 的 `KeyManager` 里根本不认识这个 `kid`——结果就是 `401 Unauthorized`。

这个问题的本质是**分布式缓存失效**：每个进程的内存是一个独立的缓存副本，缺乏相互通知的机制。

### 2.2 解决方案：Redis Pub/Sub + Ticker 兜底

一个直接有效的方案是引入 Redis Pub/Sub 作为实例间的通知机制：

1. **发布**：任意实例完成轮换后，向 Redis 频道发布一条消息——`PUBLISH jwks:rotated <timestamp|new_kid>`。Payload 只需要携带时间戳或新的 KID，接收方不需要解析复杂结构，直接触发一次完整的 key 重载即可。
2. **订阅**：所有实例在启动时执行 `SUBSCRIBE jwks:rotated`，注册监听。
3. **响应**：收到消息后，立即执行 `LoadKeyManagerFromRepository()` → `ReplaceWith()`，从共享存储加载最新的密钥集合并替换内存中的 `KeyManager`。

本项目通过 `KeySyncBroadcaster` (位于 `idp-server/internal/infrastructure/crypto/key_sync.go`) 实现了这一同步机制：

```go
func (b *KeySyncBroadcaster) Subscribe(ctx context.Context, manager *KeyManager, repo rotationRepository, workingDir string) {
	go func() {
		pubsub := b.rdb.Subscribe(ctx, b.channel)
		defer func() { _ = pubsub.Close() }()
		// ... 监听逻辑
		for {
			select {
			case _, ok := <-ch:
				if !ok { return }
				// 收到通知后触发重载
				refreshed, err := LoadKeyManagerFromRepository(loadCtx, repo, workingDir)
				if err == nil {
					manager.ReplaceWith(refreshed)
				}
			}
		}
	}()
}
```

这种方式将窗口期从 `CheckInterval`（1 小时）缩短到 Redis 消息的传播延迟——通常在毫秒级别。

但 Pub/Sub 有一个重要的限制：**它不保证送达**。如果一个实例在消息发布时恰好不在线（重启中、网络断开、Redis 连接闪断），它就会错过这条消息。因此，现有的 ticker 机制必须保留作为兜底——它保证任何实例在最长 `CheckInterval` 时间后一定会同步到最新状态。

两者的定位是互补的：

| 机制 | 职责 | 延迟 | 可靠性 |
|------|------|------|--------|
| Redis Pub/Sub | 快速收敛 | 毫秒级 | 不保证送达（Best-effort） |
| 后台 Ticker | 最终一致性兜底 | ≤ CheckInterval | 保证送达（只要实例在运行） |

### 2.3 其他可选方案

除了 Redis Pub/Sub，还有几种替代思路，适用于不同的基础设施环境：

- **数据库轮询优化**：将 `CheckInterval` 大幅缩短（如从 1 小时改为 30 秒），以更高的轮询频率换取更短的窗口期。代价是数据库的读压力增加，但如果密钥表很小（通常只有几行），这个开销可以接受。
- **分布式缓存版本号**：在 Redis 或 Memcached 中维护一个全局版本号（monotonically increasing），每次轮转递增。Ticker 每次检查时先比对版本号，只在版本号变化时才加载完整密钥——这比每次都读数据库更轻量。
- **事件总线**：如果系统已经有 Kafka、NATS 或 RabbitMQ，可以通过消息队列广播轮转事件，比 Redis Pub/Sub 多了持久化保证。

---

## 3. 失去控制？Refresh Token 是最后的补救

即使 IdP 做了所有正确的事情（JWKS 端点更新及时、Grace Period 设置合理、多实例同步到位），下游服务仍然可能因为自身的原因而同步失败——比如把公钥硬编码在配置文件里（没有动态拉取 JWKS）、或者设置了过长的 JWKS 缓存 TTL。

在这种情况下，IdP 并非完全无计可施。**短有效期 Access Token + Refresh Token 轮转**构成了第二道防线。

逻辑链条是这样的：

1. Access Token 的有效期很短（通常 5-15 分钟）。即使当前的 Access Token 是用旧密钥签的，它很快就会过期。
2. 客户端必须用 Refresh Token 去 IdP 换取新的 Access Token。
3. IdP 在签发新 Access Token 时，使用的是最新的私钥。这个新 Token 的 `kid` 指向新的公钥。
4. 当下游服务收到这个新 Token 时，即使它之前因为缓存问题没有同步到新公钥，`kid` miss 也会强制触发一次 JWKS 拉取——除非下游连动态拉取都没实现。

换句话说，Refresh Token 的周期性刷新本身就是一个隐式的密钥同步驱动器。只要 Access Token 的有效期足够短，IdP 对下游的"控制力恢复时间"就不会超过一个 Access Token 的生命周期。

这也解释了为什么短有效期 Access Token 不仅仅是"安全最佳实践"，更是系统架构层面的鲁棒性设计。

---

## 4. 进阶安全：Refresh Token 轮转与 Grace Replay

在安全性要求较高的场景下，Refresh Token 应该是**一次性的（One-time use）**：每次刷新时，旧的 Refresh Token 立即失效，同时签发一个新的。这样做的好处是显而易见的——如果一个 Refresh Token 被泄露，攻击者最多只能使用一次，合法用户在下一次刷新时会发现 Token 被拒绝，从而触发异常检测。

但这个模式在工程实现中有一个棘手的边界情况。

### 4.1 竞态问题

假设以下时序：

1. 客户端发送刷新请求，携带 Refresh Token `RT-old`。
2. IdP 收到请求，在数据库中将 `RT-old` 标记为已使用，同时生成新的 `RT-new` 和新的 Access Token。
3. IdP 将响应发回客户端。
4. **网络闪断**——客户端没有收到响应。
5. 客户端等待超时，重试：再次发送 `RT-old`。
6. IdP 查到 `RT-old` 已经被标记为已使用——拒绝请求。

结果：客户端手里既没有新的 Access Token，也没有有效的 Refresh Token。用户被迫重新登录。

更糟糕的是，如果 IdP 把"已使用的 Refresh Token 被再次提交"视为潜在的攻击行为（这是合理的安全策略），它可能会直接撤销整个 Token Family（即该用户的所有 Refresh Token），导致用户在所有设备上被踢出。

### 4.2 Grace Replay 机制

优雅的解决方案是引入一个极短的"宽限重放窗口"：

1. **原子轮转**：在数据库事务中，旧 Token 的失效和新 Token 的生成作为一个原子操作完成。这确保了不会出现"旧 Token 已失效但新 Token 尚未生成"的中间态。
2. **缓存最近一次轮转结果**：当轮转成功完成后，IdP 在缓存层（如 Redis）中存储一条记录，Key 为旧 Refresh Token 的哈希值，Value 为刚才生成的完整响应（新 Access Token + 新 Refresh Token）。这条缓存记录的 TTL 设为极短的时间，如 10 秒。
3. **重放判定**：当 IdP 收到一个已失效的 Refresh Token 时，先检查缓存。如果存在对应的记录，并且请求的指纹（IP、User-Agent、Device ID 等）与上一次一致，则认为这是一次合法的网络重试——不报错，直接返回缓存中的响应。
4. **攻击检测**：如果超出宽限期（缓存已过期），或者指纹不匹配（说明可能是另一个设备在尝试使用这个 Token），则视为异常，执行安全响应——撤销该 Token Family 下的所有令牌，强制用户重新认证。

本项目在 `idp-server/internal/application/token/service.go` 中通过两级检查实现了 Grace Replay：

```go
func (s *Service) exchangeRefreshToken(ctx context.Context, input ExchangeInput) (*ExchangeResult, error) {
	// ...
	if s.tokenCache != nil {
		// 第一级检查：直接从缓存中获取最近一次成功的轮转结果
		replay, _ := s.tokenCache.CheckRefreshTokenReplay(ctx, oldSHA, strings.TrimSpace(input.ReplayFingerprint))
		if result := refreshReplayToExchangeResult(replay); result != nil {
			return result, nil // 命中 Grace Replay，直接返回上一次的成功响应
		}
	}

	// ... 数据库操作 ...

	if err := s.tokens.RotateRefreshToken(ctx, oldSHA, now, newRefresh); err != nil {
		// 第二级检查：如果数据库轮转由于冲突失败，可能是并发重试，再次尝试从缓存恢复
		if replayResult, replayErr := s.tryRefreshTokenGraceReplay(ctx, oldSHA, input.ReplayFingerprint); replayErr == nil && replayResult != nil {
			return replayResult, nil
		}
		// ...
	}
	// ...
}
```

### 4.3 为什么是 10 秒？

宽限期的长度是一个权衡：

- **太短**（如 1 秒）：可能覆盖不了高延迟网络（弱网、跨洋请求）的重试周期，问题没有真正解决。
- **太长**（如 60 秒）：扩大了攻击窗口。如果攻击者在 60 秒内拦截到了旧 Refresh Token 并完成重放，IdP 会把它当成合法重试。
- **10 秒左右**：大多数 HTTP 客户端的默认超时在 5-30 秒之间，一次重试通常在原始请求的 2-5 秒后发出。10 秒覆盖了绝大多数合法重试场景，同时把攻击窗口控制在可接受的范围内。

当然，这个值应该是可配置的，并且应该结合具体业务场景（移动端弱网多还是机房内网为主？）来调整。

### 4.4 指纹校验的作用

指纹（Fingerprint）在 Grace Replay 机制中扮演着关键角色。它的目的是区分"合法重试"和"Token 泄露后的恶意重放"。

一个合理的指纹可以包括：

- 客户端 IP（或 IP 段，考虑 NAT 和移动网络切换）
- User-Agent
- 设备标识符（如果有的话，比如移动端的 Device ID）
- TLS Session 相关信息

指纹不需要也不应该过于严格。如果要求所有字段完全一致，可能会导致合法重试被拒绝（比如用户在重试期间从 WiFi 切换到了移动数据，IP 变了）。通常，2-3 个维度的"大致匹配"就足够了。

---

## 5. Token Family 与级联撤销

前文提到"撤销整个 Token Family"，这个概念值得展开。

在 Refresh Token 轮转模型中，每次刷新都会生成一个新的 Refresh Token。这些 Token 形成了一条链：`RT-0 → RT-1 → RT-2 → RT-3 → ...`。这条链中的所有 Token 都属于同一个 Token Family，通常通过一个共享的 `family_id` 关联。

当 IdP 检测到异常时（已使用的 Refresh Token 在宽限期外被再次提交），它执行**级联撤销**：

1. 标记该 `family_id` 下的所有 Refresh Token 为已撤销。
2. 吊销该 Family 下所有已签发但尚未过期的 Access Token（如果使用了 Token Introspection 或黑名单机制的话）。
3. 强制该用户重新认证。

这种"宁可错杀一千"的策略是有道理性：如果一个旧 Token 在宽限期外被重新提交，要么是攻击者拿到了旧 Token，要么是客户端的实现有严重的 bug——无论哪种情况，撤销整个 Family 都是最安全的选择。

---

## 6. 实现注意事项

### 6.1 数据库事务设计

Refresh Token 的原子轮转要求数据库操作在单个事务中完成：

```
BEGIN;
  UPDATE refresh_tokens SET revoked = true WHERE token_hash = $old_hash AND revoked = false;
  -- 如果 UPDATE 影响了 0 行，说明 Token 已被使用或不存在，中止
  INSERT INTO refresh_tokens (token_hash, family_id, ...) VALUES ($new_hash, $family_id, ...);
COMMIT;
```

`revoked = false` 的条件检查和 `UPDATE` 必须在同一个语句中，利用数据库的行级锁防止并发轮转。

本项目在 `idp-server/internal/infrastructure/persistence/token_repo.go` 中的实现逻辑如下：

```go
func (r *TokenRepository) RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, revokedAt time.Time, newToken *tokendomain.RefreshToken) error {
	tx, err := r.db.writer().BeginTx(ctx, nil)
	// ...
	// 锁住旧 Token 行进行检查
	oldToken, err := scanRefreshToken(tx.QueryRowContext(ctx, tokenRepositorySQL.rotateFindOldForUpdate, oldTokenSHA256))
	
	// 校验旧 Token 是否仍处于活跃状态
	if oldToken == nil || oldToken.RevokedAt != nil || oldToken.ReplacedByTokenID != nil || !oldToken.ExpiresAt.After(revokedAt) {
		return sql.ErrNoRows // 状态非法，拒绝轮转并让上层触发重放/攻击检测
	}

	// 插入新 Token 并将旧 Token 的 ReplacedByTokenID 指向新 Token ID
	// ...
	return tx.Commit()
}
```

### 6.2 缓存层的键设计

Grace Replay 的缓存记录建议使用以下结构：

```
Key:   refresh_replay:{hash(RT-old)}
Value: { access_token, refresh_token, expires_in, fingerprint_hash }
TTL:   10s
```

注意存储的是旧 Token 的哈希值作为 Key——永远不要把 Token 明文作为缓存键。

### 6.3 日志与监控

Grace Replay 的每一次命中都应该被记录，因为它本身就是一个"边界事件"。建议区分以下几种情况的监控指标：

- **正常刷新**：旧 Token 有效，轮转成功。
- **Grace Replay 命中**：旧 Token 已失效，但在宽限期内且指纹匹配，返回缓存结果。
- **指纹不匹配**：旧 Token 已失效，在宽限期内但指纹不匹配——可疑，记录告警。
- **宽限期外重放**：旧 Token 已失效且超出宽限期——触发 Token Family 撤销。

如果"Grace Replay 命中"的比例突然升高，可能意味着网络质量恶化或客户端实现有问题；如果"指纹不匹配"或"宽限期外重放"的比例升高，可能意味着存在主动攻击。

---

## 7. 总结

IdP 对下游的控制力不是靠一个单一机制实现的，而是由多层防线叠加构成的：

1. **JWKS + kid** 实现公钥的自动同步——这是正常路径，绝大多数场景下它就够了。
2. **Grace Period 四阶段轮转** 确保密钥切换不会引发瞬时故障——这是对正常路径的加固。
3. **多实例通知机制**（如 Redis Pub/Sub）缩短 JWKS 内存视图的同步窗口——这是对分布式部署场景的修补。
4. **短效 Access Token + Refresh Token 轮转** 在下游同步失败时提供兜底——这是对异常路径的容错。
5. **Grace Replay** 在一次性 Refresh Token 模式下容忍网络抖动——这是对极端边界情况的处理。
6. **Token Family 级联撤销** 在检测到异常时果断切断——这是安全的最后一道门。

这些机制层层递进，前一层解决"正常情况下如何工作"，后一层解决"前一层失败时怎么办"。好的安全架构不是追求某一层做到完美，而是接受每一层都可能失败，然后确保总有下一层在兜底。
