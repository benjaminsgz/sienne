package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"idp-server/internal/infrastructure/persistence"
)

type rotationRepository interface {
	ListCurrent(ctx context.Context) ([]persistence.JWKKeyRecord, error)
	CreateActiveKey(ctx context.Context, record persistence.JWKKeyRecord, retiresExistingAt time.Time) error
}

type RotationConfig struct {
	WorkingDir    string
	StorageDir    string
	KeyBits       int
	CheckInterval time.Duration
	RotateBefore  time.Duration
	RetireAfter   time.Duration
	KIDPrefix     string
}

type ManualRotateResult struct {
	PreviousKID string
	ActiveKID   string
	RotatedAt   time.Time
	RotatesAt   *time.Time
}

func EnsureKeyManager(ctx context.Context, repo rotationRepository, cfg RotationConfig) (*KeyManager, error) {
	// EnsureKeyManager 先确保“至少有一把可用 active key”，
	// 再把数据库里的当前密钥集加载进内存 KeyManager。
	if _, err := ensureRotation(ctx, repo, cfg); err != nil {
		return nil, err
	}
	return LoadKeyManagerFromRepository(ctx, repo, cfg.WorkingDir)
}

func StartRotationLoop(repo rotationRepository, manager *KeyManager, cfg RotationConfig, broadcaster *KeySyncBroadcaster) {
	if repo == nil || manager == nil || cfg.CheckInterval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(cfg.CheckInterval)
		defer ticker.Stop()

		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			rotated, err := ensureRotation(ctx, repo, cfg)
			if err == nil {
				if refreshed, loadErr := LoadKeyManagerFromRepository(ctx, repo, cfg.WorkingDir); loadErr == nil {
					manager.ReplaceWith(refreshed)
					if rotated {
						_ = broadcaster.Publish(ctx)
					}
				}
			}
			cancel()
		}
	}()
}

func ensureRotation(ctx context.Context, repo rotationRepository, cfg RotationConfig) (bool, error) {
	// 非强制模式下只在即将到达轮换窗口时才生成新 key。
	return rotateKey(ctx, repo, cfg, false)
}

func RotateSigningKeyNow(
	ctx context.Context,
	repo interface {
		ListCurrent(ctx context.Context) ([]persistence.JWKKeyRecord, error)
		CreateActiveKey(ctx context.Context, record persistence.JWKKeyRecord, retiresExistingAt time.Time) error
	},
	manager *KeyManager,
	cfg RotationConfig,
	broadcaster *KeySyncBroadcaster,
) (*ManualRotateResult, error) {
	if repo == nil {
		return nil, fmt.Errorf("rotation repository is required")
	}
	previousRecords, err := repo.ListCurrent(ctx)
	if err != nil {
		return nil, err
	}
	var previousKID string
	if previous := findActiveKey(previousRecords); previous != nil {
		previousKID = previous.KID
	}
	rotatedAt := time.Now().UTC()
	if _, err := rotateKey(ctx, repo, cfg, true); err != nil {
		return nil, err
	}
	if manager != nil {
		refreshed, err := LoadKeyManagerFromRepository(ctx, repo, cfg.WorkingDir)
		if err != nil {
			return nil, err
		}
		manager.ReplaceWith(refreshed)
	}
	_ = broadcaster.Publish(ctx)
	currentRecords, err := repo.ListCurrent(ctx)
	if err != nil {
		return nil, err
	}
	active := findActiveKey(currentRecords)
	if active == nil {
		return nil, fmt.Errorf("no active signing key")
	}
	return &ManualRotateResult{
		PreviousKID: previousKID,
		ActiveKID:   active.KID,
		RotatedAt:   rotatedAt,
		RotatesAt:   active.RotatesAt,
	}, nil
}

func rotateKey(ctx context.Context, repo rotationRepository, cfg RotationConfig, force bool) (bool, error) {
	// rotateKey 决定“是否需要轮换”以及“如何生成并持久化新 key”。
	if repo == nil {
		return false, fmt.Errorf("rotation repository is required")
	}
	if cfg.KeyBits <= 0 {
		cfg.KeyBits = 2048
	}
	if cfg.RotateBefore <= 0 {
		cfg.RotateBefore = 24 * time.Hour
	}
	if cfg.RetireAfter <= 0 {
		cfg.RetireAfter = 24 * time.Hour
	}
	if strings.TrimSpace(cfg.KIDPrefix) == "" {
		cfg.KIDPrefix = "kid"
	}

	records, err := repo.ListCurrent(ctx)
	if err != nil {
		return false, err
	}

	now := time.Now().UTC()
	active := findActiveKey(records)
	// 非强制模式下，如果当前 active key 的 rotates_at 还远在 RotateBefore 窗口之外，就不做事。
	if !force && active != nil && active.RotatesAt != nil && active.RotatesAt.After(now.Add(cfg.RotateBefore)) {
		return false, nil
	}
	if !force && active != nil && active.RotatesAt == nil {
		// 没有计划轮换时间的 active key 被视作长期有效，不自动替换。
		return false, nil
	}

	newKey, err := rsa.GenerateKey(rand.Reader, cfg.KeyBits)
	if err != nil {
		return false, fmt.Errorf("generate signing key: %w", err)
	}

	kid := fmt.Sprintf("%s-%s", strings.TrimSpace(cfg.KIDPrefix), now.Format("20060102T150405Z"))
	privateKeyRef, err := writePrivateKey(cfg, kid, newKey)
	if err != nil {
		return false, err
	}

	publicJWK, err := buildPublicJWKJSON(kid, &newKey.PublicKey, DefaultJWTAlg, DefaultKeyUse)
	if err != nil {
		return false, err
	}

	record := persistence.JWKKeyRecord{
		KID:           kid,
		KTY:           "RSA",
		Alg:           DefaultJWTAlg,
		UseType:       DefaultKeyUse,
		PublicJWKJSON: publicJWK,
		PrivateKeyRef: privateKeyRef,
		IsActive:      true,
		CreatedAt:     now,
		// 当前实现给新 key 一个固定的未来轮换时间，后台循环会据此判断下一次轮换窗口。
		RotatesAt: ptrTime(now.Add(90 * 24 * time.Hour)),
	}

	if err := repo.CreateActiveKey(ctx, record, now.Add(cfg.RetireAfter)); err != nil {
		return false, err
	}
	return true, nil
}

func findActiveKey(records []persistence.JWKKeyRecord) *persistence.JWKKeyRecord {
	// 仓储层保证同一时刻只有一把 active key；这里取第一把即可。
	for i := range records {
		if records[i].IsActive {
			return &records[i]
		}
	}
	return nil
}

func writePrivateKey(cfg RotationConfig, kid string, privateKey *rsa.PrivateKey) (string, error) {
	// 私钥文件落盘到受限目录，并返回可持久化引用给数据库记录。
	dir := strings.TrimSpace(cfg.StorageDir)
	if dir == "" {
		dir = "scripts/dev_keys"
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(cfg.WorkingDir, dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create key dir: %w", err)
	}

	path := filepath.Join(dir, kid+".pem")
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: encoded}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	// 尽量保存相对工作目录的引用，减少环境迁移时的绝对路径耦合。
	relative, err := filepath.Rel(cfg.WorkingDir, path)
	if err != nil {
		return "file://" + path, nil
	}
	return "file://" + filepath.ToSlash(relative), nil
}

func buildPublicJWKJSON(kid string, publicKey *rsa.PublicKey, alg, use string) (string, error) {
	// public JWK 直接持久化为 JSON，方便 discovery/JWKS 端点原样对外发布。
	jwk := JSONWebKey{
		Kty: "RSA",
		Kid: kid,
		Use: use,
		Alg: alg,
		N:   jwtEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   jwtEncoding.EncodeToString(bigEndianExponentBytes(publicKey.E)),
	}
	encoded, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
