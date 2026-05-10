package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"time"

	"idp-server/internal/infrastructure/persistence"
)

func TestRotateSigningKeyNowReplacesManagerAndReturnsNewActiveKey(t *testing.T) {
	cfg := RotationConfig{
		WorkingDir:   t.TempDir(),
		StorageDir:   "keys",
		KeyBits:      1024,
		RotateBefore: time.Hour,
		RetireAfter:  2 * time.Hour,
		KIDPrefix:    "kid",
	}
	now := time.Now().UTC()
	initial := newTestJWKKeyRecord(t, cfg, "kid-initial", true, now.Add(48*time.Hour))
	repo := &stubRotationRepo{records: []persistence.JWKKeyRecord{initial}}

	manager, err := LoadKeyManagerFromRepository(context.Background(), repo, cfg.WorkingDir)
	if err != nil {
		t.Fatalf("LoadKeyManagerFromRepository() error = %v", err)
	}

	result, err := RotateSigningKeyNow(context.Background(), repo, manager, cfg, nil)
	if err != nil {
		t.Fatalf("RotateSigningKeyNow() error = %v", err)
	}

	if result.PreviousKID != "kid-initial" {
		t.Fatalf("PreviousKID = %q, want %q", result.PreviousKID, "kid-initial")
	}
	if result.ActiveKID == "" || result.ActiveKID == "kid-initial" {
		t.Fatalf("ActiveKID = %q, want new active kid", result.ActiveKID)
	}

	meta, _, err := manager.ActiveSigningKey()
	if err != nil {
		t.Fatalf("ActiveSigningKey() error = %v", err)
	}
	if meta.KID != result.ActiveKID {
		t.Fatalf("manager active kid = %q, want %q", meta.KID, result.ActiveKID)
	}
}

func TestStartRotationLoopReloadsRepositoryWithoutLocalRotation(t *testing.T) {
	cfg := RotationConfig{
		WorkingDir:    t.TempDir(),
		StorageDir:    "keys",
		CheckInterval: 20 * time.Millisecond,
		RotateBefore:  time.Hour,
		RetireAfter:   2 * time.Hour,
		KIDPrefix:     "kid",
	}
	now := time.Now().UTC()
	initial := newTestJWKKeyRecord(t, cfg, "kid-a", true, now.Add(48*time.Hour))
	repo := &stubRotationRepo{records: []persistence.JWKKeyRecord{initial}}

	manager, err := LoadKeyManagerFromRepository(context.Background(), repo, cfg.WorkingDir)
	if err != nil {
		t.Fatalf("LoadKeyManagerFromRepository() error = %v", err)
	}

	StartRotationLoop(repo, manager, cfg, nil)

	repo.setRecords([]persistence.JWKKeyRecord{
		newTestJWKKeyRecord(t, cfg, "kid-b", true, now.Add(72*time.Hour)),
	})

	deadline := time.Now().Add(750 * time.Millisecond)
	for time.Now().Before(deadline) {
		meta, _, err := manager.ActiveSigningKey()
		if err == nil && meta.KID == "kid-b" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}

	meta, _, err := manager.ActiveSigningKey()
	if err != nil {
		t.Fatalf("ActiveSigningKey() error = %v", err)
	}
	t.Fatalf("manager active kid = %q, want %q after ticker reload", meta.KID, "kid-b")
}

func TestNewKeySyncBroadcasterUsesDefaultPrefix(t *testing.T) {
	broadcaster := NewKeySyncBroadcaster(nil, "")
	if broadcaster.channel != "idp:jwks:rotated" {
		t.Fatalf("channel = %q, want %q", broadcaster.channel, "idp:jwks:rotated")
	}
}

type stubRotationRepo struct {
	mu      sync.RWMutex
	records []persistence.JWKKeyRecord
}

func (r *stubRotationRepo) ListCurrent(context.Context) ([]persistence.JWKKeyRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return cloneJWKKeyRecords(r.records), nil
}

func (r *stubRotationRepo) CreateActiveKey(_ context.Context, record persistence.JWKKeyRecord, retiresExistingAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	updated := make([]persistence.JWKKeyRecord, 0, len(r.records)+1)
	for _, existing := range r.records {
		if existing.IsActive {
			existing.IsActive = false
			existing.DeactivatedAt = ptrTime(retiresExistingAt)
		}
		updated = append(updated, existing)
	}
	updated = append(updated, record)
	r.records = updated
	return nil
}

func (r *stubRotationRepo) setRecords(records []persistence.JWKKeyRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.records = cloneJWKKeyRecords(records)
}

func cloneJWKKeyRecords(records []persistence.JWKKeyRecord) []persistence.JWKKeyRecord {
	cloned := make([]persistence.JWKKeyRecord, len(records))
	copy(cloned, records)
	return cloned
}

func newTestJWKKeyRecord(t *testing.T, cfg RotationConfig, kid string, active bool, rotatesAt time.Time) persistence.JWKKeyRecord {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	privateKeyRef, err := writePrivateKey(cfg, kid, privateKey)
	if err != nil {
		t.Fatalf("writePrivateKey() error = %v", err)
	}
	publicJWK, err := buildPublicJWKJSON(kid, &privateKey.PublicKey, DefaultJWTAlg, DefaultKeyUse)
	if err != nil {
		t.Fatalf("buildPublicJWKJSON() error = %v", err)
	}

	return persistence.JWKKeyRecord{
		KID:           kid,
		KTY:           "RSA",
		Alg:           DefaultJWTAlg,
		UseType:       DefaultKeyUse,
		PublicJWKJSON: publicJWK,
		PrivateKeyRef: privateKeyRef,
		IsActive:      active,
		CreatedAt:     time.Now().UTC(),
		RotatesAt:     ptrTime(rotatesAt.UTC()),
	}
}
