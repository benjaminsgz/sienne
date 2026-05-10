package crypto

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

type KeySyncBroadcaster struct {
	rdb     *redis.Client
	channel string
}

func NewKeySyncBroadcaster(rdb *redis.Client, keyPrefix string) *KeySyncBroadcaster {
	if keyPrefix == "" {
		keyPrefix = "idp"
	}
	return &KeySyncBroadcaster{
		rdb:     rdb,
		channel: keyPrefix + ":jwks:rotated",
	}
}

func (b *KeySyncBroadcaster) Publish(ctx context.Context) error {
	if b == nil || b.rdb == nil {
		return nil
	}
	payload := fmt.Sprintf("%d", time.Now().UnixMilli())
	return b.rdb.Publish(ctx, b.channel, payload).Err()
}

func (b *KeySyncBroadcaster) Subscribe(ctx context.Context, manager *KeyManager, repo rotationRepository, workingDir string) {
	if b == nil || b.rdb == nil || manager == nil || repo == nil {
		return
	}

	go func() {
		pubsub := b.rdb.Subscribe(ctx, b.channel)
		defer func() { _ = pubsub.Close() }()

		debounce := time.NewTimer(0)
		if !debounce.Stop() {
			<-debounce.C
		}
		pending := false

		ch := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				debounce.Stop()
				return
			case _, ok := <-ch:
				if !ok {
					return
				}
				if !pending {
					debounce.Reset(500 * time.Millisecond)
					pending = true
				}
			case <-debounce.C:
				pending = false
				loadCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				refreshed, err := LoadKeyManagerFromRepository(loadCtx, repo, workingDir)
				cancel()
				if err != nil {
					log.Printf("[key_sync] reload keys after broadcast: %v", err)
					continue
				}
				manager.ReplaceWith(refreshed)
			}
		}
	}()
}
