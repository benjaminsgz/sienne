package redis

import (
	"github.com/redis/go-redis/v9"
)

func NewClient(addr, password string, db int) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
}

func NewFailoverClient(masterName string, sentinelAddrs []string, password string, db int) *redis.Client {
	return redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:       masterName,
		SentinelAddrs:    sentinelAddrs,
		SentinelPassword: password,
		Password:         password,
		DB:               db,
	})
}
