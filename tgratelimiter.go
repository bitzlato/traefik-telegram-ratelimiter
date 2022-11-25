// Package traefik_telegram_ratelimiter implements a rate limiting middleware based on messages' telegram ids
package traefik_telegram_ratelimiter

import (
	"context"
	"net/http"
	"sync"
	"time"
)

const defaultHitMapSize = 50000

// Config holds configuration to pass to the plugin
type Config struct {
	HitMapSize     uint32
	Limit          int32
	WhitelistLimit int32
	TTL            time.Duration
	Whitelist      *string
	Blacklist      *string
}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{
		HitMapSize:     defaultHitMapSize,
		Limit:          -1,
		WhitelistLimit: -1,
		TTL:            time.Duration(24) * time.Hour, // 24 hours
	}
}

// rateLimiter implements rate limiting with a set of tocken buckets;
type rateLimiter struct {
	next http.Handler
	name string
	// ttl of the hit record
	ttl time.Duration
	// maximum hits limit
	limit int32
	// whitelist limit
	wlLimit int32
	// whitelist bst
	whitelist map[int64]struct{}
	// blacklist bst
	blacklist map[int64]struct{}
	// hits map
	hits map[int64]uint32
	// expire times map
	expiry map[int64]uint32
	mu     sync.Mutex
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	return &rateLimiter{
		next: next,
		name: name,
		mu:   sync.Mutex{},
	}, nil
}

func (r *rateLimiter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	r.next.ServeHTTP(rw, req)
}
