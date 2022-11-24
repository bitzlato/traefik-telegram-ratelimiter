package traefik_telegram_ratelimiter

import (
	"context"
	"net/http"
)

// Config holds configuration to pass to the plugin
type Config struct{}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{}
}

// RateLimiter holds the necessary components of a Traefik plugin
type RateLimiter struct {
	next http.Handler
	name string
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &RateLimiter{
		next: next,
		name: name,
	}, nil
}

func (rl *RateLimiter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rl.next.ServeHTTP(w, r)
}
