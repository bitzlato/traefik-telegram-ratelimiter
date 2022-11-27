// Package traefik_telegram_ratelimiter implements a rate limiting middleware based on messages' telegram ids
package traefik_telegram_ratelimiter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

const defaultHitMapSize = 50000

var ErrUnknownMessageFormat = errors.New("unknown incoming telegram message format")

// Config holds configuration to pass to the plugin
type Config struct {
	// HitMapSize defined the max size of the hit table
	HitMapSize int `json:"hitMapSize,omitempty" yaml:"hitMapSize,omitempty" toml:"hitMapSize,omitempty" export:"true"`
	// Limit defines the hit limit for regular account ids. -1 defines infinite limit.
	Limit int32 `json:"limit,omitempty" yaml:"limit,omitempty" toml:"limit:omitempty" export:"true"`
	// WhitelistLimit defines hit limit for whitelisted account ids. -1 defines infinite limit.
	WhitelistLimit int32 `json:"whitelistLimit,omitempty" yaml:"whitelistLimit,omitempty" toml:"whitelistLimit,omitempty" export:"true"`
	// TTL is a number in seconds to keep the hit record for a single id
	TTL time.Duration `json:"ttl,omitempty" yaml:"ttl,omitempty" toml:"ttl,omitempty" export:"true"`
	// Whitelist is a path to the file with whitelisted ids. Each id on separate line
	Whitelist *string `json:"whitelist,omitempty" yaml:"whitelist,omitempty" toml:"whitelist,omitempty" export:"true"`
	// Blacklist is a path to the file with blacklisted ids.
	// IDs from blacklist are mutely ignored without counting hits
	Blacklist *string `json:"blacklist,omitempty" yaml:"blacklist,omitempty" toml:"blacklist,omitempty" export:"true"`
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
	// whitelisted telegram ids
	whitelist map[int64]struct{}
	// blacklisted telegram ids
	blacklist map[int64]struct{}
	// hits map
	hits *expiryMap
}

// New instantiates and returns the required components used to handle a HTTP request
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var err error
	var wl, bl map[int64]struct{}
	if config.Whitelist != nil {
		wl, err = readIDList(*config.Whitelist)
		if err != nil {
			return nil, err
		}
	}

	if config.Blacklist != nil {
		bl, err = readIDList(*config.Blacklist)
		if err != nil {
			return nil, err
		}
	}

	return &rateLimiter{
		next:      next,
		name:      name,
		ttl:       config.TTL,
		limit:     config.Limit,
		wlLimit:   config.WhitelistLimit,
		whitelist: wl,
		blacklist: bl,
		hits:      newExpiryMap(config.HitMapSize),
	}, nil
}

func (r *rateLimiter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var buf bytes.Buffer
	tee := io.TeeReader(req.Body, &buf)
	tgID, err := extractTgID(tee)
	// skip rate limiting if failed to retrieve tg ID
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("error retrieving telegram id: %v", err))
		r.next.ServeHTTP(rw, req)
		return
	}

	// if id is blacklisted skip handling and return 200 OK
	if _, ok := r.blacklist[tgID]; ok {
		os.Stdout.WriteString(fmt.Sprintf("rejecting blacklisted id: %d", tgID))
		silentReject(rw)
		return
	}

	_, isWl := r.whitelist[tgID]
	hits := r.hits.incNGet(tgID)

	// if is whitelisted tg id check wlLimit
	if isWl {
		if r.wlLimit >= 0 && hits > r.wlLimit {
			os.Stdout.WriteString(fmt.Sprintf("rejecting whitelisted id: %d, limit: %d, hits: %d", tgID, r.wlLimit, hits))
			silentReject(rw)
			return
		}
	} else if r.limit >= 0 && hits > r.limit {
		os.Stdout.WriteString(fmt.Sprintf("rejecting regular id: %d, limit: %d, hits: %d", tgID, r.limit, hits))
		silentReject(rw)
		return
	}
	r.next.ServeHTTP(rw, req)
}

func silentReject(rw http.ResponseWriter) {
	rw.Header().Add("Content-Type", "text/plain")
	rw.Write([]byte(http.StatusText(http.StatusOK)))
}

type tgMsg struct {
	Message struct {
		From struct {
			ID *int64 `json:"id"`
		} `json:"from"`
	} `json:"message"`
	CBQuery struct {
		From struct {
			ID *int64 `json:"id"`
		} `json:"from"`
	} `json:"callback_query"`
}

func extractTgID(r io.Reader) (int64, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}

	var tgMsg tgMsg
	err = json.Unmarshal(body, &tgMsg)
	if err != nil {
		return 0, err
	}

	if tgMsg.Message.From.ID != nil {
		return *tgMsg.Message.From.ID, nil
	} else if tgMsg.CBQuery.From.ID != nil {
		return *tgMsg.CBQuery.From.ID, nil
	}

	return 0, ErrUnknownMessageFormat
}

func readIDList(fp string) (map[int64]struct{}, error) {
	return nil, nil
}

type expiryItem struct {
	id      int64
	expires int64
}

type expiryMap struct {
	mu sync.Mutex
	// max hit table capacity
	capacity int
	hits     map[int64]int32
	// circular array keeping records about hit expiration times
	expires []expiryItem
	// starting and ending indexes of the `expires` circular array
	st, end uint32
}

func newExpiryMap(capacity int) *expiryMap {
	return &expiryMap{
		mu:       sync.Mutex{},
		capacity: capacity,
		hits:     make(map[int64]int32, capacity),
		expires:  make([]expiryItem, capacity),
		st:       0,
		end:      0,
	}
}

// incNGet returns number of hits by the specified telegram id
func (e *expiryMap) incNGet(id int64) int32 {
	e.mu.Lock()
	defer e.mu.Lock()

	return 1
}
