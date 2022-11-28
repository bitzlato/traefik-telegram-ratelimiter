// Package traefik_telegram_ratelimiter implements a rate limiting middleware based on messages' telegram ids
package traefik_telegram_ratelimiter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const defaultHitTableSize = 50000

var (
	ErrUnknownMessageFormat = errors.New("unknown incoming telegram message format")
	ErrInvalidHitTableSize  = errors.New("hit table size cannot be 0 or less")
)

var (
	loggerInfo  = log.New(os.Stdout, "INFO: TelegramRateLimiterPlugin: ", log.Ldate|log.Ltime)
	loggerError = log.New(os.Stderr, "ERROR: TelegramRateLimiterPlugin: ", log.Ldate|log.Ltime)
)

// Config holds configuration to pass to the plugin
type Config struct {
	// HitTableSize defined the max size of the hit table
	HitTableSize int `json:"hitMapSize,omitempty" yaml:"hitMapSize,omitempty" toml:"hitMapSize,omitempty" export:"true"`
	// Limit defines the hit limit for regular account ids. -1 defines infinite limit.
	Limit int32 `json:"limit,omitempty" yaml:"limit,omitempty" toml:"limit:omitempty" export:"true"`
	// WhitelistLimit defines hit limit for whitelisted account ids. -1 defines infinite limit.
	WhitelistLimit int32 `json:"whitelistLimit,omitempty" yaml:"whitelistLimit,omitempty" toml:"whitelistLimit,omitempty" export:"true"`
	// Expire is a number in seconds to keep the hit record for a single id
	Expire int64 `json:"expire,omitempty" yaml:"expire,omitempty" toml:"expire,omitempty" export:"true"`
	// Whitelist is a path to the file with whitelisted ids. Each id on separate line
	Whitelist *string `json:"whitelist,omitempty" yaml:"whitelist,omitempty" toml:"whitelist,omitempty" export:"true"`
	// Blacklist is a path to the file with blacklisted ids.
	// IDs from blacklist are mutely ignored without counting hits
	Blacklist *string `json:"blacklist,omitempty" yaml:"blacklist,omitempty" toml:"blacklist,omitempty" export:"true"`
}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{
		HitTableSize:   defaultHitTableSize,
		Limit:          -1,
		WhitelistLimit: -1,
		Expire:         86400, // 24 hours
	}
}

// rateLimiter implements rate limiting with a set of tocken buckets;
type rateLimiter struct {
	next http.Handler
	name string
	// expire time in seconds of the hit record
	expire int64
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
	if config.HitTableSize <= 0 {
		return nil, ErrInvalidHitTableSize
	}

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
		expire:    config.Expire,
		limit:     config.Limit,
		wlLimit:   config.WhitelistLimit,
		whitelist: wl,
		blacklist: bl,
		hits:      newExpiryMap(config.HitTableSize),
	}, nil
}

func (r *rateLimiter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var buf bytes.Buffer
	tee := io.TeeReader(req.Body, &buf)
	tgID, err := extractTgID(tee)
	// skip rate limiting if failed to retrieve tg ID
	if err != nil {
		loggerError.Printf("error retrieving telegram id: %v", err)
		r.next.ServeHTTP(rw, req)
		return
	}

	// if id is blacklisted skip handling and return 200 OK
	if _, ok := r.blacklist[tgID]; ok {
		loggerInfo.Printf("rejecting blacklisted id: %d", tgID)
		silentReject(rw)
		return
	}

	_, isWl := r.whitelist[tgID]
	hits := r.hits.incNGet(tgID, r.expire)

	// if is whitelisted tg id check wlLimit
	if isWl {
		if r.wlLimit >= 0 && hits > r.wlLimit {
			loggerInfo.Printf("rejecting whitelisted id: %d, limit: %d, hits: %d", tgID, r.wlLimit, hits)
			silentReject(rw)
			return
		}
	} else if r.limit >= 0 && hits > r.limit {
		loggerInfo.Printf("rejecting regular id: %d, limit: %d, hits: %d", tgID, r.limit, hits)
		silentReject(rw)
		return
	}
	r.next.ServeHTTP(rw, req)
}

func silentReject(rw http.ResponseWriter) {
	rw.Header().Add("Content-Type", "text/plain")
	rw.Header().Add("Connection", "keep-alive")
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
	abs, err := filepath.Abs(fp)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ret := make(map[int64]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if id, err := strconv.ParseInt(line, 10, 64); err == nil {
			ret[id] = struct{}{}
		}
	}
	return ret, nil
}

type expiryHits struct {
	id      int64
	hits    int32
	expires int64
}

type expiryMap struct {
	mu sync.Mutex
	// max hit table cap
	cap int
	// map telegram id to the index in the `hits` slice
	idxs map[int64]int
	// circular queue keeping records about hits and expiration times
	hits []expiryHits
	// starting index and the size of the `hits` circular array
	head, size int
}

func newExpiryMap(capacity int) *expiryMap {
	return &expiryMap{
		mu:   sync.Mutex{},
		cap:  capacity,
		idxs: make(map[int64]int, capacity),
		hits: make([]expiryHits, capacity),
		head: 0,
		size: 0,
	}
}

// incNGet returns number of hits by the specified telegram id
func (e *expiryMap) incNGet(id int64, expire int64) int32 {
	e.mu.Lock()
	defer e.mu.Unlock()

	idx, ok := e.idxs[id]
	// when the record does not exist
	if !ok {
		e.insert(expiryHits{id, 1, time.Now().UTC().Unix() + expire})
		return 1
	}
	// when the record exists but has expired
	if e.hits[idx].expires < time.Now().UTC().Unix() {
		e.insert(expiryHits{id, 1, time.Now().UTC().Unix() + expire})
		return 1
	}

	e.hits[idx].hits++
	return e.hits[idx].hits
}

// full return wether the circular queue is full
func (e *expiryMap) full() bool {
	return e.size == e.cap
}

// free removes one item from the start of the circular queue
// and the corresponding id mapping
func (e *expiryMap) free(count int) {
	for i := 0; i < count; i++ {
		if e.size == 0 {
			break
		}
		id := e.hits[e.head].id
		delete(e.idxs, id)
		e.head = (e.head + 1) % e.cap
		e.size--
	}
}

// insert inserts one item into the circular queue
// and inserts corresponding id mapping
func (e *expiryMap) insert(h expiryHits) {
	if e.full() {
		e.free(1)
	}

	idx := (e.head + e.size) % e.cap
	e.idxs[h.id] = idx
	e.hits[idx] = h
	e.size++
}
