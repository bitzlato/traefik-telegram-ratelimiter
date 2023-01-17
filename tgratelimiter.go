// Package traefik_telegram_ratelimiter implements a rate limiting middleware based on messages' telegram ids
package traefik_telegram_ratelimiter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultHitTableSize = 50000
const defaultExpire = 86400 // 24 hours
const isDeletedID int64 = -1 << 63

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
	HitTableSize int `json:"hitTableSize,omitempty" yaml:"hitTableSize,omitempty" toml:"hitTableSize,omitempty"`
	// Limit defines the hit limit for regular account ids. -1 defines infinite limit.
	Limit int32 `json:"limit,omitempty" yaml:"limit,omitempty" toml:"limit,omitempty"`
	// WhitelistLimit defines hit limit for whitelisted account ids. -1 defines infinite limit.
	WhitelistLimit int32 `json:"whitelistLimit,omitempty" yaml:"whitelistLimit,omitempty" toml:"whitelistLimit,omitempty"`
	// Expire is a number in seconds to keep the hit record for a single id
	Expire int64 `json:"expire,omitempty" yaml:"expire,omitempty" toml:"expire,omitempty"`
	// Whitelist is a path to the file with whitelisted ids. Each id on separate line
	Whitelist *string `json:"whitelist,omitempty" yaml:"whitelist,omitempty" toml:"whitelist,omitempty"`
	// Whitelist URL to load the list with whitelisted ids from. The same format as for the file
	WhitelistURL *string `json:"whitelistURL,omitempty" yaml:"whitelistURL,omitempty" toml:"whitelistURL,omitempty"`
	// Blacklist is a path to the file with blacklisted ids.
	// IDs from blacklist are mutely ignored without counting hits
	Blacklist *string `json:"blacklist,omitempty" yaml:"blacklist,omitempty" toml:"blacklist,omitempty"`
	// BlacklistURL
	BlacklistURL *string `json:"blacklistURL,omitempty" yaml:"blacklistURL,omitempty" toml:"blacklistURL,omitempty"`
	// enable http management server
	Console bool `json:"console" yaml:"console" toml:"console"`
	// management server address
	ConsoleAddress *string `json:"consoleAddress" yaml:"consoleAddress" toml:"consoleAddress"`
}

// CreateConfig populates the Config data object
func CreateConfig() *Config {
	return &Config{
		HitTableSize:   defaultHitTableSize,
		Limit:          -1,
		WhitelistLimit: -1,
		Expire:         defaultExpire,
	}
}

// rateLimiter implements rate limiting with a set of tocken buckets;
type rateLimiter struct {
	next   http.Handler
	config *Config
	rwmu   sync.RWMutex
	name   string
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

	r := &rateLimiter{
		next:    next,
		config:  config,
		name:    name,
		expire:  config.Expire,
		limit:   config.Limit,
		wlLimit: config.WhitelistLimit,
		hits:    newExpiryMap(config.HitTableSize),
	}

	r.updateLists()

	if config.Console {
		err := r.startManagement(*config.ConsoleAddress)
		if err != nil {
			loggerError.Printf("failed to start management server: %s", err.Error())
			return nil, err
		}
	}

	return r, nil
}

func (r *rateLimiter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var buf bytes.Buffer
	tee := io.TeeReader(req.Body, &buf)
	tgID, err := extractTgID(tee)
	req.Body = io.NopCloser(&buf)
	// skip rate limiting if failed to retrieve tg ID
	if err != nil {
		loggerError.Printf("error retrieving telegram id: %v", err)
		r.next.ServeHTTP(rw, req)
		return
	}

	if r.rejectedTgID(tgID) {
		silentReject(rw)
		return
	}

	r.next.ServeHTTP(rw, req)
}

func (r *rateLimiter) rejectedTgID(tgID int64) bool {
	r.rwmu.RLock()
	defer r.rwmu.RUnlock()
	// if id is blacklisted skip handling and return 200 OK
	if _, ok := r.blacklist[tgID]; ok {
		loggerInfo.Printf("rejecting blacklisted id: %d", tgID)
		return true
	}

	_, isWl := r.whitelist[tgID]
	hits := r.hits.incNGet(tgID, r.expire)

	// if is whitelisted tg id check wlLimit
	if isWl {
		if r.wlLimit >= 0 && hits > r.wlLimit {
			loggerInfo.Printf("rejecting whitelisted id: %d, limit: %d, hits: %d", tgID, r.wlLimit, hits)
			return true
		}
	} else if r.limit >= 0 && hits > r.limit {
		loggerInfo.Printf("rejecting regular id: %d, limit: %d, hits: %d", tgID, r.limit, hits)
		return true
	}

	return false
}

func (r *rateLimiter) updateLists() error {
	wl := make(map[int64]struct{}, 1024)
	bl := make(map[int64]struct{}, 1024)
	if r.config.Whitelist != nil {
		err := readIDFile(*r.config.Whitelist, wl)
		if err != nil {
			return err
		}
	}

	if r.config.WhitelistURL != nil {
		err := readIDURL(*r.config.WhitelistURL, wl)
		if err != nil {
			return err
		}
	}

	if r.config.Blacklist != nil {
		err := readIDFile(*r.config.Blacklist, bl)
		if err != nil {
			return err
		}
	}

	if r.config.BlacklistURL != nil {
		err := readIDURL(*r.config.BlacklistURL, bl)
		if err != nil {
			return err
		}
	}

	loggerInfo.Printf("updating lists. wl recs: %d, bl recs: %d", len(wl), len(bl))
	r.rwmu.Lock()
	defer r.rwmu.Unlock()
	r.whitelist = wl
	r.blacklist = bl

	return nil
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

func readIDFile(fp string, m map[int64]struct{}) error {
	abs, err := filepath.Abs(fp)
	if err != nil {
		return err
	}

	file, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer file.Close()

	scanIDs(file, m)
	return nil
}

func readIDURL(url string, m map[int64]struct{}) error {
	res, err := http.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	scanIDs(res.Body, m)
	return nil
}

func scanIDs(r io.Reader, m map[int64]struct{}) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if id, err := strconv.ParseInt(line, 10, 64); err == nil {
			m[id] = struct{}{}
		}
	}
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

// incNGet increments and returns number of hits of the specified telegram id
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
		// delete the id mapping and mark the queue record id
		// as deleted so when the head of the queue gets to
		// the record it will not remove the newly created mapping
		delete(e.idxs, id)
		e.hits[idx].id = isDeletedID

		e.insert(expiryHits{id, 1, time.Now().UTC().Unix() + expire})
		return 1
	}

	e.hits[idx].hits++
	return e.hits[idx].hits
}

// get returns numbers of hits of the specified telegram id
func (e *expiryMap) get(id int64) int32 {
	e.mu.Lock()
	defer e.mu.Unlock()

	idx, ok := e.idxs[id]
	if !ok {
		return 0
	}

	if e.hits[idx].expires < time.Now().UTC().Unix() {
		return 0
	}

	return e.hits[idx].hits
}

// reset resets hit counter for the specified telegram id
// returns wether the id was found in the map
func (e *expiryMap) reset(id int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	idx, ok := e.idxs[id]
	if ok {
		e.hits[idx].hits = 0
	}

	return ok
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
		// isDeletedID means the id mapping has been deleted already
		if id != isDeletedID {
			delete(e.idxs, id)
			e.hits[e.head].id = isDeletedID
		}
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

// list returns all recorded hits
func (e *expiryMap) list() map[int64]int32 {
	e.mu.Lock()
	defer e.mu.Unlock()

	m := make(map[int64]int32, e.size)
	for i := 0; i < e.size; i++ {
		j := (e.head + i) % e.cap
		m[e.hits[j].id] = e.hits[j].hits
	}
	return m
}

func (r *rateLimiter) startManagement(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", r.serveManagement)
		err = http.Serve(l, mux)
		loggerError.Printf("management server finished. error: %s", err.Error())
	}()

	loggerInfo.Printf("management server is running on: %s", l.Addr().String())
	return nil
}

func (r *rateLimiter) serveManagement(res http.ResponseWriter, req *http.Request) {
	p := strings.Split(req.URL.Path, "/")[1:]
	n := len(p)

	switch {
	case n == 1 && p[0] == "reload" && req.Method == http.MethodPost:
		r.updateLists()
		res.WriteHeader(http.StatusNoContent)
	case n == 1 && p[0] == "hits" && req.Method == http.MethodGet:
		var data bytes.Buffer
		for k, v := range r.hits.list() {
			data.WriteString(fmt.Sprintf("%d %d\n", k, v))
		}
		res.Write(data.Bytes())
	case n == 2 && p[0] == "hits":
		id, err := parseTgID(p[1])
		if err != nil {
			http.Error(res, "400 bad request", http.StatusBadRequest)
			return
		}
		switch req.Method {
		case http.MethodGet: // show hits
			hits := r.hits.get(id)
			res.Write([]byte(strconv.Itoa(int(hits))))
		case http.MethodDelete: // reset hits
			r.hits.reset(id)
			res.WriteHeader(http.StatusNoContent)
		}
	case n == 3 && p[0] == "list":
		id, err := parseTgID(p[2])
		if err != nil {
			http.Error(res, "400 bad request", http.StatusBadRequest)
			return
		}

		var m map[int64]struct{}
		switch p[1] {
		case "bl":
			m = r.blacklist
		case "wl":
			m = r.whitelist
		default:
			http.Error(res, "400 bad request", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case http.MethodGet: // check id presence
			var result string
			_, ok := m[id]
			if ok {
				result = "true"
			} else {
				result = "false"
			}
			res.Write([]byte(result + "\n"))
		case http.MethodDelete: // remove from list
			delete(m, id)
			res.WriteHeader(http.StatusNoContent)
		case http.MethodPut: // add to list
			m[id] = struct{}{}
			res.WriteHeader(http.StatusCreated)
		default:
			res.Header().Add("Allow", "GET, PUT, DELETE")
			http.Error(res, "405 method not allowed", http.StatusMethodNotAllowed)
		}
	case n == 1 && (p[0] == "limit" || p[0] == "wllimit"):
		switch req.Method {
		case http.MethodPut:
			body, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(res, "500 internal server error", http.StatusInternalServerError)
				return
			}

			limit, err := strconv.ParseInt(string(body), 10, 32)
			if err != nil {
				http.Error(res, "400 bad request", http.StatusBadRequest)
				return
			}

			r.rwmu.Lock()
			defer r.rwmu.Unlock()
			if p[0] == "limit" {
				r.limit = int32(limit)

			} else {
				r.wlLimit = int32(limit)
			}
			res.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			r.rwmu.RLock()
			defer r.rwmu.RUnlock()
			var result int32
			if p[0] == "limit" {
				result = r.limit

			} else {
				result = r.wlLimit
			}
			res.Write([]byte(fmt.Sprintf("%d", result)))
		default:
			res.Header().Add("Allow", "GET, PUT")
			http.Error(res, "405 method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(res, req)
	}
}

func parseTgID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse telegram id: %s", s)
	}
	return id, nil
}
