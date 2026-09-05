// Package ratelimit provides in-memory HTTP rate-limiting middleware built on
// golang.org/x/time/rate.
//
// It is designed specifically for single-VM, containerized, or standalone server
// deployments requiring lightweight, robust, and zero-dependency rate limiting.
//
// Two primary entry points are provided:
//   - New: Applies a single shared rate limiter across all incoming requests.
//   - NewWithConfig: Supports per-client token buckets partitioned in an in-memory
//     sharded LRU store with configurable keys (e.g., IP address, headers, or
//     auth context), dynamic policies, weighted token costs, and telemetry hooks.
package gocap

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/maphash"
	"math"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Middleware wraps an HTTP handler with rate-limiting enforcement.
type Middleware func(http.Handler) http.Handler

// KeyFunc extracts a rate-limiting key from an incoming HTTP request.
// It must return a stable, consistent identifier (e.g. client IP or API key).
//
// Returning an empty string ("") indicates that the request should bypass rate
// limiting entirely. Keys exceeding Config.MaxKeyLength are canonicalized to a
// SHA-256 digest before storage to prevent memory exhaustion.
type KeyFunc func(*http.Request) string

// PolicyFunc dynamically determines the refill Limit and Burst capacity for a
// request (e.g. based on authenticated user tier or route).
//
// If enabled is false, rate limiting is bypassed for the request.
// If enabled is true, limit must be non-negative and burst must be greater than zero.
type PolicyFunc func(*http.Request) (limit rate.Limit, burst int, enabled bool)

// Config defines the rate-limiting policy and storage behavior for NewWithConfig.
type Config struct {
	// Limit is the sustained refill rate in tokens per second (e.g., 10 or rate.Every(time.Minute)).
	Limit rate.Limit

	// Burst is the maximum burst capacity (maximum tokens a bucket can hold).
	// Must be greater than zero unless PolicyFunc is provided.
	Burst int

	// KeyFunc extracts the bucket key from an *http.Request. If nil, all requests
	// share one global bucket. Returning "" bypasses limiting for that request.
	KeyFunc KeyFunc

	// PolicyFunc dynamically overrides Limit and Burst per request. When provided,
	// its returned Limit and Burst replace the static fields. Invalid results fail closed.
	PolicyFunc PolicyFunc

	// CostFunc determines the number of tokens consumed by a request.
	// Defaults to 1 if nil or if a negative number is returned.
	// Returning 0 allows "free" requests without consuming bucket tokens.
	CostFunc func(*http.Request) int

	// SkipFunc returns true if rate limiting should be bypassed entirely for this request
	// (e.g. for health checks or Prometheus scrape endpoints).
	SkipFunc func(*http.Request) bool

	// EntryTTL is the idle duration after which an inactive client bucket becomes
	// eligible for eviction. Defaults to 10 minutes if zero.
	EntryTTL time.Duration

	// CleanupInterval controls how often idle/expired buckets are swept.
	// Defaults to 1 minute if zero.
	CleanupInterval time.Duration

	// MaxEntries caps the total number of retained client buckets across all shards.
	// Defaults to 100,000. When reached, least-recently-used (LRU) buckets are evicted.
	MaxEntries int

	// MaxKeyLength is the maximum key length stored verbatim. Keys exceeding this
	// length are hashed with SHA-256. Defaults to 1024 bytes; minimum is 64 bytes.
	MaxKeyLength int

	// DisableHeaders suppresses the standard RateLimit-Limit, RateLimit-Remaining,
	// and RateLimit-Reset response headers.
	DisableHeaders bool

	// OnAllowed is called when a request is successfully permitted.
	// Deprecated: prefer OnDecision.
	OnAllowed func(*http.Request)

	// OnDecision is a synchronous telemetry hook invoked after every rate-limit
	// decision (both allowed and rejected). It must not block.
	OnDecision func(*http.Request, Decision)

	// OnRejected writes custom rejection responses for 429 Too Many Requests.
	// If nil, standard RFC 7807 problem detail JSON or plain text is written.
	OnRejected func(http.ResponseWriter, *http.Request)
}

// Decision describes the outcome of an evaluated rate-limit decision.
type Decision struct {
	// Allowed is true if the request was permitted to proceed.
	Allowed bool

	// Limit is the effective refill rate in tokens per second.
	Limit rate.Limit

	// Burst is the effective maximum token capacity.
	Burst int

	// Remaining is the number of available tokens left in the bucket.
	Remaining int

	// Reset is the number of seconds until the bucket is refilled to full burst capacity.
	// Conforms to the IETF RateLimit-Reset header specification.
	Reset int

	// RetryAfter is the number of seconds until enough tokens (equal to request cost)
	// are available to admit a rejected request. Zero if the request was allowed
	// or if the request is unfulfillable.
	RetryAfter int

	// Unfulfillable is true if the requested cost exceeds the bucket's Burst capacity
	// and can therefore never be admitted regardless of wait time.
	Unfulfillable bool
}

const (
	defaultEntryTTL        = 10 * time.Minute
	defaultCleanupInterval = time.Minute
	defaultMaxEntries      = 100000
	defaultMaxKeyLength    = 1024
	numShards              = 64
)

// bucketNode represents an individual client's rate-limiter bucket within a shard.
// It is stored in both the shard's hash map and its LRU doubly-linked list.
type bucketNode struct {
	// mu serializes rate policy updates, token consumption (AllowN), and decision
	// snapshot calculation atomically for this specific bucket.
	mu       sync.Mutex
	key      string
	limiter  *rate.Limiter
	lastUsed time.Time
	prev     *bucketNode
	next     *bucketNode
}

// shard maintains an independent partition of keyed buckets protected by its own mutex.
// Partitioning into shards eliminates global lock contention under concurrent load.
type shard struct {
	mu          sync.Mutex
	buckets     map[string]*bucketNode
	head        *bucketNode // Most recently used entry
	tail        *bucketNode // Least recently used entry (candidate for eviction)
	limit       rate.Limit
	burst       int
	ttl         time.Duration
	cleanupEach time.Duration
	maxEntries  int
	lastCleanup time.Time
}

// shardedStore coordinates multiple shards to distribute memory and lock overhead.
type shardedStore struct {
	shards       [numShards]*shard
	activeShards uint64
	seed         maphash.Seed // Hardware-accelerated, randomized per-store seed
}

// newShardedStore initializes the sharded store, dividing the global MaxEntries
// quota evenly across shards and setting up per-shard eviction boundaries.
func newShardedStore(config Config) *shardedStore {
	active := min(config.MaxEntries, numShards)
	if active <= 0 {
		active = 1
	}

	store := &shardedStore{
		activeShards: uint64(active),
		seed:         maphash.MakeSeed(),
	}

	for i := 0; i < active; i++ {
		// Split capacity evenly so the sum of shard capacities equals MaxEntries.
		shardMax := config.MaxEntries / numShards
		if i < config.MaxEntries%numShards {
			shardMax++
		}
		store.shards[i] = &shard{
			buckets:     make(map[string]*bucketNode),
			limit:       config.Limit,
			burst:       config.Burst,
			ttl:         config.EntryTTL,
			cleanupEach: config.CleanupInterval,
			maxEntries:  shardMax,
		}
	}
	return store
}

// remove unlinks a bucketNode from the shard's doubly-linked list and deletes it from the map.
// Must be called with s.mu locked.
func (s *shard) remove(node *bucketNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		s.head = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		s.tail = node.prev
	}
	node.prev = nil
	node.next = nil
	delete(s.buckets, node.key)
}

// pushFront inserts a new node at the head of the list (most recently used).
// Must be called with s.mu locked.
func (s *shard) pushFront(node *bucketNode) {
	node.prev = nil
	node.next = s.head
	if s.head != nil {
		s.head.prev = node
	}
	s.head = node
	if s.tail == nil {
		s.tail = node
	}
}

// moveToFront moves an existing node to the head of the list when accessed.
// Must be called with s.mu locked.
func (s *shard) moveToFront(node *bucketNode) {
	if s.head == node {
		return // Already at the head
	}
	if node.prev != nil {
		node.prev.next = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	}
	if s.tail == node {
		s.tail = node.prev
	}
	node.prev = nil
	node.next = s.head
	if s.head != nil {
		s.head.prev = node
	}
	s.head = node
}

// removeExpiredLocked evicts buckets from the tail of the list that have exceeded TTL.
// Because nodes are ordered from oldest (tail) to newest (head), expired entries
// are always clustered at the tail. Must be called with s.mu locked.
func (s *shard) removeExpiredLocked(now time.Time) {
	if now.Sub(s.lastCleanup) < s.cleanupEach {
		return
	}
	for s.tail != nil && now.Sub(s.tail.lastUsed) >= s.ttl {
		s.remove(s.tail)
	}
	s.lastCleanup = now
}

// bucketFor retrieves or creates a bucketNode for the given key in this shard.
// It also performs opportunistic local cleanup and cross-shard sweeps.
func (s *shard) bucketFor(now time.Time, key string, limit rate.Limit, burst int, store *shardedStore) (*bucketNode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Periodic opportunistic expiration
	if now.Sub(s.lastCleanup) >= s.cleanupEach {
		s.removeExpiredLocked(now)
		if store != nil {
			store.sweepIdleShards(now, s)
		}
	}

	// 2. Cache Hit: update access timestamp and bump to head of LRU list
	if node, ok := s.buckets[key]; ok {
		node.lastUsed = now
		s.moveToFront(node)
		return node, true
	}

	// 3. Cache Miss & Capacity Bound: evict LRU tail if shard is at capacity
	if len(s.buckets) >= s.maxEntries && s.tail != nil {
		s.remove(s.tail)
	}

	// 4. Determine initial limit/burst for newly allocated bucket.
	// Only fall back to shard defaults if strictly negative (preserving valid limit = 0).
	lim := limit
	bst := burst
	if lim < 0 {
		lim = s.limit
	}
	if bst <= 0 {
		bst = s.burst
	}

	limiter := rate.NewLimiter(lim, bst)
	node := &bucketNode{
		key:      key,
		limiter:  limiter,
		lastUsed: now,
	}
	s.buckets[key] = node
	s.pushFront(node)
	return node, true
}

// limiterFor is an internal helper retained for direct shard-level testing.
func (s *shard) limiterFor(now time.Time, key string, limit rate.Limit, burst int) (*rate.Limiter, bool) {
	node, ok := s.bucketFor(now, key, limit, burst, nil)
	if !ok {
		return nil, false
	}
	return node.limiter, true
}

// sweepIdleShards sweeps expired entries from other shards non-blockingly using TryLock.
// This prevents quiet shards from leaking memory after traffic bursts without requiring
// persistent background goroutines.
func (store *shardedStore) sweepIdleShards(now time.Time, current *shard) {
	for i := uint64(0); i < store.activeShards; i++ {
		sh := store.shards[i]
		if sh == nil || sh == current {
			continue
		}
		// Non-blocking attempt: skip if another goroutine is actively using this shard
		if sh.mu.TryLock() {
			sh.removeExpiredLocked(now)
			sh.mu.Unlock()
		}
	}
}

// bucketFor maps a key to its owning shard via hardware-accelerated maphash and returns its node.
func (store *shardedStore) bucketFor(now time.Time, key string, limit rate.Limit, burst int) (*bucketNode, bool) {
	shardIdx := maphash.String(store.seed, key) % store.activeShards
	return store.shards[shardIdx].bucketFor(now, key, limit, burst, store)
}

// resetAfter calculates the number of seconds until the limiter's token bucket
// is refilled to full burst capacity. Returns 0 if the bucket is already full
// or if the limiter has no refill rate.
func resetAfter(limiter *rate.Limiter, now time.Time, burst int) int {
	limit := limiter.Limit()
	if limit <= 0 || limit == rate.Inf {
		return 0
	}
	missing := float64(burst) - limiter.TokensAt(now)
	if missing <= 0 {
		return 0
	}
	return int(math.Ceil(missing / float64(limit)))
}

// retryAfter calculates the number of seconds until enough tokens (equal to cost)
// will be available in the bucket to admit the request. Returns 0 if cost is
// already available or if the limiter has no refill rate.
func retryAfter(limiter *rate.Limiter, now time.Time, cost int) int {
	limit := limiter.Limit()
	if limit <= 0 || limit == rate.Inf {
		return 0
	}
	missing := float64(cost) - limiter.TokensAt(now)
	if missing <= 0 {
		return 0
	}
	return int(math.Ceil(missing / float64(limit)))
}

// decide executes an atomic rate-limit check against a bucket.
// It synchronizes dynamic policy changes, evaluates token consumption, and
// captures a consistent snapshot of the resulting Decision.
func (node *bucketNode) decide(now time.Time, cost int, limit rate.Limit, burst int) Decision {
	node.mu.Lock()
	defer node.mu.Unlock()

	// Synchronize limiter settings if policy changed dynamically
	if node.limiter.Limit() != limit {
		node.limiter.SetLimitAt(now, limit)
	}
	if node.limiter.Burst() != burst {
		node.limiter.SetBurstAt(now, burst)
	}

	decision := Decision{Limit: limit, Burst: burst}

	// Cost exceeds burst capacity: request can never be fulfilled
	if cost > burst {
		decision.Unfulfillable = true
		decision.Remaining = int(math.Floor(math.Max(0, node.limiter.TokensAt(now))))
		decision.Reset = resetAfter(node.limiter, now, burst)
		return decision
	}

	// Attempt to consume tokens
	decision.Allowed = node.limiter.AllowN(now, cost)
	decision.Remaining = int(math.Floor(math.Max(0, node.limiter.TokensAt(now))))
	decision.Reset = resetAfter(node.limiter, now, burst)
	if !decision.Allowed {
		decision.RetryAfter = retryAfter(node.limiter, now, cost)
	}
	return decision
}

// New creates middleware using limiter as a single bucket shared across all requests.
// It panics if limiter is nil.
func New(limiter *rate.Limiter) Middleware {
	if limiter == nil {
		panic("ratelimit: nil limiter")
	}
	bucket := &bucketNode{limiter: limiter}
	return newMiddleware(Config{}, func(time.Time, *http.Request) (*bucketNode, rate.Limit, int, bool) {
		return bucket, limiter.Limit(), limiter.Burst(), true
	})
}

// NewWithConfig creates middleware according to the provided Config.
// It returns an error if the configuration is invalid.
func NewWithConfig(config Config) (Middleware, error) {
	err := validateConfig(config)
	if err != nil {
		return nil, err
	}

	// Optimization: static shared limiter case (no key resolution or dynamic policies needed)
	if config.KeyFunc == nil && config.PolicyFunc == nil {
		limiter := rate.NewLimiter(config.Limit, config.Burst)
		bucket := &bucketNode{limiter: limiter}
		return newMiddleware(config, func(time.Time, *http.Request) (*bucketNode, rate.Limit, int, bool) {
			return bucket, config.Limit, config.Burst, true
		}), nil
	}

	config = keyedDefaults(config)
	store := newShardedStore(config)
	invalidPolicyBucket := &bucketNode{limiter: rate.NewLimiter(0, 0)}

	return newMiddleware(config, func(now time.Time, r *http.Request) (*bucketNode, rate.Limit, int, bool) {
		key := "global"
		if config.KeyFunc != nil {
			key = config.KeyFunc(r)
			if key == "" {
				// Returning an empty key bypasses rate limiting
				return nil, 0, 0, false
			}
			key = canonicalKey(key, config.MaxKeyLength)
		}

		limit := config.Limit
		burst := config.Burst
		if config.PolicyFunc != nil {
			pLimit, pBurst, enabled := config.PolicyFunc(r)
			if !enabled {
				return nil, 0, 0, false
			}
			if pLimit < 0 || math.IsNaN(float64(pLimit)) || pBurst <= 0 {
				// Invalid runtime policy must fail closed (reject) rather than
				// accidentally inheriting another tenant's policy.
				return invalidPolicyBucket, 0, 0, true
			}
			limit, burst = pLimit, pBurst
		}

		bucket, found := store.bucketFor(now, key, limit, burst)
		return bucket, limit, burst, found
	}), nil
}

// validateConfig enforces configuration constraints at initialization.
func validateConfig(config Config) error {
	if config.Limit < 0 || math.IsNaN(float64(config.Limit)) {
		return errors.New("ratelimit: Limit must be non-negative")
	}
	if config.PolicyFunc == nil && config.Burst <= 0 {
		return errors.New("ratelimit: Burst must be greater than zero")
	}
	if config.Burst < 0 {
		return errors.New("ratelimit: Burst must be non-negative")
	}
	if config.EntryTTL < 0 || config.CleanupInterval < 0 {
		return errors.New("ratelimit: durations must be non-negative")
	}
	if config.MaxEntries < 0 {
		return errors.New("ratelimit: MaxEntries must be non-negative")
	}
	if config.MaxKeyLength != 0 && config.MaxKeyLength < sha256.Size*2 {
		return errors.New("ratelimit: MaxKeyLength must be at least 64 bytes")
	}
	return nil
}

// keyedDefaults populates fallback defaults for keyed store configuration.
func keyedDefaults(config Config) Config {
	if config.EntryTTL == 0 {
		config.EntryTTL = defaultEntryTTL
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = defaultCleanupInterval
	}
	if config.MaxEntries == 0 {
		config.MaxEntries = defaultMaxEntries
	}
	if config.MaxKeyLength == 0 {
		config.MaxKeyLength = defaultMaxKeyLength
	}
	return config
}

// canonicalKey limits key memory usage by hashing keys that exceed maxLength using SHA-256.
func canonicalKey(key string, maxLength int) string {
	if len(key) <= maxLength {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// newMiddleware constructs the final HTTP middleware handler wrapping next.
func newMiddleware(config Config, findBucket func(time.Time, *http.Request) (*bucketNode, rate.Limit, int, bool)) Middleware {
	return func(next http.Handler) http.Handler {
		if next == nil {
			panic("ratelimit: nil next handler")
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Fast path: context canceled by client before processing
			err := r.Context().Err()
			if err != nil {
				return
			}

			// 2. Fast path: explicit bypass filter (e.g. /healthz)
			if config.SkipFunc != nil && config.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			// 3. Resolve bucket and policy for this request
			now := time.Now()
			bucket, limit, burst, found := findBucket(now, r)
			if !found {
				// Empty key or PolicyFunc disabled -> bypass
				next.ServeHTTP(w, r)
				return
			}

			// 4. Calculate token cost (allowing 0 for free requests)
			cost := 1
			if config.CostFunc != nil {
				if c := config.CostFunc(r); c >= 0 {
					cost = c
				}
			}

			// 5. Execute atomic token-bucket decision
			decision := bucket.decide(now, cost, limit, burst)

			// 6. Set standard RateLimit-* headers
			if !config.DisableHeaders {
				writeRateLimitHeaders(w, decision)
			}

			// 7. Invoke telemetry hook synchronously
			if config.OnDecision != nil {
				config.OnDecision(r, decision)
			}

			// 8. Handle rejected requests
			if !decision.Allowed {
				writeRetryAfter(w, decision)
				writeRejection(w, r, config.OnRejected)
				return
			}

			// 9. Handle allowed requests
			if config.OnAllowed != nil {
				config.OnAllowed(r)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isJSONRequest checks if the request's Accept header asks for JSON or RFC 7807 problem details.
func isJSONRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "application/json") ||
		strings.Contains(accept, "application/problem+json") ||
		strings.Contains(accept, "+json")
}

// writeRejection writes a 429 response using either custom logic, RFC 7807 JSON, or plain text.
func writeRejection(w http.ResponseWriter, r *http.Request, custom func(http.ResponseWriter, *http.Request)) {
	w.Header().Set("Cache-Control", "private, no-store")
	if custom != nil {
		custom(w, r)
		return
	}
	if isJSONRequest(r) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"type":"https://tools.ietf.org/html/rfc6585#section-4","title":"Too Many Requests","status":429,"detail":"Rate limit exceeded. Please retry later."}`))
		return
	}
	http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
}

// writeRateLimitHeaders sets standard RateLimit-* response headers.
func writeRateLimitHeaders(w http.ResponseWriter, decision Decision) {
	w.Header().Set("RateLimit-Limit", strconv.Itoa(decision.Burst))
	w.Header().Set("RateLimit-Remaining", strconv.Itoa(decision.Remaining))
	w.Header().Set("RateLimit-Reset", strconv.Itoa(decision.Reset))
}

// writeRetryAfter sets the Retry-After header indicating wait seconds on 429 rejections.
func writeRetryAfter(w http.ResponseWriter, decision Decision) {
	if seconds := decision.RetryAfter; seconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
}

// parseIPString extracts and canonicalizes an IP from an address string which may or
// may not contain a port and enclosing brackets (e.g. "192.0.2.1:1234" or "[2001:db8::1]:443").
// It uses net/netip to achieve zero heap allocations on common paths.
func parseIPString(addrStr string) (netip.Addr, bool) {
	addrStr = strings.TrimSpace(addrStr)
	if addrStr == "" {
		return netip.Addr{}, false
	}
	// Fast path: host:port without heap allocation
	if ap, err := netip.ParseAddrPort(addrStr); err == nil {
		return ap.Addr().Unmap(), true
	}
	// Fast path: bare IP or [IPv6]
	bare := strings.Trim(addrStr, "[]")
	if addr, err := netip.ParseAddr(bare); err == nil {
		return addr.Unmap(), true
	}
	// Fallback: SplitHostPort for non-standard port or unparsable port strings
	if host, _, err := net.SplitHostPort(addrStr); err == nil && host != "" {
		if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			return addr.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// canonicalizeAddr formats an IP into a consistent rate-limiting key:
//   - IPv4 addresses are keyed by their exact 32-bit address.
//   - IPv6 addresses are grouped into their /64 routing prefix to mitigate
//     single-client address rotation and LRU thrashing.
func canonicalizeAddr(addr netip.Addr) string {
	if !addr.IsValid() {
		return "unknown"
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().Addr().String()
	}
	return addr.String()
}

// parseForwardedHeader extracts IP addresses from RFC 7239 Forwarded headers.
func parseForwardedHeader(header string) []net.IP {
	var ips []net.IP
	for element := range strings.SplitSeq(header, ",") {
		for param := range strings.SplitSeq(element, ";") {
			param = strings.TrimSpace(param)
			if strings.HasPrefix(strings.ToLower(param), "for=") {
				val := strings.TrimSpace(param[4:])
				val = strings.Trim(val, "\"")
				host, _, err := net.SplitHostPort(val)
				if err != nil || host == "" {
					host = val
				}
				host = strings.Trim(host, "[]")
				if ip := net.ParseIP(host); ip != nil {
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips
}

// KeyByIP groups requests by the client's IP address extracted from Request.RemoteAddr.
//
// IPv4 addresses are keyed by their full 32-bit address.
// IPv6 addresses are masked to their /64 routing prefix to mitigate address-rotation abuse.
// Requests with an unparseable address share the "unknown" key.
func KeyByIP(r *http.Request) string {
	addr, ok := parseIPString(r.RemoteAddr)
	if !ok {
		return "unknown"
	}
	return canonicalizeAddr(addr)
}

// KeyByHeader returns a KeyFunc that extracts the rate-limiting key from the specified
// HTTP header (e.g., "X-API-Key", "CF-Connecting-IP", or "Authorization").
// Missing or whitespace-only headers return an empty string, which bypasses the limiter.
func KeyByHeader(headerName string) KeyFunc {
	return func(r *http.Request) string {
		return strings.TrimSpace(r.Header.Get(headerName))
	}
}

// KeyByContext returns a KeyFunc that extracts the rate-limiting key from r.Context()
// using the given context key (e.g. user ID or auth claim). If the value is nil or empty,
// an empty string is returned, bypassing the limiter.
func KeyByContext(key any) KeyFunc {
	return func(r *http.Request) string {
		val := r.Context().Value(key)
		if val == nil {
			return ""
		}
		if s, ok := val.(string); ok {
			return strings.TrimSpace(s)
		}
		if s, ok := val.(fmt.Stringer); ok {
			return strings.TrimSpace(s.String())
		}
		return strings.TrimSpace(fmt.Sprintf("%v", val))
	}
}

// KeyWithFallback returns a KeyFunc that invokes primary first; if primary
// returns an empty string (e.g. missing header or unauthenticated context),
// fallback is invoked instead.
//
// This prevents missing headers from unintentionally bypassing rate limits:
//
//	KeyFunc: ratelimit.KeyWithFallback(ratelimit.KeyByHeader("X-API-Key"), ratelimit.KeyByIP)
func KeyWithFallback(primary, fallback KeyFunc) KeyFunc {
	return func(r *http.Request) string {
		if primary != nil {
			if k := primary(r); k != "" {
				return k
			}
		}
		if fallback != nil {
			return fallback(r)
		}
		return ""
	}
}

// KeyWithRoute returns a KeyFunc that appends the request's HTTP method and
// URL path to the key produced by base (e.g. "192.0.2.1:GET:/api/data").
//
// This is essential when using PolicyFunc to define per-route rate limits,
// ensuring requests to different routes do not mutate or contend for the same
// client token bucket.
func KeyWithRoute(base KeyFunc) KeyFunc {
	if base == nil {
		base = KeyByIP
	}
	return func(r *http.Request) string {
		key := base(r)
		if key == "" {
			return ""
		}
		return key + ":" + r.Method + ":" + r.URL.Path
	}
}

// ProxyHeaderStrategy specifies which proxy forwarding headers are evaluated
// by KeyByTrustedProxyWithOptions.
type ProxyHeaderStrategy int

const (
	// ProxyHeaderAuto evaluates headers in standard order: Forwarded (RFC 7239),
	// followed by X-Forwarded-For, then X-Real-IP.
	ProxyHeaderAuto ProxyHeaderStrategy = iota

	// ProxyHeaderXForwardedFor prioritizes X-Forwarded-For over Forwarded.
	// Recommended when deploying behind proxies like NGINX, AWS ALB, or Cloudflare
	// that populate X-Forwarded-For without stripping untrusted Forwarded headers.
	ProxyHeaderXForwardedFor

	// ProxyHeaderForwarded strictly evaluates RFC 7239 Forwarded headers.
	ProxyHeaderForwarded

	// ProxyHeaderXRealIP strictly evaluates X-Real-IP headers.
	ProxyHeaderXRealIP
)

// TrustedProxyConfig configures key extraction behind reverse proxies and load balancers.
type TrustedProxyConfig struct {
	// TrustedCIDRs is the list of trusted proxy networks. Only when RemoteAddr
	// originates from one of these networks will proxy forwarding headers be inspected.
	TrustedCIDRs []*net.IPNet

	// Strategy determines which forwarding headers to evaluate. Defaults to ProxyHeaderAuto.
	Strategy ProxyHeaderStrategy
}

// isTrustedIP checks whether an IP address belongs to any of the trusted networks.
func isTrustedIP(addr netip.Addr, trusted []*net.IPNet) bool {
	if !addr.IsValid() {
		return false
	}
	ip := net.IP(addr.AsSlice())
	for _, cidr := range trusted {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// KeyByTrustedProxy returns a KeyFunc that inspects standard forwarding headers
// (RFC 7239 Forwarded, X-Forwarded-For, and X-Real-IP) only when RemoteAddr
// originates from one of the specified trusted CIDR networks.
//
// If RemoteAddr is not in a trusted network, RemoteAddr itself is canonicalized
// and used as the key, preventing clients from spoofing proxy headers.
func KeyByTrustedProxy(trusted []*net.IPNet) KeyFunc {
	return KeyByTrustedProxyWithOptions(TrustedProxyConfig{
		TrustedCIDRs: trusted,
		Strategy:     ProxyHeaderAuto,
	})
}

// KeyByTrustedProxyWithOptions provides fine-grained control over which forwarding
// headers to trust and inspect when operating behind reverse proxies.
func KeyByTrustedProxyWithOptions(cfg TrustedProxyConfig) KeyFunc {
	return func(r *http.Request) string {
		remoteAddr, ok := parseIPString(r.RemoteAddr)
		if !ok {
			return "unknown"
		}

		// If RemoteAddr is not from a trusted proxy, ignore all forwarding headers
		if !isTrustedIP(remoteAddr, cfg.TrustedCIDRs) {
			return canonicalizeAddr(remoteAddr)
		}

		evalForwarded := func() (string, bool) {
			for _, fwd := range r.Header.Values("Forwarded") {
				if ips := parseForwardedHeader(fwd); len(ips) > 0 {
					// Traverse hops backwards: the first untrusted hop is the client IP
					for _, ip := range slices.Backward(ips) {
						hop, err := netip.ParseAddr(ip.String())
						if err != nil {
							continue
						}
						if !isTrustedIP(hop, cfg.TrustedCIDRs) {
							return canonicalizeAddr(hop), true
						}
					}
					// If all hops are trusted, fallback to leftmost hop
					if hop, err := netip.ParseAddr(ips[0].String()); err == nil {
						return canonicalizeAddr(hop), true
					}
				}
			}
			return "", false
		}

		evalXForwardedFor := func() (string, bool) {
			var allParts []string
			for _, xff := range r.Header.Values("X-Forwarded-For") {
				for part := range strings.SplitSeq(xff, ",") {
					if trimmed := strings.TrimSpace(part); trimmed != "" {
						allParts = append(allParts, trimmed)
					}
				}
			}
			if len(allParts) > 0 {
				// Traverse backwards from nearest proxy to origin client
				for _, allPart := range slices.Backward(allParts) {
					hop, ok := parseIPString(allPart)
					if !ok {
						continue
					}
					if !isTrustedIP(hop, cfg.TrustedCIDRs) {
						return canonicalizeAddr(hop), true
					}
				}
				// All hops trusted: return leftmost entry
				if hop, ok := parseIPString(allParts[0]); ok {
					return canonicalizeAddr(hop), true
				}
			}
			return "", false
		}

		evalXRealIP := func() (string, bool) {
			for _, xrip := range r.Header.Values("X-Real-IP") {
				if hop, ok := parseIPString(xrip); ok {
					return canonicalizeAddr(hop), true
				}
			}
			return "", false
		}

		switch cfg.Strategy {
		case ProxyHeaderXForwardedFor:
			if key, ok := evalXForwardedFor(); ok {
				return key
			}
			if key, ok := evalForwarded(); ok {
				return key
			}
			if key, ok := evalXRealIP(); ok {
				return key
			}

		case ProxyHeaderForwarded:
			if key, ok := evalForwarded(); ok {
				return key
			}

		case ProxyHeaderXRealIP:
			if key, ok := evalXRealIP(); ok {
				return key
			}

		default: // ProxyHeaderAuto
			if key, ok := evalForwarded(); ok {
				return key
			}
			if key, ok := evalXForwardedFor(); ok {
				return key
			}
			if key, ok := evalXRealIP(); ok {
				return key
			}
		}

		return canonicalizeAddr(remoteAddr)
	}
}

// ParseCIDRs parses a list of CIDR strings into []*net.IPNet.
func ParseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}

// Handler wraps next with a shared limiter. It is equivalent to New(limiter)(next).
func Handler(limiter *rate.Limiter, next http.Handler) http.Handler { return New(limiter)(next) }
