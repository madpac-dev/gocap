package gocap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestMiddlewareAllowsThenRejects(t *testing.T) {
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	})

	handler := New(rate.NewLimiter(0, 1))(next)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first request status = %d, want %d", first.Code, http.StatusNoContent)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
	if called != 1 {
		t.Fatalf("next handler calls = %d, want 1", called)
	}
}

func TestNewWithConfigUsesSeparateBuckets(t *testing.T) {
	middleware, err := NewWithConfig(Config{
		Limit:   0,
		Burst:   1,
		KeyFunc: func(r *http.Request) string { return r.Header.Get("X-User") },
	})
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	request := func(user string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-User", user)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if got := request("a").Code; got != http.StatusNoContent {
		t.Fatalf("first user A status = %d, want %d", got, http.StatusNoContent)
	}
	if got := request("b").Code; got != http.StatusNoContent {
		t.Fatalf("first user B status = %d, want %d", got, http.StatusNoContent)
	}
	if got := request("a").Code; got != http.StatusTooManyRequests {
		t.Fatalf("second user A status = %d, want %d", got, http.StatusTooManyRequests)
	}
}

func TestNewWithConfigLRUEviction(t *testing.T) {
	// A single shard capacity of 1 with MaxEntries=1
	s := &shard{
		buckets:    make(map[string]*bucketNode),
		limit:      0,
		burst:      1,
		ttl:        time.Hour,
		maxEntries: 1,
	}
	now := time.Now()

	// Admitting user 'a' consumes its token
	l1, ok1 := s.limiterFor(now, "a", 0, 1)
	if !ok1 || !l1.AllowN(now, 1) {
		t.Fatal("user a should be allowed")
	}
	// Second request for 'a' is rejected (out of tokens)
	if l1.AllowN(now, 1) {
		t.Fatal("user a second request should be out of tokens")
	}

	// Admitting user 'b' exceeds capacity 1, evicting 'a' (LRU)
	l2, ok2 := s.limiterFor(now.Add(time.Second), "b", 0, 1)
	if !ok2 || !l2.AllowN(now.Add(time.Second), 1) {
		t.Fatal("user b should be admitted and allowed via LRU eviction of user a")
	}
	if len(s.buckets) != 1 {
		t.Fatalf("shard size = %d, want 1", len(s.buckets))
	}
	if _, foundA := s.buckets["a"]; foundA {
		t.Fatal("user a should have been evicted")
	}
	if _, foundB := s.buckets["b"]; !foundB {
		t.Fatal("user b should be in bucket map")
	}
}

func TestRateLimitHeadersAndCustomRejection(t *testing.T) {
	middleware, err := NewWithConfig(Config{
		Limit: 1, Burst: 1,
		OnRejected: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
	})
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := first.Header().Get("RateLimit-Remaining"); got != "0" {
		t.Fatalf("RateLimit-Remaining = %q, want 0", got)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("rejection status = %d, want %d", second.Code, http.StatusServiceUnavailable)
	}
	if got := second.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}

func TestJSONRejectionResponse(t *testing.T) {
	middleware, err := NewWithConfig(Config{Limit: 0, Burst: 1})
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request succeeds
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, r1)

	// Second request with Accept: application/json returns RFC 7807 JSON problem detail
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Accept", "application/json")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)

	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", w2.Code, http.StatusTooManyRequests)
	}
	if ct := w2.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", ct)
	}
	var resp map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON problem response: %v", err)
	}
	if resp["status"] != float64(429) {
		t.Fatalf("json status = %v, want 429", resp["status"])
	}
}

func TestDynamicPolicyFunc(t *testing.T) {
	middleware, err := NewWithConfig(Config{
		PolicyFunc: func(r *http.Request) (rate.Limit, int, bool) {
			tier := r.Header.Get("X-Tier")
			switch tier {
			case "admin":
				return 0, 0, false // bypass
			case "pro":
				return 100, 10, true
			default:
				return 0, 1, true // 1 burst, no refill
			}
		},
		KeyFunc: func(r *http.Request) string {
			return r.Header.Get("X-User")
		},
	})
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Admin is bypassed completely
	rAdmin := httptest.NewRequest(http.MethodGet, "/", nil)
	rAdmin.Header.Set("X-Tier", "admin")
	wAdmin := httptest.NewRecorder()
	handler.ServeHTTP(wAdmin, rAdmin)
	if wAdmin.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200", wAdmin.Code)
	}
	if wAdmin.Header().Get("RateLimit-Limit") != "" {
		t.Fatal("bypassed request should not have rate limit headers")
	}

	// Free tier: allowed 1st, rejected 2nd
	rFree := httptest.NewRequest(http.MethodGet, "/", nil)
	rFree.Header.Set("X-User", "free-user")
	wFree1 := httptest.NewRecorder()
	handler.ServeHTTP(wFree1, rFree)
	if wFree1.Code != http.StatusOK {
		t.Fatalf("free 1st status = %d, want 200", wFree1.Code)
	}
	wFree2 := httptest.NewRecorder()
	handler.ServeHTTP(wFree2, rFree)
	if wFree2.Code != http.StatusTooManyRequests {
		t.Fatalf("free 2nd status = %d, want 429", wFree2.Code)
	}
}

func TestCostFunc(t *testing.T) {
	middleware, err := NewWithConfig(Config{
		Limit: 0,
		Burst: 5,
		CostFunc: func(r *http.Request) int {
			if r.URL.Path == "/heavy" {
				return 4
			}
			return 1
		},
	})
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Heavy request consumes 4 of 5 tokens
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/heavy", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("heavy request 1 status = %d, want 200", w1.Code)
	}

	// Another heavy request needs 4 tokens, only 1 left -> 429
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/heavy", nil))
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("heavy request 2 status = %d, want 429", w2.Code)
	}

	// Normal request needs 1 token, exactly 1 remaining -> 200
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "/light", nil))
	if w3.Code != http.StatusOK {
		t.Fatalf("light request status = %d, want 200", w3.Code)
	}
}

func TestSkipFuncAndObservability(t *testing.T) {
	var allowedCount int
	middleware, err := NewWithConfig(Config{
		Limit: 0,
		Burst: 1,
		SkipFunc: func(r *http.Request) bool {
			return r.URL.Path == "/healthz"
		},
		OnAllowed: func(r *http.Request) {
			allowedCount++
		},
	})
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Health check skipped
	wHealth := httptest.NewRecorder()
	handler.ServeHTTP(wHealth, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if wHealth.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", wHealth.Code)
	}
	if allowedCount != 0 {
		t.Fatalf("skipped request should not trigger OnAllowed, got %d", allowedCount)
	}

	// Standard request consumed token and triggers OnAllowed
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/api", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("api status = %d, want 200", w1.Code)
	}
	if allowedCount != 1 {
		t.Fatalf("allowedCount = %d, want 1", allowedCount)
	}
}

func TestKeyByIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[2001:db8:abcd:0012:1234:5678:9abc:def0]:443"
	// IPv6 addresses in the same /64 subnet must share the canonical /64 prefix key
	if got := KeyByIP(r); got != "2001:db8:abcd:12::" {
		t.Fatalf("KeyByIP() IPv6 = %q, want 2001:db8:abcd:12::", got)
	}

	r.RemoteAddr = "[2001:db8:abcd:0012:ffff:ffff:ffff:ffff]:443"
	if got := KeyByIP(r); got != "2001:db8:abcd:12::" {
		t.Fatalf("KeyByIP() IPv6 same /64 = %q, want 2001:db8:abcd:12::", got)
	}

	r.RemoteAddr = "192.0.2.1:1234"
	if got := KeyByIP(r); got != "192.0.2.1" {
		t.Fatalf("KeyByIP() IPv4 = %q, want 192.0.2.1", got)
	}

	r.RemoteAddr = "not-an-address"
	if got := KeyByIP(r); got != "unknown" {
		t.Fatalf("KeyByIP() malformed = %q", got)
	}
}

func TestKeyByHeader(t *testing.T) {
	keyFunc := KeyByHeader("X-API-Key")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", "  secret-token-123  ")
	if got := keyFunc(r); got != "secret-token-123" {
		t.Fatalf("KeyByHeader() = %q, want secret-token-123", got)
	}

	rMissing := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := keyFunc(rMissing); got != "" {
		t.Fatalf("KeyByHeader() missing = %q, want empty string", got)
	}
}

type ctxKey string

func TestKeyByContext(t *testing.T) {
	keyFunc := KeyByContext(ctxKey("userID"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := keyFunc(r); got != "" {
		t.Fatalf("KeyByContext() empty = %q, want empty string", got)
	}

	rWithVal := r.WithContext(context.WithValue(r.Context(), ctxKey("userID"), "user_42"))
	if got := keyFunc(rWithVal); got != "user_42" {
		t.Fatalf("KeyByContext() = %q, want user_42", got)
	}
}

func TestKeyByTrustedProxy(t *testing.T) {
	trusted, err := ParseCIDRs([]string{"10.0.0.0/8", "192.168.1.0/24", "fd00::/8"})
	if err != nil {
		t.Fatalf("ParseCIDRs error = %v", err)
	}
	keyFunc := KeyByTrustedProxy(trusted)

	// Untrusted remote address: ignores X-Forwarded-For
	rUntrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	rUntrusted.RemoteAddr = "203.0.113.195:1234"
	rUntrusted.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := keyFunc(rUntrusted); got != "203.0.113.195" {
		t.Fatalf("untrusted remote addr key = %q, want 203.0.113.195", got)
	}

	// Trusted proxy remote address: extracts real client IP from X-Forwarded-For
	rTrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	rTrusted.RemoteAddr = "10.0.0.1:1234"
	rTrusted.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.2")
	if got := keyFunc(rTrusted); got != "203.0.113.50" {
		t.Fatalf("trusted proxy key = %q, want 203.0.113.50", got)
	}

	// Trusted proxy with RFC 7239 Forwarded header
	rForwarded := httptest.NewRequest(http.MethodGet, "/", nil)
	rForwarded.RemoteAddr = "10.0.0.1:1234"
	rForwarded.Header.Set("Forwarded", `for=198.51.100.22;proto=https, for=10.0.0.2`)
	if got := keyFunc(rForwarded); got != "198.51.100.22" {
		t.Fatalf("Forwarded header key = %q, want 198.51.100.22", got)
	}

	// Trusted proxy with IPv6 Forwarded header (masked to /64)
	rForwardedIPv6 := httptest.NewRequest(http.MethodGet, "/", nil)
	rForwardedIPv6.RemoteAddr = "10.0.0.1:1234"
	rForwardedIPv6.Header.Set("Forwarded", `for="[2001:db8:cafe:11::99]:443"`)
	if got := keyFunc(rForwardedIPv6); got != "2001:db8:cafe:11::" {
		t.Fatalf("Forwarded IPv6 key = %q, want 2001:db8:cafe:11::", got)
	}
}

func TestConfigValidationAndExpiry(t *testing.T) {
	for _, config := range []Config{{Limit: -1, Burst: 1}, {Limit: rate.Limit(math.NaN()), Burst: 1}, {Limit: 1, Burst: 0}, {Limit: 1, Burst: 1, EntryTTL: -time.Second}, {Limit: 1, Burst: 1, MaxKeyLength: 63}} {
		if _, err := NewWithConfig(config); err == nil {
			t.Fatalf("NewWithConfig(%+v) returned nil error", config)
		}
	}
	s := &shard{buckets: map[string]*bucketNode{}, limit: 0, burst: 1, ttl: time.Second, cleanupEach: time.Second, maxEntries: 1}
	now := time.Now()
	if _, ok := s.limiterFor(now, "old", 0, 1); !ok {
		t.Fatal("initial entry was rejected")
	}
	if _, ok := s.limiterFor(now.Add(2*time.Second), "new", 0, 1); !ok {
		t.Fatal("expired entry was not removed before admitting new key")
	}
}

func TestMaxEntriesIsAnExactGlobalBound(t *testing.T) {
	middleware, err := NewWithConfig(Config{
		Limit:      0,
		Burst:      1,
		MaxEntries: 1,
		KeyFunc:    func(r *http.Request) string { return r.Header.Get("X-Key") },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, key := range []string{"a", "b", "c", "d"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Key", key)
		handler.ServeHTTP(httptest.NewRecorder(), r)
	}

	// MaxEntries below the shard count uses a smaller active shard set; no key
	// can make the total exceed the requested global cap.
	store := newShardedStore(keyedDefaults(Config{Limit: 0, Burst: 1, MaxEntries: 1}))
	for _, key := range []string{"a", "b", "c", "d"} {
		if _, ok := store.bucketFor(time.Now(), key, 0, 1); !ok {
			t.Fatal("bucket admission failed")
		}
	}
	total := 0
	for _, shard := range store.shards {
		if shard != nil {
			total += len(shard.buckets)
		}
	}
	if total != 1 {
		t.Fatalf("retained buckets = %d, want exact MaxEntries of 1", total)
	}
}

func TestLongKeysAreCanonicalizedAndInvalidPoliciesFailClosed(t *testing.T) {
	longA := strings.Repeat("a", defaultMaxKeyLength+1)
	longB := strings.Repeat("b", defaultMaxKeyLength+1)
	if got := canonicalKey(longA, defaultMaxKeyLength); len(got) != sha256.Size*2 {
		t.Fatalf("canonical key length = %d, want %d", len(got), sha256.Size*2)
	}
	if canonicalKey(longA, defaultMaxKeyLength) == canonicalKey(longB, defaultMaxKeyLength) {
		t.Fatal("different long keys must not share a canonical key")
	}

	middleware, err := NewWithConfig(Config{PolicyFunc: func(*http.Request) (rate.Limit, int, bool) {
		return rate.Limit(math.NaN()), 1, true
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("invalid policy status = %d, want 429", w.Code)
	}
}

func TestUnfulfillableCostDoesNotAdvertiseRetry(t *testing.T) {
	middleware, err := NewWithConfig(Config{Limit: 1, Burst: 1, CostFunc: func(*http.Request) int { return 2 }})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "" {
		t.Fatalf("status/retry-after = %d/%q, want 429/empty", w.Code, w.Header().Get("Retry-After"))
	}
}

func FuzzKeyByTrustedProxy(f *testing.F) {
	trusted, err := ParseCIDRs([]string{"10.0.0.0/8", "fd00::/8"})
	if err != nil {
		f.Fatal(err)
	}
	keyFunc := KeyByTrustedProxy(trusted)
	f.Add("10.0.0.1:443", "198.51.100.1, 10.0.0.2", "")
	f.Add("not-an-address", "garbage", "also garbage")
	f.Fuzz(func(t *testing.T, remoteAddr, xff, xRealIP string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remoteAddr
		r.Header.Set("X-Forwarded-For", xff)
		r.Header.Set("X-Real-IP", xRealIP)
		_ = keyFunc(r)
	})
}

func TestKeyedMiddlewareIsConcurrentSafe(t *testing.T) {
	middleware, err := NewWithConfig(Config{Limit: 0, Burst: 1, KeyFunc: func(*http.Request) string { return "same" }})
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}
	var allowed int
	var mu sync.Mutex
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		allowed++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	var group sync.WaitGroup
	for range 100 {
		group.Go(func() {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		})
	}
	group.Wait()
	if allowed != 1 {
		t.Fatalf("allowed requests = %d, want 1", allowed)
	}
}

func TestHandlerConvenience(t *testing.T) {
	handler := Handler(rate.NewLimiter(1, 1), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestContextCancellation(t *testing.T) {
	middleware, err := NewWithConfig(Config{Limit: 0, Burst: 1})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before request is processed
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Fatal("handler should not be called when request context is canceled")
	}
	if w.Code != http.StatusOK && w.Body.Len() > 0 {
		t.Fatalf("canceled request should not produce response, got code %d", w.Code)
	}
}

func TestSweepIdleShards(t *testing.T) {
	store := newShardedStore(Config{
		Limit:           0,
		Burst:           1,
		EntryTTL:        time.Millisecond * 50,
		CleanupInterval: time.Millisecond * 50,
		MaxEntries:      1000,
	})

	now := time.Now()
	// Populate keys in different shards
	if _, ok := store.bucketFor(now, "key-1", 0, 1); !ok {
		t.Fatal("key-1 failed")
	}
	if _, ok := store.bucketFor(now, "key-2", 0, 1); !ok {
		t.Fatal("key-2 failed")
	}

	totalBefore := 0
	for _, sh := range store.shards {
		if sh != nil {
			totalBefore += len(sh.buckets)
		}
	}
	if totalBefore < 2 {
		t.Fatalf("expected at least 2 buckets before expiry, got %d", totalBefore)
	}

	// Advance time past TTL and cleanup interval, and make a request with a new key (which may hit any shard)
	later := now.Add(time.Second)
	if _, ok := store.bucketFor(later, "key-3", 0, 1); !ok {
		t.Fatal("key-3 failed")
	}

	// All expired idle buckets across all shards should now have been swept
	totalAfter := 0
	for _, sh := range store.shards {
		if sh != nil {
			totalAfter += len(sh.buckets)
		}
	}
	// Only the newly admitted "key-3" should remain
	if totalAfter != 1 {
		t.Fatalf("expected 1 bucket after sweep, got %d", totalAfter)
	}
}

func BenchmarkKeyedParallel(b *testing.B) {
	middleware, err := NewWithConfig(Config{
		Limit:   rate.Inf,
		Burst:   1000000,
		KeyFunc: KeyByIP,
	})
	if err != nil {
		b.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "192.168.1.10:1234"
		w := httptest.NewRecorder()
		for pb.Next() {
			handler.ServeHTTP(w, r)
		}
	})
}

func TestRateLimitResetReflectsFullBucketRefill(t *testing.T) {
	middleware, err := NewWithConfig(Config{
		Limit: 1, // 1 token per second
		Burst: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// After consuming 1 token of 10, 9 remain. Reset should be ceil((10 - 9) / 1) = 1 second.
	if got := w.Header().Get("RateLimit-Remaining"); got != "9" {
		t.Fatalf("RateLimit-Remaining = %q, want 9", got)
	}
	if got := w.Header().Get("RateLimit-Reset"); got != "1" {
		t.Fatalf("RateLimit-Reset = %q, want 1", got)
	}
}

func TestKeyWithFallback(t *testing.T) {
	keyFunc := KeyWithFallback(KeyByHeader("X-API-Key"), KeyByIP)

	// Case 1: Header present -> uses header key
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	r1.Header.Set("X-API-Key", "my-secret-key")
	r1.RemoteAddr = "192.0.2.1:1234"
	if got := keyFunc(r1); got != "my-secret-key" {
		t.Fatalf("got %q, want my-secret-key", got)
	}

	// Case 2: Header missing -> falls back to IP
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "192.0.2.1:1234"
	if got := keyFunc(r2); got != "192.0.2.1" {
		t.Fatalf("got %q, want 192.0.2.1", got)
	}
}

func TestKeyWithRoute(t *testing.T) {
	keyFunc := KeyWithRoute(KeyByHeader("X-User"))

	r := httptest.NewRequest(http.MethodPost, "/api/v1/resource", nil)
	r.Header.Set("X-User", "alice")
	if got := keyFunc(r); got != "alice:POST:/api/v1/resource" {
		t.Fatalf("got %q, want alice:POST:/api/v1/resource", got)
	}

	// Empty key preserves bypass
	rEmpty := httptest.NewRequest(http.MethodGet, "/api", nil)
	if got := keyFunc(rEmpty); got != "" {
		t.Fatalf("got %q, want empty string", got)
	}
}

func TestCostFuncZeroAllowsFreeRequests(t *testing.T) {
	middleware, err := NewWithConfig(Config{
		Limit: 0,
		Burst: 1,
		CostFunc: func(r *http.Request) int {
			if r.Method == http.MethodOptions {
				return 0 // Free request
			}
			return 1
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Multiple OPTIONS requests do not consume the 1 token
	for range 5 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodOptions, "/", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("OPTIONS status = %d, want 200", w.Code)
		}
		if got := w.Header().Get("RateLimit-Remaining"); got != "1" {
			t.Fatalf("Remaining = %q, want 1", got)
		}
	}

	// GET request consumes the token
	wGet1 := httptest.NewRecorder()
	handler.ServeHTTP(wGet1, httptest.NewRequest(http.MethodGet, "/", nil))
	if wGet1.Code != http.StatusOK {
		t.Fatalf("GET 1 status = %d, want 200", wGet1.Code)
	}

	// Second GET request is rejected (0 tokens left)
	wGet2 := httptest.NewRecorder()
	handler.ServeHTTP(wGet2, httptest.NewRequest(http.MethodGet, "/", nil))
	if wGet2.Code != http.StatusTooManyRequests {
		t.Fatalf("GET 2 status = %d, want 429", wGet2.Code)
	}
}

func TestRejectionProblemJSONAccept(t *testing.T) {
	middleware, err := NewWithConfig(Config{Limit: 0, Burst: 1})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// Consume token
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	// Request with application/problem+json
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept", "application/problem+json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", ct)
	}
	if nosniff := w.Header().Get("X-Content-Type-Options"); nosniff != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", nosniff)
	}
}

func TestKeyByTrustedProxyWithOptionsStrategy(t *testing.T) {
	trusted, err := ParseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}

	// Attacker sends spoofed Forwarded header, but proxy populates X-Forwarded-For
	keyFunc := KeyByTrustedProxyWithOptions(TrustedProxyConfig{
		TrustedCIDRs: trusted,
		Strategy:     ProxyHeaderXForwardedFor,
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:443"
	r.Header.Set("Forwarded", "for=198.51.100.99")            // Spoofed
	r.Header.Set("X-Forwarded-For", "203.0.113.77, 10.0.0.2") // Legitimate proxy chain

	// With ProxyHeaderXForwardedFor, the real X-Forwarded-For client IP is used, ignoring spoofed Forwarded
	if got := keyFunc(r); got != "203.0.113.77" {
		t.Fatalf("got %q, want 203.0.113.77", got)
	}
}

func TestShardMoveToFront(t *testing.T) {
	s := &shard{
		buckets:    make(map[string]*bucketNode),
		limit:      1,
		burst:      1,
		ttl:        time.Hour,
		maxEntries: 10,
	}
	now := time.Now()

	// Insert three nodes: a, b, c. List order head -> c -> b -> a -> tail
	_, _ = s.bucketFor(now, "a", 1, 1, nil)
	_, _ = s.bucketFor(now, "b", 1, 1, nil)
	_, _ = s.bucketFor(now, "c", 1, 1, nil)

	// Access 'b' (middle node). Should move to head: b -> c -> a
	_, _ = s.bucketFor(now, "b", 1, 1, nil)
	if s.head.key != "b" {
		t.Fatalf("head key = %q, want b", s.head.key)
	}

	// Access 'a' (tail node). Should move to head: a -> b -> c
	_, _ = s.bucketFor(now, "a", 1, 1, nil)
	if s.head.key != "a" {
		t.Fatalf("head key = %q, want a", s.head.key)
	}
	if s.tail.key != "c" {
		t.Fatalf("tail key = %q, want c", s.tail.key)
	}
}
