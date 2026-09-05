# gocap

`gocap` is a lightweight, concurrency-safe, in-memory token-bucket rate-limiting middleware for Go's `net/http`. It is designed specifically for single-VM, containerized, or standalone server deployments with low to medium traffic that require robust, zero-dependency rate limiting.

Rejected requests receive `429 Too Many Requests` along with standard `RateLimit-*` and `Retry-After` headers. Admitted requests are processed immediately without blocking.

> **Note:** `gocap` stores all bucket state in process memory. It is intended for single-instance applications. If you run multiple replicas behind a load balancer and require a strictly shared global quota, enforce limits at your edge gateway/CDN or use a distributed datastore (such as Redis).

---

## Installation

```bash
go get github.com/madpac-dev/gocap
```

---

## Quickstart

### 1. Shared Global Limit
Applies a single shared token bucket across all incoming requests:

```go
package main

import (
    "net/http"
    "golang.org/x/time/rate"
    "github.com/madpac-dev/gocap"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/api/data", handleData)

    // 100 requests/second sustained, burst of 200
    limiter := rate.NewLimiter(100, 200)
    handler := gocap.New(limiter)(mux)

    http.ListenAndServe(":8080", handler)
}
```

### 2. Per-Client Rate Limiting
Assigns a separate rate-limiting bucket to each client (by IP, API key, user ID, or context claim):

```go
middleware, err := gocap.NewWithConfig(gocap.Config{
    Limit:   10, // 10 requests per second
    Burst:   20, // burst up to 20 requests
    KeyFunc: gocap.KeyByIP,
})
if err != nil {
    log.Fatal(err)
}

http.ListenAndServe(":8080", middleware(mux))
```

---

## Configuration Reference

`gocap.Config` provides fine-grained control over rate-limiting policies:

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Limit` | `rate.Limit` | `0` | Refill rate in tokens per second (e.g., `10` or `rate.Every(time.Minute)`). |
| `Burst` | `int` | `0` | Maximum burst capacity (maximum tokens a bucket can hold). Must be $> 0$ unless `PolicyFunc` is used. |
| `KeyFunc` | `KeyFunc` | `nil` | Extracts the client key from `*http.Request`. If `nil`, all requests share one global bucket. Returning `""` bypasses limiting. |
| `PolicyFunc` | `PolicyFunc` | `nil` | Dynamically overrides `Limit` and `Burst` per request (e.g., based on user tier or route). |
| `CostFunc` | `func(*http.Request) int` | `nil` (cost = 1) | Determines how many tokens a request consumes (e.g., higher cost for expensive endpoints). |
| `SkipFunc` | `func(*http.Request) bool` | `nil` | Bypasses rate limiting entirely when returning `true` (e.g., `/healthz` or `/metrics`). |
| `EntryTTL` | `time.Duration` | `10m` | Time after which an idle client bucket is eligible for cleanup. |
| `CleanupInterval` | `time.Duration` | `1m` | Frequency for opportunistic eviction of expired idle buckets. |
| `MaxEntries` | `int` | `100,000` | Global cap on retained client buckets across all shards. When full, least-recently-used (LRU) buckets are evicted. |
| `MaxKeyLength` | `int` | `1024` | Maximum length of keys stored verbatim. Keys exceeding this length are hashed to a SHA-256 digest. Minimum value is `64`. |
| `DisableHeaders` | `bool` | `false` | When `true`, suppresses `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` response headers. |
| `OnDecision` | `func(*http.Request, Decision)` | `nil` | Synchronous telemetry hook invoked after each rate-limit decision (for Prometheus metrics or logging). |
| `OnRejected` | `func(http.ResponseWriter, *http.Request)` | `nil` | Custom response handler for `429` rejections. If `nil`, writes default RFC 7807 JSON or plain text. |

---

## Built-in Key Resolvers

`gocap` includes key resolver functions for common single-VM architectures:

### `KeyByIP`
Extracts the client IP from `Request.RemoteAddr`.
- IPv4 addresses are keyed by their exact 32-bit `/32` address.
- IPv6 addresses are automatically grouped into their `/64` routing prefix to mitigate address-rotation / LRU cache exhaustion attacks.
- Requests with unparseable addresses share the `"unknown"` key.

```go
KeyFunc: gocap.KeyByIP
```

### `KeyByHeader`
Extracts the rate-limiting key directly from a specified HTTP header (e.g. `X-API-Key`, `CF-Connecting-IP`, or `Authorization`). Missing or whitespace-only headers return `""`, bypassing rate limiting.

```go
KeyFunc: gocap.KeyByHeader("X-API-Key")
```

### `KeyByContext`
Extracts a user ID or account token stored in `r.Context()` by an upstream authentication middleware.

```go
KeyFunc: gocap.KeyByContext("userID")
```

### `KeyByTrustedProxy`
Extracts client IP addresses from standard proxy headers (`Forwarded` (RFC 7239), `X-Forwarded-For`, and `X-Real-IP`) only when `RemoteAddr` matches a trusted CIDR network. If `RemoteAddr` is not trusted, `RemoteAddr` is used directly. For proxies that do not strip external `Forwarded` headers, use `KeyByTrustedProxyWithOptions` with `ProxyHeaderXForwardedFor`.

```go
trustedProxies, err := gocap.ParseCIDRs([]string{"10.0.0.0/8", "172.16.0.0/12", "127.0.0.1/32"})
if err != nil {
    log.Fatal(err)
}

KeyFunc: gocap.KeyByTrustedProxy(trustedProxies)
```

### `KeyWithFallback`
Chains two key resolvers. If the primary resolver returns an empty string (such as an unauthenticated request or missing header), the fallback resolver is used instead:

```go
// Rate limit by API Key, falling back to IP if unauthenticated
KeyFunc: gocap.KeyWithFallback(gocap.KeyByHeader("X-API-Key"), gocap.KeyByIP)
```

### `KeyWithRoute`
Appends the request's HTTP method and URL path to the key produced by a base resolver (`<key>:<method>:<path>`). This is essential when using `PolicyFunc` with route-specific limits to prevent cross-route bucket collision:

```go
KeyFunc: gocap.KeyWithRoute(gocap.KeyByIP)
```

---

## Advanced Example

```go
package main

import (
    "net/http"
    "golang.org/x/time/rate"
    "github.com/madpac-dev/gocap"
)

func main() {
    trustedCIDRs, _ := gocap.ParseCIDRs([]string{"10.0.0.0/8", "127.0.0.1/32"})

    middleware, err := gocap.NewWithConfig(gocap.Config{
        Limit:   10,
        Burst:   20,
        KeyFunc: gocap.KeyByTrustedProxy(trustedCIDRs),

        // Dynamic per-tier rate limits
        PolicyFunc: func(r *http.Request) (rate.Limit, int, bool) {
            role := r.Header.Get("X-Role")
            switch role {
            case "admin":
                return 0, 0, false // bypass
            case "premium":
                return 100, 200, true
            default:
                return 10, 20, true
            }
        },

        // Weighted token cost
        CostFunc: func(r *http.Request) int {
            if r.URL.Path == "/api/export" {
                return 5 // heavy request consumes 5 tokens
            }
            return 1
        },

        // Bypass probes & health checks
        SkipFunc: func(r *http.Request) bool {
            return r.URL.Path == "/healthz" || r.URL.Path == "/ready"
        },

        // Observability hook
        OnDecision: func(r *http.Request, d gocap.Decision) {
            if !d.Allowed {
                // e.g. metrics.RateLimitRejections.Inc()
            }
        },
    })
    if err != nil {
        panic(err)
    }

    http.ListenAndServe(":8080", middleware(http.DefaultServeMux))
}
```

---

## Operational Behavior

- **Sharded LRU Architecture:** State is partitioned across up to 64 independent shards to minimize mutex lock contention under concurrent load.
- **Strict Memory Safety:** Total bucket retention is strictly capped by `MaxEntries` (default 100,000, using $< 20\text{ MB}$ RAM). Expired entries are removed via LRU eviction when capacity is reached.
- **Cross-Shard Idle Cleanup:** When any shard performs opportunistic cleanup, it non-blockingly sweeps expired entries across idle shards, preventing quiet shards from retaining memory after traffic bursts.
- **Context-Aware:** Requests whose client context is already canceled (`r.Context().Err() != nil`) are terminated immediately without consuming tokens.
- **Standard HTTP Headers:**
  - `RateLimit-Limit`: Maximum token burst capacity.
  - `RateLimit-Remaining`: Number of available tokens remaining in the bucket.
  - `RateLimit-Reset`: Number of seconds until the bucket is refilled.
  - `Retry-After`: Included on `429` rejections indicating seconds to wait.
- **Structured Error Responses:** Default `429` rejections return RFC 7807 `application/problem+json` when the client sends `Accept: application/json`, or `text/plain` otherwise. Responses are marked `Cache-Control: private, no-store`.
