# Token Proxy v2.0 

OAuth2 token proxy for OHIF-VNA integration.

## Features

### Security
- Zod-based configuration validation
- API key authentication (configurable modes: none, api_key, jwt, mtls)
- Header allowlist with hop-by-hop header filtering
- Secret redaction in logs (Authorization, Cookie, X-API-Key)
- Non-root container execution with read-only filesystem
- NetworkPolicy for ingress/egress restriction

### Reliability
- Token cache with singleflight pattern (prevents thundering herd)
- Exponential backoff retry for token fetch
- Circuit breakers for both token fetch and VNA requests
- Configurable timeouts for all outbound calls
- Graceful shutdown handling

### Observability
- Structured JSON logging with request/trace IDs
- Prometheus metrics at `/metrics`
- OpenTelemetry tracing integration
- Error counters by status code and endpoint

### Performance
- HTTP keep-alive connection pooling
- Configurable body size limits
- Request streaming support

## Architecture

### Overview

```
OHIF Viewer --> Token Proxy --> Okta (token fetch)
                    |
                    +--> VNA Services (proxied requests)
```

The token proxy is a stateless OAuth2 client credentials proxy that:
- Keeps OAuth secrets out of browser applications
- Manages token lifecycle (fetch, cache, refresh)
- Injects authentication headers into VNA requests
- Enforces security policies (header allowlists, content validation)

### Request Flow

1. **Request arrives** from OHIF Viewer with `X-API-Key` header (if auth enabled)
2. **Authentication check** validates API key or allows unauthenticated access based on `PROXY_AUTH_MODE`
3. **Token acquisition**:
   - Check in-memory cache for valid token (cache hit = <10ms)
   - If cache miss: fetch from Okta with retry logic (1-5 seconds)
   - Singleflight pattern prevents concurrent fetches within the same pod
4. **Header processing**:
   - Drop hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, etc.)
   - Filter incoming headers against allowlist (`accept`, `content-type`, `rp-vna-site-id`)
   - Inject `Authorization: Bearer <token>`
   - Set required VNA headers (`Accept`, `Content-Type`, `Rp-Vna-Site-Id`)
5. **Proxy to VNA** through circuit breaker with keep-alive connection pooling
6. **Response forwarding** with filtered headers back to client

### Token Caching Strategy

**Per-Pod In-Memory Cache:**
- Each pod maintains its own independent token cache
- No shared state between pods (no Redis, no database)
- Cache TTL: 55 minutes (3300 seconds) with 5-minute expiry buffer

**Multi-Replica Implications:**
- With 2 replicas: 2 independent token fetches from Okta
- With 10 replicas (HPA max): 10 independent token fetches
- Each pod fetches ~26 tokens/day (55-minute TTL)
- Total Okta calls with 10 pods: ~260/day (well within typical rate limits of 1000+/minute)

**Why This Is Acceptable:**
- Token fetch cost is low (1-2 seconds every 55 minutes per pod)
- Okta rate limits are high enough for this scale
- No infrastructure dependencies (Redis) simplifies deployment
- Eliminates single point of failure

**When to Consider Shared Cache:**
- Scaling beyond 50 replicas
- Strict Okta rate limits or cost concerns
- Frequent pod churn causing excessive token fetches

### Circuit Breakers

Two circuit breakers protect against cascading failures:

**1. Token Fetch Circuit Breaker**
- Opens when: 50% of token fetch attempts fail within the error window
- Timeout: 30 seconds per attempt
- Reset timeout: 30 seconds after opening
- Impact when open: All requests fail fast with 503 until breaker closes

**2. VNA Request Circuit Breaker**
- Opens when: 50% of VNA requests fail within the error window
- Timeout: 30 seconds per request
- Reset timeout: 30 seconds after opening
- Impact when open: All proxy requests fail with 503 `CIRCUIT_OPEN`

**States:**
- `0` (closed): Normal operation
- `1` (open): Rejecting all requests, breaker tripped
- `2` (half-open): Testing if service recovered with limited requests

Monitor `circuit_breaker_state` metric to detect upstream issues.

### Retry Logic

**Token Fetch Only** (VNA requests are NOT retried to preserve idempotency):
- Attempts: 3
- Base delay: 1 second
- Backoff: Exponential (1s, 2s, 4s)
- Total max time: ~7 seconds before giving up

Retries only occur for token fetch failures (Okta timeouts, 5xx errors). VNA requests fail immediately to avoid duplicate operations.

### Security Model

**Why Tokens Stay Server-Side:**
- Browser applications cannot securely store OAuth client secrets
- Exposing tokens to browsers increases attack surface (XSS, token theft)
- Proxy pattern centralizes secret management in Kubernetes Secrets

**Authentication Flow:**
1. OHIF viewer includes `X-API-Key` in requests (optional, based on `PROXY_AUTH_MODE`)
2. Proxy validates API key (if enabled)
3. Proxy fetches OAuth token using client credentials (never exposed to client)
4. Proxy injects token into VNA request
5. VNA validates OAuth token and processes request

**Secret Handling:**
- Sensitive values (`OAUTH_CLIENT_SECRET`, `PROXY_API_KEY`) stored in Kubernetes Secret
- Non-sensitive config in ConfigMap for easy updates
- Secrets redacted from logs (Authorization, Cookie, X-API-Key headers)

**Header Security:**
- Hop-by-hop headers dropped to prevent protocol smuggling
- Allowlist enforced: only `accept`, `content-type`, `rp-vna-site-id` forwarded from client
- Incoming `Authorization` headers stripped to prevent token injection attacks

### High Availability

**Pod Distribution:**
- Anti-affinity rules spread pods across nodes (best effort)
- PodDisruptionBudget ensures minimum 1 pod available during disruptions
- HPA scales 2-10 replicas based on CPU (70%) and memory (80%) utilization

**Scaling Behavior:**
- Scale-up: Aggressive (2 pods per 30 seconds)
- Scale-down: Conservative (1 pod per 60 seconds with 5-minute stabilization)
- New pods immediately fetch their own token on first request

**Zero-Downtime Deployments:**
- Rolling update strategy: `maxSurge=1`, `maxUnavailable=0`
- Readiness probe delays traffic until token cache is valid
- Graceful shutdown (30-second termination grace period)

### Observability

**Request Tracing:**
- Each request gets `X-Request-Id` (UUID, generated or forwarded)
- `X-Trace-Id` for distributed tracing across services
- Both IDs included in structured logs and error responses

**Logging:**
- Structured JSON format for log aggregation
- Secret redaction prevents credential leaks
- Log levels: `debug`, `info`, `warn`, `error` (configurable via `LOG_LEVEL`)

**Metrics Cardinality:**
- Routes normalized to prevent high-cardinality labels
- `req.path` → `req.route.path` for consistent labeling
- Status codes grouped by endpoint for granular error tracking

**OpenTelemetry Integration:**
- Automatic span creation for token fetch and VNA requests
- Spans include HTTP method, URL, status code attributes
- Requires `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces

### Network Policies

**Ingress Rules:**
- Only accept traffic from `ohif-ac` namespace and `istio-system` (service mesh)
- Port 3000 only

**Egress Rules:**
- DNS: UDP/TCP 53 to any namespace (required for name resolution)
- HTTPS: TCP 443 to internet (Okta token endpoint)
- HTTP/HTTPS: TCP 80/443/8080 to any namespace (VNA services)

**Security Considerations:**
- Egress to `0.0.0.0/0:443` allows internet HTTPS (required for Okta)
- Tighten egress rules if Okta IP ranges are known
- VNA services typically run in-cluster, so internal routing applies

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/health` | GET | Liveness probe |
| `/ready` | GET | Readiness probe (validates token fetch) |
| `/metrics` | GET | Prometheus metrics |
| `/token` | GET | Get OAuth2 access token |
| `/token/clear` | POST | Clear token cache |
| `/proxy/*` | ALL | VNA proxy endpoint |

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | 3000 | Server port |
| `LOG_LEVEL` | No | info | Log level (debug, info, warn, error) |
| `OAUTH_TOKEN_URL` | Yes | - | Okta token endpoint URL |
| `OAUTH_CLIENT_ID` | Yes | - | OAuth2 client ID |
| `OAUTH_CLIENT_SECRET` | Yes | - | OAuth2 client secret |
| `OAUTH_SCOPE` | Yes | - | OAuth2 scope |
| `TOKEN_CACHE_TTL_SEC` | No | 3300 | Token cache TTL in seconds |
| `TOKEN_EXPIRY_BUFFER_SEC` | No | 300 | Buffer before token expiry |
| `TOKEN_TIMEOUT_MS` | No | 5000 | Token fetch timeout |
| `VNA_BASE_URL` | Yes | - | VNA service base URL |
| `VNA_TIMEOUT_MS` | No | 10000 | VNA request timeout |
| `PROXY_AUTH_MODE` | No | api_key | Auth mode (none, api_key, jwt, mtls) |
| `PROXY_API_KEY` | Conditional | - | API key (required if PROXY_AUTH_MODE=api_key) |
| `FORWARDED_HEADER_ALLOWLIST` | No | accept,content-type,rp-vna-site-id | Allowed forward headers |
| `BODY_SIZE_LIMIT_MB` | No | 10 | Max request body size |
| `TOKEN_RETRY_COUNT` | No | 3 | Token fetch retry count |
| `TOKEN_RETRY_DELAY_MS` | No | 1000 | Base retry delay |
| `OTEL_SERVICE_NAME` | No | token-proxy | Service name for tracing |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | - | OTLP endpoint for traces |

## Deployment

### Build Docker Image

```bash
docker build -t token-proxy:v2 .
```

### Create Secret

```bash
cp token-proxy-secret.yaml.template token-proxy-secret.yaml
# Edit token-proxy-secret.yaml with actual values
kubectl apply -f token-proxy-secret.yaml -n ohif-ac
```

### Deploy to Kubernetes

```bash
kubectl apply -f token-proxy.yaml -n ohif-ac
```

### Verify Deployment

```bash
kubectl get pods -n ohif-ac -l app=token-proxy
kubectl logs -n ohif-ac -l app=token-proxy --tail=50
```

## Kubernetes Resources

The `token-proxy.yaml` includes:

- **ConfigMap**: Non-sensitive configuration
- **Deployment**: 2 replicas with security hardening
- **Service**: ClusterIP on port 3000
- **ServiceAccount**: Dedicated service account
- **PodDisruptionBudget**: Minimum 1 pod available
- **HorizontalPodAutoscaler**: Scale 2-10 replicas based on CPU/memory
- **NetworkPolicy**: Restrict ingress/egress traffic

## Metrics

Available Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `http_request_duration_seconds` | Histogram | Request duration |
| `http_requests_total` | Counter | Total requests |
| `token_fetch_duration_seconds` | Histogram | Token fetch duration |
| `token_fetch_total` | Counter | Token fetch attempts |
| `token_cache_hits_total` | Counter | Cache hits |
| `token_cache_misses_total` | Counter | Cache misses |
| `upstream_request_duration_seconds` | Histogram | VNA request duration |
| `circuit_breaker_state` | Gauge | Circuit breaker state |
| `errors_by_status_code_total` | Counter | Errors by status code |

## Local Development

```bash
# Install dependencies
npm install

# Set required environment variables
export OAUTH_TOKEN_URL="https://..."
export OAUTH_CLIENT_ID="..."
export OAUTH_CLIENT_SECRET="..."
export OAUTH_SCOPE="stream-dicom"
export VNA_BASE_URL="https://..."
export PROXY_AUTH_MODE="none"

# Start server
npm start
```

## Testing

```bash
# Health check
curl http://localhost:3000/health

# Get token (requires API key if enabled)
curl -H "X-API-Key: your-api-key" http://localhost:3000/token

# Proxy request
curl -H "X-API-Key: your-api-key" \
     -H "Rp-Vna-Site-Id: RPVNA-1" \
     "http://localhost:3000/proxy/rp/vna/query/studies?limit=2"

# Metrics
curl http://localhost:3000/metrics
```

## Error Codes

| Code | Description |
|------|-------------|
| `INVALID_API_KEY` | Missing or invalid API key |
| `TOKEN_UNAVAILABLE` | Failed to fetch OAuth2 token |
| `UPSTREAM_ERROR` | VNA returned an error |
| `CIRCUIT_OPEN` | Circuit breaker is open |
| `CONNECTION_FAILED` | Failed to connect to upstream |
| `ENDPOINT_NOT_FOUND` | Unknown endpoint |
| `INTERNAL_SERVER_ERROR` | Unexpected error |

## Non-Functional Targets

- Availability: 99.9%
- p95 proxy latency: <= 250ms (cache hits)
- p95 token fetch latency: <= 2s
- Error budget: 0.1% of monthly requests
