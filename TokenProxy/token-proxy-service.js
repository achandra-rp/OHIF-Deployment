'use strict';

// Production Token Proxy Service for OAuth2 Client Credentials Flow
// Implements all requirements from TOKEN-PROXY-PRODUCTION-REQUIREMENTS.md

const express = require('express');
const axios = require('axios');
const http = require('http');
const https = require('https');
const { z } = require('zod');
const { v4: uuidv4 } = require('uuid');
const promClient = require('prom-client');
const { trace, context, SpanStatusCode } = require('@opentelemetry/api');

// ============================================================================
// Configuration Validation (Zod)
// ============================================================================

const configSchema = z.object({
  PORT: z.coerce.number().default(3000),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

  // OAuth2 settings
  OAUTH_TOKEN_URL: z.string().url(),
  OAUTH_CLIENT_ID: z.string().min(1),
  OAUTH_CLIENT_SECRET: z.string().min(1),
  OAUTH_SCOPE: z.string().min(1),
  TOKEN_CACHE_TTL_SEC: z.coerce.number().default(3300),
  TOKEN_EXPIRY_BUFFER_SEC: z.coerce.number().default(300),
  TOKEN_TIMEOUT_MS: z.coerce.number().default(5000),

  // VNA settings
  VNA_BASE_URL: z.string().url(),
  VNA_TIMEOUT_MS: z.coerce.number().default(10000),

  // Auth settings
  PROXY_AUTH_MODE: z.enum(['none', 'api_key', 'jwt', 'mtls']).default('api_key'),
  PROXY_API_KEY: z.string().optional(),

  // Header allowlist
  FORWARDED_HEADER_ALLOWLIST: z.string().default('accept,content-type,rp-vna-site-id,rp-vna-operation-location,rp-vna-cross-site-query,rp-vna-site-group-expansion,rp-vna-exclude-default-tags,rp-vna-include-private-block,rp-vna-generate-store-uids,rp-vna-qc-trusted,rp-vna-qc-trusted-allow-null-overwrites,dicompatientid,dicompatientname,dicomissuerofpatientid'),

  // Body size limit
  BODY_SIZE_LIMIT_MB: z.coerce.number().default(10),

  // Circuit breaker settings
  CIRCUIT_BREAKER_TIMEOUT_MS: z.coerce.number().default(30000),
  CIRCUIT_BREAKER_ERROR_THRESHOLD: z.coerce.number().default(50),
  CIRCUIT_BREAKER_RESET_TIMEOUT_MS: z.coerce.number().default(30000),

  // Retry settings
  TOKEN_RETRY_COUNT: z.coerce.number().default(3),
  TOKEN_RETRY_DELAY_MS: z.coerce.number().default(1000),

  // OpenTelemetry
  OTEL_EXPORTER_OTLP_ENDPOINT: z.string().optional(),
  OTEL_SERVICE_NAME: z.string().default('token-proxy'),
});

let config;
try {
  config = configSchema.parse(process.env);
} catch (err) {
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'ERROR',
    message: 'Configuration validation failed',
    errors: err.errors
  }));
  process.exit(1);
}

// ============================================================================
// Logging (Structured, with request/trace IDs, secret redaction)
// ============================================================================

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const REDACTED_HEADERS = new Set(['authorization', 'cookie', 'x-api-key', 'proxy-authorization']);

function log(level, message, meta = {}) {
  if (LOG_LEVELS[level] < LOG_LEVELS[config.LOG_LEVEL]) {
    return;
  }

  const sanitizedMeta = sanitizeLogMeta(meta);
  const logEntry = {
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    message,
    service: config.OTEL_SERVICE_NAME,
    ...sanitizedMeta
  };

  const output = JSON.stringify(logEntry);
  if (level === 'error') {
    console.error(output);
  } else {
    console.log(output);
  }
}

function sanitizeLogMeta(meta) {
  const sanitized = {};
  for (const [key, value] of Object.entries(meta)) {
    if (key.toLowerCase() === 'headers' && typeof value === 'object') {
      sanitized[key] = sanitizeHeaders(value);
    } else if (REDACTED_HEADERS.has(key.toLowerCase())) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'string' && value.length > 100) {
      sanitized[key] = value.substring(0, 100) + '...[truncated]';
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

function sanitizeHeaders(headers) {
  const sanitized = {};
  for (const [key, value] of Object.entries(headers)) {
    if (REDACTED_HEADERS.has(key.toLowerCase())) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

// ============================================================================
// Prometheus Metrics
// ============================================================================

const metricsRegistry = new promClient.Registry();
promClient.collectDefaultMetrics({ register: metricsRegistry });

const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [metricsRegistry]
});

const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [metricsRegistry]
});

const tokenFetchDuration = new promClient.Histogram({
  name: 'token_fetch_duration_seconds',
  help: 'Duration of token fetch requests in seconds',
  buckets: [0.1, 0.25, 0.5, 1, 2, 5],
  registers: [metricsRegistry]
});

const tokenFetchTotal = new promClient.Counter({
  name: 'token_fetch_total',
  help: 'Total number of token fetch attempts',
  labelNames: ['status'],
  registers: [metricsRegistry]
});

const tokenCacheHits = new promClient.Counter({
  name: 'token_cache_hits_total',
  help: 'Total number of token cache hits',
  registers: [metricsRegistry]
});

const tokenCacheMisses = new promClient.Counter({
  name: 'token_cache_misses_total',
  help: 'Total number of token cache misses',
  registers: [metricsRegistry]
});

const upstreamRequestDuration = new promClient.Histogram({
  name: 'upstream_request_duration_seconds',
  help: 'Duration of upstream VNA requests in seconds',
  labelNames: ['method', 'status_code'],
  buckets: [0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [metricsRegistry]
});

const circuitBreakerState = new promClient.Gauge({
  name: 'circuit_breaker_state',
  help: 'Circuit breaker state (0=closed, 1=open, 2=half-open)',
  labelNames: ['name'],
  registers: [metricsRegistry]
});

const errorsByStatusCode = new promClient.Counter({
  name: 'errors_by_status_code_total',
  help: 'Total errors by status code',
  labelNames: ['status_code', 'endpoint'],
  registers: [metricsRegistry]
});

// ============================================================================
// Circuit Breaker
// ============================================================================

const CircuitBreaker = require('opossum');

function createCircuitBreaker(fn, name) {
  const breaker = new CircuitBreaker(fn, {
    timeout: config.CIRCUIT_BREAKER_TIMEOUT_MS,
    errorThresholdPercentage: config.CIRCUIT_BREAKER_ERROR_THRESHOLD,
    resetTimeout: config.CIRCUIT_BREAKER_RESET_TIMEOUT_MS,
    name
  });

  breaker.on('open', () => {
    circuitBreakerState.set({ name }, 1);
    log('warn', `Circuit breaker opened: ${name}`);
  });

  breaker.on('halfOpen', () => {
    circuitBreakerState.set({ name }, 2);
    log('info', `Circuit breaker half-open: ${name}`);
  });

  breaker.on('close', () => {
    circuitBreakerState.set({ name }, 0);
    log('info', `Circuit breaker closed: ${name}`);
  });

  circuitBreakerState.set({ name }, 0);
  return breaker;
}

// ============================================================================
// Token Cache with Singleflight Pattern
// ============================================================================

class TokenCache {
  constructor() {
    this.token = null;
    this.expiresAtMs = 0;
    this.inflightPromise = null;
    this.expiresInSec = 0;
  }

  isValid(nowMs, bufferMs) {
    return this.token && (this.expiresAtMs - bufferMs) > nowMs;
  }

  async getToken(fetchFn, nowMs, bufferSec) {
    if (this.isValid(nowMs, bufferSec * 1000)) {
      tokenCacheHits.inc();
      return { access_token: this.token, expires_in: this.expiresInSec };
    }

    tokenCacheMisses.inc();

    if (!this.inflightPromise) {
      this.inflightPromise = fetchFn()
        .then(tokenResponse => {
          this.token = tokenResponse.access_token;
          this.expiresAtMs = nowMs + (tokenResponse.expires_in * 1000);
          this.expiresInSec = tokenResponse.expires_in;
          this.inflightPromise = null;
          return tokenResponse;
        })
        .catch(err => {
          this.inflightPromise = null;
          throw err;
        });
    }

    return this.inflightPromise;
  }

  clear() {
    this.token = null;
    this.expiresAtMs = 0;
    this.inflightPromise = null;
  }
}

const tokenCache = new TokenCache();

// ============================================================================
// Token Fetch with Retries and Exponential Backoff
// ============================================================================

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchTokenWithRetry() {
  const tracer = trace.getTracer(config.OTEL_SERVICE_NAME);

  return tracer.startActiveSpan('fetchToken', async (span) => {
    const endTimer = tokenFetchDuration.startTimer();
    let lastError;

    for (let attempt = 1; attempt <= config.TOKEN_RETRY_COUNT; attempt++) {
      try {
        span.setAttribute('attempt', attempt);

        const payload = new URLSearchParams({
          grant_type: 'client_credentials',
          scope: config.OAUTH_SCOPE
        });

        const response = await axios.post(config.OAUTH_TOKEN_URL, payload.toString(), {
          auth: {
            username: config.OAUTH_CLIENT_ID,
            password: config.OAUTH_CLIENT_SECRET
          },
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
          },
          timeout: config.TOKEN_TIMEOUT_MS
        });

        if (!response.data.access_token || !response.data.expires_in) {
          throw new Error('Invalid token response: missing access_token or expires_in');
        }

        endTimer();
        tokenFetchTotal.inc({ status: 'success' });
        span.setStatus({ code: SpanStatusCode.OK });
        span.end();

        log('info', 'Token fetched successfully', {
          attempt,
          expiresIn: response.data.expires_in
        });

        return response.data;

      } catch (err) {
        lastError = err;
        log('warn', `Token fetch attempt ${attempt} failed`, {
          attempt,
          error: err.message,
          status: err.response?.status
        });

        if (attempt < config.TOKEN_RETRY_COUNT) {
          const delayMs = config.TOKEN_RETRY_DELAY_MS * Math.pow(2, attempt - 1);
          await sleep(delayMs);
        }
      }
    }

    endTimer();
    tokenFetchTotal.inc({ status: 'failure' });
    span.setStatus({ code: SpanStatusCode.ERROR, message: lastError.message });
    span.end();

    log('error', 'Token fetch failed after all retries', {
      error: lastError.message,
      attempts: config.TOKEN_RETRY_COUNT
    });

    throw lastError;
  });
}

const tokenFetchBreaker = createCircuitBreaker(fetchTokenWithRetry, 'tokenFetch');

// ============================================================================
// Header Allowlist and Validation
// ============================================================================

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade'
]);

function buildForwardHeaders(req, token, siteId) {
  const allowlist = new Set(
    config.FORWARDED_HEADER_ALLOWLIST.split(',').map(h => h.trim().toLowerCase())
  );
  const headers = {};

  for (const [key, value] of Object.entries(req.headers)) {
    const lowerKey = key.toLowerCase();

    if (HOP_BY_HOP_HEADERS.has(lowerKey)) {
      continue;
    }

    if (!allowlist.has(lowerKey)) {
      continue;
    }

    headers[key] = value;
  }

  headers['Authorization'] = `Bearer ${token}`;
  headers['Rp-Vna-Site-Id'] = siteId;

  return headers;
}

// ============================================================================
// HTTP Keep-Alive Agents
// ============================================================================

const keepAliveHttpAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 50,
  maxFreeSockets: 10,
  timeout: 60000
});

const keepAliveHttpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 50,
  maxFreeSockets: 10,
  timeout: 60000
});

// ============================================================================
// VNA Request Handler with Circuit Breaker
// ============================================================================

async function makeVnaRequest(requestConfig) {
  const tracer = trace.getTracer(config.OTEL_SERVICE_NAME);

  return tracer.startActiveSpan('vnaRequest', async (span) => {
    span.setAttribute('http.method', requestConfig.method);
    span.setAttribute('http.url', requestConfig.url);

    const endTimer = upstreamRequestDuration.startTimer({
      method: requestConfig.method
    });

    try {
      const response = await axios({
        ...requestConfig,
        httpAgent: keepAliveHttpAgent,
        httpsAgent: keepAliveHttpsAgent,
        timeout: config.VNA_TIMEOUT_MS,
        maxRedirects: 5,
        responseType: 'stream',
        validateStatus: (status) => status >= 200 && status < 500
      });

      endTimer({ status_code: response.status });
      span.setAttribute('http.status_code', response.status);
      span.setStatus({ code: SpanStatusCode.OK });
      span.end();

      return response;

    } catch (err) {
      endTimer({ status_code: 'error' });
      span.setStatus({ code: SpanStatusCode.ERROR, message: err.message });
      span.end();
      throw err;
    }
  });
}

const vnaRequestBreaker = createCircuitBreaker(makeVnaRequest, 'vnaRequest');

// ============================================================================
// Express Application
// ============================================================================

const app = express();

// Request ID and Trace ID middleware
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || uuidv4();
  req.traceId = req.headers['x-trace-id'] || uuidv4();
  res.setHeader('X-Request-Id', req.requestId);
  res.setHeader('X-Trace-Id', req.traceId);
  next();
});

// Metrics middleware
app.use((req, res, next) => {
  const start = process.hrtime.bigint();

  res.on('finish', () => {
    const durationNs = Number(process.hrtime.bigint() - start);
    const durationSec = durationNs / 1e9;

    const route = req.route?.path || (req.path.startsWith('/proxy') ? '/proxy' : req.path);
    const labels = {
      method: req.method,
      route,
      status_code: res.statusCode
    };

    httpRequestDuration.observe(labels, durationSec);
    httpRequestsTotal.inc(labels);

    if (res.statusCode >= 400) {
      errorsByStatusCode.inc({
        status_code: res.statusCode,
        endpoint: route
      });
    }
  });

  next();
});

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const durationMs = Date.now() - start;
    log('info', `${req.method} ${req.path} ${res.statusCode}`, {
      requestId: req.requestId,
      traceId: req.traceId,
      durationMs,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      userAgent: req.headers['user-agent']
    });
  });

  next();
});

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-API-Key, Rp-Vna-Site-Id, X-Request-Id, X-Trace-Id');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// API Key authentication middleware
function requireApiKey(req, res, next) {
  if (config.PROXY_AUTH_MODE !== 'api_key') {
    return next();
  }

  if (req.path === '/health' || req.path === '/ready' || req.path === '/metrics') {
    return next();
  }

  const apiKey = req.header('x-api-key');
  if (!apiKey || apiKey !== config.PROXY_API_KEY) {
    log('warn', 'Unauthorized request - invalid API key', {
      requestId: req.requestId,
      path: req.path
    });
    return res.status(401).json({
      error: 'unauthorized',
      code: 'INVALID_API_KEY',
      message: 'Invalid or missing API key',
      requestId: req.requestId
    });
  }

  next();
}

app.use(requireApiKey);

// ============================================================================
// Routes
// ============================================================================

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: config.OTEL_SERVICE_NAME
  });
});

// Readiness check
app.get('/ready', async (req, res) => {
  try {
    // Check if we can get a token (validates Okta connectivity)
    const nowMs = Date.now();
    await tokenCache.getToken(
      () => tokenFetchBreaker.fire(),
      nowMs,
      config.TOKEN_EXPIRY_BUFFER_SEC
    );

    res.json({
      status: 'ready',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(503).json({
      status: 'not_ready',
      timestamp: new Date().toISOString(),
      error: 'Unable to fetch token'
    });
  }
});

// Prometheus metrics endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', metricsRegistry.contentType);
    res.end(await metricsRegistry.metrics());
  } catch (err) {
    res.status(500).json({ error: 'metrics_error' });
  }
});

// Token endpoint
app.get('/token', async (req, res) => {
  const tracer = trace.getTracer(config.OTEL_SERVICE_NAME);

  return tracer.startActiveSpan('getToken', async (span) => {
    try {
      const nowMs = Date.now();
      const tokenResponse = await tokenCache.getToken(
        () => tokenFetchBreaker.fire(),
        nowMs,
        config.TOKEN_EXPIRY_BUFFER_SEC
      );
      const token = tokenResponse.access_token;

      span.setStatus({ code: SpanStatusCode.OK });
      span.end();

      const remainingTtlSec = Math.max(
        0,
        Math.floor((tokenCache.expiresAtMs - Date.now()) / 1000)
      );

      res.json({
        access_token: token,
        token_type: 'Bearer',
        expires_in: remainingTtlSec
      });

    } catch (err) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: err.message });
      span.end();

      log('error', 'Token fetch failed', {
        requestId: req.requestId,
        error: err.message
      });

      res.status(503).json({
        error: 'token_fetch_failed',
        code: 'TOKEN_UNAVAILABLE',
        message: 'Failed to fetch OAuth2 token',
        requestId: req.requestId
      });
    }
  });
});

// Clear token cache
app.post('/token/clear', (req, res) => {
  tokenCache.clear();
  log('info', 'Token cache cleared', { requestId: req.requestId });
  res.json({
    message: 'Token cache cleared',
    requestId: req.requestId
  });
});

// Proxy endpoint
app.use('/proxy', async (req, res) => {
  const tracer = trace.getTracer(config.OTEL_SERVICE_NAME);

  return tracer.startActiveSpan('proxyRequest', async (span) => {
    try {
      // Get token
      const nowMs = Date.now();
      const tokenResponse = await tokenCache.getToken(
        () => tokenFetchBreaker.fire(),
        nowMs,
        config.TOKEN_EXPIRY_BUFFER_SEC
      );
      const token = tokenResponse.access_token;

      // Build target URL
      let urlPath = req.url.replace(/^\/?proxy\/?/, '');

      // Strip VNA environment prefix for internal cluster DNS
      if (config.VNA_BASE_URL.includes('.svc.cluster.local') && !urlPath.startsWith('/rp/vna/')) {
        urlPath = urlPath.replace(/^\/[^\/]+\//, '/');
      }

      const targetUrl = config.VNA_BASE_URL + (urlPath.startsWith('/') ? '' : '/') + urlPath;

      // Get site ID from headers
      const siteId = req.headers['rp-vna-site-id'] || 'RPVNA-1';

      // Build forward headers
      const headers = buildForwardHeaders(req, token, siteId);

      span.setAttribute('proxy.target_url', targetUrl);
      span.setAttribute('proxy.site_id', siteId);

      log('debug', 'Proxying request', {
        requestId: req.requestId,
        method: req.method,
        targetUrl: targetUrl.replace(/\/\/[^\/]+/, '//[host]'),
        siteId
      });

      // Make request through circuit breaker
      const response = await vnaRequestBreaker.fire({
        method: req.method,
        url: targetUrl,
        headers,
        data: req,
        maxBodyLength: Infinity,
        maxContentLength: Infinity
      });

      // Forward response status
      res.status(response.status);

      // Forward safe response headers
      const safeResponseHeaders = [
        'content-type',
        'content-length',
        'cache-control',
        'etag',
        'last-modified'
      ];

      for (const header of safeResponseHeaders) {
        if (response.headers[header]) {
          res.setHeader(header, response.headers[header]);
        }
      }

      span.setAttribute('http.response.status_code', response.status);
      span.setStatus({ code: SpanStatusCode.OK });
      span.end();

      if (response.data && typeof response.data.pipe === 'function') {
        response.data.pipe(res);
      } else {
        res.send(response.data);
      }

    } catch (err) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: err.message });
      span.end();

      log('error', 'Proxy request failed', {
        requestId: req.requestId,
        error: err.message,
        path: req.path
      });

      if (err.response) {
        if (err.response.status === 401 || err.response.status === 403) {
          tokenCache.clear();
        }
        res.status(err.response.status || 502).json({
          error: 'proxy_error',
          code: 'UPSTREAM_ERROR',
          message: 'Upstream request failed',
          statusCode: err.response.status,
          requestId: req.requestId
        });
      } else if (err.code === 'EOPENBREAKER') {
        res.status(503).json({
          error: 'service_unavailable',
          code: 'CIRCUIT_OPEN',
          message: 'Service temporarily unavailable due to upstream failures',
          requestId: req.requestId
        });
      } else {
        res.status(502).json({
          error: 'proxy_error',
          code: 'CONNECTION_FAILED',
          message: 'Failed to connect to upstream',
          requestId: req.requestId
        });
      }
    }
  });
});

// Root endpoint - service info
app.get('/', (req, res) => {
  res.json({
    service: config.OTEL_SERVICE_NAME,
    version: '2.0.0',
    endpoints: [
      { path: '/health', method: 'GET', description: 'Liveness probe' },
      { path: '/ready', method: 'GET', description: 'Readiness probe' },
      { path: '/metrics', method: 'GET', description: 'Prometheus metrics' },
      { path: '/token', method: 'GET', description: 'Get OAuth2 access token' },
      { path: '/token/clear', method: 'POST', description: 'Clear token cache' },
      { path: '/proxy/*', method: 'ALL', description: 'VNA proxy endpoint' }
    ]
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'not_found',
    code: 'ENDPOINT_NOT_FOUND',
    message: `Endpoint ${req.method} ${req.path} not found`,
    requestId: req.requestId
  });
});

// Error handler
app.use((err, req, res, next) => {
  log('error', 'Unhandled error', {
    requestId: req.requestId,
    error: err.message,
    stack: err.stack
  });

  res.status(500).json({
    error: 'internal_error',
    code: 'INTERNAL_SERVER_ERROR',
    message: 'An unexpected error occurred',
    requestId: req.requestId
  });
});

// ============================================================================
// Server Startup and Graceful Shutdown
// ============================================================================

let server;

function startServer() {
  return new Promise((resolve, reject) => {
    server = app.listen(config.PORT, config.HOST, () => {
      log('info', 'Token proxy server started', {
        host: config.HOST,
        port: config.PORT,
        authMode: config.PROXY_AUTH_MODE,
        vnaBaseUrl: config.VNA_BASE_URL.replace(/\/\/[^\/]+/, '//[host]')
      });
      resolve(server);
    });

    server.on('error', (err) => {
      log('error', 'Server failed to start', { error: err.message });
      reject(err);
    });

    // Set keep-alive timeout
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;
  });
}

async function gracefulShutdown(signal) {
  log('info', `Received ${signal}, initiating graceful shutdown`);

  if (server) {
    await new Promise((resolve) => {
      server.close(resolve);
    });
    log('info', 'Server closed');
  }

  // Close HTTP agents
  keepAliveHttpAgent.destroy();
  keepAliveHttpsAgent.destroy();

  log('info', 'Shutdown complete');
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (err) => {
  log('error', 'Uncaught exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  log('error', 'Unhandled rejection', { reason: String(reason) });
});

// Start server if run directly
if (require.main === module) {
  startServer().catch((err) => {
    log('error', 'Failed to start server', { error: err.message });
    process.exit(1);
  });
}

module.exports = { app, startServer, tokenCache, config };
