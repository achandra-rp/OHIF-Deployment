// Token Proxy Service for OAuth2 Client Credentials Flow
// Fetches and caches OAuth2 tokens on behalf of browser applications

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

// Configuration
const config = {
  // OAuth2 Provider Settings
  tokenUrl: process.env.OAUTH_TOKEN_URL || 'https://ciam-radpartners.oktapreview.com/oauth2/ausi5i8tqwLfitWSI1d7/v1/token',
  clientId: process.env.OAUTH_CLIENT_ID || '0oahv72jg6XGpk4Gd1d7',
  clientSecret: process.env.OAUTH_CLIENT_SECRET || 'Q8q78Dl0TUQ_cqA-ymcbdb2Tz5acG0z1fmw1lawLaSTEp-enJOcCIuy03l5rPQ38',
  scope: process.env.OAUTH_SCOPE || 'stream-dicom',

  // Server Settings
  port: process.env.PORT || 3000,
  host: process.env.HOST || '0.0.0.0',

  // Token Cache Settings
  defaultTokenTtl: parseInt(process.env.TOKEN_CACHE_TTL || '3300', 10), // 55 minutes
  expiryBuffer: parseInt(process.env.TOKEN_EXPIRY_BUFFER || '300', 10), // 5 minutes
  cleanupInterval: parseInt(process.env.CACHE_CLEANUP_INTERVAL || '600', 10), // 10 minutes

  // Security
  enableAuth: process.env.ENABLE_AUTH === 'true',
  apiKey: process.env.API_KEY || null,

  // Logging
  logLevel: process.env.LOG_LEVEL || 'info',

  // Request Proxy Settings
  enableProxy: true,  // Enable VNA proxy mode
  upstreamTimeout: parseInt(process.env.UPSTREAM_TIMEOUT || '30000', 10),
  vnaBaseUrl: process.env.VNA_BASE_URL || 'https://rp.dev.aws.radpartners.com/rpvna-dev'
};

// Simple in-memory cache with TTL
class TokenCache {
  constructor() {
    this.cache = new Map();
    this.lastCleanup = Date.now();
  }

  get(key) {
    this.cleanupIfNeeded();
    const item = this.cache.get(key);
    if (!item) return null;

    if (item.expiresAt <= Date.now()) {
      this.cache.delete(key);
      return null;
    }

    return item.value;
  }

  set(key, value, ttlSeconds) {
    const expiresAt = Date.now() + (ttlSeconds * 1000);
    this.cache.set(key, { value, expiresAt });
    return value;
  }

  delete(key) {
    return this.cache.delete(key);
  }

  cleanupIfNeeded() {
    const now = Date.now();
    if (now - this.lastCleanup < config.cleanupInterval * 1000) return;

    this.lastCleanup = now;
    let cleaned = 0;

    for (const [key, item] of this.cache.entries()) {
      if (item.expiresAt <= now) {
        this.cache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      log('debug', `Cache cleanup removed ${cleaned} expired tokens`);
    }
  }

  clear() {
    const size = this.cache.size;
    this.cache.clear();
    log('info', `Cache cleared, removed ${size} tokens`);
  }

  size() {
    this.cleanupIfNeeded();
    return this.cache.size;
  }
}

// Token Service
class TokenService {
  constructor(cache) {
    this.cache = cache;
    this.fetching = new Map(); // Prevent concurrent fetches for same token
  }

  /**
   * Get a valid token from cache or fetch a new one
   */
  async getToken() {
    const cacheKey = this.getCacheKey();
    const cachedToken = this.cache.get(cacheKey);

    if (cachedToken) {
      log('info', 'Returning cached token');
      return cachedToken;
    }

    // Check if token is currently being fetched (prevent thundering herd)
    if (this.fetching.has(cacheKey)) {
      log('debug', 'Token fetch already in progress, waiting...');
      return this.fetching.get(cacheKey);
    }

    // Fetch new token
    log('info', 'No valid cached token, fetching from OAuth provider');
    const fetchPromise = this.fetchTokenFromProvider()
      .then(token => {
        this.fetching.delete(cacheKey);
        return token;
      })
      .catch(error => {
        this.fetching.delete(cacheKey);
        throw error;
      });

    this.fetching.set(cacheKey, fetchPromise);
    return fetchPromise;
  }

  /**
   * Fetch token directly from OAuth provider (bypass cache)
   */
  async fetchTokenFromProvider() {
    try {
      log('info', 'Fetching new token from OAuth provider', { tokenUrl: maskUrl(config.tokenUrl) });

      const tokenRequestBody = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: config.clientId,
        client_secret: config.clientSecret,
        scope: config.scope
      });

      const response = await axios.post(config.tokenUrl, tokenRequestBody.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        timeout: config.upstreamTimeout
      });

      if (!response.data.access_token || !response.data.expires_in) {
        throw new Error('Invalid token response: missing access_token or expires_in');
      }

      const token = {
        access_token: response.data.access_token,
        token_type: response.data.token_type || 'Bearer',
        expires_in: response.data.expires_in,
        scope: response.data.scope || config.scope,
        obtained_at: Math.floor(Date.now() / 1000)
      };

      log('info', 'Token fetched successfully', {
        expiresIn: token.expires_in,
        scope: token.scope
      });

      log('debug', 'Token details', {
        tokenPreview: token.access_token.substring(0, 20) + '...',
        tokenType: token.token_type
      });

      // Cache token with expiry buffer
      const cacheTtl = Math.max(1, token.expires_in - config.expiryBuffer);
      const cacheKey = this.getCacheKey();
      this.cache.set(cacheKey, token, cacheTtl);

      log('info', `Token cached for ${cacheTtl} seconds (with ${config.expiryBuffer}s buffer)`);

      return token;
    } catch (error) {
      log('error', 'Failed to fetch token from OAuth provider', {
        error: error.message,
        status: error.response?.status,
        statusText: error.response?.statusText,
        responseData: error.response?.data
      });
      throw error;
    }
  }

  /**
   * Clear cached token (useful after 401 errors)
   */
  clearToken() {
    const cacheKey = this.getCacheKey();
    this.cache.delete(cacheKey);
    log('info', 'Token cleared from cache');
  }

  /**
   * Get cache key based on client_id and scope
   */
  getCacheKey() {
    const scopeHash = crypto.createHash('md5').update(config.scope).digest('hex');
    return `token:${config.clientId}:${scopeHash}`;
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return {
      size: this.cache.size(),
      config: {
        tokenCacheTtl: config.defaultTokenTtl,
        expiryBuffer: config.expiryBuffer,
        clientId: maskString(config.clientId, 4, 4)
      }
    };
  }
}

// Express App
class TokenProxyApp {
  constructor() {
    this.app = express();
    this.cache = new TokenCache();
    this.tokenService = new TokenService(this.cache);
    this.setupMiddleware();
    this.setupRoutes();
  }

  setupMiddleware() {
    // Body parser for JSON
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // CORS
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-API-Key');

      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
      } else {
        next();
      }
    });

    // API Key authentication (optional)
    if (config.enableAuth && config.apiKey) {
      this.app.use((req, res, next) => {
        if (req.path === '/health' || req.path === '/ready') {
          return next();
        }

        const apiKey = req.headers['x-api-key'] || req.query.apiKey;
        if (!apiKey || apiKey !== config.apiKey) {
          return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or missing API key' });
        }
        next();
      });
    }

    // Request logging
    this.app.use((req, res, next) => {
      const start = Date.now();
      const originalSend = res.send;

      res.send = function(body) {
        res.send = originalSend;
        const duration = Date.now() - start;
        log('info', `${req.method} ${req.path} ${res.statusCode} - ${duration}ms`);
        return res.send(body);
      };

      next();
    });
  }

  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'token-proxy'
      });
    });

    // Readiness check
    this.app.get('/ready', (req, res) => {
      res.json({
        status: 'ready',
        timestamp: new Date().toISOString()
      });
    });

    // Get token endpoint (simple)
    this.app.get('/token', async (req, res) => {
      try {
        const token = await this.tokenService.getToken();
        res.json({
          access_token: token.access_token,
          token_type: token.token_type,
          expires_in: token.expires_in - config.expiryBuffer
        });
      } catch (error) {
        res.status(500).json({
          error: 'token_fetch_failed',
          message: 'Failed to fetch OAuth2 token',
          details: error.message
        });
      }
    });

    // Get token with full details
    this.app.get('/token/details', async (req, res) => {
      try {
        const token = await this.tokenService.getToken();
        res.json(token);
      } catch (error) {
        res.status(500).json({
          error: 'token_fetch_failed',
          message: 'Failed to fetch OAuth2 token',
          details: error.message
        });
      }
    });

    // Clear cached token
    this.app.post('/token/clear', (req, res) => {
      this.tokenService.clearToken();
      res.json({ message: 'Token cleared from cache' });
    });

    // Cache statistics
    this.app.get('/cache/stats', (req, res) => {
      res.json(this.tokenService.getCacheStats());
    });

    // Proxy mode: Forward requests to upstream with token injection
    if (config.enableProxy) {
      this.app.use('/proxy', async (req, res) => {
        await this.handleProxy(req, res);
      });
    }

    // Default route
    this.app.get('/', (req, res) => {
      res.json({
        service: 'token-proxy',
        version: '1.0.0',
        endpoints: [
          { path: '/health', description: 'Health check' },
          { path: '/token', description: 'Get OAuth2 access token' },
          { path: '/token/details', description: 'Get token with full details' },
          { path: '/token/clear', method: 'POST', description: 'Clear cached token' },
          { path: '/cache/stats', description: 'Cache statistics' }
        ],
        proxyEnabled: config.enableProxy
      });
    });

    // Error handler
    this.app.use((error, req, res, next) => {
      log('error', 'Unhandled error', {
        error: error.message,
        stack: error.stack,
        path: req.path,
        method: req.method
      });

      res.status(500).json({
        error: 'internal_error',
        message: 'An unexpected error occurred'
      });
    });

    // 404 handler
    this.app.use((req, res) => {
      res.status(404).json({
        error: 'not_found',
        message: `Endpoint ${req.method} ${req.path} not found`
      });
    });
  }

  /**
   * Handle proxy requests - forward to upstream with token injection
   */
  async handleProxy(req, res) {
    try {
      const token = await this.tokenService.getToken();
      // Build target URL - req.url includes query params, remove /proxy prefix
      let urlWithoutProxy = req.url.replace(/^\/proxy\/?/, '');

      log('info', 'Processing proxy request', {
        reqUrl: req.url,
        urlWithoutProxy: urlWithoutProxy,
        vnaBaseUrl: config.vnaBaseUrl,
        isInternalDns: config.vnaBaseUrl.includes('.svc.cluster.local')
      });

      // When using internal cluster DNS, strip the VNA environment name from the path
      // Internal VNA services don't need the environment name in the URL path
      // Example: query-rs-v1.rpvna-dev.svc.cluster.local/rp/vna/... (not /rpvna-dev/rp/vna/...)
      if (config.vnaBaseUrl.includes('.svc.cluster.local') && !urlWithoutProxy.startsWith('/rp/vna/')) {
        log('info', 'Stripping VNA environment from path');
        const originalUrl = urlWithoutProxy;
        // Match leading slash + environment name + slash (e.g., /rpvna-dev/)
        urlWithoutProxy = urlWithoutProxy.replace(/^\/[^\/]+\//, '/');
        log('info', 'Path modified', {
          original: originalUrl,
          modified: urlWithoutProxy
        });
      }

      const targetUrl = config.vnaBaseUrl + (urlWithoutProxy.startsWith('/') ? '' : '/') + urlWithoutProxy;

      log('info', 'Proxying VNA request with token', {
        requestedPath: req.url,
        targetUrl: maskUrl(targetUrl),
        method: req.method,
        isInternalDns: config.vnaBaseUrl.includes('.svc.cluster.local')
      });

      // Extract VNA site ID from request headers (if provided)
      const vnaSiteId = req.headers['rp-vna-site-id'] || req.headers['Rp-Vna-Site-Id'] || 'RPVNA-1';

      // Build request config with all required VNA headers
      const requestConfig = {
        method: req.method,
        url: targetUrl,
        headers: {
          ...req.headers,
          'Authorization': `Bearer ${token.access_token}`,
          'Rp-Vna-Site-Id': vnaSiteId,
          'Accept': 'application/dicom+json',
          'Content-Type': req.method === 'GET' ? undefined : 'application/dicom+json',
          'host': undefined // Let axios set the host
        },
        params: req.query,
        data: req.body,
        timeout: config.upstreamTimeout,
        maxRedirects: 5,
        validateStatus: null // Don't throw on error status codes
      };

      const response = await axios(requestConfig);

      // Forward response
      res.status(response.status);

      // Copy important headers from upstream
      const headersToForward = [
        'content-type',
        'content-length',
        'cache-control',
        'access-control-allow-origin',
        'access-control-allow-headers',
        'access-control-allow-methods'
      ];

      Object.keys(response.headers).forEach(key => {
        try {
          if (headersToForward.includes(key.toLowerCase())) {
            res.setHeader(key, response.headers[key]);
          }
        } catch (e) {
          // Ignore headers that can't be set
        }
      });

      // Ensure CORS is allowed from any origin for browser access
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Rp-Vna-Site-Id, Accept');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');

      res.send(response.data);
    } catch (error) {
      log('error', 'Proxy request failed', {
        error: error.message,
        path: req.path,
        method: req.method
      });

      if (error.response) {
        res.status(error.response.status || 502).json({
          error: 'proxy_error',
          message: 'Upstream request failed',
          details: error.response.data
        });
      } else {
        res.status(502).json({
          error: 'proxy_error',
          message: 'Failed to connect to upstream'
        });
      }
    }
  }

  start() {
    return new Promise((resolve, reject) => {
      try {
        const server = this.app.listen(config.port, config.host, () => {
          log('info', `Token proxy server started`, {
            host: config.host,
            port: config.port,
            oauthProvider: maskUrl(config.tokenUrl),
            tokenCacheEnabled: true,
            tokenCacheTtl: config.defaultTokenTtl,
            proxyEnabled: config.enableProxy
          });
          resolve(server);
        });

        server.on('error', (error) => {
          log('error', 'Server failed to start', { error: error.message });
          reject(error);
        });
      } catch (error) {
        reject(error);
      }
    });
  }
}

// Logging utilities
function log(level, message, meta = {}) {
  const levels = ['debug', 'info', 'warn', 'error'];
  if (levels.indexOf(level) < levels.indexOf(config.logLevel)) {
    return;
  }

  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level: level.toUpperCase(),
    message,
    ...meta
  };

  if (level === 'error') {
    console.error(JSON.stringify(logEntry));
  } else {
    console.log(JSON.stringify(logEntry));
  }
}

function maskUrl(url) {
  if (!url || typeof url !== 'string') return url;
  try {
    const urlObj = new URL(url);
    return `${urlObj.protocol}//${urlObj.hostname}${urlObj.pathname}`;
  } catch (e) {
    return url;
  }
}

function maskString(str, showFirst = 4, showLast = 4) {
  if (!str || typeof str !== 'string') return str;
  if (str.length <= showFirst + showLast) return str;
  return str.substring(0, showFirst) + '****' + str.substring(str.length - showLast);
}

// Graceful shutdown
function setupGracefulShutdown(server) {
  const shutdown = async (signal) => {
    log('info', `Received ${signal}, shutting down gracefully...`);

    try {
      await new Promise((resolve) => {
        server.close(resolve);
      });
      log('info', 'Server closed');
      process.exit(0);
    } catch (error) {
      log('error', 'Error during shutdown', { error: error.message });
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Start server if run directly
if (require.main === module) {
  const app = new TokenProxyApp();

  app.start()
    .then(server => {
      setupGracefulShutdown(server);
    })
    .catch(error => {
      log('error', 'Failed to start application', { error: error.message });
      process.exit(1);
    });
}

module.exports = { TokenProxyApp, TokenService, TokenCache, config };
