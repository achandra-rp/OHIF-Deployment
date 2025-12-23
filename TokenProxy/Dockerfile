# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies (use npm install if no lockfile, npm ci if lockfile exists)
RUN npm install --only=production && npm cache clean --force

# Production stage
FROM node:20-alpine

# Security: Use the built-in non-root user (uid 1000)

WORKDIR /app

# Copy node_modules from builder
COPY --from=builder --chown=node:node /app/node_modules ./node_modules

# Copy application code
COPY --chown=node:node token-proxy-service.js ./

# Security: Set file permissions
RUN chmod -R 555 /app && \
    chmod 444 /app/token-proxy-service.js

# Security: Run as non-root user
USER node

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Start application
CMD ["node", "token-proxy-service.js"]
