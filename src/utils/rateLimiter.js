const logger = require('./logger');

/**
 * Rate Limiter for API Protection
 * Prevents DoS attacks by limiting requests per IP address and endpoint
 */
class RateLimiter {
  /**
   *
   */
  constructor() {
    // Store request counts per IP and endpoint
    this.requestCounts = new Map();

    // Configuration for different endpoints
    this.limits = {
      // General API requests
      default: { maxRequests: 1000, windowMs: 60000 }, // 1000 requests per minute

      // Transaction submission (moderate - allow more for blockchain usage)
      submitTransaction: { maxRequests: 100, windowMs: 60000 }, // 100 transactions per minute

      // Mining operations (moderate - mining needs to be frequent)
      mining: { maxRequests: 200, windowMs: 60000 }, // 200 mining requests per minute

      // Blockchain queries (high - blockchain needs frequent queries)
      blockchain: { maxRequests: 500, windowMs: 60000 }, // 500 queries per minute

      // Network operations (moderate)
      network: { maxRequests: 300, windowMs: 60000 }, // 300 network requests per minute

      // Wallet operations (high - wallets need frequent access)
      wallet: { maxRequests: 400, windowMs: 60000 }, // 400 wallet operations per minute
    };

    // Cleanup interval (remove old entries every 5 minutes)
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);

    logger.info('RATE_LIMITER', 'Rate limiter initialized with DoS protection');
  }

  /**
   * Check if a request is allowed
   * @param {string} ip - Client IP address
   * @param {string} endpoint - API endpoint being accessed
   * @returns {boolean} - True if request is allowed, false if rate limited
   */
  isAllowed(ip, endpoint) {
    const now = Date.now();
    const key = `${ip}:${endpoint}`;

    // Get the appropriate limit for this endpoint
    const limit = this.getLimitForEndpoint(endpoint);

    // Get current request count for this IP+endpoint
    const requestData = this.requestCounts.get(key) || { count: 0, firstRequest: now };

    // Check if we're in a new time window
    if (now - requestData.firstRequest > limit.windowMs) {
      // Reset for new time window
      requestData.count = 1;
      requestData.firstRequest = now;
      this.requestCounts.set(key, requestData);
      return true;
    }

    // Check if we're under the limit
    if (requestData.count < limit.maxRequests) {
      requestData.count++;
      this.requestCounts.set(key, requestData);
      return true;
    }

    // Rate limited - log the attempt
    logger.warn(
      'RATE_LIMITER',
      `Rate limited: ${ip} exceeded limit for ${endpoint} (${requestData.count}/${limit.maxRequests} in ${limit.windowMs}ms)`
    );
    return false;
  }

  /**
   * Get rate limit configuration for a specific endpoint
   * @param {string} endpoint - API endpoint
   * @returns {object} - Rate limit configuration
   */
  getLimitForEndpoint(endpoint) {
    // Check for specific endpoint limits
    if (endpoint.includes('/submit-transaction') || endpoint.includes('submitTransaction')) {
      return this.limits.submitTransaction;
    }

    if (endpoint.includes('/mining') || endpoint.includes('/mine') || endpoint.includes('mining')) {
      return this.limits.mining;
    }

    if (endpoint.includes('/blockchain') || endpoint.includes('blockchain')) {
      return this.limits.blockchain;
    }

    if (endpoint.includes('/network') || endpoint.includes('network')) {
      return this.limits.network;
    }

    if (endpoint.includes('/wallet') || endpoint.includes('wallet')) {
      return this.limits.wallet;
    }

    // Default limit for unknown endpoints
    return this.limits.default;
  }

  /**
   * Get current rate limit status for an IP and endpoint
   * @param {string} ip - Client IP address
   * @param {string} endpoint - API endpoint
   * @returns {object} - Rate limit status information
   */
  getStatus(ip, endpoint) {
    const key = `${ip}:${endpoint}`;
    const requestData = this.requestCounts.get(key);
    const limit = this.getLimitForEndpoint(endpoint);

    if (!requestData) {
      return {
        remaining: limit.maxRequests,
        resetTime: Date.now() + limit.windowMs,
        limit: limit.maxRequests,
        windowMs: limit.windowMs,
      };
    }

    const now = Date.now();
    const timeUntilReset = Math.max(0, requestData.firstRequest + limit.windowMs - now);

    return {
      remaining: Math.max(0, limit.maxRequests - requestData.count),
      resetTime: requestData.firstRequest + limit.windowMs,
      limit: limit.maxRequests,
      windowMs: limit.windowMs,
      timeUntilReset,
    };
  }

  /**
   * Clean up old rate limit entries
   */
  cleanup() {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, data] of this.requestCounts.entries()) {
      const limit = this.getLimitForEndpoint(key.split(':')[1]);
      if (now - data.firstRequest > limit.windowMs * 2) {
        this.requestCounts.delete(key);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.debug('RATE_LIMITER', `Cleaned up ${cleanedCount} old rate limit entries`);
    }
  }

  /**
   * Get rate limiter statistics
   * @returns {object} - Statistics about current rate limiting
   */
  getStats() {
    const stats = {
      totalTrackedIPs: new Set(),
      totalRequests: 0,
      endpointStats: {},
    };

    for (const [key, data] of this.requestCounts.entries()) {
      const [ip, endpoint] = key.split(':');
      stats.totalTrackedIPs.add(ip);
      stats.totalRequests += data.count;

      if (!stats.endpointStats[endpoint]) {
        stats.endpointStats[endpoint] = { requests: 0, ips: new Set() };
      }
      stats.endpointStats[endpoint].requests += data.count;
      stats.endpointStats[endpoint].ips.add(ip);
    }

    // Convert Sets to counts for JSON serialization
    stats.totalTrackedIPs = stats.totalTrackedIPs.size;
    for (const endpoint in stats.endpointStats) {
      stats.endpointStats[endpoint].ips = stats.endpointStats[endpoint].ips.size;
    }

    return stats;
  }

  /**
   * Reset rate limits for a specific IP (admin function)
   * @param {string} ip - IP address to reset
   */
  resetForIP(ip) {
    let resetCount = 0;

    for (const [key] of this.requestCounts.entries()) {
      if (key.startsWith(`${ip}:`)) {
        this.requestCounts.delete(key);
        resetCount++;
      }
    }

    if (resetCount > 0) {
      logger.info('RATE_LIMITER', `Reset rate limits for IP ${ip} (${resetCount} endpoints)`);
    }

    return resetCount;
  }

  /**
   * Reset all rate limits (admin function)
   */
  resetAll() {
    const totalEntries = this.requestCounts.size;
    this.requestCounts.clear();

    if (totalEntries > 0) {
      logger.info('RATE_LIMITER', `Reset all rate limits (${totalEntries} entries cleared)`);
    }

    return totalEntries;
  }

  /**
   * Shutdown cleanup
   */
  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.requestCounts.clear();
    logger.info('RATE_LIMITER', 'Rate limiter shutdown complete');
  }
}

module.exports = RateLimiter;
