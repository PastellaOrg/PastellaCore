/**
 * Authentication middleware for Wallet API
 */

const logger = require('../../utils/logger');

/**
 * API Key authentication middleware
 * @param {string} expectedApiKey - The expected API key
 */
function authMiddleware(expectedApiKey) {
  return (req, res, next) => {
    // Skip auth for health and info endpoints
    if (req.path === '/health' || req.path === '/info') {
      return next();
    }

    const apiKey = req.headers['x-api-key'] || req.headers.authorization?.replace('Bearer ', '');

    if (!apiKey) {
      logger.warn(`API access denied - missing API key from ${req.ip}`);
      return res.status(401).json({
        error: 'API key required. Include X-API-Key header or Authorization: Bearer <key>',
      });
    }

    if (apiKey !== expectedApiKey) {
      logger.warn(`API access denied - invalid API key from ${req.ip}`);
      return res.status(401).json({
        error: 'Invalid API key',
      });
    }

    // API key is valid, proceed
    next();
  };
}

module.exports = {
  authMiddleware,
};
