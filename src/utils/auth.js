const logger = require('./logger');

/**
 * Authentication utilities for API key validation
 */
class AuthMiddleware {
  /**
   *
   * @param apiKey
   */
  constructor(apiKey = null) {
    this.apiKey = apiKey;
    this.enabled = !!apiKey;
  }

  /**
   * Middleware function for Express to validate API key
   * @param {object} req - Express request object
   * @param {object} res - Express response object
   * @param {Function} next - Express next function
   */
  validateApiKey(req, res, next) {
    // Debug logging
    logger.debug('AUTH', `Validating API key for ${req.method} ${req.path}`);
    logger.debug(
      'AUTH',
      `Authentication enabled: ${this.enabled}, API key stored: ${this.apiKey ? `${this.apiKey.substring(0, 8)}...` : 'none'}`
    );

    // If authentication is not enabled, skip validation
    if (!this.enabled) {
      logger.debug('AUTH', `Authentication disabled, skipping validation`);
      return next();
    }

    // Get API key from headers
    const authHeader = req.headers.authorization;
    const apiKeyHeader = req.headers['x-api-key'];
    const queryApiKey = req.query.api_key;

    logger.debug(
      'AUTH',
      `Request headers: authorization=${authHeader ? 'present' : 'missing'}, x-api-key=${apiKeyHeader ? 'present' : 'missing'}, query api_key=${queryApiKey ? 'present' : 'missing'}`
    );

    let providedKey = null;

    // Check Authorization header (Bearer token format)
    if (authHeader && authHeader.startsWith('Bearer ')) {
      providedKey = authHeader.substring(7);
    }
    // Check X-API-Key header
    else if (apiKeyHeader) {
      providedKey = apiKeyHeader;
    }
    // Check query parameter
    else if (queryApiKey) {
      providedKey = queryApiKey;
    }

    // Validate API key
    if (!providedKey) {
      logger.warn('AUTH', `API key missing from request: ${req.method} ${req.path}`);
      return res.status(401).json({
        error: 'API key required',
        message:
          'Please provide a valid API key in the Authorization header, X-API-Key header, or api_key query parameter',
      });
    }

    if (providedKey !== this.apiKey) {
      logger.warn('AUTH', `Invalid API key provided: ${req.method} ${req.path}`);
      return res.status(403).json({
        error: 'Invalid API key',
        message: 'The provided API key is invalid',
      });
    }

    logger.debug('AUTH', `API key validated successfully: ${req.method} ${req.path}`);
    next();
  }

  /**
   * Validate API key directly (for non-Express usage)
   * @param {string} providedKey - The API key to validate
   * @returns {boolean} - True if valid, false otherwise
   */
  isValidApiKey(providedKey) {
    if (!this.enabled) {
      return true;
    }

    return providedKey === this.apiKey;
  }

  /**
   * Get authentication status
   * @returns {object} - Authentication configuration
   */
  getAuthStatus() {
    return {
      enabled: this.enabled,
      hasKey: !!this.apiKey,
    };
  }

  /**
   * Update API key
   * @param {string} newApiKey - New API key
   */
  updateApiKey(newApiKey) {
    this.apiKey = newApiKey;
    this.enabled = !!newApiKey;
    logger.info('AUTH', `API key updated, authentication ${this.enabled ? 'enabled' : 'disabled'}`);
  }

  /**
   * Disable authentication
   */
  disableAuth() {
    this.apiKey = null;
    this.enabled = false;
    logger.info('AUTH', 'Authentication disabled');
  }
}

module.exports = AuthMiddleware;
