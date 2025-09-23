const logger = require('../utils/logger');

/**
 * Spam Protection System - Handles rate limiting and spam prevention
 */
class SpamProtection {
  /**
   *
   */
  constructor() {
    // SPAM PROTECTION SYSTEM
    this.addressRateLimits = new Map(); // Track transaction rate per address
    this.spamProtection = {
      maxTransactionsPerAddress: 10, // Max transactions per address per minute
      maxTransactionsPerMinute: 100, // Global max transactions per minute
      lastCleanup: Date.now(),
    };
  }

  /**
   * Check if address is allowed to submit transactions
   * @param fromAddress
   */
  isAddressAllowedToSubmit(fromAddress) {
    /*const now = Date.now();

    // Get current rate limit data for this address
    const addressData = this.addressRateLimits.get(fromAddress) || { count: 0, firstTx: now };

    // Check if we're in a new time window (1 minute)
    if (now - addressData.firstTx > 60000) {
      // Reset for new time window
      addressData.count = 1;
      addressData.firstTx = now;
    } else {
      // Check if address has exceeded limit
      if (addressData.count >= this.spamProtection.maxTransactionsPerAddress) {
        logger.warn(
          'SPAM_PROTECTION',
          `Address ${fromAddress} exceeded rate limit (${addressData.count} transactions in 1 minute) - transaction rejected`
        );
        return false;
      }
      addressData.count++;
    }

    this.addressRateLimits.set(fromAddress, addressData);*/
    return true;
  }

  /**
   * Check global transaction rate limit
   * @param pendingTransactions
   */
  isGlobalRateLimitExceeded(pendingTransactions) {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    // Count transactions in the last minute
    const recentTransactions = pendingTransactions.filter(tx => tx.timestamp > oneMinuteAgo);

    if (recentTransactions.length >= this.spamProtection.maxTransactionsPerMinute) {
      logger.warn(
        'SPAM_PROTECTION',
        `Global rate limit exceeded: ${recentTransactions.length} transactions in 1 minute`
      );
      return true;
    }

    return false;
  }

  /**
   * Clean up old rate limit data
   */
  cleanupSpamProtection() {
    const now = Date.now();

    // Remove old rate limit data
    for (const [address, data] of this.addressRateLimits.entries()) {
      if (now - data.firstTx > 60000) {
        this.addressRateLimits.delete(address);
      }
    }

    this.spamProtection.lastCleanup = now;
  }

  /**
   * Get spam protection status
   */
  getStatus() {
    const rateLimitData = Array.from(this.addressRateLimits.entries()).map(([address, data]) => ({
      address,
      count: data.count,
      firstTx: new Date(data.firstTx).toISOString(),
    }));

    return {
      rateLimitData,
      maxTransactionsPerAddress: this.spamProtection.maxTransactionsPerAddress,
      maxTransactionsPerMinute: this.spamProtection.maxTransactionsPerMinute,
    };
  }

  /**
   * Reset all spam protection data
   */
  reset() {
    this.addressRateLimits.clear();
    this.spamProtection.lastCleanup = Date.now();
  }

  /**
   * Update configuration
   * @param config
   */
  updateConfig(config) {
    if (config.maxTransactionsPerAddress !== undefined) {
      this.spamProtection.maxTransactionsPerAddress = config.maxTransactionsPerAddress;
    }
    if (config.maxTransactionsPerMinute !== undefined) {
      this.spamProtection.maxTransactionsPerMinute = config.maxTransactionsPerMinute;
    }
  }
}

module.exports = SpamProtection;
