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
      addressBanDuration: 5 * 60 * 1000, // 5 minutes ban for spam
      bannedAddresses: new Set(), // Currently banned addresses
      lastCleanup: Date.now(),
    };
  }

  /**
   * Check if address is allowed to submit transactions
   * @param fromAddress
   */
  isAddressAllowedToSubmit(fromAddress) {
    const now = Date.now();

    // Check if address is banned
    if (this.spamProtection.bannedAddresses.has(fromAddress)) {
      const banTime = this.addressRateLimits.get(fromAddress)?.banTime || 0;
      if (now - banTime < this.spamProtection.addressBanDuration) {
        logger.warn(
          'SPAM_PROTECTION',
          `Address ${fromAddress} is banned for spam (${Math.ceil((this.spamProtection.addressBanDuration - (now - banTime)) / 1000)}s remaining)`
        );
        return false;
      }
      // Ban expired, remove from banned list
      this.spamProtection.bannedAddresses.delete(fromAddress);
      this.addressRateLimits.delete(fromAddress);
    }

    // Get current rate limit data for this address
    const addressData = this.addressRateLimits.get(fromAddress) || { count: 0, firstTx: now, banTime: 0 };

    // Check if we're in a new time window (1 minute)
    if (now - addressData.firstTx > 60000) {
      // Reset for new time window
      addressData.count = 1;
      addressData.firstTx = now;
    } else {
      // Check if address has exceeded limit
      if (addressData.count >= this.spamProtection.maxTransactionsPerAddress) {
        // Ban address for spam
        addressData.banTime = now;
        this.spamProtection.bannedAddresses.add(fromAddress);
        logger.warn(
          'SPAM_PROTECTION',
          `Address ${fromAddress} banned for spam (${addressData.count} transactions in 1 minute)`
        );
        return false;
      }
      addressData.count++;
    }

    this.addressRateLimits.set(fromAddress, addressData);
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
    const oneMinuteAgo = now - 60000;

    // Remove old rate limit data
    for (const [address, data] of this.addressRateLimits.entries()) {
      if (now - data.firstTx > 60000) {
        this.addressRateLimits.delete(address);
      }
    }

    // Remove expired bans
    for (const address of this.spamProtection.bannedAddresses) {
      const banTime = this.addressRateLimits.get(address)?.banTime || 0;
      if (now - banTime > this.spamProtection.addressBanDuration) {
        this.spamProtection.bannedAddresses.delete(address);
        this.addressRateLimits.delete(address);
      }
    }

    this.spamProtection.lastCleanup = now;
  }

  /**
   * Get spam protection status
   */
  getStatus() {
    const bannedAddresses = Array.from(this.spamProtection.bannedAddresses);
    const rateLimitData = Array.from(this.addressRateLimits.entries()).map(([address, data]) => ({
      address,
      count: data.count,
      firstTx: new Date(data.firstTx).toISOString(),
      banTime: data.banTime ? new Date(data.banTime).toISOString() : null,
    }));

    return {
      bannedAddresses,
      rateLimitData,
      maxTransactionsPerAddress: this.spamProtection.maxTransactionsPerAddress,
      maxTransactionsPerMinute: this.spamProtection.maxTransactionsPerMinute,
      addressBanDuration: this.spamProtection.addressBanDuration,
    };
  }

  /**
   * Reset all spam protection data
   */
  reset() {
    this.spamProtection.bannedAddresses.clear();
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
    if (config.addressBanDuration !== undefined) {
      this.spamProtection.addressBanDuration = config.addressBanDuration;
    }
  }
}

module.exports = SpamProtection;
