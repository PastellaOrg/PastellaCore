const logger = require('../utils/logger');

/**
 * Fork Height Manager - Handles protocol version compatibility and fork management
 */
class ForkManager {
  /**
   * Initialize fork manager
   * @param {Object} config - Configuration object containing fork heights
   */
  constructor(config) {
    this.config = config;
    this.forkConfig = config.blockchain?.forkHeights || {};
    this.currentVersion = this.forkConfig.currentVersion || 0;
    this.minimumAcceptableVersion = this.forkConfig.minimumAcceptableVersion || 0;
    this.forks = this.forkConfig.forks || {};

    logger.info('FORK_MANAGER', `Initialized with version ${this.currentVersion} (minimum acceptable: ${this.minimumAcceptableVersion})`);
    this.logActiveFork();
  }

  /**
   * Get the current daemon version
   * @returns {number} Current version
   */
  getCurrentVersion() {
    return this.currentVersion;
  }

  /**
   * Get the minimum acceptable version for network participation
   * @returns {number} Minimum acceptable version
   */
  getMinimumAcceptableVersion() {
    return this.minimumAcceptableVersion;
  }

  /**
   * Check if a peer version is compatible with current network requirements
   * STRICT COMPATIBILITY: Peer must have same or higher version than current node
   * @param {number} peerVersion - Peer's daemon version
   * @returns {boolean} True if compatible, false otherwise
   */
  isVersionCompatible(peerVersion) {
    if (typeof peerVersion !== 'number' || peerVersion < 0) {
      logger.warn('FORK_MANAGER', `Invalid peer version: ${peerVersion}`);
      return false;
    }

    // STRICT CHECK: Peer version must be same or higher than our current version
    const compatible = peerVersion >= this.currentVersion;

    if (!compatible) {
      logger.warn('FORK_MANAGER', `Peer version ${peerVersion} is below current version ${this.currentVersion} - connection rejected`);
      logger.warn('FORK_MANAGER', `Strict compatibility enforced: peers must run version ${this.currentVersion} or higher`);
    } else {
      logger.debug('FORK_MANAGER', `Peer version ${peerVersion} is compatible with current version ${this.currentVersion}`);
    }

    return compatible;
  }

  /**
   * Validate that the current daemon version can participate in the network
   * @returns {Object} Validation result with success status and message
   */
  validateNetworkParticipation() {
    const currentFork = this.getCurrentFork();

    if (!currentFork) {
      return {
        success: false,
        message: `No fork configuration found for current version ${this.currentVersion}`,
        canParticipate: false
      };
    }

    if (this.currentVersion < this.minimumAcceptableVersion) {
      return {
        success: false,
        message: `Current daemon version ${this.currentVersion} is below minimum acceptable version ${this.minimumAcceptableVersion}`,
        canParticipate: false,
        upgradeRequired: true
      };
    }

    return {
      success: true,
      message: `Daemon version ${this.currentVersion} is compatible with network requirements`,
      canParticipate: true,
      currentFork: currentFork
    };
  }

  /**
   * Get fork information for a specific version
   * @param {number} version - Fork version to get info for
   * @returns {Object|null} Fork information or null if not found
   */
  getForkInfo(version) {
    return this.forks[version.toString()] || null;
  }

  /**
   * Get current active fork information
   * @returns {Object|null} Current fork information
   */
  getCurrentFork() {
    return this.getForkInfo(this.currentVersion);
  }

  /**
   * Get all available fork versions
   * @returns {Array<number>} Array of fork version numbers
   */
  getAvailableForks() {
    return Object.keys(this.forks).map(v => parseInt(v)).sort((a, b) => a - b);
  }

  /**
   * Check if a specific feature is enabled at the current fork height
   * @param {string} feature - Feature name to check
   * @returns {boolean} True if feature is enabled
   */
  isFeatureEnabled(feature) {
    const currentFork = this.getCurrentFork();
    if (!currentFork || !currentFork.features) {
      return false;
    }
    return currentFork.features.includes(feature);
  }

  /**
   * Get the minimum version required for a specific feature
   * @param {string} feature - Feature name
   * @returns {number|null} Minimum version or null if feature not found
   */
  getMinimumVersionForFeature(feature) {
    for (const version of this.getAvailableForks()) {
      const fork = this.getForkInfo(version);
      if (fork && fork.features && fork.features.includes(feature)) {
        return version;
      }
    }
    return null;
  }

  /**
   * Generate a version compatibility message for logging
   * @param {number} peerVersion - Peer version to check
   * @returns {string} Formatted compatibility message
   */
  getCompatibilityMessage(peerVersion) {
    const compatible = this.isVersionCompatible(peerVersion);
    const peerFork = this.getForkInfo(peerVersion);
    const currentFork = this.getCurrentFork();

    let message = `Version compatibility check: `;
    message += `Peer v${peerVersion} ${compatible ? '✅ COMPATIBLE' : '❌ INCOMPATIBLE'} with current version (required: v${this.currentVersion}+)`;

    if (peerFork) {
      message += `\\n  Peer Fork: ${peerFork.name} - ${peerFork.description}`;
    }
    if (currentFork) {
      message += `\\n  Current Fork: ${currentFork.name} - ${currentFork.description}`;
    }

    if (!compatible) {
      message += `\\n  ⚠️  STRICT ENFORCEMENT: Only peers with version ${this.currentVersion} or higher are accepted`;
    }

    return message;
  }

  /**
   * Log current active fork information
   */
  logActiveFork() {
    const currentFork = this.getCurrentFork();
    if (currentFork) {
      logger.info('FORK_MANAGER', `🔗 Active Fork: ${currentFork.name} (v${this.currentVersion})`);
      logger.info('FORK_MANAGER', `   Description: ${currentFork.description}`);
      if (currentFork.features && currentFork.features.length > 0) {
        logger.info('FORK_MANAGER', `   Features: ${currentFork.features.join(', ')}`);
      }
    } else {
      logger.warn('FORK_MANAGER', `No fork configuration found for current version ${this.currentVersion}`);
    }
  }

  /**
   * Create version info object for network messages
   * @returns {Object} Version information for network communication
   */
  getVersionInfo() {
    const currentFork = this.getCurrentFork();
    return {
      version: this.currentVersion,
      minimumAcceptableVersion: this.minimumAcceptableVersion,
      forkName: currentFork?.name || 'Unknown',
      features: currentFork?.features || [],
      compatible: true // Always true for our own version
    };
  }

  /**
   * Validate version info received from a peer
   * @param {Object} peerVersionInfo - Version info from peer
   * @returns {Object} Validation result
   */
  validatePeerVersionInfo(peerVersionInfo) {
    if (!peerVersionInfo || typeof peerVersionInfo.version !== 'number') {
      return {
        success: false,
        message: 'Invalid or missing version information from peer',
        shouldDisconnect: true
      };
    }

    const peerVersion = peerVersionInfo.version;
    const compatible = this.isVersionCompatible(peerVersion);

    if (!compatible) {
      const message = `Peer version ${peerVersion} is incompatible (current version required: ${this.currentVersion}+)`;
      return {
        success: false,
        message,
        shouldDisconnect: true,
        peerVersion,
        upgradeRequired: peerVersion < this.currentVersion,
        strictEnforcement: true
      };
    }

    return {
      success: true,
      message: `Peer version ${peerVersion} is compatible`,
      shouldDisconnect: false,
      peerVersion,
      peerFork: this.getForkInfo(peerVersion)
    };
  }

  /**
   * Check if the daemon should block network participation
   * @returns {Object} Network participation status
   */
  checkNetworkParticipation() {
    const validation = this.validateNetworkParticipation();

    if (!validation.success) {
      logger.error('FORK_MANAGER', '🚨 NETWORK PARTICIPATION BLOCKED');
      logger.error('FORK_MANAGER', `   Reason: ${validation.message}`);

      if (validation.upgradeRequired) {
        logger.error('FORK_MANAGER', '   ⚠️  DAEMON UPGRADE REQUIRED');
        logger.error('FORK_MANAGER', `   Current Version: ${this.currentVersion}`);
        logger.error('FORK_MANAGER', `   Minimum Required: ${this.minimumAcceptableVersion}`);
        logger.error('FORK_MANAGER', '   Please upgrade your daemon to continue participating in the network');
      }

      return {
        canParticipate: false,
        blockReason: validation.message,
        upgradeRequired: validation.upgradeRequired || false
      };
    }

    return {
      canParticipate: true,
      currentFork: validation.currentFork
    };
  }
}

module.exports = ForkManager;