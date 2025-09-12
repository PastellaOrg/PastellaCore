const logger = require('../utils/logger');

/**
 * Seed Node Manager - Handles seed node connections and reconnection
 */
class SeedNodeManager {
  /**
   *
   * @param config
   * @param port
   */
  constructor(config = null, port = 3001) {
    this.seedNodes = [];
    this.isSeedNode = false;
    this.seedNodeConfig = null;
    this.connectedSeedNodes = 0;
    this.minSeedConnections = config?.network?.minSeedConnections !== undefined ? config.network.minSeedConnections : 2;
    this.port = port;

    // Seed node reconnection tracking
    this.seedNodeConnections = new Map(); // Track connection status per seed node
    this.reconnectionInterval = null;
    this.reconnectionIntervalMs = 60000; // 60 seconds

    this.loadSeedNodes(config);
  }

  /**
   * Load seed nodes from config
   * @param config
   */
  loadSeedNodes(config) {
    if (config && config.network && config.network.seedNodes) {
      this.seedNodes = config.network.seedNodes;
      logger.info('SEED_NODE_MANAGER', `Loaded ${this.seedNodes.length} seed nodes from config`);
    }
  }

  /**
   * Setup seed node configuration
   * @param seedConfig
   */
  setupSeedNode(seedConfig) {
    this.isSeedNode = true;
    this.seedNodeConfig = seedConfig;
    logger.info('SEED_NODE_MANAGER', `Seed node configured with max connections: ${seedConfig.maxConnections || 50}`);
  }

  /**
   * Get filtered seed nodes (excluding self)
   */
  getFilteredSeedNodes() {
    return this.seedNodes.filter(seedNode => {
      try {
        const url = new URL(seedNode);
        if (url.port === this.port.toString()) {
          return false; // Skip self-connection
        }
        return true;
      } catch (error) {
        return false; // Skip invalid URLs
      }
    });
  }

  /**
   * Initialize seed node connection tracking
   */
  initializeConnectionTracking() {
    const filteredSeedNodes = this.getFilteredSeedNodes();

    if (filteredSeedNodes.length === 0) {
      logger.info('SEED_NODE_MANAGER', 'No external seed nodes available');
      this.minSeedConnections = 0;
      return [];
    }

    // Initialize seed node connection tracking
    filteredSeedNodes.forEach(seedNode => {
      this.seedNodeConnections.set(seedNode, { connected: false, lastAttempt: 0 });
    });

    return filteredSeedNodes;
  }

  /**
   * Mark seed node as connected
   * @param seedNode
   */
  markSeedNodeConnected(seedNode) {
    this.connectedSeedNodes++;
    this.seedNodeConnections.set(seedNode, { connected: true, lastAttempt: Date.now() });
    logger.info('SEED_NODE_MANAGER', `Seed node connected: ${seedNode}`);
  }

  /**
   * Mark seed node as disconnected
   * @param seedNode
   */
  markSeedNodeDisconnected(seedNode) {
    if (this.seedNodeConnections.get(seedNode)?.connected) {
      this.connectedSeedNodes = Math.max(0, this.connectedSeedNodes - 1);
      this.seedNodeConnections.set(seedNode, { connected: false, lastAttempt: Date.now() });
      logger.info('SEED_NODE_MANAGER', `Seed node disconnected: ${seedNode}`);
    }
  }

  /**
   * Mark seed node connection attempt
   * @param seedNode
   * @param success
   */
  markSeedNodeAttempt(seedNode, success = false) {
    const now = Date.now();
    this.seedNodeConnections.set(seedNode, {
      connected: success,
      lastAttempt: now,
    });

    if (success) {
      this.connectedSeedNodes++;
    }
  }

  /**
   * Start seed node reconnection process
   */
  startSeedNodeReconnection() {
    if (this.reconnectionInterval) {
      clearInterval(this.reconnectionInterval);
    }

    this.reconnectionInterval = setInterval(() => {
      this.attemptSeedNodeReconnection();
    }, this.reconnectionIntervalMs);

    logger.debug(
      'SEED_NODE_MANAGER',
      `Seed node reconnection process started (every ${this.reconnectionIntervalMs / 1000}s)`
    );
  }

  /**
   * Stop seed node reconnection process
   */
  stopSeedNodeReconnection() {
    if (this.reconnectionInterval) {
      clearInterval(this.reconnectionInterval);
      this.reconnectionInterval = null;
      logger.info('SEED_NODE_MANAGER', 'Seed node reconnection process stopped');
    }
  }

  /**
   * Attempt to reconnect to disconnected seed nodes
   */
  async attemptSeedNodeReconnection() {
    if (!this.isSeedNode) {
      return;
    }

    const now = Date.now();
    const disconnectedSeedNodes = [];

    // Find disconnected seed nodes that haven't been attempted recently
    for (const [seedNode, status] of this.seedNodeConnections.entries()) {
      if (!status.connected && now - status.lastAttempt >= this.reconnectionIntervalMs) {
        disconnectedSeedNodes.push(seedNode);
      }
    }

    if (disconnectedSeedNodes.length === 0) {
      return; // No disconnected seed nodes to reconnect
    }

    // Only log reconnection attempts at debug level to reduce spam
    logger.debug(
      'SEED_NODE_MANAGER',
      `Attempting to reconnect to ${disconnectedSeedNodes.length} disconnected seed nodes...`
    );

    for (const seedNode of disconnectedSeedNodes) {
      try {
        const url = new URL(seedNode);

        // Check if this is still our own port (in case config changed)
        if (url.port === this.port.toString()) {
          continue; // Skip self-connection
        }

        // Update last attempt time
        this.seedNodeConnections.set(seedNode, {
          connected: false,
          lastAttempt: now,
        });

        // Note: Actual connection logic will be handled by the main P2PNetwork
        // This method just prepares the seed nodes for reconnection
      } catch (error) {
        // Connection failed, keep as disconnected - only log at debug level
        logger.debug('SEED_NODE_MANAGER', `Reconnection preparation failed for ${seedNode}: ${error.message}`);
      }
    }
  }

  /**
   * Mark a seed node as disconnected based on peer address
   * @param peerAddress
   */
  markSeedNodeAsDisconnected(peerAddress) {
    // Convert IPv6 localhost to IPv4 for comparison
    const normalizedPeerAddress = peerAddress.replace('::1', '127.0.0.1');

    for (const [seedNode, status] of this.seedNodeConnections.entries()) {
      try {
        const url = new URL(seedNode);
        const seedNodeAddress = `${url.hostname === 'localhost' ? '127.0.0.1' : url.hostname}:${url.port}`;

        if (seedNodeAddress === normalizedPeerAddress && status.connected) {
          this.seedNodeConnections.set(seedNode, {
            connected: false,
            lastAttempt: Date.now(),
          });
          return true; // This was a seed node
        }
      } catch (error) {
        // Skip invalid URLs
      }
    }

    return false; // This was not a seed node
  }

  /**
   * Get seed node status
   */
  getSeedNodeStatus() {
    return {
      isSeedNode: this.isSeedNode,
      seedNodes: this.seedNodes,
      connectedSeedNodes: this.connectedSeedNodes,
      minSeedConnections: this.minSeedConnections,
      connectionStatus: Object.fromEntries(this.seedNodeConnections),
      reconnectionActive: !!this.reconnectionInterval,
    };
  }

  /**
   * Check if minimum seed connections are met
   */
  hasMinimumSeedConnections() {
    return this.connectedSeedNodes >= this.minSeedConnections;
  }

  /**
   * Get disconnected seed nodes
   */
  getDisconnectedSeedNodes() {
    const disconnected = [];
    for (const [seedNode, status] of this.seedNodeConnections.entries()) {
      if (!status.connected) {
        disconnected.push(seedNode);
      }
    }
    return disconnected;
  }

  /**
   * Get connected seed nodes
   */
  getConnectedSeedNodes() {
    const connected = [];
    for (const [seedNode, status] of this.seedNodeConnections.entries()) {
      if (status.connected) {
        connected.push(seedNode);
      }
    }
    return connected;
  }
}

module.exports = SeedNodeManager;
