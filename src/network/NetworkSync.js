const logger = require('../utils/logger');

/**
 * Network Synchronization - Handles network synchronization and peer discovery
 */
class NetworkSync {
  /**
   *
   * @param blockchain
   * @param peerManager
   * @param seedNodeManager
   */
  constructor(blockchain, peerManager, seedNodeManager) {
    this.blockchain = blockchain;
    this.peerManager = peerManager;
    this.seedNodeManager = seedNodeManager;
    this.networkSyncStatus = {
      isSyncing: false,
      lastSyncTime: null,
      syncAttempts: 0,
      maxSyncAttempts: 5,
    };
    this.periodicSyncInterval = null;
  }

  /**
   * Start network synchronization
   */
  async syncWithNetwork() {
    if (this.networkSyncStatus.isSyncing) {
      logger.debug('NETWORK_SYNC', 'Network sync already in progress');
      return false;
    }

    this.networkSyncStatus.isSyncing = true;
    this.networkSyncStatus.syncAttempts++;

    try {
      logger.debug('NETWORK_SYNC', 'Starting network synchronization...');

      // Query latest block from all peers
      const peers = this.peerManager.getAllPeers();
      if (peers.length === 0) {
        logger.warn('NETWORK_SYNC', 'No peers available for synchronization');
        this.networkSyncStatus.isSyncing = false;
        return false;
      }

      // Send query to all peers
      for (const peer of peers) {
        try {
          this.sendMessage(peer, { type: 'QUERY_LATEST' });
        } catch (error) {
          logger.debug('NETWORK_SYNC', `Failed to query peer: ${error.message}`);
        }
      }

      // Wait a bit for responses
      await new Promise(resolve => setTimeout(resolve, 2000));

      this.networkSyncStatus.lastSyncTime = Date.now();
      logger.debug('NETWORK_SYNC', 'Network synchronization completed');

      return true;
    } catch (error) {
      logger.error('NETWORK_SYNC', `Network synchronization failed: ${error.message}`);
      return false;
    } finally {
      this.networkSyncStatus.isSyncing = false;
    }
  }

  /**
   * Start periodic network synchronization
   */
  startPeriodicSync() {
    if (this.periodicSyncInterval) {
      logger.debug('NETWORK_SYNC', 'Periodic sync already running');
      return;
    }

    // Sync every 30 seconds (Bitcoin-style)
    this.periodicSyncInterval = setInterval(() => {
      this.performPeriodicSync();
    }, 30000);

    logger.info('NETWORK_SYNC', 'Periodic network synchronization started (30s interval)');
  }

  /**
   * Perform periodic network synchronization
   */
  async performPeriodicSync() {
    try {
      const peers = this.peerManager.getAllPeers();
      if (peers.length === 0) {
        logger.debug('NETWORK_SYNC', 'No peers available for periodic sync');
        return;
      }

      logger.debug('NETWORK_SYNC', `Performing periodic sync with ${peers.length} peers`);

      // Sync blockchain state
      await this.syncBlockchainState();

      // Sync mempool state (Bitcoin-style)
      await this.syncMempoolState();

      // Update sync status
      this.networkSyncStatus.lastSync = Date.now();
      this.networkSyncStatus.isSyncing = false;

      logger.debug('NETWORK_SYNC', 'Periodic sync completed successfully');
    } catch (error) {
      logger.error('NETWORK_SYNC', `Periodic sync failed: ${error.message}`);
      this.networkSyncStatus.isSyncing = false;
    }
  }

  /**
   * Sync mempool state with peers (Bitcoin-style)
   */
  async syncMempoolState() {
    try {
      const peers = this.peerManager.getAllPeers();
      if (peers.length === 0) return;

      logger.debug('NETWORK_SYNC', 'Starting mempool synchronization with peers');

      // Request mempool sync from a few random peers
      const syncPeers = this.selectRandomPeers(peers, Math.min(3, peers.length));

      for (const peer of syncPeers) {
        try {
          // Send mempool sync request
          const message = {
            type: 'MEMPOOL_SYNC_REQUEST',
            data: {
              timestamp: Date.now(),
              networkId: this.blockchain.config?.networkId || 'unknown',
            },
          };

          if (this.sendMessage(peer, message)) {
            logger.debug('NETWORK_SYNC', `Mempool sync request sent to peer ${peer.url || 'unknown'}`);
          }
        } catch (error) {
          logger.debug('NETWORK_SYNC', `Failed to send mempool sync request to peer: ${error.message}`);
        }
      }

      logger.debug('NETWORK_SYNC', `Mempool sync requests sent to ${syncPeers.length} peers`);
    } catch (error) {
      logger.error('NETWORK_SYNC', `Mempool sync failed: ${error.message}`);
    }
  }

  /**
   * Select random peers for synchronization
   * @param peers
   * @param count
   */
  selectRandomPeers(peers, count) {
    const shuffled = [...peers].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, count);
  }

  /**
   * Stop periodic network synchronization
   */
  stopPeriodicSync() {
    if (this.periodicSyncInterval) {
      clearInterval(this.periodicSyncInterval);
      this.periodicSyncInterval = null;
      logger.info('NETWORK_SYNC', 'Periodic network sync stopped');
    }
  }

  /**
   * Connect to seed nodes with minimum connection requirement
   * @param connectToPeerFunction
   */
  async connectToSeedNodes(connectToPeerFunction) {
    if (this.seedNodeManager.minSeedConnections === 0) {
      logger.info('NETWORK_SYNC', 'P2P Network: Standalone mode (no seed connections required)');
      return 0;
    }

    logger.info('NETWORK_SYNC', 'P2P Network: Attempting to connect to seed nodes...');

    const filteredSeedNodes = this.seedNodeManager.getFilteredSeedNodes();

    if (filteredSeedNodes.length === 0) {
      logger.info('NETWORK_SYNC', 'P2P Network: No external seed nodes available');
      this.seedNodeManager.minSeedConnections = 0;
      return 0;
    }

    // Initialize seed node connection tracking
    this.seedNodeManager.initializeConnectionTracking();

    const connectionPromises = filteredSeedNodes.map(async seedNode => {
      try {
        const url = new URL(seedNode);
        const connected = await connectToPeerFunction(url.hostname, url.port);
        if (connected) {
          this.seedNodeManager.markSeedNodeConnected(seedNode);
          return true;
        }
        if (connected === null) {
          // Already connected, mark as connected
          this.seedNodeManager.markSeedNodeConnected(seedNode);
          return true;
        }
        this.seedNodeManager.markSeedNodeAttempt(seedNode, false);
        return false;
      } catch (error) {
        this.seedNodeManager.markSeedNodeAttempt(seedNode, false);
        return false; // Fail silently
      }
    });

    const results = await Promise.all(connectionPromises);
    const successfulConnections = results.filter(result => result).length;

    if (successfulConnections >= this.seedNodeManager.minSeedConnections) {
      logger.info('NETWORK_SYNC', `P2P Network: Connected to ${successfulConnections} seed nodes`);
    } else if (this.seedNodeManager.minSeedConnections > 0) {
      logger.info(
        'NETWORK_SYNC',
        `P2P Network: Standalone mode (${successfulConnections}/${this.seedNodeManager.minSeedConnections} seed connections)`
      );
    }

    return successfulConnections;
  }

  /**
   * Broadcast new block to all peers
   * @param block
   */
  broadcastNewBlock(block) {
    const peers = this.peerManager.getAllPeers();
    if (peers.length === 0) {
      logger.debug('NETWORK_SYNC', 'No peers to broadcast new block to');
      return 0;
    }

    const message = {
      type: 'NEW_BLOCK',
      data: block,
    };

    let broadcastCount = 0;
    for (const peer of peers) {
      try {
        if (this.sendMessage(peer, message)) {
          broadcastCount++;
        }
      } catch (error) {
        logger.debug('NETWORK_SYNC', `Failed to broadcast block to peer: ${error.message}`);
      }
    }

    logger.info('NETWORK_SYNC', `New block broadcasted to ${broadcastCount}/${peers.length} peers`);
    return broadcastCount;
  }

  /**
   * Broadcast new transaction to all peers
   * @param transaction
   */
  broadcastNewTransaction(transaction) {
    const peers = this.peerManager.getAllPeers();
    if (peers.length === 0) {
      logger.debug('NETWORK_SYNC', 'No peers to broadcast new transaction to');
      return 0;
    }

    const message = {
      type: 'NEW_TRANSACTION',
      data: transaction,
    };

    let broadcastCount = 0;
    for (const peer of peers) {
      try {
        if (this.sendMessage(peer, message)) {
          broadcastCount++;
        }
      } catch (error) {
        logger.debug('NETWORK_SYNC', `Failed to broadcast transaction to peer: ${error.message}`);
      }
    }

    logger.debug('NETWORK_SYNC', `New transaction broadcasted to ${broadcastCount}/${peers.length} peers`);
    return broadcastCount;
  }

  /**
   * Send message to peer
   * @param peer
   * @param message
   */
  sendMessage(peer, message) {
    try {
      if (peer.readyState === 1) {
        // WebSocket.OPEN
        peer.send(JSON.stringify(message));
        return true;
      }
    } catch (error) {
      logger.error('NETWORK_SYNC', `Failed to send message: ${error.message}`);
    }
    return false;
  }

  /**
   * Get network sync status
   */
  getNetworkSyncStatus() {
    return {
      ...this.networkSyncStatus,
      peerCount: this.peerManager.getPeerCount(),
      seedNodeStatus: this.seedNodeManager.getSeedNodeStatus(),
      periodicSyncActive: !!this.periodicSyncInterval,
    };
  }

  /**
   * Check if network is synced
   */
  isNetworkSynced() {
    return this.peerManager.getPeerCount() > 0 && !this.networkSyncStatus.isSyncing;
  }

  /**
   * Reset sync status
   */
  resetSyncStatus() {
    this.networkSyncStatus = {
      isSyncing: false,
      lastSyncTime: null,
      syncAttempts: 0,
      maxSyncAttempts: 5,
    };
    logger.info('NETWORK_SYNC', 'Network sync status reset');
  }

  /**
   * Get sync statistics
   */
  getSyncStats() {
    return {
      totalSyncAttempts: this.networkSyncStatus.syncAttempts,
      lastSyncTime: this.networkSyncStatus.lastSyncTime,
      isCurrentlySyncing: this.networkSyncStatus.isSyncing,
      peerCount: this.peerManager.getPeerCount(),
      seedNodeConnections: this.seedNodeManager.connectedSeedNodes,
      periodicSyncActive: !!this.periodicSyncInterval,
    };
  }
}

module.exports = NetworkSync;
