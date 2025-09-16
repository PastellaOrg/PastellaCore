const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

/**
 * Enhanced Peer Discovery and Connection Management
 *
 * Features:
 * - Persistent peer storage (peers.json)
 * - Automatic reconnection with exponential backoff
 * - Peer sharing and discovery
 * - Connection health monitoring
 * - Decentralized peer management
 * - Connection retry strategies
 */
class PeerDiscovery {
  /**
   * @param {Object} config - Configuration object
   * @param {string} dataDir - Data directory for persistence
   * @param {number} maxPeers - Maximum number of peer connections
   */
  constructor(config = null, dataDir = './data', maxPeers = 20) {
    this.config = config;
    this.dataDir = dataDir;
    this.maxPeers = maxPeers;

    // Peer storage and management
    this.knownPeers = new Map(); // address -> PeerInfo
    this.activePeers = new Map(); // address -> WebSocket
    this.connectionAttempts = new Map(); // address -> AttemptInfo

    // Connection settings
    this.baseRetryDelay = 5000; // 5 seconds
    this.maxRetryDelay = 300000; // 5 minutes
    this.maxRetryAttempts = 10;
    this.peerShareInterval = 60000; // 1 minute
    this.healthCheckInterval = 30000; // 30 seconds

    // File paths
    this.peersFilePath = path.join(dataDir, 'peers.json');
    this.bannedPeersFilePath = path.join(dataDir, 'banned_peers.json');

    // Timers
    this.reconnectionTimer = null;
    this.peerShareTimer = null;
    this.healthCheckTimer = null;

    // Load persistent data
    this.loadPeersFromDisk();
    this.loadBannedPeers();

    logger.info('PEER_DISCOVERY', `Initialized with ${this.knownPeers.size} known peers, max connections: ${maxPeers}`);
  }

  /**
   * PeerInfo structure for storing peer data
   */
  createPeerInfo(address, port = 23000) {
    return {
      address,
      port,
      lastSeen: Date.now(),
      lastConnected: null,
      connectionCount: 0,
      failureCount: 0,
      reputation: 1000, // Starting reputation
      isReliable: false, // Becomes true after successful connections
      discoveredBy: 'config', // 'config', 'peer_share', 'manual'
      networkId: this.config?.networkId || 'unknown'
    };
  }

  /**
   * Load peers from persistent storage
   */
  loadPeersFromDisk() {
    try {
      if (fs.existsSync(this.peersFilePath)) {
        const data = fs.readFileSync(this.peersFilePath, 'utf8');
        const peersData = JSON.parse(data);

        // Convert array back to Map
        peersData.forEach(peerInfo => {
          this.knownPeers.set(peerInfo.address, peerInfo);
        });

        logger.info('PEER_DISCOVERY', `Loaded ${this.knownPeers.size} peers from ${this.peersFilePath}`);
      } else {
        // Initialize with seed nodes from config
        this.initializeFromSeedNodes();
      }
    } catch (error) {
      logger.error('PEER_DISCOVERY', `Failed to load peers from disk: ${error.message}`);
      this.initializeFromSeedNodes();
    }
  }

  /**
   * Initialize peer list from seed nodes in config
   */
  initializeFromSeedNodes() {
    if (this.config?.network?.seedNodes) {
      this.config.network.seedNodes.forEach(seedNode => {
        const peerInfo = this.createPeerInfo(seedNode);
        peerInfo.discoveredBy = 'config';
        peerInfo.isReliable = true; // Seed nodes are considered reliable
        this.knownPeers.set(seedNode, peerInfo);
      });

      logger.info('PEER_DISCOVERY', `Initialized with ${this.knownPeers.size} seed nodes from config`);
      this.savePeersToDisk();
    }
  }

  /**
   * Save peers to persistent storage
   */
  savePeersToDisk() {
    try {
      // Ensure data directory exists
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }

      // Convert Map to array for JSON serialization
      const peersArray = Array.from(this.knownPeers.values());
      fs.writeFileSync(this.peersFilePath, JSON.stringify(peersArray, null, 2));

      logger.debug('PEER_DISCOVERY', `Saved ${peersArray.length} peers to ${this.peersFilePath}`);
    } catch (error) {
      logger.error('PEER_DISCOVERY', `Failed to save peers to disk: ${error.message}`);
    }
  }

  /**
   * Load banned peers from storage
   */
  loadBannedPeers() {
    this.bannedPeers = new Set();
    try {
      if (fs.existsSync(this.bannedPeersFilePath)) {
        const data = fs.readFileSync(this.bannedPeersFilePath, 'utf8');
        const bannedArray = JSON.parse(data);
        this.bannedPeers = new Set(bannedArray);
        logger.info('PEER_DISCOVERY', `Loaded ${this.bannedPeers.size} banned peers`);
      }
    } catch (error) {
      logger.error('PEER_DISCOVERY', `Failed to load banned peers: ${error.message}`);
    }
  }

  /**
   * Add a new peer to the known peers list
   */
  addKnownPeer(address, port = 23000, discoveredBy = 'manual') {
    if (this.bannedPeers.has(address)) {
      logger.debug('PEER_DISCOVERY', `Not adding banned peer: ${address}`);
      return false;
    }

    if (!this.knownPeers.has(address)) {
      const peerInfo = this.createPeerInfo(address, port);
      peerInfo.discoveredBy = discoveredBy;
      this.knownPeers.set(address, peerInfo);

      logger.info('PEER_DISCOVERY', `Added new peer: ${address}:${port} (discovered by: ${discoveredBy})`);
      this.savePeersToDisk();
      return true;
    }

    // Update existing peer's last seen time
    const existingPeer = this.knownPeers.get(address);
    existingPeer.lastSeen = Date.now();
    this.savePeersToDisk();
    return true;
  }

  /**
   * Get peers sorted by connection priority
   */
  getPeersForConnection() {
    const availablePeers = Array.from(this.knownPeers.values())
      .filter(peer => {
        // Skip banned peers
        if (this.bannedPeers.has(peer.address)) return false;

        // Skip already connected peers
        if (this.activePeers.has(peer.address)) return false;

        // Skip peers with too many recent failures
        const attemptInfo = this.connectionAttempts.get(peer.address);
        if (attemptInfo && attemptInfo.failures >= this.maxRetryAttempts) {
          return false;
        }

        return true;
      })
      .sort((a, b) => {
        // Priority: reliable peers first, then by reputation, then by last successful connection
        if (a.isReliable !== b.isReliable) return b.isReliable - a.isReliable;
        if (a.reputation !== b.reputation) return b.reputation - a.reputation;
        return (b.lastConnected || 0) - (a.lastConnected || 0);
      });

    return availablePeers.slice(0, this.maxPeers);
  }

  /**
   * Mark peer as connected
   */
  markPeerConnected(address, ws) {
    this.activePeers.set(address, ws);

    const peerInfo = this.knownPeers.get(address);
    if (peerInfo) {
      peerInfo.lastConnected = Date.now();
      peerInfo.connectionCount++;
      peerInfo.isReliable = peerInfo.connectionCount >= 3;
      peerInfo.reputation = Math.min(1000, peerInfo.reputation + 10);
    }

    // Reset connection attempts
    this.connectionAttempts.delete(address);

    logger.info('PEER_DISCOVERY', `Peer connected: ${address} (total: ${this.activePeers.size}/${this.maxPeers})`);
    this.savePeersToDisk();
  }

  /**
   * Mark peer as disconnected
   */
  markPeerDisconnected(address, reason = 'unknown') {
    this.activePeers.delete(address);

    const peerInfo = this.knownPeers.get(address);
    if (peerInfo) {
      peerInfo.lastSeen = Date.now();
      // Don't penalize reputation for normal disconnections
      if (reason !== 'normal' && reason !== 'shutdown') {
        peerInfo.reputation = Math.max(0, peerInfo.reputation - 5);
      }
    }

    logger.info('PEER_DISCOVERY', `Peer disconnected: ${address} (reason: ${reason}, remaining: ${this.activePeers.size})`);
    this.savePeersToDisk();
  }

  /**
   * Mark connection attempt failure
   */
  markConnectionFailure(address, error) {
    const attemptInfo = this.connectionAttempts.get(address) || {
      failures: 0,
      lastAttempt: 0,
      nextRetry: 0
    };

    attemptInfo.failures++;
    attemptInfo.lastAttempt = Date.now();

    // Calculate exponential backoff
    const delay = Math.min(
      this.baseRetryDelay * Math.pow(2, attemptInfo.failures - 1),
      this.maxRetryDelay
    );
    attemptInfo.nextRetry = Date.now() + delay;

    this.connectionAttempts.set(address, attemptInfo);

    // Update peer reputation
    const peerInfo = this.knownPeers.get(address);
    if (peerInfo) {
      peerInfo.failureCount++;
      peerInfo.reputation = Math.max(0, peerInfo.reputation - 2);
    }

    logger.debug('PEER_DISCOVERY', `Connection failure to ${address}: ${error.message} (failures: ${attemptInfo.failures}, retry in: ${Math.round(delay/1000)}s)`);
  }

  /**
   * Check if peer can be attempted for connection
   */
  canAttemptConnection(address) {
    const attemptInfo = this.connectionAttempts.get(address);
    if (!attemptInfo) return true;

    // Check if we've exceeded max attempts
    if (attemptInfo.failures >= this.maxRetryAttempts) return false;

    // Check if enough time has passed for retry
    return Date.now() >= attemptInfo.nextRetry;
  }

  /**
   * Get list of peers to share with other nodes
   */
  getPeersToShare(maxPeers = 10) {
    const reliablePeers = Array.from(this.knownPeers.values())
      .filter(peer => peer.isReliable && !this.bannedPeers.has(peer.address))
      .sort((a, b) => b.reputation - a.reputation)
      .slice(0, maxPeers);

    return reliablePeers.map(peer => ({
      address: peer.address,
      port: peer.port,
      reputation: peer.reputation,
      lastSeen: peer.lastSeen
    }));
  }

  /**
   * Process received peer list from another node
   */
  processPeerShare(peerList, fromAddress) {
    let newPeersAdded = 0;

    peerList.forEach(peerData => {
      if (this.addKnownPeer(peerData.address, peerData.port, 'peer_share')) {
        newPeersAdded++;
      }
    });

    logger.info('PEER_DISCOVERY', `Received ${peerList.length} peers from ${fromAddress}, added ${newPeersAdded} new peers`);
  }

  /**
   * Ban a peer (temporarily or permanently)
   */
  banPeer(address, reason = 'unknown', duration = null) {
    this.bannedPeers.add(address);

    // Disconnect if currently connected
    if (this.activePeers.has(address)) {
      const ws = this.activePeers.get(address);
      try {
        ws.close();
      } catch (error) {
        // Ignore close errors
      }
      this.markPeerDisconnected(address, 'banned');
    }

    // Update peer info
    const peerInfo = this.knownPeers.get(address);
    if (peerInfo) {
      peerInfo.reputation = 0;
    }

    logger.warn('PEER_DISCOVERY', `Banned peer ${address}: ${reason}`);

    // Save banned peers
    try {
      const bannedArray = Array.from(this.bannedPeers);
      fs.writeFileSync(this.bannedPeersFilePath, JSON.stringify(bannedArray, null, 2));
    } catch (error) {
      logger.error('PEER_DISCOVERY', `Failed to save banned peers: ${error.message}`);
    }

    // Set unban timer if duration specified
    if (duration) {
      setTimeout(() => {
        this.unbanPeer(address);
      }, duration);
    }
  }

  /**
   * Unban a peer
   */
  unbanPeer(address) {
    if (this.bannedPeers.delete(address)) {
      logger.info('PEER_DISCOVERY', `Unbanned peer: ${address}`);

      // Save updated banned peers list
      try {
        const bannedArray = Array.from(this.bannedPeers);
        fs.writeFileSync(this.bannedPeersFilePath, JSON.stringify(bannedArray, null, 2));
      } catch (error) {
        logger.error('PEER_DISCOVERY', `Failed to save banned peers: ${error.message}`);
      }
    }
  }

  /**
   * Start automatic reconnection process
   */
  startReconnectionProcess(connectionCallback) {
    if (this.reconnectionTimer) {
      clearInterval(this.reconnectionTimer);
    }

    this.reconnectionTimer = setInterval(async () => {
      const currentConnections = this.activePeers.size;
      const targetConnections = Math.min(this.maxPeers, this.knownPeers.size);

      if (currentConnections < targetConnections) {
        const peersToConnect = this.getPeersForConnection()
          .filter(peer => this.canAttemptConnection(peer.address))
          .slice(0, targetConnections - currentConnections);

        if (peersToConnect.length > 0) {
          logger.debug('PEER_DISCOVERY', `Attempting to connect to ${peersToConnect.length} peers (current: ${currentConnections}/${targetConnections})`);

          for (const peer of peersToConnect) {
            try {
              await connectionCallback(peer.address, peer.port);
            } catch (error) {
              this.markConnectionFailure(peer.address, error);
            }
          }
        }
      }
    }, 15000); // Check every 15 seconds

    logger.info('PEER_DISCOVERY', 'Started automatic reconnection process');
  }

  /**
   * Start peer sharing process
   */
  startPeerSharing(shareCallback) {
    if (this.peerShareTimer) {
      clearInterval(this.peerShareTimer);
    }

    this.peerShareTimer = setInterval(() => {
      const peersToShare = this.getPeersToShare();
      if (peersToShare.length > 0 && this.activePeers.size > 0) {
        // Share with all connected peers
        this.activePeers.forEach((ws, address) => {
          try {
            shareCallback(ws, peersToShare);
          } catch (error) {
            logger.debug('PEER_DISCOVERY', `Failed to share peers with ${address}: ${error.message}`);
          }
        });

        logger.debug('PEER_DISCOVERY', `Shared ${peersToShare.length} peers with ${this.activePeers.size} connected peers`);
      }
    }, this.peerShareInterval);

    logger.info('PEER_DISCOVERY', 'Started peer sharing process');
  }

  /**
   * Start health monitoring
   */
  startHealthMonitoring(healthCallback) {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }

    this.healthCheckTimer = setInterval(() => {
      // Check connection health
      this.activePeers.forEach((ws, address) => {
        try {
          healthCallback(ws, address);
        } catch (error) {
          logger.debug('PEER_DISCOVERY', `Health check failed for ${address}: ${error.message}`);
          this.markPeerDisconnected(address, 'health_check_failed');
        }
      });

      // Clean up old connection attempts
      const now = Date.now();
      const oneHour = 60 * 60 * 1000;

      this.connectionAttempts.forEach((attemptInfo, address) => {
        if (now - attemptInfo.lastAttempt > oneHour) {
          this.connectionAttempts.delete(address);
        }
      });

    }, this.healthCheckInterval);

    logger.info('PEER_DISCOVERY', 'Started connection health monitoring');
  }

  /**
   * Get statistics about peer discovery
   */
  getStats() {
    const stats = {
      knownPeers: this.knownPeers.size,
      activePeers: this.activePeers.size,
      bannedPeers: this.bannedPeers.size,
      connectionAttempts: this.connectionAttempts.size,
      reliablePeers: Array.from(this.knownPeers.values()).filter(p => p.isReliable).length,
      discoveryMethods: {},
      averageReputation: 0
    };

    // Count discovery methods
    this.knownPeers.forEach(peer => {
      stats.discoveryMethods[peer.discoveredBy] = (stats.discoveryMethods[peer.discoveredBy] || 0) + 1;
    });

    // Calculate average reputation
    const totalReputation = Array.from(this.knownPeers.values()).reduce((sum, peer) => sum + peer.reputation, 0);
    stats.averageReputation = this.knownPeers.size > 0 ? totalReputation / this.knownPeers.size : 0;

    return stats;
  }

  /**
   * Cleanup and stop all timers
   */
  shutdown() {
    if (this.reconnectionTimer) {
      clearInterval(this.reconnectionTimer);
      this.reconnectionTimer = null;
    }

    if (this.peerShareTimer) {
      clearInterval(this.peerShareTimer);
      this.peerShareTimer = null;
    }

    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }

    // Save final state
    this.savePeersToDisk();

    logger.info('PEER_DISCOVERY', 'Peer discovery system shutdown complete');
  }
}

module.exports = PeerDiscovery;