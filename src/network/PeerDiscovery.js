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

    // UPnP and external connectivity
    this.externalAddress = null; // Set by UPnP manager when available

    // Connection settings
    this.baseRetryDelay = 5000; // 5 seconds
    this.maxRetryDelay = 300000; // 5 minutes
    this.maxRetryAttempts = 10;
    this.peerShareInterval = 15000; // 15 seconds (faster for small networks)
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

    // Clean up any duplicate peer entries and DNS names
    this.cleanupDuplicatePeers();
    this.cleanupDNSEntries();

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

        // Convert array back to Map with address normalization
        peersData.forEach(peerInfo => {
          let normalizedAddress = peerInfo.address;
          let normalizedPort = peerInfo.port;

          // Normalize any WebSocket URLs that might be stored
          try {
            if (peerInfo.address.startsWith('ws://')) {
              const url = new URL(peerInfo.address);
              normalizedAddress = url.hostname;
              normalizedPort = parseInt(url.port) || peerInfo.port || 23000;
              logger.debug('PEER_DISCOVERY', `Normalized stored peer ${peerInfo.address} to ${normalizedAddress}:${normalizedPort}`);
            }
          } catch (error) {
            logger.warn('PEER_DISCOVERY', `Failed to normalize stored peer address ${peerInfo.address}: ${error.message}`);
          }

          // Create normalized peer info
          const normalizedPeerInfo = {
            ...peerInfo,
            address: normalizedAddress,
            port: normalizedPort
          };

          this.knownPeers.set(normalizedAddress, normalizedPeerInfo);
        });

        logger.info('PEER_DISCOVERY', `Loaded ${this.knownPeers.size} peers from ${this.peersFilePath}`);

        // Save the normalized data back to disk
        this.savePeersToDisk();
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
        // Parse seed node to extract host and port
        let address, port;

        try {
          // Handle different seed node formats
          if (seedNode.startsWith('ws://')) {
            // WebSocket URL format: ws://hostname:port
            const url = new URL(seedNode);
            address = url.hostname;
            port = parseInt(url.port) || 23000;
          } else if (seedNode.includes(':')) {
            // Host:port format: hostname:port
            const parts = seedNode.split(':');
            address = parts[0];
            port = parseInt(parts[1]) || 23000;
          } else {
            // Host only format: hostname
            address = seedNode;
            port = 23000;
          }

          const peerInfo = this.createPeerInfo(address, port);
          peerInfo.discoveredBy = 'config';
          peerInfo.isReliable = true; // Seed nodes are considered reliable
          this.knownPeers.set(address, peerInfo);

          logger.debug('PEER_DISCOVERY', `Added seed node: ${address}:${port} (from: ${seedNode})`);
        } catch (error) {
          logger.warn('PEER_DISCOVERY', `Failed to parse seed node ${seedNode}: ${error.message}`);
        }
      });

      logger.info('PEER_DISCOVERY', `Initialized with ${this.knownPeers.size} seed nodes from config`);
      this.savePeersToDisk();
    }
  }

  /**
   * Clean up duplicate peer entries (e.g., "1.2.3.4" and "1.2.3.4:23000")
   */
  cleanupDuplicatePeers() {
    const toRemove = [];
    const seen = new Map(); // hostname -> {address, peerInfo}

    for (const [address, peerInfo] of this.knownPeers) {
      // Extract hostname from address
      let hostname = address;
      if (address.includes(':') && !address.includes('::')) {
        hostname = address.split(':')[0];
      }

      const existing = seen.get(hostname);
      if (existing) {
        // We have a duplicate - keep the one with more connections or higher reputation
        const existingInfo = existing.peerInfo;
        const currentInfo = peerInfo;

        if (currentInfo.connectionCount > existingInfo.connectionCount ||
            (currentInfo.connectionCount === existingInfo.connectionCount && currentInfo.reputation > existingInfo.reputation)) {
          // Current is better, remove the existing one
          toRemove.push(existing.address);
          seen.set(hostname, { address, peerInfo });
        } else {
          // Existing is better, remove current one
          toRemove.push(address);
        }

        logger.debug('PEER_DISCOVERY', `Found duplicate peer: ${existing.address} vs ${address}, removing duplicate`);
      } else {
        seen.set(hostname, { address, peerInfo });
      }
    }

    // Remove duplicates
    toRemove.forEach(address => {
      this.knownPeers.delete(address);
    });

    if (toRemove.length > 0) {
      logger.info('PEER_DISCOVERY', `Cleaned up ${toRemove.length} duplicate peer entries`);
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
   * Check if a peer is a duplicate (DNS name vs resolved IP)
   * @param address - Address to check
   * @param port - Port to check
   * @returns {boolean} - True if this peer already exists in a different form
   */
  isDuplicatePeer(address, port) {
    const addressWithPort = `${address}:${port}`;

    // Check if any existing peer matches this one via seed node configuration
    if (this.config?.network?.seedNodes) {
      for (const seedNode of this.config.network.seedNodes) {
        try {
          const url = new URL(seedNode);
          const seedAddress = `${url.hostname}:${url.port}`;

          // If this address matches a seed node's DNS name, check if we have its IP
          if (addressWithPort === seedAddress) {
            // Look for existing IP version of this seed node
            for (const [existingAddress, peerInfo] of this.knownPeers) {
              if (peerInfo.port === port && /^\d+\.\d+\.\d+\.\d+$/.test(existingAddress)) {
                // This might be the IP version of the DNS name
                return true;
              }
            }
          }

          // If this is an IP address, check if we have the DNS version
          if (/^\d+\.\d+\.\d+\.\d+$/.test(address) && seedAddress.includes(':' + port)) {
            const seedHost = url.hostname;
            if (this.knownPeers.has(seedHost)) {
              return true;
            }
          }
        } catch (error) {
          // Invalid seed node URL, skip
          continue;
        }
      }
    }

    return false;
  }

  /**
   * Clean up DNS entries from peer storage - only keep IP addresses
   */
  cleanupDNSEntries() {
    let removedCount = 0;
    const toRemove = [];

    for (const [address, peerInfo] of this.knownPeers) {
      // If this is not an IP address (DNS name), mark for removal
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(address)) {
        toRemove.push(address);
        removedCount++;
      }
    }

    // Remove DNS entries
    toRemove.forEach(address => {
      this.knownPeers.delete(address);
      logger.debug('PEER_DISCOVERY', `Removed DNS entry: ${address}`);
    });

    if (removedCount > 0) {
      logger.info('PEER_DISCOVERY', `Cleaned up ${removedCount} DNS entries from peer storage`);
      this.savePeersToDisk();
    }
  }

  /**
   * Add a new peer to the known peers list
   */
  addKnownPeer(address, port = 23000, discoveredBy = 'manual') {
    // Normalize the address to extract hostname from WebSocket URLs or host:port format
    let normalizedAddress = address;
    let normalizedPort = port;

    try {
      if (address.startsWith('ws://')) {
        const url = new URL(address);
        normalizedAddress = url.hostname;
        normalizedPort = parseInt(url.port) || port || 23000;
        logger.debug('PEER_DISCOVERY', `Normalized WebSocket URL ${address} to ${normalizedAddress}:${normalizedPort}`);
      } else if (address.includes(':') && !address.includes('::')) {
        // Handle host:port format (but not IPv6)
        const parts = address.split(':');
        if (parts.length === 2) {
          normalizedAddress = parts[0];
          const parsedPort = parseInt(parts[1]);
          if (!isNaN(parsedPort)) {
            normalizedPort = parsedPort;
            logger.debug('PEER_DISCOVERY', `Normalized host:port ${address} to ${normalizedAddress}:${normalizedPort}`);
          }
        }
      }
    } catch (error) {
      logger.warn('PEER_DISCOVERY', `Failed to parse address ${address}: ${error.message}`);
    }

    if (this.bannedPeers.has(normalizedAddress)) {
      logger.debug('PEER_DISCOVERY', `Not adding banned peer: ${normalizedAddress}`);
      return false;
    }

    if (!this.knownPeers.has(normalizedAddress)) {
      // Check for DNS/IP duplicates before adding
      if (this.isDuplicatePeer(normalizedAddress, normalizedPort)) {
        logger.debug('PEER_DISCOVERY', `Not adding ${normalizedAddress}:${normalizedPort} - equivalent peer already exists`);
        return false;
      }

      const peerInfo = this.createPeerInfo(normalizedAddress, normalizedPort);
      peerInfo.discoveredBy = discoveredBy;
      this.knownPeers.set(normalizedAddress, peerInfo);

      logger.info('PEER_DISCOVERY', `Added new peer: ${normalizedAddress}:${normalizedPort} (discovered by: ${discoveredBy})`);
      this.savePeersToDisk();
      return true;
    }

    // Update existing peer's last seen time
    const existingPeer = this.knownPeers.get(normalizedAddress);
    existingPeer.lastSeen = Date.now();
    this.savePeersToDisk();
    return false; // Return false since no new peer was added
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
        // Give newly discovered peers a chance by prioritizing never-connected peers
        const aConnected = a.lastConnected !== null;
        const bConnected = b.lastConnected !== null;

        // Priority: never-connected peers first (to give new peers a chance)
        if (aConnected !== bConnected) return aConnected - bConnected;

        // Then reliable peers first
        if (a.isReliable !== b.isReliable) return b.isReliable - a.isReliable;

        // Then by reputation
        if (a.reputation !== b.reputation) return b.reputation - a.reputation;

        // Finally by last successful connection
        return (b.lastConnected || 0) - (a.lastConnected || 0);
      });

    return availablePeers.slice(0, this.maxPeers);
  }

  /**
   * Check if an address corresponds to a seed node (either hostname or resolved IP)
   * @param address - The address to check (e.g., "188.91.102.21:23000" or "node.pastella.org:23000")
   */
  isSeedNodeAddress(address) {
    if (!this.config?.network?.seedNodes) return false;

    for (const seedNode of this.config.network.seedNodes) {
      try {
        const url = new URL(seedNode);
        const seedAddress = `${url.hostname}:${url.port}`;

        // Direct match (DNS name)
        if (address === seedAddress) {
          return true;
        }

        // Check if this address matches any resolved IPs for this seed node
        // This relies on the DNS resolution done in P2PNetwork
        // We'll check if the IP part matches any known seed node IPs
        if (address.includes(':')) {
          const [ip, port] = address.split(':');
          const seedPort = url.port;

          // If this is an IP address and the port matches a seed node port,
          // we consider it a potential seed node match
          if (/^\d+\.\d+\.\d+\.\d+$/.test(ip) && port === seedPort) {
            return true;
          }
        }
      } catch (error) {
        // Invalid seed node URL, skip
        continue;
      }
    }

    return false;
  }

  /**
   * Mark peer as connected
   */
  markPeerConnected(address, ws) {
    this.activePeers.set(address, ws);

    let peerInfo = this.knownPeers.get(address);
    if (peerInfo) {
      peerInfo.lastConnected = Date.now();
      peerInfo.connectionCount++;
      peerInfo.isReliable = peerInfo.connectionCount >= 1; // Lowered for small networks
      peerInfo.reputation = Math.min(1000, peerInfo.reputation + 10);
    } else {
      // CRITICAL: Auto-add unknown peers when they connect
      logger.info('PEER_DISCOVERY', `Auto-adding unknown peer: ${address}`);

      // Extract hostname and port if address includes port
      let hostname = address;
      let port = 23000;

      if (address.includes(':') && !address.startsWith('ws://')) {
        const parts = address.split(':');
        hostname = parts[0];
        port = parseInt(parts[1]) || 23000;
      }

      // Check if this is a seed node (either by hostname or IP)
      const discoveryType = this.isSeedNodeAddress(address) ? 'config' : 'connection';

      if (this.addKnownPeer(hostname, port, discoveryType)) {
        peerInfo = this.knownPeers.get(hostname);
        if (peerInfo) {
          peerInfo.lastConnected = Date.now();
          peerInfo.connectionCount = 1;
          peerInfo.isReliable = true;
          peerInfo.reputation = 1000;
        }
      }
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
   * Set external address from UPnP manager
   */
  setExternalAddress(externalAddress) {
    this.externalAddress = externalAddress;
    logger.info('PEER_DISCOVERY', `External address set: ${externalAddress}`);

    // Add our own external address to known peers so it can be shared
    if (externalAddress) {
      const [host, port] = externalAddress.split(':');
      this.addKnownPeer(host, parseInt(port) || 23000, 'upnp');
    }
  }

  /**
   * Get external address if available
   */
  getExternalAddress() {
    return this.externalAddress;
  }

  /**
   * Get list of peers to share with other nodes
   */
  getPeersToShare(maxPeers = 10) {
    let reliablePeers = Array.from(this.knownPeers.values())
      .filter(peer => {
        // Only share IP addresses, not DNS names
        const isIPAddress = /^\d+\.\d+\.\d+\.\d+$/.test(peer.address);
        return peer.isReliable && !this.bannedPeers.has(peer.address) && isIPAddress;
      })
      .sort((a, b) => b.reputation - a.reputation);

    // Prioritize our external address if available (discovered by UPnP)
    if (this.externalAddress) {
      const [externalHost] = this.externalAddress.split(':');
      const externalPeer = reliablePeers.find(peer => peer.address === externalHost);
      if (externalPeer) {
        // Move external peer to front of list
        reliablePeers = [externalPeer, ...reliablePeers.filter(peer => peer.address !== externalHost)];
      }
    }

    return reliablePeers.slice(0, maxPeers).map(peer => ({
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

    // Only log INFO when new peers are actually added
    if (newPeersAdded > 0) {
      logger.info('PEER_DISCOVERY', `Received ${peerList.length} peers from ${fromAddress}, added ${newPeersAdded} new peers`);
    } else {
      logger.debug('PEER_DISCOVERY', `Received ${peerList.length} peers from ${fromAddress}, no new peers added`);
    }
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

      // Get unique IP addresses we're currently connected to
      const connectedIPs = new Set();
      for (const address of this.activePeers.keys()) {
        const ip = address.split(':')[0]; // Extract IP from address:port
        connectedIPs.add(ip);
      }

      // Try to connect to peers from different IP addresses that we're not connected to
      const peersToConnect = this.getPeersForConnection()
        .filter(peer => {
          const peerIP = peer.address.split(':')[0];
          return !connectedIPs.has(peerIP) && this.canAttemptConnection(peer.address);
        })
        .slice(0, Math.max(1, this.maxPeers - currentConnections)); // Always try at least 1 new peer

      if (peersToConnect.length > 0) {
        logger.info('PEER_DISCOVERY', `Attempting to connect to ${peersToConnect.length} new peers from different IPs (current connections: ${currentConnections}, unique IPs: ${connectedIPs.size})`);

        for (const peer of peersToConnect) {
          try {
            logger.debug('PEER_DISCOVERY', `Attempting connection to ${peer.address}:${peer.port}`);
            await connectionCallback(peer.address, peer.port);
          } catch (error) {
            logger.warn('PEER_DISCOVERY', `Failed to connect to ${peer.address}:${peer.port}: ${error.message}`);
            this.markConnectionFailure(peer.address, error);
          }
        }
      } else {
        logger.debug('PEER_DISCOVERY', `No new peers to connect (current: ${currentConnections}, unique IPs: ${connectedIPs.size})`);
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