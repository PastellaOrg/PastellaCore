const dns = require('dns');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const WebSocket = require('ws');

const Block = require('../models/Block');
const Blockchain = require('../models/Blockchain');
const { Transaction } = require('../models/Transaction');
const logger = require('../utils/logger');

const MessageHandler = require('./MessageHandler');
const NetworkPartitionHandler = require('./NetworkPartitionHandler');
const NetworkSync = require('./NetworkSync');
const NodeIdentity = require('./NodeIdentity');

// Import modular components
const PeerManager = require('./PeerManager');
const PeerReputation = require('./PeerReputation');
const SeedNodeManager = require('./SeedNodeManager');

// Promisify DNS functions
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve = promisify(dns.resolve);

/**
 * MODULAR & SECURE P2P NETWORK CLASS
 *
 * This class now orchestrates specialized modules:
 * - PeerManager: Handles all peer connection management
 * - SeedNodeManager: Manages seed node connections and reconnection
 * - PeerReputation: Handles peer reputation and banning
 * - MessageHandler: Manages message processing and routing
 * - NetworkSync: Handles network synchronization and peer discovery
 *
 * BENEFITS:
 * - Better code organization and maintainability
 * - Easier testing and debugging
 * - Clear separation of concerns
 * - Reduced file size and complexity
 */
class P2PNetwork {
  /**
   *
   * @param blockchain
   * @param port
   * @param config
   */
  constructor(blockchain, port = 3001, config = null) {
    logger.debug('P2P_NETWORK', `Initializing P2P Network: port=${port}, config=${config ? 'present' : 'null'}`);
    logger.debug('P2P_NETWORK', `Blockchain instance: ${blockchain ? 'present' : 'null'}, type: ${typeof blockchain}`);

    this.blockchain = blockchain;
    this.port = port;
    this.wss = null;
    this.isRunning = false;
    this.config = config;

    // Get data directory from config
    const dataDir = config?.storage?.dataDir || './data';
    logger.debug('P2P_NETWORK', `Data directory: ${dataDir}`);

    // Initialize modular components
    logger.debug('P2P_NETWORK', `Initializing P2P Network components...`);
    try {
      this.peerManager = new PeerManager(config?.network?.maxPeers || 10);
      logger.debug('P2P_NETWORK', `PeerManager initialized: maxPeers=${config?.network?.maxPeers || 10}`);

      this.seedNodeManager = new SeedNodeManager(config, port);
      logger.debug('P2P_NETWORK', `SeedNodeManager initialized: port=${port}`);

      this.peerReputation = new PeerReputation(dataDir);
      logger.debug('P2P_NETWORK', `PeerReputation initialized: dataDir=${dataDir}`);

      this.messageHandler = new MessageHandler(blockchain, this.peerReputation, config);
      logger.debug('P2P_NETWORK', `MessageHandler initialized with blockchain and peerReputation`);

      // Set cross-reference for handshake handling
      this.messageHandler.setP2PNetworkReference(this);

      this.networkSync = new NetworkSync(blockchain, this.peerManager, this.seedNodeManager);
      logger.debug('P2P_NETWORK', `NetworkSync initialized with blockchain, peerManager, and seedNodeManager`);

      logger.debug('P2P_NETWORK', `All modular components initialized successfully`);
    } catch (error) {
      logger.error('P2P_NETWORK', `Failed to initialize P2P Network components: ${error.message}`);
      logger.error('P2P_NETWORK', `Error stack: ${error.stack}`);
      throw error;
    }

    // Node identity and authentication system
    logger.debug('P2P_NETWORK', `Initializing node identity and authentication system...`);
    try {
      this.nodeIdentity = new NodeIdentity(null, null, dataDir);
      logger.debug('P2P_NETWORK', `NodeIdentity initialized successfully`);

      this.authenticatedPeers = new Map(); // Map<peerAddress, {nodeId, publicKey, authenticatedAt}>
      this.pendingChallenges = new Map(); // Map<peerAddress, {challenge, timestamp, nodeId}>
      this.initiatedAuthentication = new Set(); // Set<peerAddress> - track which peers we've initiated auth with
      this.pendingHandshakes = new Map(); // Map<peerAddress, timeout> - track handshake timeouts
      this.authenticationTimeout = 10000; // 10 seconds for authentication

      logger.debug('P2P_NETWORK', `Authentication system initialized: timeout=${this.authenticationTimeout}ms`);
    } catch (error) {
      logger.error('P2P_NETWORK', `Failed to initialize authentication system: ${error.message}`);
      logger.error('P2P_NETWORK', `Error stack: ${error.stack}`);
      throw error;
    }

    // Network partition handling system
    logger.debug('P2P_NETWORK', `Initializing network partition handler...`);
    try {
      this.partitionHandler = new NetworkPartitionHandler(this);
      logger.debug('P2P_NETWORK', `NetworkPartitionHandler initialized successfully`);
    } catch (error) {
      logger.error('P2P_NETWORK', `Failed to initialize NetworkPartitionHandler: ${error.message}`);
      logger.error('P2P_NETWORK', `Error stack: ${error.stack}`);
      throw error;
    }

    // Force IPv4-only DNS resolution
    logger.debug('P2P_NETWORK', `Setting up IPv4-only DNS resolution...`);
    this.setupIPv4OnlyDNS();

    logger.debug('P2P_NETWORK', `Loading seed nodes from config...`);
    this.loadSeedNodes();

    logger.debug('P2P_NETWORK', `P2P Network constructor completed successfully`);
  }

  /**
   * Setup IPv4-only DNS resolution
   */
  setupIPv4OnlyDNS() {
    // Configure DNS to prefer IPv4
    dns.setDefaultResultOrder('ipv4first');
    logger.info('P2P', 'DNS resolution configured for IPv4-first');
  }

  /**
   * Load seed nodes from config
   */
  loadSeedNodes() {
    if (this.config && this.config.network && this.config.network.seedNodes) {
      this.seedNodeManager.loadSeedNodes(this.config);
      // Update PeerManager with seed node addresses for detection
      this.updatePeerManagerSeedNodes();
    }
  }

  /**
   * Update PeerManager with seed node addresses for detection
   */
  updatePeerManagerSeedNodes() {
    if (this.config?.network?.seedNodes) {
      const seedNodeAddresses = this.config.network.seedNodes
        .map(seedNode => {
          try {
            const url = new URL(seedNode);
            return `${url.hostname}:${url.port}`;
          } catch (error) {
            logger.warn('P2P_NETWORK', `Invalid seed node URL: ${seedNode}`);
            return null;
          }
        })
        .filter(Boolean);

      this.peerManager.setSeedNodeAddresses(seedNodeAddresses);
      logger.info(
        'P2P_NETWORK',
        `Seed node detection enabled for ${seedNodeAddresses.length} addresses: ${seedNodeAddresses.join(', ')}`
      );
    }
  }

  /**
   * Setup seed node configuration
   * @param seedConfig
   */
  setupSeedNode(seedConfig) {
    this.seedNodeManager.setupSeedNode(seedConfig);
    this.peerManager.setMaxPeers(seedConfig.maxConnections || 50);
  }

  /**
   * Start P2P network
   */
  async start() {
    logger.debug('P2P_NETWORK', `Starting P2P network...`);
    logger.debug(
      'P2P_NETWORK',
      `Current state: isRunning=${this.isRunning}, port=${this.port}, host=${this.host || '0.0.0.0'}`
    );

    if (this.isRunning) {
      logger.debug('P2P_NETWORK', `Network already running, skipping start operation`);
      return false;
    }

    try {
      logger.info('P2P', `Starting P2P network on port ${this.port}`);
      logger.debug('P2P_NETWORK', `Creating HTTP server bound to IPv4 only...`);

      // Create HTTP server bound to IPv4 only
      const http = require('http');
      const server = http.createServer();
      logger.debug('P2P_NETWORK', `HTTP server created successfully`);

      // Bind to IPv4 only
      logger.debug('P2P_NETWORK', `Binding HTTP server to IPv4 0.0.0.0:${this.port}...`);
      server.listen(this.port, '0.0.0.0', () => {
        logger.info('P2P', `P2P server listening on IPv4 0.0.0.0:${this.port}`);
        logger.debug('P2P_NETWORK', `HTTP server bound successfully to port ${this.port}`);
      });

      logger.debug('P2P_NETWORK', `Creating WebSocket server...`);
      this.wss = new WebSocket.Server({ server });
      logger.debug('P2P_NETWORK', `WebSocket server created successfully`);

      logger.debug('P2P_NETWORK', `Setting up WebSocket connection handler...`);
      this.wss.on('connection', (ws, req) => {
        const { remoteAddress } = req.socket;
        logger.info('P2P', `New peer connected: ${remoteAddress}:${req.socket.remotePort}`);
        logger.debug('P2P_NETWORK', `Handling new connection from ${remoteAddress}:${req.socket.remotePort}`);
        this.handleConnection(ws);
      });
      logger.debug('P2P_NETWORK', `WebSocket connection handler configured successfully`);

      this.isRunning = true;
      logger.debug('P2P_NETWORK', `Network state updated: isRunning=${this.isRunning}`);

      // Start reputation maintenance
      logger.debug('P2P_NETWORK', `Starting reputation maintenance...`);
      this.startReputationMaintenance();
      logger.debug('P2P_NETWORK', `Reputation maintenance started successfully`);

      // Start partition handling
      logger.debug('P2P_NETWORK', `Starting network partition handler...`);
      this.partitionHandler.start();
      logger.debug('P2P_NETWORK', `Network partition handler started successfully`);

      // Connect to seed nodes if not running as seed node
      logger.debug(
        'P2P_NETWORK',
        `Checking seed node configuration: isSeedNode=${this.seedNodeManager.isSeedNode}, seedNodes=${this.seedNodeManager.seedNodes.length}`
      );
      if (!this.seedNodeManager.isSeedNode && this.seedNodeManager.seedNodes.length > 0) {
        logger.debug(
          'P2P_NETWORK',
          `Not running as seed node, connecting to ${this.seedNodeManager.seedNodes.length} seed nodes...`
        );
        try {
          logger.debug('P2P_NETWORK', `Connecting to seed nodes...`);
          await this.networkSync.connectToSeedNodes(this.connectToPeer.bind(this));
          logger.debug('P2P_NETWORK', `Seed node connections established successfully`);

          // Wait for authentication to complete before syncing
          logger.info('P2P', 'Waiting for authentication to complete before network sync...');
          logger.debug('P2P_NETWORK', `Waiting 2 seconds for authentication to complete...`);
          await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds for authentication

          // Start network synchronization after successful seed node connections
          logger.debug('P2P_NETWORK', `Starting network synchronization...`);
          await this.networkSync.syncWithNetwork();
          logger.debug('P2P_NETWORK', `Network synchronization completed successfully`);
        } catch (error) {
          logger.error('P2P_NETWORK', `Failed to establish network connectivity: ${error.message}`);
          logger.error('P2P_NETWORK', `Error stack: ${error.stack}`);
          console.error(`❌ Failed to establish network connectivity: ${error.message}`);
          throw error;
        }
      } else {
        logger.debug('P2P_NETWORK', `Running as seed node or no seed nodes configured, skipping seed node connection`);
      }

      logger.debug('P2P_NETWORK', `P2P network started successfully`);
      return true;
    } catch (error) {
      logger.error('P2P_NETWORK', `Failed to start P2P network: ${error.message}`);
      logger.error('P2P_NETWORK', `Error stack: ${error.stack}`);
      logger.error('P2P_NETWORK', `Network state at failure: isRunning=${this.isRunning}, port=${this.port}`);
      throw error;
    }
  }

  /**
   * Stop P2P network
   */
  stop() {
    if (!this.isRunning) {
      console.log('P2P network is not running');
      return false;
    }

    logger.info('P2P', 'Stopping P2P network...');

    // Stop reputation maintenance
    this.stopReputationMaintenance();

    // Stop partition handling
    this.partitionHandler.stop();

    // Stop seed node reconnection
    this.seedNodeManager.stopSeedNodeReconnection();

    // Stop periodic sync
    this.networkSync.stopPeriodicSync();

    // Save reputation data before stopping
    this.peerReputation.savePeerReputation();

    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }

    this.peerManager.clearPeers();
    this.isRunning = false;

    logger.info('P2P', 'P2P network stopped');
    return true;
  }

  /**
   * Handle outgoing WebSocket connection (we initiated the connection)
   * @param ws
   * @param peerAddress
   */
  handleOutgoingConnection(ws, peerAddress) {
    logger.debug('P2P_NETWORK', `Handling outgoing connection to ${peerAddress}...`);

    // Extract peer address from WebSocket connection
    const extractedAddress = this.extractPeerAddress(ws);
    logger.debug('P2P_NETWORK', `Peer address extracted: ${extractedAddress}`);

    // Track connection state
    this.connectionStates = this.connectionStates || new Map();
    this.connectionStates.set(extractedAddress, 'connecting');
    logger.debug('P2P_NETWORK', `Connection state set to 'connecting' for ${extractedAddress}`);

    // Check if this is a seed node connection
    const isSeedNode = this.peerManager.isSeedNodeAddress(extractedAddress);
    if (isSeedNode) {
      logger.debug('P2P_NETWORK', `Outgoing connection to seed node: ${extractedAddress}`);
    }

    // Check if peer is banned
    logger.debug('P2P_NETWORK', `Checking if peer ${extractedAddress} is banned...`);
    if (this.peerReputation.isPeerBanned(extractedAddress)) {
      logger.warn('P2P', `[REPUTATION] Rejecting banned peer: ${extractedAddress}`);
      logger.debug('P2P_NETWORK', `Closing connection to banned peer ${extractedAddress}`);
      ws.close();
      return;
    }
    logger.debug('P2P_NETWORK', `Peer ${extractedAddress} is not banned, proceeding with connection`);

    // Check if we can accept more peers
    if (!this.peerManager.canAcceptPeers()) {
      logger.warn('P2P', `Max peers reached (${this.peerManager.maxPeers}), rejecting connection`);
      this.peerReputation.updatePeerReputation(extractedAddress, 'bad_behavior', { reason: 'max_peers_reached' });
      ws.close();
      return;
    }

    // Update reputation for successful connection
    this.peerReputation.updatePeerReputation(extractedAddress, 'connect');

    // Add peer to manager
    if (!this.peerManager.addPeer(ws, extractedAddress)) {
      ws.close();
      return;
    }

    // CRITICAL: For outgoing connections, WE initiate the handshake
    logger.debug('P2P_NETWORK', `Outgoing connection established with ${extractedAddress}, initiating handshake`);
    this.initiateHandshake(ws, extractedAddress);

    // Set up message handlers
    this.setupMessageHandlers(ws, extractedAddress);
  }

  /**
   * Handle incoming WebSocket connection (peer connected to us)
   * @param ws
   */
  handleConnection(ws) {
    logger.debug('P2P_NETWORK', `Handling new WebSocket connection...`);

    // Extract peer address from WebSocket connection
    const peerAddress = this.extractPeerAddress(ws);
    logger.debug('P2P_NETWORK', `Peer address extracted: ${peerAddress}`);

    // Track connection state
    this.connectionStates = this.connectionStates || new Map();
    this.connectionStates.set(peerAddress, 'connecting');
    logger.debug('P2P_NETWORK', `Connection state set to 'connecting' for ${peerAddress}`);

    // Check if this is a seed node connection
    const isSeedNode = this.peerManager.isSeedNodeAddress(peerAddress);
    if (isSeedNode) {
      logger.debug('P2P_NETWORK', `Connection from seed node: ${peerAddress}`);
    }

    // Check if peer is banned
    logger.debug('P2P_NETWORK', `Checking if peer ${peerAddress} is banned...`);
    if (this.peerReputation.isPeerBanned(peerAddress)) {
      logger.warn('P2P', `[REPUTATION] Rejecting banned peer: ${peerAddress}`);
      logger.debug('P2P_NETWORK', `Closing connection to banned peer ${peerAddress}`);
      ws.close();
      return;
    }
    logger.debug('P2P_NETWORK', `Peer ${peerAddress} is not banned, proceeding with connection`);

    // Check if we can accept more peers
    if (!this.peerManager.canAcceptPeers()) {
      logger.warn('P2P', `Max peers reached (${this.peerManager.maxPeers}), rejecting connection`);
      this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', { reason: 'max_peers_reached' });
      ws.close();
      return;
    }

    // Update reputation for successful connection
    this.peerReputation.updatePeerReputation(peerAddress, 'connect');

    // Add peer to manager
    if (!this.peerManager.addPeer(ws, peerAddress)) {
      ws.close();
      return;
    }

    // CRITICAL FIX: Don't initiate handshake from receiving node
    // The connecting node (initiator) will send the handshake
    // We just wait for it to arrive
    logger.debug('P2P_NETWORK', `Connection established with ${peerAddress}, waiting for handshake from peer`);

    // Set up message handlers
    this.setupMessageHandlers(ws, peerAddress);
  }

  /**
   * Set up message handlers for a WebSocket connection
   * @param ws
   * @param peerAddress
   */
  setupMessageHandlers(ws, peerAddress) {
    ws.on('message', data => {
      try {
        const message = JSON.parse(data);

        // Update reputation for message received
        this.peerReputation.updatePeerReputation(peerAddress, 'message_received');

        // Handle message through message handler
        this.messageHandler.handleMessage(ws, message, peerAddress, this.isPeerAuthenticated(peerAddress));
      } catch (error) {
        logger.error('P2P', `Error parsing message: ${error.message}`);
        this.peerReputation.updatePeerReputation(peerAddress, 'invalid_message', { reason: 'json_parse_error' });
      }
    });

    ws.on('close', () => {
      // Update reputation for disconnect
      this.peerReputation.updatePeerReputation(peerAddress, 'disconnect');

      // Clean up connection state
      if (this.connectionStates) {
        this.connectionStates.delete(peerAddress);
      }

      // Clean up authentication data
      this.authenticatedPeers.delete(peerAddress);
      this.pendingChallenges.delete(peerAddress);
      this.initiatedAuthentication.delete(peerAddress);

      // Check if this was a seed node connection
      const wasSeedNode = this.seedNodeManager.markSeedNodeAsDisconnected(peerAddress);

      // Remove peer from manager
      this.peerManager.removePeer(ws);

      if (wasSeedNode) {
        logger.info('P2P', `Seed node disconnected: ${peerAddress}`);
      } else {
        // Notify partition handler of peer disconnection
        this.partitionHandler.handlePeerDisconnection(peerAddress);
      }
      logger.info('P2P', `Peer disconnected: ${peerAddress}`);
    });

    ws.on('error', error => {
      logger.error('P2P', `WebSocket error from ${peerAddress}: ${error.message}`);
      this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', { reason: 'websocket_error' });
      this.authenticatedPeers.delete(peerAddress);
      this.pendingChallenges.delete(peerAddress);
      this.initiatedAuthentication.delete(peerAddress);
    });
  }

  /**
   * Initiate handshake with a new peer
   * @param ws
   * @param peerAddress
   */
  initiateHandshake(ws, peerAddress) {
    try {
      const handshakeMessage = {
        type: 'HANDSHAKE',
        data: {
          networkId: this.config?.networkId || 'unknown',
          nodeVersion: '1.0.0',
          timestamp: Date.now(),
          nodeId: this.nodeIdentity.nodeId,
          listeningPort: this.port, // Add listening port for seed node detection
        },
      };

      logger.debug(
        'P2P_NETWORK',
        `Initiating handshake with ${peerAddress}: networkId=${handshakeMessage.data.networkId}`
      );
      ws.send(JSON.stringify(handshakeMessage));

      // Set a timeout for handshake response
      const handshakeTimeout = setTimeout(() => {
        logger.warn('P2P_NETWORK', `Handshake timeout with ${peerAddress}`);
        this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', { reason: 'handshake_timeout' });
        ws.close(1000, 'Handshake timeout');
      }, 30000); // 30 second timeout (increased from 10 seconds)

      // Store timeout reference for cleanup
      this.pendingHandshakes = this.pendingHandshakes || new Map();
      this.pendingHandshakes.set(peerAddress, handshakeTimeout);
    } catch (error) {
      logger.error('P2P_NETWORK', `Error initiating handshake with ${peerAddress}: ${error.message}`);
      this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', { reason: 'handshake_initiation_error' });
    }
  }

  /**
   * Extract peer address from WebSocket connection
   * @param ws
   */
  extractPeerAddress(ws) {
    try {
      // Try to get address from WebSocket connection info
      if (ws._socket && ws._socket.remoteAddress && ws._socket.remotePort) {
        return `${ws._socket.remoteAddress}:${ws._socket.remotePort}`;
      }

      // Fallback for different WebSocket implementations
      if (ws.url) {
        const url = new URL(ws.url);
        return `${url.hostname}:${url.port}`;
      }

      // If we can't determine the address, generate a unique identifier
      return `peer-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    } catch (error) {
      logger.warn('P2P_NETWORK', `Could not extract peer address: ${error.message}`);
      return `unknown-${Date.now()}`;
    }
  }

  /**
   * Get peer address from PeerManager (for existing connections)
   * @param ws
   */
  getPeerAddress(ws) {
    return this.peerManager.getPeerAddress(ws);
  }

  /**
   * Connect to a peer
   * @param host
   * @param port
   */
  async connectToPeer(host, port) {
    const peerAddress = `${host}:${port}`;

    // Check if already connected
    if (this.peerManager.getPeerAddresses().includes(peerAddress)) {
      return null; // Already connected
    }

    try {
      const ws = new WebSocket(`ws://${host}:${port}`);

      return new Promise(resolve => {
        const timeout = setTimeout(() => {
          ws.terminate();
          resolve(false);
        }, 5000);

        ws.on('open', () => {
          clearTimeout(timeout);

          // CRITICAL FIX: For outgoing connections, we need to handle them differently
          // than incoming connections. Outgoing connections should send handshakes.
          this.handleOutgoingConnection(ws, peerAddress);

          resolve(true);
        });

        ws.on('error', () => {
          clearTimeout(timeout);
          resolve(false);
        });
      });
    } catch (error) {
      logger.error('P2P', `Failed to connect to peer ${peerAddress}: ${error.message}`);
      return false;
    }
  }

  /**
   * Check if peer is authenticated
   * @param peerAddress
   */
  isPeerAuthenticated(peerAddress) {
    return this.authenticatedPeers.has(peerAddress);
  }

  /**
   * Start reputation maintenance
   */
  startReputationMaintenance() {
    // Apply score decay every hour
    setInterval(
      () => {
        this.peerReputation.applyScoreDecay();
      },
      60 * 60 * 1000
    );

    // Save reputation data every 5 minutes
    setInterval(
      () => {
        this.peerReputation.savePeerReputation();
      },
      5 * 60 * 1000
    );

    // Clean up old data every day
    setInterval(
      () => {
        this.peerReputation.cleanupOldData();
      },
      24 * 60 * 60 * 1000
    );
  }

  /**
   * Stop reputation maintenance
   */
  stopReputationMaintenance() {
    // Save reputation data before stopping
    this.peerReputation.savePeerReputation();
  }

  /**
   * Get network status
   */
  getNetworkStatus() {
    const peerList = this.peerManager.getPeerList();

    // Add seed node detection info
    const seedNodeInfo = {
      configuredSeedNodes: this.config?.network?.seedNodes || [],
      detectedSeedNodes: peerList.filter(peer => peer.isSeedNode).map(peer => peer.address),
      totalSeedNodes: peerList.filter(peer => peer.isSeedNode).length,
    };

    return {
      isRunning: this.isRunning,
      port: this.port,
      networkId: this.config?.networkId || 'unknown',
      peerCount: this.peerManager.getPeerCount(),
      maxPeers: this.peerManager.maxPeers,
      peerList,
      seedNodeConnections: this.seedNodeManager.getSeedNodeStatus(),
      seedNodeInfo,
      networkSync: this.networkSync.getNetworkSyncStatus(),
      nodeIdentity: this.nodeIdentity.getIdentityInfo(),
    };
  }

  /**
   * CRITICAL: Get reputation status for API
   */
  getReputationStatus() {
    try {
      return this.peerReputation.getReputationStatus();
    } catch (error) {
      logger.error('P2P_NETWORK', `Failed to get reputation status: ${error.message}`);
      return { error: 'Failed to get reputation status' };
    }
  }

  /**
   * CRITICAL: Get reputation statistics for API
   */
  getReputationStats() {
    try {
      return this.peerReputation.getReputationStats();
    } catch (error) {
      logger.error('P2P_NETWORK', `Failed to get reputation stats: ${error.message}`);
      return { error: 'Failed to get reputation stats' };
    }
  }

  /**
   * Broadcast new block to all peers
   * @param block
   */
  broadcastNewBlock(block) {
    return this.networkSync.broadcastNewBlock(block);
  }

  /**
   * Broadcast new transaction to all peers
   * @param transaction
   */
  broadcastNewTransaction(transaction) {
    return this.networkSync.broadcastNewTransaction(transaction);
  }

  /**
   * Sync mempool with peers (Bitcoin-style)
   */
  syncMempoolWithPeers() {
    try {
      if (!this.networkSync) {
        return { success: false, message: 'Network sync not available' };
      }

      // Trigger mempool sync
      this.networkSync.syncMempoolState();

      const peerCount = this.peerManager.getPeerCount();
      return {
        success: true,
        peersNotified: peerCount,
        message: `Mempool sync initiated with ${peerCount} peers`,
      };
    } catch (error) {
      logger.error('P2P_NETWORK', `Failed to sync mempool with peers: ${error.message}`);
      return { success: false, message: error.message };
    }
  }

  /**
   * Get mempool synchronization status
   */
  getMempoolSyncStatus() {
    try {
      if (!this.networkSync) {
        return { error: 'Network sync not available' };
      }

      const networkStatus = this.networkSync.getNetworkSyncStatus();
      const mempoolStatus = this.blockchain.memoryPool.getMemoryStatus();

      return {
        networkSync: networkStatus,
        mempool: {
          poolSize: mempoolStatus.poolSize,
          memoryUsage: mempoolStatus.memoryUsage,
          lastCleanup: mempoolStatus.lastCleanup,
          batchProcessing: this.blockchain.memoryPool.getBatchProcessingConfig(),
        },
        lastSync: networkStatus.lastSync,
        isSyncing: networkStatus.isSyncing,
        peerCount: this.peerManager.getPeerCount(),
        timestamp: Date.now(),
      };
    } catch (error) {
      logger.error('P2P_NETWORK', `Failed to get mempool sync status: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Get peer list
   */
  getPeerList() {
    return this.peerManager.getPeerList();
  }

  /**
   * Get peer count
   */
  getPeerCount() {
    return this.peerManager.getPeerCount();
  }

  /**
   * Get all peers
   */
  getAllPeers() {
    return this.peerManager.getAllPeers();
  }

  /**
   * Check if peer exists
   * @param ws
   */
  hasPeer(ws) {
    return this.peerManager.hasPeer(ws);
  }

  /**
   * Get peer reputation
   * @param peerAddress
   */
  getPeerReputation(peerAddress) {
    return this.peerReputation.getPeerReputation(peerAddress);
  }

  /**
   * Get peer score
   * @param peerAddress
   */
  getPeerScore(peerAddress) {
    return this.peerReputation.getPeerScore(peerAddress);
  }

  /**
   * Ban peer
   * @param peerAddress
   * @param duration
   */
  banPeer(peerAddress, duration = null) {
    return this.peerReputation.banPeer(peerAddress, duration);
  }

  /**
   * Unban peer
   * @param peerAddress
   */
  unbanPeer(peerAddress) {
    return this.peerReputation.unbanPeer(peerAddress);
  }

  /**
   * Reset peer reputation
   * @param peerAddress
   */
  resetPeerReputation(peerAddress) {
    return this.peerReputation.resetPeerReputation(peerAddress);
  }

  /**
   * Get banned peers
   */
  getBannedPeers() {
    return this.peerReputation.getBannedPeers();
  }

  /**
   * Start periodic sync
   * @param intervalMs
   */
  startPeriodicSync(intervalMs = 30000) {
    this.networkSync.startPeriodicSync(intervalMs);
  }

  /**
   * Stop periodic sync
   */
  stopPeriodicSync() {
    this.networkSync.stopPeriodicSync();
  }

  /**
   * Sync with network
   */
  async syncWithNetwork() {
    return await this.networkSync.syncWithNetwork();
  }

  /**
   * Get sync stats
   */
  getSyncStats() {
    return this.networkSync.getSyncStats();
  }

  /**
   * Check if network is synced
   */
  isNetworkSynced() {
    return this.networkSync.isNetworkSynced();
  }

  /**
   * Reset sync status
   */
  resetSyncStatus() {
    this.networkSync.resetSyncStatus();
  }

  /**
   * Get message validation stats
   */
  getMessageValidationStats() {
    return this.messageHandler.getMessageValidationStats();
  }

  /**
   * Reset message validation stats
   */
  resetMessageValidationStats() {
    this.messageHandler.resetMessageValidationStats();
  }
}

module.exports = P2PNetwork;
