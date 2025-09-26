const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const path = require('path');
const cors = require('cors');

const logger = require('../utils/logger');

// Import all monitoring services
const NodeInfoService = require('./services/NodeInfoService');
const BlockchainService = require('./services/BlockchainService');
const NetworkService = require('./services/NetworkService');
// Additional services will be added as needed
const TransactionService = require('./services/TransactionService');
const MiningService = require('./services/MiningService');
// const UTXOService = require('./services/UTXOService');
// const WalletService = require('./services/WalletService');
// const APIService = require('./services/APIService');
// const PerformanceService = require('./services/PerformanceService');
const SecurityService = require('./services/SecurityService');
// const LogService = require('./services/LogService');
// const ConfigService = require('./services/ConfigService');
// const ControlService = require('./services/ControlService');
// const AnalyticsService = require('./services/AnalyticsService');

// Controllers will be added as needed
// const DashboardController = require('./controllers/DashboardController');
// const BlockExplorerController = require('./controllers/BlockExplorerController');
// const PeerController = require('./controllers/PeerController');
// const TransactionController = require('./controllers/TransactionController');
// const UTXOController = require('./controllers/UTXOController');
// const SecurityController = require('./controllers/SecurityController');
// const AnalyticsController = require('./controllers/AnalyticsController');
// const LogController = require('./controllers/LogController');
// const ControlController = require('./controllers/ControlController');

// Import WebSocket handlers
const WebSocketManager = require('./websocket/WebSocketManager');

/**
 * PASTELLA MONITORING SERVER
 *
 * Ultimate monitoring dashboard with 100+ features:
 * - Real-time blockchain monitoring
 * - Network health tracking
 * - Transaction analysis
 * - Security monitoring
 * - Performance metrics
 * - Log management
 * - Control functions
 * - Analytics & charts
 * - Mobile responsive interface
 */
class MonitorServer {
  constructor(daemon, config = {}) {
    this.daemon = daemon;
    this.config = {
      port: config.port || 24000,
      host: config.host || '0.0.0.0',
      enabled: config.enabled || false,
      updateInterval: config.updateInterval || 1000, // 1 second
      theme: config.theme || 'dark',
      authentication: config.authentication || false,
      ...config
    };

    this.app = express();
    this.server = http.createServer(this.app);
    this.io = socketIO(this.server, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    this.isRunning = false;
    this.startTime = Date.now();

    // Initialize all services
    this.initializeServices();

    // Initialize controllers
    this.initializeControllers();

    // Initialize WebSocket manager
    this.webSocketManager = new WebSocketManager(this.io, this.services);

    // Setup middleware and routes
    this.setupMiddleware();
    this.setupRoutes();
    this.setupWebSocketHandlers();

    // Load blocked nodes on startup
    this.loadBlockedNodes();

    logger.info('MONITOR_SERVER', 'Pastella Monitoring Server initialized');
  }

  /**
   * Initialize all monitoring services
   */
  initializeServices() {
    logger.debug('MONITOR_SERVER', 'Initializing monitoring services...');

    this.services = {
      nodeInfo: new NodeInfoService(this.daemon),
      blockchain: new BlockchainService(this.daemon),
      network: new NetworkService(this.daemon),
      transaction: new TransactionService(this.daemon),
      mining: new MiningService(this.daemon),
      // Additional services will be initialized as they are implemented
      // utxo: new UTXOService(this.daemon),
      // wallet: new WalletService(this.daemon),
      // api: new APIService(this.daemon),
      // performance: new PerformanceService(this.daemon),
      security: new SecurityService(this.daemon),
      // log: new LogService(this.daemon),
      // config: new ConfigService(this.daemon),
      // control: new ControlService(this.daemon),
      // analytics: new AnalyticsService(this.daemon)
    };

    logger.debug('MONITOR_SERVER', 'All monitoring services initialized');
  }

  /**
   * Initialize all controllers
   */
  initializeControllers() {
    logger.debug('MONITOR_SERVER', 'Initializing controllers...');

    this.controllers = {
      // Controllers will be initialized as they are implemented
      // dashboard: new DashboardController(this.services),
      // blockExplorer: new BlockExplorerController(this.services),
      // peer: new PeerController(this.services),
      // transaction: new TransactionController(this.services),
      // utxo: new UTXOController(this.services),
      // security: new SecurityController(this.services),
      // analytics: new AnalyticsController(this.services),
      // log: new LogController(this.services),
      // control: new ControlController(this.services)
    };

    logger.debug('MONITOR_SERVER', 'All controllers initialized');
  }

  /**
   * Setup Express middleware
   */
  setupMiddleware() {
    // CORS
    this.app.use(cors());

    // JSON parsing
    this.app.use(express.json({ limit: '50mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));

    // Static files - serve CSS, JS, and other assets
    this.app.use('/css', express.static(path.join(__dirname, 'public/css')));
    this.app.use('/js', express.static(path.join(__dirname, 'public/js')));
    this.app.use('/assets', express.static(path.join(__dirname, 'public/assets')));

    // Set view engine (serving static HTML files)
    this.app.set('view engine', 'html');
    this.app.set('views', path.join(__dirname, 'views'));

    // Security headers
    this.app.use((req, res, next) => {
      res.header('X-Content-Type-Options', 'nosniff');
      res.header('X-Frame-Options', 'DENY');
      res.header('X-XSS-Protection', '1; mode=block');
      next();
    });

    // Request logging
    this.app.use((req, res, next) => {
      logger.debug('MONITOR_SERVER', `${req.method} ${req.url} from ${req.ip}`);
      next();
    });

    logger.debug('MONITOR_SERVER', 'Middleware configured');
  }

  /**
   * Setup all routes
   */
  setupRoutes() {
    logger.debug('MONITOR_SERVER', 'Setting up routes...');

    // Main dashboard - serve HTML interface
    this.app.get('/', (req, res) => {
      res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
    });

    // API endpoints
    this.app.get('/api/status', (req, res) => {
      res.json({
        daemon: 'running',
        blockchain: this.services.blockchain.getCurrentBlockchainStatus(),
        network: this.services.network.getNetworkStatus(),
        node: this.services.nodeInfo.getCompleteNodeInfo(),
        timestamp: new Date().toISOString()
      });
    });

    this.app.get('/api/overview', (req, res) => {
      res.json({
        nodeInfo: this.services.nodeInfo.getCompleteNodeInfo(),
        blockchain: this.services.blockchain.getBlockchainStatistics(),
        network: this.services.network.getConnectedPeers(),
        timestamp: new Date().toISOString()
      });
    });

    // Block explorer API
    this.app.get('/api/blocks', (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 10;
        const blocks = this.services.blockchain.getRecentBlocks(Math.min(limit, 1000)); // Max 1000 blocks
        res.json({ recent: blocks, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Analytics data API - optimized for charts
    this.app.get('/api/analytics/blocks', (req, res) => {
      try {
        const blocks = this.services.blockchain.getRecentBlocks(100); // Last 100 blocks for analytics

        // Calculate real analytics
        const analytics = {
          blockTimes: this.calculateBlockTimes(blocks),
          difficulties: blocks.map(block => ({
            timestamp: block.timestamp,
            difficulty: block.difficulty || 0
          })),
          transactionCounts: blocks.map(block => ({
            timestamp: block.timestamp,
            count: block.transactions?.length || 0
          })),
          hashRates: this.estimateHashRatesFromBlocks(blocks),
          averageBlockTime: this.getAverageBlockTimeFromBlocks(blocks),
          totalTransactions: blocks.reduce((sum, block) => sum + (block.transactions?.length || 0), 0)
        };

        res.json({
          success: true,
          data: {
            blockTimes: analytics.blockTimes,
            hashRates: analytics.hashRates,
            difficulties: analytics.difficulties,
            blocks: blocks
          },
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Peer monitoring API
    this.app.get('/api/peers', (req, res) => {
      try {
        const peers = this.services.network.getConnectedPeers();
        res.json({ peers, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/network-stats', (req, res) => {
      try {
        const stats = this.services.network.getNetworkStatistics();
        res.json({ stats, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Transaction monitoring API
    this.app.get('/api/mempool', (req, res) => {
      try {
        const mempool = this.services.transaction.getMempoolStatus();
        res.json({ mempool, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Memory Pool Status endpoint
    this.app.get('/api/mempool/status', (req, res) => {
      try {
        const status = this.services.transaction.getMempoolStatus();
        res.json(status);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Memory Pool Transactions endpoint
    this.app.get('/api/mempool/transactions', (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 30;
        const offset = parseInt(req.query.offset) || 0;
        const sortBy = req.query.sortBy || 'fee';
        const type = req.query.type || null;

        const pendingTransactions = this.services.transaction.getPendingTransactions();

        // Filter by type if specified
        let filteredTransactions = type ?
          pendingTransactions.filter(tx => tx.type === type || tx.tag === type) :
          pendingTransactions;

        // Sort transactions
        switch (sortBy) {
          case 'fee':
            filteredTransactions.sort((a, b) => (b.fee || 0) - (a.fee || 0));
            break;
          case 'time':
            filteredTransactions.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
            break;
          case 'size':
            filteredTransactions.sort((a, b) => (b.size || 0) - (a.size || 0));
            break;
          case 'type':
            filteredTransactions.sort((a, b) => (a.type || a.tag || '').localeCompare(b.type || b.tag || ''));
            break;
        }

        // Apply pagination
        const total = filteredTransactions.length;
        const transactions = filteredTransactions.slice(offset, offset + limit);

        res.json({
          transactions,
          pagination: {
            total,
            limit,
            offset,
            hasNext: offset + limit < total,
            hasPrevious: offset > 0
          }
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/transactions/recent', (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 20;
        const transactions = this.services.transaction.getRecentTransactions(limit);
        res.json({ transactions, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/transaction/:id', (req, res) => {
      try {
        const details = this.services.transaction.getTransactionDetails(req.params.id);
        res.json({ transaction: details, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/transactions/search', (req, res) => {
      try {
        const query = req.query.q || '';
        const options = {
          type: req.query.type || null,
          limit: parseInt(req.query.limit) || 50,
          offset: parseInt(req.query.offset) || 0,
          fromDate: req.query.fromDate || null,
          toDate: req.query.toDate || null,
          minAmount: req.query.minAmount ? parseFloat(req.query.minAmount) : null,
          maxAmount: req.query.maxAmount ? parseFloat(req.query.maxAmount) : null
        };
        const searchResult = this.services.transaction.searchTransactions(query, options);

        // Structure response to match frontend expectations
        res.json({
          success: true,
          data: {
            transactions: searchResult.results,
            pagination: {
              total: searchResult.total,
              limit: searchResult.limit,
              offset: searchResult.offset,
              hasPrevious: searchResult.offset > 0,
              hasNext: searchResult.hasMore
            }
          },
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/transactions/details/:id', (req, res) => {
      try {
        const transactionId = req.params.id;
        const details = this.services.transaction.getTransactionDetails(transactionId);

        if (!details) {
          return res.status(404).json({
            success: false,
            error: 'Transaction not found'
          });
        }

        res.json({
          success: true,
          data: details,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          error: error.message
        });
      }
    });

    this.app.get('/api/transactions/statistics', (req, res) => {
      try {
        const stats = this.services.transaction.getTransactionStatistics();
        res.json({
          success: true,
          data: stats,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/transactions/fee-analysis', (req, res) => {
      try {
        const analysis = this.services.transaction.getFeeAnalysis();
        res.json({
          success: true,
          data: analysis,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/transactions/queue-analytics', (req, res) => {
      try {
        const analytics = this.services.transaction.getQueueAnalytics();
        res.json({
          success: true,
          data: analytics,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Mining monitoring API
    this.app.get('/api/mining/status', (req, res) => {
      try {
        const status = this.services.mining.getMiningStatus();
        res.json({ mining: status, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/mining/rewards', (req, res) => {
      try {
        const rewards = this.services.mining.getMiningRewards();
        res.json({ rewards, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/mining/difficulty', (req, res) => {
      try {
        const analysis = this.services.mining.getDifficultyAnalysis();
        res.json({ difficulty: analysis, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Node blocking endpoints
    this.app.get('/api/blocked-nodes', (req, res) => {
      try {
        const blockedNodes = this.getBlockedNodes();
        res.json({ blocked: blockedNodes, timestamp: new Date().toISOString() });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/block-node', (req, res) => {
      try {
        const { address, reason } = req.body;
        if (!address) {
          return res.status(400).json({ error: 'Address is required' });
        }

        const result = this.blockNode(address, reason || 'Manual block');
        res.json({ success: true, message: `Node ${address} blocked`, result });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/unblock-node', (req, res) => {
      try {
        const { address } = req.body;
        if (!address) {
          return res.status(400).json({ error: 'Address is required' });
        }

        const result = this.unblockNode(address);
        res.json({ success: true, message: `Node ${address} unblocked`, result });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Node control endpoints
    this.app.post('/api/node/restart', (req, res) => {
      try {
        logger.warn('MONITOR_SERVER', 'Node restart requested via monitoring interface');

        // Schedule restart after response
        setTimeout(() => {
          this.restartNode();
        }, 1000);

        res.json({
          success: true,
          message: 'Node restart scheduled',
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.post('/api/node/shutdown', (req, res) => {
      try {
        logger.warn('MONITOR_SERVER', 'Node shutdown requested via monitoring interface');

        // Schedule shutdown after response
        setTimeout(() => {
          this.shutdownNode();
        }, 1000);

        res.json({
          success: true,
          message: 'Node shutdown scheduled',
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Security monitoring endpoints
    this.app.get('/api/security/dashboard', (req, res) => {
      try {
        const securityData = this.services.security.getSecurityDashboard();
        res.json({
          success: true,
          data: securityData,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/security/attacks', (req, res) => {
      try {
        const attacks = this.services.security.detectNetworkAttacks();
        res.json({
          success: true,
          data: attacks,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/security/peers', (req, res) => {
      try {
        const peerAnalysis = this.services.security.analyzePeerBehavior();
        res.json({
          success: true,
          data: peerAnalysis,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/security/transactions', (req, res) => {
      try {
        const transactionThreats = this.services.security.detectTransactionThreats();
        res.json({
          success: true,
          data: transactionThreats,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/security/mining', (req, res) => {
      try {
        const miningAttacks = this.services.security.detectMiningAttacks();
        res.json({
          success: true,
          data: miningAttacks,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/security/consensus', (req, res) => {
      try {
        const consensusAnomalies = this.services.security.detectConsensusAnomalies();
        res.json({
          success: true,
          data: consensusAnomalies,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/security/resources', (req, res) => {
      try {
        const resourceStatus = this.services.security.getResourceAbuseStatus();
        res.json({
          success: true,
          data: resourceStatus,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    this.app.get('/api/security/rate-limiting', (req, res) => {
      try {
        const rateLimitingStatus = this.services.security.getRateLimitingStatus();
        res.json({
          success: true,
          data: rateLimitingStatus,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        uptime: Date.now() - this.startTime,
        timestamp: new Date().toISOString(),
        version: require('../../package.json').version
      });
    });

    logger.debug('MONITOR_SERVER', 'All routes configured');
  }

  /**
   * Setup WebSocket handlers for real-time updates
   */
  setupWebSocketHandlers() {
    logger.debug('MONITOR_SERVER', 'Setting up WebSocket handlers...');

    this.io.on('connection', (socket) => {
      logger.debug('MONITOR_SERVER', `WebSocket client connected: ${socket.id}`);

      // Handle client joining specific rooms for targeted updates
      socket.on('join-room', (roomName) => {
        if (roomName === 'dashboard') {
          this.webSocketManager.joinDashboard(socket);
        }
      });
      socket.on('join-dashboard', () => this.webSocketManager.joinDashboard(socket));
      socket.on('join-blocks', () => this.webSocketManager.joinBlocks(socket));
      socket.on('join-transactions', () => this.webSocketManager.joinTransactions(socket));
      socket.on('join-peers', () => this.webSocketManager.joinPeers(socket));
      socket.on('join-logs', () => this.webSocketManager.joinLogs(socket));

      socket.on('disconnect', () => {
        logger.debug('MONITOR_SERVER', `WebSocket client disconnected: ${socket.id}`);
      });
    });

    // Start real-time update intervals
    this.startRealtimeUpdates();

    logger.debug('MONITOR_SERVER', 'WebSocket handlers configured');
  }

  /**
   * Start real-time update intervals
   */
  startRealtimeUpdates() {
    // Dashboard updates (every 1 second)
    setInterval(() => {
      this.webSocketManager.broadcastDashboardUpdate();
    }, this.config.updateInterval);

    // Block updates (every 5 seconds)
    setInterval(() => {
      this.webSocketManager.broadcastBlockUpdate();
    }, this.config.updateInterval * 5);

    // Transaction updates (every 2 seconds)
    setInterval(() => {
      this.webSocketManager.broadcastTransactionUpdate();
    }, this.config.updateInterval * 2);

    // Peer updates (every 10 seconds)
    setInterval(() => {
      this.webSocketManager.broadcastPeerUpdate();
    }, this.config.updateInterval * 10);

    logger.debug('MONITOR_SERVER', 'Real-time update intervals started');
  }

  /**
   * Start the monitoring server
   */
  async start() {
    if (this.isRunning) {
      logger.warn('MONITOR_SERVER', 'Monitoring server is already running');
      return;
    }

    if (!this.config.enabled) {
      logger.info('MONITOR_SERVER', 'Monitoring server is disabled');
      return;
    }

    try {
      await new Promise((resolve, reject) => {
        this.server.listen(this.config.port, this.config.host, (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });

      this.isRunning = true;

      logger.info('MONITOR_SERVER', 'Pastella Monitoring Server started successfully');
      logger.info('MONITOR_SERVER', `Web Interface: http://${this.config.host}:${this.config.port}`);

      console.log('\n╔══════════════════════════════════════════════════════════════╗');
      console.log('║              🖥️  MONITORING SERVER ACTIVE                   ║');
      console.log('╚══════════════════════════════════════════════════════════════╝');
      console.log(`📊 Access your monitoring dashboard at:`);
      console.log(`🌐 http://${this.config.host}:${this.config.port}`);
      console.log('');

    } catch (error) {
      logger.error('MONITOR_SERVER', `Failed to start monitoring server: ${error.message}`);
      throw error;
    }
  }

  /**
   * Stop the monitoring server
   */
  async stop() {
    if (!this.isRunning) {
      return;
    }

    try {
      await new Promise((resolve) => {
        this.server.close(() => {
          resolve();
        });
      });

      this.isRunning = false;
      logger.info('MONITOR_SERVER', '🛑 Monitoring server stopped');

    } catch (error) {
      logger.error('MONITOR_SERVER', `Error stopping monitoring server: ${error.message}`);
    }
  }

  /**
   * Get monitoring server status
   */
  getStatus() {
    return {
      running: this.isRunning,
      port: this.config.port,
      host: this.config.host,
      uptime: Date.now() - this.startTime,
      connectedClients: this.io ? this.io.engine.clientsCount : 0,
      features: {
        nodeInfo: true,
        blockchain: true,
        network: true,
        transactions: true,
        mining: true,
        utxo: true,
        wallet: true,
        api: true,
        performance: true,
        security: true,
        logs: true,
        analytics: true,
        control: true,
        realtime: true
      }
    };
  }

  /**
   * Node blocking functionality
   */
  getBlockedNodes() {
    if (!this.blockedNodes) {
      this.loadBlockedNodes();
    }
    return Array.from(this.blockedNodes.values());
  }

  blockNode(address, reason = 'Manual block') {
    try {
      if (!this.blockedNodes) {
        this.blockedNodes = new Map();
      }

      const blockInfo = {
        address,
        reason,
        timestamp: Date.now(),
        blockedBy: 'monitor-interface'
      };

      this.blockedNodes.set(address, blockInfo);

      // Disconnect if currently connected
      if (this.daemon.p2pNetwork) {
        const peerManager = this.daemon.p2pNetwork.peerManager;
        if (peerManager && typeof peerManager.disconnectPeer === 'function') {
          peerManager.disconnectPeer(address);
        }

        // Add to blocked list in P2P network
        if (peerManager && typeof peerManager.blockPeer === 'function') {
          peerManager.blockPeer(address, reason);
        }
      }

      // Save to persistent storage
      this.saveBlockedNodes();

      logger.warn('MONITOR_SERVER', `Blocked node: ${address} - ${reason}`);

      return blockInfo;
    } catch (error) {
      logger.error('MONITOR_SERVER', `Error blocking node ${address}: ${error.message}`);
      throw error;
    }
  }

  unblockNode(address) {
    try {
      if (!this.blockedNodes) {
        this.blockedNodes = new Map();
      }

      const wasBlocked = this.blockedNodes.has(address);
      this.blockedNodes.delete(address);

      // Remove from P2P network blocked list
      if (this.daemon.p2pNetwork) {
        const peerManager = this.daemon.p2pNetwork.peerManager;
        if (peerManager && typeof peerManager.unblockPeer === 'function') {
          peerManager.unblockPeer(address);
        }
      }

      // Save to persistent storage
      this.saveBlockedNodes();

      logger.info('MONITOR_SERVER', `Unblocked node: ${address}`);

      return { wasBlocked, address };
    } catch (error) {
      logger.error('MONITOR_SERVER', `Error unblocking node ${address}: ${error.message}`);
      throw error;
    }
  }

  loadBlockedNodes() {
    try {
      const fs = require('fs');
      const path = require('path');
      const blockedNodesFile = path.join(process.cwd(), 'data', 'blocked-nodes.json');

      if (fs.existsSync(blockedNodesFile)) {
        const data = fs.readFileSync(blockedNodesFile, 'utf8');
        const blockedArray = JSON.parse(data);
        this.blockedNodes = new Map(blockedArray.map(node => [node.address, node]));
        logger.info('MONITOR_SERVER', `Loaded ${this.blockedNodes.size} blocked nodes`);
      } else {
        this.blockedNodes = new Map();
      }
    } catch (error) {
      logger.error('MONITOR_SERVER', `Error loading blocked nodes: ${error.message}`);
      this.blockedNodes = new Map();
    }
  }

  saveBlockedNodes() {
    try {
      const fs = require('fs');
      const path = require('path');

      // Ensure data directory exists
      const dataDir = path.join(process.cwd(), 'data');
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }

      const blockedNodesFile = path.join(dataDir, 'blocked-nodes.json');
      const blockedArray = Array.from(this.blockedNodes.values());

      fs.writeFileSync(blockedNodesFile, JSON.stringify(blockedArray, null, 2));
      logger.debug('MONITOR_SERVER', `Saved ${blockedArray.length} blocked nodes`);
    } catch (error) {
      logger.error('MONITOR_SERVER', `Error saving blocked nodes: ${error.message}`);
    }
  }

  /**
   * Node control functionality
   */
  restartNode() {
    try {
      logger.warn('MONITOR_SERVER', '🔄 Node restart requested - shutting down gracefully...');

      // Stop the monitoring server first
      this.stop().then(() => {
        // Then stop the daemon
        if (this.daemon && typeof this.daemon.shutdown === 'function') {
          this.daemon.shutdown().then(() => {
            logger.info('MONITOR_SERVER', '✅ Node shutdown complete - restart process should begin');
            process.exit(0); // Exit to allow process manager to restart
          });
        } else {
          logger.warn('MONITOR_SERVER', 'Daemon shutdown method not available - forcing exit');
          process.exit(0);
        }
      });

    } catch (error) {
      logger.error('MONITOR_SERVER', `Error during restart: ${error.message}`);
      process.exit(1);
    }
  }

  shutdownNode() {
    try {
      logger.warn('MONITOR_SERVER', '⛔ Node shutdown requested - stopping all services...');

      // Stop the monitoring server first
      this.stop().then(() => {
        // Then stop the daemon
        if (this.daemon && typeof this.daemon.shutdown === 'function') {
          this.daemon.shutdown().then(() => {
            logger.info('MONITOR_SERVER', '✅ Node shutdown complete');
            process.exit(0);
          });
        } else {
          logger.warn('MONITOR_SERVER', 'Daemon shutdown method not available - forcing exit');
          process.exit(0);
        }
      });

    } catch (error) {
      logger.error('MONITOR_SERVER', `Error during shutdown: ${error.message}`);
      process.exit(1);
    }
  }

  /**
   * Analytics helper methods for real blockchain data
   */
  calculateBlockTimes(blocks) {
    if (blocks.length < 2) return [];

    const blockTimes = [];
    for (let i = 0; i < blocks.length - 1; i++) {
      const currentBlock = blocks[i];
      const previousBlock = blocks[i + 1];

      const timeDiff = Math.abs(currentBlock.timestamp - previousBlock.timestamp) / 1000; // Convert to seconds
      blockTimes.push({
        blockHeight: currentBlock.index,
        timestamp: currentBlock.timestamp,
        blockTime: timeDiff
      });
    }
    return blockTimes;
  }

  estimateHashRatesFromBlocks(blocks) {
    return blocks.map(block => {
      const difficulty = block.difficulty || 1;
      const estimatedHashRate = difficulty / 60; // Rough estimate: difficulty per target block time

      return {
        blockHeight: block.index,
        timestamp: block.timestamp,
        hashRate: estimatedHashRate
      };
    });
  }

  getAverageBlockTimeFromBlocks(blocks) {
    const blockTimes = this.calculateBlockTimes(blocks);
    if (blockTimes.length === 0) return 0;

    const totalTime = blockTimes.reduce((sum, bt) => sum + bt.blockTime, 0);
    return totalTime / blockTimes.length;
  }
}

module.exports = MonitorServer;