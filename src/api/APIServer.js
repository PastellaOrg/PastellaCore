const cors = require('cors');
const express = require('express');

const Block = require('../models/Block.js');
const { Transaction, TransactionInput, TransactionOutput } = require('../models/Transaction.js');
const ContractTransaction = require('../contracts/ContractTransaction.js');
const { toAtomicUnits, fromAtomicUnits, formatAtomicUnits } = require('../utils/atomicUnits.js');
const AuthMiddleware = require('../utils/auth.js');
const { TRANSACTION_TAGS } = require('../utils/constants.js');
const logger = require('../utils/logger.js');
const RateLimiter = require('../utils/rateLimiter.js');
const InputValidator = require('../utils/validation.js');

/**
 *
 */
class APIServer {
  /**
   *
   * @param blockchain
   * @param wallet
   * @param miner
   * @param p2pNetwork
   * @param port
   * @param config
   * @param customApiKey
   */
  constructor(blockchain, wallet, miner, p2pNetwork, port = 3002, config = {}, customApiKey = null) {
    this.blockchain = blockchain;
    this.wallet = wallet;
    this.miner = miner;
    this.p2pNetwork = p2pNetwork;
    this.port = port;
    this.config = config;
    this.app = express();
    this.server = null;
    this.isRunning = false;

    // Initialize rate limiter for DoS protection
    this.rateLimiter = new RateLimiter();

    // CRITICAL: Use custom API key if provided, otherwise generate secure API key
    this.apiKey = customApiKey || this.generateSecureApiKey();
    this.auth = new AuthMiddleware(this.apiKey);

    // Display API key to user on startup
    if (customApiKey) {
      logger.info('API_SERVER', `🔑 Using custom API key: ${this.apiKey}`);
    } else {
      logger.info('API_SERVER', `🔑 Generated secure API key: ${this.apiKey}`);
      logger.info('API_SERVER', '⚠️  IMPORTANT: Save this API key - it will be required for protected endpoints');
    }

    // Block submission synchronization
    this.blockSubmissionLock = false;
    this.submissionQueue = [];

    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Setup middleware
   */
  setupMiddleware() {
    this.app.use(cors());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Add rate limiting middleware for DoS protection
    this.app.use((req, res, next) => this.rateLimitMiddleware(req, res, next));

    // Add authentication middleware for sensitive endpoints
    // These endpoints require a valid API key to prevent unauthorized access
    this.app.use('/api/blocks/submit', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/blocks/validate', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/blocks/validate-merkle', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/network/connect', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/network/message-validation/reset', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/network/partition-reset', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/blockchain/reset', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/rate-limits*', this.auth.validateApiKey.bind(this.auth));

    this.app.use('/api/blockchain/validate-checkpoints', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/blockchain/checkpoints/clear', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/blockchain/checkpoints/update', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/blockchain/checkpoints/add', this.auth.validateApiKey.bind(this.auth));

    this.app.use('/api/memory-pool/status', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/spam-protection/status', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/spam-protection/reset', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/transactions/batch', this.auth.validateApiKey.bind(this.auth));

    this.app.use('/api/cpu-protection/enable', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/cpu-protection/disable', this.auth.validateApiKey.bind(this.auth));
    this.app.use('/api/cpu-protection/settings', this.auth.validateApiKey.bind(this.auth));

    this.app.use('/api/batch-processing/config', this.auth.validateApiKey.bind(this.auth));

    // Add error handling middleware
    this.app.use((error, req, res, _next) => {
      console.error(`❌ API Error: ${error.message}`);
      res.status(500).json({ error: error.message });
    });
  }

  /**
   * Rate limiting middleware for DoS protection
   * @param req
   * @param res
   * @param next
   */
  rateLimitMiddleware(req, res, next) {
    const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
    const endpoint = req.path;

    // Debug logging for rate limiting
    logger.debug('RATE_LIMITER', `Processing request: ${req.method} ${endpoint} from ${clientIP}`);

    // Check if request is allowed
    if (!this.rateLimiter.isAllowed(clientIP, endpoint)) {
      const status = this.rateLimiter.getStatus(clientIP, endpoint);

      logger.warn('API', `Rate limited request from ${clientIP} for ${endpoint}`);

      return res.status(429).json({
        error: 'Too Many Requests',
        message: 'Rate limit exceeded. Please try again later.',
        rateLimit: {
          limit: status.limit,
          remaining: status.remaining,
          resetTime: new Date(status.resetTime).toISOString(),
          timeUntilReset: status.timeUntilReset,
        },
      });
    }

    // Add rate limit headers to response
    const status = this.rateLimiter.getStatus(clientIP, endpoint);
    res.set({
      'X-RateLimit-Limit': status.limit,
      'X-RateLimit-Remaining': status.remaining,
      'X-RateLimit-Reset': new Date(status.resetTime).toISOString(),
    });

    logger.debug('RATE_LIMITER', `Request allowed: ${req.method} ${endpoint} from ${clientIP}`);
    next();
  }

  /**
   * Setup API routes
   */
  setupRoutes() {
    // Root route for testing
    this.app.get('/', (req, res) => {
      res.json({ message: 'Pastella API Server is running!', version: '1.0.0' });
    });

    // Blockchain routes
    this.app.get('/api/blockchain/status', this.getBlockchainStatus.bind(this));
    this.app.get('/api/blockchain/supply', this.getTotalSupply.bind(this));
    this.app.get('/api/blockchain/blocks/:identifier', this.getBlock.bind(this));
    this.app.get('/api/blockchain/blocks-range/:start/:count', this.getBlocksRange.bind(this)); // New batch endpoint
    this.app.post('/api/blocks/submit', this.submitBlock.bind(this)); // Behind Key
    this.app.post('/api/blocks/validate-merkle', this.validateMerkleRoot.bind(this)); // Behind Key
    this.app.get('/api/blockchain/security', this.getSecurityReport.bind(this));
    this.app.get('/api/blockchain/mempool', this.getMempoolStatus.bind(this));
    this.app.get('/api/blockchain/replay-protection', this.getReplayProtectionAnalysis.bind(this));
    this.app.post('/api/blockchain/test-replay-protection', this.testReplayProtection.bind(this));
    this.app.get('/api/blockchain/consensus', this.getConsensusStatus.bind(this));
    this.app.get('/api/blockchain/security-analysis', this.getSecurityAnalysis.bind(this));
    this.app.post('/api/blockchain/validator-signature', this.addValidatorSignature.bind(this));
    this.app.post('/api/blockchain/reset', this.resetBlockchain.bind(this)); // Behind Key
    this.app.get('/api/blockchain/blocks', this.getBlocks.bind(this));
    this.app.get('/api/blockchain/download', this.downloadBlockchain.bind(this)); // Download blockchain.json with rate limiting
    this.app.get('/api/blockchain/latest', this.getLatestBlock.bind(this));
    this.app.get('/api/blockchain/transactions', this.getPendingTransactions.bind(this));
    this.app.get('/api/blockchain/transactions-range/:page/:limit', this.getTransactionsRange.bind(this));
    this.app.get('/api/blockchain/transactions/:txId', this.getTransaction.bind(this));
    this.app.get('/api/blockchain/transactions/payment-id/:paymentId', this.getTransactionByPaymentId.bind(this));
    this.app.post('/api/blockchain/transactions', this.submitTransaction.bind(this));
    // New mining template route
    this.app.get('/api/mining/template', this.getMiningTemplate.bind(this));
    this.app.get('/api/blockchain/memory-protection', this.getMemoryProtectionStatus.bind(this));
    this.app.get('/api/blockchain/cpu-protection', this.getCPUProtectionStatus.bind(this));
    this.app.get('/api/network/reputation-status', this.getReputationStatus.bind(this));

    // Block submission routes
    this.app.get('/api/blocks/pending', this.getPendingBlocks.bind(this));
    this.app.post('/api/blocks/validate', this.validateBlock.bind(this)); // Behind Key

    // Network routes
    this.app.get('/api/network/status', this.getNetworkStatus.bind(this));
    this.app.get('/api/network/peers', this.getPeers.bind(this));
    this.app.post('/api/network/connect', this.connectToPeer.bind(this)); // Behind Key

    // Reputation routes
    this.app.get('/api/network/reputation', this.getReputationStats.bind(this));
    this.app.get('/api/network/reputation/:peerAddress', this.getPeerReputation.bind(this));

    // Message validation endpoints
    this.app.get('/api/network/message-validation', this.getMessageValidationStats.bind(this));
    this.app.post('/api/network/message-validation/reset', this.resetMessageValidationStats.bind(this)); // Behind Key

    // Network diagnostics endpoint
    this.app.get('/api/network/diagnostics', this.getNetworkDiagnostics.bind(this));

    // Enhanced peer discovery endpoints
    this.app.get('/api/network/peer-discovery/stats', this.getPeerDiscoveryStats.bind(this));
    this.app.post('/api/network/peer-discovery/add-peer', this.addKnownPeer.bind(this)); // Behind Key
    this.app.post('/api/network/peer-discovery/ban-peer', this.banPeer.bind(this)); // Behind Key
    this.app.get('/api/network/peer-discovery/known-peers', this.getKnownPeers.bind(this));

    // Partition handling endpoints
    this.app.get('/api/network/partition-stats', this.getPartitionStats.bind(this));
    this.app.post('/api/network/partition-reset', this.resetPartitionStats.bind(this)); // Behind Key

    // Daemon routes
    this.app.get('/api/daemon/status', this.getDaemonStatus.bind(this));

    // Rate limiting management routes (protected by API key)
    this.app.get('/api/rate-limits/stats', this.getRateLimitStats.bind(this)); // Behind Key
    this.app.post('/api/rate-limits/reset/:ip', this.resetRateLimitsForIP.bind(this)); // Behind Key
    this.app.post('/api/rate-limits/reset-all', this.resetAllRateLimits.bind(this)); // Behind Key

    // NEW FEATURES: Memory pool and spam protection routes (protected by API key)
    this.app.get('/api/memory-pool/status', this.getMemoryPoolStatus.bind(this)); // Behind Key
    this.app.get('/api/spam-protection/status', this.getSpamProtectionStatus.bind(this)); // Behind Key
    this.app.post('/api/spam-protection/reset', this.resetSpamProtection.bind(this)); // Behind Key
    this.app.post('/api/transactions/batch', this.addTransactionBatch.bind(this)); // Behind Key

    // CPU Protection management routes (protected by API key)
    this.app.post('/api/cpu-protection/enable', this.setCpuProtection.bind(this)); // Behind Key
    this.app.post('/api/cpu-protection/disable', this.setCpuProtection.bind(this)); // Behind Key
    this.app.post('/api/cpu-protection/settings', this.updateCpuProtection.bind(this)); // Behind Key

    // Batch Processing configuration route (protected by API key)
    this.app.get('/api/batch-processing/config', this.getBatchProcessingConfig.bind(this)); // Behind Key

    // SMART CONTRACT ENDPOINTS
    // Contract fee information (public)
    this.app.get('/api/contracts/fees', this.getContractFees.bind(this)); // Public

    // Contract management routes (public read, protected write)
    this.app.get('/api/contracts', this.getAllContracts.bind(this)); // Public
    this.app.get('/api/contracts/:address', this.getContract.bind(this)); // Public
    this.app.post('/api/contracts/deploy', this.auth.validateApiKey.bind(this.auth), this.deployContract.bind(this)); // Behind Key

    // Token contract routes (public read, protected write)
    this.app.get('/api/contracts/:address/tokens', this.getContractTokens.bind(this)); // Public
    this.app.get('/api/contracts/:address/tokens/:tokenId', this.getToken.bind(this)); // Public
    this.app.get('/api/contracts/:address/balance/:tokenId/:walletAddress', this.getTokenBalance.bind(this)); // Public

    // Token operations (protected by API key)
    this.app.post('/api/contracts/:address/createToken', this.auth.validateApiKey.bind(this.auth), this.createToken.bind(this)); // Behind Key
    this.app.post('/api/contracts/:address/mint', this.auth.validateApiKey.bind(this.auth), this.mintTokens.bind(this)); // Behind Key
    this.app.post('/api/contracts/:address/burn', this.auth.validateApiKey.bind(this.auth), this.burnTokens.bind(this)); // Behind Key
    this.app.post('/api/contracts/:address/transfer', this.auth.validateApiKey.bind(this.auth), this.transferTokens.bind(this)); // Behind Key

    // Permission management (protected by API key)
    this.app.post('/api/contracts/:address/grantPermission', this.auth.validateApiKey.bind(this.auth), this.grantPermission.bind(this)); // Behind Key
    this.app.post('/api/contracts/:address/revokePermission', this.auth.validateApiKey.bind(this.auth), this.revokePermission.bind(this)); // Behind Key

    // Checkpoint endpoints
    this.app.get('/api/blockchain/checkpoints', this.getCheckpoints.bind(this));
    this.app.post('/api/blockchain/checkpoints/add', this.addCheckpoint.bind(this)); // Behind Key
    this.app.post('/api/blockchain/checkpoints/update', this.updateCheckpoints.bind(this)); // Behind Key
    this.app.post('/api/blockchain/checkpoints/clear', this.clearCheckpoints.bind(this)); // Behind Key
    this.app.post('/api/blockchain/validate-checkpoints', this.validateCheckpoints.bind(this)); // Behind Key

    // Utility routes (always available)
    this.app.get('/api/health', this.getHealth.bind(this));
    this.app.get('/api/info', this.getInfo.bind(this));

    // Mempool synchronization routes (protected by API key)
    this.app.post('/api/mempool/sync', this.syncMempoolWithPeers.bind(this)); // Behind Key
    this.app.get('/api/mempool/sync/status', this.getMempoolSyncStatus.bind(this)); // Behind Key

    // Wallet routes (public - no API key required)
    this.app.get('/api/wallet/balance/:address', this.getWalletBalance.bind(this));
    this.app.get('/api/wallet/transactions/:address', this.getWalletTransactions.bind(this));
    this.app.get('/api/wallet/utxos/:address', this.getWalletUTXOs.bind(this));
    this.app.post('/api/transactions/submit', this.submitTransaction.bind(this));
    
    // UTXO status endpoints
    this.app.get('/api/utxos/check/:txId/:outputIndex', this.checkUTXOStatus.bind(this));
    this.app.get('/api/utxos/address/:address', this.getAddressUTXOs.bind(this));

    // Rich List endpoints
    this.app.get('/api/blockchain/rich-list', this.getRichList.bind(this));
    this.app.get('/api/blockchain/rich-list/:limit', this.getRichList.bind(this));

    // Debug endpoints (protected by API key)
    this.app.use('/api/debug*', this.auth.validateApiKey.bind(this.auth));
    this.app.post('/api/debug/rebuild-utxos', this.rebuildUTXOs.bind(this));
  }

  /**
   * Set API key for authentication
   * @param {string} apiKey - The API key to use for authentication
   */
  setApiKey(apiKey) {
    if (apiKey && typeof apiKey === 'string' && apiKey.length > 0) {
      this.auth.updateApiKey(apiKey);
    } else {
      // Don't clear the existing API key if called with invalid value
      if (apiKey === null || apiKey === undefined) {
        return;
      }
      this.auth.updateApiKey(null);
    }
  }

  /**
   * Start API server
   */
  start() {
    if (this.isRunning) {
      console.log('API server is already running');
      return false;
    }

    // Get host binding from config (defaults to 127.0.0.1 for security)
    const host = this.config.api?.host || '127.0.0.1';

    // Log the binding information at the beginning using consistent logger style
    logger.info('API', `API Server: http://${host}:${this.port}`);

    // Security warning for external binding
    if (host !== '127.0.0.1' && host !== 'localhost') {
      logger.warn('API', `API server bound to external interface: ${host}`);
      logger.warn('API', `Ensure your network is secure and API key authentication is enabled!`);
    } else {
      logger.info('API', `API server bound to localhost-only for security`);
    }

    this.server = this.app.listen(this.port, host, () => {
      this.isRunning = true;
    });

    // Add error handling
    this.server.on('error', error => {
      console.error(`❌ API Server error: ${error.message}`);
      if (error.code === 'EADDRINUSE') {
        console.error(`Port ${this.port} is already in use`);
      } else if (error.code === 'EACCES') {
        console.error(`Permission denied binding to ${host}:${this.port}`);
        console.error(`Try using a different port or run with elevated privileges`);
      } else if (error.code === 'EADDRNOTAVAIL') {
        console.error(`Address ${host} is not available on this system`);
        console.error(`Check your network configuration and try again`);
      }
    });

    return true;
  }

  /**
   * Stop API server
   */
  stop() {
    if (!this.isRunning) {
      console.log('API server is not running');
      return false;
    }

    if (this.server) {
      this.server.close();
      this.server = null;
    }

    this.isRunning = false;
    console.log('API server stopped');
    return true;
  }

  // Blockchain endpoints
  /**
   *
   * @param req
   * @param res
   */
  getBlockchainStatus(req, res) {
    try {
      const status = this.blockchain.getStatus();
      // Ensure compatibility with wallet sync by adding height property
      res.json({
        ...status,
        height: status.chainLength,
        networkId: this.config.networkId || 'unknown',
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getSecurityReport(req, res) {
    try {
      const securityReport = this.blockchain.getSecurityReport();
      res.json(securityReport);
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getReplayProtectionStats(req, res) {
    try {
      const replayProtectionStats = this.blockchain.getReplayProtectionStats();
      res.json(replayProtectionStats);
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getMempoolStatus(req, res) {
    try {
      const mempoolStatus = {
        pendingTransactions: this.blockchain.memoryPool.getPendingTransactionCount(),
        memoryUsage: this.blockchain.memoryPool.estimateMemoryUsage(),
        poolSize: this.blockchain.memoryPool.getPendingTransactions().length,
        recentTransactions: this.blockchain.memoryPool
          .getPendingTransactions()
          .slice(-10)
          .map(tx => ({
            id: tx.id,
            fee: tx.fee,
            timestamp: tx.timestamp,
            isExpired: tx.isExpired ? tx.isExpired() : false,
          })),
      };
      res.json(mempoolStatus);
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getReplayProtectionAnalysis(req, res) {
    try {
      const analysis = this.blockchain.getReplayProtectionAnalysis();
      res.json(analysis);
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  testReplayProtection(req, res) {
    try {
      // Create a test transaction with atomic units
      const testInputs = [new TransactionInput('test-tx-hash', 0, 'test-signature', 'test-public-key')];

      const testOutputs = [new TransactionOutput('test-address', 10)];

      const testTransaction = new Transaction(
        testInputs,
        testOutputs,
        100000,
        TRANSACTION_TAGS.TRANSACTION,
        Date.now()
      );
      testTransaction.calculateId();

      // Test the replay protection
      const testResults = this.blockchain.testReplayProtection(testTransaction);

      res.json({
        message: 'Replay protection test completed',
        testTransaction: {
          id: testTransaction.id,
          nonce: testTransaction.nonce,
          expiresAt: testTransaction.expiresAt,
          isExpired: testTransaction.isExpired(),
        },
        testResults,
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getConsensusStatus(req, res) {
    try {
      const consensusStatus = this.blockchain.getConsensusStatus();
      res.json(consensusStatus);
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getSecurityAnalysis(req, res) {
    try {
      const securityAnalysis = {
        timestamp: new Date().toISOString(),
        blockchain: {
          height: this.blockchain.getHeight(),
          difficulty: this.blockchain.difficulty,
          lastBlockHash: this.blockchain.getLatestBlock()?.hash || 'none',
        },
        consensus: this.blockchain.getConsensusStatus(),
        replayProtection: this.blockchain.getReplayProtectionStats(),
        threats: this._analyzeThreats(),
        recommendations: this._generateSecurityRecommendations(),
      };

      res.json(securityAnalysis);
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  addValidatorSignature(req, res) {
    try {
      const { blockHash, validatorAddress, stakeAmount } = req.body;

      // Input validation
      if (!blockHash || !validatorAddress || !stakeAmount) {
        return res.status(400).json({
          error: 'Missing required fields: blockHash, validatorAddress, stakeAmount',
        });
      }

      // Validate inputs
      const validatedHash = InputValidator.validateHash(blockHash);
      const validatedAddress = InputValidator.validateCryptocurrencyAddress(validatorAddress);
      const validatedStake = InputValidator.validateAmount(stakeAmount, { min: 0 });

      if (!validatedHash || !validatedAddress || validatedStake === null) {
        return res.status(400).json({
          error: 'Invalid input data',
        });
      }

      // Add validator signature
      this.blockchain.addValidatorSignature(validatedHash, validatedAddress, validatedStake);

      res.json({
        success: true,
        message: 'Validator signature added successfully',
        blockHash: validatedHash,
        validator: validatedAddress,
        stake: validatedStake,
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   * CRITICAL: Analyze current security threats
   */
  _analyzeThreats() {
    const threats = [];

    try {
      const consensus = this.blockchain.getConsensusStatus();

      // Check for 51% attack indicators
      if (consensus.miningPowerDistribution.length > 0) {
        const topMiner = consensus.miningPowerDistribution[0];
        if (parseFloat(topMiner.share) > 40) {
          threats.push({
            type: '51%_ATTACK_RISK',
            severity: 'HIGH',
            description: `Top miner controls ${topMiner.share}% of network hash rate`,
            recommendation: 'Implement additional consensus mechanisms and monitor closely',
          });
        }
      }

      // Check for network partition
      if (consensus.networkPartition) {
        threats.push({
          type: 'NETWORK_PARTITION',
          severity: 'MEDIUM',
          description: 'Network partition detected - consecutive late blocks',
          recommendation: 'Investigate network connectivity and peer synchronization',
        });
      }

      // Check for suspicious miners
      if (consensus.suspiciousMiners.length > 0) {
        threats.push({
          type: 'SUSPICIOUS_ACTIVITY',
          severity: 'MEDIUM',
          description: `${consensus.suspiciousMiners.length} miners flagged for suspicious activity`,
          recommendation: 'Review mining patterns and implement additional monitoring',
        });
      }

      // Check security level
      if (consensus.securityLevel < 70) {
        threats.push({
          type: 'LOW_SECURITY_LEVEL',
          severity: 'HIGH',
          description: `Overall security level is ${consensus.securityLevel}/100`,
          recommendation: 'Immediate security review and mitigation required',
        });
      }
    } catch (error) {
      threats.push({
        type: 'ANALYSIS_ERROR',
        severity: 'HIGH',
        description: `Failed to analyze threats: ${error.message}`,
        recommendation: 'Check system logs and restart security monitoring',
      });
    }

    return threats;
  }

  /**
   * CRITICAL: Generate security recommendations
   */
  _generateSecurityRecommendations() {
    const recommendations = [];

    try {
      const consensus = this.blockchain.getConsensusStatus();

      if (consensus.securityLevel < 80) {
        recommendations.push({
          priority: 'HIGH',
          action: 'Implement additional consensus validators',
          description: 'Add more proof-of-stake validators to improve network security',
        });
      }

      if (consensus.miningPowerDistribution.length > 0) {
        const topMiner = consensus.miningPowerDistribution[0];
        if (parseFloat(topMiner.share) > 30) {
          recommendations.push({
            priority: 'MEDIUM',
            action: 'Diversify mining power',
            description: 'Encourage more miners to join the network to reduce centralization',
          });
        }
      }

      if (consensus.validatorCount < 10) {
        recommendations.push({
          priority: 'MEDIUM',
          action: 'Increase validator count',
          description: 'Aim for at least 10 active validators for robust consensus',
        });
      }

      recommendations.push({
        priority: 'LOW',
        action: 'Regular security audits',
        description: 'Conduct monthly security audits and penetration testing',
      });
    } catch (error) {
      recommendations.push({
        priority: 'HIGH',
        action: 'System recovery',
        description: `System error detected: ${error.message}. Immediate attention required.`,
      });
    }

    return recommendations;
  }

  /**
   *
   * @param req
   * @param res
   */
  resetBlockchain(req, res) {
    try {
      // Clear the blockchain and create new genesis block
      this.blockchain.clearChain();

      // Create new genesis block with mandatory replay protection
      const genesisConfig = {
        premineAmount: 42000000000, // 420 PAS in atomic units
        premineAddress: 'genesis-address',
        nonce: 0,
        hash: null, // Will be calculated
        algorithm: 'velora',
      };

      this.blockchain.initializeBlockchain(genesisConfig, true);

      res.json({
        success: true,
        message: 'Blockchain reset successfully with mandatory replay protection',
        genesisBlock: this.blockchain.chain[0]?.toJSON(),
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getBlocks(req, res) {
    try {
      // Input validation for limit parameter
      const validatedLimit =
        InputValidator.validateNumber(req.query.limit, {
          min: 1,
          max: 1000,
          integer: true,
        }) || 10;

      const blocks = this.blockchain.chain.slice(-validatedLimit).map(block => {
        // Check if block has toJSON method, if not, convert to proper Block object
        if (typeof block.toJSON === 'function') {
          return block.toJSON();
        }
        // Convert plain object to Block instance and then to JSON
        const blockInstance = Block.fromJSON(block);
        return blockInstance.toJSON();
      });

      res.json({
        blocks,
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   * Download blockchain.json file with rate limiting (1 MB/s max) and forced download
   */
  downloadBlockchain(req, res) {
    try {
      const fs = require('fs');
      const path = require('path');

      // Get blockchain file path from configuration
      const blockchainPath = path.join(
        this.config?.storage?.dataDir || './data',
        this.config?.storage?.blockchainFile || 'blockchain.json'
      );

      // Check if blockchain file exists
      if (!fs.existsSync(blockchainPath)) {
        return res.status(404).json({
          error: 'Blockchain file not found',
          message: 'The blockchain.json file does not exist'
        });
      }

      // Get file stats for size
      const stats = fs.statSync(blockchainPath);
      const fileSizeInBytes = stats.size;
      const fileSizeInMB = (fileSizeInBytes / (1024 * 1024)).toFixed(2);

      // Get client IP address (handle proxies and load balancers)
      const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                      req.headers['x-real-ip'] ||
                      req.connection?.remoteAddress ||
                      req.socket?.remoteAddress ||
                      req.ip ||
                      'unknown';

      logger.info('API_SERVER', `Blockchain download requested from IP: ${clientIP} - file size: ${fileSizeInMB} MB`);

      // Set headers for forced download
      const filename = `blockchain-${Date.now()}.json`;
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', fileSizeInBytes);
      res.setHeader('Cache-Control', 'no-cache');

      // Rate limiting: 1 MB/s = 1,048,576 bytes per second
      const maxBytesPerSecond = 1048576; // 1 MB/s
      const chunkSize = 64 * 1024; // 64KB chunks
      const chunkDelayMs = (chunkSize / maxBytesPerSecond) * 1000; // Delay between chunks

      // Create read stream
      const readStream = fs.createReadStream(blockchainPath, {
        highWaterMark: chunkSize
      });

      let totalBytesSent = 0;
      let startTime = Date.now();

      // Handle stream events
      readStream.on('data', (chunk) => {
        totalBytesSent += chunk.length;

        // Pause stream to implement rate limiting
        readStream.pause();

        // Write chunk to response
        res.write(chunk);

        // Calculate progress
        const progress = ((totalBytesSent / fileSizeInBytes) * 100).toFixed(1);

        // Log progress every 10%
        if (Math.floor(progress) % 10 === 0 && progress % 10 < 1) {
          const elapsedSeconds = (Date.now() - startTime) / 1000;
          const currentSpeed = (totalBytesSent / elapsedSeconds / 1024 / 1024).toFixed(2);
          logger.debug('API_SERVER', `Download progress [${clientIP}]: ${progress}% (${currentSpeed} MB/s average)`);
        }

        // Resume after delay to maintain 1 MB/s rate
        setTimeout(() => {
          if (!res.destroyed) {
            readStream.resume();
          }
        }, chunkDelayMs);
      });

      readStream.on('end', () => {
        const elapsedSeconds = (Date.now() - startTime) / 1000;
        const averageSpeed = (totalBytesSent / elapsedSeconds / 1024 / 1024).toFixed(2);

        logger.info('API_SERVER', `Blockchain download completed: ${fileSizeInMB} MB in ${elapsedSeconds.toFixed(1)}s (${averageSpeed} MB/s average)`);
        res.end();
      });

      readStream.on('error', (error) => {
        logger.error('API_SERVER', `Blockchain download error: ${error.message}`);
        if (!res.headersSent) {
          res.status(500).json({
            error: 'Download failed',
            message: error.message
          });
        } else {
          res.end();
        }
      });

      // Handle client disconnect
      req.on('close', () => {
        if (!readStream.destroyed) {
          readStream.destroy();
          logger.info('API_SERVER', 'Blockchain download cancelled by client');
        }
      });

    } catch (error) {
      logger.error('API_SERVER', `Blockchain download setup error: ${error.message}`);
      res.status(500).json({
        error: 'Download setup failed',
        message: error.message
      });
    }
  }

  /**
   * Get total supply information
   * @param req
   * @param res
   */
  getTotalSupply(req, res) {
    try {
      const totalSupplyAtomic = this.blockchain.getTotalSupply();
      const totalSupplyFormatted = fromAtomicUnits(totalSupplyAtomic);

      res.json({
        totalSupply: totalSupplyAtomic,
        totalSupplyFormatted,
        totalSupplyDisplay: `${totalSupplyFormatted} PAS`,
        chainHeight: this.blockchain.getHeight(),
        currency: 'PAS',
        decimals: 8
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getBlock(req, res) {
    try {
      const identifier = req.params.identifier;
      let block = null;

      // Check if identifier is a hash (64 hex characters)
      if (/^[a-fA-F0-9]{64}$/.test(identifier)) {
        // It's a hash, search for the block
        block = this.blockchain.chain.find(b => b.hash === identifier);
        
        if (!block) {
          return res.status(404).json({
            error: 'Block with this hash not found',
          });
        }
      } else {
        // It's a block index, validate as number
        const validatedIndex = InputValidator.validateNumber(identifier, {
          required: true,
          min: 0,
          integer: true,
        });

        if (validatedIndex === null) {
          return res.status(400).json({
            error: 'Invalid block index',
          });
        }

        block = this.blockchain.chain[validatedIndex];

        if (!block) {
          return res.status(404).json({
            error: 'Block not found',
          });
        }
      }

      // Check if block has toJSON method, if not, convert to proper Block object
      if (typeof block.toJSON === 'function') {
        res.json(block.toJSON());
      } else {
        // Convert plain object to Block instance and then to JSON
        const blockInstance = Block.fromJSON(block);
        res.json(blockInstance.toJSON());
      }
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   * Get multiple blocks in a range for efficient sync
   * @param req
   * @param res
   */
  getBlocksRange(req, res) {
    try {
      // Input validation for start block index
      const validatedStart = InputValidator.validateNumber(req.params.start, {
        required: true,
        min: 0,
        integer: true,
      });

      if (validatedStart === null) {
        return res.status(400).json({
          error: 'Invalid start block index',
        });
      }

      // Input validation for count (limit to 100 blocks max for performance)
      const validatedCount = InputValidator.validateNumber(req.params.count, {
        required: true,
        min: 1,
        max: 100,
        integer: true,
      });

      if (validatedCount === null) {
        return res.status(400).json({
          error: 'Invalid count (must be between 1 and 100)',
        });
      }

      const blocks = [];
      const endIndex = validatedStart + validatedCount;

      // Fetch blocks in the requested range
      for (let i = validatedStart; i < endIndex && i < this.blockchain.chain.length; i++) {
        const block = this.blockchain.chain[i];
        if (block) {
          // Check if block has toJSON method, if not, convert to proper Block object
          if (typeof block.toJSON === 'function') {
            blocks.push(block.toJSON());
          } else {
            // Convert plain object to Block instance and then to JSON
            const blockInstance = Block.fromJSON(block);
            blocks.push(blockInstance.toJSON());
          }
        }
      }

      res.json({
        success: true,
        startIndex: validatedStart,
        count: blocks.length,
        requestedCount: validatedCount,
        totalBlocks: this.blockchain.chain.length,
        blocks,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getLatestBlock(req, res) {
    try {
      const latestBlock = this.blockchain.getLatestBlock();

      // Check if block has toJSON method, if not, convert to proper Block object
      if (typeof latestBlock.toJSON === 'function') {
        res.json(latestBlock.toJSON());
      } else {
        // Convert plain object to Block instance and then to JSON
        const blockInstance = Block.fromJSON(latestBlock);
        res.json(blockInstance.toJSON());
      }
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   * Return a block template for miners
   * @param req
   * @param res
   */
  getMiningTemplate(req, res) {
    try {
      const address = req.query.address || this.config?.wallet?.defaultAddress || 'miner-address';
      const latest = this.blockchain.getLatestBlock();
      const nextIndex = (latest?.index || 0) + 1;
      // Use NEXT difficulty from LWMA-3 preview so miners target the enforced value
      // const difficulty = this.blockchain.computeNextDifficulty();
      const { difficulty } = this.blockchain;
      const previousHash = latest ? latest.hash : '0';

      // Select mempool transactions by age (oldest first) as per user preference
      const mempoolTxs = this.blockchain
        .getPendingTransactions()
        .slice()
        .sort((a, b) => a.timestamp - b.timestamp)
        .slice(0, this.config?.blockchain?.maxTxPerBlock || 1000);

      // Calculate total fees from selected transactions
      const totalFees = mempoolTxs.reduce((sum, tx) => sum + (tx.fee || 0), 0);
      
      // Build coinbase for the provided address (mining reward + transaction fees)
      const { Transaction } = require('../models/Transaction');
      const baseReward = this.blockchain.getCurrentMiningReward();
      const totalReward = baseReward + totalFees;
      const timestamp = Date.now();
      const coinbase = Transaction.createCoinbase(address, totalReward, timestamp);

      const transactions = [coinbase, ...mempoolTxs];

      // Compute merkle root using Block helper
      const Block = require('../models/Block');
      const tempBlock = new Block(nextIndex, timestamp, transactions, previousHash, 0, difficulty, this.config);
      tempBlock.calculateMerkleRoot();

      const nextDifficulty = difficulty;
      const currentDifficulty = this.blockchain.difficulty;
      const height = this.blockchain.chain.length;
      const latestHash = latest ? latest.hash : '0';

      res.json({
        index: nextIndex,
        difficulty: nextDifficulty,
        previousHash,
        timestamp,
        merkleRoot: tempBlock.merkleRoot,
        transactions: transactions.map(tx => tx.toJSON()),
        coinbase: coinbase.toJSON(),
        // Diagnostics to verify difficulty behavior
        diagnostics: {
          height,
          currentDifficulty,
          nextDifficulty,
          latestHash,
        },
      });
    } catch (error) {
      logger.error('API', `Error building mining template: ${error.message}`);
      res.status(500).json({ error: 'Failed to build mining template', details: error.message });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getPendingTransactions(req, res) {
    try {
      const transactions = this.blockchain.memoryPool.getPendingTransactions().map(tx => tx.toJSON());
      res.json({
        transactions,
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getTransaction(req, res) {
    try {
      // Input validation for transaction ID
      const validatedTxId = InputValidator.validateString(req.params.txId, {
        required: true,
        minLength: 1,
        maxLength: 100,
      });

      if (!validatedTxId) {
        return res.status(400).json({
          error: 'Invalid transaction ID',
        });
      }

      // Search in pending transactions
      let transaction = this.blockchain.memoryPool.getPendingTransactions().find(tx => tx.id === validatedTxId);
      let blockInfo = null;

      // Search in blockchain
      if (!transaction) {
        const block = this.blockchain.chain
          .find(block => block.transactions.find(tx => tx.id === validatedTxId));
        
        if (block) {
          transaction = block.transactions.find(tx => tx.id === validatedTxId);
          if (transaction) {
            blockInfo = {
              height: block.index,
              hash: block.hash,
              timestamp: block.timestamp,
              confirmations: this.blockchain.chain.length - 1 - block.index
            };
          }
        }
      }

      if (!transaction) {
        return res.status(404).json({
          error: 'Transaction not found',
        });
      }

      // Include block information in the response if available
      const response = transaction.toJSON();
      if (blockInfo) {
        response.blockHeight = blockInfo.height;
        response.blockHash = blockInfo.hash;
        response.blockTimestamp = blockInfo.timestamp;
        response.confirmations = blockInfo.confirmations;
      }

      res.json(response);
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   * Get transaction by payment ID
   * @param req
   * @param res
   */
  getTransactionByPaymentId(req, res) {
    try {
      // Input validation for payment ID
      const validatedPaymentId = InputValidator.validatePaymentId(req.params.paymentId);

      if (!validatedPaymentId) {
        return res.status(400).json({
          error: 'Invalid payment ID: must be exactly 64 hex characters',
        });
      }

      // Search in pending transactions
      let transaction = this.blockchain.memoryPool
        .getPendingTransactions()
        .find(tx => tx.paymentId === validatedPaymentId);
      let blockInfo = null;

      // Search in blockchain
      if (!transaction) {
        const block = this.blockchain.chain
          .find(block => block.transactions.find(tx => tx.paymentId === validatedPaymentId));
        
        if (block) {
          transaction = block.transactions.find(tx => tx.paymentId === validatedPaymentId);
          if (transaction) {
            blockInfo = {
              height: block.index,
              hash: block.hash,
              timestamp: block.timestamp,
              confirmations: this.blockchain.chain.length - 1 - block.index
            };
          }
        }
      }

      if (!transaction) {
        return res.status(404).json({
          error: 'Transaction with this payment ID not found',
        });
      }

      // Include block information in the response if available
      const response = transaction.toJSON();
      if (blockInfo) {
        response.blockHeight = blockInfo.height;
        response.blockHash = blockInfo.hash;
        response.blockTimestamp = blockInfo.timestamp;
        response.confirmations = blockInfo.confirmations;
      }

      res.json(response);
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   * Get paginated range of transactions from blockchain
   * @param req
   * @param res
   */
  getTransactionsRange(req, res) {
    try {
      // Input validation for page
      const validatedPage = InputValidator.validateNumber(req.params.page, {
        required: true,
        min: 0,
        integer: true,
      });

      if (validatedPage === null) {
        return res.status(400).json({
          error: 'Invalid page number',
        });
      }

      // Input validation for limit (max 100 transactions for performance)
      const validatedLimit = InputValidator.validateNumber(req.params.limit, {
        required: true,
        min: 1,
        max: 100,
        integer: true,
      });

      if (validatedLimit === null) {
        return res.status(400).json({
          error: 'Invalid limit (must be between 1 and 100)',
        });
      }

      // Collect all transactions from all blocks (newest first)
      const allTransactions = [];
      
      // Iterate through blocks in reverse order (newest first)
      for (let i = this.blockchain.chain.length - 1; i >= 0; i--) {
        const block = this.blockchain.chain[i];
        if (block && block.transactions) {
          // Add block info to each transaction
          block.transactions.forEach(tx => {
            const transactionWithBlock = tx.toJSON();
            transactionWithBlock.blockHeight = block.index;
            transactionWithBlock.blockHash = block.hash;
            transactionWithBlock.blockTimestamp = block.timestamp;
            transactionWithBlock.confirmations = this.blockchain.chain.length - 1 - block.index;

            // Calculate net amounts for all addresses involved in this transaction
            const addressNetAmounts = {};

            // Collect all unique addresses from inputs and outputs
            const involvedAddresses = new Set();

            // Add output addresses
            tx.outputs.forEach(output => {
              if (output.address) {
                involvedAddresses.add(output.address);
              }
            });

            // Add input addresses (derived from public keys)
            tx.inputs.forEach(input => {
              try {
                if (input.publicKey) {
                  const { CryptoUtils } = require('../utils/crypto');
                  const inputAddress = CryptoUtils.publicKeyToAddress(input.publicKey);
                  involvedAddresses.add(inputAddress);
                }
              } catch (error) {
                // Skip if unable to derive address
              }
            });

            // Calculate net amount for each involved address
            involvedAddresses.forEach(address => {
              addressNetAmounts[address] = this.calculateNetAmountForAddress(tx, address);
            });

            // Calculate transaction value (total outputs to external addresses)
            // For coinbase transactions, use total outputs
            let transactionValue = 0;
            if (tx.isCoinbase) {
              transactionValue = tx.outputs.reduce((sum, output) => sum + output.amount, 0);
            } else {
              // For regular transactions, find the largest output (usually the main transfer)
              // or sum outputs to addresses different from the sender
              const senderAddresses = new Set();

              // Collect sender addresses from inputs
              tx.inputs.forEach(input => {
                try {
                  if (input.publicKey) {
                    const { CryptoUtils } = require('../utils/crypto');
                    const inputAddress = CryptoUtils.publicKeyToAddress(input.publicKey);
                    senderAddresses.add(inputAddress);
                  }
                } catch (error) {
                  // Skip if unable to derive address
                }
              });

              // Sum outputs that are NOT change (sent to different addresses)
              transactionValue = tx.outputs
                .filter(output => !senderAddresses.has(output.address))
                .reduce((sum, output) => sum + output.amount, 0);

              // If no external outputs found, use the largest output as transaction value
              if (transactionValue === 0 && tx.outputs.length > 0) {
                transactionValue = Math.max(...tx.outputs.map(output => output.amount));
              }
            }

            transactionWithBlock.netAmounts = addressNetAmounts;
            transactionWithBlock.netAmount = transactionValue;
            allTransactions.push(transactionWithBlock);
          });
        }
      }

      // Calculate pagination
      const startIndex = validatedPage * validatedLimit;
      const endIndex = startIndex + validatedLimit;
      const paginatedTransactions = allTransactions.slice(startIndex, endIndex);

      // Response with pagination info
      res.json({
        success: true,
        page: validatedPage,
        limit: validatedLimit,
        total: allTransactions.length,
        totalPages: Math.ceil(allTransactions.length / validatedLimit),
        transactions: paginatedTransactions
      });

    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  submitTransaction(req, res) {
    try {
      const { transaction } = req.body;

      if (!transaction) {
        return res.status(400).json({
          error: 'Transaction data is required',
        });
      }

      // DEBUG: Log the FULL RAW JSON transaction data
      logger.debug('API', `=== FULL RAW TRANSACTION SUBMISSION DATA ===`);
      logger.debug('API', `RAW REQUEST BODY: ${JSON.stringify(req.body)}`);
      logger.debug('API', `FULL TRANSACTION JSON: ${JSON.stringify(transaction)}`);
      logger.debug('API', `=== END RAW TRANSACTION DATA ===`);

      // Convert plain object to Transaction instance
      const newTransaction = Transaction.fromJSON(transaction);

      // SECURITY: Verify transaction ID integrity (prevent ID manipulation attacks)
      const submittedId = newTransaction.id;
      const calculatedId = newTransaction.calculateId();

      logger.debug('API', `Transaction ID integrity check:`);
      logger.debug('API', `  Submitted ID: ${submittedId}`);
      logger.debug('API', `  Calculated ID: ${calculatedId}`);
      logger.debug('API', `  ID Match: ${submittedId === calculatedId ? '✅ VALID' : '❌ TAMPERED'}`);

      if (submittedId !== calculatedId) {
        logger.error('API', `🚨 TRANSACTION ID TAMPERING DETECTED!`);
        logger.error('API', `  Submitted ID: ${submittedId}`);
        logger.error('API', `  Calculated ID: ${calculatedId}`);
        logger.error('API', `  Transaction data may have been modified`);

        return res.status(400).json({
          error: 'Transaction ID tampering detected',
          details: 'The submitted transaction ID does not match the calculated ID',
          submittedId,
          calculatedId,
          securityViolation: 'TRANSACTION_ID_MANIPULATION_ATTEMPT'
        });
      }

      // Validate transaction
      if (!newTransaction.isValid()) {
        return res.status(400).json({
          error: 'Invalid transaction',
          details: 'Transaction validation failed',
        });
      }

      // CRITICAL: Check for double-spend BEFORE adding to memory pool
      if (!newTransaction.isCoinbase) {
        logger.debug('API', `Pre-validating UTXOs for transaction ${newTransaction.id}...`);
        const utxoValidation = this.blockchain.transactionManager.atomicValidateAndReserveUTXOs(newTransaction);

        if (!utxoValidation) {
          logger.warn('API', `Transaction ${newTransaction.id} REJECTED: Double-spend detected - UTXO already in use`);
          return res.status(400).json({
            error: 'Double-spend detected',
            details: 'One or more UTXOs are already being used by another transaction',
            transactionId: newTransaction.id,
          });
        }

        // Release the reserved UTXOs since we'll reserve them again in addPendingTransaction
        this.blockchain.transactionManager.releaseReservedUTXOs(newTransaction);
      }

      // Add to memory pool (this includes double-spend validation)
      logger.debug('API', `Attempting to add transaction ${newTransaction.id} to memory pool...`);
      const addedToPool = this.blockchain.addPendingTransaction(newTransaction);
      logger.debug('API', `Transaction ${newTransaction.id} memory pool result: ${addedToPool ? 'ACCEPTED' : 'REJECTED'}`);

      if (addedToPool) {
        logger.info('API', `New transaction submitted: ${newTransaction.id}`);

        // Only broadcast if successfully added to memory pool
        try {
          if (this.p2pNetwork) {
            this.p2pNetwork.broadcastNewTransaction(newTransaction);
            logger.debug('API', `Transaction broadcasted to P2P network`);
          }
        } catch (broadcastError) {
          logger.warn('API', `Failed to broadcast transaction: ${broadcastError.message}`);
        }

        res.json({
          success: true,
          transactionId: newTransaction.id,
          message: 'Transaction submitted successfully',
          timestamp: new Date().toISOString(),
        });
      } else {
        // Transaction was rejected (double-spend, invalid, etc.)
        logger.warn('API', `Transaction ${newTransaction.id} rejected by memory pool`);
        res.status(400).json({
          error: 'Transaction rejected',
          details: 'Transaction validation failed - may be double-spend, replay attack, or invalid',
          transactionId: newTransaction.id,
        });
      }
    } catch (error) {
      logger.error('API', `Error submitting transaction: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  // Network endpoints
  /**
   *
   * @param req
   * @param res
   */
  getNetworkStatus(req, res) {
    try {
      const status = this.p2pNetwork.getNetworkStatus();
      res.json(status);
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getPeers(req, res) {
    try {
      const peers = this.p2pNetwork.getPeerList();
      res.json({
        peers,
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  connectToPeer(req, res) {
    try {
      const { host, port } = req.body;

      // Input validation
      const validatedHost = InputValidator.validateString(host, {
        required: true,
        minLength: 1,
        maxLength: 255,
      });

      const validatedPort = InputValidator.validatePort(port, { required: true });

      if (!validatedHost || !validatedPort) {
        return res.status(400).json({
          error: 'Invalid host or port parameters',
        });
      }

      this.p2pNetwork.connectToPeer(validatedHost, validatedPort);

      res.json({
        success: true,
        message: `Connecting to peer ${validatedHost}:${validatedPort}`,
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  // Daemon endpoints
  /**
   *
   * @param req
   * @param res
   */
  getDaemonStatus(req, res) {
    logger.debug('API', `Daemon status request received`);
    logger.debug('API', `Request headers: ${JSON.stringify(req.headers)}`);

    try {
      logger.debug('API', `Gathering daemon status information...`);

      const apiStatus = {
        isRunning: this.isRunning,
        port: this.port,
      };
      logger.debug('API', `API status: ${JSON.stringify(apiStatus)}`);

      const networkStatus = {
        isRunning: this.p2pNetwork ? this.p2pNetwork.isRunning : false,
        port: this.p2pNetwork ? this.p2pNetwork.port : null,
      };
      logger.debug('API', `Network status: ${JSON.stringify(networkStatus)}`);

      const blockchainHeight = this.blockchain.chain.length;
      const { difficulty } = this.blockchain;
      const pendingTransactions = this.blockchain.memoryPool.getPendingTransactionCount();

      const blockchainStatus = {
        height: blockchainHeight,
        difficulty,
        pendingTransactions,
      };
      logger.debug(
        'API',
        `Blockchain status: height=${blockchainHeight}, difficulty=${difficulty}, pendingTransactions=${pendingTransactions}`
      );

      const status = {
        isRunning: true,
        api: apiStatus,
        network: networkStatus,
        blockchain: blockchainStatus,
      };

      logger.debug('API', `Daemon status response prepared successfully`);
      logger.debug('API', `Full response data: ${JSON.stringify(status)}`);

      res.json(status);
    } catch (error) {
      logger.error('API', `Error getting daemon status: ${error.message}`);
      logger.error('API', `Error stack: ${error.stack}`);
      logger.error('API', `Request details: headers=${JSON.stringify(req.headers)}`);

      res.status(500).json({
        error: 'Internal server error while getting daemon status',
        details: error.message,
        timestamp: new Date().toISOString(),
      });
    }
  }

  // Utility endpoints
  /**
   *
   * @param req
   * @param res
   */
  getHealth(req, res) {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  }

  /**
   *
   * @param req
   * @param res
   */
  getInfo(req, res) {
    // Count transactions across all blocks, separating coinbase from regular transactions
    let totalTransactions = 0; // Non-coinbase transactions
    let totalTransactionsWithCoinbase = 0; // All transactions including coinbase

    this.blockchain.chain.forEach(block => {
      if (block && block.transactions) {
        block.transactions.forEach(tx => {
          totalTransactionsWithCoinbase++; // Count all transactions
          if (!tx.isCoinbase) {
            totalTransactions++; // Count only non-coinbase transactions
          }
        });
      }
    });

    res.json({
      name: this.config.name,
      ticker: this.config.ticker,
      version: '1.0.0',
      networkId: this.config.networkId || 'unknown',
      uptime: process.uptime(),
      apiPort: this.port,
      p2pPort: this.p2pPort,
      height: this.blockchain.chain.length,
      difficulty: this.blockchain.difficulty,
      pendingTransactions: this.blockchain.memoryPool.getPendingTransactionCount(),
      totalTransactions: totalTransactions,
      totalTransactionsWithCoinbase: totalTransactionsWithCoinbase,
      totalSupply: this.blockchain.getTotalSupply(),
      blockTime: this.config.blockchain.blockTime,
      coinbaseReward: this.config.blockchain.coinbaseReward,
      halvingBlocks: this.config.blockchain.halvingBlocks || 1000,
      currentReward: this.blockchain.getCurrentMiningReward(),
      halvingInfo: this.blockchain.getHalvingInfo(),
      premineReward: this.config.blockchain.genesis.premineAmount,
      defaultFee: this.config.wallet.defaultFee,
      minFee: this.config.wallet.minFee,
      description: '',
    });
  }

  // Block submission endpoints
  /**
   *
   * @param req
   * @param res
   */
  async submitBlock(req, res) {
    logger.debug('API', `Block submission request received`);
    logger.debug('API', `Request body: ${JSON.stringify(req.body)}`);
    logger.debug('API', `Request headers: ${JSON.stringify(req.headers)}`);

    // Check if another submission is in progress
    if (this.blockSubmissionLock) {
      logger.warn('API', `Block submission rejected - another submission in progress`);
      return res.status(429).json({
        error: 'Block submission in progress',
        details: 'Please wait for the current submission to complete',
        code: 'SUBMISSION_IN_PROGRESS',
      });
    }

    // Acquire lock
    this.blockSubmissionLock = true;
    logger.debug('API', `Block submission lock acquired`);

    try {
      const { block } = req.body;
      logger.debug('API', `Extracted block data: ${block ? 'present' : 'missing'}`);

      if (!block) {
        logger.debug('API', `Block submission failed: no block data in request body`);
        this.blockSubmissionLock = false; // Release lock before return
        return res.status(400).json({
          error: 'Block data is required',
        });
      }

      logger.debug(
        'API',
        `Block data received: index=${block.index}, timestamp=${block.timestamp}, transactions=${block.transactions?.length || 0}`
      );
      logger.debug(
        'API',
        `Block hash: ${block.hash?.substring(0, 16) || 'none'}..., previousHash: ${block.previousHash?.substring(0, 16) || 'none'}...`
      );

      // Import Block class
      logger.debug('API', `Block class available`);

      // Create block object from JSON
      logger.debug('API', `Creating Block instance from JSON data`);
      const blockObj = Block.fromJSON(block);
      logger.debug(
        'API',
        `Block instance created: index=${blockObj.index}, hash=${blockObj.hash?.substring(0, 16)}...`
      );
      logger.debug(
        'API',
        `Block instance type: ${typeof blockObj}, has isValid: ${typeof blockObj.isValid === 'function'}`
      );
      
      logger.debug('API', `Recalculating transaction IDs for security validation`);
      for (const tx of blockObj.transactions) {
        if (typeof tx.calculateId === 'function') {
          const originalId = tx.id;
          const recalculatedId = tx.calculateId();
          if (originalId !== recalculatedId) {
            logger.warn(
              'API',
              `Transaction ID mismatch detected - recalculated: original=${originalId}, recalculated=${recalculatedId}`
            );
            logger.debug('API', `Updating transaction ID to daemon-calculated value`);
            // The ID is already updated by calculateId(), no need to set it again
          }
        }
      }

      // Recalculate merkle root after fixing transaction IDs
      blockObj.calculateMerkleRoot();

      // Validate block
      logger.debug('API', `Validating block ${blockObj.index}`);
      try {
        // Precompute diagnostics to explain failures better
        const mismatchReasons = [];
        try {
          // Enhanced Merkle Root Validation - ALWAYS LOG FOR DEBUGGING
          const recomputedMerkle = blockObj.calculateMerkleRoot();

          // ALWAYS log transaction information for debugging
          const submittedTransactions = blockObj.transactions || [];
          
          if (submittedTransactions.length > 0) {
            submittedTransactions.slice(0, 3).forEach((tx, index) => {
              const txType = tx.isCoinbase ? 'COINBASE' : 'REGULAR';
              const txId = tx.id || 'NO_ID';
            });

            // Log transaction summary
            const coinbaseCount = submittedTransactions.filter(tx => tx.isCoinbase).length;
            const regularCount = submittedTransactions.length - coinbaseCount;
          }
          if (blockObj.merkleRoot !== recomputedMerkle) {
            // Detailed merkle root mismatch analysis
            const submittedTxHashes = submittedTransactions.map(tx => {
              if (tx.id) return tx.id;
              if (typeof tx.calculateId === 'function') return tx.calculateId();
              if (tx.inputs && tx.outputs) {
                const transaction = new Transaction(
                  tx.inputs,
                  tx.outputs,
                  tx.fee,
                  tx.tag || TRANSACTION_TAGS.TRANSACTION,
                  tx.timestamp
                );
                transaction.isCoinbase = tx.isCoinbase;
                transaction.timestamp = tx.timestamp;
                return transaction.calculateId();
              }
              return CryptoUtils.hash(JSON.stringify(tx));
            });

            // Log detailed transaction information for debugging
            logger.error('API', `=== MERKLE ROOT MISMATCH DETAILED ANALYSIS ===`);
            logger.error('API', `Submitted Merkle Root: ${blockObj.merkleRoot}`);
            logger.error('API', `Recomputed Merkle Root: ${recomputedMerkle}`);
            logger.error('API', `Number of Transactions: ${submittedTransactions.length}`);

            // Log first few transaction hashes for comparison
            if (submittedTxHashes.length > 0) {
              logger.error('API', `First 5 Transaction Hashes:`);
              submittedTxHashes.slice(0, 5).forEach((hash, index) => {
                logger.error('API', `  TX[${index}]: ${hash}`);
              });
              if (submittedTxHashes.length > 5) {
                logger.error('API', `  ... and ${submittedTxHashes.length - 5} more transactions`);
              }
            }

            // Check if transactions are properly formatted
            submittedTransactions.forEach((tx, index) => {
              if (!tx.id && !tx.inputs && !tx.outputs) {
                logger.error('API', `  TX[${index}] has invalid format: ${JSON.stringify(tx).substring(0, 100)}...`);
              }
            });

            // Try to identify the root cause
            let rootCause = 'UNKNOWN';
            if (submittedTransactions.length === 0) {
              rootCause = 'NO_TRANSACTIONS_PROVIDED';
            } else if (submittedTransactions.some(tx => !tx.id && !tx.inputs && !tx.outputs)) {
              rootCause = 'INVALID_TRANSACTION_FORMAT';
            } else if (submittedTxHashes.some(hash => !hash || hash.length !== 64)) {
              rootCause = 'INVALID_TRANSACTION_HASHES';
            } else {
              rootCause = 'TRANSACTION_SET_MISMATCH';
            }

            logger.error('API', `Root Cause: ${rootCause}`);
            logger.error('API', `=== END MERKLE ROOT ANALYSIS ===`);

            mismatchReasons.push({
              type: 'MERKLE_ROOT_MISMATCH',
              submitted: blockObj.merkleRoot,
              recomputed: recomputedMerkle,
              rootCause,
              transactionCount: submittedTransactions.length,
              firstTxHashes: submittedTxHashes.slice(0, 3), // Include first 3 for debugging
            });
          }

          // Parent linkage check
          const latest = this.blockchain.getLatestBlock();
          if (latest && blockObj.previousHash !== latest.hash) {
            mismatchReasons.push({
              type: 'PARENT_MISMATCH',
              submittedPrev: blockObj.previousHash,
              latestHash: latest.hash,
            });
            logger.debug(
              'API',
              `Previous hash mismatch: submittedPrev=${blockObj.previousHash.substring(0, 16)}..., latest=${latest.hash.substring(0, 16)}...`
            );
          }

          // Difficulty policy check
          if (blockObj.index > 0 && blockObj.difficulty !== this.blockchain.difficulty) {
            mismatchReasons.push({
              type: 'DIFFICULTY_MISMATCH',
              submitted: blockObj.difficulty,
              expected: this.blockchain.difficulty,
            });
            logger.debug(
              'API',
              `Difficulty mismatch: submitted=${blockObj.difficulty}, expected=${this.blockchain.difficulty}`
            );
          }

          // Hash recomputation diagnostics (Velora)
          try {
            const VeloraUtils = require('../utils/velora');
            const vu = new VeloraUtils();
            const expectedHash = vu.veloraHash(
              blockObj.index,
              blockObj.nonce,
              blockObj.timestamp,
              blockObj.previousHash,
              blockObj.merkleRoot,
              blockObj.difficulty,
              null
            );
            if (expectedHash !== blockObj.hash) {
              mismatchReasons.push({
                type: 'HASH_MISMATCH',
                expected: expectedHash,
                submitted: blockObj.hash,
              });
              logger.error('BLOCK', '=== HASH MISMATCH DIAGNOSTICS ===');
              logger.error('BLOCK', `Submitted: ${blockObj.hash}`);
              logger.error('BLOCK', `Expected (from submitted fields): ${expectedHash}`);

              // If merkle was mismatched, try with recomputed merkle root
              if (blockObj.merkleRoot !== recomputedMerkle) {
                const expectedWithRecomputed = vu.veloraHash(
                  blockObj.index,
                  blockObj.nonce,
                  blockObj.timestamp,
                  blockObj.previousHash,
                  recomputedMerkle,
                  blockObj.difficulty,
                  null
                );
                logger.error('BLOCK', `Expected (with recomputed merkleRoot): ${expectedWithRecomputed}`);
                if (expectedWithRecomputed === blockObj.hash) {
                  mismatchReasons.push({
                    type: 'CAUSE',
                    reason: 'SUBMITTED_MERKLE_ROOT_DERIVED_FROM_DIFFERENT TX SET',
                  });
                }
              }

              // If difficulty mismatch, try with network difficulty
              if (blockObj.difficulty !== this.blockchain.difficulty) {
                const expectedWithNetworkDiff = vu.veloraHash(
                  blockObj.index,
                  blockObj.nonce,
                  blockObj.timestamp,
                  blockObj.previousHash,
                  blockObj.merkleRoot,
                  this.blockchain.difficulty,
                  null
                );
                logger.error('BLOCK', `Expected (with network difficulty): ${expectedWithNetworkDiff}`);
              }
              logger.error('BLOCK', '=== END HASH MISMATCH DIAGNOSTICS ===');
            }
          } catch (e) {
            logger.warn('API', `Hash diagnostics failed: ${e.message}`);
          }

          // Attach reasons to request log for traceability
          if (mismatchReasons.length > 0) {
            logger.debug('API', `Block diagnostics: ${JSON.stringify(mismatchReasons).substring(0, 500)}`);
          }
        } catch (diagErr) {
          logger.warn('API', `Diagnostics error: ${diagErr.message}`);
        }

        const isValidResult = blockObj.isValid();
        logger.debug('API', `Block validation result: ${isValidResult}`);

        if (!isValidResult) {
          logger.debug('API', `Block ${blockObj.index} validation failed`);

          // Enhanced error response with detailed mismatch information
          const errorResponse = {
            error: 'Invalid block submitted',
            details: 'Block validation failed',
            validationErrors: [],
          };

          // Add detailed merkle root mismatch information if available
          if (mismatchReasons.length > 0) {
            errorResponse.validationErrors = mismatchReasons.map(reason => {
              if (reason.type === 'MERKLE_ROOT_MISMATCH') {
                return {
                  type: 'MERKLE_ROOT_MISMATCH',
                  message: `Merkle root mismatch detected. The submitted merkle root does not match the one calculated from the provided transactions.`,
                  submitted: reason.submitted,
                  recomputed: reason.recomputed,
                  rootCause: reason.rootCause,
                  transactionCount: reason.transactionCount,
                  firstTxHashes: reason.firstTxHashes,
                  suggestion:
                    'Ensure that the merkle root in the submitted block matches the merkle root calculated from the actual transaction set in the block.',
                };
              }
              return reason;
            });
          }

          return res.status(400).json(errorResponse);
        }
        logger.debug('API', `Block ${blockObj.index} validation passed`);

        // Coinbase verification for submitted block
        logger.debug('API', `Starting coinbase verification for block ${blockObj.index}`);
        try {
          const coinbaseVerificationResult = this.verifyCoinbaseTransaction(blockObj);
          if (!coinbaseVerificationResult.valid) {
            logger.error('API', `Coinbase verification failed: ${coinbaseVerificationResult.reason}`);
            return res.status(400).json({
              error: 'Invalid coinbase transaction',
              details: coinbaseVerificationResult.reason,
              expected: coinbaseVerificationResult.expected,
              actual: coinbaseVerificationResult.actual,
              code: 'COINBASE_VERIFICATION_FAILED',
            });
          }
          logger.debug('API', `Coinbase verification passed for block ${blockObj.index}`);
        } catch (coinbaseError) {
          logger.error('API', `Coinbase verification error: ${coinbaseError.message}`);
          return res.status(400).json({
            error: 'Coinbase verification error',
            details: coinbaseError.message,
            code: 'COINBASE_VERIFICATION_ERROR',
          });
        }
      } catch (validationError) {
        logger.error('API', `Block validation error: ${validationError.message}`);
        logger.error('API', `Validation error stack: ${validationError.stack}`);
        return res.status(400).json({
          error: 'Block validation error',
          details: validationError.message,
        });
      }

      // Check if block already exists
      logger.debug('API', `Checking if block ${blockObj.index} already exists in chain`);
      const existingBlock = this.blockchain.chain.find(b => b.hash === blockObj.hash);
      if (existingBlock) {
        logger.debug('API', `Block ${blockObj.index} already exists in chain at index ${existingBlock.index}`);
        return res.status(409).json({
          error: 'Block already exists in chain',
          details: `Block with hash ${blockObj.hash.substring(0, 16)}... already exists at index ${existingBlock.index}`,
        });
      }
      logger.debug('API', `Block ${blockObj.index} is not a duplicate`);

      // Add block to blockchain
      // FIXED: API submitted blocks should use embedded difficulty (could be from remote miners/pools)
      logger.debug('API', `Adding block ${blockObj.index} to blockchain`);
      const addResult = this.blockchain.addBlock(blockObj, false, true, false); // skipValidation=false, useBlockDifficulty=true, fastSyncMode=false
      logger.debug('API', `Blockchain addBlock result: ${addResult}`);

      if (addResult) {
        logger.debug('API', `Block ${blockObj.index} added to blockchain successfully`);

        // Broadcast to network
        try {
          logger.debug('API', `Broadcasting new block to P2P network`);
          if (this.p2pNetwork) {
            this.p2pNetwork.broadcastNewBlock(blockObj);
            logger.debug('API', `Block broadcasted successfully`);
          } else {
            logger.debug('API', `P2P network not available, skipping broadcast`);
          }
        } catch (broadcastError) {
          logger.warn('API', `Failed to broadcast block: ${broadcastError.message}`);
          logger.debug('API', `Broadcast error stack: ${broadcastError.stack}`);
        }

        // Save blockchain immediately
        try {
          this.blockchain.saveToDefaultFile();
          logger.debug('API', `Blockchain saved immediately after API block submission`);
        } catch (saveError) {
          logger.warn('API', `Failed to save blockchain immediately: ${saveError.message}`);
        }

        logger.debug('API', `Sending success response for block ${blockObj.index}`);
        res.json({
          success: true,
          message: 'Block submitted successfully',
          block: {
            index: blockObj.index,
            hash: blockObj.hash,
            timestamp: blockObj.timestamp,
          },
        });
      } else {
        logger.debug('API', `Failed to add block ${blockObj.index} to blockchain`);
        res.status(400).json({
          error: 'Failed to add block to chain',
          details: 'Blockchain rejected the block',
        });
      }
    } catch (error) {
      logger.error('API', `Block submission error: ${error.message}`);
      logger.error('API', `Error stack: ${error.stack}`);
      logger.error('API', `Request body: ${JSON.stringify(req.body)}`);

      res.status(500).json({
        error: 'Internal server error during block submission',
        details: error.message,
        timestamp: new Date().toISOString(),
      });
    } finally {
      // Always release the submission lock
      this.blockSubmissionLock = false;
      logger.debug('API', `Block submission lock released`);
    }
  }

  /**
   * CRITICAL: Generate cryptographically secure API key
   * @returns {string} Secure API key
   */
  generateSecureApiKey() {
    const crypto = require('crypto');
    // Generate 32 bytes (256 bits) of cryptographically secure random data
    const randomBytes = crypto.randomBytes(32);
    // Convert to base64 for easy handling
    const apiKey = randomBytes.toString('base64').replace(/[+/=]/g, (char) => {
      // Replace URL-unsafe characters with safe alternatives
      switch (char) {
        case '+': return '-';
        case '/': return '_';
        case '=': return '';
        default: return char;
      }
    });

    return `pastella-${apiKey}`;
  }

  /**
   * Verify coinbase transaction amount includes correct base reward and fees with halving logic
   * @param {Block} block - The block to verify
   * @returns {object} Verification result with valid flag and details
   */
  verifyCoinbaseTransaction(block) {
    const { calculateHalvedReward } = require('../utils/atomicUnits');
    const InputValidator = require('../utils/validation');

    // Find coinbase transaction
    const coinbase = block.transactions.find(tx => tx.isCoinbase);
    if (!coinbase) {
      return {
        valid: false,
        reason: 'No coinbase transaction found in block',
        expected: null,
        actual: null,
      };
    }

    if (coinbase.outputs.length !== 1) {
      return {
        valid: false,
        reason: `Coinbase transaction must have exactly 1 output, found ${coinbase.outputs.length}`,
        expected: 1,
        actual: coinbase.outputs.length,
      };
    }

    // CRITICAL: Validate coinbase recipient address format
    const coinbaseAddress = coinbase.outputs[0].address;
    const validatedAddress = InputValidator.validateCryptocurrencyAddress(coinbaseAddress);

    if (!validatedAddress) {
      return {
        valid: false,
        reason: 'Coinbase recipient address is invalid or improperly formatted',
        expected: 'Valid cryptocurrency address (format: ^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$)',
        actual: coinbaseAddress,
      };
    }

    // Calculate expected base reward with halving logic
    const baseReward = this.config?.blockchain?.coinbaseReward || 5000000000;
    const halvingBlocks = this.config?.blockchain?.halvingBlocks || 2102400;
    const expectedBaseReward = calculateHalvedReward(block.index, baseReward, halvingBlocks);

    // Calculate total fees from non-coinbase transactions
    const regularTransactions = block.transactions.filter(tx => !tx.isCoinbase);
    const totalFees = regularTransactions.reduce((sum, tx) => sum + (tx.fee || 0), 0);

    // Expected total reward = base reward + fees
    const expectedTotalReward = expectedBaseReward + totalFees;
    const actualReward = coinbase.outputs[0].amount;

    logger.debug('API', `Coinbase verification details:`);
    logger.debug('API', `  Block height: ${block.index}`);
    logger.debug('API', `  Base reward (with halving): ${expectedBaseReward} atomic units`);
    logger.debug('API', `  Total fees: ${totalFees} atomic units`);
    logger.debug('API', `  Expected total reward: ${expectedTotalReward} atomic units`);
    logger.debug('API', `  Actual coinbase amount: ${actualReward} atomic units`);

    if (actualReward !== expectedTotalReward) {
      return {
        valid: false,
        reason: 'Coinbase reward amount incorrect',
        expected: {
          baseReward: expectedBaseReward,
          totalFees,
          totalReward: expectedTotalReward,
        },
        actual: {
          coinbaseAmount: actualReward,
          difference: actualReward - expectedTotalReward,
        },
      };
    }

    // Verify coinbase transaction is properly formatted
    if (!coinbase.tag || coinbase.tag !== 'COINBASE') {
      return {
        valid: false,
        reason: 'Coinbase transaction must have tag "COINBASE"',
        expected: 'COINBASE',
        actual: coinbase.tag,
      };
    }

    if (coinbase.inputs.length !== 0) {
      return {
        valid: false,
        reason: 'Coinbase transaction must have zero inputs',
        expected: 0,
        actual: coinbase.inputs.length,
      };
    }

    if (coinbase.fee !== 0) {
      return {
        valid: false,
        reason: 'Coinbase transaction must have zero fee',
        expected: 0,
        actual: coinbase.fee,
      };
    }

    return {
      valid: true,
      reason: 'Coinbase transaction verification passed',
      expected: {
        baseReward: expectedBaseReward,
        totalFees,
        totalReward: expectedTotalReward,
      },
      actual: {
        coinbaseAmount: actualReward,
      },
    };
  }

  /**
   * Validate merkle root independently without full block validation
   * @param req
   * @param res
   */
  validateMerkleRoot(req, res) {
    logger.debug('API', `Merkle root validation request received`);

    try {
      const { block } = req.body;

      if (!block) {
        return res.status(400).json({
          error: 'Block data is required',
          details: 'Please provide block data in the request body',
        });
      }

      // Create block object from JSON
      const blockObj = Block.fromJSON(block);

      // Extract transaction information
      const submittedTransactions = blockObj.transactions || [];
      const submittedTxHashes = submittedTransactions.map(tx => {
        if (tx.id) return tx.id;
        if (typeof tx.calculateId === 'function') return tx.calculateId();
        if (tx.inputs && tx.outputs) {
          const transaction = new Transaction(
            tx.inputs,
            tx.outputs,
            tx.fee,
            tx.tag || TRANSACTION_TAGS.TRANSACTION,
            tx.timestamp
          );
          transaction.isCoinbase = tx.isCoinbase;
          transaction.timestamp = tx.timestamp;
          return transaction.calculateId();
        }
        return CryptoUtils.hash(JSON.stringify(tx));
      });

      // Calculate merkle root from transactions
      const calculatedMerkleRoot = CryptoUtils.calculateMerkleRoot(submittedTxHashes);

      // Check for mismatch
      const isMismatch = blockObj.merkleRoot !== calculatedMerkleRoot;

      // Prepare detailed response
      const response = {
        success: !isMismatch,
        submittedMerkleRoot: blockObj.merkleRoot,
        calculatedMerkleRoot,
        isMismatch,
        transactionCount: submittedTransactions.length,
        transactionHashes: submittedTxHashes,
        analysis: {
          submittedTransactions: submittedTransactions.map((tx, index) => ({
            index,
            hasId: !!tx.id,
            hasInputs: !!(tx.inputs && tx.inputs.length > 0),
            hasOutputs: !!(tx.outputs && tx.outputs.length > 0),
            isCoinbase: !!tx.isCoinbase,
            calculatedHash: submittedTxHashes[index],
          })),
        },
      };

      if (isMismatch) {
        response.error = 'Merkle root mismatch detected';
        response.details = 'The submitted merkle root does not match the one calculated from the provided transactions';

        // Identify potential root causes
        let rootCause = 'UNKNOWN';
        if (submittedTransactions.length === 0) {
          rootCause = 'NO_TRANSACTIONS_PROVIDED';
        } else if (submittedTransactions.some(tx => !tx.id && !tx.inputs && !tx.outputs)) {
          rootCause = 'INVALID_TRANSACTION_FORMAT';
        } else if (submittedTxHashes.some(hash => !hash || hash.length !== 64)) {
          rootCause = 'INVALID_TRANSACTION_HASHES';
        } else {
          rootCause = 'TRANSACTION_SET_MISMATCH';
        }

        response.rootCause = rootCause;
        response.suggestion =
          'Ensure that the merkle root in the submitted block matches the merkle root calculated from the actual transaction set in the block.';
      }
      res.json(response);
    } catch (error) {
      logger.error('API', `Merkle root validation error: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error during merkle root validation',
        details: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getPendingBlocks(req, res) {
    try {
      const pendingTransactions = this.blockchain.memoryPool.getPendingTransactions();

      // Group transactions by potential block
      const blockGroups = [];
      let currentGroup = [];
      let currentSize = 0;

      pendingTransactions.forEach(tx => {
        if (currentSize + tx.size > this.config.blockchain.blockSize) {
          blockGroups.push(currentGroup);
          currentGroup = [];
          currentSize = 0;
        }
        currentGroup.push(tx);
        currentSize += tx.size;
      });
      if (currentGroup.length > 0) {
        blockGroups.push(currentGroup);
      }

      res.json({
        pendingTransactions: blockGroups.map(group => ({
          transactions: group.map(tx => tx.toJSON()),
          totalSize: group.reduce((sum, tx) => sum + tx.size, 0),
        })),
        count: blockGroups.length,
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  validateBlock(req, res) {
    try {
      const { block } = req.body;

      if (!block) {
        return res.status(400).json({
          error: 'Block data is required',
        });
      }

      // Create block object from JSON
      const blockObj = Block.fromJSON(block);

      // Validate block
      const isValid = blockObj.isValid();

      res.json({
        valid: isValid,
        block: {
          index: blockObj.index,
          hash: blockObj.hash,
          timestamp: blockObj.timestamp,
          difficulty: blockObj.difficulty,
          nonce: blockObj.nonce,
        },
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  // Reputation endpoints
  /**
   *
   * @param req
   * @param res
   */
  getReputationStats(req, res) {
    try {
      if (!this.p2pNetwork) {
        return res.status(503).json({
          error: 'P2P network not available',
        });
      }

      const stats = this.p2pNetwork.getReputationStats();
      res.json({
        reputation: stats,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getPeerReputation(req, res) {
    try {
      if (!this.p2pNetwork) {
        return res.status(503).json({
          error: 'P2P network not available',
        });
      }

      // Input validation for peer address
      const validatedPeerAddress = InputValidator.validateString(req.params.peerAddress, {
        required: true,
        minLength: 1,
        maxLength: 255,
      });

      if (!validatedPeerAddress) {
        return res.status(400).json({
          error: 'Invalid peer address',
        });
      }

      const reputation = this.p2pNetwork.getPeerReputation(validatedPeerAddress);
      res.json({
        peerAddress: validatedPeerAddress,
        reputation,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({
        error: error.message,
      });
    }
  }

  // Message validation endpoints
  /**
   *
   * @param req
   * @param res
   */
  getMessageValidationStats(req, res) {
    try {
      if (!this.p2pNetwork) {
        return res.status(503).json({
          error: 'P2P network not available',
        });
      }

      const stats = this.p2pNetwork.getMessageValidationStats();
      res.json({
        ...stats,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting message validation stats: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  resetMessageValidationStats(req, res) {
    try {
      if (!this.p2pNetwork) {
        return res.status(503).json({
          error: 'P2P network not available',
        });
      }

      this.p2pNetwork.resetMessageValidationStats();
      res.json({
        message: 'Message validation statistics reset successfully',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error resetting message validation stats: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getPartitionStats(req, res) {
    try {
      if (!this.p2pNetwork) {
        return res.status(503).json({
          error: 'P2P network not available',
        });
      }

      const stats = this.p2pNetwork.partitionHandler.getPartitionStats();
      res.json({
        success: true,
        data: stats,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting partition stats: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  resetPartitionStats(req, res) {
    try {
      if (!this.p2pNetwork) {
        return res.status(503).json({
          error: 'P2P network not available',
        });
      }

      this.p2pNetwork.partitionHandler.resetPartitionStats();
      res.json({
        success: true,
        message: 'Partition statistics reset successfully',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error resetting partition stats: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // Rate limiting management endpoints
  /**
   *
   * @param req
   * @param res
   */
  getRateLimitStats(req, res) {
    try {
      const stats = this.rateLimiter.getStats();
      res.json({
        success: true,
        data: stats,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting rate limit stats: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  resetRateLimitsForIP(req, res) {
    try {
      const { ip } = req.params;
      if (!ip || ip === 'unknown') {
        return res.status(400).json({
          error: 'Invalid IP address',
        });
      }

      const resetCount = this.rateLimiter.resetForIP(ip);
      res.json({
        success: true,
        message: `Rate limits reset for IP ${ip}`,
        resetEndpoints: resetCount,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error resetting rate limits for IP: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  resetAllRateLimits(req, res) {
    try {
      const resetCount = this.rateLimiter.resetAll();
      res.json({
        success: true,
        message: 'All rate limits reset successfully',
        resetEntries: resetCount,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error resetting all rate limits: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // NEW FEATURES: Memory pool and spam protection management endpoints
  /**
   *
   * @param req
   * @param res
   */
  getMemoryPoolStatus(req, res) {
    try {
      const status = this.blockchain.manageMemoryPool();
      res.json({
        success: true,
        data: {
          poolSize: status.poolSize,
          memoryUsage: status.memoryUsage,
          actions: status.actions,
          maxPoolSize: this.config?.memory?.maxPoolSize || 10000,
          maxMemoryUsage: (this.config?.memory?.maxMemoryUsage || 2048) * 1024 * 1024, // Convert MB to bytes
          cpuProtection: status.cpuProtection,
          batchProcessing: this.blockchain.memoryPool.getBatchProcessingConfig(),
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting memory pool status: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Enable or disable CPU protection
   * @param req
   * @param res
   */
  setCpuProtection(req, res) {
    try {
      const { enabled } = req.body;

      if (typeof enabled !== 'boolean') {
        return res.status(400).json({
          error: 'Invalid request: enabled must be a boolean',
        });
      }

      this.blockchain.memoryPool.memoryProtection.setCpuProtection(enabled);

      res.json({
        success: true,
        message: `CPU protection ${enabled ? 'enabled' : 'disabled'} successfully`,
        data: {
          cpuProtectionEnabled: enabled,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error setting CPU protection: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Update CPU protection settings
   * @param req
   * @param res
   */
  updateCpuProtection(req, res) {
    try {
      const { maxCpuUsage, monitoringInterval, cleanupInterval } = req.body;

      const settings = {};
      if (maxCpuUsage !== undefined) {
        if (typeof maxCpuUsage !== 'number' || maxCpuUsage < 1 || maxCpuUsage > 100) {
          return res.status(400).json({
            error: 'Invalid maxCpuUsage: must be a number between 1 and 100',
          });
        }
        settings.maxCpuUsage = maxCpuUsage;
      }

      if (monitoringInterval !== undefined) {
        if (typeof monitoringInterval !== 'number' || monitoringInterval < 1000) {
          return res.status(400).json({
            error: 'Invalid monitoringInterval: must be a number >= 1000ms',
          });
        }
        settings.monitoringInterval = monitoringInterval;
      }

      if (cleanupInterval !== undefined) {
        if (typeof cleanupInterval !== 'number' || cleanupInterval < 1000) {
          return res.status(400).json({
            error: 'Invalid cleanupInterval: must be a number >= 1000ms',
          });
        }
        settings.cleanupInterval = cleanupInterval;
      }

      this.blockchain.memoryPool.memoryProtection.updateCpuProtection(settings);

      res.json({
        success: true,
        message: 'CPU protection settings updated successfully',
        data: settings,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error updating CPU protection: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Get batch processing configuration
   * @param req
   * @param res
   */
  getBatchProcessingConfig(req, res) {
    try {
      const config = this.blockchain.memoryPool.getBatchProcessingConfig();

      res.json({
        success: true,
        data: config,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting batch processing config: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getSpamProtectionStatus(req, res) {
    try {
      const bannedAddresses = Array.from(this.blockchain.spamProtection.spamProtection.bannedAddresses);
      const rateLimitData = Array.from(this.blockchain.spamProtection.addressRateLimits.entries()).map(
        ([address, data]) => ({
          address,
          count: data.count,
          firstTx: new Date(data.firstTx).toISOString(),
          banTime: data.banTime ? new Date(data.banTime).toISOString() : null,
        })
      );

      res.json({
        success: true,
        data: {
          bannedAddresses,
          rateLimitData,
          maxTransactionsPerAddress: this.blockchain.spamProtection.spamProtection.maxTransactionsPerAddress,
          maxTransactionsPerMinute: this.blockchain.spamProtection.spamProtection.maxTransactionsPerMinute,
          addressBanDuration: this.blockchain.spamProtection.spamProtection.addressBanDuration,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting spam protection status: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  resetSpamProtection(req, res) {
    try {
      // Reset all spam protection data
      this.blockchain.spamProtection.spamProtection.bannedAddresses.clear();
      this.blockchain.spamProtection.addressRateLimits.clear();
      this.blockchain.spamProtection.spamProtection.lastCleanup = Date.now();

      res.json({
        success: true,
        message: 'Spam protection reset successfully',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error resetting spam protection: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  addTransactionBatch(req, res) {
    try {
      const { transactions } = req.body;

      if (!transactions || !Array.isArray(transactions)) {
        return res.status(400).json({
          error: 'Invalid request: transactions array required',
        });
      }

      // Convert plain objects to Transaction instances if needed
      const processedTransactions = transactions.map(tx => {
        if (typeof tx === 'object' && !tx.isValid) {
          try {
            return Transaction.fromJSON(tx);
          } catch (error) {
            logger.warn(
              'API',
              `Failed to convert transaction ${tx.id || 'unknown'} to Transaction instance: ${error.message}`
            );
            return tx; // Return original if conversion fails
          }
        }
        return tx;
      });

      const result = this.blockchain.addTransactionBatch(processedTransactions);

      res.json({
        success: true,
        data: result,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error adding transaction batch: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getMemoryProtectionStatus(req, res) {
    try {
      const status = this.blockchain.getMemoryProtectionStatus();
      res.json({
        success: true,
        data: status,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting memory protection status: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getCPUProtectionStatus(req, res) {
    try {
      const status = this.blockchain.getCPUProtectionStatus();
      res.json({
        success: true,
        data: status,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting CPU protection status: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getReputationStatus(req, res) {
    try {
      if (!this.p2pNetwork) {
        return res.status(503).json({
          error: 'P2P network not available',
        });
      }
      const status = this.p2pNetwork.getReputationStatus();
      res.json({
        success: true,
        data: status,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting reputation status: ${error.message}`);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // Checkpoint endpoints
  /**
   *
   * @param req
   * @param res
   */
  getCheckpoints(req, res) {
    try {
      const checkpoints = this.blockchain.checkpointManager.getAllCheckpoints();
      const stats = this.blockchain.checkpointManager.getCheckpointStats();

      res.json({
        success: true,
        checkpoints,
        stats,
      });
    } catch (error) {
      logger.error('API', `Error getting checkpoints: ${error.message}`);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  addCheckpoint(req, res) {
    try {
      const { height, hash, description } = req.body;

      if (!height || !hash) {
        return res.status(400).json({
          success: false,
          error: 'Height and hash are required',
        });
      }

      const success = this.blockchain.checkpointManager.addCheckpoint(height, hash, description);

      if (success) {
        res.json({
          success: true,
          message: `Checkpoint added at height ${height}`,
        });
      } else {
        res.status(400).json({
          success: false,
          error: 'Failed to add checkpoint',
        });
      }
    } catch (error) {
      logger.error('API', `Error adding checkpoint: ${error.message}`);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  updateCheckpoints(req, res) {
    try {
      // This would typically update checkpoints from a trusted source
      // For now, just return success
      res.json({
        success: true,
        message: 'Checkpoints updated successfully',
        updated: 0,
      });
    } catch (error) {
      logger.error('API', `Error updating checkpoints: ${error.message}`);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  clearCheckpoints(req, res) {
    try {
      const success = this.blockchain.checkpointManager.clearCheckpoints();

      if (success) {
        res.json({
          success: true,
          message: 'All checkpoints cleared successfully',
        });
      } else {
        res.status(500).json({
          success: false,
          error: 'Failed to clear checkpoints',
        });
      }
    } catch (error) {
      logger.error('API', `Error clearing checkpoints: ${error.message}`);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  validateCheckpoints(req, res) {
    try {
      logger.debug('API', `Checkpoint validation request received`);

      // Validate checkpoints against current blockchain
      const isValid = this.blockchain.checkpointManager.validateCheckpoints(this.blockchain);

      if (isValid) {
        const stats = this.blockchain.checkpointManager.getCheckpointStats();
        res.json({
          success: true,
          message: 'Checkpoint validation completed successfully',
          checkpointsUsed: stats.total,
          stats,
        });
      } else {
        // This should never happen as validateCheckpoints will exit the process
        res.status(500).json({
          success: false,
          error: 'Checkpoint validation failed',
        });
      }
    } catch (error) {
      logger.error('API', `Error validating checkpoints: ${error.message}`);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }

  // Wallet routes (public - no API key required)
  /**
   *
   * @param req
   * @param res
   */
  getWalletBalance(req, res) {
    try {
      const { address } = req.params;

      // For network-based wallet system, get balance from blockchain UTXOs
      if (!this.blockchain) {
        return res.status(503).json({
          error: 'Blockchain not available',
        });
      }

      // Get all UTXOs for the address from the blockchain
      const utxos = this.blockchain.getUTXOsForAddress(address);
      const balance = utxos.reduce((total, utxo) => total + utxo.amount, 0);

      res.json({
        success: true,
        address,
        balance,
        utxoCount: utxos.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting wallet balance for ${req.params.address}: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getWalletTransactions(req, res) {
    try {
      const { address } = req.params;

      // For network-based wallet system, get transactions from blockchain
      if (!this.blockchain) {
        return res.status(503).json({
          error: 'Blockchain not available',
        });
      }

      // Get all transactions involving this address from the blockchain
      const transactions = [];
      for (const block of this.blockchain.chain) {
        for (const tx of block.transactions) {
          // Check if address is involved in inputs or outputs
          const isInvolved =
            tx.inputs.some(input => input.address === address) || tx.outputs.some(output => output.address === address);

          if (isInvolved) {
            // Show complete transaction context instead of filtering
            transactions.push({
              id: tx.id,
              blockHeight: block.index,
              blockHash: block.hash,
              timestamp: block.timestamp,
              // Show ALL inputs and outputs for complete context
              inputs: tx.inputs,
              outputs: tx.outputs,
              fee: tx.fee || 0,
              tag: tx.tag,
              // Add helpful flags to identify address involvement
              isSender: this.isAddressSender(tx, address),
              isReceiver: this.isAddressReceiver(tx, address),
              // Calculate net amount for this address
              netAmount: this.calculateNetAmountForAddress(tx, address),
            });
          }
        }
      }

      res.json({
        success: true,
        address,
        transactions,
        count: transactions.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting wallet transactions for ${req.params.address}: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  /**
   * Calculate net amount for a specific address in a transaction
   * @param transaction
   * @param address
   * @returns {number}
   */
  /**
   * Check if an address is a sender in a transaction by checking input public keys
   * @param {Object} transaction - The transaction to check
   * @param {string} address - The address to check for
   * @returns {boolean} True if address is a sender
   */
  isAddressSender(transaction, address) {
    try {
      const { CryptoUtils } = require('../utils/crypto');

      // Check each input's public key to see if it corresponds to our address
      for (const input of transaction.inputs) {
        if (input.publicKey) {
          // Derive address from the public key in the input
          const inputAddress = CryptoUtils.publicKeyToAddress(input.publicKey);
          // If derived address matches our target address, this address is the sender
          if (inputAddress === address) {
            return true;
          }
        }
      }
      return false;
    } catch (error) {
      logger.error('API', `Error checking if address ${address} is sender: ${error.message}`);
      return false;
    }
  }

  /**
   * Check if an address is a receiver in a transaction (excluding change)
   * @param {Object} transaction - The transaction to check
   * @param {string} address - The address to check for
   * @returns {boolean} True if address is a receiver (but not if it's only change)
   */
  isAddressReceiver(transaction, address) {
    try {
      const isSender = this.isAddressSender(transaction, address);
      const hasOutputs = transaction.outputs.some(output => output.address === address);

      // If address is sender and has outputs, it's likely change - not a receiver
      if (isSender && hasOutputs) {
        // Check if there are OTHER recipients besides this address
        const otherRecipients = transaction.outputs.some(output => output.address !== address);

        // If there are other recipients, this address is getting change (sender)
        // If there are NO other recipients, this might be a self-transfer (receiver)
        return !otherRecipients;
      }

      // If not a sender but has outputs, definitely a receiver
      return hasOutputs;
    } catch (error) {
      logger.error('API', `Error checking if address ${address} is receiver: ${error.message}`);
      return false;
    }
  }

  /**
   * Find a transaction by ID across all blocks
   * @param {string} txId - Transaction ID to find
   * @returns {Object|null} Transaction object or null if not found
   */
  findTransactionById(txId) {
    try {
      // Search through all blocks to find the transaction
      for (const block of this.blockchain.chain) {
        for (const tx of block.transactions) {
          if (tx.id === txId) {
            return tx;
          }
        }
      }
      return null;
    } catch (error) {
      logger.error('API', `Error finding transaction ${txId}: ${error.message}`);
      return null;
    }
  }

  calculateNetAmountForAddress(transaction, address) {
    let netAmount = 0;

    // Add outputs TO this address (received)
    transaction.outputs.forEach(output => {
      if (output.address === address) {
        netAmount += output.amount;
      }
    });

    // Subtract inputs FROM this address (sent) - using public key approach
    transaction.inputs.forEach(input => {
      try {
        const { CryptoUtils } = require('../utils/crypto');

        if (input.publicKey) {
          // Derive address from the public key in the input
          const inputAddress = CryptoUtils.publicKeyToAddress(input.publicKey);
          // If this input is from our address, we need to look up the UTXO amount
          if (inputAddress === address) {
            // Look up the previous transaction to get the amount spent
            const prevTransaction = this.findTransactionById(input.txId);
            if (prevTransaction && prevTransaction.outputs[input.outputIndex]) {
              const prevOutput = prevTransaction.outputs[input.outputIndex];
              netAmount -= prevOutput.amount; // Subtract the actual UTXO amount
            }
          }
        }
      } catch (error) {
        logger.error('API', `Error calculating input amount for ${address}: ${error.message}`);
      }
    });

    return netAmount;
  }

  /**
   *
   * @param req
   * @param res
   */
  getWalletUTXOs(req, res) {
    try {
      const { address } = req.params;

      if (!this.blockchain) {
        return res.status(503).json({
          error: 'Blockchain not available',
        });
      }

      const utxos = this.blockchain.getUTXOsForAddress(address);

      res.json({
        success: true,
        address,
        utxos,
        count: utxos.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting UTXOs for ${req.params.address}: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  /**
   * Check if a specific UTXO is spent or unspent
   * @param req
   * @param res
   */
  checkUTXOStatus(req, res) {
    try {
      const { txId, outputIndex } = req.params;
      const outputIndexInt = parseInt(outputIndex);

      if (!this.blockchain || !this.blockchain.utxoManager) {
        return res.status(503).json({
          success: false,
          error: 'Blockchain or UTXO manager not available',
        });
      }

      // Check if UTXO exists in the current UTXO set (unspent)
      const utxo = this.blockchain.utxoManager.findUTXO(txId, outputIndexInt);
      const isSpent = !utxo; // If UTXO doesn't exist in set, it's spent

      res.json({
        success: true,
        txId,
        outputIndex: outputIndexInt,
        spent: isSpent,
        unspent: !isSpent,
        utxo: utxo || null,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error checking UTXO status for ${req.params.txId}:${req.params.outputIndex}: ${error.message}`);
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  /**
   * Get all UTXOs for a specific address
   * @param req
   * @param res
   */
  getAddressUTXOs(req, res) {
    try {
      const { address } = req.params;

      if (!this.blockchain || !this.blockchain.utxoManager) {
        return res.status(503).json({
          success: false,
          error: 'Blockchain or UTXO manager not available',
        });
      }

      const utxos = this.blockchain.utxoManager.getUTXOsForAddress(address);
      const totalBalance = utxos.reduce((sum, utxo) => sum + utxo.amount, 0);

      res.json({
        success: true,
        address,
        utxos,
        count: utxos.length,
        totalBalance,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting UTXOs for address ${req.params.address}: ${error.message}`);
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  syncMempoolWithPeers(req, res) {
    try {
      if (!this.p2pNetwork) {
        return res.status(503).json({
          error: 'P2P network not available',
        });
      }
      this.p2pNetwork.syncMempoolWithPeers();
      res.json({
        success: true,
        message: 'Mempool sync initiated with peers',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error syncing mempool with peers: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   */
  getMempoolSyncStatus(req, res) {
    try {
      if (!this.p2pNetwork) {
        return res.status(503).json({
          error: 'P2P network not available',
        });
      }
      const status = this.p2pNetwork.getMempoolSyncStatus();
      res.json({
        success: true,
        data: status,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting mempool sync status: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  /**
   * Debug endpoint to rebuild UTXO set from blockchain
   * @param req
   * @param res
   */
  rebuildUTXOs(req, res) {
    try {
      if (!this.blockchain) {
        return res.status(503).json({
          error: 'Blockchain not available',
        });
      }

      logger.info('API', 'Rebuilding UTXO set from blockchain...');

      // Get chain and rebuild UTXOs
      const chain = this.blockchain.getChain();
      this.blockchain.utxoManager.rebuildUTXOSet(chain);

      logger.info('API', `UTXO set rebuilt from ${chain.length} blocks`);

      res.json({
        success: true,
        message: `UTXO set rebuilt from ${chain.length} blocks`,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error rebuilding UTXO set: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  /**
   * Get Rich List - addresses with highest balances
   * @param req
   * @param res
   */
  async getRichList(req, res) {
    try {
      if (!this.blockchain) {
        return res.status(503).json({
          error: 'Blockchain not available',
        });
      }

      const limit = parseInt(req.params.limit) || 100;
      const maxLimit = 1000;
      
      if (limit > maxLimit) {
        return res.status(400).json({
          error: `Limit cannot exceed ${maxLimit}`,
        });
      }

      logger.debug('API', `Getting rich list with limit: ${limit}`);

      // Get all UTXOs and calculate balances by address
      const utxos = this.blockchain.utxoManager.getAllUTXOs();
      const balanceMap = new Map();
      
      // Calculate total balance for each address
      utxos.forEach(utxo => {
        const address = utxo.address;
        const currentBalance = balanceMap.get(address) || 0;
        balanceMap.set(address, currentBalance + utxo.amount);
      });

      // Convert to array and sort by balance (descending)
      const richList = Array.from(balanceMap.entries())
        .map(([address, balance]) => ({
          address,
          balance,
          rank: 0 // Will be set below
        }))
        .sort((a, b) => b.balance - a.balance)
        .slice(0, limit);

      // Set ranks
      richList.forEach((entry, index) => {
        entry.rank = index + 1;
      });

      // Calculate some statistics
      const totalAddresses = balanceMap.size;
      const totalBalance = Array.from(balanceMap.values()).reduce((sum, balance) => sum + balance, 0);
      const topPercentageOfSupply = richList.length > 0 ? 
        (richList.reduce((sum, entry) => sum + entry.balance, 0) / totalBalance * 100) : 0;

      logger.debug('API', `Rich list generated: ${richList.length} addresses, ${totalAddresses} total addresses`);

      res.json({
        success: true,
        richList,
        statistics: {
          totalAddresses,
          totalBalance,
          topPercentageOfSupply: Math.round(topPercentageOfSupply * 100) / 100,
          requestedLimit: limit,
          returnedCount: richList.length
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('API', `Error getting rich list: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message,
      });
    }
  }

  // ================================
  // SMART CONTRACT API ENDPOINTS
  // ================================

  /**
   * Get contract fees information (public endpoint)
   */
  getContractFees(req, res) {
    try {
      const config = this.blockchain.config;

      if (!config || !config.smartContracts) {
        return res.status(404).json({
          error: 'Smart contracts not configured'
        });
      }

      const deploymentFees = {};
      const executionFees = {};

      // Convert deployment fees to human-readable format
      if (config.smartContracts.deploymentFees) {
        for (const [contractType, fee] of Object.entries(config.smartContracts.deploymentFees)) {
          deploymentFees[contractType] = {
            atomic: fee,
            formatted: fromAtomicUnits(fee) + ' PAS'
          };
        }
      }

      // Convert execution fees to human-readable format
      if (config.smartContracts.executionFees) {
        for (const [method, fee] of Object.entries(config.smartContracts.executionFees)) {
          executionFees[method] = {
            atomic: fee,
            formatted: fee === 0 ? 'Free' : fromAtomicUnits(fee) + ' PAS'
          };
        }
      }

      res.json({
        enabled: config.smartContracts.enabled,
        developmentAddress: config.smartContracts.developmentAddress,
        requiredConfirmations: config.smartContracts.requiredConfirmations || 20,
        minDevelopmentPayment: {
          atomic: config.smartContracts.minDevelopmentPayment || 1,
          formatted: fromAtomicUnits(config.smartContracts.minDevelopmentPayment || 1) + ' PAS'
        },
        deploymentFees,
        executionFees,
        paymentModel: {
          deployment: {
            type: 'full_to_dev',
            description: 'Full deployment fee must be sent to development address',
            example: 'Send 1.00 PAS to development address for TOKEN deployment'
          },
          execution: {
            type: 'min_to_dev_plus_fee',
            description: 'Minimum 0.00000001 PAS to development address + operation fee as transaction fee',
            example: 'Send 0.00000001 PAS to dev address + 0.10 PAS transaction fee for createToken'
          }
        },
        paymentRequirements: {
          address: config.smartContracts.developmentAddress,
          confirmations: config.smartContracts.requiredConfirmations || 20,
          deployment: 'Send full fee amount to development address',
          execution: 'Send minimum 0.00000001 PAS to development address + set transaction fee to operation cost'
        },
        note: 'Deployment fees go to developers, execution fees go to miners (with small dev payment)',
        feeStructure: {
          deployment: 'Full fee to development address (developers earn from contract creation)',
          execution: 'Minimum amount to dev address + transaction fee to miners (miners earn from operations)',
          readOperations: 'Free operations that only read data'
        }
      });
    } catch (error) {
      logger.error('API', `Error getting contract fees: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Get all contracts
   */
  getAllContracts(req, res) {
    try {
      const contracts = this.blockchain.getAllContracts();
      res.json({
        contracts,
        count: contracts.length
      });
    } catch (error) {
      logger.error('API', `Error getting contracts: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Get specific contract information
   */
  getContract(req, res) {
    try {
      const { address } = req.params;

      if (!address) {
        return res.status(400).json({
          error: 'Contract address is required'
        });
      }

      const contract = this.blockchain.getContract(address);
      res.json(contract);
    } catch (error) {
      if (error.message.includes('not found')) {
        return res.status(404).json({
          error: error.message
        });
      }

      logger.error('API', `Error getting contract: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Deploy a new contract with mandatory payment verification
   */
  async deployContract(req, res) {
    try {
      const { contractType, initData, owner, paymentTxId } = req.body;

      // Validate input
      if (!contractType) {
        return res.status(400).json({
          error: 'Contract type is required'
        });
      }

      if (!owner) {
        return res.status(400).json({
          error: 'Owner address is required'
        });
      }

      if (!paymentTxId) {
        return res.status(400).json({
          error: 'Payment transaction ID is required for contract deployment'
        });
      }

      // Validate owner address
      if (!InputValidator.validateCryptocurrencyAddress(owner)) {
        return res.status(400).json({
          error: 'Invalid owner address format'
        });
      }

      // Check if this payment has already been used for contract deployment
      const existingPayment = this.blockchain.contractEngine.getPaymentStatus(paymentTxId);
      if (existingPayment.verified || existingPayment.status === 'pending') {
        const status = existingPayment.verified ? 'deployed' : 'pending deployment';
        return res.status(409).json({
          error: 'Payment transaction already used',
          details: `Payment ${paymentTxId} was already used for ${existingPayment.operation} (${status})`,
          existingContract: existingPayment.contractAddress || null,
          status: existingPayment.status || 'deployed'
        });
      }

      // PAYMENT SYSTEM: Get required deployment fee and inform user
      let requiredFee;
      try {
        requiredFee = this.blockchain.contractEngine.getDeploymentFee(contractType);
      } catch (error) {
        return res.status(400).json({
          error: `Deployment fee configuration error: ${error.message}`
        });
      }

      // PAYMENT VERIFICATION: Check if payment transaction has enough confirmations
      const requiredConfirmations = this.blockchain.config.smartContracts?.requiredConfirmations || 20;
      const confirmations = this.blockchain.contractEngine.getTransactionConfirmations(paymentTxId);

      if (confirmations < requiredConfirmations) {
        return res.status(400).json({
          error: 'Insufficient payment confirmations',
          details: `Payment transaction requires ${requiredConfirmations} confirmations, currently has ${confirmations}`,
          paymentTxId,
          currentConfirmations: confirmations,
          requiredConfirmations
        });
      }

      // Create contract deployment transaction with payment reference
      // Contract transactions have zero fee - payment is verified separately
      const contractTx = ContractTransaction.createDeployment(
        contractType,
        initData,
        owner,
        0 // Contract transactions don't create fees from nothing
      );

      // PAYMENT SYSTEM: Store the payment transaction ID for verification during execution
      contractTx.paymentTxId = paymentTxId;

      // Generate predictable contract address
      const contractAddress = this.blockchain.contractEngine.generateContractAddress();

      // Add contract address to transaction data
      contractTx.contractData.contractAddress = contractAddress;

      // Add transaction to mempool
      const added = await this.blockchain.addPendingTransaction(contractTx);

      if (!added) {
        return res.status(400).json({
          error: 'Failed to add contract deployment transaction to mempool'
        });
      }

      // PAYMENT TRACKING: Immediately track payment to prevent duplicates
      // This prevents duplicate contract deployments using the same payment
      this.blockchain.contractEngine.paymentTracker.set(paymentTxId, {
        contractAddress,
        operation: 'deployment',
        type: contractType,
        paidAmount: requiredFee,
        verified: false, // Will be set to true when block is mined
        timestamp: Date.now(),
        owner,
        status: 'pending' // Indicates transaction is in mempool
      });

      res.json({
        success: true,
        message: 'Contract deployment transaction created with payment verification',
        transactionId: contractTx.id,
        contractAddress: contractAddress,
        contractType,
        owner,
        paymentTxId,
        requiredFee: fromAtomicUnits(requiredFee) + ' PAS',
        initData: initData || {},
        note: 'Contract will be deployed to ' + contractAddress + ' once transaction is mined and payment is verified'
      });
    } catch (error) {
      logger.error('API', `Error deploying contract: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Get contract tokens
   */
  getContractTokens(req, res) {
    try {
      const { address } = req.params;

      if (!address) {
        return res.status(400).json({
          error: 'Contract address is required'
        });
      }

      const contract = this.blockchain.getContract(address);

      if (contract.type !== 'TOKEN') {
        return res.status(400).json({
          error: 'Contract is not a token contract'
        });
      }

      res.json({
        contractAddress: address,
        tokens: contract.state.tokens || {},
        tokenCount: contract.state.tokenCount || 0
      });
    } catch (error) {
      if (error.message.includes('not found')) {
        return res.status(404).json({
          error: error.message
        });
      }

      logger.error('API', `Error getting contract tokens: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Get specific token information
   */
  getToken(req, res) {
    try {
      const { address, tokenId } = req.params;

      if (!address || !tokenId) {
        return res.status(400).json({
          error: 'Contract address and token ID are required'
        });
      }

      // Execute contract method to get token info
      const result = this.blockchain.contractEngine.executeContract(
        address,
        'getToken',
        { tokenId },
        'system' // System call for read operations
      );

      res.json({
        contractAddress: address,
        tokenId,
        tokenInfo: result.result
      });
    } catch (error) {
      if (error.message.includes('not found') || error.message.includes('does not exist')) {
        return res.status(404).json({
          error: error.message
        });
      }

      logger.error('API', `Error getting token: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Get token balance for a wallet address
   */
  getTokenBalance(req, res) {
    try {
      const { address, tokenId, walletAddress } = req.params;

      if (!address || !tokenId || !walletAddress) {
        return res.status(400).json({
          error: 'Contract address, token ID, and wallet address are required'
        });
      }

      // Execute contract method to get balance
      const result = this.blockchain.contractEngine.executeContract(
        address,
        'getBalance',
        { tokenId, address: walletAddress },
        'system' // System call for read operations
      );

      res.json({
        contractAddress: address,
        tokenId,
        walletAddress,
        balance: result.result
      });
    } catch (error) {
      if (error.message.includes('not found') || error.message.includes('does not exist')) {
        return res.status(404).json({
          error: error.message
        });
      }

      logger.error('API', `Error getting token balance: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Create a new token in a contract with mandatory payment verification
   */
  async createToken(req, res) {
    try {
      const { address } = req.params;
      const { name, symbol, decimals, maxSupply, caller, paymentTxId } = req.body;

      if (!address || !name || !symbol || !caller) {
        return res.status(400).json({
          error: 'Contract address, name, symbol, and caller are required'
        });
      }

      if (!paymentTxId) {
        return res.status(400).json({
          error: 'Payment transaction ID is required for createToken operation'
        });
      }

      // Validate caller address
      if (!InputValidator.validateCryptocurrencyAddress(caller)) {
        return res.status(400).json({
          error: 'Invalid caller address format'
        });
      }

      // PAYMENT SYSTEM: Get required execution fee
      let requiredFee;
      try {
        requiredFee = this.blockchain.contractEngine.getExecutionFee('createToken');
      } catch (error) {
        return res.status(400).json({
          error: `Execution fee configuration error: ${error.message}`
        });
      }

      // Create contract execution transaction with payment reference
      const contractTx = ContractTransaction.createExecution(
        address,
        'createToken',
        { name, symbol, decimals, maxSupply },
        caller,
        requiredFee // Set the actual required fee
      );

      // PAYMENT SYSTEM: Store the payment transaction ID for verification during execution
      contractTx.paymentTxId = paymentTxId;

      // Add transaction to mempool
      const added = await this.blockchain.addPendingTransaction(contractTx);

      if (!added) {
        return res.status(400).json({
          error: 'Failed to add token creation transaction to mempool'
        });
      }

      res.json({
        success: true,
        message: 'Token creation transaction created with payment verification',
        transactionId: contractTx.id,
        contractAddress: address,
        tokenSymbol: symbol,
        caller,
        paymentTxId,
        requiredFee: fromAtomicUnits(requiredFee) + ' PAS'
      });
    } catch (error) {
      logger.error('API', `Error creating token: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Mint tokens
   */
  async mintTokens(req, res) {
    try {
      const { address } = req.params;
      const { tokenId, to, amount, caller, paymentTxId } = req.body;

      if (!address || !tokenId || !to || !amount || !caller) {
        return res.status(400).json({
          error: 'Contract address, token ID, recipient address, amount, and caller are required'
        });
      }

      if (!paymentTxId) {
        return res.status(400).json({
          error: 'Payment transaction ID is required for mint operation'
        });
      }

      // Validate addresses
      if (!InputValidator.validateCryptocurrencyAddress(caller) || !InputValidator.validateCryptocurrencyAddress(to)) {
        return res.status(400).json({
          error: 'Invalid address format'
        });
      }

      // Validate amount
      const validAmount = InputValidator.validateAmount(amount, { min: 0 });
      if (validAmount === null || validAmount <= 0) {
        return res.status(400).json({
          error: 'Invalid amount'
        });
      }

      // PAYMENT SYSTEM: Get required execution fee
      let requiredFee;
      try {
        requiredFee = this.blockchain.contractEngine.getExecutionFee('mint');
      } catch (error) {
        return res.status(400).json({
          error: `Execution fee configuration error: ${error.message}`
        });
      }

      // Create contract execution transaction with payment reference
      const contractTx = ContractTransaction.createExecution(
        address,
        'mint',
        { tokenId, to, amount: validAmount },
        caller,
        requiredFee
      );

      // PAYMENT SYSTEM: Store the payment transaction ID for verification
      contractTx.paymentTxId = paymentTxId;

      // Add transaction to mempool
      const added = await this.blockchain.addPendingTransaction(contractTx);

      if (!added) {
        return res.status(400).json({
          error: 'Failed to add mint transaction to mempool'
        });
      }

      res.json({
        success: true,
        message: 'Token mint transaction created with payment verification',
        transactionId: contractTx.id,
        contractAddress: address,
        tokenId,
        to,
        amount: validAmount,
        caller,
        paymentTxId,
        requiredFee: fromAtomicUnits(requiredFee) + ' PAS'
      });
    } catch (error) {
      logger.error('API', `Error minting tokens: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Burn tokens
   */
  async burnTokens(req, res) {
    try {
      const { address } = req.params;
      const { tokenId, from, amount, caller, paymentTxId } = req.body;

      if (!address || !tokenId || !from || !amount || !caller) {
        return res.status(400).json({
          error: 'Contract address, token ID, source address, amount, and caller are required'
        });
      }

      if (!paymentTxId) {
        return res.status(400).json({
          error: 'Payment transaction ID is required for burn operation'
        });
      }

      // Validate addresses
      if (!InputValidator.validateCryptocurrencyAddress(caller) || !InputValidator.validateCryptocurrencyAddress(from)) {
        return res.status(400).json({
          error: 'Invalid address format'
        });
      }

      // Validate amount
      const validAmount = InputValidator.validateAmount(amount, { min: 0 });
      if (validAmount === null || validAmount <= 0) {
        return res.status(400).json({
          error: 'Invalid amount'
        });
      }

      // PAYMENT SYSTEM: Get required execution fee
      let requiredFee;
      try {
        requiredFee = this.blockchain.contractEngine.getExecutionFee('burn');
      } catch (error) {
        return res.status(400).json({
          error: `Execution fee configuration error: ${error.message}`
        });
      }

      // Create contract execution transaction with payment reference
      const contractTx = ContractTransaction.createExecution(
        address,
        'burn',
        { tokenId, from, amount: validAmount },
        caller,
        requiredFee
      );

      // PAYMENT SYSTEM: Store the payment transaction ID for verification
      contractTx.paymentTxId = paymentTxId;

      // Add transaction to mempool
      const added = await this.blockchain.addPendingTransaction(contractTx);

      if (!added) {
        return res.status(400).json({
          error: 'Failed to add burn transaction to mempool'
        });
      }

      res.json({
        success: true,
        message: 'Token burn transaction created with payment verification',
        transactionId: contractTx.id,
        contractAddress: address,
        tokenId,
        from,
        amount: validAmount,
        caller,
        paymentTxId,
        requiredFee: fromAtomicUnits(requiredFee) + ' PAS'
      });
    } catch (error) {
      logger.error('API', `Error burning tokens: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Transfer tokens
   */
  async transferTokens(req, res) {
    try {
      const { address } = req.params;
      const { tokenId, from, to, amount, caller, paymentTxId } = req.body;

      if (!address || !tokenId || !from || !to || !amount || !caller) {
        return res.status(400).json({
          error: 'Contract address, token ID, from/to addresses, amount, and caller are required'
        });
      }

      if (!paymentTxId) {
        return res.status(400).json({
          error: 'Payment transaction ID is required for transfer operation'
        });
      }

      // Validate addresses
      if (!InputValidator.validateCryptocurrencyAddress(caller) ||
          !InputValidator.validateCryptocurrencyAddress(from) ||
          !InputValidator.validateCryptocurrencyAddress(to)) {
        return res.status(400).json({
          error: 'Invalid address format'
        });
      }

      // Validate amount
      const validAmount = InputValidator.validateAmount(amount, { min: 0 });
      if (validAmount === null || validAmount <= 0) {
        return res.status(400).json({
          error: 'Invalid amount'
        });
      }

      // PAYMENT SYSTEM: Get required execution fee
      let requiredFee;
      try {
        requiredFee = this.blockchain.contractEngine.getExecutionFee('transfer');
      } catch (error) {
        return res.status(400).json({
          error: `Execution fee configuration error: ${error.message}`
        });
      }

      // Create contract execution transaction with payment reference
      const contractTx = ContractTransaction.createExecution(
        address,
        'transfer',
        { tokenId, from, to, amount: validAmount },
        caller,
        requiredFee
      );

      // PAYMENT SYSTEM: Store the payment transaction ID for verification
      contractTx.paymentTxId = paymentTxId;

      // Add transaction to mempool
      const added = await this.blockchain.addPendingTransaction(contractTx);

      if (!added) {
        return res.status(400).json({
          error: 'Failed to add transfer transaction to mempool'
        });
      }

      res.json({
        success: true,
        message: 'Token transfer transaction created with payment verification',
        transactionId: contractTx.id,
        contractAddress: address,
        tokenId,
        from,
        to,
        amount: validAmount,
        caller,
        paymentTxId,
        requiredFee: fromAtomicUnits(requiredFee) + ' PAS'
      });
    } catch (error) {
      logger.error('API', `Error transferring tokens: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Grant permission to an address
   */
  async grantPermission(req, res) {
    try {
      const { address } = req.params;
      const { to, permission, caller, paymentTxId } = req.body;

      if (!address || !to || !permission || !caller) {
        return res.status(400).json({
          error: 'Contract address, recipient address, permission, and caller are required'
        });
      }

      if (!paymentTxId) {
        return res.status(400).json({
          error: 'Payment transaction ID is required for grantPermission operation'
        });
      }

      // Validate addresses
      if (!InputValidator.validateCryptocurrencyAddress(caller) || !InputValidator.validateCryptocurrencyAddress(to)) {
        return res.status(400).json({
          error: 'Invalid address format'
        });
      }

      // PAYMENT SYSTEM: Get required execution fee
      let requiredFee;
      try {
        requiredFee = this.blockchain.contractEngine.getExecutionFee('grantPermission');
      } catch (error) {
        return res.status(400).json({
          error: `Execution fee configuration error: ${error.message}`
        });
      }

      // Create contract execution transaction with payment reference
      const contractTx = ContractTransaction.createExecution(
        address,
        'grantPermission',
        { to, permission },
        caller,
        requiredFee
      );

      // PAYMENT SYSTEM: Store the payment transaction ID for verification
      contractTx.paymentTxId = paymentTxId;

      // Add transaction to mempool
      const added = await this.blockchain.addPendingTransaction(contractTx);

      if (!added) {
        return res.status(400).json({
          error: 'Failed to add permission grant transaction to mempool'
        });
      }

      res.json({
        success: true,
        message: 'Permission grant transaction created with payment verification',
        transactionId: contractTx.id,
        contractAddress: address,
        to,
        permission,
        caller,
        paymentTxId,
        requiredFee: fromAtomicUnits(requiredFee) + ' PAS'
      });
    } catch (error) {
      logger.error('API', `Error granting permission: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Revoke permission from an address
   */
  async revokePermission(req, res) {
    try {
      const { address } = req.params;
      const { from, permission, caller, paymentTxId } = req.body;

      if (!address || !from || !permission || !caller) {
        return res.status(400).json({
          error: 'Contract address, target address, permission, and caller are required'
        });
      }

      if (!paymentTxId) {
        return res.status(400).json({
          error: 'Payment transaction ID is required for revokePermission operation'
        });
      }

      // Validate addresses
      if (!InputValidator.validateCryptocurrencyAddress(caller) || !InputValidator.validateCryptocurrencyAddress(from)) {
        return res.status(400).json({
          error: 'Invalid address format'
        });
      }

      // PAYMENT SYSTEM: Get required execution fee
      let requiredFee;
      try {
        requiredFee = this.blockchain.contractEngine.getExecutionFee('revokePermission');
      } catch (error) {
        return res.status(400).json({
          error: `Execution fee configuration error: ${error.message}`
        });
      }

      // Create contract execution transaction with payment reference
      const contractTx = ContractTransaction.createExecution(
        address,
        'revokePermission',
        { from, permission },
        caller,
        requiredFee
      );

      // PAYMENT SYSTEM: Store the payment transaction ID for verification
      contractTx.paymentTxId = paymentTxId;

      // Add transaction to mempool
      const added = await this.blockchain.addPendingTransaction(contractTx);

      if (!added) {
        return res.status(400).json({
          error: 'Failed to add permission revoke transaction to mempool'
        });
      }

      res.json({
        success: true,
        message: 'Permission revoke transaction created with payment verification',
        transactionId: contractTx.id,
        contractAddress: address,
        from,
        permission,
        caller,
        paymentTxId,
        requiredFee: fromAtomicUnits(requiredFee) + ' PAS'
      });
    } catch (error) {
      logger.error('API', `Error revoking permission: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Get comprehensive network diagnostics for debugging P2P issues
   */
  getNetworkDiagnostics(req, res) {
    try {
      const networkSync = this.networkSync;
      const peerManager = this.peerManager;
      const memoryPoolManager = this.blockchain.memoryPool;

      // Get all peers and their connection states
      const peers = peerManager.getAllPeers();
      const peerDetails = peers.map(peer => ({
        remoteAddress: peer.remoteAddress || 'unknown',
        url: peer.url || 'unknown',
        readyState: peer.readyState,
        readyStateText: this.getReadyStateText(peer.readyState),
        isConnected: peer.readyState === 1, // WebSocket.OPEN
        connectionTime: peer.connectionTime || null,
        lastMessageTime: peer.lastMessageTime || null
      }));

      // Get mempool status
      const mempoolStatus = {
        pendingTransactions: memoryPoolManager.getPendingTransactionCount(),
        mempoolSize: memoryPoolManager.pendingTransactions.size,
        recentTransactions: Array.from(memoryPoolManager.pendingTransactions.values()).slice(-5).map(tx => ({
          id: tx.id,
          type: tx.type,
          tag: tx.tag,
          timestamp: tx.timestamp
        }))
      };

      // Get network sync status
      const syncStatus = networkSync.getNetworkSyncStatus();

      // Get last broadcast attempts (if available)
      const diagnostics = {
        timestamp: Date.now(),
        peerConnectivity: {
          totalPeers: peers.length,
          connectedPeers: peerDetails.filter(p => p.isConnected).length,
          peerDetails
        },
        mempool: mempoolStatus,
        networkSync: syncStatus,
        broadcastCapability: {
          canBroadcast: peers.length > 0 && peerDetails.some(p => p.isConnected),
          lastBroadcastTest: 'Not implemented yet'
        }
      };

      res.json(diagnostics);
    } catch (error) {
      logger.error('API', `Error getting network diagnostics: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Convert WebSocket readyState to human-readable text
   */
  getReadyStateText(readyState) {
    const states = {
      0: 'CONNECTING',
      1: 'OPEN',
      2: 'CLOSING',
      3: 'CLOSED'
    };
    return states[readyState] || 'UNKNOWN';
  }

  /**
   * Get peer discovery statistics
   */
  getPeerDiscoveryStats(req, res) {
    try {
      const stats = this.p2pNetwork.getPeerDiscoveryStats();
      res.json({
        success: true,
        stats
      });
    } catch (error) {
      logger.error('API', `Error getting peer discovery stats: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Add a known peer manually
   */
  addKnownPeer(req, res) {
    // API key protection
    if (!this.verifyApiKey(req)) {
      return res.status(401).json({ error: 'Unauthorized - Valid API key required' });
    }

    try {
      const { address, port = 23000, discoveredBy = 'manual' } = req.body;

      if (!address) {
        return res.status(400).json({
          error: 'Address is required'
        });
      }

      // Basic address validation
      if (typeof address !== 'string' || address.trim() === '') {
        return res.status(400).json({
          error: 'Invalid address format'
        });
      }

      const success = this.p2pNetwork.addKnownPeer(address.trim(), port, discoveredBy);

      res.json({
        success,
        message: success ? 'Peer added successfully' : 'Peer already exists or is banned',
        peer: {
          address: address.trim(),
          port,
          discoveredBy
        }
      });
    } catch (error) {
      logger.error('API', `Error adding known peer: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Ban a peer
   */
  banPeer(req, res) {
    // API key protection
    if (!this.verifyApiKey(req)) {
      return res.status(401).json({ error: 'Unauthorized - Valid API key required' });
    }

    try {
      const { address, reason = 'manual', duration = null } = req.body;

      if (!address) {
        return res.status(400).json({
          error: 'Address is required'
        });
      }

      this.p2pNetwork.banPeer(address, reason, duration);

      res.json({
        success: true,
        message: 'Peer banned successfully',
        bannedPeer: {
          address,
          reason,
          duration: duration ? `${duration}ms` : 'permanent'
        }
      });
    } catch (error) {
      logger.error('API', `Error banning peer: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }

  /**
   * Get list of known peers
   */
  getKnownPeers(req, res) {
    try {
      const stats = this.p2pNetwork.getPeerDiscoveryStats();

      // Get additional peer information if available
      const peerDetails = [];
      if (this.p2pNetwork.peerDiscovery && this.p2pNetwork.peerDiscovery.knownPeers) {
        this.p2pNetwork.peerDiscovery.knownPeers.forEach((peerInfo, address) => {
          peerDetails.push({
            address,
            port: peerInfo.port,
            lastSeen: peerInfo.lastSeen,
            lastConnected: peerInfo.lastConnected,
            connectionCount: peerInfo.connectionCount,
            failureCount: peerInfo.failureCount,
            reputation: peerInfo.reputation,
            isReliable: peerInfo.isReliable,
            discoveredBy: peerInfo.discoveredBy,
            isActive: this.p2pNetwork.peerDiscovery.activePeers.has(address)
          });
        });
      }

      res.json({
        success: true,
        summary: stats,
        peers: peerDetails.sort((a, b) => b.reputation - a.reputation)
      });
    } catch (error) {
      logger.error('API', `Error getting known peers: ${error.message}`);
      res.status(500).json({
        error: 'Internal server error',
        details: error.message
      });
    }
  }
}

module.exports = APIServer;
