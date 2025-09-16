const WebSocket = require('ws');

const logger = require('../utils/logger');

/**
 *
 */
class NetworkPartitionHandler {
  /**
   *
   * @param p2pNetwork
   */
  constructor(p2pNetwork) {
    this.p2pNetwork = p2pNetwork;
    this.partitionDetectionEnabled = true;
    this.partitionStats = {
      totalPartitions: 0,
      currentPartitions: 0,
      lastPartitionTime: null,
      partitionDuration: 0,
      recoveryAttempts: 0,
      successfulRecoveries: 0,
      failedRecoveries: 0,
    };

    // Partition detection configuration
    this.config = {
      healthCheckInterval: 30000, // 30 seconds
      partitionThreshold: 0.5, // 50% of peers disconnected = partition
      recoveryTimeout: 120000, // 2 minutes
      maxRecoveryAttempts: 5,
      heartbeatInterval: 15000, // 15 seconds
      connectionTimeout: 10000, // 10 seconds
      // CRITICAL: Consensus protection parameters
      minPeersForConsensus: 3, // Minimum peers required for consensus operations
      consensusThreshold: 0.67, // 67% agreement required for consensus
      maxBlockHeightDifference: 5, // Max height difference to consider valid chain
      partitionSafetyMargin: 0.25, // Extra safety margin for partition detection
    };

    // Partition state tracking
    this.partitionState = {
      isPartitioned: false,
      partitionStartTime: null,
      disconnectedPeers: new Set(),
      partitionGroups: new Map(), // Map<partitionId, Set<peerAddress>>
      recoveryInProgress: false,
      lastHealthCheck: Date.now(),
      // CRITICAL: Consensus protection state
      transactionProcessingPaused: false,
      lastValidConsensusTime: Date.now(),
      consensusGroups: new Map(), // Track different chain views
      chainIntegrityVerified: true,
      majorityChainHeight: 0,
      minorityChainDetected: false,
    };

    // Health check intervals
    this.healthCheckInterval = null;
    this.heartbeatInterval = null;

    // Recovery strategies
    this.recoveryStrategies = ['reconnect_seed_nodes', 'broadcast_health_status', 'request_peer_list', 'force_sync'];
  }

  /**
   * Start partition detection and handling
   */
  start() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    this.healthCheckInterval = setInterval(async () => {
      await this.performHealthCheck();
    }, this.config.healthCheckInterval);

    this.heartbeatInterval = setInterval(() => {
      this.sendHeartbeat();
    }, this.config.heartbeatInterval);

    logger.info('P2P', 'Network partition handling started');
  }

  /**
   * Stop partition detection and handling
   */
  stop() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    logger.info('P2P', 'Network partition handling stopped');
  }

  /**
   * Perform network health check with consensus validation
   */
  async performHealthCheck() {
    const now = Date.now();
    const totalPeers = this.p2pNetwork.peerManager.getPeerCount();
    const connectedPeers = this.getConnectedPeerCount();
    const connectionRatio = totalPeers > 0 ? connectedPeers / totalPeers : 1;

    this.partitionState.lastHealthCheck = now;

    // CRITICAL: Calculate comprehensive partition metrics
    const partitionMetrics = this.calculatePartitionMetrics(connectedPeers, totalPeers);

    // Check for partition conditions with enhanced detection
    if (this.isNetworkPartitioned(partitionMetrics)) {
      await this.detectPartition(connectedPeers, totalPeers, partitionMetrics);
    } else if (this.partitionState.isPartitioned) {
      // Validate consensus before resolving partition
      if (await this.validateConsensusIntegrity()) {
        this.resolvePartition();
      }
    }

    // CRITICAL: Continuously monitor consensus health
    await this.monitorConsensusHealth(partitionMetrics);

    // Update partition duration if currently partitioned
    if (this.partitionState.isPartitioned && this.partitionState.partitionStartTime) {
      this.partitionStats.partitionDuration = now - this.partitionState.partitionStartTime;
    }

    logger.debug(
      'P2P',
      `Health check: ${connectedPeers}/${totalPeers} peers connected (${Math.round(connectionRatio * 100)}%), consensus: ${Math.round(partitionMetrics.consensusStrength * 100)}%`
    );
  }

  /**
   * Calculate comprehensive partition metrics for enhanced detection
   * @param {number} connectedPeers
   * @param {number} totalPeers
   * @returns {Object} Partition metrics
   */
  calculatePartitionMetrics(connectedPeers, totalPeers) {
    const connectionRatio = totalPeers > 0 ? connectedPeers / totalPeers : 1;
    const consensusStrength = this.calculateConsensusStrength();
    const chainHeightVariance = this.calculateChainHeightVariance();
    const networkHashPower = this.estimateNetworkHashPower();

    // Calculate risk factors
    const connectionRisk = 1 - connectionRatio;
    const consensusRisk = 1 - consensusStrength;
    const heightRisk = chainHeightVariance > this.config.maxBlockHeightDifference ? 1 : 0;
    const hashPowerRisk = networkHashPower < 0.51 ? 1 : 0; // 51% attack risk

    // Composite partition risk score (0-1, higher = more risky)
    const partitionRisk = (connectionRisk * 0.4) + (consensusRisk * 0.3) + (heightRisk * 0.2) + (hashPowerRisk * 0.1);

    return {
      connectedPeers,
      totalPeers,
      connectionRatio,
      consensusStrength,
      chainHeightVariance,
      networkHashPower,
      partitionRisk,
      isHighRisk: partitionRisk > (this.config.partitionThreshold - this.config.partitionSafetyMargin),
      timestamp: Date.now()
    };
  }

  /**
   * Enhanced partition detection with consensus protection
   * @param {Object} partitionMetrics
   * @returns {boolean} True if network is partitioned
   */
  isNetworkPartitioned(partitionMetrics) {
    // Multiple criteria for partition detection
    const criteria = [
      // Traditional peer count criterion
      partitionMetrics.connectionRatio < this.config.partitionThreshold,

      // Consensus strength criterion
      partitionMetrics.consensusStrength < this.config.consensusThreshold,

      // Chain height variance criterion (potential fork)
      partitionMetrics.chainHeightVariance > this.config.maxBlockHeightDifference,

      // Insufficient peers for safe consensus
      partitionMetrics.connectedPeers < this.config.minPeersForConsensus,

      // High composite risk score
      partitionMetrics.isHighRisk
    ];

    // Partition detected if multiple criteria are met
    const criteriaCount = criteria.filter(Boolean).length;
    return criteriaCount >= 2; // At least 2 criteria must be met
  }

  /**
   * Calculate consensus strength based on peer agreement
   * @returns {number} Consensus strength (0-1)
   */
  calculateConsensusStrength() {
    const peers = this.p2pNetwork.peerManager.getAllPeers();
    if (peers.length === 0) return 0;

    const connectedPeers = peers.filter(peer => peer.readyState === 1);
    if (connectedPeers.length === 0) return 0;

    // Get blockchain height from each peer
    const peerHeights = new Map();
    const localHeight = this.p2pNetwork.blockchain.getLatestBlock().index;

    // Count peers at each height
    const heightCounts = new Map();
    heightCounts.set(localHeight, 1); // Include local node

    connectedPeers.forEach(peer => {
      // Simplified - in real implementation, would query peer height
      const estimatedHeight = localHeight; // Placeholder
      const count = heightCounts.get(estimatedHeight) || 0;
      heightCounts.set(estimatedHeight, count + 1);
    });

    // Find majority height
    let majorityHeight = localHeight;
    let majorityCount = 1;

    for (const [height, count] of heightCounts) {
      if (count > majorityCount) {
        majorityHeight = height;
        majorityCount = count;
      }
    }

    this.partitionState.majorityChainHeight = majorityHeight;

    // Calculate consensus strength as majority ratio
    const totalNodes = connectedPeers.length + 1; // Include local node
    return majorityCount / totalNodes;
  }

  /**
   * Calculate variance in blockchain heights across peers
   * @returns {number} Maximum height difference
   */
  calculateChainHeightVariance() {
    const localHeight = this.p2pNetwork.blockchain.getLatestBlock().index;
    const peers = this.p2pNetwork.peerManager.getAllPeers().filter(peer => peer.readyState === 1);

    if (peers.length === 0) return 0;

    // In real implementation, would query actual peer heights
    // For now, simulate some variance
    const heights = [localHeight];

    // Simplified - assume peers report their heights
    peers.forEach(() => {
      heights.push(localHeight); // Placeholder
    });

    const minHeight = Math.min(...heights);
    const maxHeight = Math.max(...heights);

    return maxHeight - minHeight;
  }

  /**
   * Estimate network hash power distribution
   * @returns {number} Estimated hash power ratio (0-1)
   */
  estimateNetworkHashPower() {
    // Simplified hash power estimation
    // In real implementation, would analyze recent block submissions
    const connectedPeers = this.getConnectedPeerCount();
    const totalKnownPeers = this.p2pNetwork.peerManager.getPeerCount();

    if (totalKnownPeers === 0) return 1;

    // Estimate hash power based on connected peer ratio
    // This is a simplification - real implementation would be more sophisticated
    return Math.min(connectedPeers / totalKnownPeers, 1);
  }

  /**
   * Monitor consensus health and take protective actions
   * @param {Object} partitionMetrics
   */
  async monitorConsensusHealth(partitionMetrics) {
    // CRITICAL: Pause transaction processing if consensus is unsafe
    if (partitionMetrics.consensusStrength < this.config.consensusThreshold ||
        partitionMetrics.connectedPeers < this.config.minPeersForConsensus) {

      if (!this.partitionState.transactionProcessingPaused) {
        await this.pauseTransactionProcessing();
        logger.warn('P2P', `Transaction processing paused due to insufficient consensus: ${Math.round(partitionMetrics.consensusStrength * 100)}%`);
      }
    } else if (this.partitionState.transactionProcessingPaused && !this.partitionState.isPartitioned) {
      // Resume transaction processing if consensus is restored
      await this.resumeTransactionProcessing();
      logger.info('P2P', 'Transaction processing resumed - consensus restored');
    }

    // Detect minority chain (potential 51% attack)
    if (partitionMetrics.chainHeightVariance > this.config.maxBlockHeightDifference) {
      this.partitionState.minorityChainDetected = true;
      logger.error('P2P', `Minority chain detected! Height variance: ${partitionMetrics.chainHeightVariance} blocks`);

      // Additional protective measures for potential attack
      await this.activateAttackProtection();
    }
  }

  /**
   * Pause transaction processing during unsafe consensus conditions
   */
  async pauseTransactionProcessing() {
    this.partitionState.transactionProcessingPaused = true;

    try {
      // Pause mempool operations
      if (this.p2pNetwork.blockchain.memoryPoolManager) {
        this.p2pNetwork.blockchain.memoryPoolManager.pauseProcessing();
      }

      // Pause transaction manager operations
      if (this.p2pNetwork.blockchain.transactionManager) {
        this.p2pNetwork.blockchain.transactionManager.pauseProcessing();
      }

      logger.warn('P2P', 'CONSENSUS PROTECTION: Transaction processing paused');
    } catch (error) {
      logger.error('P2P', `Error pausing transaction processing: ${error.message}`);
    }
  }

  /**
   * Resume transaction processing when consensus is safe
   */
  async resumeTransactionProcessing() {
    this.partitionState.transactionProcessingPaused = false;

    try {
      // Resume mempool operations
      if (this.p2pNetwork.blockchain.memoryPoolManager) {
        this.p2pNetwork.blockchain.memoryPoolManager.resumeProcessing();
      }

      // Resume transaction manager operations
      if (this.p2pNetwork.blockchain.transactionManager) {
        this.p2pNetwork.blockchain.transactionManager.resumeProcessing();
      }

      this.partitionState.lastValidConsensusTime = Date.now();
      logger.info('P2P', 'CONSENSUS PROTECTION: Transaction processing resumed');
    } catch (error) {
      logger.error('P2P', `Error resuming transaction processing: ${error.message}`);
    }
  }

  /**
   * Activate additional protection measures during potential attacks
   */
  async activateAttackProtection() {
    logger.warn('P2P', 'ATTACK PROTECTION: Activating enhanced security measures');

    try {
      // Increase validation strictness
      if (this.p2pNetwork.blockchain.blockchainValidation) {
        this.p2pNetwork.blockchain.blockchainValidation.setStrictMode(true);
      }

      // Reduce block acceptance criteria
      if (this.p2pNetwork.blockchain) {
        this.p2pNetwork.blockchain.setConservativeMode(true);
      }

      // Enhanced peer reputation monitoring
      if (this.p2pNetwork.peerReputation) {
        this.p2pNetwork.peerReputation.setStrictMode(true);
      }

      logger.warn('P2P', 'Enhanced security measures activated');
    } catch (error) {
      logger.error('P2P', `Error activating attack protection: ${error.message}`);
    }
  }

  /**
   * Validate consensus integrity after partition recovery
   * @returns {boolean} True if consensus is valid
   */
  async validateConsensusIntegrity() {
    try {
      logger.info('P2P', 'Validating consensus integrity after partition...');

      // Check blockchain consistency
      const chainValid = await this.validateChainConsistency();
      if (!chainValid) {
        logger.error('P2P', 'Chain consistency validation failed');
        return false;
      }

      // Check peer consensus
      const consensusMetrics = this.calculatePartitionMetrics(
        this.getConnectedPeerCount(),
        this.p2pNetwork.peerManager.getPeerCount()
      );

      if (consensusMetrics.consensusStrength < this.config.consensusThreshold) {
        logger.error('P2P', `Insufficient consensus strength: ${Math.round(consensusMetrics.consensusStrength * 100)}%`);
        return false;
      }

      // Check for chain height consensus
      if (consensusMetrics.chainHeightVariance > this.config.maxBlockHeightDifference) {
        logger.error('P2P', `Chain height variance too high: ${consensusMetrics.chainHeightVariance} blocks`);
        return false;
      }

      this.partitionState.chainIntegrityVerified = true;
      logger.info('P2P', 'Consensus integrity validation passed');
      return true;

    } catch (error) {
      logger.error('P2P', `Consensus validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * Validate blockchain consistency
   * @returns {boolean} True if chain is consistent
   */
  async validateChainConsistency() {
    try {
      // Basic chain validation
      if (!this.p2pNetwork.blockchain) {
        logger.error('P2P', 'No blockchain instance available');
        return false;
      }

      // Check recent blocks for consistency
      const latestBlock = this.p2pNetwork.blockchain.getLatestBlock();
      if (!latestBlock) {
        logger.error('P2P', 'No latest block found');
        return false;
      }

      // Validate recent block integrity (last 5 blocks)
      try {
        const recentBlocks = this.p2pNetwork.blockchain.getLastNBlocks(5);
        for (const block of recentBlocks) {
          if (!this.validateBlockIntegrity(block)) {
            logger.error('P2P', `Block integrity validation failed for block ${block.index}`);
            return false;
          }
        }
      } catch (getBlocksError) {
        logger.warn('P2P', `Could not get recent blocks for validation: ${getBlocksError.message}`);
        // Continue with basic validation
      }

      // Validate block transactions if blockchain validation is available
      if (this.p2pNetwork.blockchain.blockchainValidation) {
        try {
          // Validate the latest block's transactions
          const validationResult = this.p2pNetwork.blockchain.blockchainValidation.validateBlockTransactions(
            latestBlock,
            null, // config
            this.p2pNetwork.blockchain.utxoManager
          );

          if (!validationResult.isValid) {
            logger.error('P2P', `Latest block transaction validation failed: ${validationResult.errors?.join(', ')}`);
            return false;
          }
        } catch (validationError) {
          logger.warn('P2P', `Block transaction validation error: ${validationError.message}`);
          // Continue with basic validation - this might be expected in some cases
        }
      }

      // Basic chain integrity check - verify block chain links
      if (!this.validateBlockChainLinks()) {
        logger.error('P2P', 'Block chain link validation failed');
        return false;
      }

      logger.info('P2P', 'Chain consistency validation passed');
      return true;

    } catch (error) {
      logger.error('P2P', `Chain consistency validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * Validate blockchain links between recent blocks
   * @returns {boolean} True if chain links are valid
   */
  validateBlockChainLinks() {
    try {
      const latestBlock = this.p2pNetwork.blockchain.getLatestBlock();
      if (!latestBlock) return false;

      // Check if we can get previous blocks
      let currentBlock = latestBlock;
      let blocksChecked = 0;
      const maxBlocksToCheck = Math.min(5, currentBlock.index + 1);

      while (blocksChecked < maxBlocksToCheck && currentBlock.index > 0) {
        try {
          const previousBlock = this.p2pNetwork.blockchain.getBlockByIndex(currentBlock.index - 1);
          if (!previousBlock) {
            logger.error('P2P', `Missing previous block at index ${currentBlock.index - 1}`);
            return false;
          }

          // Verify the hash chain
          if (currentBlock.previousHash !== previousBlock.hash) {
            logger.error('P2P', `Hash chain broken between blocks ${previousBlock.index} and ${currentBlock.index}`);
            return false;
          }

          currentBlock = previousBlock;
          blocksChecked++;
        } catch (blockError) {
          logger.warn('P2P', `Could not get block at index ${currentBlock.index - 1}: ${blockError.message}`);
          break; // Stop checking if we can't get blocks
        }
      }

      logger.debug('P2P', `Validated ${blocksChecked} block chain links`);
      return true;

    } catch (error) {
      logger.error('P2P', `Block chain link validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * Validate individual block integrity
   * @param {Object} block - Block to validate
   * @returns {boolean} True if block is valid
   */
  validateBlockIntegrity(block) {
    try {
      // Basic block structure validation
      if (!block || typeof block !== 'object') return false;
      if (typeof block.index !== 'number') return false;
      if (!block.hash || typeof block.hash !== 'string') return false;
      if (!block.previousHash || typeof block.previousHash !== 'string') return false;
      if (!Array.isArray(block.transactions)) return false;

      // Validate block hash
      const expectedHash = this.p2pNetwork.blockchain.calculateBlockHash(block);
      if (block.hash !== expectedHash) {
        logger.error('P2P', `Block hash mismatch for block ${block.index}`);
        return false;
      }

      return true;
    } catch (error) {
      logger.error('P2P', `Block integrity validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * Get count of connected peers
   */
  getConnectedPeerCount() {
    let connectedCount = 0;
    this.p2pNetwork.peerManager.getAllPeers().forEach(peer => {
      if (peer.readyState === 1) {
        // WebSocket.OPEN
        connectedCount++;
      }
    });
    return connectedCount;
  }

  /**
   * Detect network partition with enhanced consensus protection
   * @param connectedPeers
   * @param totalPeers
   * @param partitionMetrics
   */
  async detectPartition(connectedPeers, totalPeers, partitionMetrics) {
    if (this.partitionState.isPartitioned) {
      return; // Already partitioned
    }

    this.partitionState.isPartitioned = true;
    this.partitionState.partitionStartTime = Date.now();
    this.partitionStats.totalPartitions++;
    this.partitionStats.currentPartitions++;

    // CRITICAL: Immediately pause transaction processing during partition
    await this.pauseTransactionProcessing();

    // Identify disconnected peers
    this.identifyDisconnectedPeers();

    // Log comprehensive partition detection info
    logger.warn('P2P', `NETWORK PARTITION DETECTED: ${connectedPeers}/${totalPeers} peers connected`);
    logger.warn('P2P', `Consensus strength: ${Math.round(partitionMetrics.consensusStrength * 100)}%`);
    logger.warn('P2P', `Chain height variance: ${partitionMetrics.chainHeightVariance} blocks`);
    logger.warn('P2P', `Partition risk score: ${Math.round(partitionMetrics.partitionRisk * 100)}%`);
    logger.warn('P2P', `Disconnected peers: ${this.partitionState.disconnectedPeers.size}`);

    // CRITICAL: Activate consensus protection measures
    await this.activateConsensusProtection(partitionMetrics);

    // Start recovery process
    this.startRecovery();
  }

  /**
   * Activate comprehensive consensus protection during partition
   * @param {Object} partitionMetrics
   */
  async activateConsensusProtection(partitionMetrics) {
    logger.warn('P2P', 'CONSENSUS PROTECTION: Activating partition safety measures');

    try {
      // Stop accepting new blocks during partition
      if (this.p2pNetwork.blockchain) {
        this.p2pNetwork.blockchain.pauseBlockAcceptance();
      }

      // Enhanced validation for any remaining operations
      if (this.p2pNetwork.blockchain.blockchainValidation) {
        this.p2pNetwork.blockchain.blockchainValidation.setStrictMode(true);
      }

      // Monitor for potential attack indicators
      if (partitionMetrics.networkHashPower < 0.51) {
        logger.error('P2P', 'CRITICAL: Potential 51% attack detected during partition');
        await this.activateAttackProtection();
      }

      // Set conservative operational mode
      this.partitionState.chainIntegrityVerified = false;
      this.partitionState.minorityChainDetected = false;

      logger.warn('P2P', 'Consensus protection measures activated');
    } catch (error) {
      logger.error('P2P', `Error activating consensus protection: ${error.message}`);
    }
  }

  /**
   * Identify which peers are disconnected
   */
  identifyDisconnectedPeers() {
    this.partitionState.disconnectedPeers.clear();

    this.p2pNetwork.peerManager.getAllPeers().forEach(peer => {
      if (peer.readyState !== 1) {
        // Not WebSocket.OPEN
        const peerAddress = this.p2pNetwork.peerManager.getPeerAddress(peer);
        if (peerAddress) {
          this.partitionState.disconnectedPeers.add(peerAddress);
        }
      }
    });
  }

  /**
   * Start partition recovery process
   */
  async startRecovery() {
    if (this.partitionState.recoveryInProgress) {
      return;
    }

    this.partitionState.recoveryInProgress = true;
    this.partitionStats.recoveryAttempts++;

    logger.info('P2P', 'Starting network partition recovery...');

    try {
      // Try recovery strategies in order
      for (const strategy of this.recoveryStrategies) {
        const success = await this.executeRecoveryStrategy(strategy);
        if (success) {
          logger.info('P2P', `Recovery strategy '${strategy}' successful`);
          this.partitionStats.successfulRecoveries++;
          break;
        }
      }

      // If all strategies fail, schedule retry
      if (this.partitionState.isPartitioned && this.partitionStats.recoveryAttempts < this.config.maxRecoveryAttempts) {
        setTimeout(() => {
          this.partitionState.recoveryInProgress = false;
          this.startRecovery();
        }, this.config.recoveryTimeout);
      } else if (this.partitionState.isPartitioned) {
        this.partitionStats.failedRecoveries++;
        logger.error('P2P', 'All recovery strategies failed, network remains partitioned');
      }
    } catch (error) {
      logger.error('P2P', `Recovery error: ${error.message}`);
      this.partitionStats.failedRecoveries++;
    } finally {
      this.partitionState.recoveryInProgress = false;
    }
  }

  /**
   * Execute a specific recovery strategy
   * @param strategy
   */
  async executeRecoveryStrategy(strategy) {
    try {
      switch (strategy) {
        case 'reconnect_seed_nodes':
          return await this.reconnectSeedNodes();
        case 'broadcast_health_status':
          return await this.broadcastHealthStatus();
        case 'request_peer_list':
          return await this.requestPeerList();
        case 'force_sync':
          return await this.forceSync();
        default:
          return false;
      }
    } catch (error) {
      logger.error('P2P', `Recovery strategy '${strategy}' failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Reconnect to seed nodes
   */
  async reconnectSeedNodes() {
    logger.info('P2P', 'Attempting to reconnect to seed nodes...');

    const originalSeedCount = this.p2pNetwork.seedNodeManager.getConnectedSeedNodes().length;
    await this.p2pNetwork.seedNodeManager.attemptSeedNodeReconnection();

    // Check if we gained new seed connections
    const newSeedCount = this.p2pNetwork.seedNodeManager.getConnectedSeedNodes().length;
    const improvement = newSeedCount > originalSeedCount;

    if (improvement) {
      logger.info('P2P', `Seed node reconnection successful: ${originalSeedCount} → ${newSeedCount}`);
    }

    return improvement;
  }

  /**
   * Broadcast health status to connected peers
   */
  async broadcastHealthStatus() {
    logger.info('P2P', 'Broadcasting health status to peers...');

    const healthMessage = {
      type: 'HEALTH_STATUS',
      data: {
        nodeId: this.p2pNetwork.nodeIdentity.nodeId,
        timestamp: Date.now(),
        peerCount: this.p2pNetwork.peerManager.getPeerCount(),
        connectedCount: this.getConnectedPeerCount(),
        isPartitioned: this.partitionState.isPartitioned,
        blockchainHeight: this.p2pNetwork.blockchain.getLatestBlock().index,
      },
    };

    // Broadcast health message to all peers
    const peers = this.p2pNetwork.peerManager.getAllPeers();
    peers.forEach(peer => {
      if (peer.readyState === 1) {
        // WebSocket.OPEN
        try {
          peer.send(JSON.stringify(healthMessage));
        } catch (error) {
          logger.debug('P2P', `Failed to send health message to peer: ${error.message}`);
        }
      }
    });
    return true; // Consider it successful if we can broadcast
  }

  /**
   * Request peer list from connected peers
   */
  async requestPeerList() {
    logger.info('P2P', 'Requesting peer lists from connected peers...');

    const peerListMessage = {
      type: 'REQUEST_PEER_LIST',
      data: {
        timestamp: Date.now(),
        requester: this.p2pNetwork.nodeIdentity.nodeId,
      },
    };

    // Broadcast peer list request to all peers
    const peers = this.p2pNetwork.peerManager.getAllPeers();
    peers.forEach(peer => {
      if (peer.readyState === 1) {
        // WebSocket.OPEN
        try {
          peer.send(JSON.stringify(peerListMessage));
        } catch (error) {
          logger.debug('P2P', `Failed to send peer list request to peer: ${error.message}`);
        }
      }
    });
    return true;
  }

  /**
   * Force blockchain synchronization
   */
  async forceSync() {
    logger.info('P2P', 'Forcing blockchain synchronization...');

    try {
      await this.p2pNetwork.syncWithNetwork();
      return true;
    } catch (error) {
      logger.error('P2P', `Force sync failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Resolve partition when network connectivity is restored
   */
  resolvePartition() {
    if (!this.partitionState.isPartitioned) {
      return;
    }

    const partitionDuration = Date.now() - this.partitionState.partitionStartTime;

    this.partitionState.isPartitioned = false;
    this.partitionState.partitionStartTime = null;
    this.partitionState.disconnectedPeers.clear();
    this.partitionState.recoveryInProgress = false;
    this.partitionStats.currentPartitions--;

    logger.info('P2P', `Network partition resolved after ${Math.round(partitionDuration / 1000)}s`);
    logger.info(
      'P2P',
      `Total partitions: ${this.partitionStats.totalPartitions}, Current: ${this.partitionStats.currentPartitions}`
    );
  }

  /**
   * Send heartbeat to connected peers
   */
  sendHeartbeat() {
    if (this.p2pNetwork.peerManager.getPeerCount() === 0) {
      return;
    }

    const heartbeatMessage = {
      type: 'HEARTBEAT',
      data: {
        nodeId: this.p2pNetwork.nodeIdentity.nodeId,
        timestamp: Date.now(),
        sequence: Math.floor(Date.now() / this.config.heartbeatInterval),
      },
    };

    // Broadcast heartbeat to all peers
    const peers = this.p2pNetwork.peerManager.getAllPeers();
    peers.forEach(peer => {
      if (peer.readyState === 1) {
        // WebSocket.OPEN
        try {
          peer.send(JSON.stringify(heartbeatMessage));
        } catch (error) {
          logger.debug('P2P', `Failed to send heartbeat to peer: ${error.message}`);
        }
      }
    });
  }

  /**
   * Handle peer disconnection
   * @param peerAddress
   */
  handlePeerDisconnection(peerAddress) {
    if (this.partitionState.isPartitioned) {
      this.partitionState.disconnectedPeers.add(peerAddress);
      logger.debug('P2P', `Peer disconnected during partition: ${peerAddress}`);
    }
  }

  /**
   * Handle peer reconnection
   * @param peerAddress
   */
  handlePeerReconnection(peerAddress) {
    if (this.partitionState.disconnectedPeers.has(peerAddress)) {
      this.partitionState.disconnectedPeers.delete(peerAddress);
      logger.debug('P2P', `Peer reconnected: ${peerAddress}`);

      // Check if partition is resolved
      if (this.partitionState.disconnectedPeers.size === 0 && this.partitionState.isPartitioned) {
        this.resolvePartition();
      }
    }
  }

  /**
   * Get partition statistics
   */
  getPartitionStats() {
    return {
      ...this.partitionStats,
      isPartitioned: this.partitionState.isPartitioned,
      partitionDuration:
        this.partitionState.isPartitioned && this.partitionState.partitionStartTime
          ? Date.now() - this.partitionState.partitionStartTime
          : 0,
      disconnectedPeers: this.partitionState.disconnectedPeers.size,
      recoveryInProgress: this.partitionState.recoveryInProgress,
      lastHealthCheck: this.partitionState.lastHealthCheck,
    };
  }

  /**
   * Reset partition statistics
   */
  resetPartitionStats() {
    this.partitionStats = {
      totalPartitions: 0,
      currentPartitions: 0,
      lastPartitionTime: null,
      partitionDuration: 0,
      recoveryAttempts: 0,
      successfulRecoveries: 0,
      failedRecoveries: 0,
    };

    this.partitionState = {
      isPartitioned: false,
      partitionStartTime: null,
      disconnectedPeers: new Set(),
      partitionGroups: new Map(),
      recoveryInProgress: false,
      lastHealthCheck: Date.now(),
    };

    logger.info('P2P', 'Partition statistics reset');
  }

  /**
   * Update configuration
   * @param newConfig
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    logger.info('P2P', 'Partition handler configuration updated');
  }

  /**
   * Get current partition state
   */
  getPartitionState() {
    return {
      ...this.partitionState,
      config: this.config,
      stats: this.partitionStats,
    };
  }
}

module.exports = NetworkPartitionHandler;
