const logger = require('../../utils/logger');
const { fromAtomicUnits, getHalvingInfo } = require('../../utils/atomicUnits');
const Block = require('../../models/Block');

/**
 * BLOCKCHAIN SERVICE
 *
 * Features:
 * 6. Current blockchain height, latest block hash, and difficulty
 * 7. Recent blocks table with details (hash, timestamp, transactions, miner)
 * 8. Block explorer - view any block by height or hash
 * 9. Blockchain statistics (total supply, average block time, etc.)
 * 10. Chain validation status and integrity checks
 * 11. Halving countdown and reward information
 * 12. Genesis block information display
 */
class BlockchainService {
  constructor(daemon) {
    this.daemon = daemon;
    this.blockchain = daemon.blockchain;

    // Cache for frequently accessed data
    this.cache = {
      recentBlocks: [],
      statistics: null,
      lastUpdate: 0
    };

    // Update cache every 30 seconds
    this.cacheUpdateInterval = 30000;
    this.startCacheUpdates();

    logger.debug('BLOCKCHAIN_SERVICE', 'Blockchain service initialized');
  }

  /**
   * Feature 6: Current blockchain height, latest block hash, and difficulty
   */
  getCurrentBlockchainStatus() {
    try {
      if (!this.blockchain) {
        return { error: 'Blockchain not available' };
      }

      const latestBlock = this.blockchain.getLatestBlock();
      const chain = this.blockchain.chain || [];

      return {
        height: chain.length,
        latestBlock: latestBlock ? {
          hash: latestBlock.hash,
          index: latestBlock.index,
          timestamp: latestBlock.timestamp,
          difficulty: latestBlock.difficulty,
          nonce: latestBlock.nonce,
          transactions: latestBlock.transactions?.length || 0,
          size: JSON.stringify(latestBlock).length,
          algorithm: latestBlock.algorithm || 'unknown'
        } : null,
        difficulty: {
          current: latestBlock?.difficulty || 0,
          algorithm: this.blockchain.difficultyAlgorithm || 'unknown',
          blocks: this.blockchain.difficultyBlocks || 2016,
          minimum: this.blockchain.difficultyMinimum || 1
        },
        totalTransactions: this.getTotalTransactionCount(),
        lastBlockTime: latestBlock?.timestamp || 0,
        averageBlockTime: this.getAverageBlockTime(),
        hashRate: this.estimateNetworkHashRate(),
        status: 'active'
      };
    } catch (error) {
      logger.error('BLOCKCHAIN_SERVICE', `Error getting blockchain status: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Feature 7: Recent blocks table with details
   */
  getRecentBlocks(limit = 10) {
    try {
      if (!this.blockchain || !this.blockchain.chain) {
        return [];
      }

      const chain = this.blockchain.chain;
      const startIndex = Math.max(0, chain.length - limit);
      const recentBlocks = chain.slice(startIndex).reverse();

      return recentBlocks.map(block => ({
        hash: block.hash,
        index: block.index,
        timestamp: block.timestamp,
        age: Date.now() - block.timestamp,
        transactions: block.transactions?.length || 0,
        difficulty: block.difficulty,
        nonce: block.nonce,
        size: JSON.stringify(block).length,
        algorithm: block.algorithm || 'unknown',
        miner: this.extractMinerAddress(block),
        reward: this.calculateBlockReward(block),
        fees: this.calculateBlockFees(block),
        merkleRoot: block.merkleRoot,
        previousHash: block.previousHash
      }));
    } catch (error) {
      logger.error('BLOCKCHAIN_SERVICE', `Error getting recent blocks: ${error.message}`);
      return [];
    }
  }

  /**
   * Feature 8: Block explorer - view any block by height or hash
   */
  getBlock(identifier) {
    try {
      if (!this.blockchain || !this.blockchain.chain) {
        return null;
      }

      let block = null;

      // Check if identifier is a number (block height)
      if (/^\d+$/.test(identifier)) {
        const height = parseInt(identifier);
        if (height >= 0 && height < this.blockchain.chain.length) {
          block = this.blockchain.chain[height];
        }
      } else {
        // Search by hash
        block = this.blockchain.chain.find(b => b.hash === identifier);
      }

      if (!block) {
        return null;
      }

      // Enhance block with additional information
      const enhancedBlock = {
        ...block,
        size: JSON.stringify(block).length,
        age: Date.now() - block.timestamp,
        miner: this.extractMinerAddress(block),
        reward: this.calculateBlockReward(block),
        fees: this.calculateBlockFees(block),
        confirmations: this.blockchain.chain.length - block.index,
        isGenesis: block.index === 0,
        nextBlock: block.index < this.blockchain.chain.length - 1 ?
          this.blockchain.chain[block.index + 1]?.hash : null,
        transactionDetails: block.transactions?.map(tx => ({
          id: tx.id,
          inputs: tx.inputs?.length || 0,
          outputs: tx.outputs?.length || 0,
          amount: this.calculateTransactionAmount(tx),
          fee: tx.fee || 0,
          isCoinbase: tx.isCoinbase || false,
          tag: tx.tag,
          timestamp: tx.timestamp
        })) || []
      };

      return enhancedBlock;
    } catch (error) {
      logger.error('BLOCKCHAIN_SERVICE', `Error getting block ${identifier}: ${error.message}`);
      return null;
    }
  }

  /**
   * Feature 9: Blockchain statistics
   */
  getBlockchainStatistics() {
    try {
      if (!this.blockchain || !this.blockchain.chain) {
        return { error: 'Blockchain not available' };
      }

      const now = Date.now();

      // Use cache if recent
      if (this.cache.statistics && (now - this.cache.lastUpdate) < this.cacheUpdateInterval) {
        return this.cache.statistics;
      }

      const chain = this.blockchain.chain;
      const latestBlock = this.blockchain.getLatestBlock();

      // Calculate total supply
      const totalSupply = this.calculateTotalSupply();

      // Calculate average block time
      const averageBlockTime = this.getAverageBlockTime();

      // Calculate hash rate estimate
      const hashRateEstimate = this.estimateNetworkHashRate();

      // Get halving information
      const halvingInfo = this.getHalvingInformation();

      // Calculate transaction statistics
      const transactionStats = this.getTransactionStatistics();

      const statistics = {
        basic: {
          height: chain.length,
          totalTransactions: this.getTotalTransactionCount(),
          totalSupply: totalSupply,
          circulatingSupply: totalSupply, // Same as total for now
          averageBlockTime: averageBlockTime,
          targetBlockTime: this.blockchain.blockTime || 60000,
          lastBlockTime: latestBlock?.timestamp || 0
        },
        mining: {
          currentDifficulty: latestBlock?.difficulty || 0,
          hashRateEstimate: hashRateEstimate,
          algorithm: this.blockchain.difficultyAlgorithm || 'unknown',
          nextDifficultyAdjustment: this.getNextDifficultyAdjustment(),
          blocksUntilAdjustment: this.getBlocksUntilDifficultyAdjustment()
        },
        rewards: {
          currentReward: this.blockchain.getCurrentMiningReward ?
            fromAtomicUnits(this.blockchain.getCurrentMiningReward()) : 0,
          halvingInfo: halvingInfo
        },
        transactions: transactionStats,
        security: {
          totalWork: this.calculateTotalWork(),
          securityBudget: this.calculateSecurityBudget(),
          decentralization: this.calculateDecentralizationMetrics()
        },
        performance: {
          averageBlockSize: this.getAverageBlockSize(),
          transactionThroughput: this.getTransactionThroughput(),
          blockProcessingTime: this.getAverageBlockProcessingTime()
        }
      };

      // Update cache
      this.cache.statistics = statistics;
      this.cache.lastUpdate = now;

      return statistics;
    } catch (error) {
      logger.error('BLOCKCHAIN_SERVICE', `Error getting blockchain statistics: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Feature 10: Chain validation status and integrity checks
   */
  getChainValidationStatus() {
    try {
      if (!this.blockchain) {
        return { valid: false, error: 'Blockchain not available' };
      }

      // Perform basic chain validation
      const validationResult = this.performChainValidation();

      return {
        valid: validationResult.valid,
        height: this.blockchain.chain?.length || 0,
        lastValidation: new Date().toISOString(),
        checks: validationResult.checks,
        errors: validationResult.errors,
        warnings: validationResult.warnings,
        integrity: {
          hashChain: validationResult.hashChainValid,
          transactions: validationResult.transactionsValid,
          timestamps: validationResult.timestampsValid,
          difficulty: validationResult.difficultyValid,
          merkleRoots: validationResult.merkleRootsValid
        }
      };
    } catch (error) {
      logger.error('BLOCKCHAIN_SERVICE', `Error validating chain: ${error.message}`);
      return { valid: false, error: error.message };
    }
  }

  /**
   * Feature 11: Halving countdown and reward information
   */
  getHalvingInformation() {
    try {
      if (!this.blockchain || typeof this.blockchain.getHalvingInfo !== 'function') {
        // Fallback calculation
        const baseReward = this.blockchain?.config?.blockchain?.coinbaseReward || 5000000000;
        const halvingBlocks = this.blockchain?.config?.blockchain?.halvingBlocks || 210000;
        const currentHeight = this.blockchain?.chain?.length || 0;

        const nextHalvingHeight = Math.ceil((currentHeight + 1) / halvingBlocks) * halvingBlocks;
        const blocksUntilHalving = Math.max(0, nextHalvingHeight - currentHeight);

        return {
          currentReward: fromAtomicUnits(baseReward),
          nextReward: fromAtomicUnits(Math.floor(baseReward / 2)),
          blocksUntilHalving: blocksUntilHalving,
          estimatedTimeUntilHalving: blocksUntilHalving * (this.blockchain.blockTime || 60000),
          halvingHeight: nextHalvingHeight,
          halvingNumber: Math.floor(currentHeight / halvingBlocks) + 1
        };
      }

      if (typeof this.blockchain.getHalvingInfo !== 'function') {
        const baseReward = this.blockchain?.config?.blockchain?.coinbaseReward || 5000000000;
        const halvingBlocks = this.blockchain?.config?.blockchain?.halvingBlocks || 210000;
        const currentHeight = this.blockchain?.chain?.length || 0;
        const nextHalvingHeight = Math.ceil((currentHeight + 1) / halvingBlocks) * halvingBlocks;
        const blocksUntilHalving = Math.max(0, nextHalvingHeight - currentHeight);

        return {
          currentReward: fromAtomicUnits(baseReward),
          nextReward: fromAtomicUnits(Math.floor(baseReward / 2)),
          blocksUntilHalving: blocksUntilHalving,
          estimatedTimeUntilHalving: blocksUntilHalving * (this.blockchain?.blockTime || 60000),
          halvingHeight: nextHalvingHeight,
          halvingNumber: Math.floor(currentHeight / halvingBlocks) + 1
        };
      }

      const halvingInfo = this.blockchain.getHalvingInfo();
      if (!halvingInfo || typeof halvingInfo.currentReward === 'undefined') {
        const baseReward = this.blockchain?.config?.blockchain?.coinbaseReward || 5000000000;
        const halvingBlocks = this.blockchain?.config?.blockchain?.halvingBlocks || 210000;
        const currentHeight = this.blockchain?.chain?.length || 0;
        const nextHalvingHeight = Math.ceil((currentHeight + 1) / halvingBlocks) * halvingBlocks;
        const blocksUntilHalving = Math.max(0, nextHalvingHeight - currentHeight);

        return {
          currentReward: fromAtomicUnits(baseReward),
          nextReward: fromAtomicUnits(Math.floor(baseReward / 2)),
          blocksUntilHalving: blocksUntilHalving,
          estimatedTimeUntilHalving: blocksUntilHalving * (this.blockchain?.blockTime || 60000),
          halvingHeight: nextHalvingHeight,
          halvingNumber: Math.floor(currentHeight / halvingBlocks) + 1
        };
      }

      return {
        currentReward: typeof halvingInfo.currentReward === 'number' ? fromAtomicUnits(halvingInfo.currentReward) : 0,
        nextReward: typeof halvingInfo.nextReward === 'number' ? fromAtomicUnits(halvingInfo.nextReward) : 0,
        blocksUntilHalving: halvingInfo.blocksUntilHalving || 0,
        estimatedTimeUntilHalving: (halvingInfo.blocksUntilHalving || 0) * (this.blockchain.blockTime || 60000),
        halvingHeight: halvingInfo.nextHalvingHeight || 0,
        halvingNumber: (halvingInfo.halvingEpoch || 0) + 1,
        totalHalvings: halvingInfo.totalHalvings || 0
      };
    } catch (error) {
      logger.error('BLOCKCHAIN_SERVICE', `Error getting halving info: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Feature 12: Genesis block information display
   */
  getGenesisBlockInfo() {
    try {
      if (!this.blockchain || !this.blockchain.chain || this.blockchain.chain.length === 0) {
        return { error: 'Genesis block not available' };
      }

      const genesisBlock = this.blockchain.chain[0];
      const config = this.blockchain.config;

      return {
        block: {
          hash: genesisBlock.hash,
          timestamp: genesisBlock.timestamp,
          difficulty: genesisBlock.difficulty,
          nonce: genesisBlock.nonce,
          merkleRoot: genesisBlock.merkleRoot,
          algorithm: genesisBlock.algorithm || 'unknown',
          size: JSON.stringify(genesisBlock).length
        },
        premine: {
          address: config?.blockchain?.genesis?.premineAddress || 'unknown',
          amount: config?.blockchain?.genesis?.premineAmount ?
            fromAtomicUnits(config.blockchain.genesis.premineAmount) : 0,
          transactions: genesisBlock.transactions?.length || 0
        },
        network: {
          networkId: config?.networkId || 'unknown',
          name: config?.name || 'Unknown',
          ticker: config?.ticker || 'UNK'
        },
        creation: {
          timestamp: genesisBlock.timestamp,
          date: new Date(genesisBlock.timestamp).toISOString(),
          age: Date.now() - genesisBlock.timestamp
        }
      };
    } catch (error) {
      logger.error('BLOCKCHAIN_SERVICE', `Error getting genesis block info: ${error.message}`);
      return { error: error.message };
    }
  }

  // Helper methods

  extractMinerAddress(block) {
    try {
      const coinbaseTx = block.transactions?.find(tx => tx.isCoinbase);
      return coinbaseTx?.outputs?.[0]?.address || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  calculateBlockReward(block) {
    try {
      const coinbaseTx = block.transactions?.find(tx => tx.isCoinbase);
      if (!coinbaseTx) return 0;

      const totalOutput = coinbaseTx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
      return fromAtomicUnits(totalOutput);
    } catch {
      return 0;
    }
  }

  calculateBlockFees(block) {
    try {
      const regularTxs = block.transactions?.filter(tx => !tx.isCoinbase) || [];
      return regularTxs.reduce((sum, tx) => sum + (tx.fee || 0), 0);
    } catch {
      return 0;
    }
  }

  calculateTransactionAmount(tx) {
    try {
      if (tx.isCoinbase) {
        return tx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
      }
      return tx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
    } catch {
      return 0;
    }
  }

  getTotalTransactionCount() {
    try {
      if (!this.blockchain || !this.blockchain.chain) return 0;
      return this.blockchain.chain.reduce((count, block) =>
        count + (block.transactions?.length || 0), 0);
    } catch {
      return 0;
    }
  }

  calculateTotalSupply() {
    try {
      if (!this.blockchain || !this.blockchain.chain) return 0;

      let totalSupply = 0;
      for (const block of this.blockchain.chain) {
        const coinbaseTx = block.transactions?.find(tx => tx.isCoinbase);
        if (coinbaseTx) {
          totalSupply += coinbaseTx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
        }
      }

      return fromAtomicUnits(totalSupply);
    } catch {
      return 0;
    }
  }

  getAverageBlockTime() {
    try {
      if (!this.blockchain || !this.blockchain.chain || this.blockchain.chain.length < 2) {
        return this.blockchain?.blockTime || 60000;
      }

      const recentBlocks = this.blockchain.chain.slice(-100); // Last 100 blocks
      if (recentBlocks.length < 2) return this.blockchain.blockTime || 60000;

      const timeDiff = recentBlocks[recentBlocks.length - 1].timestamp - recentBlocks[0].timestamp;
      return Math.round(timeDiff / (recentBlocks.length - 1));
    } catch {
      return this.blockchain?.blockTime || 60000;
    }
  }

  estimateNetworkHashRate() {
    try {
      const latestBlock = this.blockchain.getLatestBlock();
      if (!latestBlock) return 0;

      const difficulty = latestBlock.difficulty;
      const blockTime = this.getAverageBlockTime() / 1000; // Convert to seconds

      // Simplified hash rate estimation
      return Math.round(difficulty / blockTime);
    } catch {
      return 0;
    }
  }

  getNextDifficultyAdjustment() {
    try {
      const currentHeight = this.blockchain.chain?.length || 0;
      const adjustmentInterval = this.blockchain.difficultyBlocks || 2016;
      const nextAdjustmentHeight = Math.ceil((currentHeight + 1) / adjustmentInterval) * adjustmentInterval;
      return nextAdjustmentHeight;
    } catch {
      return 0;
    }
  }

  getBlocksUntilDifficultyAdjustment() {
    try {
      const currentHeight = this.blockchain.chain?.length || 0;
      const nextAdjustment = this.getNextDifficultyAdjustment();
      return Math.max(0, nextAdjustment - currentHeight);
    } catch {
      return 0;
    }
  }

  getTransactionStatistics() {
    try {
      const chain = this.blockchain.chain || [];
      let totalTx = 0;
      let totalFees = 0;
      let coinbaseTx = 0;

      for (const block of chain) {
        totalTx += block.transactions?.length || 0;
        coinbaseTx += block.transactions?.filter(tx => tx.isCoinbase).length || 0;
        totalFees += this.calculateBlockFees(block);
      }

      return {
        total: totalTx,
        coinbase: coinbaseTx,
        regular: totalTx - coinbaseTx,
        totalFees: fromAtomicUnits(totalFees),
        averageFee: totalTx > coinbaseTx ? fromAtomicUnits(totalFees / (totalTx - coinbaseTx)) : 0
      };
    } catch {
      return { total: 0, coinbase: 0, regular: 0, totalFees: 0, averageFee: 0 };
    }
  }

  performChainValidation() {
    // Simplified validation - in production this would be more comprehensive
    const checks = {
      hashChainValid: true,
      transactionsValid: true,
      timestampsValid: true,
      difficultyValid: true,
      merkleRootsValid: true
    };

    const errors = [];
    const warnings = [];

    // Basic validation would go here
    // This is a placeholder for comprehensive validation

    return {
      valid: errors.length === 0,
      checks: Object.keys(checks).length,
      errors: errors,
      warnings: warnings,
      ...checks
    };
  }

  calculateTotalWork() {
    try {
      const chain = this.blockchain.chain || [];
      return chain.reduce((work, block) => work + (block.difficulty || 0), 0);
    } catch {
      return 0;
    }
  }

  calculateSecurityBudget() {
    try {
      const latestBlock = this.blockchain.getLatestBlock();
      if (!latestBlock) return 0;

      const reward = this.calculateBlockReward(latestBlock);
      const fees = this.calculateBlockFees(latestBlock);
      return reward + fromAtomicUnits(fees);
    } catch {
      return 0;
    }
  }

  calculateDecentralizationMetrics() {
    // Simplified decentralization metrics
    return {
      uniqueMiners: 0, // Would need to calculate actual unique miners
      giniCoefficient: 0, // Would need to calculate wealth distribution
      nakamotoCoefficient: 0 // Would need to calculate mining concentration
    };
  }

  getAverageBlockSize() {
    try {
      const recentBlocks = this.getRecentBlocks(100);
      if (recentBlocks.length === 0) return 0;

      const totalSize = recentBlocks.reduce((sum, block) => sum + (block.size || 0), 0);
      return Math.round(totalSize / recentBlocks.length);
    } catch {
      return 0;
    }
  }

  getTransactionThroughput() {
    try {
      const recentBlocks = this.getRecentBlocks(100);
      if (recentBlocks.length === 0) return 0;

      const totalTx = recentBlocks.reduce((sum, block) => sum + (block.transactions || 0), 0);
      const timeSpan = recentBlocks.length * (this.getAverageBlockTime() / 1000); // seconds
      return totalTx / timeSpan; // tx per second
    } catch {
      return 0;
    }
  }

  getAverageBlockProcessingTime() {
    // This would need to be measured during actual block processing
    // For now, return a placeholder
    return 100; // ms
  }

  startCacheUpdates() {
    // Update cache every 30 seconds
    setInterval(() => {
      try {
        this.cache.recentBlocks = this.getRecentBlocks(20);
      } catch (error) {
        logger.error('BLOCKCHAIN_SERVICE', `Error updating cache: ${error.message}`);
      }
    }, this.cacheUpdateInterval);
  }
}

module.exports = BlockchainService;