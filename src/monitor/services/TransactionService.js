const logger = require('../../utils/logger');
const { fromAtomicUnits, toAtomicUnits } = require('../../utils/atomicUnits');

/**
 * Transaction Monitoring Service
 * Implements features 21-27: Transaction monitoring and analysis
 */
class TransactionService {
  constructor(daemon) {
    this.daemon = daemon;
    this.blockchain = daemon.blockchain;
    this.p2pNetwork = daemon.p2pNetwork;
    this.memoryPoolManager = daemon.blockchain?.memoryPoolManager;
    this.transactionManager = daemon.blockchain?.transactionManager;

    // Transaction statistics tracking
    this.transactionStats = {
      startTime: Date.now(),
      totalProcessed: 0,
      totalFees: 0,
      avgBlockTime: 0,
      byType: new Map(),
      byHour: new Map(),
      recentTransactions: []
    };

    logger.debug('TRANSACTION_SERVICE', 'Transaction monitoring service initialized');
  }

  /**
   * Feature 21: Real-time transaction monitoring and mempool status
   */
  getMempoolStatus() {
    try {
      if (!this.memoryPoolManager) {
        return {
          enabled: false,
          error: 'Memory pool manager not available'
        };
      }

      const mempool = this.memoryPoolManager.mempool || [];
      const pendingTransactions = mempool.length;

      // Calculate mempool statistics
      const totalValue = mempool.reduce((sum, tx) => {
        const txValue = tx.outputs?.reduce((outputSum, output) => outputSum + (output.amount || 0), 0) || 0;
        return sum + txValue;
      }, 0);

      const totalFees = mempool.reduce((sum, tx) => sum + (tx.fee || 0), 0);
      const avgFee = pendingTransactions > 0 ? totalFees / pendingTransactions : 0;

      // Group by transaction type
      const byType = {};
      mempool.forEach(tx => {
        const type = tx.tag || 'TRANSACTION';
        byType[type] = (byType[type] || 0) + 1;
      });

      return {
        enabled: true,
        status: pendingTransactions > 0 ? 'active' : 'empty',
        pendingTransactions: pendingTransactions,
        totalValue: fromAtomicUnits(totalValue),
        totalFees: fromAtomicUnits(totalFees),
        averageFee: fromAtomicUnits(avgFee),
        byType: byType,
        oldestTransaction: mempool.length > 0 ? mempool[0].timestamp : null,
        newestTransaction: mempool.length > 0 ? mempool[mempool.length - 1].timestamp : null,
        memoryUsage: JSON.stringify(mempool).length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('TRANSACTION_SERVICE', `Error getting mempool status: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Feature 22: Transaction history and search functionality
   */
  searchTransactions(query, options = {}) {
    try {
      const {
        type = null,
        limit = 50,
        offset = 0,
        fromDate = null,
        toDate = null,
        minAmount = null,
        maxAmount = null
      } = options;

      if (!this.blockchain || !this.blockchain.chain) {
        return { results: [], total: 0 };
      }

      let allTransactions = [];

      // Collect all transactions from blockchain
      this.blockchain.chain.forEach((block, blockIndex) => {
        if (block.transactions && Array.isArray(block.transactions)) {
          block.transactions.forEach(tx => {
            allTransactions.push({
              ...tx,
              blockIndex: blockIndex,
              blockHash: block.hash,
              blockTimestamp: block.timestamp,
              confirmed: true
            });
          });
        }
      });

      // Add mempool transactions
      const mempool = this.memoryPoolManager?.mempool || [];
      mempool.forEach(tx => {
        allTransactions.push({
          ...tx,
          blockIndex: -1,
          blockHash: null,
          blockTimestamp: null,
          confirmed: false
        });
      });

      // Apply filters
      let filteredTransactions = allTransactions;

      if (query && query.trim()) {
        const searchTerm = query.toLowerCase();
        filteredTransactions = filteredTransactions.filter(tx =>
          tx.id?.toLowerCase().includes(searchTerm) ||
          tx.from?.toLowerCase().includes(searchTerm) ||
          tx.to?.toLowerCase().includes(searchTerm) ||
          tx.outputs?.some(output => output.address?.toLowerCase().includes(searchTerm)) ||
          tx.inputs?.some(input => input.address?.toLowerCase().includes(searchTerm))
        );
      }

      if (type) {
        filteredTransactions = filteredTransactions.filter(tx => tx.tag === type);
      }

      if (fromDate) {
        const fromTimestamp = new Date(fromDate).getTime();
        filteredTransactions = filteredTransactions.filter(tx =>
          (tx.blockTimestamp || tx.timestamp) >= fromTimestamp
        );
      }

      if (toDate) {
        const toTimestamp = new Date(toDate).getTime();
        filteredTransactions = filteredTransactions.filter(tx =>
          (tx.blockTimestamp || tx.timestamp) <= toTimestamp
        );
      }

      if (minAmount !== null) {
        const minAtomicAmount = toAtomicUnits(minAmount);
        filteredTransactions = filteredTransactions.filter(tx => {
          const txAmount = tx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
          return txAmount >= minAtomicAmount;
        });
      }

      if (maxAmount !== null) {
        const maxAtomicAmount = toAtomicUnits(maxAmount);
        filteredTransactions = filteredTransactions.filter(tx => {
          const txAmount = tx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
          return txAmount <= maxAtomicAmount;
        });
      }

      // Sort by timestamp (newest first)
      filteredTransactions.sort((a, b) => {
        const timeA = a.blockTimestamp || a.timestamp;
        const timeB = b.blockTimestamp || b.timestamp;
        return timeB - timeA;
      });

      // Apply pagination
      const total = filteredTransactions.length;
      const results = filteredTransactions.slice(offset, offset + limit);

      return {
        results: results.map(tx => this.formatTransactionForDisplay(tx)),
        total: total,
        limit: limit,
        offset: offset,
        hasMore: offset + limit < total
      };
    } catch (error) {
      logger.error('TRANSACTION_SERVICE', `Error searching transactions: ${error.message}`);
      return { results: [], total: 0, error: error.message };
    }
  }

  /**
   * Feature 23: Transaction details viewer with input/output analysis
   */
  getTransactionDetails(transactionId) {
    try {
      if (!transactionId) {
        return { error: 'Transaction ID is required' };
      }

      // Search in blockchain
      let transaction = null;
      let blockInfo = null;

      for (let i = 0; i < (this.blockchain?.chain?.length || 0); i++) {
        const block = this.blockchain.chain[i];
        if (block.transactions && Array.isArray(block.transactions)) {
          const foundTx = block.transactions.find(tx => tx.id === transactionId);
          if (foundTx) {
            transaction = foundTx;
            blockInfo = {
              index: i,
              hash: block.hash,
              timestamp: block.timestamp,
              difficulty: block.difficulty,
              confirmed: true
            };
            break;
          }
        }
      }

      // If not found in blockchain, check mempool
      if (!transaction) {
        const mempool = this.memoryPoolManager?.mempool || [];
        const foundTx = mempool.find(tx => tx.id === transactionId);
        if (foundTx) {
          transaction = foundTx;
          blockInfo = {
            index: -1,
            hash: null,
            timestamp: null,
            confirmed: false
          };
        }
      }

      if (!transaction) {
        return { error: 'Transaction not found' };
      }

      // Calculate transaction statistics
      const inputValue = transaction.inputs?.reduce((sum, input) => sum + (input.amount || 0), 0) || 0;
      const outputValue = transaction.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
      const fee = inputValue - outputValue;

      // Analyze inputs and outputs
      const inputAnalysis = (transaction.inputs || []).map(input => ({
        address: input.address || input.from,
        amount: fromAtomicUnits(input.amount || 0),
        atomicAmount: input.amount || 0,
        transactionId: input.transactionId,
        outputIndex: input.outputIndex,
        signature: input.signature
      }));

      const outputAnalysis = (transaction.outputs || []).map((output, index) => ({
        index: index,
        address: output.address || output.to,
        amount: fromAtomicUnits(output.amount || 0),
        atomicAmount: output.amount || 0,
        spent: false // Would need UTXO lookup to determine this
      }));

      return {
        transaction: {
          id: transaction.id,
          type: transaction.tag || 'TRANSACTION',
          timestamp: transaction.timestamp,
          nonce: transaction.nonce,
          atomicSequence: transaction._atomicSequence,
          size: JSON.stringify(transaction).length
        },
        block: blockInfo,
        amounts: {
          inputValue: fromAtomicUnits(inputValue),
          outputValue: fromAtomicUnits(outputValue),
          fee: fromAtomicUnits(fee),
          atomicInputValue: inputValue,
          atomicOutputValue: outputValue,
          atomicFee: fee
        },
        inputs: inputAnalysis,
        outputs: outputAnalysis,
        analysis: {
          inputCount: transaction.inputs?.length || 0,
          outputCount: transaction.outputs?.length || 0,
          isValid: this.validateTransaction(transaction),
          isCoinbase: transaction.tag === 'COINBASE',
          confirmations: blockInfo.confirmed ? (this.blockchain.chain.length - blockInfo.index) : 0
        }
      };
    } catch (error) {
      logger.error('TRANSACTION_SERVICE', `Error getting transaction details: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Feature 24: Transaction validation and verification
   */
  validateTransaction(transaction) {
    try {
      if (!transaction || !transaction.id) {
        return { valid: false, reason: 'Invalid transaction format' };
      }

      // Use blockchain's transaction manager if available
      if (this.transactionManager && typeof this.transactionManager.validateTransaction === 'function') {
        try {
          const result = this.transactionManager.validateTransaction(transaction);
          return { valid: result.valid || false, reason: result.error || 'Validation completed' };
        } catch (validationError) {
          return { valid: false, reason: validationError.message };
        }
      }

      // Basic validation fallback
      const checks = [];

      // Check transaction structure
      if (!transaction.id || !transaction.timestamp) {
        checks.push('Missing required fields (id, timestamp)');
      }

      // Check inputs/outputs for non-coinbase transactions
      if (transaction.tag !== 'COINBASE' && transaction.tag !== 'PREMINE') {
        if (!transaction.inputs || transaction.inputs.length === 0) {
          checks.push('No inputs provided');
        }
        if (!transaction.outputs || transaction.outputs.length === 0) {
          checks.push('No outputs provided');
        }

        // Check input/output balance
        const inputValue = transaction.inputs?.reduce((sum, input) => sum + (input.amount || 0), 0) || 0;
        const outputValue = transaction.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;

        if (inputValue < outputValue) {
          checks.push('Output value exceeds input value');
        }
      }

      // Check for duplicate spending (simplified check)
      if (transaction.inputs && Array.isArray(transaction.inputs)) {
        const inputKeys = transaction.inputs.map(input => `${input.transactionId}:${input.outputIndex}`);
        const uniqueKeys = [...new Set(inputKeys)];
        if (inputKeys.length !== uniqueKeys.length) {
          checks.push('Duplicate input detected');
        }
      }

      return {
        valid: checks.length === 0,
        reason: checks.length === 0 ? 'Transaction is valid' : checks.join(', '),
        checks: checks
      };
    } catch (error) {
      logger.error('TRANSACTION_SERVICE', `Error validating transaction: ${error.message}`);
      return { valid: false, reason: error.message };
    }
  }

  /**
   * Feature 25: Transaction fee analysis and recommendations
   */
  getFeeAnalysis() {
    try {
      const recentBlocks = this.blockchain?.chain?.slice(-10) || [];
      const mempool = this.memoryPoolManager?.mempool || [];

      let allTransactions = [];

      // Collect recent transactions from blocks
      recentBlocks.forEach(block => {
        if (block.transactions && Array.isArray(block.transactions)) {
          block.transactions.forEach(tx => {
            if (tx.tag !== 'COINBASE' && tx.tag !== 'PREMINE') {
              const inputValue = tx.inputs?.reduce((sum, input) => sum + (input.amount || 0), 0) || 0;
              const outputValue = tx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
              const fee = inputValue - outputValue;

              if (fee > 0) {
                allTransactions.push({
                  fee: fee,
                  size: JSON.stringify(tx).length,
                  timestamp: tx.timestamp,
                  confirmed: true
                });
              }
            }
          });
        }
      });

      // Add mempool transactions
      mempool.forEach(tx => {
        if (tx.tag !== 'COINBASE' && tx.tag !== 'PREMINE') {
          const inputValue = tx.inputs?.reduce((sum, input) => sum + (input.amount || 0), 0) || 0;
          const outputValue = tx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
          const fee = inputValue - outputValue;

          if (fee > 0) {
            allTransactions.push({
              fee: fee,
              size: JSON.stringify(tx).length,
              timestamp: tx.timestamp,
              confirmed: false
            });
          }
        }
      });

      if (allTransactions.length === 0) {
        return {
          enabled: true,
          recommendations: {
            low: fromAtomicUnits(1000),
            medium: fromAtomicUnits(5000),
            high: fromAtomicUnits(10000)
          },
          statistics: {
            totalTransactions: 0,
            averageFee: 0,
            medianFee: 0,
            minFee: 0,
            maxFee: 0
          }
        };
      }

      // Calculate statistics
      const fees = allTransactions.map(tx => tx.fee);
      fees.sort((a, b) => a - b);

      const averageFee = fees.reduce((sum, fee) => sum + fee, 0) / fees.length;
      const medianFee = fees[Math.floor(fees.length / 2)];
      const minFee = fees[0];
      const maxFee = fees[fees.length - 1];

      // Calculate fee per byte
      const feeRates = allTransactions.map(tx => tx.fee / tx.size);
      feeRates.sort((a, b) => a - b);

      const avgFeeRate = feeRates.reduce((sum, rate) => sum + rate, 0) / feeRates.length;

      // Generate recommendations based on current network conditions
      const lowFee = Math.max(minFee, avgFeeRate * 200); // ~200 bytes typical transaction
      const mediumFee = averageFee;
      const highFee = Math.max(averageFee * 1.5, maxFee * 0.8);

      return {
        enabled: true,
        recommendations: {
          low: fromAtomicUnits(lowFee),
          medium: fromAtomicUnits(mediumFee),
          high: fromAtomicUnits(highFee),
          lowAtomic: Math.round(lowFee),
          mediumAtomic: Math.round(mediumFee),
          highAtomic: Math.round(highFee)
        },
        statistics: {
          totalTransactions: allTransactions.length,
          confirmedTransactions: allTransactions.filter(tx => tx.confirmed).length,
          pendingTransactions: allTransactions.filter(tx => !tx.confirmed).length,
          averageFee: fromAtomicUnits(averageFee),
          medianFee: fromAtomicUnits(medianFee),
          minFee: fromAtomicUnits(minFee),
          maxFee: fromAtomicUnits(maxFee),
          averageFeeRate: avgFeeRate,
          atomicAverageFee: Math.round(averageFee),
          atomicMedianFee: Math.round(medianFee)
        },
        networkCondition: this.assessNetworkCondition(mempool.length, averageFee)
      };
    } catch (error) {
      logger.error('TRANSACTION_SERVICE', `Error analyzing fees: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Feature 26: Transaction broadcasting and status tracking
   */
  broadcastTransaction(transactionData) {
    try {
      if (!this.p2pNetwork) {
        return { success: false, error: 'P2P network not available' };
      }

      // Validate transaction before broadcasting
      const validation = this.validateTransaction(transactionData);
      if (!validation.valid) {
        return { success: false, error: `Invalid transaction: ${validation.reason}` };
      }

      // Add to mempool if memory pool manager is available
      if (this.memoryPoolManager && typeof this.memoryPoolManager.addTransaction === 'function') {
        try {
          const addResult = this.memoryPoolManager.addTransaction(transactionData);
          if (!addResult || !addResult.success) {
            return {
              success: false,
              error: addResult?.error || 'Failed to add transaction to mempool'
            };
          }
        } catch (mempoolError) {
          return { success: false, error: `Mempool error: ${mempoolError.message}` };
        }
      }

      // Broadcast to network
      if (typeof this.p2pNetwork.broadcastTransaction === 'function') {
        try {
          this.p2pNetwork.broadcastTransaction(transactionData);
        } catch (broadcastError) {
          logger.warn('TRANSACTION_SERVICE', `Failed to broadcast transaction: ${broadcastError.message}`);
        }
      }

      // Track transaction status
      this.trackTransaction(transactionData.id);

      return {
        success: true,
        transactionId: transactionData.id,
        status: 'pending',
        timestamp: new Date().toISOString(),
        message: 'Transaction submitted to network'
      };
    } catch (error) {
      logger.error('TRANSACTION_SERVICE', `Error broadcasting transaction: ${error.message}`);
      return { success: false, error: error.message };
    }
  }

  /**
   * Feature 27: Transaction statistics and network activity metrics
   */
  getTransactionStatistics() {
    try {
      const currentTime = Date.now();
      const last24Hours = currentTime - (24 * 60 * 60 * 1000);
      const last1Hour = currentTime - (60 * 60 * 1000);

      let stats = {
        last24Hours: { count: 0, volume: 0, fees: 0 },
        last1Hour: { count: 0, volume: 0, fees: 0 },
        byType: {},
        byHour: [],
        averages: {},
        network: {
          mempoolCount: this.memoryPoolManager?.mempool?.length || 0,
          processingTime: 0,
          throughput: 0
        }
      };

      if (!this.blockchain || !this.blockchain.chain) {
        return stats;
      }

      // Analyze recent blocks
      const recentBlocks = this.blockchain.chain.slice(-100); // Last 100 blocks

      recentBlocks.forEach(block => {
        if (block.transactions && Array.isArray(block.transactions)) {
          block.transactions.forEach(tx => {
            const txTime = tx.timestamp;
            const inputValue = tx.inputs?.reduce((sum, input) => sum + (input.amount || 0), 0) || 0;
            const outputValue = tx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
            const fee = Math.max(0, inputValue - outputValue);
            const type = tx.tag || 'TRANSACTION';

            // 24-hour stats
            if (txTime >= last24Hours) {
              stats.last24Hours.count++;
              stats.last24Hours.volume += outputValue;
              stats.last24Hours.fees += fee;
            }

            // 1-hour stats
            if (txTime >= last1Hour) {
              stats.last1Hour.count++;
              stats.last1Hour.volume += outputValue;
              stats.last1Hour.fees += fee;
            }

            // By type
            if (!stats.byType[type]) {
              stats.byType[type] = { count: 0, volume: 0, fees: 0 };
            }
            stats.byType[type].count++;
            stats.byType[type].volume += outputValue;
            stats.byType[type].fees += fee;

            // By hour (for last 24 hours)
            if (txTime >= last24Hours) {
              const hour = Math.floor((txTime - last24Hours) / (60 * 60 * 1000));
              if (!stats.byHour[hour]) {
                stats.byHour[hour] = { count: 0, volume: 0, fees: 0 };
              }
              stats.byHour[hour].count++;
              stats.byHour[hour].volume += outputValue;
              stats.byHour[hour].fees += fee;
            }
          });
        }
      });

      // Convert atomic units and calculate averages
      stats.last24Hours.volume = fromAtomicUnits(stats.last24Hours.volume);
      stats.last24Hours.fees = fromAtomicUnits(stats.last24Hours.fees);
      stats.last1Hour.volume = fromAtomicUnits(stats.last1Hour.volume);
      stats.last1Hour.fees = fromAtomicUnits(stats.last1Hour.fees);

      // Calculate throughput (transactions per minute)
      stats.network.throughput = stats.last1Hour.count / 60;

      // Convert by-type stats
      Object.keys(stats.byType).forEach(type => {
        stats.byType[type].volume = fromAtomicUnits(stats.byType[type].volume);
        stats.byType[type].fees = fromAtomicUnits(stats.byType[type].fees);
      });

      // Calculate averages
      stats.averages = {
        transactionsPerBlock: recentBlocks.length > 0 ?
          recentBlocks.reduce((sum, block) => sum + (block.transactions?.length || 0), 0) / recentBlocks.length : 0,
        feePerTransaction: stats.last24Hours.count > 0 ? stats.last24Hours.fees / stats.last24Hours.count : 0,
        volumePerTransaction: stats.last24Hours.count > 0 ? stats.last24Hours.volume / stats.last24Hours.count : 0
      };

      return stats;
    } catch (error) {
      logger.error('TRANSACTION_SERVICE', `Error getting transaction statistics: ${error.message}`);
      return { error: error.message };
    }
  }

  // Helper Methods

  formatTransactionForDisplay(transaction) {
    const inputValue = transaction.inputs?.reduce((sum, input) => sum + (input.amount || 0), 0) || 0;
    const outputValue = transaction.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
    const fee = Math.max(0, inputValue - outputValue);

    return {
      id: transaction.id,
      type: transaction.tag || 'TRANSACTION',
      timestamp: transaction.blockTimestamp || transaction.timestamp,
      blockIndex: transaction.blockIndex,
      blockHash: transaction.blockHash,
      confirmed: transaction.confirmed,
      inputCount: transaction.inputs?.length || 0,
      outputCount: transaction.outputs?.length || 0,
      amount: fromAtomicUnits(outputValue),
      fee: fromAtomicUnits(fee),
      size: JSON.stringify(transaction).length,
      from: transaction.inputs?.[0]?.address || transaction.from,
      to: transaction.outputs?.[0]?.address || transaction.to
    };
  }

  trackTransaction(transactionId) {
    // Track transaction status changes
    logger.info('TRANSACTION_SERVICE', `Tracking transaction: ${transactionId}`);
  }

  assessNetworkCondition(mempoolSize, averageFee) {
    if (mempoolSize > 100) {
      return 'congested';
    } else if (mempoolSize > 50) {
      return 'busy';
    } else {
      return 'normal';
    }
  }

  /**
   * Get recent transactions for dashboard display
   */
  getRecentTransactions(limit = 20) {
    try {
      const searchResult = this.searchTransactions('', { limit: limit });
      return searchResult.results;
    } catch (error) {
      logger.error('TRANSACTION_SERVICE', `Error getting recent transactions: ${error.message}`);
      return [];
    }
  }
}

module.exports = TransactionService;