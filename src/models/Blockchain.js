const fs = require('fs');
const path = require('path');

const {
  toAtomicUnits,
  fromAtomicUnits,
  formatAtomicUnits,
  calculateHalvedReward,
  getHalvingInfo,
} = require('../utils/atomicUnits.js');
const { TRANSACTION_TAGS } = require('../utils/constants');
const logger = require('../utils/logger');

const Block = require('./Block');

// Import modular components
const BlockchainValidation = require('./BlockchainValidation');
const CheckpointManager = require('./CheckpointManager');
const MemoryPoolManager = require('./MemoryPoolManager');
const SpamProtection = require('./SpamProtection');
const { Transaction } = require('./Transaction');
const TransactionManager = require('./TransactionManager');
const UTXOManager = require('./UTXOManager');

// Import contract system
const { ContractEngine } = require('../contracts/ContractEngine');
const ContractTransaction = require('../contracts/ContractTransaction');

/**
 * MODULAR & SECURE BLOCKCHAIN CLASS
 *
 * This class now orchestrates specialized modules:
 * - UTXOManager: Handles all UTXO operations
 * - SpamProtection: Manages rate limiting and spam prevention
 * - MemoryPoolManager: Handles transaction pool and batch processing
 * - TransactionManager: Manages transaction validation and creation
 * - BlockchainValidation: Handles blockchain validation methods
 *
 * BENEFITS:
 * - Better code organization and maintainability
 * - Easier testing and debugging
 * - Clear separation of concerns
 * - Reduced file size and complexity
 */
class Blockchain {
  /**
   *
   * @param dataDir
   * @param config
   */
  constructor(dataDir = './data', config = null) {
    this.chain = [];
    this.difficulty = 1000; // Default difficulty (will be overridden by config)
    this.miningReward = this.config?.blockchain?.coinbaseReward || 5000000000; // Use configured value or fallback
    this.blockTime = 60000; // 1 minute
    this.dataDir = dataDir;
    this.difficultyAlgorithm = 'lwma3'; // Default to LWMA-3 algorithm
    this.difficultyBlocks = 30; // Default number of blocks for LWMA calculation
    this.difficultyMinimum = 1; // Minimum difficulty floor
    this.config = config; // Configuration for validation

    // Initialize modular components
    this.utxoManager = new UTXOManager();
    this.spamProtection = new SpamProtection();
    this.memoryPool = new MemoryPoolManager(config); // Pass config for memory limits
    this.transactionManager = new TransactionManager(this.utxoManager, this.spamProtection, this.memoryPool);
    this.blockchainValidation = new BlockchainValidation(config); // Pass config for validation limits

    
    this.checkpointManager = new CheckpointManager(dataDir);

    // Initialize contract engine for smart contract support
    this.contractEngine = new ContractEngine(this);

    
    this.historicalTransactions = new Map(); // Key: "nonce:senderAddress", Value: {txId, blockHeight, timestamp}
    this.historicalTransactionIds = new Set(); // Track all transaction IDs ever processed

    
    this.unsavedTransactions = new Map(); // Key: "nonce:senderAddress", Value: {txId, blockHeight, timestamp}
    this.unsavedTransactionIds = new Set(); // Track transaction IDs in unsaved blocks
    this.unsavedGlobalNonceUsage = new Map(); // Track nonce usage for unsaved blocks
    this.lastSavedBlockHeight = -1; // Track last saved block height

    

    // SYNC PROGRESS TRACKING
    this.syncStatus = {
      isSyncing: false,
      syncStartTime: null,
      syncStartHeight: 0,
      lastSyncUpdate: null,
      expectedHeight: 0, // Estimated final height based on peer info
      syncSpeed: 0, // Blocks per second
      recentBlockTimes: [], // Track recent block addition times for speed calculation
    };

    
    this.blockAcceptancePaused = false;
    this.conservativeMode = false;
    this.globalNonceUsage = new Map(); // nonce -> count of how many times used globally
    this.nonceCollisionThreshold = 100; // Maximum times a nonce can be used globally before considering it an attack

    
    this.consensusManager = {
      // Track mining power distribution
      miningPowerDistribution: new Map(), // address -> hashRate
      totalNetworkHashRate: 0,

      // Proof-of-Stake validation (hybrid consensus)
      stakedValidators: new Map(), // address -> stakeAmount
      totalStake: 0,
      minStakeForValidation: 1000, // Minimum PAS required to be a validator

      // Network partition detection
      partitionDetection: {
        lastBlockTime: Date.now(),
        expectedBlockTime: this.blockTime,
        consecutiveLateBlocks: 0,
        partitionThreshold: 5, // Consecutive late blocks before partition warning
        isPartitioned: false,
      },

      // Consensus validation
      consensusThreshold: 0.67, // 67% consensus required
      validatorSignatures: new Map(), // blockHash -> [validatorSignatures]

      // Anti-51% measures
      maxSingleMinerHashRate: 0.4, // Max 40% hash rate per single miner
      suspiciousActivity: new Set(), // Track suspicious mining patterns
    };
  }

  /**
   * Get the current mining reward based on block height and halving configuration
   * @returns {number} Current mining reward in atomic units
   */
  getCurrentMiningReward() {
    const baseReward = this.config?.blockchain?.coinbaseReward || 5000000000;
    const halvingBlocks = this.config?.blockchain?.halvingBlocks || 1000;
    const currentHeight = this.chain.length;

    return calculateHalvedReward(currentHeight, baseReward, halvingBlocks);
  }

  /**
   * Get halving information for the current blockchain state
   * @returns {object} Halving information
   */
  getHalvingInfo() {
    const baseReward = this.config?.blockchain?.coinbaseReward || 5000000000;
    const halvingBlocks = this.config?.blockchain?.halvingBlocks || 1000;
    const currentHeight = this.chain.length;

    return getHalvingInfo(currentHeight, baseReward, halvingBlocks);
  }

  /**
   * Initialize blockchain with genesis block
   * @param address
   * @param config
   * @param suppressLogging
   */
  initialize(address, config = null, suppressLogging = false) {
    // Store config for validation
    this.config = config;

    // Load configuration values
    if (config && config.blockchain) {
      this.difficulty = config.blockchain.genesis?.difficulty || this.difficulty;
      this.blockTime = config.blockchain.blockTime || this.blockTime;
      this.miningReward = config.blockchain.coinbaseReward || this.miningReward;
      this.difficultyAlgorithm = config.blockchain.difficultyAlgorithm || 'lwma3';
      this.difficultyBlocks = config.blockchain.difficultyBlocks || 30;
      this.difficultyMinimum = config.blockchain.difficultyMinimum || 1;

      if (this.difficulty > 100000) {
        logger.warn('BLOCKCHAIN', `Initial difficulty too high (${this.difficulty}), resetting to 100`);
        this.difficulty = 100;
      }
    }

    if (this.chain.length === 0) {
      let genesisBlock;

      if (config && config.blockchain && config.blockchain.genesis) {
        const genesisConfig = config.blockchain.genesis;
        const genesisTimestamp = genesisConfig.timestamp;
        const { premineAmount } = genesisConfig;
        const { premineAddress } = genesisConfig;

        const premineTransaction = Transaction.createCoinbase(
          premineAddress,
          premineAmount,
          genesisTimestamp,
          this.config?.blockchain?.genesis?.coinbaseNonce,
          this.config?.blockchain?.genesis?.coinbaseAtomicSequence,
          true
        );
        premineTransaction.tag = TRANSACTION_TAGS.PREMINE;
        // Don't override the timestamp - keep the config timestamp for determinism
        premineTransaction.calculateId();

        genesisBlock = Block.createGenesisBlock(
          premineAddress,
          genesisTimestamp,
          [premineTransaction],
          this.difficulty,
          genesisConfig,
          this.config
        );
        if (!suppressLogging) {
          const { formatAtomicUnits } = require('../utils/atomicUnits');
          logger.info(
            'BLOCKCHAIN',
            `Genesis block created with premine: ${formatAtomicUnits(premineAmount)} PAS to ${premineAddress}`
          );
        }
      } else {
        // Use config timestamp if available, otherwise create without timestamp
        const configTimestamp = this.config?.blockchain?.genesis?.timestamp;
        genesisBlock = Block.createGenesisBlock(
          address,
          configTimestamp,
          [],
          this.difficulty,
          this.config?.blockchain?.genesis,
          this.config
        );
        if (!suppressLogging) {
          logger.info('BLOCKCHAIN', 'Genesis block created with default settings');
        }
      }

      this.chain.push(genesisBlock);
      this.utxoManager.updateUTXOSet(genesisBlock);
      if (!suppressLogging) {
        logger.info('BLOCKCHAIN', `Genesis block added to chain. Hash: ${genesisBlock.hash}`);
      }
    }

    if (config && config.spamProtection) {
      this.spamProtection.updateConfig(config.spamProtection);
    }

    if (!suppressLogging) {
      logger.info('BLOCKCHAIN', `Blockchain initialized with ${this.chain.length} blocks`);
    }
  }

  /**
   * Get blockchain status
   */
  getStatus() {
    return {
      chainLength: this.chain.length,
      difficulty: this.difficulty,
      miningReward: this.miningReward,
      blockTime: this.blockTime,
      totalSupply: this.getTotalSupply(),
      totalSupplyFormatted: fromAtomicUnits(this.getTotalSupply()),
      pendingTransactions: this.memoryPool.getPendingTransactionCount(),
      utxoCount: this.utxoManager.getUTXOCount(),
      spamProtection: this.spamProtection.getStatus(),
    };
  }

  /**
   * Get latest block
   */
  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  /**
   * Get the last N blocks from the chain
   * @param {number} n - Number of blocks to retrieve
   * @returns {Array} Array of the last N blocks
   */
  getLastNBlocks(n) {
    if (n <= 0) return [];
    if (n >= this.chain.length) return [...this.chain];
    return this.chain.slice(-n);
  }

  /**
   * Get blockchain height
   */
  getHeight() {
    return this.chain.length;
  }

  /**
   * Add new block to the chain
   * @param block
   * @param skipValidation
   * @param useBlockDifficulty - If true, use the block's embedded difficulty for validation instead of global difficulty
   */
  addBlock(block, skipValidation = false, useBlockDifficulty = false, fastSyncMode = false) {
    // SYNC DETECTION: useBlockDifficulty=true means syncing from network
    const isSyncingFromNetwork = useBlockDifficulty;

    // Update sync status tracking
    this.updateSyncStatus(block, isSyncingFromNetwork, fastSyncMode);

    logger.debug(
      'BLOCKCHAIN',
      `Adding block to chain: index=${block.index}, hash=${block.hash?.substring(0, 16)}..., previousHash=${block.previousHash?.substring(0, 16)}..., skipValidation=${skipValidation}, useBlockDifficulty=${useBlockDifficulty}, fastSyncMode=${fastSyncMode}, syncMode=${isSyncingFromNetwork ? 'NETWORK' : 'MINING'}`
    );
    logger.debug(
      'BLOCKCHAIN',
      `Current chain length: ${this.chain.length}, config present: ${this.config ? 'yes' : 'no'}`
    );

    try {
      if (!skipValidation) {
        logger.debug('BLOCKCHAIN', `Running block validation for block ${block.index}`);
        const validationResult = this.blockchainValidation.isValidBlock(block, this.config, this.utxoManager);
        logger.debug('BLOCKCHAIN', `Block validation result: ${validationResult}`);
        if (!validationResult) {
          logger.error('BLOCKCHAIN', `Block ${block.index} validation failed`);
          return false;
        }
        logger.debug('BLOCKCHAIN', `Block ${block.index} validation passed`);

        // Enforce network difficulty policy (reject blocks mined with incorrect difficulty)
        if (block.index > 0) {
          const expectedDifficulty = useBlockDifficulty ? block.difficulty : this.difficulty;
          logger.debug('BLOCKCHAIN', `Difficulty validation: useBlockDifficulty=${useBlockDifficulty}, expectedDifficulty=${expectedDifficulty}, blockDifficulty=${block.difficulty}, globalDifficulty=${this.difficulty}`);

          // FIXED: Only enforce strict difficulty matching for locally mined blocks
          // Blocks from network (sync or new blocks from peers) should use their embedded difficulty
          if (!useBlockDifficulty && block.difficulty !== expectedDifficulty) {
            // This is a locally mined block that doesn't match our current difficulty
            logger.error(
              'BLOCKCHAIN',
              `Block ${block.index} rejected: locally mined block difficulty mismatch (block=${block.difficulty}, expected=${expectedDifficulty})`
            );
            return false;
          }

          // For network blocks, always use the block's embedded difficulty for hash validation
          if (useBlockDifficulty) {
            logger.debug('BLOCKCHAIN', `Using embedded block difficulty ${block.difficulty} for network block validation`);
          }

          // Verify hash meets the expected difficulty (block's own difficulty when syncing, or current network difficulty when mining)
          try {
            const maxTarget = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
            const target = maxTarget / BigInt(Math.max(1, expectedDifficulty));
            const hashNum = BigInt(`0x${block.hash}`);
            if (hashNum > target) {
              logger.error(
                'BLOCKCHAIN',
                `Block ${block.index} rejected: hash does not meet expected difficulty (hash > target, difficulty=${expectedDifficulty})`
              );
              logger.debug('BLOCKCHAIN', `  hash:   0x${hashNum.toString(16).padStart(64, '0')}`);
              logger.debug('BLOCKCHAIN', `  target: 0x${target.toString(16).padStart(64, '0')}`);
              return false;
            }
          } catch (e) {
            logger.error('BLOCKCHAIN', `Difficulty verification error: ${e.message}`);
            return false;
          }
        }
      } else {
        logger.debug('BLOCKCHAIN', `Skipping validation for block ${block.index}`);
      }

      // Check if block is already in chain
      const existingBlock = this.chain.find(existingBlock => existingBlock.hash === block.hash);
      if (existingBlock) {
        logger.warn('BLOCKCHAIN', `Block ${block.index} already exists in chain at index ${existingBlock.index}`);
        return false;
      }

      // Check if block links properly
      const latestBlock = this.getLatestBlock();

      // For genesis block (index 0) or when chain is empty, skip linking validation
      if (block.index === 0 || !latestBlock) {
        // Skip linking validation for genesis block or empty chain
      } else if (block.previousHash !== latestBlock.hash) {
        logger.debug('BLOCKCHAIN', `Block ${block.index} does not link to latest block`);
        logger.debug('BLOCKCHAIN', `  Block previousHash: ${block.previousHash}`);
        logger.debug('BLOCKCHAIN', `  Latest block hash: ${latestBlock.hash}`);
        return false;
      }

      // Add block to chain
      this.chain.push(block);

      
      this.utxoManager.updateUTXOSet(block);

      // Process contract transactions in the block (CRITICAL for security)
      this.processContractTransactions(block);

      // Add transactions to historical database for replay attack protection (CRITICAL)
      this.addTransactionsToHistoricalDatabase(block);

      // Only skip non-critical performance operations in fast sync mode
      if (!fastSyncMode) {
        // Remove transactions from pending pool (performance optimization)
        this.memoryPool.removeTransactions(block.transactions);
        // Adjust difficulty (can be deferred in fast sync)
        this.adjustDifficulty();
      }

      // Enhanced logging with sync progress
      const progressInfo = this.getSyncProgressInfo();
      if (isSyncingFromNetwork) {
        logger.info('BLOCKCHAIN', `[SYNC] Block ${block.index} added to chain successfully. Hash: ${block.hash} ${progressInfo}`);
      } else {
        logger.info('BLOCKCHAIN', `[MINING] Block ${block.index} added to chain successfully. Hash: ${block.hash}`);
      }
      return true;
    } catch (error) {
      logger.error('BLOCKCHAIN', `Error adding block ${block.index}: ${error.message}`);
      logger.error('BLOCKCHAIN', `Error stack: ${error.stack}`);
      logger.error(
        'BLOCKCHAIN',
        `Block data: index=${block.index}, hash=${block.hash}, previousHash=${block.previousHash}`
      );

      
      if (error.message && error.message.includes('Transaction ID collision detected')) {
        logger.error('BLOCKCHAIN', 'Re-throwing Transaction ID collision error for blockchain resync handling');
        throw error; // Re-throw to allow MessageHandler to detect and handle resync
      }

      return false;
    }
  }

  /**
   * Perform final state rebuild after fast sync completion
   * This rebuilds UTXO set, processes contracts, and updates historical database
   * @param {number} startFromBlock - Block index to start rebuilding from (default: 1, skip genesis)
   */
  performFinalStateRebuild(startFromBlock = 1) {
    logger.info('BLOCKCHAIN', '🔄 Starting final state rebuild after fast sync...');
    const totalBlocks = this.chain.length;
    const blocksToProcess = totalBlocks - startFromBlock;

    logger.info('BLOCKCHAIN', `Rebuilding state for ${blocksToProcess} blocks (from block ${startFromBlock} to ${totalBlocks - 1})`);

    // Clear existing state to rebuild from scratch
    this.utxoManager.clear();
    this.historicalTransactions.clear();
    this.historicalTransactionIds.clear();
    this.globalNonceUsage.clear();

    let processedCount = 0;
    const progressInterval = Math.max(1, Math.floor(blocksToProcess / 20)); // Show progress every 5%

    try {
      // Process each block in order
      for (let i = startFromBlock; i < totalBlocks; i++) {
        const block = this.chain[i];

        // Update UTXO set
        this.utxoManager.updateUTXOSet(block);

        // Process contract transactions
        this.processContractTransactions(block);

        // Add transactions to historical database
        this.addTransactionsToHistoricalDatabase(block);

        processedCount++;

        // Log progress
        if (processedCount % progressInterval === 0 || i === totalBlocks - 1) {
          const percentage = Math.round((processedCount / blocksToProcess) * 100);
          logger.info('BLOCKCHAIN', `State rebuild progress: ${processedCount}/${blocksToProcess} blocks (${percentage}%) - Current block: ${block.index}`);
        }
      }

      // Adjust difficulty to current state
      this.adjustDifficulty();

      logger.info('BLOCKCHAIN', `✅ Final state rebuild completed successfully! Processed ${processedCount} blocks`);
      logger.info('BLOCKCHAIN', `  - UTXO set updated with all transactions`);
      logger.info('BLOCKCHAIN', `  - Contract state processed for all blocks`);
      logger.info('BLOCKCHAIN', `  - Historical transaction database rebuilt`);
      logger.info('BLOCKCHAIN', `  - Difficulty adjusted to current network state`);

      return true;
    } catch (error) {
      logger.error('BLOCKCHAIN', `❌ Final state rebuild failed at block ${startFromBlock + processedCount}: ${error.message}`);
      logger.error('BLOCKCHAIN', `Error stack: ${error.stack}`);

      // Re-throw critical errors
      if (error.message && error.message.includes('Transaction ID collision detected')) {
        throw error;
      }

      return false;
    }
  }

  /**
   * CRITICAL: Add transactions to historical database for replay attack protection
   * @param block
   */
  addTransactionsToHistoricalDatabase(block) {
    block.transactions.forEach(transaction => {
      if (!transaction.isCoinbase && transaction.nonce) {
        // Create unique key: "nonce:senderAddress"
        const senderAddress = this.getTransactionSenderAddress(transaction);
        if (senderAddress) {
          const key = `${transaction.nonce}:${senderAddress}`;

          // Store transaction info in both permanent and temporary storage
          const transactionInfo = {
            txId: transaction.id,
            blockHeight: block.index,
            timestamp: transaction.timestamp,
            nonce: transaction.nonce,
            senderAddress,
          };

          
          const isNewTransaction = !this.historicalTransactionIds.has(transaction.id) && !this.unsavedTransactionIds.has(transaction.id);

          if (isNewTransaction) {
            // Add to permanent historical database
            this.historicalTransactions.set(key, transactionInfo);

            
            if (block.index > this.lastSavedBlockHeight) {
              this.unsavedTransactions.set(key, transactionInfo);
              this.unsavedTransactionIds.add(transaction.id);

              // Track nonce usage in unsaved buffer
              const unsavedUsage = this.unsavedGlobalNonceUsage.get(transaction.nonce) || 0;
              this.unsavedGlobalNonceUsage.set(transaction.nonce, unsavedUsage + 1);
            }

            
            const currentUsage = this.globalNonceUsage.get(transaction.nonce) || 0;
            this.globalNonceUsage.set(transaction.nonce, currentUsage + 1);

            // Log potential nonce collision attacks
            if (currentUsage + 1 > this.nonceCollisionThreshold) {
              logger.warn(
                'BLOCKCHAIN',
                `🚨 NONCE COLLISION ATTACK DETECTED: Nonce ${transaction.nonce} used ${currentUsage + 1} times (threshold: ${this.nonceCollisionThreshold})`
              );
            } else if (currentUsage + 1 > 10) {
              logger.debug(
                'BLOCKCHAIN',
                `Nonce collision warning: Nonce ${transaction.nonce} used ${currentUsage + 1} times`
              );
            }
            // Add transaction ID to tracking
            this.historicalTransactionIds.add(transaction.id);
            logger.debug(
              'BLOCKCHAIN',
              `Added NEW transaction ${transaction.id} to historical database with nonce ${transaction.nonce} from ${senderAddress} (block ${block.index})`
            );
          } else {
            // Transaction already exists - this is normal during blockchain sync/re-processing
            logger.debug(
              'BLOCKCHAIN',
              `Transaction ${transaction.id} already tracked - normal during sync (block ${block.index})`
            );
          }
        }
      }
    });
  }

  /**
   * CRITICAL: Get sender address from transaction inputs with cryptographic validation
   * For contract transactions, extract from contractData instead of inputs
   * @param transaction
   */
  getTransactionSenderAddress(transaction) {
    // SPECIAL HANDLING: Contract transactions store sender in contractData
    if (transaction.contractData && transaction.tag === 'CONTRACT') {
      const contractSender = transaction.contractData.owner || transaction.contractData.caller;
      if (contractSender) {
        logger.debug('BLOCKCHAIN', `Extracted contract sender address: ${contractSender}`);
        return contractSender;
      }
      logger.warn('BLOCKCHAIN', 'Contract transaction missing owner/caller in contractData');
      return null;
    }

    if (!transaction.inputs || transaction.inputs.length === 0) {
      logger.warn('BLOCKCHAIN', 'Cannot extract sender address: no transaction inputs');
      return null;
    }

    const firstInput = transaction.inputs[0];
    if (!firstInput || !firstInput.publicKey) {
      logger.warn('BLOCKCHAIN', 'Cannot extract sender address: missing public key in first input');
      return null;
    }

    try {
      
      const { CryptoUtils } = require('../utils/crypto');
      
      // Validate public key format (should be 130 hex chars for uncompressed secp256k1)
      if (typeof firstInput.publicKey !== 'string' || 
          !/^[0-9a-fA-F]{130}$/.test(firstInput.publicKey)) {
        logger.error('BLOCKCHAIN', `Invalid public key format: ${firstInput.publicKey?.substring(0, 20)}...`);
        return null;
      }

      // Use the same address derivation as the crypto utils
      const derivedAddress = CryptoUtils.publicKeyToAddress(firstInput.publicKey);
      
      if (!derivedAddress) {
        logger.error('BLOCKCHAIN', 'Failed to derive address from public key');
        return null;
      }

      return derivedAddress;
    } catch (error) {
      logger.error('BLOCKCHAIN', `Error extracting sender address: ${error.message}`);
      return null;
    }
  }

  /**
   * CRITICAL: Check if transaction is a replay attack against historical blockchain
   * @param transaction
   */
  isReplayAttack(transaction) {
    if (transaction.isCoinbase) {
      return false; // Coinbase transactions cannot be replayed
    }

    if (!transaction.nonce) {
      logger.warn('BLOCKCHAIN', `Transaction ${transaction.id} missing nonce - potential replay attack`);
      return true; // Reject transactions without nonce
    }

    
    if (this.historicalTransactionIds.has(transaction.id) || this.unsavedTransactionIds.has(transaction.id)) {
      logger.warn('BLOCKCHAIN', `Replay attack detected: Transaction ${transaction.id} already exists in blockchain (saved or unsaved)`);
      return true;
    }

    // Check if nonce from same sender already exists
    const senderAddress = this.getTransactionSenderAddress(transaction);
    if (!senderAddress) {
      
      logger.error('BLOCKCHAIN', `SECURITY FAILURE: Cannot extract sender address for transaction ${transaction.id} - rejecting as potential attack`);
      return true; // Treat as replay attack to fail safely
    }

    const key = `${transaction.nonce}:${senderAddress}`;
    
    const existing = this.historicalTransactions.get(key) || this.unsavedTransactions.get(key);

    if (existing) {
      logger.warn(
        'BLOCKCHAIN',
        `Replay attack detected: Transaction ${transaction.id} uses nonce ${transaction.nonce} already used by ${senderAddress} in block ${existing.blockHeight}`
      );
      return true;
    }

    
    // Include both saved and unsaved nonce usage
    const globalUsage = this.globalNonceUsage.get(transaction.nonce) || 0;
    const unsavedUsage = this.unsavedGlobalNonceUsage.get(transaction.nonce) || 0;
    const totalUsage = globalUsage + unsavedUsage;

    if (totalUsage >= this.nonceCollisionThreshold) {
      logger.error(
        'BLOCKCHAIN',
        `🚨 NONCE COLLISION ATTACK: Transaction ${transaction.id} rejected - nonce ${transaction.nonce} already used ${totalUsage} times (saved: ${globalUsage}, unsaved: ${unsavedUsage}, threshold: ${this.nonceCollisionThreshold})`
      );
      return true; // Treat as replay attack to reject transaction
    }

    return false;
  }

  /**
   * CRITICAL: Enhanced validation for historical blocks during sync to prevent manipulation
   * @param {Block} block - The block to validate
   * @param {number} blockIndex - The index of the block in the chain
   * @returns {boolean} - True if block passes enhanced historical validation
   */
  validateHistoricalBlock(block, blockIndex) {
    try {
      // Validate block structure
      if (!block || typeof block !== 'object') {
        logger.error('BLOCKCHAIN', `Historical block ${blockIndex} has invalid structure`);
        return false;
      }

      // Validate required fields
      if (!block.hash || !block.previousHash || !block.merkleRoot || block.index !== blockIndex) {
        logger.error('BLOCKCHAIN', `Historical block ${blockIndex} missing required fields or index mismatch`);
        return false;
      }

      // Validate timestamp is reasonable
      const currentTime = Date.now();
      const tenYearsMs = 10 * 365 * 24 * 60 * 60 * 1000;

      if (block.timestamp > currentTime) {
        logger.error('BLOCKCHAIN', `Historical block ${blockIndex} timestamp ${block.timestamp} is in the future`);
        return false;
      }

      if (currentTime - block.timestamp > tenYearsMs) {
        logger.error('BLOCKCHAIN', `Historical block ${blockIndex} timestamp ${block.timestamp} is too ancient`);
        return false;
      }

      // Validate transaction count is reasonable
      if (!block.transactions || !Array.isArray(block.transactions) || block.transactions.length === 0) {
        logger.error('BLOCKCHAIN', `Historical block ${blockIndex} has no valid transactions`);
        return false;
      }

      if (block.transactions.length > 10000) {
        logger.error('BLOCKCHAIN', `Historical block ${blockIndex} has too many transactions: ${block.transactions.length}`);
        return false;
      }

      // Validate first transaction is coinbase
      if (!block.transactions[0] || !block.transactions[0].isCoinbase) {
        logger.error('BLOCKCHAIN', `Historical block ${blockIndex} first transaction is not coinbase`);
        return false;
      }

      // Validate difficulty is reasonable
      if (typeof block.difficulty !== 'number' || block.difficulty < 100 || block.difficulty > 1000000000) {
        logger.error('BLOCKCHAIN', `Historical block ${blockIndex} has invalid difficulty: ${block.difficulty}`);
        return false;
      }

      logger.debug('BLOCKCHAIN', `Historical block ${blockIndex} passed enhanced validation`);
      return true;

    } catch (error) {
      logger.error('BLOCKCHAIN', `Historical block ${blockIndex} validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * CRITICAL: Get comprehensive replay attack protection statistics
   */
  getReplayProtectionStats() {
    return {
      historicalTransactionCount: this.historicalTransactions.size,
      historicalTransactionIdCount: this.historicalTransactionIds.size,
      pendingTransactionCount: this.memoryPool.getPendingTransactionCount(),
      replayProtectionEnabled: true,
      nonceValidation: 'enabled',
      expirationValidation: 'enabled',
      historicalValidation: 'enabled',
      duplicateDetection: 'enabled',
      protectionLevel: 'comprehensive',
    };
  }

  /**
   * CRITICAL: 51% Attack Protection - Validate consensus
   * @param block
   * @param minerAddress
   * @param hashRate
   */
  validateConsensus(block, minerAddress, hashRate) {
    try {
      // Update mining power distribution
      this.consensusManager.miningPowerDistribution.set(minerAddress, hashRate);
      this.consensusManager.totalNetworkHashRate = Array.from(
        this.consensusManager.miningPowerDistribution.values()
      ).reduce((total, rate) => total + rate, 0);

      // Check for 51% attack
      const minerShare = hashRate / this.consensusManager.totalNetworkHashRate;
      if (minerShare > this.consensusManager.maxSingleMinerHashRate) {
        logger.warn(
          'CONSENSUS',
          `⚠️  51% Attack Warning: Miner ${minerAddress} controls ${(minerShare * 100).toFixed(2)}% of network hash rate`
        );
        this.consensusManager.suspiciousActivity.add(minerAddress);
        return { valid: false, reason: 'Miner controls too much hash rate', attackType: '51%_ATTACK' };
      }

      // Check for network partition
      const currentTime = Date.now();
      const timeSinceLastBlock = currentTime - this.consensusManager.partitionDetection.lastBlockTime;

      if (timeSinceLastBlock > this.consensusManager.partitionDetection.expectedBlockTime * 2) {
        this.consensusManager.partitionDetection.consecutiveLateBlocks++;

        if (
          this.consensusManager.partitionDetection.consecutiveLateBlocks >=
          this.consensusManager.partitionDetection.partitionThreshold
        ) {
          this.consensusManager.partitionDetection.isPartitioned = true;
          logger.warn(
            'CONSENSUS',
            `⚠️  Network Partition Detected: ${this.consensusManager.partitionDetection.consecutiveLateBlocks} consecutive late blocks`
          );
          return { valid: false, reason: 'Network partition detected', attackType: 'NETWORK_PARTITION' };
        }
      } else {
        this.consensusManager.partitionDetection.consecutiveLateBlocks = 0;
      }

      // Update partition detection
      this.consensusManager.partitionDetection.lastBlockTime = currentTime;

      // Validate proof-of-stake consensus (hybrid approach)
      const validatorCount = this.consensusManager.stakedValidators.size;
      if (validatorCount > 0) {
        const requiredValidators = Math.ceil(validatorCount * this.consensusManager.consensusThreshold);
        const currentValidators = this.consensusManager.validatorSignatures.get(block.hash)?.length || 0;

        if (currentValidators < requiredValidators) {
          logger.warn(
            'CONSENSUS',
            `⚠️  Insufficient validator consensus: ${currentValidators}/${requiredValidators} required`
          );
          return { valid: false, reason: 'Insufficient validator consensus', attackType: 'INSUFFICIENT_CONSENSUS' };
        }
      }

      return { valid: true, reason: 'Consensus validation passed' };
    } catch (error) {
      logger.error('CONSENSUS', `Consensus validation error: ${error.message}`);
      return { valid: false, reason: `Consensus validation error: ${error.message}`, attackType: 'VALIDATION_ERROR' };
    }
  }

  /**
   * CRITICAL: Add validator signature for hybrid consensus
   * @param blockHash
   * @param validatorAddress
   * @param stakeAmount
   */
  addValidatorSignature(blockHash, validatorAddress, stakeAmount) {
    if (stakeAmount >= this.consensusManager.minStakeForValidation) {
      if (!this.consensusManager.validatorSignatures.has(blockHash)) {
        this.consensusManager.validatorSignatures.set(blockHash, []);
      }

      this.consensusManager.validatorSignatures.get(blockHash).push({
        validator: validatorAddress,
        stake: stakeAmount,
        timestamp: Date.now(),
      });

      logger.debug('CONSENSUS', `Validator ${validatorAddress} signed block ${blockHash} with stake ${stakeAmount}`);
    }
  }

  /**
   * CRITICAL: Get consensus status and security metrics
   */
  getConsensusStatus() {
    const miningPower = Array.from(this.consensusManager.miningPowerDistribution.entries())
      .map(([address, hashRate]) => ({
        address,
        hashRate,
        share: ((hashRate / this.consensusManager.totalNetworkHashRate) * 100).toFixed(2),
      }))
      .sort((a, b) => b.share - a.share);

    return {
      totalNetworkHashRate: this.consensusManager.totalNetworkHashRate,
      miningPowerDistribution: miningPower,
      suspiciousMiners: Array.from(this.consensusManager.suspiciousActivity),
      networkPartition: this.consensusManager.partitionDetection.isPartitioned,
      consecutiveLateBlocks: this.consensusManager.partitionDetection.consecutiveLateBlocks,
      validatorCount: this.consensusManager.stakedValidators.size,
      totalStake: this.consensusManager.totalStake,
      consensusThreshold: this.consensusManager.consensusThreshold,
      securityLevel: this._calculateSecurityLevel(),
    };
  }

  /**
   * CRITICAL: Calculate overall security level
   */
  _calculateSecurityLevel() {
    let securityScore = 100;

    // Deduct points for suspicious activity
    securityScore -= this.consensusManager.suspiciousActivity.size * 10;

    // Deduct points for network partition
    if (this.consensusManager.partitionDetection.isPartitioned) {
      securityScore -= 30;
    }

    // Deduct points for high hash rate concentration
    const topMiner = Array.from(this.consensusManager.miningPowerDistribution.values()).sort((a, b) => b - a)[0] || 0;
    const topMinerShare = topMiner / this.consensusManager.totalNetworkHashRate;
    if (topMinerShare > 0.3) {
      securityScore -= Math.floor((topMinerShare - 0.3) * 100);
    }

    return Math.max(0, Math.min(100, securityScore));
  }

  /**
   * CRITICAL: Get memory protection status
   */
  getMemoryProtectionStatus() {
    try {
      return this.memoryPool.memoryProtection.getMemoryStatus();
    } catch (error) {
      logger.error('BLOCKCHAIN', `Failed to get memory protection status: ${error.message}`);
      return { error: 'Failed to get memory protection status' };
    }
  }

  /**
   * CRITICAL: Get CPU protection status
   */
  getCPUProtectionStatus() {
    try {
      return this.blockchainValidation.cpuProtection.getCPUStatus();
    } catch (error) {
      logger.error('BLOCKCHAIN', `Failed to get CPU protection status: ${error.message}`);
      return { error: 'Failed to get CPU protection status' };
    }
  }

  /**
   * CRITICAL: Get detailed replay protection analysis
   */
  getReplayProtectionAnalysis() {
    const analysis = {
      summary: 'Comprehensive replay attack protection enabled',
      protectionMechanisms: [
        'Unique nonce per transaction',
        'Transaction expiration (24 hours)',
        'Historical transaction database',
        'Duplicate transaction ID detection',
        'Sender-based nonce validation',
        'Blockchain-level validation',
      ],
      databaseStats: {
        totalHistoricalTransactions: this.historicalTransactions.size,
        totalTransactionIds: this.historicalTransactionIds.size,
        databaseSize: JSON.stringify(Array.from(this.historicalTransactions.entries())).length,
      },
      recentActivity: [],
      threats: [],
    };

    // Get recent transactions (last 10)
    const recentEntries = Array.from(this.historicalTransactions.entries()).slice(-10);
    analysis.recentActivity = recentEntries.map(([key, value]) => ({
      nonce: value.nonce,
      sender: value.senderAddress,
      blockHeight: value.blockHeight,
      timestamp: new Date(value.timestamp).toISOString(),
    }));

    // Check for potential threats (transactions with same nonce from different senders)
    const nonceGroups = new Map();
    this.historicalTransactions.forEach((value, key) => {
      const { nonce } = value;
      if (!nonceGroups.has(nonce)) {
        nonceGroups.set(nonce, []);
      }
      nonceGroups.get(nonce).push(value);
    });

    nonceGroups.forEach((transactions, nonce) => {
      if (transactions.length > 1) {
        const senders = [...new Set(transactions.map(tx => tx.senderAddress))];
        if (senders.length > 1) {
          analysis.threats.push({
            type: 'Nonce collision detected',
            nonce,
            senders,
            severity: 'low',
            description: 'Multiple senders using same nonce (this is normal if nonces are truly random)',
          });
        }
      }
    });

    return analysis;
  }

  /**
   * CRITICAL: Test replay protection by attempting to add a duplicate transaction
   * This is useful for security testing and validation
   * @param transaction
   */
  testReplayProtection(transaction) {
    const testResults = {
      passed: true,
      tests: [],
      threats: [],
    };

    // Test 1: Check if transaction has required replay protection fields
    if (!transaction.isCoinbase) {
      if (!transaction.nonce) {
        testResults.passed = false;
        testResults.tests.push({
          test: 'Nonce presence',
          result: 'FAILED',
          description: 'Transaction missing nonce field',
        });
        testResults.threats.push('Transaction can be replayed without nonce');
      } else {
        testResults.tests.push({
          test: 'Nonce presence',
          result: 'PASSED',
          description: 'Transaction has nonce field',
        });
      }

      if (!transaction.expiresAt) {
        testResults.passed = false;
        testResults.tests.push({
          test: 'Expiration presence',
          result: 'FAILED',
          description: 'Transaction missing expiration field',
        });
        testResults.threats.push('Transaction can be replayed without expiration');
      } else {
        testResults.tests.push({
          test: 'Expiration presence',
          result: 'PASSED',
          description: 'Transaction has expiration field',
        });
      }
    }

    // Test 2: Check if transaction has expired
    if (transaction.isExpired && transaction.isExpired()) {
      testResults.passed = false;
      testResults.tests.push({
        test: 'Transaction expiration',
        result: 'FAILED',
        description: 'Transaction has expired',
      });
      testResults.threats.push('Expired transaction can be replayed');
    } else {
      testResults.tests.push({
        test: 'Transaction expiration',
        result: 'PASSED',
        description: 'Transaction is not expired',
      });
    }

    // Test 3: Check against historical blockchain
    if (this.isReplayAttack(transaction)) {
      testResults.passed = false;
      testResults.tests.push({
        test: 'Historical replay check',
        result: 'FAILED',
        description: 'Transaction detected as replay attack against historical blockchain',
      });
      testResults.threats.push('Transaction is a replay of a previously confirmed transaction');
    } else {
      testResults.tests.push({
        test: 'Historical replay check',
        result: 'PASSED',
        description: 'Transaction is not a replay attack',
      });
    }

    // Test 4: Check for duplicate in pending pool
    const pendingTxs = this.memoryPool.getPendingTransactions();
    if (transaction.isReplayAttack && typeof transaction.isReplayAttack === 'function') {
      if (transaction.isReplayAttack(pendingTxs)) {
        testResults.passed = false;
        testResults.tests.push({
          test: 'Pending pool replay check',
          result: 'FAILED',
          description: 'Transaction detected as replay attack in pending pool',
        });
        testResults.threats.push('Transaction is a replay of a pending transaction');
      } else {
        testResults.tests.push({
          test: 'Pending pool replay check',
          result: 'PASSED',
          description: 'Transaction is not a replay in pending pool',
        });
      }
    }

    return testResults;
  }

  /**
   * Adjust difficulty using LWMA-3 algorithm
   */
  adjustDifficulty() {
    if (this.chain.length < this.difficultyBlocks + 1) {
      return; // Not enough blocks to adjust difficulty
    }

    const oldDifficulty = this.difficulty;
    const targetBlockTime = this.blockTime;

    // Debug: initial state
    logger.debug(
      'BLOCKCHAIN',
      `adjustDifficulty: height=${this.chain.length}, curr=${oldDifficulty}, target=${targetBlockTime}ms, window=${this.difficultyBlocks}`
    );

    // Get recent blocks for difficulty calculation
    const recentBlocks = this.chain.slice(-this.difficultyBlocks);

    // Calculate average block time
    let totalTime = 0;
    let nonMonotonic = 0;
    for (let i = 1; i < recentBlocks.length; i++) {
      const delta = recentBlocks[i].timestamp - recentBlocks[i - 1].timestamp;
      if (delta <= 0) nonMonotonic++;
      totalTime += delta;
    }
    const averageBlockTime = totalTime / (recentBlocks.length - 1);

    // Debug: computed window stats
    logger.debug(
      'BLOCKCHAIN',
      `adjustDifficulty: avg=${averageBlockTime}ms, total=${totalTime}ms, gaps=${recentBlocks.length - 1}, nonMonotonic=${nonMonotonic}`
    );

    // Only first 100 to be more aggressive because difficulty is too low
    let difficultyHigher = 1.02;
    let difficultyLower = 0.98;
    if (this.chain.length < 100) {
      difficultyHigher = 1.3;
      difficultyLower = 0.9;
    }

    // Adjust difficulty based on block time
    if (averageBlockTime < targetBlockTime * difficultyLower) {
      // From 0.5 to 0.9
      this.difficulty = Math.floor(this.difficulty * difficultyHigher); // from 1.5 to 1.05
    } else if (averageBlockTime > targetBlockTime * difficultyHigher) {
      // from 1.5 to 1.05
      this.difficulty = Math.max(this.difficultyMinimum, Math.floor(this.difficulty * difficultyLower)); // 0.75 to 0.95
    }

    // Ensure difficulty doesn't go below minimum
    this.difficulty = Math.max(this.difficulty, this.difficultyMinimum);

    // Debug: decision
    logger.debug('BLOCKCHAIN', `adjustDifficulty: new=${this.difficulty} (min=${this.difficultyMinimum})`);

    if (this.difficulty !== oldDifficulty) {
      logger.debug('BLOCKCHAIN', `Difficulty adjusted from ${oldDifficulty} to ${this.difficulty}`);
    }
  }

  /**
   * Get pending transactions for mining
   */
  getPendingTransactions() {
    return this.memoryPool.getPendingTransactions();
  }

  /**
   * Add transaction to pending pool
   * @param transaction
   */
  addPendingTransaction(transaction) {
    
    if (this.isReplayAttack(transaction)) {
      logger.error(
        'BLOCKCHAIN',
        `Transaction ${transaction.id} REJECTED: Replay attack detected against historical blockchain`
      );
      return false;
    }

    return this.transactionManager.addPendingTransaction(transaction);
  }

  /**
   * Add multiple transactions in batch
   * @param transactions
   */
  addTransactionBatch(transactions) {
    return this.transactionManager.addTransactionBatch(transactions);
  }

  /**
   * Validate entire blockchain
   */
  isValidChain() {
    return this.blockchainValidation.isValidChain(this.chain, this.config, this.utxoManager);
  }

  /**
   * Fast validation (skips expensive operations)
   */
  isValidChainFast() {
    return this.blockchainValidation.isValidChainFast(this.chain);
  }

  /**
   * Ultra-fast validation (minimal checks)
   */
  isValidChainUltraFast() {
    return this.blockchainValidation.isValidChainUltraFast(this.chain);
  }

  /**
   * Medium validation (includes transaction verification)
   */
  isValidChainMedium() {
    return this.blockchainValidation.isValidChainMedium(this.chain, this.config);
  }

  /**
   * Clean up expired transactions
   */
  cleanupExpiredTransactions() {
    return this.memoryPool.cleanupExpiredTransactions();
  }

  /**
   * Clean up orphaned UTXOs
   */
  cleanupOrphanedUTXOs() {
    return this.utxoManager.cleanupOrphanedUTXOs(this.chain);
  }

  /**
   * Manage memory pool
   */
  manageMemoryPool() {
    return this.memoryPool.manageMemoryPool();
  }

  /**
   * Clean up spam protection data
   */
  cleanupSpamProtection() {
    this.spamProtection.cleanupSpamProtection();
  }

  /**
   * Get balance for an address
   * @param address
   */
  getBalance(address) {
    return this.utxoManager.getBalance(address);
  }

  /**
   * Get UTXOs for an address
   * @param address
   */
  getUTXOsForAddress(address) {
    return this.utxoManager.getUTXOsForAddress(address);
  }

  /**
   * Create transaction
   * @param fromAddress
   * @param toAddress
   * @param amount
   * @param fee
   * @param tag
   */
  createTransaction(fromAddress, toAddress, amount, fee = 100000, tag = TRANSACTION_TAGS.TRANSACTION) {
    try {
      // Convert amount and fee to atomic units if they're not already
      const atomicAmount = typeof amount === 'string' ? toAtomicUnits(amount) : amount;
      const atomicFee = typeof fee === 'string' ? toAtomicUnits(fee) : fee;

      return this.transactionManager.createTransaction(fromAddress, toAddress, atomicAmount, atomicFee, tag);
    } catch (error) {
      logger.error('BLOCKCHAIN', `Failed to create transaction: ${error.message}`);
      return null;
    }
  }

  /**
   * Save blockchain to file
   * @param filePath
   */
  saveToFile(filePath) {
    try {
      const data = {
        chain: this.chain,
        difficulty: this.difficulty,
        miningReward: this.miningReward,
        blockTime: this.blockTime,
        pendingTransactions: this.memoryPool.getPendingTransactions(),
        
        historicalTransactions: Array.from(this.historicalTransactions.entries()),
        historicalTransactionIds: Array.from(this.historicalTransactionIds),
        // Save contract engine state
        contracts: this.contractEngine.serialize(),
        
        globalNonceUsage: Array.from(this.globalNonceUsage.entries()),
      };

      fs.writeFileSync(filePath, JSON.stringify(data, null, 2));

      
      this.lastSavedBlockHeight = this.chain.length - 1;
      this.clearUnsavedBuffer();
      
      return true;
    } catch (error) {
      logger.error('BLOCKCHAIN', `Failed to save blockchain: ${error.message}`);
      return false;
    }
  }

  /**
   * Get default blockchain file path
   */
  getDefaultFilePath() {
    const dataDir = this.config?.storage?.dataDir || this.dataDir || './data';
    const fileName = this.config?.storage?.blockchainFile || 'blockchain.json';
    return path.join(dataDir, fileName);
  }

  /**
   * Save blockchain to default file location
   */
  saveToDefaultFile() {
    return this.saveToFile(this.getDefaultFilePath());
  }

  /**
   * Validate genesis block against config.json specifications
   * @returns {boolean} True if genesis block matches config, false otherwise
   */
  validateGenesisBlockAgainstConfig() {
    try {
      if (!this.config || !this.config.blockchain || !this.config.blockchain.genesis) {
        logger.warn('BLOCKCHAIN', 'No genesis config found, skipping genesis validation');
        return true;
      }

      if (this.chain.length === 0) {
        logger.warn('BLOCKCHAIN', 'No blocks in chain, skipping genesis validation');
        return true;
      }

      const genesisBlock = this.chain[0];
      const genesisConfig = this.config.blockchain.genesis;

      logger.debug('BLOCKCHAIN', 'Validating genesis block against config.json specifications...');

      // Check if this is actually a genesis block
      if (genesisBlock.index !== 0 || genesisBlock.previousHash !== '0') {
        logger.error('BLOCKCHAIN', 'First block is not a valid genesis block');
        return false;
      }

      // Validate genesis block properties against config
      const validationChecks = [
        {
          name: 'timestamp',
          expected: genesisConfig.timestamp,
          actual: genesisBlock.timestamp,
          check: (expected, actual) => expected === actual,
        },
        {
          name: 'difficulty',
          expected: genesisConfig.difficulty,
          actual: genesisBlock.difficulty,
          check: (expected, actual) => expected === actual,
        },
        {
          name: 'hash',
          expected: genesisConfig.hash,
          actual: genesisBlock.hash,
          check: (expected, actual) => expected === actual,
        },
        {
          name: 'nonce',
          expected: genesisConfig.nonce,
          actual: genesisBlock.nonce,
          check: (expected, actual) => expected === actual,
        },
        {
          name: 'algorithm',
          expected: genesisConfig.algorithm,
          actual: genesisBlock.algorithm,
          check: (expected, actual) => expected === actual,
        },
      ];

      let validationFailed = false;
      for (const check of validationChecks) {
        if (check.expected !== undefined && !check.check(check.expected, check.actual)) {
          logger.error('BLOCKCHAIN', `Genesis block ${check.name} mismatch:`);
          logger.error('BLOCKCHAIN', `  Expected: ${check.expected}`);
          logger.error('BLOCKCHAIN', `  Actual:   ${check.actual}`);
          validationFailed = true;
        }
      }

      // Validate premine transaction if specified in config
      if (genesisConfig.premineAmount && genesisConfig.premineAddress) {
        if (genesisBlock.transactions.length === 0) {
          logger.error('BLOCKCHAIN', 'Genesis block has no transactions but config specifies premine');
          validationFailed = true;
        } else {
          const premineTransaction = genesisBlock.transactions[0];
          if (!premineTransaction.isCoinbase) {
            logger.error('BLOCKCHAIN', 'First transaction in genesis block is not a coinbase transaction');
            validationFailed = true;
          } else if (premineTransaction.outputs.length === 0) {
            logger.error('BLOCKCHAIN', 'Genesis coinbase transaction has no outputs');
            validationFailed = true;
          } else {
            const output = premineTransaction.outputs[0];
            if (output.address !== genesisConfig.premineAddress) {
              logger.error('BLOCKCHAIN', 'Genesis premine address mismatch:');
              logger.error('BLOCKCHAIN', `  Expected: ${genesisConfig.premineAddress}`);
              logger.error('BLOCKCHAIN', `  Actual:   ${output.address}`);
              validationFailed = true;
            }
            if (output.amount !== genesisConfig.premineAmount) {
              logger.error('BLOCKCHAIN', 'Genesis premine amount mismatch:');
              logger.error('BLOCKCHAIN', `  Expected: ${genesisConfig.premineAmount}`);
              logger.error('BLOCKCHAIN', `  Actual:   ${output.amount}`);
              validationFailed = true;
            }
          }
        }
      }

      if (validationFailed) {
        logger.error('BLOCKCHAIN', 'Genesis block validation against config.json FAILED');
        logger.error('BLOCKCHAIN', 'The loaded genesis block does not match the specifications in config.json');
        logger.error('BLOCKCHAIN', '');
        logger.error('BLOCKCHAIN', 'SOLUTION:');
        logger.error('BLOCKCHAIN', '  • If you are FORKING: node src/index.js --generate-genesis');
        logger.error('BLOCKCHAIN', '  • If you are SYNCING: Delete blockchain folder and redownload binaries');
        logger.error('BLOCKCHAIN', '');
        logger.error('BLOCKCHAIN', 'The daemon will now stop to prevent using an invalid genesis block.');

        // Stop the daemon immediately
        process.exit(1);
      }

      logger.info('BLOCKCHAIN', 'Genesis block validation against config.json PASSED');
      return true;
    } catch (error) {
      logger.error('BLOCKCHAIN', `Error validating genesis block against config: ${error.message}`);
      logger.error('BLOCKCHAIN', `Error stack: ${error.stack}`);
      return false;
    }
  }

  /**
   * Load blockchain from file
   * @param filePath
   */
  loadFromFile(filePath) {
    logger.debug('BLOCKCHAIN', `Loading blockchain from file: ${filePath}`);
    try {
      if (fs.existsSync(filePath)) {
        logger.debug('BLOCKCHAIN', `File exists, reading and parsing JSON data`);
        const fileContent = fs.readFileSync(filePath, 'utf8');
        logger.debug('BLOCKCHAIN', `File content length: ${fileContent.length} characters`);

        const data = JSON.parse(fileContent);
        logger.debug(
          'BLOCKCHAIN',
          `JSON parsed successfully: chain=${data.chain?.length || 0} blocks, difficulty=${data.difficulty}, miningReward=${data.miningReward}`
        );

        // Convert loaded blocks to proper Block instances
        if (data.chain && Array.isArray(data.chain)) {
          logger.info('BLOCKCHAIN', `Processing ${data.chain.length} blocks from file...`);
          
          // Use bulk loading with progress indicators for better performance
          const Block = require('./Block');
          this.chain = [];
          
          for (let index = 0; index < data.chain.length; index++) {
            const blockData = data.chain[index];
            
            try {
              
              const previousBlockTimestamp = index > 0 ? data.chain[index - 1].timestamp : undefined;

              // Validate block timestamp sequence for historical blocks
              if (index > 0 && blockData.timestamp <= previousBlockTimestamp) {
                throw new Error(`Historical block ${index} timestamp ${blockData.timestamp} is not after previous block ${previousBlockTimestamp} - potential manipulation`);
              }

              const blockInstance = Block.fromJSON(blockData, previousBlockTimestamp);

              
              if (!this.validateHistoricalBlock(blockInstance, index)) {
                throw new Error(`Historical block ${index} failed enhanced validation - potential manipulation`);
              }

              this.chain.push(blockInstance);
              
              // Show progress for large chains without excessive logging
              if (data.chain.length > 50 && index % Math.max(1, Math.floor(data.chain.length / 10)) === 0) {
                const progress = ((index / data.chain.length) * 100).toFixed(1);
                logger.info('BLOCKCHAIN', `Block loading progress: ${index}/${data.chain.length} blocks (${progress}%)`);
              }
            } catch (error) {
              logger.error(
                'BLOCKCHAIN',
                `Failed to convert block ${blockData.index || 'unknown'} to Block instance: ${error.message}`
              );
              logger.warn('BLOCKCHAIN', `Returning original block data for block ${index}`);
              this.chain.push(blockData); // Return original if conversion fails
            }
          }
          
          logger.info('BLOCKCHAIN', `Successfully loaded ${this.chain.length} blocks`);
        } else {
          logger.debug('BLOCKCHAIN', `No chain data found in file or invalid format, initializing empty chain`);
          this.chain = [];
        }

        logger.debug(
          'BLOCKCHAIN',
          `Setting blockchain properties: difficulty=${data.difficulty || 1000}, miningReward=${data.miningReward || this.config.blockchain.coinbaseReward}, blockTime=${data.blockTime || 60000}`
        );
        this.difficulty = data.difficulty || 1000;
        this.miningReward = this.config.blockchain.coinbaseReward;
        this.blockTime = data.blockTime || 60000;

        
        if (data.historicalTransactions && Array.isArray(data.historicalTransactions)) {
          logger.debug('BLOCKCHAIN', `Loading ${data.historicalTransactions.length} historical transactions from file`);
          this.historicalTransactions = new Map(data.historicalTransactions);
          logger.info('BLOCKCHAIN', `Loaded ${this.historicalTransactions.size} historical transactions from file`);
        } else {
          logger.debug('BLOCKCHAIN', `No historical transactions data found in file`);
        }

        if (data.historicalTransactionIds && Array.isArray(data.historicalTransactionIds)) {
          logger.debug(
            'BLOCKCHAIN',
            `Loading ${data.historicalTransactionIds.length} historical transaction IDs from file`
          );
          this.historicalTransactionIds = new Set(data.historicalTransactionIds);
          logger.info(
            'BLOCKCHAIN',
            `Loaded ${this.historicalTransactionIds.size} historical transaction IDs from file`
          );
        } else {
          logger.debug('BLOCKCHAIN', `No historical transaction IDs data found in file`);
        }

        // SMART CONTRACTS: Restore contract engine state
        if (data.contracts) {
          logger.debug('BLOCKCHAIN', `Loading contract engine state from file`);
          this.contractEngine.deserialize(data.contracts);
          logger.info('BLOCKCHAIN', `Loaded ${this.contractEngine.contracts.size} contracts from file`);

          // Clean up any failed contract deployments
          const cleanedCount = this.contractEngine.cleanupFailedDeployments();
          if (cleanedCount > 0) {
            logger.info('BLOCKCHAIN', `Cleaned up ${cleanedCount} failed contract deployment payments on startup`);
          }
        } else {
          logger.debug('BLOCKCHAIN', `No contract data found in file`);
        }

        
        if (data.globalNonceUsage && Array.isArray(data.globalNonceUsage)) {
          logger.debug('BLOCKCHAIN', `Loading ${data.globalNonceUsage.length} nonce usage entries from file`);
          this.globalNonceUsage = new Map(data.globalNonceUsage);
          logger.info('BLOCKCHAIN', `Loaded ${this.globalNonceUsage.size} nonce usage entries from file`);
        } else {
          logger.debug('BLOCKCHAIN', `No nonce usage data found in file`);
        }

        // If no historical data in file, rebuild from chain
        if (this.historicalTransactions.size === 0) {
          logger.debug('BLOCKCHAIN', `No historical data found, rebuilding from chain`);
          this.rebuildHistoricalTransactionDatabase();
        }

        
        logger.debug('BLOCKCHAIN', `Loading and validating checkpoints...`);
        if (!this.checkpointManager.loadCheckpoints()) {
          logger.error('BLOCKCHAIN', `Failed to load checkpoints`);
          return false;
        }

        
        logger.debug('BLOCKCHAIN', `Validating genesis block against config.json...`);
        if (!this.validateGenesisBlockAgainstConfig()) {
          logger.error('BLOCKCHAIN', `Genesis block validation against config.json FAILED`);
          logger.error('BLOCKCHAIN', `The daemon will stop to prevent using an invalid genesis block`);
          logger.error('BLOCKCHAIN', '');
          logger.error('BLOCKCHAIN', 'SOLUTION:');
          logger.error('BLOCKCHAIN', '  • If you are FORKING: node src/index.js --generate-genesis');
          logger.error('BLOCKCHAIN', '  • If you are SYNCING: Delete blockchain folder and redownload binaries');

          // Stop the daemon immediately
          process.exit(1);
        }

        
        logger.debug('BLOCKCHAIN', `Validating checkpoints against loaded blockchain...`);
        if (!this.checkpointManager.validateCheckpoints(this)) {
          logger.error('BLOCKCHAIN', `Checkpoint validation failed - daemon will stop`);
          // Note: validateCheckpoints will call process.exit(1) if invalid checkpoints are found
          return false;
        }

        logger.debug('BLOCKCHAIN', `Checkpoint validation passed`);

        
        logger.debug('BLOCKCHAIN', `Running medium blockchain validation during startup (includes transaction verification)...`);
        const validationResult = this.blockchainValidation.isValidChainMedium(this.chain, this.config);
        
        if (!validationResult) {
          logger.error('BLOCKCHAIN', '🚨 SECURITY ALERT: Loaded blockchain failed medium validation!');
          logger.error('BLOCKCHAIN', 'Transaction verification detected issues - running full validation...');
          
          // If fast validation fails, run full validation for security
          const fullValidationResult = this.blockchainValidation.isValidChain(this.chain, this.config);
          
          if (!fullValidationResult) {
            logger.error('BLOCKCHAIN', '🚨 CRITICAL: Blockchain failed full validation!');
            logger.error('BLOCKCHAIN', 'The blockchain file may have been tampered with or corrupted');
            logger.error('BLOCKCHAIN', 'This could be a manipulation attempt - rejecting invalid blockchain');
            logger.error('BLOCKCHAIN', '');
            logger.error('BLOCKCHAIN', 'SOLUTION:');
            logger.error('BLOCKCHAIN', '  • Restore blockchain from a trusted backup');
            logger.error('BLOCKCHAIN', '  • Or delete the blockchain file and resync from network');
            logger.error('BLOCKCHAIN', '  • If you are forking: node src/index.js --generate-genesis');
            
            // Stop the daemon immediately to prevent using manipulated data
            process.exit(1);
          } else {
            logger.warn('BLOCKCHAIN', 'Medium validation failed but full validation passed - continuing with caution');
          }
        }
        
        logger.info('BLOCKCHAIN', '✅ Blockchain validation passed - proceeding with UTXO rebuild');
        
        // Update UTXO set from validated chain
        logger.debug('BLOCKCHAIN', `Rebuilding UTXO set from ${this.chain.length} validated blocks`);
        this.utxoManager.rebuildUTXOSet(this.chain);

        
        this.lastSavedBlockHeight = this.chain.length - 1;
        this.clearUnsavedBuffer(); // Ensure unsaved buffer is clean

        logger.info('BLOCKCHAIN', `Blockchain loaded from file with ${this.chain.length} blocks`);
        logger.debug(
          'BLOCKCHAIN',
          `Final blockchain state: chain.length=${this.chain.length}, difficulty=${this.difficulty}, miningReward=${this.miningReward}, lastSavedBlock=${this.lastSavedBlockHeight}`
        );
        return true;
      }
      logger.debug('BLOCKCHAIN', `File does not exist: ${filePath}`);
      return false;
    } catch (error) {
      logger.error('BLOCKCHAIN', `Failed to load blockchain: ${error.message}`);
      logger.error('BLOCKCHAIN', `Error stack: ${error.stack}`);
      logger.error('BLOCKCHAIN', `File path: ${filePath}`);
      return false;
    }
  }

  /**
   * CRITICAL: Clear unsaved transaction buffer after successful save
   */
  clearUnsavedBuffer() {
    const unsavedCount = this.unsavedTransactions.size;
    this.unsavedTransactions.clear();
    this.unsavedTransactionIds.clear();
    this.unsavedGlobalNonceUsage.clear();

    if (unsavedCount > 0) {
      logger.debug('BLOCKCHAIN', `Cleared unsaved transaction buffer with ${unsavedCount} transactions`);
    }
  }

  /**
   * CRITICAL: Get unsaved buffer statistics for monitoring
   */
  getUnsavedBufferStats() {
    return {
      unsavedTransactionCount: this.unsavedTransactions.size,
      unsavedTransactionIdCount: this.unsavedTransactionIds.size,
      unsavedNonceCount: this.unsavedGlobalNonceUsage.size,
      lastSavedBlockHeight: this.lastSavedBlockHeight,
      currentBlockHeight: this.chain.length - 1,
      blocksUnsaved: Math.max(0, (this.chain.length - 1) - this.lastSavedBlockHeight),
    };
  }

  /**
   * Update sync status tracking for progress monitoring
   * @param {Block} block - Block being added
   * @param {boolean} isSyncingFromNetwork - True if syncing from network
   * @param {boolean} fastSyncMode - True if in fast sync mode
   */
  updateSyncStatus(block, isSyncingFromNetwork, fastSyncMode) {
    const currentTime = Date.now();

    if (isSyncingFromNetwork) {
      // Start sync tracking if not already syncing
      if (!this.syncStatus.isSyncing) {
        this.syncStatus.isSyncing = true;
        this.syncStatus.syncStartTime = currentTime;
        this.syncStatus.syncStartHeight = this.chain.length;
        this.syncStatus.recentBlockTimes = [];
        logger.info('BLOCKCHAIN', '🔄 Network synchronization started...');
      }

      // Track recent block addition times for speed calculation
      this.syncStatus.recentBlockTimes.push(currentTime);
      if (this.syncStatus.recentBlockTimes.length > 20) {
        this.syncStatus.recentBlockTimes.shift(); // Keep only last 20 for speed calculation
      }

      // Calculate sync speed (blocks per second)
      if (this.syncStatus.recentBlockTimes.length >= 2) {
        const timeSpan = currentTime - this.syncStatus.recentBlockTimes[0];
        const blockCount = this.syncStatus.recentBlockTimes.length - 1;
        this.syncStatus.syncSpeed = (blockCount / (timeSpan / 1000)).toFixed(2);
      }

      this.syncStatus.lastSyncUpdate = currentTime;
    } else {
      // Stop sync tracking if we were syncing (switched to mining)
      if (this.syncStatus.isSyncing) {
        this.syncStatus.isSyncing = false;
        const syncDuration = currentTime - this.syncStatus.syncStartTime;
        const blocksAdded = this.chain.length - this.syncStatus.syncStartHeight;
        logger.info('BLOCKCHAIN', `✅ Network synchronization completed! Added ${blocksAdded} blocks in ${(syncDuration / 1000).toFixed(1)}s`);
      }
    }
  }

  /**
   * Get sync progress information for logging
   * @returns {string} Progress information string
   */
  getSyncProgressInfo() {
    if (!this.syncStatus.isSyncing) {
      return '';
    }

    const currentHeight = this.chain.length;
    let progressStr = `(Top Height: ${currentHeight}`;

    // Add estimated progress if we know expected height
    if (this.syncStatus.expectedHeight > 0 && this.syncStatus.expectedHeight > currentHeight) {
      const progress = ((currentHeight / this.syncStatus.expectedHeight) * 100).toFixed(1);
      progressStr += `, Progress: ${progress}%`;
    }

    progressStr += ')';
    return progressStr;
  }

  /**
   * Set expected blockchain height for progress calculation
   * @param {number} expectedHeight - Expected final height from peers
   */
  setExpectedHeight(expectedHeight) {
    if (expectedHeight > this.chain.length) {
      this.syncStatus.expectedHeight = expectedHeight;
      logger.info('BLOCKCHAIN', `📊 Expected blockchain height set to ${expectedHeight} (current: ${this.chain.length})`);
    }
  }

  /**
   * Get comprehensive sync status
   * @returns {Object} Sync status information
   */
  getSyncStatus() {
    return {
      isSyncing: this.syncStatus.isSyncing,
      currentHeight: this.chain.length,
      expectedHeight: this.syncStatus.expectedHeight,
      syncSpeed: this.syncStatus.syncSpeed,
      syncProgress: this.syncStatus.expectedHeight > 0 ?
        ((this.chain.length / this.syncStatus.expectedHeight) * 100).toFixed(1) : 0,
      blocksRemaining: Math.max(0, this.syncStatus.expectedHeight - this.chain.length),
      syncStartTime: this.syncStatus.syncStartTime,
      lastSyncUpdate: this.syncStatus.lastSyncUpdate,
    };
  }

  /**
   * CRITICAL: Rebuild historical transaction database from loaded blockchain
   */
  rebuildHistoricalTransactionDatabase() {
    // Clear existing database
    this.historicalTransactions.clear();
    this.historicalTransactionIds.clear();

    // Rebuild from all blocks
    this.chain.forEach(block => {
      this.addTransactionsToHistoricalDatabase(block);
    });

    logger.info(
      'BLOCKCHAIN',
      `Historical transaction database rebuilt with ${this.historicalTransactions.size} entries`
    );
  }

  /**
   * Process contract transactions in a block
   * @param {Block} block - Block containing transactions to process
   */
  processContractTransactions(block) {
    try {
      // Filter for contract transactions
      const contractTransactions = block.transactions.filter(tx =>
        tx.tag === 'CONTRACT' || tx instanceof ContractTransaction
      );

      if (contractTransactions.length === 0) {
        return; // No contract transactions to process
      }

      logger.debug('BLOCKCHAIN', `Processing ${contractTransactions.length} contract transactions in block ${block.index}`);

      for (const transaction of contractTransactions) {
        try {
          // Convert to ContractTransaction if needed
          let contractTx = transaction;
          if (!(transaction instanceof ContractTransaction)) {
            if (transaction.contractData) {
              contractTx = ContractTransaction.fromJSON(transaction);
            } else {
              // Handle legacy contract transactions that may be missing contractData
              logger.warn('BLOCKCHAIN', `Contract transaction ${transaction.id} missing contractData field - skipping processing`);
              continue;
            }
          }

          if (contractTx.isDeployment()) {
            // Handle contract deployment
            this.executeContractDeployment(contractTx);
          } else if (contractTx.isExecution()) {
            // Handle contract execution
            this.executeContractMethod(contractTx);
          }

          logger.debug('BLOCKCHAIN', `Successfully processed contract transaction ${transaction.id}`);
        } catch (error) {
          logger.error('BLOCKCHAIN', `Failed to process contract transaction ${transaction.id}: ${error.message}`);
          // Contract execution failures don't invalidate the block but are recorded
        }
      }
    } catch (error) {
      logger.error('BLOCKCHAIN', `Error processing contract transactions: ${error.message}`);
    }
  }

  /**
   * Execute contract deployment transaction
   * @param {ContractTransaction} contractTx - Contract deployment transaction
   */
  executeContractDeployment(contractTx) {
    const { contractType, initData, owner } = contractTx.contractData;

    logger.info('BLOCKCHAIN', `Deploying ${contractType} contract for ${owner} with payment ${contractTx.id}`);

    // PAYMENT SYSTEM: Pass the transaction ID as payment verification
    const result = this.contractEngine.deployContract(contractType, initData, owner, contractTx.id);

    logger.info('BLOCKCHAIN', `Contract deployed at address ${result.contractAddress} with verified payment`);
    return result;
  }

  /**
   * Execute contract method call transaction
   * @param {ContractTransaction} contractTx - Contract execution transaction
   */
  executeContractMethod(contractTx) {
    const { contractAddress, method, params, caller } = contractTx.contractData;

    logger.debug('BLOCKCHAIN', `Executing ${method} on contract ${contractAddress} by ${caller} with payment ${contractTx.id}`);

    // PAYMENT SYSTEM: Pass the transaction ID as payment verification
    const result = this.contractEngine.executeContract(contractAddress, method, params, caller, contractTx.id);

    logger.debug('BLOCKCHAIN', `Contract method executed successfully with verified payment`);
    return result;
  }

  /**
   * Get contract information
   * @param {string} contractAddress - Contract address
   * @returns {Object} - Contract information
   */
  getContract(contractAddress) {
    return this.contractEngine.getContract(contractAddress);
  }

  /**
   * Get all contracts
   * @returns {Array} - Array of contract information
   */
  getAllContracts() {
    return this.contractEngine.getAllContracts();
  }

  /**
   * Deploy a new contract (creates a transaction)
   * @param {string} contractType - Type of contract to deploy
   * @param {Object} initData - Initial contract data
   * @param {string} owner - Contract owner address
   * @param {number} fee - Transaction fee
   * @returns {ContractTransaction} - Contract deployment transaction
   */
  createContractDeployment(contractType, initData, owner, fee = 0) {
    return ContractTransaction.createDeployment(contractType, initData, owner, fee);
  }

  /**
   * Create a contract execution transaction
   * @param {string} contractAddress - Contract address
   * @param {string} method - Method to call
   * @param {Object} params - Method parameters
   * @param {string} caller - Caller address
   * @param {number} fee - Transaction fee
   * @returns {ContractTransaction} - Contract execution transaction
   */
  createContractExecution(contractAddress, method, params, caller, fee = 0) {
    return ContractTransaction.createExecution(contractAddress, method, params, caller, fee);
  }

  /**
   * Clear blockchain (for testing/reset purposes)
   */
  clearChain() {
    this.chain = [];
    this.difficulty = 1000;
    this.miningReward = this.config.blockchain.coinbaseReward;
    this.blockTime = 60000;
    this.historicalTransactions.clear();
    this.historicalTransactionIds.clear();
    this.clearUnsavedBuffer(); // Clear unsaved transaction buffer
    this.lastSavedBlockHeight = -1; // Reset last saved block height
    this.utxoManager.clearUTXOs();
    this.memoryPool.clear();
    this.spamProtection.reset();

    // Clear contract engine
    this.contractEngine = new ContractEngine(this);

    logger.info('BLOCKCHAIN', 'Blockchain and contracts cleared successfully');
    return true;
  }

  /**
   * Calculate total supply including all mining rewards with halving
   * @returns {number} Total supply in atomic units
   */
  calculateTotalSupply() {
    let totalMiningRewards = 0;
    const baseReward = this.config?.blockchain?.coinbaseReward || 5000000000;
    const halvingBlocks = this.config?.blockchain?.halvingBlocks || 1000;

    // Calculate rewards for each block considering halving
    for (let i = 0; i < this.chain.length; i++) {
      const blockReward = calculateHalvedReward(i, baseReward, halvingBlocks);
      totalMiningRewards += blockReward;
    }

    logger.debug(
      'BLOCKCHAIN',
      `Calculating total supply: ${this.chain.length} blocks with halving every ${halvingBlocks} blocks = ${totalMiningRewards} atomic units`
    );

    return totalMiningRewards;
  }

  /**
   * Get total supply in circulation
   * @returns {number} Total supply in atomic units
   */
  getTotalSupply() {
    return this.calculateTotalSupply();
  }

  /**
   * Get security report
   */
  getSecurityReport() {
    return {
      chainLength: this.chain.length,
      lastBlockHash: this.getLatestBlock()?.hash || 'none',
      difficulty: this.difficulty,
      pendingTransactions: this.memoryPool.getPendingTransactionCount(),
      utxoCount: this.utxoManager.getUTXOCount(),
      spamProtection: this.spamProtection.getStatus(),
      validationStatus: this.isValidChain(),
    };
  }

  /**
   *
   * @param difficulty
   * @param miningReward
   * @param blockTime
   */
  setBlockchainProperties(difficulty, miningReward, blockTime) {
    this.difficulty = difficulty || this.difficulty;
    // Don't store miningReward statically - use dynamic calculation instead
    this.blockTime = blockTime || this.blockTime;

    logger.debug(
      'BLOCKCHAIN',
      `Setting blockchain properties: difficulty=${this.difficulty}, blockTime=${this.blockTime}, halvingBlocks=${this.config?.blockchain?.halvingBlocks || 1000}`
    );
  }

  /**
   * CRITICAL: Pause block acceptance during network partitions
   */
  pauseBlockAcceptance() {
    this.blockAcceptancePaused = true;
    logger.warn('BLOCKCHAIN', 'Block acceptance PAUSED for consensus protection');
  }

  /**
   * CRITICAL: Resume block acceptance after partition recovery
   */
  resumeBlockAcceptance() {
    this.blockAcceptancePaused = false;
    logger.info('BLOCKCHAIN', 'Block acceptance RESUMED - consensus restored');
  }

  /**
   * CRITICAL: Enable conservative mode during potential attacks
   * @param {boolean} enabled - Enable or disable conservative mode
   */
  setConservativeMode(enabled) {
    this.conservativeMode = enabled;
    if (enabled) {
      logger.warn('BLOCKCHAIN', 'Conservative mode ACTIVATED - enhanced security measures');
    } else {
      logger.info('BLOCKCHAIN', 'Conservative mode DEACTIVATED');
    }
  }

  /**
   * Check if block acceptance is currently paused
   * @returns {boolean}
   */
  isBlockAcceptancePaused() {
    return this.blockAcceptancePaused;
  }

  /**
   * Check if blockchain is in conservative mode
   * @returns {boolean}
   */
  isConservativeMode() {
    return this.conservativeMode;
  }
}

module.exports = Blockchain;
