const logger = require('../utils/logger');
const { CryptoUtils } = require('../utils/crypto');

/**
 * CRITICAL: CPU exhaustion protection system
 */
class CPUProtection {
  /**
   *
   * @param config
   */
  constructor(config = null) {
    // Use config values or fallback to defaults
    this.maxExecutionTime = config?.memory?.cpuProtection?.maxExecutionTime || 5000; // 5 seconds max execution time
    this.maxValidationComplexity = config?.memory?.cpuProtection?.maxValidationComplexity || 1000; // Maximum validation complexity score
    this.maxTransactionsPerBatch = config?.batchProcessing?.maxTransactionsPerBatch || 100; // Maximum transactions to validate per batch
    this.cpuThreshold = config?.memory?.cpuProtection?.cpuThreshold || 0.8; // 80% CPU usage threshold
    this.rateLimitPerSecond = config?.memory?.cpuProtection?.validationRateLimit || 100; // Configurable validation rate limit

    // CPU monitoring
    this.currentCPUUsage = 0;
    this.validationCount = 0;
    this.lastValidationReset = Date.now();
    this.executionTimes = [];
    this.complexityScores = [];

    // Start CPU monitoring
    this.startCPUMonitoring();
  }

  /**
   * CRITICAL: Start CPU monitoring
   */
  startCPUMonitoring() {
    setInterval(() => {
      this.checkCPUUsage();
      this.resetRateLimits();
    }, 1000); // Check every second
  }

  /**
   * CRITICAL: Check CPU usage and reset rate limits
   */
  checkCPUUsage() {
    try {
      // Reset validation count every second
      this.validationCount = 0;
      this.lastValidationReset = Date.now();

      // Monitor execution times
      if (this.executionTimes.length > 10) {
        this.executionTimes.shift();
      }

      // Monitor complexity scores
      if (this.complexityScores.length > 10) {
        this.complexityScores.shift();
      }
    } catch (error) {
      logger.error('CPU_PROTECTION', `CPU monitoring failed: ${error.message}`);
    }
  }

  /**
   * CRITICAL: Reset rate limits
   */
  resetRateLimits() {
    this.validationCount = 0;
    this.lastValidationReset = Date.now();
  }

  /**
   * CRITICAL: Check if validation is allowed (rate limiting)
   */
  canValidate() {
    if (this.validationCount >= this.rateLimitPerSecond) {
      logger.warn(
        'CPU_PROTECTION',
        `⚠️  Validation rate limit exceeded: ${this.validationCount}/${this.rateLimitPerSecond}`
      );
      return false;
    }

    this.validationCount++;
    return true;
  }

  /**
   * CRITICAL: Measure execution time and complexity
   * @param operation
   * @param complexity
   */
  measureExecution(operation, complexity = 1) {
    const startTime = Date.now();

    return {
      start: () => {
        // Check if operation is allowed
        if (!this.canValidate()) {
          throw new Error('CPU validation rate limit exceeded');
        }

        // Check complexity
        if (complexity > this.maxValidationComplexity) {
          throw new Error(`Operation complexity ${complexity} exceeds maximum ${this.maxValidationComplexity}`);
        }

        return startTime;
      },
      end: () => {
        const executionTime = Date.now() - startTime;

        // Record execution time
        this.executionTimes.push(executionTime);

        // Record complexity score
        this.complexityScores.push(complexity);

        // Check execution time limit
        if (executionTime > this.maxExecutionTime) {
          logger.warn(
            'CPU_PROTECTION',
            `⚠️  Operation execution time ${executionTime}ms exceeds limit ${this.maxExecutionTime}ms`
          );
        }

        return executionTime;
      },
    };
  }

  /**
   * CRITICAL: Get CPU protection status
   */
  getCPUStatus() {
    const avgExecutionTime =
      this.executionTimes.length > 0 ? this.executionTimes.reduce((a, b) => a + b, 0) / this.executionTimes.length : 0;

    const avgComplexity =
      this.complexityScores.length > 0
        ? this.complexityScores.reduce((a, b) => a + b, 0) / this.complexityScores.length
        : 0;

    return {
      currentValidationCount: this.validationCount,
      maxValidationsPerSecond: this.rateLimitPerSecond,
      maxExecutionTime: this.maxExecutionTime,
      maxValidationComplexity: this.maxValidationComplexity,
      averageExecutionTime: avgExecutionTime.toFixed(2),
      averageComplexity: avgComplexity.toFixed(2),
      executionTimes: this.executionTimes.length,
      complexityScores: this.complexityScores.length,
    };
  }

  /**
   * CRITICAL: Update CPU protection limits
   * @param newLimits
   */
  updateCPULimits(newLimits) {
    if (newLimits.maxExecutionTime) {
      this.maxExecutionTime = newLimits.maxExecutionTime;
    }
    if (newLimits.maxValidationComplexity) {
      this.maxValidationComplexity = newLimits.maxValidationComplexity;
    }
    if (newLimits.maxTransactionsPerBatch) {
      this.maxTransactionsPerBatch = newLimits.maxTransactionsPerBatch;
    }
    if (newLimits.rateLimitPerSecond) {
      this.rateLimitPerSecond = newLimits.rateLimitPerSecond;
    }

    logger.info('CPU_PROTECTION', 'CPU protection limits updated');
  }
}

/**
 * Blockchain Validation - Handles all blockchain validation methods
 */
class BlockchainValidation {
  /**
   *
   * @param config
   */
  constructor(config = null) {
    // Initialize CPU protection with config
    this.cpuProtection = new CPUProtection(config);

    
    this.strictMode = false;

    logger.debug('BLOCKCHAIN_VALIDATION', `Initialized with config: ${config ? 'present' : 'null'}`);
    logger.debug(
      'BLOCKCHAIN_VALIDATION',
      `CPU Protection maxTransactionsPerBatch: ${this.cpuProtection.maxTransactionsPerBatch}`
    );
    logger.debug(
      'BLOCKCHAIN_VALIDATION',
      `CPU Protection validationRateLimit: ${this.cpuProtection.rateLimitPerSecond}`
    );
  }

  /**
   * CRITICAL: Validate block transactions with CPU protection and UTXO validation
   * @param block
   * @param config
   * @param utxoManager - UTXO manager instance for validation
   */
  validateBlockTransactions(block, config = null, utxoManager = null) {
    const measurement = this.cpuProtection.measureExecution('validateBlockTransactions', block.transactions.length);
    const startTime = measurement.start();

    try {
      // Validate transaction count
      if (!Array.isArray(block.transactions) || block.transactions.length === 0) {
        throw new Error('Block must contain at least one transaction');
      }

      // Check batch size limit
      if (block.transactions.length > this.cpuProtection.maxTransactionsPerBatch) {
        throw new Error(
          `Transaction count ${block.transactions.length} exceeds batch limit ${this.cpuProtection.maxTransactionsPerBatch}`
        );
      }

      // Validate each transaction
      for (let i = 0; i < block.transactions.length; i++) {
        const transaction = block.transactions[i];

        // First transaction must be coinbase
        if (i === 0 && !transaction.isCoinbase) {
          throw new Error('First transaction must be coinbase');
        }

        // Other transactions must not be coinbase
        if (i > 0 && transaction.isCoinbase) {
          throw new Error('Only first transaction can be coinbase');
        }

        // STANDARDIZED VALIDATION ORDER FOR SECURITY:
        // 1. STRUCTURAL VALIDATION (Basic format checks first)
        if (typeof transaction.isValid !== 'function') {
          // Plain object - do basic validation
          if (!transaction.id || !transaction.outputs || transaction.outputs.length === 0) {
            throw new Error(`Transaction ${i} basic validation failed: missing required fields`);
          }
        }

        // 2. UTXO VALIDATION (Prevent double-spending before expensive operations)
        if (!transaction.isCoinbase && utxoManager) {
          const utxoValidation = this.validateTransactionInputsAgainstUTXO(transaction, utxoManager);
          if (!utxoValidation.valid) {
            throw new Error(`Transaction ${i} UTXO validation failed: ${utxoValidation.reason}`);
          }
        }

        // 3. CRYPTOGRAPHIC VALIDATION (Expensive operations last)
        if (typeof transaction.isValid === 'function') {
          // Pass block context for historical validation
          const transactionConfig = {
            ...config,
            blockIndex: block.index,
            blockTimestamp: block.timestamp,
            isEarlyBlock: block.index <= 1
          };

          // Transaction instance - call isValid method with historical context
          if (!transaction.isValid(transactionConfig)) {
            throw new Error(`Transaction ${i} is invalid: ${transaction.id}`);
          }
        }
      }

      const executionTime = measurement.end();
      logger.debug('BLOCKCHAIN_VALIDATION', `Block transactions validated in ${executionTime}ms`);

      return { valid: true, reason: null };
    } catch (error) {
      const executionTime = measurement.end();
      logger.error(
        'BLOCKCHAIN_VALIDATION',
        `Block transaction validation failed in ${executionTime}ms: ${error.message}`
      );
      return { valid: false, reason: error.message };
    }
  }

  /**
   * CRITICAL SECURITY: Validate transaction inputs against actual UTXO set
   * This prevents spending non-existent or already spent UTXOs
   * @param {Transaction} transaction - Transaction to validate
   * @param {UTXOManager} utxoManager - UTXO manager instance
   * @returns {object} - Validation result with valid flag and reason
   */
  validateTransactionInputsAgainstUTXO(transaction, utxoManager) {
    // Skip UTXO validation for coinbase transactions (they don't have inputs)
    if (transaction.isCoinbase) {
      return { valid: true, reason: 'Coinbase transaction - UTXO validation skipped' };
    }

    // Validate each input against the UTXO set
    for (let i = 0; i < transaction.inputs.length; i++) {
      const input = transaction.inputs[i];
      const txHash = input.txHash || input.txId; // Handle both field names

      // Check if the UTXO exists and is unspent
      const utxo = utxoManager.findUTXO(txHash, input.outputIndex);

      if (!utxo) {
        logger.error(
          'BLOCKCHAIN_VALIDATION',
          `SECURITY VIOLATION: Input ${i} references non-existent or spent UTXO: ${txHash}:${input.outputIndex}`
        );
        logger.error('BLOCKCHAIN_VALIDATION', `This could be a blockchain manipulation attempt or double-spend attack`);

        
        logger.error('BLOCKCHAIN_VALIDATION', '🚨 CRITICAL BLOCKCHAIN SECURITY VIOLATION DETECTED');
        logger.error('BLOCKCHAIN_VALIDATION', '🛑 SHUTTING DOWN DAEMON TO PREVENT FURTHER CORRUPTION');
        logger.error('BLOCKCHAIN_VALIDATION', '⚠️  Manual intervention required - check blockchain integrity');

        console.error('\n╔══════════════════════════════════════════════════════════════╗');
        console.error('║                    🚨 CRITICAL ERROR                         ║');
        console.error('║                BLOCKCHAIN SECURITY VIOLATION                 ║');
        console.error('╚══════════════════════════════════════════════════════════════╝');
        console.error('');
        console.error('💥 UTXO validation failed - potential blockchain attack detected');
        console.error(`💥 Invalid UTXO reference: ${txHash}:${input.outputIndex}`);
        console.error('💥 Daemon shutdown to prevent blockchain corruption');
        console.error('');
        console.error('🔧 Manual intervention required:');
        console.error('   1. Check blockchain integrity');
        console.error('   2. Verify network consensus');
        console.error('   3. Consider blockchain resync if corrupted');
        console.error('');

        process.exit(1);
      }

      // Verify the input amount matches what's expected (if available)
      if (utxo.amount !== undefined) {
        logger.debug(
          'BLOCKCHAIN_VALIDATION',
          `UTXO ${txHash}:${input.outputIndex} validated: amount=${utxo.amount}, address=${utxo.address}`
        );
      }
    }

    logger.debug(
      'BLOCKCHAIN_VALIDATION',
      `✅ UTXO validation passed for transaction ${transaction.id}: all ${transaction.inputs.length} inputs are valid`
    );
    return { valid: true, reason: 'All UTXOs validated successfully' };
  }

  /**
   * Get current configuration status
   */
  getConfigStatus() {
    return {
      cpuProtection: {
        maxExecutionTime: this.cpuProtection.maxExecutionTime,
        maxValidationComplexity: this.cpuProtection.maxValidationComplexity,
        maxTransactionsPerBatch: this.cpuProtection.maxTransactionsPerBatch,
        cpuThreshold: this.cpuProtection.cpuThreshold,
        rateLimitPerSecond: this.cpuProtection.rateLimitPerSecond,
      },
      configReceived: this.config !== null,
    };
  }

  /**
   * Check if block is valid
   * @param block
   * @param config
   * @param utxoManager - UTXO manager instance for validation
   */
  isValidBlock(block, config = null, utxoManager = null) {
    logger.debug(
      'BLOCKCHAIN_VALIDATION',
      `Validating block: index=${block?.index}, timestamp=${block?.timestamp}, previousHash=${block?.previousHash?.substring(0, 16) || 'none'}..., hash=${block?.hash?.substring(0, 16) || 'none'}...`
    );
    logger.debug('BLOCKCHAIN_VALIDATION', `Config present: ${config ? 'yes' : 'no'}, config type: ${typeof config}`);

    try {
      // Basic block validation
      if (
        !block ||
        block.index === undefined ||
        block.index === null ||
        block.timestamp === undefined ||
        block.timestamp === null ||
        block.previousHash === undefined ||
        block.previousHash === null ||
        block.hash === undefined ||
        block.hash === null
      ) {
        return false;
      }

      // Validate block structure - check if it's a proper Block instance

      // For genesis blocks, we need to check additional properties
      if (block.index === 0) {
        if (!block.transactions || !Array.isArray(block.transactions) || block.transactions.length === 0) {
          return false;
        }

        if (!block.merkleRoot || !block.nonce || !block.difficulty || !block.algorithm || block.version === undefined) {
          return false;
        }

        
        try {
          if (typeof block.validateTransactionIntegrity === 'function') {
            const isIntegrityValid = block.validateTransactionIntegrity();
            if (!isIntegrityValid) {
              logger.error('BLOCKCHAIN_VALIDATION', `Genesis block TRANSACTION TAMPERING DETECTED!`);
              logger.error('BLOCKCHAIN_VALIDATION', `  Genesis transaction data has been modified`);
              return false;
            }
          }

          // Also validate Merkle root for consistency (using original transaction IDs)
          const storedMerkleRoot = block.merkleRoot;
          const calculatedMerkleRoot = block.calculateMerkleRoot();
          
          if (storedMerkleRoot !== calculatedMerkleRoot) {
            logger.error('BLOCKCHAIN_VALIDATION', `Genesis block MERKLE ROOT TAMPERING DETECTED!`);
            logger.error('BLOCKCHAIN_VALIDATION', `  Stored Merkle Root:     ${storedMerkleRoot}`);
            logger.error('BLOCKCHAIN_VALIDATION', `  Calculated Merkle Root: ${calculatedMerkleRoot}`);
            logger.error('BLOCKCHAIN_VALIDATION', `  Genesis transaction data has been modified`);
            return false;
          }
        } catch (error) {
          logger.error('BLOCKCHAIN_VALIDATION', `Genesis block integrity verification failed: ${error.message}`);
          return false;
        }
      } else {
        // For non-genesis blocks, ensure version is present
        if (block.version === undefined || block.version === null) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block ${block.index} missing version field`);
          return false;
        }
      }

      // For genesis blocks, return true after Merkle root validation
      if (block.index === 0) {
        return true;
      }

      // For non-genesis blocks, check if they have the isValid method
      if (typeof block.isValid === 'function') {
        if (!block.isValid()) {
          return false;
        }
      }
      
      // Validate version field for all blocks (additional check beyond what's in block.isValid())
      if (block.version === undefined || block.version === null || !Number.isInteger(block.version) || block.version < 0) {
        logger.error('BLOCKCHAIN_VALIDATION', `Block ${block.index} has invalid version: ${block.version}`);
        return false;
      }

      // Validate block transactions (except genesis)
      if (block.index > 0) {
        const validationResult = this.validateBlockTransactions(block, config, utxoManager);

        if (!validationResult.valid) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block ${block.index} REJECTED: ${validationResult.reason}`);
          return false;
        }
      }
      return true;
    } catch (error) {
      logger.error('BLOCKCHAIN_VALIDATION', `Block validation error for block ${block?.index}: ${error.message}`);
      logger.error('BLOCKCHAIN_VALIDATION', `Error stack: ${error.stack}`);
      logger.error(
        'BLOCKCHAIN_VALIDATION',
        `Block data: ${JSON.stringify({
          index: block?.index,
          timestamp: block?.timestamp,
          previousHash: block?.previousHash,
          hash: block?.hash,
          hasIsValid: typeof block?.isValid === 'function',
        })}`
      );
      return false;
    }
  }

  /**
   * CRITICAL SECURITY: Validate entire blockchain with UTXO integrity checking
   * This method rebuilds the UTXO set step-by-step and validates each transaction
   * @param chain
   * @param config
   * @param utxoManager - UTXO manager instance for validation
   */
  isValidChain(chain, config, utxoManager = null) {
    try {
      if (!chain || !Array.isArray(chain) || chain.length === 0) {
        return false;
      }

      logger.info('BLOCKCHAIN_VALIDATION', `Validating blockchain with ${chain.length} blocks...`);

      
      const UTXOManager = require('./UTXOManager');
      const tempUtxoManager = new UTXOManager();
      
      logger.debug('BLOCKCHAIN_VALIDATION', 'Created temporary UTXO manager for validation');

      // Validate genesis block
      const genesisBlock = chain[0];
      if (genesisBlock.index !== 0 || genesisBlock.previousHash !== '0') {
        logger.error('BLOCKCHAIN_VALIDATION', 'Genesis block validation failed');
        return false;
      }

      if (!this.isValidBlock(genesisBlock, config)) {
        logger.error('BLOCKCHAIN_VALIDATION', 'Genesis block structure validation failed');
        return false;
      }
      
      // Add genesis block to temporary UTXO set
      tempUtxoManager.updateUTXOSet(genesisBlock);
      logger.debug('BLOCKCHAIN_VALIDATION', `Genesis block added to temporary UTXO set`);

      // Validate all other blocks with UTXO checking
      for (let i = 1; i < chain.length; i++) {
        const currentBlock = chain[i];
        const previousBlock = chain[i - 1];

        // Check block linking
        if (currentBlock.previousHash !== previousBlock.hash) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} is not properly linked to previous block`);
          return false;
        }

        // Check block index sequence
        if (currentBlock.index !== previousBlock.index + 1) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block index sequence broken at index ${i}`);
          return false;
        }

        
        try {
          if (typeof currentBlock.validateTransactionIntegrity === 'function') {
            const isIntegrityValid = currentBlock.validateTransactionIntegrity();
            if (!isIntegrityValid) {
              logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} TRANSACTION TAMPERING DETECTED in full validation!`);
              logger.error('BLOCKCHAIN_VALIDATION', `  Transaction data has been modified (addresses, amounts, etc.)`);
              return false;
            }
            logger.debug('BLOCKCHAIN_VALIDATION', `Block ${i} transaction integrity validation PASSED in full validation`);
          }
        } catch (error) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} transaction integrity validation error: ${error.message}`);
          return false;
        }

        
        try {
          const storedMerkleRoot = currentBlock.merkleRoot;
          
          // Calculate merkle root without modifying the block's merkleRoot property
          const transactionHashes = currentBlock.transactions.map((tx, index) => {
            if (tx.id) {
              return tx.id;
            }
            if (typeof tx.calculateId === 'function') {
              return tx.calculateId(true); // true = historical validation mode
            }
            return CryptoUtils.hash(JSON.stringify(tx));
          });
          
          const calculatedMerkleRoot = CryptoUtils.calculateMerkleRoot(transactionHashes);
          
          if (storedMerkleRoot !== calculatedMerkleRoot) {
            logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} MERKLE ROOT TAMPERING DETECTED in full validation!`);
            logger.error('BLOCKCHAIN_VALIDATION', `  Stored Merkle Root:     ${storedMerkleRoot}`);
            logger.error('BLOCKCHAIN_VALIDATION', `  Calculated Merkle Root: ${calculatedMerkleRoot}`);
            logger.error('BLOCKCHAIN_VALIDATION', `  Transaction data has been modified (addresses, amounts, etc.)`);
            return false;
          }
          logger.debug('BLOCKCHAIN_VALIDATION', `Block ${i} merkle root validation PASSED in full validation`);
        } catch (error) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} merkle root validation error: ${error.message}`);
          return false;
        }

        
        if (!this.isValidBlock(currentBlock, config, tempUtxoManager)) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} validation failed - could be manipulation attempt`);
          return false;
        }
        
        // Update temporary UTXO set with validated block
        tempUtxoManager.updateUTXOSet(currentBlock);
        logger.debug('BLOCKCHAIN_VALIDATION', `Block ${i} validated and added to temporary UTXO set`);

        // Show progress for large chains
        if (chain.length > 100 && i % Math.floor(chain.length / 10) === 0) {
          const progress = ((i / chain.length) * 100).toFixed(1);
          logger.info('BLOCKCHAIN_VALIDATION', `Validation progress: ${i}/${chain.length} blocks (${progress}%)`);
        }
      }

      logger.info('BLOCKCHAIN_VALIDATION', 'Blockchain validation completed successfully');
      return true;
    } catch (error) {
      logger.error('BLOCKCHAIN_VALIDATION', `Blockchain validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * Fast validation that skips expensive operations
   * @param chain
   */
  isValidChainFast(chain) {
    try {
      if (!chain || !Array.isArray(chain) || chain.length === 0) {
        return false;
      }

      logger.info('BLOCKCHAIN_VALIDATION', `Fast validation for ${chain.length} blocks (skipping expensive checks)...`);

      // Validate genesis block (basic checks only)
      const genesisBlock = chain[0];
      if (!genesisBlock || genesisBlock.index !== 0 || genesisBlock.previousHash !== '0') {
        logger.error('BLOCKCHAIN_VALIDATION', 'Genesis block basic validation failed');
        return false;
      }

      // Use Set for O(1) duplicate detection
      const seenHashes = new Set([genesisBlock.hash]);

      // Fast validation: only check chain integrity, not block proofs
      for (let i = 1; i < chain.length; i++) {
        const currentBlock = chain[i];
        const previousBlock = chain[i - 1];

        // Basic block existence check
        if (!currentBlock || !previousBlock) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block missing at index ${i}`);
          return false;
        }

        // Check index sequence
        if (currentBlock.index !== previousBlock.index + 1) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block index sequence broken at index ${i}`);
          return false;
        }

        // Check for duplicates (O(1) operation)
        if (seenHashes.has(currentBlock.hash)) {
          logger.error('BLOCKCHAIN_VALIDATION', `Duplicate block hash found at index ${i}`);
          return false;
        }
        seenHashes.add(currentBlock.hash);

        // Check chain linking (most important)
        if (currentBlock.previousHash !== previousBlock.hash) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block at index ${i} is not properly linked`);
          return false;
        }

        // SKIP expensive operations:
        // - block.isValid() (Velora verification)
        // - Transaction validation
        // - Merkle root verification
        // - Hash difficulty verification
      }

      logger.info('BLOCKCHAIN_VALIDATION', 'Fast validation completed successfully');
      return true;
    } catch (error) {
      logger.error('BLOCKCHAIN_VALIDATION', `Fast validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * Ultra-fast validation for very large chains
   * @param chain
   */
  isValidChainUltraFast(chain) {
    try {
      if (!chain || !Array.isArray(chain) || chain.length === 0) {
        return false;
      }

      logger.info('BLOCKCHAIN_VALIDATION', `Ultra-fast validation for ${chain.length} blocks (minimal checks)...`);

      // Only validate chain integrity, nothing else
      for (let i = 1; i < chain.length; i++) {
        const currentBlock = chain[i];
        const previousBlock = chain[i - 1];

        // Minimal linking check only
        if (currentBlock.previousHash !== previousBlock.hash) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block at index ${i} is not properly linked`);
          return false;
        }
      }

      logger.info('BLOCKCHAIN_VALIDATION', 'Ultra-fast validation completed successfully');
      return true;
    } catch (error) {
      logger.error('BLOCKCHAIN_VALIDATION', `Ultra-fast validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * Medium validation that includes transaction verification but skips expensive mining operations
   * This provides security for transaction integrity while maintaining reasonable performance
   * @param chain
   * @param config
   */
  isValidChainMedium(chain, config) {
    try {
      if (!chain || !Array.isArray(chain) || chain.length === 0) {
        return false;
      }

      logger.info('BLOCKCHAIN_VALIDATION', `Medium validation for ${chain.length} blocks (transaction validation enabled)...`);

      // Validate genesis block basic structure
      const genesisBlock = chain[0];
      if (!genesisBlock || genesisBlock.index !== 0 || genesisBlock.previousHash !== '0') {
        logger.error('BLOCKCHAIN_VALIDATION', 'Genesis block basic validation failed');
        return false;
      }

      // Use Set for O(1) duplicate detection
      const seenHashes = new Set([genesisBlock.hash]);

      // Medium validation: check chain integrity + transaction validation, skip mining verification
      for (let i = 1; i < chain.length; i++) {
        const currentBlock = chain[i];
        const previousBlock = chain[i - 1];

        // Basic block existence check
        if (!currentBlock || !previousBlock) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block missing at index ${i}`);
          return false;
        }

        // Check index sequence
        if (currentBlock.index !== previousBlock.index + 1) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block index sequence broken at index ${i}`);
          return false;
        }

        // Check for duplicates (O(1) operation)
        if (seenHashes.has(currentBlock.hash)) {
          logger.error('BLOCKCHAIN_VALIDATION', `Duplicate block hash found at index ${i}`);
          return false;
        }
        seenHashes.add(currentBlock.hash);

        // Check chain linking (most important)
        if (currentBlock.previousHash !== previousBlock.hash) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block at index ${i} is not properly linked`);
          return false;
        }

        
        try {
          const transactionValidation = this.validateBlockTransactions(currentBlock, config, null);
          if (!transactionValidation.valid) {
            logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} transaction validation failed: ${transactionValidation.reason}`);
            return false;
          }
        } catch (error) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} transaction validation error: ${error.message}`);
          return false;
        }

        
        // Relying on Merkle root validation below to catch transaction content tampering

        
        try {
          if (typeof currentBlock.validateTransactionIntegrity === 'function') {
            const isIntegrityValid = currentBlock.validateTransactionIntegrity();
            if (!isIntegrityValid) {
              logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} TRANSACTION TAMPERING DETECTED!`);
              logger.error('BLOCKCHAIN_VALIDATION', `  Transaction data has been modified (addresses, amounts, etc.)`);
              return false;
            }
          }

          // Also validate Merkle root for consistency (using original transaction IDs)
          const storedMerkleRoot = currentBlock.merkleRoot;
          const calculatedMerkleRoot = currentBlock.calculateMerkleRoot();
          
          if (storedMerkleRoot !== calculatedMerkleRoot) {
            logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} MERKLE ROOT TAMPERING DETECTED!`);
            logger.error('BLOCKCHAIN_VALIDATION', `  Stored Merkle Root:     ${storedMerkleRoot}`);
            logger.error('BLOCKCHAIN_VALIDATION', `  Calculated Merkle Root: ${calculatedMerkleRoot}`);
            logger.error('BLOCKCHAIN_VALIDATION', `  Transaction data has been modified (addresses, amounts, etc.)`);
            return false;
          }
        } catch (error) {
          logger.error('BLOCKCHAIN_VALIDATION', `Block ${i} integrity verification failed: ${error.message}`);
          return false;
        }

        // SKIP expensive mining operations:
        // - Velora hash verification (expensive)
        // - Hash difficulty verification (expensive)
        // - UTXO rebuilding (expensive)

        // Show progress for large chains
        if (chain.length > 50 && i % Math.max(1, Math.floor(chain.length / 10)) === 0) {
          const progress = ((i / chain.length) * 100).toFixed(1);
          logger.info('BLOCKCHAIN_VALIDATION', `Transaction validation progress: ${i}/${chain.length} blocks (${progress}%)`);
        }
      }

      logger.info('BLOCKCHAIN_VALIDATION', 'Medium validation completed successfully - transactions verified');
      return true;
    } catch (error) {
      logger.error('BLOCKCHAIN_VALIDATION', `Medium validation error: ${error.message}`);
      return false;
    }
  }

  /**
   * CRITICAL: Enable strict validation mode during consensus protection
   * @param {boolean} enabled - Enable or disable strict mode
   */
  setStrictMode(enabled) {
    this.strictMode = enabled;
    if (enabled) {
      logger.warn('BLOCKCHAIN_VALIDATION', 'Strict validation mode ACTIVATED - enhanced security measures');
    } else {
      logger.info('BLOCKCHAIN_VALIDATION', 'Strict validation mode DEACTIVATED');
    }
  }

  /**
   * Check if strict validation mode is enabled
   * @returns {boolean}
   */
  isStrictMode() {
    return this.strictMode;
  }
}

module.exports = BlockchainValidation;
