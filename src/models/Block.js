const { TRANSACTION_TAGS } = require('../utils/constants');
const { CryptoUtils } = require('../utils/crypto');
const logger = require('../utils/logger');

const { Transaction } = require('./Transaction');

/**
 *
 */
class Block {
  /**
   *
   * @param index
   * @param timestamp
   * @param transactions
   * @param previousHash
   * @param nonce
   * @param difficulty
   * @param config
   * @param validationContext
   */
  constructor(
    index,
    timestamp,
    transactions,
    previousHash,
    nonce = 0,
    difficulty = 4,
    config = null,
    validationContext = null,
    skipMerkleCalculation = false
  ) {
    this.index = index;
    this.timestamp = timestamp;
    this.transactions = transactions;
    this.previousHash = previousHash;
    this.nonce = nonce;
    this.difficulty = difficulty;
    this.hash = null;
    this.merkleRoot = null;
    this.config = config;

    // CRITICAL: Timestamp validation
    this.validateTimestamp(validationContext);

    // Calculate Merkle root (skip when loading from JSON for validation purposes)
    if (!skipMerkleCalculation) {
      this.calculateMerkleRoot();
    }
  }

  /**
   * CRITICAL: Validate timestamp to prevent manipulation attacks
   * @param {object} validationContext - Context for validation (for historical blocks)
   * @param {boolean} validationContext.isHistoricalLoad - If true, this is a historical block being loaded
   * @param {number} validationContext.previousBlockTimestamp - Timestamp of previous block for historical validation
   */
  validateTimestamp(validationContext = null) {
    const currentTime = Date.now();
    const maxFutureTime = 2 * 60 * 1000; // 2 minutes in future
    const maxPastTime = 24 * 60 * 60 * 1000; // 24 hours in past
    const minBlockTime = 1000; // 1 second minimum between blocks

    // Check if timestamp is negative
    if (this.timestamp < 0) {
      throw new Error(`Block timestamp ${this.timestamp} cannot be negative`);
    }

    // Check if timestamp is a valid number
    if (isNaN(this.timestamp) || !isFinite(this.timestamp)) {
      throw new Error(`Block timestamp ${this.timestamp} is not a valid number`);
    }

    // Check if timestamp is an integer
    if (!Number.isInteger(this.timestamp)) {
      throw new Error(`Block timestamp ${this.timestamp} must be an integer`);
    }

    // Handle historical block loading vs new block validation
    if (validationContext && validationContext.isHistoricalLoad) {
      // For historical blocks, validate against previous block timestamp
      if (validationContext.previousBlockTimestamp !== undefined && this.index > 0) {
        // Ensure timestamp is after previous block (with minimum interval)
        if (this.timestamp <= validationContext.previousBlockTimestamp) {
          throw new Error(
            `Historical block timestamp ${this.timestamp} must be after previous block timestamp ${validationContext.previousBlockTimestamp}`
          );
        }

        // Ensure reasonable time gap (not too close together)
        if (this.timestamp - validationContext.previousBlockTimestamp < minBlockTime) {
          throw new Error(
            `Historical block timestamp ${this.timestamp} is too close to previous block (min gap: ${minBlockTime}ms)`
          );
        }
      }

      logger.debug(
        'BLOCK',
        `Historical timestamp validation passed: ${this.timestamp} (previous: ${validationContext.previousBlockTimestamp || 'N/A'})`
      );
    } else {
      // For new blocks being mined, validate against current time
      if (this.timestamp > currentTime + maxFutureTime) {
        throw new Error(
          `Block timestamp ${this.timestamp} is too far in the future (max: ${currentTime + maxFutureTime})`
        );
      }

      // Check if timestamp is too far in the past (skip for genesis blocks)
      if (this.index !== 0 && this.timestamp < currentTime - maxPastTime) {
        throw new Error(`Block timestamp ${this.timestamp} is too far in the past (min: ${currentTime - maxPastTime})`);
      }

      logger.debug('BLOCK', `Timestamp validation passed: ${this.timestamp} (current: ${currentTime})`);
    }
  }

  /**
   * Calculate block hash using SHA256 (for CPU mining)
   */
  calculateId() {
    const data = JSON.stringify({
      index: this.index,
      timestamp: this.timestamp,
      previousHash: this.previousHash,
      merkleRoot: this.merkleRoot,
      nonce: this.nonce,
      difficulty: this.difficulty,
    });

    this.hash = CryptoUtils.doubleHash(data);
    this.algorithm = 'sha256';
    return this.hash;
  }

  /**
   * Calculate block hash using Velora (for GPU mining)
   */
  calculateVeloraId() {
    try {
      // Import Velora utils dynamically to avoid circular dependencies
      const VeloraUtils = require('../utils/velora');
      const veloraUtils = new VeloraUtils();

      // Calculate Velora hash with all required parameters
      // The veloraHash function handles scratchpad generation and caching internally
      this.hash = veloraUtils.veloraHash(
        this.index, // blockNumber
        this.nonce, // nonce
        this.timestamp, // timestamp
        this.previousHash, // previousHash
        this.merkleRoot, // merkleRoot
        this.difficulty, // difficulty
        null // cache - null to use internal caching
      );
      this.algorithm = 'velora';

      return this.hash;
    } catch (error) {
      console.log(`❌ ERROR: calculateVeloraId failed: ${error.message}`);
      logger.error('BLOCK', `Failed to calculate Velora hash: ${error.message}`);
      // Fallback to SHA256
      return this.calculateId();
    }
  }

  /**
   * Alias for calculateId() for compatibility
   */
  calculateHash() {
    return this.calculateId();
  }

  /**
   * Calculate Merkle root from transactions
   */
  calculateMerkleRoot() {
    const transactionHashes = this.transactions.map((tx, index) => {
      if (tx.id) {
        return tx.id;
      }

      // If no ID exists, calculate it (for new transactions)
      if (typeof tx.calculateId === 'function') {
        return tx.calculateId(true); // true = historical validation mode
      }

      // If it's a plain object, try to create a transaction from it
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

    this.merkleRoot = CryptoUtils.calculateMerkleRoot(transactionHashes);
    return this.merkleRoot;
  }

  /**
   * CRITICAL: Validate that transaction content matches their stored IDs
   * This detects if transaction data has been tampered with
   */
  validateTransactionIntegrity() {
    logger.debug('BLOCK', `Validating transaction integrity for block ${this.index} with ${this.transactions.length} transactions`);
    
    for (let i = 0; i < this.transactions.length; i++) {
      const tx = this.transactions[i];
      
      logger.debug('BLOCK', `  Transaction ${i}: id=${tx.id?.substring(0, 16)}..., hasCalculateId=${typeof tx.calculateId === 'function'}`);
      
      if (tx.id && typeof tx.calculateId === 'function') {
        // Create a temporary copy with original atomic sequence preserved
        const tempTx = Object.assign(Object.create(Object.getPrototypeOf(tx)), tx);
        
        // Temporarily clear the ID to force recalculation
        const originalId = tempTx.id;
        tempTx.id = null;
        
        logger.debug('BLOCK', `  Recalculating ID for transaction ${i} (original: ${originalId?.substring(0, 16)}...)`);
        logger.debug('BLOCK', `  Transaction details: outputs=${JSON.stringify(tempTx.outputs)}, atomicSequence=${tempTx._atomicSequence}`);
        
        try {
          // Recalculate ID using the same method as when block was created
          const calculatedId = tempTx.calculateId(true);
          
          logger.debug('BLOCK', `  Calculated ID: ${calculatedId?.substring(0, 16)}...`);
          
          // Compare with stored ID
          if (originalId !== calculatedId) {
            logger.error('BLOCK', `🚨 TRANSACTION INTEGRITY VIOLATION DETECTED!`);
            logger.error('BLOCK', `  Block: ${this.index}, Transaction: ${i}`);
            logger.error('BLOCK', `  Stored ID: ${originalId}`);
            logger.error('BLOCK', `  Calculated ID: ${calculatedId}`);
            logger.error('BLOCK', `  Transaction outputs: ${JSON.stringify(tempTx.outputs)}`);
            logger.error('BLOCK', `  Transaction data has been modified (amounts, addresses, etc.)`);
            return false;
          }
          
          logger.debug('BLOCK', `  Transaction ${i} integrity verification PASSED`);
        } catch (error) {
          logger.error('BLOCK', `Transaction ${i} ID calculation failed: ${error.message}`);
          return false;
        }
      } else {
        logger.debug('BLOCK', `  Transaction ${i} skipped (no ID or calculateId method)`);
      }
    }
    
    logger.debug('BLOCK', `Block ${this.index} transaction integrity validation PASSED`);
    return true;
  }

  /**
   * Calculate target hash from difficulty
   */
  calculateTarget() {
    logger.debug('BLOCK', `=== TARGET CALCULATION DEBUG ===`);
    logger.debug('BLOCK', `Block Index: ${this.index}`);
    logger.debug('BLOCK', `Block Difficulty: ${this.difficulty}`);

    // Convert difficulty to a target hash
    // Higher difficulty = smaller target (harder to find)
    const maxTarget = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    logger.debug('BLOCK', `Max Target (hex): 0x${maxTarget}`);

    const maxTargetBigInt = BigInt(`0x${maxTarget}`);
    logger.debug('BLOCK', `Max Target (BigInt): ${maxTargetBigInt.toString()}`);

    // For genesis block, respect the user's difficulty setting
    // But ensure it's not impossibly hard (cap at reasonable difficulty)
    if (this.index === 0) {
      // Use the actual difficulty, but cap it to prevent impossible mining
      const genesisDifficulty = Math.min(this.difficulty, 1000); // Cap at 1000
      logger.debug('BLOCK', `Genesis block detected, capping difficulty at 1000, using: ${genesisDifficulty}`);

      const targetHex = maxTargetBigInt / BigInt(Math.max(1, genesisDifficulty));
      const result = targetHex.toString(16).padStart(64, '0');

      logger.debug('BLOCK', `Genesis Target (BigInt): ${targetHex.toString()}`);
      logger.debug('BLOCK', `Genesis Target (hex): 0x${result}`);
      logger.debug('BLOCK', `=== END TARGET CALCULATION DEBUG ===`);

      return result;
    }

    // For other blocks, use the actual difficulty
    // Standard formula: Target = MaxTarget / Difficulty
    const effectiveDifficulty = Math.max(1, this.difficulty);
    logger.debug('BLOCK', `Effective Difficulty: ${effectiveDifficulty}`);

    const targetHex = maxTargetBigInt / BigInt(effectiveDifficulty);
    const result = targetHex.toString(16).padStart(64, '0');

    logger.debug('BLOCK', `Calculated Target (BigInt): ${targetHex.toString()}`);
    logger.debug('BLOCK', `Calculated Target (hex): 0x${result}`);
    logger.debug('BLOCK', `=== END TARGET CALCULATION DEBUG ===`);

    return result;
  }

  /**
   * Verify block hash meets difficulty requirement
   */
  hasValidHash() {
    logger.debug('BLOCK', `=== DIFFICULTY VALIDATION DEBUG ===`);
    logger.debug('BLOCK', `Block Hash: ${this.hash}`);
    logger.debug('BLOCK', `Block Difficulty: ${this.difficulty}`);

    const target = this.calculateTarget();
    logger.debug('BLOCK', `Calculated Target: ${target}`);

    if (!this.hash) {
      logger.debug('BLOCK', `Hash validation failed: no hash provided`);
      logger.debug('BLOCK', `=== END DIFFICULTY VALIDATION DEBUG ===`);
      return false;
    }

    try {
      const hashNum = BigInt(`0x${this.hash}`);
      const targetNum = BigInt(`0x${target}`);

      logger.debug('BLOCK', `Hash as BigInt: ${hashNum.toString()}`);
      logger.debug('BLOCK', `Target as BigInt: ${targetNum.toString()}`);

      const isValid = hashNum <= targetNum;
      logger.debug('BLOCK', `Hash <= Target: ${hashNum.toString()} <= ${targetNum.toString()} = ${isValid}`);

      if (isValid) {
        logger.debug('BLOCK', `✅ Hash meets difficulty requirements`);
      } else {
        logger.debug('BLOCK', `❌ Hash does NOT meet difficulty requirements`);
      }

      logger.debug('BLOCK', `=== END DIFFICULTY VALIDATION DEBUG ===`);
      return isValid;
    } catch (error) {
      logger.error('BLOCK', `Hash validation error: ${error.message}`);
      logger.debug('BLOCK', `=== END DIFFICULTY VALIDATION DEBUG ===`);
      return false;
    }
  }

  /**
   * Verify block hash meets difficulty requirement for specific algorithm
   * @param algorithm
   */
  hasValidHashForAlgorithm(algorithm = 'velora') {
    // For genesis blocks (index 0), be more lenient with hash validation
    // since they're special and may have been created with different parameters
    if (this.index === 0) {
      // Just ensure the hash exists and has the right format
      return this.hash && this.hash.length === 64 && /^[0-9a-f]+$/i.test(this.hash);
    }

    if (algorithm === 'velora') {
      // For Velora, recalculate the hash to verify it's correct
      try {
        const VeloraUtils = require('../utils/velora');
        const veloraUtils = new VeloraUtils();

        // DEBUG: Log all parameters being used for hash validation
        logger.debug('BLOCK', `=== VELORA HASH VALIDATION DEBUG ===`);
        logger.debug('BLOCK', `Block Index: ${this.index}`);
        logger.debug('BLOCK', `Block Hash (submitted): ${this.hash}`);
        logger.debug('BLOCK', `Block Previous Hash: ${this.previousHash}`);
        logger.debug('BLOCK', `Block Merkle Root: ${this.merkleRoot}`);
        logger.debug('BLOCK', `Block Nonce: ${this.nonce}`);
        logger.debug('BLOCK', `Block Timestamp: ${this.timestamp}`);
        logger.debug('BLOCK', `Block Difficulty: ${this.difficulty}`);
        logger.debug('BLOCK', `=== END VELORA HASH VALIDATION DEBUG ===`);

        // CRITICAL: DO NOT pre-generate the scratchpad here!
        // The veloraHash function will handle scratchpad generation and caching internally
        // Pre-generating it causes double-mixing and corrupts the data

        // DEBUG: Log the exact parameters being passed to veloraHash
        logger.debug('BLOCK', `=== VELORA HASH CALL PARAMETERS ===`);
        logger.debug(
          'BLOCK',
          `veloraHash(${this.index}, ${this.nonce}, ${this.timestamp}, ${this.previousHash}, ${this.merkleRoot}, ${this.difficulty}, null)`
        );
        logger.debug('BLOCK', `=== END VELORA HASH CALL PARAMETERS ===`);

        // The miner calculates the hash using these parameters in this order:
        // veloraHash(blockNumber, nonce, timestamp, previousHash, merkleRoot, difficulty, cache)
        // For validation, we pass null as cache to let veloraHash handle scratchpad generation
        const expectedHash = veloraUtils.veloraHash(
          this.index, // blockNumber
          this.nonce, // nonce
          this.timestamp, // timestamp
          this.previousHash, // previousHash
          this.merkleRoot, // merkleRoot
          this.difficulty, // difficulty
          null // cache - null to use internal caching
        );

        // DEBUG: Log the hash comparison
        logger.debug('BLOCK', `=== HASH COMPARISON DEBUG ===`);
        logger.debug('BLOCK', `Expected Hash (daemon calculated): ${expectedHash}`);
        logger.debug('BLOCK', `Submitted Hash (miner): ${this.hash}`);
        logger.debug('BLOCK', `Hashes Match: ${expectedHash === this.hash ? 'YES' : 'NO'}`);
        logger.debug('BLOCK', `=== END HASH COMPARISON DEBUG ===`);

        // If hash matches, also check if it meets difficulty requirement
        if (expectedHash === this.hash) {
          const difficultyValid = this.hasValidHash();
          logger.debug('BLOCK', `Hash validation passed, difficulty check: ${difficultyValid}`);
          return difficultyValid;
        }

        logger.debug('BLOCK', `Hash validation FAILED: expected vs submitted hash mismatch`);
        return false;
      } catch (error) {
        logger.error('BLOCK', `Velora hash verification error: ${error.message}`);
        return false;
      }
    } else {
      // For SHA256, use the standard method
      return this.hasValidHash();
    }
  }

  /**
   * Verify block transactions are valid
   * @param config
   */
  hasValidTransactions(config = null) {
    logger.debug(
      'BLOCK',
      `Validating transactions for block ${this.index}: count=${this.transactions?.length || 0}, config=${config ? 'present' : 'null'}`
    );

    if (!this.transactions || this.transactions.length === 0) {
      logger.debug('BLOCK', `Block ${this.index} has no transactions, validation passed (genesis block)`);
      return true; // Genesis block has no transactions
    }

    // CRITICAL: First transaction must be coinbase
    if (this.transactions.length > 0) {
      const firstTx = this.transactions[0];
      logger.debug(
        'BLOCK',
        `Checking first transaction: id=${firstTx.id}, isCoinbase=${firstTx.isCoinbase}, type=${typeof firstTx.isCoinbase}`
      );
      if (!firstTx.isCoinbase) {
        logger.debug('BLOCK', `Block ${this.index} validation failed: first transaction is not coinbase`);
        return false; // First transaction must be coinbase
      }
    }

    logger.debug('BLOCK', `Validating ${this.transactions.length} transactions individually`);
    for (let i = 0; i < this.transactions.length; i++) {
      const transaction = this.transactions[i];
      logger.debug(
        'BLOCK',
        `Validating transaction ${i}: id=${transaction.id}, isCoinbase=${transaction.isCoinbase}, hasIsValid=${typeof transaction.isValid === 'function'}`
      );

      // Check if transaction has isValid method (Transaction class instance)
      if (typeof transaction.isValid === 'function') {
        logger.debug('BLOCK', `Transaction ${i} has isValid method, calling it with config`);
        try {
          // Pass block context to transaction validation for proper historical expiry validation
          const transactionConfig = {
            ...config,
            blockIndex: this.index,
            blockTimestamp: this.timestamp,
            isEarlyBlock: this.index <= 1
          };
          
          if (!transaction.isValid(transactionConfig)) {
            logger.debug('BLOCK', `Transaction ${i} validation failed: isValid() returned false`);
            return false;
          }
          logger.debug('BLOCK', `Transaction ${i} validation passed`);
        } catch (error) {
          logger.error('BLOCK', `Transaction ${i} validation error: ${error.message}`);
          logger.error('BLOCK', `Error stack: ${error.stack}`);
          return false;
        }
      } else {
        logger.debug('BLOCK', `Transaction ${i} is plain object, doing basic validation`);
        // For plain objects loaded from JSON, do basic validation
        if (!transaction.id || !transaction.outputs || transaction.outputs.length === 0) {
          logger.debug('BLOCK', `Transaction ${i} basic validation failed: missing required fields`);
          logger.debug('BLOCK', `  id: ${transaction.id} (${typeof transaction.id})`);
          logger.debug('BLOCK', `  outputs: ${transaction.outputs} (${typeof transaction.outputs})`);
          logger.debug('BLOCK', `  outputs.length: ${transaction.outputs?.length || 'undefined'}`);
          return false;
        }

        // Additional validation for plain objects
        if (i === 0 && !transaction.isCoinbase) {
          logger.debug('BLOCK', `Transaction ${i} validation failed: first transaction must be coinbase`);
          return false; // First transaction must be coinbase
        }

        if (i > 0 && transaction.isCoinbase) {
          logger.debug('BLOCK', `Transaction ${i} validation failed: only first transaction can be coinbase`);
          return false; // Only first transaction can be coinbase
        }

        logger.debug('BLOCK', `Transaction ${i} basic validation passed`);
      }
    }

    logger.debug('BLOCK', `All ${this.transactions.length} transactions validated successfully`);
    return true;
  }

  /**
   * Verify the entire block is valid
   */
  isValid() {
    logger.debug(
      'BLOCK',
      `Validating block ${this.index}: timestamp=${this.timestamp}, previousHash=${this.previousHash?.substring(0, 16)}..., hash=${this.hash?.substring(0, 16)}...`
    );

    // Check if block has required properties
    if (
      this.index === null ||
      this.index === undefined ||
      this.timestamp === null ||
      this.timestamp === undefined ||
      !this.previousHash ||
      !this.hash
    ) {
      logger.debug('BLOCK', `Block ${this.index} validation failed: missing required properties`);
      logger.debug('BLOCK', `  index: ${this.index} (${typeof this.index})`);
      logger.debug('BLOCK', `  timestamp: ${this.timestamp} (${typeof this.timestamp})`);
      logger.debug('BLOCK', `  previousHash: ${this.previousHash} (${typeof this.previousHash})`);
      logger.debug('BLOCK', `  hash: ${this.hash} (${typeof this.hash})`);
      return false;
    }

    // Check if hash is valid for the current algorithm
    logger.debug('BLOCK', `Checking hash validity for algorithm: ${this.algorithm}`);
    if (!this.hasValidHashForAlgorithm(this.algorithm)) {
      logger.debug('BLOCK', `Block ${this.index} validation failed: invalid hash for algorithm ${this.algorithm}`);
      return false;
    }

    // Check if transactions are valid
    logger.debug('BLOCK', `Validating ${this.transactions?.length || 0} transactions`);
    if (!this.hasValidTransactions(this.config)) {
      logger.debug('BLOCK', `Block ${this.index} validation failed: invalid transactions`);
      return false;
    }

    // Check if merkle root is valid
    logger.debug('BLOCK', `Checking merkle root validity: current=${this.merkleRoot?.substring(0, 16)}...`);
    const calculatedMerkleRoot = this.calculateMerkleRoot();
    logger.debug('BLOCK', `Calculated merkle root: ${calculatedMerkleRoot?.substring(0, 16)}...`);
    if (this.merkleRoot !== calculatedMerkleRoot) {
      logger.debug('BLOCK', `Block ${this.index} validation failed: merkle root mismatch`);
      logger.debug('BLOCK', `  Expected: ${this.merkleRoot}`);
      logger.debug('BLOCK', `  Calculated: ${calculatedMerkleRoot}`);
      return false;
    }

    logger.debug('BLOCK', `Block ${this.index} validation passed successfully`);
    return true;
  }

  /**
   * Create genesis block
   * @param address
   * @param timestamp
   * @param transactions
   * @param difficulty
   * @param genesisConfig
   * @param config
   */
  static createGenesisBlock(
    address,
    timestamp = null,
    transactions = null,
    difficulty = 4,
    genesisConfig = null,
    config = null
  ) {
    const genesisTimestamp = timestamp || Date.now();

    let genesisTransactions = [];

    if (genesisConfig && genesisConfig.premineAmount && genesisConfig.premineAddress) {
      // Create premine transaction
      const premineTransaction = Transaction.createCoinbase(
        genesisConfig.premineAddress,
        genesisConfig.premineAmount,
        genesisTimestamp,
        genesisConfig.nonce || 0,
        genesisConfig.coinbaseAtomicSequence,
        true
      );
      genesisTransactions = [premineTransaction];
    } else if (transactions) {
      // Use provided transactions
      genesisTransactions = transactions;
    } else {
      // Create default coinbase transaction using configured coinbaseReward
      const coinbaseReward = config?.blockchain?.coinbaseReward || 5000000000; // Default to 50 PAS in atomic units
      const coinbaseTransaction = Transaction.createCoinbase(address, coinbaseReward, genesisTimestamp);
      // Don't override the timestamp - keep the passed timestamp for determinism
      coinbaseTransaction.calculateId();
      genesisTransactions = [coinbaseTransaction];
    }

    const genesisBlock = new Block(0, genesisTimestamp, genesisTransactions, '0', 0, difficulty, genesisConfig);

    // Use genesis config if available
    if (genesisConfig && genesisConfig.nonce !== undefined && genesisConfig.hash) {
      genesisBlock.nonce = genesisConfig.nonce;
      genesisBlock.hash = genesisConfig.hash;
      genesisBlock.algorithm = genesisConfig.algorithm || 'velora';
    } else {
      // Create a simple, valid genesis block without complex mining
      genesisBlock.calculateMerkleRoot();

      // Use a simple approach: just calculate the hash once
      genesisBlock.calculateVeloraId();
    }

    return genesisBlock;
  }

  /**
   * Create a new block
   * @param index
   * @param transactions
   * @param previousHash
   * @param difficulty
   * @param config
   */
  static createBlock(index, transactions, previousHash, difficulty = 4, config = null) {
    const block = new Block(index, Date.now(), transactions, previousHash, 0, difficulty, config);
    block.calculateMerkleRoot();

    // For Velora mining, we need to set a temporary hash and ensure algorithm is set
    // The actual hash will be calculated during mining
    block.algorithm = 'velora';
    block.hash = '0000000000000000000000000000000000000000000000000000000000000000'; // Temporary hash

    return block;
  }

  /**
   * Convert block to JSON
   */
  toJSON() {
    return {
      index: this.index,
      timestamp: this.timestamp,
      transactions: this.transactions.map(tx => tx.toJSON ? tx.toJSON() : tx),
      previousHash: this.previousHash,
      nonce: this.nonce,
      difficulty: this.difficulty,
      hash: this.hash,
      merkleRoot: this.merkleRoot,
      algorithm: this.algorithm,
    };
  }

  /**
   * Create block from JSON data
   * @param data
   * @param previousBlockTimestamp
   */
  static fromJSON(data, previousBlockTimestamp = undefined) {
    logger.debug(
      'BLOCK',
      `Creating Block instance from JSON data: index=${data.index}, timestamp=${data.timestamp}, transactions=${data.transactions?.length || 0}, previousTimestamp=${previousBlockTimestamp}`
    );

    // Convert transactions to Transaction instances if they're plain objects
    let { transactions } = data;
    if (transactions && Array.isArray(transactions)) {
      logger.debug('BLOCK', `Processing ${transactions.length} transactions for conversion`);
      try {
        const { Transaction } = require('./Transaction');
        transactions = transactions.map((tx, index) => {
          logger.debug(
            'BLOCK',
            `Converting transaction ${index}: id=${tx.id}, isCoinbase=${tx.isCoinbase}, hasIsValid=${typeof tx.isValid === 'function'}`
          );
          if (typeof tx === 'object' && !tx.isValid) {
            const convertedTx = Transaction.fromJSON(tx);
            logger.debug(
              'BLOCK',
              `Successfully converted transaction ${index} to Transaction instance: id=${convertedTx.id}`
            );
            return convertedTx;
          }
          logger.debug('BLOCK', `Transaction ${index} already a Transaction instance or invalid: id=${tx.id}`);
          return tx;
        });
        logger.debug('BLOCK', `Successfully converted ${transactions.length} transactions`);
      } catch (error) {
        logger.error('BLOCK', `Failed to convert transactions to Transaction instances: ${error.message}`);
        logger.error('BLOCK', `Error stack: ${error.stack}`);
        logger.warn('BLOCK', `Keeping original transactions due to conversion failure`);
      }
    } else {
      logger.debug(
        'BLOCK',
        `No transactions to convert or invalid transactions array: ${JSON.stringify(transactions)}`
      );
    }

    logger.debug(
      'BLOCK',
      `Creating Block constructor with: index=${data.index}, timestamp=${data.timestamp}, transactions=${transactions?.length || 0}, previousHash=${data.previousHash}, nonce=${data.nonce}, difficulty=${data.difficulty}`
    );

    // Create validation context for historical block loading
    const validationContext = {
      isHistoricalLoad: true,
      previousBlockTimestamp,
    };

    const block = new Block(
      data.index,
      data.timestamp,
      transactions,
      data.previousHash,
      data.nonce,
      data.difficulty,
      data.config,
      validationContext,
      true // Skip Merkle calculation when loading from JSON
    );

    block.hash = data.hash;
    // CRITICAL: Preserve original merkle root from JSON for validation
    block.merkleRoot = data.merkleRoot; // Use original from file for validation
    block.algorithm = data.algorithm || 'velora'; // Default to Velora for new blocks

    logger.debug(
      'BLOCK',
      `Block instance created successfully: index=${block.index}, hash=${block.hash?.substring(0, 16)}..., merkleRoot=${block.merkleRoot?.substring(0, 16)}...`
    );

    return block;
  }
}

module.exports = Block;
