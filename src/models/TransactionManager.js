const { toAtomicUnits, fromAtomicUnits, formatAtomicUnits } = require('../utils/atomicUnits.js');
const { TRANSACTION_TAGS } = require('../utils/constants');
const logger = require('../utils/logger');

const { Transaction, TransactionInput, TransactionOutput } = require('./Transaction');

/**
 * Simple promise-based mutex for preventing race conditions
 */
class SimpleMutex {
  constructor() {
    this.locked = false;
    this.queue = [];
  }

  async acquire() {
    return new Promise((resolve) => {
      if (!this.locked) {
        this.locked = true;
        resolve();
      } else {
        this.queue.push(resolve);
      }
    });
  }

  release() {
    if (this.queue.length > 0) {
      const next = this.queue.shift();
      next();
    } else {
      this.locked = false;
    }
  }

  async runExclusive(fn) {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

/**
 * Transaction Manager - Handles transaction validation and management
 */
class TransactionManager {
  /**
   *
   * @param utxoManager
   * @param spamProtection
   * @param memoryPool
   */
  constructor(utxoManager, spamProtection, memoryPool) {
    this.utxoManager = utxoManager;
    this.spamProtection = spamProtection;
    this.memoryPool = memoryPool;

    // CRITICAL: Mutex to prevent double-spend race conditions
    this.transactionMutex = new SimpleMutex();
    this.reservedUTXOs = new Set(); // Track temporarily reserved UTXOs
  }

  /**
   * Add transaction to pending pool with MANDATORY replay attack protection and SPAM PROTECTION
   * @param transaction
   * @returns {Promise<boolean>} - false if rejected, true if accepted
   */
  async addPendingTransaction(transaction) {
    // Convert JSON transaction to Transaction instance if needed
    let transactionInstance = transaction;
    if (typeof transaction === 'object' && !transaction.isValid) {
      try {
        transactionInstance = Transaction.fromJSON(transaction);
      } catch (error) {
        logger.error('TRANSACTION_MANAGER', `Failed to convert transaction to Transaction instance: ${error.message}`);
        return false;
      }
    }

    // MANDATORY PROTECTION: Reject ALL transactions without replay protection (except coinbase)
    if (!transactionInstance.isCoinbase && (!transactionInstance.nonce || !transactionInstance.expiresAt)) {
      logger.error(
        'TRANSACTION_MANAGER',
        `Transaction ${transactionInstance.id} REJECTED: Missing mandatory replay protection`
      );
      logger.error('TRANSACTION_MANAGER', 'ALL transactions must include nonce and expiration fields');
      logger.error('TRANSACTION_MANAGER', 'Use Transaction.createTransaction() to create protected transactions');
      return false;
    }

    // SPAM PROTECTION: Check global rate limit
    if (this.spamProtection.isGlobalRateLimitExceeded(this.memoryPool.getPendingTransactions())) {
      logger.warn('TRANSACTION_MANAGER', `Transaction ${transactionInstance.id} REJECTED: Global rate limit exceeded`);
      return false;
    }

    // SPAM PROTECTION: Check address-specific rate limit
    if (!transactionInstance.isCoinbase) {
      // Extract sender address from inputs
      const senderAddresses = transactionInstance.inputs
        .map(input => {
          // Handle both txHash and txId field names for compatibility
          const inputTxHash = input.txHash || input.txId;
          // Find the UTXO to get the address
          const utxo = this.utxoManager.findUTXO(inputTxHash, input.outputIndex);
          return utxo ? utxo.address : null;
        })
        .filter(addr => addr !== null);

      // Check if any sender address is rate limited
      for (const senderAddress of senderAddresses) {
        if (!this.spamProtection.isAddressAllowedToSubmit(senderAddress)) {
          logger.warn(
            'TRANSACTION_MANAGER',
            `Transaction ${transactionInstance.id} REJECTED: Address ${senderAddress} rate limited for spam`
          );
          return false;
        }
      }
    }

    // Check if transaction already exists
    if (this.memoryPool.hasTransaction(transactionInstance.id)) {
      logger.warn('TRANSACTION_MANAGER', 'Transaction already exists in pending pool');
      return false;
    }

    // STANDARDIZED VALIDATION ORDER FOR SECURITY:
    // 1. REPLAY PROTECTION (Critical security, check early)
    if (transactionInstance.isExpired && typeof transactionInstance.isExpired === 'function') {
      if (transactionInstance.isExpired()) {
        logger.warn('TRANSACTION_MANAGER', `Transaction ${transactionInstance.id} has expired and cannot be added`);
        return false;
      }
    }

    if (transactionInstance.isReplayAttack && typeof transactionInstance.isReplayAttack === 'function') {
      if (transactionInstance.isReplayAttack(this.memoryPool.getPendingTransactions())) {
        logger.warn(
          'TRANSACTION_MANAGER',
          `Transaction ${transactionInstance.id} detected as replay attack in pending pool`
        );
        return false;
      }
    }

    // 2. ATOMIC UTXO VALIDATION AND RESERVATION (Prevent double-spending with mutex protection)
    return await this.transactionMutex.runExclusive(async () => {
      // Check if transaction was already added while waiting for mutex
      if (this.memoryPool.hasTransaction(transactionInstance.id)) {
        logger.warn('TRANSACTION_MANAGER', `Transaction ${transactionInstance.id} already exists in pending pool`);
        return false;
      }

      // Atomically validate and reserve UTXOs
      if (!this.atomicValidateAndReserveUTXOs(transactionInstance)) {
        logger.error(
          'TRANSACTION_MANAGER',
          `Transaction ${transactionInstance.id} REJECTED: Atomic UTXO validation failed - double-spend prevented`
        );
        return false;
      }

      try {
        // 3. STRUCTURAL VALIDATION (Basic format and field validation)
        const validationResult = this.validateTransaction(transactionInstance);
        if (!validationResult.valid) {
          logger.error('TRANSACTION_MANAGER', `Transaction ${transactionInstance.id} REJECTED: ${validationResult.reason}`);
          this.releaseReservedUTXOs(transactionInstance);
          return false;
        }

        // 4. CRYPTOGRAPHIC VALIDATION (Expensive operations last)
        if (!transactionInstance.isValid()) {
          logger.warn('TRANSACTION_MANAGER', `Transaction ${transactionInstance.id} REJECTED: Invalid cryptographic signature`);
          this.releaseReservedUTXOs(transactionInstance);
          return false;
        }

        // All validations passed - add to memory pool
        this.memoryPool.addTransaction(transactionInstance);
        logger.info(
          'TRANSACTION_MANAGER',
          `Transaction ${transactionInstance.id} added to pending pool with atomic UTXO validation, replay protection and spam protection`
        );
        return true;

      } catch (error) {
        logger.error('TRANSACTION_MANAGER', `Unexpected error validating transaction ${transactionInstance.id}: ${error.message}`);
        this.releaseReservedUTXOs(transactionInstance);
        return false;
      }
    });
  }

  /**
   * Validate individual transaction including UTXO checks
   * @param transaction
   */
  validateTransaction(transaction) {
    try {
      // Basic transaction validation
      if (!transaction || !transaction.id) {
        return { valid: false, reason: 'Invalid transaction structure' };
      }

      // Check if transaction is expired
      if (transaction.isExpired && transaction.isExpired()) {
        return { valid: false, reason: 'Transaction has expired' };
      }

      // Validate outputs (allow contract transactions to have no outputs)
      if (!transaction.outputs || transaction.outputs.length === 0) {
        // Contract transactions don't need traditional outputs
        if (transaction.tag !== 'CONTRACT') {
          return { valid: false, reason: 'Transaction has no outputs' };
        }
      }

      // Calculate total output amount (allow zero for contract transactions)
      const totalOutputAmount = transaction.outputs.reduce((sum, output) => sum + (output.amount || 0), 0);
      if (totalOutputAmount <= 0) {
        // Contract transactions can have zero output amount
        if (transaction.tag !== 'CONTRACT') {
          return { valid: false, reason: 'Transaction output amount must be positive' };
        }
      }

      // For non-coinbase transactions, validate inputs and UTXOs (except contract transactions)
      if (!transaction.isCoinbase) {
        if (!transaction.inputs || transaction.inputs.length === 0) {
          // Contract transactions don't need traditional inputs
          if (transaction.tag !== 'CONTRACT') {
            return { valid: false, reason: 'Non-coinbase transaction must have inputs' };
          }
        }

        // Calculate total input amount from UTXOs
        let totalInputAmount = 0;
        for (const input of transaction.inputs) {
          // Handle both txHash and txId field names for compatibility
          const inputTxHash = input.txHash || input.txId;
          const utxo = this.utxoManager.findUTXO(inputTxHash, input.outputIndex);
          if (!utxo) {
            return { valid: false, reason: `Input UTXO not found: ${inputTxHash}:${input.outputIndex}` };
          }

          // Check if UTXO is already spent
          if (this.utxoManager.isUTXOSpent(inputTxHash, input.outputIndex)) {
            return { valid: false, reason: `UTXO already spent: ${inputTxHash}:${input.outputIndex}` };
          }

          totalInputAmount += utxo.amount;
        }

        // Validate input/output balance (input must cover output + fee) - except for contract transactions
        if (totalInputAmount < totalOutputAmount + transaction.fee) {
          // Contract transactions handle fees through separate payment verification
          if (transaction.tag !== 'CONTRACT') {
            return {
              valid: false,
              reason: `Insufficient input amount. Input: ${totalInputAmount}, Output: ${totalOutputAmount}, Fee: ${transaction.fee}`,
            };
          }
        }
      }

      return { valid: true, reason: 'Transaction validation passed' };
    } catch (error) {
      logger.error('TRANSACTION_MANAGER', `Transaction validation error: ${error.message}`);
      return { valid: false, reason: `Validation error: ${error.message}` };
    }
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
    // Users can only create TRANSACTION tagged transactions
    if (tag !== TRANSACTION_TAGS.TRANSACTION) {
      throw new Error('Users can only create TRANSACTION tagged transactions. Other tags are reserved for system use.');
    }

    const utxos = this.utxoManager.getUTXOsForAddress(fromAddress);
    const totalAvailable = utxos.reduce((sum, utxo) => sum + utxo.amount, 0);

    if (totalAvailable < amount + fee) {
      throw new Error('Insufficient balance');
    }

    // Convert amount and fee to atomic units if they're not already
    const atomicAmount = typeof amount === 'string' ? toAtomicUnits(amount) : amount;
    const atomicFee = typeof fee === 'string' ? toAtomicUnits(fee) : fee;

    // Select UTXOs to spend
    let selectedAmount = 0;
    const selectedUtxos = [];

    for (const utxo of utxos) {
      selectedUtxos.push(utxo);
      selectedAmount += utxo.amount;
      if (selectedAmount >= amount + fee) break;
    }

    // Create inputs
    const inputs = selectedUtxos.map(
      utxo => new TransactionInput(utxo.txHash, utxo.outputIndex, '', '') // Signature will be added later
    );

    // Create outputs
    const outputs = [new TransactionOutput(toAddress, amount)];

    // Add change output if needed
    const change = selectedAmount - amount - fee;
    if (change > 0) {
      outputs.push(new TransactionOutput(fromAddress, change));
    }

    // Create transaction with tag (automatically includes replay protection)
    const transaction = new Transaction(inputs, outputs, fee, tag, Date.now());

    // Verify replay protection fields are present
    if (!transaction.nonce || !transaction.expiresAt) {
      throw new Error('Transaction creation failed: Missing replay protection fields');
    }

    transaction.calculateId();
    return transaction;
  }

  /**
   * Batch transaction addition
   * @param transactions
   */
  async addTransactionBatch(transactions) {
    const validationResults = this.memoryPool.validateTransactionBatch(transactions);
    let addedCount = 0;

    // Add all valid transactions sequentially to maintain mutex protection
    for (const tx of validationResults.valid) {
      if (await this.addPendingTransaction(tx)) {
        addedCount++;
      }
    }

    // Log results
    if (validationResults.valid.length > 0 || validationResults.invalid.length > 0) {
      logger.info(
        'TRANSACTION_MANAGER',
        `Batch transaction processing: ${validationResults.valid.length} valid, ${validationResults.invalid.length} invalid`
      );

      if (validationResults.errors.length > 0) {
        logger.warn(
          'TRANSACTION_MANAGER',
          `Batch validation errors: ${validationResults.errors.slice(0, 5).join(', ')}${validationResults.errors.length > 5 ? '...' : ''}`
        );
      }
    }

    return {
      added: addedCount,
      valid: validationResults.valid.length,
      invalid: validationResults.invalid.length,
      errors: validationResults.errors,
    };
  }

  /**
   * CRITICAL SECURITY: Validate transaction inputs against actual UTXO set
   * This prevents spending non-existent or already spent UTXOs
   * @param {Transaction} transaction - Transaction to validate
   * @returns {boolean} - True if all inputs are valid UTXOs
   */
  validateTransactionInputs(transaction) {
    // Skip UTXO validation for coinbase transactions (they don't have inputs)
    if (transaction.isCoinbase) {
      logger.debug('TRANSACTION_MANAGER', `Skipping UTXO validation for coinbase transaction: ${transaction.id}`);
      return true;
    }

    // Validate each input against the UTXO set
    for (let i = 0; i < transaction.inputs.length; i++) {
      const input = transaction.inputs[i];
      const txHash = input.txHash || input.txId; // Handle both field names

      // Check if the UTXO exists and is unspent
      const utxo = this.utxoManager.findUTXO(txHash, input.outputIndex);

      if (!utxo) {
        logger.error(
          'TRANSACTION_MANAGER',
          `SECURITY VIOLATION: Input ${i} references non-existent or spent UTXO: ${txHash}:${input.outputIndex}`
        );
        logger.error('TRANSACTION_MANAGER', `This could be a blockchain manipulation attempt or double-spend attack`);
        return false;
      }

      // Verify the input amount matches what's expected (if available)
      if (utxo.amount !== undefined) {
        logger.debug(
          'TRANSACTION_MANAGER',
          `UTXO ${txHash}:${input.outputIndex} validated: amount=${utxo.amount}, address=${utxo.address}`
        );
      }
    }

    logger.info(
      'TRANSACTION_MANAGER',
      `✅ UTXO validation passed for transaction ${transaction.id}: all ${transaction.inputs.length} inputs are valid`
    );
    return true;
  }

  /**
   * CRITICAL SECURITY: Atomically validate and reserve UTXOs to prevent double-spending
   * @param {Transaction} transaction - Transaction to validate
   * @returns {boolean} - True if all inputs are valid and reserved
   */
  atomicValidateAndReserveUTXOs(transaction) {
    // Skip UTXO validation for coinbase transactions (they don't have inputs)
    if (transaction.isCoinbase) {
      logger.debug('TRANSACTION_MANAGER', `Skipping UTXO validation for coinbase transaction: ${transaction.id}`);
      return true;
    }

    const utxosToReserve = [];

    // First pass: validate all UTXOs exist and are not reserved
    for (let i = 0; i < transaction.inputs.length; i++) {
      const input = transaction.inputs[i];
      const txHash = input.txHash || input.txId; // Handle both field names
      const utxoKey = `${txHash}:${input.outputIndex}`;

      // Check if UTXO is already reserved by another pending transaction
      if (this.reservedUTXOs.has(utxoKey)) {
        logger.error(
          'TRANSACTION_MANAGER',
          `DOUBLE-SPEND PREVENTED: UTXO ${utxoKey} is already reserved by another pending transaction`
        );
        return false;
      }

      // Check if the UTXO exists and is unspent
      const utxo = this.utxoManager.findUTXO(txHash, input.outputIndex);

      if (!utxo) {
        logger.error(
          'TRANSACTION_MANAGER',
          `SECURITY VIOLATION: Input ${i} references non-existent or spent UTXO: ${utxoKey}`
        );
        logger.error('TRANSACTION_MANAGER', `This could be a blockchain manipulation attempt or double-spend attack`);
        return false;
      }

      utxosToReserve.push(utxoKey);

      // Verify the input amount matches what's expected (if available)
      if (utxo.amount !== undefined) {
        logger.debug(
          'TRANSACTION_MANAGER',
          `UTXO ${utxoKey} validated: amount=${utxo.amount}, address=${utxo.address}`
        );
      }
    }

    // Second pass: atomically reserve all UTXOs
    for (const utxoKey of utxosToReserve) {
      this.reservedUTXOs.add(utxoKey);
    }

    logger.info('TRANSACTION_MANAGER', `Reserved ${utxosToReserve.length} UTXOs for transaction ${transaction.id}`);
    return true;
  }

  /**
   * Release reserved UTXOs when transaction is processed or rejected
   * @param {Transaction} transaction - Transaction whose UTXOs to release
   */
  releaseReservedUTXOs(transaction) {
    if (transaction.isCoinbase) return;

    let releasedCount = 0;
    for (const input of transaction.inputs) {
      const txHash = input.txHash || input.txId;
      const utxoKey = `${txHash}:${input.outputIndex}`;

      if (this.reservedUTXOs.has(utxoKey)) {
        this.reservedUTXOs.delete(utxoKey);
        releasedCount++;
      }
    }

    if (releasedCount > 0) {
      logger.debug('TRANSACTION_MANAGER', `Released ${releasedCount} reserved UTXOs for transaction ${transaction.id}`);
    }
  }

  /**
   * Clean up reserved UTXOs for transactions that are no longer in the memory pool
   * This should be called periodically or when transactions are processed into blocks
   */
  cleanupReservedUTXOs() {
    const pendingTransactions = this.memoryPool.getPendingTransactions();
    const activeTxIds = new Set(pendingTransactions.map(tx => tx.id));

    // Find reserved UTXOs that belong to transactions no longer in the pool
    const utxosToRelease = [];
    for (const utxoKey of this.reservedUTXOs) {
      let shouldRelease = true;

      // Check if this UTXO belongs to any active transaction
      for (const tx of pendingTransactions) {
        if (tx.isCoinbase) continue;

        for (const input of tx.inputs) {
          const txHash = input.txHash || input.txId;
          const currentUtxoKey = `${txHash}:${input.outputIndex}`;
          if (currentUtxoKey === utxoKey) {
            shouldRelease = false;
            break;
          }
        }

        if (!shouldRelease) break;
      }

      if (shouldRelease) {
        utxosToRelease.push(utxoKey);
      }
    }

    // Release orphaned UTXOs
    for (const utxoKey of utxosToRelease) {
      this.reservedUTXOs.delete(utxoKey);
    }

    if (utxosToRelease.length > 0) {
      logger.info('TRANSACTION_MANAGER', `Cleaned up ${utxosToRelease.length} orphaned reserved UTXOs`);
    }
  }

  /**
   * Get current status of reserved UTXOs (for debugging/monitoring)
   */
  getReservationStatus() {
    return {
      reservedCount: this.reservedUTXOs.size,
      reservedUTXOs: Array.from(this.reservedUTXOs),
      pendingTransactions: this.memoryPool.getPendingTransactions().length
    };
  }
}

module.exports = TransactionManager;
