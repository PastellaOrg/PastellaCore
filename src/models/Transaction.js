const { TRANSACTION_TAGS } = require('../utils/constants.js');
const { CryptoUtils, SafeMath } = require('../utils/crypto.js');
const logger = require('../utils/logger.js');
const InputValidator = require('../utils/validation.js');

/**
 *
 */
class TransactionInput {
  /**
   *
   * @param txId
   * @param outputIndex
   * @param signature
   * @param publicKey
   */
  constructor(txId, outputIndex, signature, publicKey) {
    this.txId = txId; // Hash of the transaction containing the UTXO
    this.outputIndex = outputIndex; // Index of the output in the previous transaction
    this.signature = signature; // Signature proving ownership
    this.publicKey = publicKey; // Public key of the owner
  }

  /**
   *
   */
  toJSON() {
    return {
      txId: this.txId,
      outputIndex: this.outputIndex,
      signature: this.signature,
      publicKey: this.publicKey,
    };
  }

  /**
   *
   * @param data
   */
  static fromJSON(data) {
    try {
      if (!data || typeof data !== 'object') {
        throw new Error('Invalid transaction input data: data is not an object');
      }

      if (typeof data.txId !== 'string') {
        throw new Error('Invalid transaction input data: txId is not a string');
      }

      if (typeof data.outputIndex !== 'number') {
        throw new Error('Invalid transaction input data: outputIndex is not a number');
      }

      if (typeof data.signature !== 'string') {
        throw new Error('Invalid transaction input data: signature is not a string');
      }

      if (typeof data.publicKey !== 'string') {
        throw new Error('Invalid transaction input data: publicKey is not a string');
      }

      return new TransactionInput(data.txId, data.outputIndex, data.signature, data.publicKey);
    } catch (error) {
      throw new Error(`Failed to create transaction input from JSON: ${error.message}`);
    }
  }
}

/**
 *
 */
class TransactionOutput {
  /**
   *
   * @param address
   * @param amount
   */
  constructor(address, amount) {
    this.address = address; // Recipient address
    this.amount = amount; // Amount in PAS
  }

  /**
   *
   */
  toJSON() {
    return {
      address: this.address,
      amount: this.amount,
    };
  }

  /**
   *
   * @param data
   */
  static fromJSON(data) {
    try {
      if (!data || typeof data !== 'object') {
        throw new Error('Invalid transaction output data: data is not an object');
      }

      if (typeof data.address !== 'string') {
        throw new Error('Invalid transaction output data: address is not a string');
      }

      if (typeof data.amount !== 'number') {
        throw new Error('Invalid transaction output data: amount is not a number');
      }

      return new TransactionOutput(data.address, data.amount);
    } catch (error) {
      throw new Error(`Failed to create transaction output from JSON: ${error.message}`);
    }
  }
}

/**
 *
 */
class Transaction {
  /**
   *
   * @param inputs
   * @param outputs
   * @param fee
   * @param tag
   * @param timestamp
   * @param nonce
   * @param atomicSequence
   * @param isGenesisBlock
   * @param paymentId
   */
  constructor(
    inputs = [],
    outputs = [],
    fee = 0,
    tag = TRANSACTION_TAGS.TRANSACTION,
    timestamp = null,
    nonce = null,
    atomicSequence = null,
    isGenesisBlock = false,
    paymentId = null
  ) {
    this.id = null; // Transaction hash
    this.inputs = inputs; // Array of TransactionInput
    this.outputs = outputs; // Array of TransactionOutput
    this.fee = fee; // Transaction fee

    // Validate payment ID if provided
    if (paymentId !== null && paymentId !== undefined) {
      const validatedPaymentId = InputValidator.validatePaymentId(paymentId);
      if (validatedPaymentId === null) {
        throw new Error('Invalid payment ID: must be exactly 64 hex characters');
      }
      this.paymentId = validatedPaymentId;
    } else {
      this.paymentId = null; // Optional payment ID (64 hex chars) for transaction identification
    }
    this.timestamp = timestamp || Date.now(); // Transaction timestamp (use provided timestamp or current time)
    this.isCoinbase = false; // Whether this is a coinbase transaction
    this.tag = tag; // Transaction tag (STAKING, GOVERNANCE, COINBASE, TRANSACTION, PREMINE)

    // REPLAY ATTACK PROTECTION
    this.nonce = nonce || this.generateNonce(); // Use provided nonce or generate unique nonce for replay protection
    this.expiresAt = this.timestamp + 24 * 60 * 60 * 1000; // 24 hour expiration
    this.sequence = 0; // Sequence number for input ordering

    
    this._lockId = null; // Transaction lock identifier
    this._isLocked = false; // Lock status
    this._lockTimestamp = null; // When lock was acquired
    this._lockTimeout = 30000; // 30 second lock timeout
    this._atomicSequence = atomicSequence || this.generateAtomicSequence(); // Use provided atomicSequence or generate unique one for race protection

    // GENESIS BLOCK IDENTIFICATION
    this._isGenesisBlock = isGenesisBlock; // Whether this transaction is part of the genesis block
  }

  /**
   * Generate unique nonce for replay attack protection using cryptographically secure randomness
   */
  generateNonce() {
    const crypto = require('crypto');
    const timestamp = Date.now().toString(36);
    const randomBytes1 = crypto.randomBytes(8).toString('hex');
    const randomBytes2 = crypto.randomBytes(8).toString('hex');
    return timestamp + randomBytes1 + randomBytes2;
  }

  /**
   * CRITICAL: Generate atomic sequence number for race attack protection using cryptographically secure randomness
   */
  generateAtomicSequence() {
    const crypto = require('crypto');
    // Combine timestamp, cryptographically secure random value, and process ID for uniqueness
    const timestamp = Date.now();
    const randomBytes = crypto.randomBytes(12).toString('hex'); // 12 bytes = 24 hex chars
    const processId = process.pid || 0;
    const threadId = crypto.randomBytes(4).readUInt32BE(0); // Crypto-secure thread ID

    // Create a unique sequence that's cryptographically impossible to duplicate
    return `${timestamp}-${randomBytes}-${processId}-${threadId}`;
  }

  /**
   * CRITICAL: Acquire transaction lock to prevent race attacks
   * @param lockId
   * @param timeout
   */
  acquireLock(lockId, timeout = 30000) {
    if (this._isLocked) {
      // Check if lock has expired
      if (this._lockTimestamp && Date.now() - this._lockTimestamp > this._lockTimeout) {
        this._releaseLock();
      } else {
        throw new Error('Transaction is already locked by another process');
      }
    }

    this._lockId = lockId;
    this._isLocked = true;
    this._lockTimestamp = Date.now();
    this._lockTimeout = timeout;

    return true;
  }

  /**
   * CRITICAL: Release transaction lock
   * @param lockId
   */
  releaseLock(lockId) {
    if (this._lockId === lockId) {
      this._releaseLock();
      return true;
    }
    throw new Error('Invalid lock ID or transaction not locked');
  }

  /**
   * CRITICAL: Internal lock release
   */
  _releaseLock() {
    this._lockId = null;
    this._isLocked = false;
    this._lockTimestamp = null;
  }

  /**
   * CRITICAL: Check if transaction is locked
   */
  isLocked() {
    // Auto-release expired locks
    if (this._isLocked && this._lockTimestamp && Date.now() - this._lockTimestamp > this._lockTimeout) {
      this._releaseLock();
    }
    return this._isLocked;
  }

  /**
   * CRITICAL: Validate atomic sequence to prevent race attacks
   * @param {boolean} isHistoricalValidation - Skip time-based checks for historical blocks
   */
  validateAtomicSequence(isHistoricalValidation = false) {
    if (!this._atomicSequence) {
      throw new Error('Transaction missing atomic sequence - potential race attack');
    }

    // For genesis block transactions (block 0), use a more lenient validation
    // This allows static atomic sequences for deterministic genesis blocks
    if (this.isCoinbase && this._isGenesisBlock) {
      // Genesis block transactions can have static atomic sequences
      // Just ensure it's not empty and has some content
      if (this._atomicSequence.length < 5) {
        throw new Error('Genesis block atomic sequence too short - potential race attack');
      }
      return true;
    }
    // For regular transactions, use strict validation
    const parts = this._atomicSequence.split('-');

    // Check for genesis transaction format: timestamp-genesis-coinbase-sequence
    const isGenesisTransaction = parts.length === 4 && parts[1] === 'genesis' && parts[2] === 'coinbase';

    // All transactions must have exactly 4 parts
    if (!isGenesisTransaction && parts.length !== 4) {
      throw new Error('Invalid atomic sequence format - potential race attack');
    }

    
    const timestamp = parseInt(parts[0]);
    if (!isHistoricalValidation) {
      // Validate timestamp is recent (within 5 minutes) - only for new transactions
      if (Date.now() - timestamp > 5 * 60 * 1000) {
        throw new Error('Atomic sequence timestamp too old - potential race attack');
      }
    } else {
      
      const currentTime = Date.now();
      const yearInMs = 365 * 24 * 60 * 60 * 1000; // 1 year in milliseconds

      if (timestamp > currentTime) {
        throw new Error('Historical atomic sequence timestamp is in the future - invalid historical block');
      }

      // Allow up to 10 years in the past for historical blocks
      if (currentTime - timestamp > (10 * yearInMs)) {
        throw new Error('Historical atomic sequence timestamp is too ancient - potential manipulation');
      }

      
      // Skip randomness validation for genesis transactions
      if (!isGenesisTransaction) {
        const randomPart = parts[1];
        if (!randomPart || randomPart.length < 8) {
          throw new Error('Historical atomic sequence has weak randomness - potential manipulation');
        }
      }
    }

    return true;
  }

  /**
   * CRITICAL: Safe amount validation using SafeMath
   */
  validateAmounts() {
    try {
      // Validate all output amounts
      for (const output of this.outputs) {
        SafeMath.validateAmount(output.amount);
      }

      // Validate fee
      SafeMath.validateAmount(this.fee);

      // Validate total output amount
      const totalOutput = this.outputs.reduce((sum, output) => SafeMath.safeAdd(sum, output.amount), 0);

      // Validate total input amount (if not coinbase)
      if (!this.isCoinbase && this.inputs.length > 0) {
        // This would need to be validated against UTXO amounts
        // For now, just ensure it's positive
        if (totalOutput < 0) {
          throw new Error('Total output amount cannot be negative');
        }
      }

      return true;
    } catch (error) {
      throw new Error(`Amount validation failed: ${error.message}`);
    }
  }

  /**
   * CRITICAL: Safe fee calculation using SafeMath
   * @param inputAmount
   * @param outputAmount
   */
  calculateSafeFee(inputAmount, outputAmount) {
    try {
      const totalInput = SafeMath.validateAmount(inputAmount);
      const totalOutput = SafeMath.validateAmount(outputAmount);

      if (totalInput < totalOutput) {
        throw new Error('Input amount must be greater than or equal to output amount');
      }

      const fee = SafeMath.safeSub(totalInput, totalOutput);
      SafeMath.validateAmount(fee);

      return fee;
    } catch (error) {
      throw new Error(`Fee calculation failed: ${error.message}`);
    }
  }

  /**
   * Calculate transaction hash with replay attack protection
   * CRITICAL: This hash is IMMUTABLE and cannot be changed after creation
   * @param {boolean} isHistoricalValidation - Skip time-based checks for historical blocks
   */
  calculateId(isHistoricalValidation = false) {
    
    this.validateAtomicSequence(isHistoricalValidation);

    // Set debug flag for canonicalJSONStringify
    this._isHistoricalValidation = isHistoricalValidation;

    
    const mappedOutputs = this.outputs.map(output => ({
      address: output.address,
      amount: output.amount,
    }));
    
    // DEBUG: Log output mapping for integrity validation
    if (isHistoricalValidation) {
      logger.debug('TRANSACTION', `calculateId DEBUG - original outputs: ${JSON.stringify(this.outputs)}`);
      logger.debug('TRANSACTION', `calculateId DEBUG - mapped outputs: ${JSON.stringify(mappedOutputs)}`);
      for (let i = 0; i < this.outputs.length; i++) {
        const output = this.outputs[i];
        logger.debug('TRANSACTION', `calculateId DEBUG - output[${i}]: address=${output.address}, amount=${output.amount}, type=${typeof output.amount}`);
      }
    }
    
    const immutableData = {
      inputs: this.inputs.map((input, index) => {
        const inputData = {
          txId: input.txId,
          outputIndex: input.outputIndex,
          publicKey: input.publicKey,
        };
        if (isHistoricalValidation && index === 0) {
          logger.debug('TRANSACTION', `calculateId DEBUG - input[${index}]: txId=${input.txId}, outputIndex=${input.outputIndex}, publicKey=${input.publicKey?.substring(0, 20)}...`);
          logger.debug('TRANSACTION', `calculateId DEBUG - inputData: ${JSON.stringify(inputData)}`);
        }
        return inputData;
      }),
      outputs: mappedOutputs,
      fee: this.fee,
      paymentId: this.paymentId, // Include payment ID in hash calculation
      timestamp: this.timestamp,
      isCoinbase: this.isCoinbase,
      tag: this.tag,
      nonce: this.nonce, // Include nonce for replay protection
      expiresAt: this.expiresAt, // Include expiration for replay protection
      sequence: this.sequence, // Include sequence for input ordering
      atomicSequence: this._atomicSequence, 
    };

    // DEBUG: Log key fields for historical validation
    if (isHistoricalValidation) {
      logger.debug('TRANSACTION', `calculateId DEBUG - timestamp: ${this.timestamp}`);
      logger.debug('TRANSACTION', `calculateId DEBUG - atomicSequence: ${this._atomicSequence}`);
      logger.debug('TRANSACTION', `calculateId DEBUG - expiresAt: ${this.expiresAt}`);
      logger.debug('TRANSACTION', `calculateId DEBUG - nonce: ${this.nonce}`);
      logger.debug('TRANSACTION', `calculateId DEBUG - fee: ${this.fee}`);
    }

    
    Object.freeze(immutableData);

    
    const dataString = this.canonicalJSONStringify(immutableData);
    
    // DEBUG: Log the data being hashed for integrity validation
    if (isHistoricalValidation && !this.isCoinbase) {
      logger.debug('TRANSACTION', `calculateId DEBUG - outputs: ${JSON.stringify(immutableData.outputs)}`);
      logger.debug('TRANSACTION', `calculateId DEBUG - inputs in dataString: ${JSON.stringify(immutableData.inputs)}`);
      logger.debug('TRANSACTION', `calculateId DEBUG - dataString: ${dataString.substring(0, 500)}...`);

      // Check if txId appears anywhere in the full dataString
      if (dataString.includes('aad2b632847934b936327917cbff11688d23e9d9f4915c7405cc9d19a923d81f')) {
        logger.debug('TRANSACTION', `calculateId DEBUG - ✅ txId FOUND in full dataString`);

        // For the specific failing transaction, test multiple legacy combinations
        if (dataString.includes('1758272901891-b2d61fbaeeef2764f751f9d2-30395-1705701523')) {
          logger.debug('TRANSACTION', `calculateId DEBUG - Testing multiple legacy combinations for failing transaction`);

          // Test 1: Simple structure (what was used before all the new fields)
          const legacyData1 = {
            timestamp: this.timestamp,
            inputs: this.inputs.map(input => ({
              txId: input.txId,
              outputIndex: input.outputIndex,
              publicKey: input.publicKey,
              signature: input.signature
            })),
            outputs: mappedOutputs,
            fee: this.fee,
            nonce: this.nonce
          };
          const legacyId1 = CryptoUtils.doubleHash(this.canonicalJSONStringify(legacyData1));
          logger.debug('TRANSACTION', `calculateId DEBUG - Legacy test 1 (simple): ${legacyId1}`);

          // Test 2: Simple with single hash instead of double hash
          const legacyId2 = CryptoUtils.hash(this.canonicalJSONStringify(legacyData1));
          logger.debug('TRANSACTION', `calculateId DEBUG - Legacy test 2 (simple+hash): ${legacyId2}`);

          // Test 3: Include all fields but use single hash
          const legacyData3 = {
            inputs: this.inputs.map(input => ({
              txId: input.txId,
              outputIndex: input.outputIndex,
              signature: input.signature,
              publicKey: input.publicKey,
            })),
            outputs: mappedOutputs,
            fee: this.fee,
            timestamp: this.timestamp,
            isCoinbase: this.isCoinbase,
            tag: this.tag,
            nonce: this.nonce,
            expiresAt: this.expiresAt,
            sequence: this.sequence,
            atomicSequence: this._atomicSequence,
            paymentId: this.paymentId,
          };
          const legacyId3 = CryptoUtils.hash(this.canonicalJSONStringify(legacyData3));
          logger.debug('TRANSACTION', `calculateId DEBUG - Legacy test 3 (full+hash): ${legacyId3}`);

          logger.debug('TRANSACTION', `calculateId DEBUG - Target stored ID: bcb703324fa33eaf560f12b1d9e2661b5d500fe1236620acf5a736928ff21e95`);
          const target = 'bcb703324fa33eaf560f12b1d9e2661b5d500fe1236620acf5a736928ff21e95';
          const matches = [
            legacyId1 === target ? 'Test 1 (simple+double)' : null,
            legacyId2 === target ? 'Test 2 (simple+hash)' : null,
            legacyId3 === target ? 'Test 3 (full+hash)' : null
          ].filter(Boolean);
          logger.debug('TRANSACTION', `calculateId DEBUG - Match found: ${matches.length > 0 ? matches.join(', ') : 'None'}`);
        }
      } else {
        logger.debug('TRANSACTION', `calculateId DEBUG - ❌ txId NOT FOUND in full dataString`);
        logger.debug('TRANSACTION', `calculateId DEBUG - Full dataString: ${dataString}`);
      }
    }

    
    this.id = CryptoUtils.doubleHash(dataString);

    
    this._isImmutable = true;

    // Reset debug flag
    this._isHistoricalValidation = false;

    return this.id;
  }

  /**
   * CRITICAL: Canonical JSON stringification to prevent collision attacks
   * Implements RFC 7515 JSON Web Signature (JWS) canonical JSON rules
   * @param {any} obj - Object to serialize
   * @returns {string} Canonical JSON string
   */
  canonicalJSONStringify(obj) {
    // Handle null, undefined, primitives
    if (obj === null) return 'null';
    if (obj === undefined) return 'undefined';
    if (typeof obj === 'string') return JSON.stringify(obj);
    if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);

    // Handle arrays
    if (Array.isArray(obj)) {
      const serializedElements = obj.map(element => this.canonicalJSONStringify(element));
      return `[${serializedElements.join(',')}]`;
    }

    // Handle objects
    if (typeof obj === 'object') {
      // Get all enumerable property names and sort them
      const sortedKeys = Object.keys(obj).sort();

      // DEBUG: Log object keys for input objects during historical validation
      if (this._isHistoricalValidation && obj.hasOwnProperty && (obj.hasOwnProperty('txId') || obj.hasOwnProperty('outputIndex'))) {
        logger.debug('TRANSACTION', `canonicalJSONStringify DEBUG - object keys: ${sortedKeys.join(', ')}`);
        logger.debug('TRANSACTION', `canonicalJSONStringify DEBUG - txId value: ${obj.txId} (type: ${typeof obj.txId})`);
        logger.debug('TRANSACTION', `canonicalJSONStringify DEBUG - outputIndex value: ${obj.outputIndex}`);
        logger.debug('TRANSACTION', `canonicalJSONStringify DEBUG - publicKey value: ${obj.publicKey?.substring(0, 20)}...`);
      }

      // Build canonical key-value pairs
      const serializedPairs = sortedKeys.map(key => {
        const serializedKey = JSON.stringify(key);
        const serializedValue = this.canonicalJSONStringify(obj[key]);
        return `${serializedKey}:${serializedValue}`;
      });

      return `{${serializedPairs.join(',')}}`;
    }

    // Fallback for other types
    return JSON.stringify(obj);
  }

  /**
   * CRITICAL: Prevent transaction modification after ID calculation
   */
  _preventModification() {
    if (this._isImmutable) {
      throw new Error('Transaction is immutable after ID calculation. Cannot modify transaction data.');
    }
  }

  /**
   * CRITICAL: Set transaction as immutable (called after mining/confirmation)
   */
  setImmutable() {
    this._isImmutable = true;
    Object.freeze(this.inputs);
    Object.freeze(this.outputs);
    Object.freeze(this);
  }

  /**
   * CRITICAL: Protected setter for fee (prevents malleability)
   * @param newFee
   */
  setFee(newFee) {
    this._preventModification();
    this.fee = newFee;
  }

  /**
   * CRITICAL: Protected setter for outputs (prevents malleability)
   * @param newOutputs
   */
  setOutputs(newOutputs) {
    this._preventModification();
    this.outputs = newOutputs;
  }

  /**
   * CRITICAL: Protected setter for inputs (prevents malleability)
   * @param newInputs
   */
  setInputs(newInputs) {
    this._preventModification();
    this.inputs = newInputs;
  }

  /**
   * Get data to sign for transaction with replay attack protection including network ID
   */
  getDataToSign() {
    // Get network ID from config for cross-chain replay protection
    let networkId = 'pastella-mainnet'; // Default fallback
    try {
      const { loadConfig } = require('../utils/configLoader');
      const config = loadConfig();
      networkId = config.networkId || networkId;
    } catch (error) {
      // Use default if config unavailable
    }

    return JSON.stringify({
      networkId: networkId, 
      inputs: this.inputs.map(input => ({
        txId: input.txId,
        outputIndex: input.outputIndex,
      })),
      outputs: this.outputs.map(output => ({
        address: output.address,
        amount: output.amount,
      })),
      fee: this.fee,
      paymentId: this.paymentId, // Include payment ID in signature
      tag: this.tag,
      timestamp: this.timestamp,
      isCoinbase: this.isCoinbase,
      nonce: this.nonce, // Include nonce in signature
      expiresAt: this.expiresAt, // Include expiration in signature
      sequence: this.sequence, // Include sequence in signature
    });
  }

  /**
   * Sign transaction inputs
   * @param privateKey
   */
  sign(privateKey) {
    const dataToSign = this.getDataToSign();
    this.inputs.forEach(input => {
      input.signature = CryptoUtils.sign(dataToSign, privateKey);
    });
  }

  /**
   * Verify transaction signatures
   */
  verify() {
    if (this.isCoinbase) return true;
    // Contract transactions don't have traditional signatures to verify
    if (this.tag === 'CONTRACT') return true;

    return this.inputs.every(input => {
      const dataToSign = this.getDataToSign();
      return CryptoUtils.verify(dataToSign, input.signature, input.publicKey);
    });
  }

  /**
   * Check if transaction has expired (replay attack protection)
   * @param {number} contextTime - Optional timestamp to check expiry against (defaults to current time)
   */
  isExpired(contextTime = null) {
    const checkTime = contextTime || Date.now();
    return checkTime > this.expiresAt;
  }

  /**
   * Check if transaction is valid and not expired
   */
  isValidAndNotExpired() {
    if (this.isExpired()) {
      return false;
    }
    return this.verify();
  }

  /**
   * Get replay attack protection info
   */
  getReplayProtectionInfo() {
    return {
      nonce: this.nonce,
      expiresAt: this.expiresAt,
      sequence: this.sequence,
      isExpired: this.isExpired(),
      timeUntilExpiry: Math.max(0, this.expiresAt - Date.now()),
    };
  }

  /**
   * Check if this transaction is a replay of another transaction
   * @param {Array} existingTransactions - Array of existing transactions to check against
   * @returns {boolean} - True if this is a replay attack
   */
  isReplayAttack(existingTransactions) {
    if (!existingTransactions || !Array.isArray(existingTransactions)) {
      return false;
    }

    // Check for duplicate nonce (same sender, same nonce = replay attack)
    const duplicateNonce = existingTransactions.find(
      tx => tx.id !== this.id && tx.nonce === this.nonce && this.hasSameSender(tx)
    );

    if (duplicateNonce) {
      return true;
    }

    // Check for duplicate transaction ID (exact same transaction)
    const duplicateId = existingTransactions.find(tx => tx.id === this.id);
    if (duplicateId) {
      return true;
    }

    return false;
  }

  /**
   * Check if this transaction has the same sender as another transaction
   * @param {Transaction} otherTx - Transaction to compare with
   * @returns {boolean} - True if same sender
   */
  hasSameSender(otherTx) {
    if (!otherTx || !otherTx.inputs || !this.inputs) {
      return false;
    }

    // Compare public keys from inputs to determine if same sender
    const thisPublicKeys = this.inputs.map(input => input.publicKey).sort();
    const otherPublicKeys = otherTx.inputs.map(input => input.publicKey).sort();

    if (thisPublicKeys.length !== otherPublicKeys.length) {
      return false;
    }

    return thisPublicKeys.every((pk, index) => pk === otherPublicKeys[index]);
  }

  /**
   * Calculate total input amount
   */
  getInputAmount() {
    if (this.isCoinbase) return 0;

    return this.inputs.reduce(
      (total, input) =>
        // This would normally look up the actual UTXO amount
        // For now, we'll assume a default value for non-coinbase transactions
        total + 100000000, // Assume each input is worth 1 PAS (reasonable default) in atomic units
      0
    );
  }

  /**
   * Calculate total output amount
   */
  getOutputAmount() {
    return this.outputs.reduce((total, output) => total + output.amount, 0);
  }

  /**
   * Check if transaction is valid with MANDATORY replay attack protection
   * @param config
   */
  isValid(config = null) {
    logger.debug(
      'TRANSACTION',
      `Validating transaction: id=${this.id}, isCoinbase=${this.isCoinbase}, outputs=${this.outputs?.length || 0}`
    );
    logger.debug(
      'TRANSACTION',
      `Transaction data: timestamp=${this.timestamp}, expiresAt=${this.expiresAt}, fee=${this.fee}, nonce=${this.nonce}`
    );

    // Check outputs exist (allow contract transactions to have no outputs)
    if (this.outputs.length === 0) {
      // Contract transactions don't need traditional outputs
      if (this.tag !== 'CONTRACT') {
        logger.debug('TRANSACTION', `Transaction validation failed: no outputs`);
        return false;
      }
    }
    logger.debug('TRANSACTION', `Outputs check passed: ${this.outputs.length} outputs`);

    // MANDATORY PROTECTION: ALL non-coinbase transactions must have replay protection
    if (!this.isCoinbase && (!this.nonce || !this.expiresAt)) {
      logger.debug('TRANSACTION', `Transaction validation failed: missing replay protection`);
      logger.debug('TRANSACTION', `  isCoinbase: ${this.isCoinbase}`);
      logger.debug('TRANSACTION', `  nonce: ${this.nonce} (${typeof this.nonce})`);
      logger.debug('TRANSACTION', `  expiresAt: ${this.expiresAt} (${typeof this.expiresAt})`);
      return false; // Reject unprotected transactions
    }
    logger.debug('TRANSACTION', `Replay protection check passed`);

    // REPLAY ATTACK PROTECTION: Check if transaction has expired (skip for genesis block and early blocks)
    const isEarlyBlock = config?.isEarlyBlock || this._isGenesisBlock;
    if (!isEarlyBlock) {
      logger.debug('TRANSACTION', `Checking if transaction is expired...`);
      
      // Use block timestamp for historical validation, current time for new transactions
      const contextTime = config?.blockTimestamp || Date.now();
      const isHistoricalValidation = config?.blockTimestamp !== undefined;
      
      if (this.isExpired(contextTime)) {
        logger.debug('TRANSACTION', `Transaction validation failed: transaction expired`);
        logger.debug('TRANSACTION', `  Context time: ${contextTime} (${isHistoricalValidation ? 'historical' : 'current'})`);
        logger.debug('TRANSACTION', `  Expires at: ${this.expiresAt}`);
        logger.debug('TRANSACTION', `  Age: ${this.expiresAt ? contextTime - this.expiresAt : 'N/A'}ms`);
        return false;
      }
      logger.debug('TRANSACTION', `Expiration check passed`);
    } else {
      logger.debug('TRANSACTION', `Skipping expiration check for early block transaction (block ${config?.blockIndex || 'genesis'})`);
    }

    // Verify transaction signature
    logger.debug('TRANSACTION', `Verifying transaction signature...`);
    if (!this.verify()) {
      logger.debug('TRANSACTION', `Transaction validation failed: signature verification failed`);
      return false;
    }
    logger.debug('TRANSACTION', `Signature verification passed`);

    const outputAmount = this.getOutputAmount();
    logger.debug('TRANSACTION', `Output amount calculated: ${outputAmount}`);

    if (this.isCoinbase) {
      logger.debug('TRANSACTION', `Validating coinbase transaction...`);

      
      const InputValidator = require('../utils/validation');
      if (this.outputs.length > 0) {
        const coinbaseAddress = this.outputs[0].address;
        const validatedAddress = InputValidator.validateCryptocurrencyAddress(coinbaseAddress);

        if (!validatedAddress) {
          logger.debug('TRANSACTION', `Coinbase validation failed: invalid recipient address format`);
          logger.debug('TRANSACTION', `  Address: ${coinbaseAddress}`);
          return false;
        }
        logger.debug('TRANSACTION', `Coinbase address validation passed: ${validatedAddress}`);
      }

      
      if (outputAmount <= 0) {
        logger.debug('TRANSACTION', `Transaction validation failed: invalid coinbase amount`);
        logger.debug('TRANSACTION', `  outputAmount: ${outputAmount}`);
        return false;
      }

      logger.debug('TRANSACTION', `Coinbase transaction validation passed`);
      // Additional coinbase validation can be done at blockchain level
      return true;
    }

    logger.debug('TRANSACTION', `Validating non-coinbase transaction...`);

    // Validate minimum fee if config is provided (except contract transactions)
    if (config && config.wallet && config.wallet.minFee !== undefined && this.tag !== 'CONTRACT') {
      logger.debug(
        'TRANSACTION',
        `Checking minimum fee requirement: minFee=${config.wallet.minFee}, actualFee=${this.fee}`
      );
      if (this.fee < config.wallet.minFee) {
        logger.debug('TRANSACTION', `Transaction validation failed: fee below minimum`);
        logger.debug('TRANSACTION', `  Required: ${config.wallet.minFee}`);
        logger.debug('TRANSACTION', `  Actual: ${this.fee}`);
        return false;
      }
      logger.debug('TRANSACTION', `Minimum fee check passed`);
    } else if (this.tag === 'CONTRACT') {
      logger.debug('TRANSACTION', `Skipping minimum fee check for contract transaction`);
    }

    // Validate fee is a positive number
    logger.debug('TRANSACTION', `Validating fee: ${this.fee} (${typeof this.fee})`);
    if (typeof this.fee !== 'number' || this.fee < 0) {
      logger.debug('TRANSACTION', `Transaction validation failed: invalid fee`);
      logger.debug('TRANSACTION', `  Fee: ${this.fee} (${typeof this.fee})`);
      return false;
    }
    logger.debug('TRANSACTION', `Fee validation passed`);

    // For non-coinbase transactions, validate inputs and outputs (except contract transactions)
    logger.debug('TRANSACTION', `Validating inputs: ${this.inputs.length} inputs`);
    if (this.inputs.length === 0) {
      // Contract transactions don't need traditional inputs
      if (this.tag !== 'CONTRACT') {
        logger.debug('TRANSACTION', `Transaction validation failed: no inputs for non-coinbase transaction`);
        return false; // Must have inputs
      }
    }
    logger.debug('TRANSACTION', `Inputs validation passed`);

    // Validate output amount is positive (allow zero for contract transactions)
    logger.debug('TRANSACTION', `Validating output amount: ${outputAmount}`);
    if (outputAmount <= 0) {
      // Contract transactions can have zero output amount
      if (this.tag !== 'CONTRACT') {
        logger.debug('TRANSACTION', `Transaction validation failed: invalid output amount`);
        logger.debug('TRANSACTION', `  outputAmount: ${outputAmount}`);
        return false;
      }
    }
    logger.debug('TRANSACTION', `Output amount validation passed`);

    logger.debug('TRANSACTION', `Transaction ${this.id} validation completed successfully`);
    return true;
  }

  /**
   * Create coinbase transaction
   * @param address
   * @param amount
   * @param timestamp
   * @param nonce
   * @param atomicSequence
   * @param isGenesisBlock
   * @param paymentId
   */
  static createCoinbase(
    address,
    amount,
    timestamp = null,
    nonce = null,
    atomicSequence = null,
    isGenesisBlock = false,
    paymentId = null
  ) {
    
    const InputValidator = require('../utils/validation');
    const validatedAddress = InputValidator.validateCryptocurrencyAddress(address);

    if (!validatedAddress) {
      throw new Error(`Invalid coinbase recipient address: ${address}. Must be a valid cryptocurrency address format.`);
    }

    const transaction = new Transaction(
      [],
      [new TransactionOutput(validatedAddress, amount)],
      0,
      isGenesisBlock ? TRANSACTION_TAGS.PREMINE : TRANSACTION_TAGS.COINBASE,
      timestamp,
      nonce,
      atomicSequence,
      isGenesisBlock,
      paymentId
    );
    transaction.isCoinbase = true;
    transaction.calculateId();
    return transaction;
  }

  /**
   * Create Transaction instance from JSON data
   * @param {Object} data - JSON transaction data
   * @returns {Transaction} Transaction instance
   */
  static fromJSON(data) {
    logger.debug('TRANSACTION', `Creating Transaction from JSON: id=${data.id}, inputs=${data.inputs?.length || 0}, outputs=${data.outputs?.length || 0}`);

    // DEBUG: Log raw input data
    if (data.inputs && data.inputs.length > 0) {
      logger.debug('TRANSACTION', `Raw input data: ${JSON.stringify(data.inputs[0])}`);
    }

    // Create Transaction instance
    const transaction = new Transaction();

    // Set all fields from JSON data
    transaction.id = data.id;
    transaction.inputs = data.inputs?.map((input, index) => {
      logger.debug('TRANSACTION', `Converting input ${index}: txId=${input.txId}, outputIndex=${input.outputIndex}`);
      return new TransactionInput(input.txId, input.outputIndex, input.signature, input.publicKey);
    }) || [];
    transaction.outputs = data.outputs?.map(output => new TransactionOutput(output.address, output.amount)) || [];
    transaction.fee = data.fee || 0;
    transaction.paymentId = data.paymentId;
    transaction.timestamp = data.timestamp;
    transaction.isCoinbase = data.isCoinbase || false;
    transaction.tag = data.tag || 'TRANSACTION';
    transaction.nonce = data.nonce;
    transaction.expiresAt = data.expiresAt;
    transaction.sequence = data.sequence || 0;
    transaction._atomicSequence = data.atomicSequence; // Use exact field name from JSON

    // Mark as immutable since it's from stored data
    transaction._isImmutable = true;

    // DEBUG: Verify reconstructed input data
    if (transaction.inputs && transaction.inputs.length > 0) {
      logger.debug('TRANSACTION', `Reconstructed input: txId=${transaction.inputs[0].txId}, outputIndex=${transaction.inputs[0].outputIndex}`);
    }

    logger.debug('TRANSACTION', `Successfully created Transaction instance: id=${transaction.id}, timestamp=${transaction.timestamp}, atomicSequence=${transaction._atomicSequence}`);
    return transaction;
  }

  /**
   * Create regular transaction
   * @param inputs
   * @param outputs
   * @param fee
   * @param timestamp
   * @param nonce
   * @param atomicSequence
   * @param paymentId
   */
  static createTransaction(
    inputs,
    outputs,
    fee = 0,
    timestamp = null,
    nonce = null,
    atomicSequence = null,
    paymentId = null
  ) {
    const transaction = new Transaction(
      inputs,
      outputs,
      fee,
      TRANSACTION_TAGS.TRANSACTION,
      timestamp,
      nonce,
      atomicSequence,
      false,
      paymentId
    );
    transaction.calculateId();
    return transaction;
  }

  /**
   *
   */
  toJSON() {
    return {
      id: this.id,
      inputs: this.inputs.map(input => input.toJSON()),
      outputs: this.outputs.map(output => output.toJSON()),
      fee: this.fee,
      paymentId: this.paymentId,
      timestamp: this.timestamp,
      isCoinbase: this.isCoinbase,
      tag: this.tag,
      nonce: this.nonce,
      expiresAt: this.expiresAt,
      sequence: this.sequence,
      atomicSequence: this._atomicSequence,
    };
  }

  /**
   *
   * @param data
   */
  static fromJSON(data) {
    try {
      if (!data || typeof data !== 'object') {
        throw new Error('Invalid transaction data: data is not an object');
      }

      if (!data.inputs || !Array.isArray(data.inputs)) {
        throw new Error('Invalid transaction data: inputs property is missing or not an array');
      }

      if (!data.outputs || !Array.isArray(data.outputs)) {
        throw new Error('Invalid transaction data: outputs property is missing or not an array');
      }

      const transaction = new Transaction(
        data.inputs.length > 0 ? data.inputs.map(input => TransactionInput.fromJSON(input)) : [],
        data.outputs.map(output => TransactionOutput.fromJSON(output)),
        data.fee || 0,
        data.tag || TRANSACTION_TAGS.TRANSACTION,
        data.timestamp || null,
        data.nonce || null,
        data.atomicSequence || null, // Preserve atomic sequence for validation
        data._isGenesisBlock || false,
        data.paymentId || null
      );
      transaction.id = data.id;
      transaction.timestamp = data.timestamp || Date.now();
      transaction.isCoinbase = data.isCoinbase || false;

      // Load replay protection fields if they exist
      if (data.nonce) {
        transaction.nonce = data.nonce;
      }
      if (data.expiresAt) {
        transaction.expiresAt = data.expiresAt;
      }
      if (data.sequence !== undefined) {
        transaction.sequence = data.sequence;
      }
      
      if (data.atomicSequence) {
        transaction._atomicSequence = data.atomicSequence;
      }

      return transaction;
    } catch (error) {
      throw new Error(`Failed to create transaction from JSON: ${error.message}`);
    }
  }
}

module.exports = { Transaction, TransactionInput, TransactionOutput };
