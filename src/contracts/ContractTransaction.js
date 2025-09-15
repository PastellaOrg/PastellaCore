const { Transaction, TransactionInput, TransactionOutput } = require('../models/Transaction');
const { TRANSACTION_TAGS } = require('../utils/constants');
const logger = require('../utils/logger');

/**
 * CONTRACT TRANSACTION CLASS
 *
 * Extends the base Transaction class to handle smart contract operations.
 * Contract transactions have special properties:
 * - They use the CONTRACT transaction tag
 * - They contain contract-specific data in the contractData field
 * - They are validated through the contract engine
 * - They can have zero monetary value (gas-free execution)
 */
class ContractTransaction extends Transaction {
  /**
   * Create a contract transaction
   * @param {Array} inputs - Transaction inputs (can be empty for deployment)
   * @param {Array} outputs - Transaction outputs (can be empty for some operations)
   * @param {number} fee - Transaction fee in atomic units
   * @param {Object} contractData - Contract-specific data
   * @param {number} timestamp - Transaction timestamp (optional)
   */
  constructor(inputs, outputs, fee, contractData, timestamp = null) {
    // Contract transactions always use the CONTRACT tag
    super(inputs, outputs, fee, TRANSACTION_TAGS.CONTRACT, timestamp);

    // Contract-specific data
    this.contractData = contractData || {};

    // Validate contract data structure
    this._validateContractData();

    logger.debug('CONTRACT_TRANSACTION', `Created contract transaction for operation: ${this.contractData.operation}`);
  }

  /**
   * Validate contract data structure
   */
  _validateContractData() {
    if (!this.contractData.operation) {
      throw new Error('Contract transaction must specify an operation');
    }

    const validOperations = ['DEPLOY', 'EXECUTE'];
    if (!validOperations.includes(this.contractData.operation)) {
      throw new Error(`Invalid contract operation: ${this.contractData.operation}`);
    }

    // Validate operation-specific data
    switch (this.contractData.operation) {
      case 'DEPLOY':
        this._validateDeploymentData();
        break;
      case 'EXECUTE':
        this._validateExecutionData();
        break;
    }
  }

  /**
   * Validate deployment data
   */
  _validateDeploymentData() {
    const { contractType, initData, owner } = this.contractData;

    if (!contractType) {
      throw new Error('Contract deployment must specify contractType');
    }

    if (!owner) {
      throw new Error('Contract deployment must specify owner address');
    }

    // contractType and initData are optional but if provided should be valid
    if (initData && typeof initData !== 'object') {
      throw new Error('Contract initData must be an object');
    }
  }

  /**
   * Validate execution data
   */
  _validateExecutionData() {
    const { contractAddress, method, params, caller } = this.contractData;

    if (!contractAddress) {
      throw new Error('Contract execution must specify contractAddress');
    }

    if (!method) {
      throw new Error('Contract execution must specify method');
    }

    if (!caller) {
      throw new Error('Contract execution must specify caller address');
    }

    // params is optional but if provided should be an object
    if (params && typeof params !== 'object') {
      throw new Error('Contract params must be an object');
    }
  }

  /**
   * Create a contract deployment transaction
   * @param {string} contractType - Type of contract to deploy
   * @param {Object} initData - Initial contract data
   * @param {string} owner - Contract owner address
   * @param {number} fee - Transaction fee
   * @returns {ContractTransaction} - Contract deployment transaction
   */
  static createDeployment(contractType, initData, owner, fee = 0) {
    // Contract deployment typically doesn't need monetary inputs/outputs
    const inputs = [];
    const outputs = [];

    const contractData = {
      operation: 'DEPLOY',
      contractType,
      initData,
      owner
    };

    const transaction = new ContractTransaction(inputs, outputs, fee, contractData);
    transaction.calculateId();
    return transaction;
  }

  /**
   * Create a contract execution transaction
   * @param {string} contractAddress - Address of contract to execute
   * @param {string} method - Method to call
   * @param {Object} params - Method parameters
   * @param {string} caller - Address calling the method
   * @param {number} fee - Transaction fee
   * @returns {ContractTransaction} - Contract execution transaction
   */
  static createExecution(contractAddress, method, params, caller, fee = 0) {
    // Contract execution typically doesn't need monetary inputs/outputs
    // unless it's a transfer or mint operation that affects balances
    const inputs = [];
    const outputs = [];

    const contractData = {
      operation: 'EXECUTE',
      contractAddress,
      method,
      params,
      caller
    };

    const transaction = new ContractTransaction(inputs, outputs, fee, contractData);
    transaction.calculateId();
    return transaction;
  }

  /**
   * Get contract operation type
   * @returns {string} - Contract operation type
   */
  getContractOperation() {
    return this.contractData.operation;
  }

  /**
   * Get contract address (for execution transactions)
   * @returns {string|null} - Contract address or null for deployment
   */
  getContractAddress() {
    return this.contractData.contractAddress || null;
  }

  /**
   * Get contract method (for execution transactions)
   * @returns {string|null} - Contract method or null for deployment
   */
  getContractMethod() {
    return this.contractData.method || null;
  }

  /**
   * Get contract caller
   * @returns {string} - Caller address
   */
  getContractCaller() {
    return this.contractData.caller || this.contractData.owner;
  }

  /**
   * Check if this is a deployment transaction
   * @returns {boolean} - True if deployment transaction
   */
  isDeployment() {
    return this.contractData.operation === 'DEPLOY';
  }

  /**
   * Check if this is an execution transaction
   * @returns {boolean} - True if execution transaction
   */
  isExecution() {
    return this.contractData.operation === 'EXECUTE';
  }

  /**
   * Override the base validation to include contract-specific checks
   * @returns {boolean} - Whether transaction is valid
   */
  isValid() {
    try {
      // Run base transaction validation
      if (!super.isValid()) {
        return false;
      }

      // Contract-specific validation
      this._validateContractData();

      return true;
    } catch (error) {
      logger.error('CONTRACT_TRANSACTION', `Contract transaction validation failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Convert contract transaction to JSON
   * @returns {Object} - JSON representation
   */
  toJSON() {
    return {
      ...super.toJSON(),
      contractData: this.contractData
    };
  }

  /**
   * Create ContractTransaction from JSON
   * @param {Object} data - JSON data
   * @returns {ContractTransaction} - Contract transaction instance
   */
  static fromJSON(data) {
    const inputs = data.inputs.map(input =>
      new TransactionInput(input.txHash, input.outputIndex, input.signature, input.publicKey)
    );

    const outputs = data.outputs.map(output =>
      new TransactionOutput(output.address, output.amount)
    );

    const transaction = new ContractTransaction(
      inputs,
      outputs,
      data.fee,
      data.contractData,
      data.timestamp
    );

    // Restore additional properties
    transaction.id = data.id;
    transaction.nonce = data.nonce;
    transaction.expiresAt = data.expiresAt;
    transaction.networkId = data.networkId;
    transaction.atomicSequence = data.atomicSequence;

    return transaction;
  }

  /**
   * Get a summary of the contract transaction
   * @returns {string} - Human-readable summary
   */
  getSummary() {
    switch (this.contractData.operation) {
      case 'DEPLOY':
        return `Deploy ${this.contractData.contractType} contract for ${this.contractData.owner}`;
      case 'EXECUTE':
        return `Execute ${this.contractData.method} on ${this.contractData.contractAddress} by ${this.contractData.caller}`;
      default:
        return `Contract transaction: ${this.contractData.operation}`;
    }
  }
}

module.exports = ContractTransaction;