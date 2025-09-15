const logger = require('../utils/logger');
const { toAtomicUnits, fromAtomicUnits } = require('../utils/atomicUnits');
const InputValidator = require('../utils/validation');

/**
 * PASTELLA SMART CONTRACT ENGINE
 *
 * Unique Features:
 * - State-based contracts (no arbitrary code execution for security)
 * - Built-in token operations with atomic execution
 * - Permission system with role-based access control
 * - Native integration with Pastella blockchain
 * - Fee-based execution (operations paid via transaction fees)
 * - Mandatory payment verification for all operations
 */
class ContractEngine {
  constructor(blockchain) {
    this.blockchain = blockchain;

    // Contract storage: contractId -> Contract instance
    this.contracts = new Map();

    // Contract addresses: unique identifier generation
    this.contractCounter = 0;

    // Supported contract types
    this.supportedTypes = ['TOKEN'];

    // PAYMENT SYSTEM: Track payments for contract operations
    this.paymentTracker = new Map(); // txId -> { contractAddress, operation, paidAmount, verified }

    // PAYMENT SYSTEM: Daily operation tracking for free tier (if needed in future)
    this.dailyOperations = new Map(); // address -> { date, count }

    logger.info('CONTRACT_ENGINE', 'Pastella Smart Contract Engine initialized with payment system');
  }

  /**
   * Generate unique contract address
   * Format: 'PC' + 8-digit hex + checksum (Pastella Contract)
   */
  generateContractAddress() {
    this.contractCounter++;
    const hex = this.contractCounter.toString(16).padStart(8, '0');
    const checksum = this._calculateChecksum(hex);
    return `PC${hex}${checksum}`;
  }

  /**
   * Calculate simple checksum for contract address
   * @param {string} hex - Hex string to calculate checksum for
   * @returns {string} - 2-character checksum
   */
  _calculateChecksum(hex) {
    let sum = 0;
    for (let i = 0; i < hex.length; i++) {
      sum += parseInt(hex[i], 16);
    }
    return (sum % 256).toString(16).padStart(2, '0');
  }

  /**
   * Deploy a new contract with mandatory payment verification
   * @param {string} type - Contract type ('TOKEN')
   * @param {Object} initData - Initial contract data
   * @param {string} owner - Contract owner address
   * @param {string} paymentTxId - Transaction ID containing the payment
   * @returns {Object} - Deployment result
   */
  deployContract(type, initData, owner, paymentTxId) {
    try {
      // Validate input
      if (!this.supportedTypes.includes(type)) {
        throw new Error(`Unsupported contract type: ${type}`);
      }

      if (!InputValidator.validateCryptocurrencyAddress(owner)) {
        throw new Error('Invalid owner address');
      }

      if (!paymentTxId) {
        throw new Error('Payment transaction ID is required for contract deployment');
      }

      // PAYMENT VERIFICATION: Check if deployment fee was paid
      const requiredFee = this.getDeploymentFee(type);
      const paymentVerified = this.verifyPayment(paymentTxId, owner, requiredFee, 'deployment');

      if (!paymentVerified) {
        throw new Error(`Deployment fee verification failed. Required: ${fromAtomicUnits(requiredFee)} PAS`);
      }

      // Generate contract address
      const contractAddress = this.generateContractAddress();

      // Create contract instance
      let contract;
      switch (type) {
        case 'TOKEN':
          contract = new TokenContract(contractAddress, owner, initData);
          break;
        default:
          throw new Error(`Contract type ${type} not implemented`);
      }

      // Store contract
      this.contracts.set(contractAddress, contract);

      // PAYMENT TRACKING: Record successful deployment payment
      this.paymentTracker.set(paymentTxId, {
        contractAddress,
        operation: 'deployment',
        type,
        paidAmount: requiredFee,
        verified: true,
        timestamp: Date.now(),
        owner
      });

      logger.info('CONTRACT_ENGINE',
        `Deployed ${type} contract at ${contractAddress} for owner ${owner} with payment ${paymentTxId}`
      );

      return {
        success: true,
        contractAddress,
        type,
        owner,
        paymentVerified: true,
        paidAmount: fromAtomicUnits(requiredFee),
        deploymentData: contract.getPublicState()
      };
    } catch (error) {
      logger.error('CONTRACT_ENGINE', `Contract deployment failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Execute contract method with mandatory payment verification
   * @param {string} contractAddress - Contract address
   * @param {string} method - Method name
   * @param {Object} params - Method parameters
   * @param {string} caller - Address calling the method
   * @param {string} paymentTxId - Transaction ID containing the payment (not required for free read operations)
   * @returns {Object} - Execution result
   */
  executeContract(contractAddress, method, params, caller, paymentTxId = null) {
    try {
      // Get contract
      const contract = this.contracts.get(contractAddress);
      if (!contract) {
        throw new Error(`Contract not found: ${contractAddress}`);
      }

      // Validate caller (allow 'system' for read-only operations)
      if (caller !== 'system' && !InputValidator.validateCryptocurrencyAddress(caller)) {
        throw new Error('Invalid caller address');
      }

      // PAYMENT VERIFICATION: Check if execution fee was paid (skip for read-only operations)
      const requiredFee = this.getExecutionFee(method);
      let paymentVerified = false;
      let actualPaidAmount = 0;

      if (requiredFee > 0) {
        // This operation requires payment
        if (!paymentTxId) {
          throw new Error(`Payment transaction ID is required for ${method}. Required fee: ${fromAtomicUnits(requiredFee)} PAS`);
        }

        paymentVerified = this.verifyPayment(paymentTxId, caller, requiredFee, method);

        if (!paymentVerified) {
          throw new Error(`Execution fee verification failed for ${method}. Required: ${fromAtomicUnits(requiredFee)} PAS`);
        }

        actualPaidAmount = requiredFee;
        logger.debug('CONTRACT_ENGINE', `Payment verified for ${method}: ${fromAtomicUnits(requiredFee)} PAS`);
      } else {
        // Free operation (read-only)
        paymentVerified = true;
        logger.debug('CONTRACT_ENGINE', `Free operation: ${method}`);
      }

      // SECURITY: Rate limiting for contract execution
      this._checkExecutionRateLimit(contractAddress, caller);

      // SECURITY: Fee limit simulation (prevent expensive operations)
      this._checkFeeLimit(method, params);

      // SECURITY: Input validation
      this._validateMethodInputs(method, params);

      // Execute method
      const result = contract.executeMethod(method, params, caller);

      // PAYMENT TRACKING: Record successful execution payment (if payment was required)
      if (requiredFee > 0 && paymentTxId) {
        this.paymentTracker.set(paymentTxId, {
          contractAddress,
          operation: method,
          paidAmount: actualPaidAmount,
          verified: true,
          timestamp: Date.now(),
          caller
        });
      }

      logger.debug('CONTRACT_ENGINE',
        `Executed ${method} on ${contractAddress} by ${caller}${paymentTxId ? ` with payment ${paymentTxId}` : ' (free operation)'}`
      );

      return {
        success: true,
        contractAddress,
        method,
        result,
        paymentVerified,
        paidAmount: fromAtomicUnits(actualPaidAmount),
        newState: contract.getPublicState()
      };
    } catch (error) {
      logger.error('CONTRACT_ENGINE', `Contract execution failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * SECURITY: Check execution rate limit per address
   * @param {string} contractAddress - Contract address
   * @param {string} caller - Caller address
   */
  _checkExecutionRateLimit(contractAddress, caller) {
    if (caller === 'system') return; // Skip rate limit for system calls

    const key = `${contractAddress}:${caller}`;
    const now = Date.now();
    const windowMs = 60000; // 1 minute window
    const maxExecutions = 100; // Max 100 executions per minute per address

    if (!this.executionRateLimits) {
      this.executionRateLimits = new Map();
    }

    const rateData = this.executionRateLimits.get(key) || { count: 0, resetTime: now + windowMs };

    if (now > rateData.resetTime) {
      // Reset window
      rateData.count = 1;
      rateData.resetTime = now + windowMs;
    } else {
      rateData.count++;
    }

    if (rateData.count > maxExecutions) {
      throw new Error(`Rate limit exceeded for contract execution. Try again later.`);
    }

    this.executionRateLimits.set(key, rateData);
  }

  /**
   * SECURITY: Simulate fee limit to prevent expensive operations
   * @param {string} method - Method name
   * @param {Object} params - Method parameters
   */
  _checkFeeLimit(method, params) {
    // Assign computation costs to different operations
    const computationCosts = {
      'createToken': 100,
      'mint': 50,
      'burn': 50,
      'transfer': 30,
      'grantPermission': 75,
      'revokePermission': 75,
      'getBalance': 10,
      'getToken': 10
    };

    const baseCost = computationCosts[method] || 50;
    let totalCost = baseCost;

    // Additional cost based on parameters
    if (params.amount) {
      const amount = parseFloat(params.amount) || 0;
      totalCost += Math.min(amount / 1000, 50); // Max 50 extra cost for large amounts
    }

    if (params.name && params.name.length > 50) {
      totalCost += 25; // Extra cost for long names
    }

    const maxCost = 1000; // Maximum computation cost per execution
    if (totalCost > maxCost) {
      throw new Error(`Operation exceeds computation limit (${totalCost} > ${maxCost})`);
    }
  }

  /**
   * SECURITY: Validate method inputs
   * @param {string} method - Method name
   * @param {Object} params - Method parameters
   */
  _validateMethodInputs(method, params) {
    // Common validations
    if (params.amount !== undefined) {
      if (typeof params.amount !== 'number' && typeof params.amount !== 'string') {
        throw new Error('Amount must be a number or string');
      }

      const amount = parseFloat(params.amount);
      if (isNaN(amount) || amount < 0) {
        throw new Error('Amount must be a positive number');
      }

      if (amount > Number.MAX_SAFE_INTEGER) {
        throw new Error('Amount exceeds maximum safe value');
      }
    }

    // String length limits
    const stringFields = ['name', 'symbol', 'tokenId'];
    stringFields.forEach(field => {
      if (params[field] && typeof params[field] === 'string') {
        if (params[field].length > 100) {
          throw new Error(`${field} exceeds maximum length (100 characters)`);
        }
        if (params[field].length === 0) {
          throw new Error(`${field} cannot be empty`);
        }
      }
    });

    // Method-specific validations
    switch (method) {
      case 'createToken':
        if (params.decimals !== undefined) {
          if (!Number.isInteger(params.decimals) || params.decimals < 0 || params.decimals > 18) {
            throw new Error('Decimals must be an integer between 0 and 18');
          }
        }
        break;

      case 'transfer':
        if (params.from === params.to) {
          throw new Error('Cannot transfer to the same address');
        }
        break;
    }
  }

  /**
   * PAYMENT SYSTEM: Get deployment fee for contract type
   * @param {string} contractType - Type of contract ('TOKEN')
   * @returns {number} - Fee in atomic units
   */
  getDeploymentFee(contractType) {
    // Get fee from blockchain configuration
    const config = this.blockchain.config;
    if (!config || !config.smartContracts || !config.smartContracts.deploymentFees) {
      throw new Error('Smart contract deployment fees not configured');
    }

    const deploymentFees = config.smartContracts.deploymentFees;
    const fee = deploymentFees[contractType];

    if (fee === undefined) {
      throw new Error(`Deployment fee not configured for contract type: ${contractType}`);
    }

    logger.debug('CONTRACT_ENGINE', `Deployment fee for ${contractType}: ${fromAtomicUnits(fee)} PAS`);
    return fee;
  }

  /**
   * PAYMENT SYSTEM: Get execution fee for method
   * @param {string} method - Method name
   * @returns {number} - Fee in atomic units
   */
  getExecutionFee(method) {
    // Get fee from blockchain configuration
    const config = this.blockchain.config;
    if (!config || !config.smartContracts || !config.smartContracts.executionFees) {
      throw new Error('Smart contract execution fees not configured');
    }

    const executionFees = config.smartContracts.executionFees;
    const fee = executionFees[method];

    if (fee === undefined) {
      // Default fee for unknown methods
      return executionFees.transfer || 1000000; // Default to transfer cost
    }

    return fee;
  }

  /**
   * PAYMENT SYSTEM: Verify that a payment transaction contains the required fee
   * This method checks if the specified transaction ID contains a valid payment
   * from the caller address with at least the required fee amount
   *
   * @param {string} paymentTxId - Transaction ID to verify
   * @param {string} callerAddress - Address that should have made the payment
   * @param {number} requiredFee - Required fee amount in atomic units
   * @param {string} operation - Operation being paid for (for logging)
   * @returns {boolean} - True if payment is verified, false otherwise
   */
  verifyPayment(paymentTxId, callerAddress, requiredFee, operation) {
    try {
      // Check if payment was already verified to prevent double-spending
      if (this.paymentTracker.has(paymentTxId)) {
        const existingPayment = this.paymentTracker.get(paymentTxId);
        logger.warn('CONTRACT_ENGINE',
          `Payment ${paymentTxId} already used for ${existingPayment.operation} by ${existingPayment.caller || existingPayment.owner}`
        );
        return false;
      }

      // Get smart contract configuration
      const config = this.blockchain.config;
      if (!config || !config.smartContracts) {
        logger.error('CONTRACT_ENGINE', 'Smart contract configuration not found');
        return false;
      }

      const developmentAddress = config.smartContracts.developmentAddress;
      const requiredConfirmations = config.smartContracts.requiredConfirmations || 20;

      if (!developmentAddress) {
        logger.error('CONTRACT_ENGINE', 'Development address not configured');
        return false;
      }

      // Find the transaction in the blockchain
      const transaction = this.findTransactionById(paymentTxId);
      if (!transaction) {
        logger.error('CONTRACT_ENGINE', `Payment transaction not found: ${paymentTxId}`);
        return false;
      }

      // Verify the transaction is from the correct caller
      const senderAddress = this.blockchain.getTransactionSenderAddress(transaction);
      if (senderAddress !== callerAddress) {
        logger.error('CONTRACT_ENGINE',
          `Payment sender mismatch. Expected: ${callerAddress}, Got: ${senderAddress}`
        );
        return false;
      }

      // Get payment model configuration
      const paymentModel = config.smartContracts.paymentModel || {};
      const minDevelopmentPayment = config.smartContracts.minDevelopmentPayment || 1; // 0.00000001 PAS
      const isDeployment = operation === 'deployment';

      // Verify transaction payment based on operation type
      let sentToDevelopmentAddress = false;
      let totalSentToDev = 0;
      let totalTransactionFee = transaction.fee || 0;

      if (transaction.outputs && transaction.outputs.length > 0) {
        for (const output of transaction.outputs) {
          if (output.address === developmentAddress) {
            sentToDevelopmentAddress = true;
            totalSentToDev += output.amount || 0;
          }
        }
      }

      if (!sentToDevelopmentAddress) {
        logger.error('CONTRACT_ENGINE',
          `Payment must be sent to development address: ${developmentAddress}. Transaction ${paymentTxId} does not contain output to development address.`
        );
        return false;
      }

      // Check payment requirements based on operation type
      if (isDeployment) {
        // DEPLOYMENT: Full fee must be sent to development address
        if (totalSentToDev < requiredFee) {
          logger.error('CONTRACT_ENGINE',
            `Deployment payment insufficient. Required: ${fromAtomicUnits(requiredFee)} PAS to ${developmentAddress}, Got: ${fromAtomicUnits(totalSentToDev)} PAS`
          );
          return false;
        }
        logger.info('CONTRACT_ENGINE',
          `Deployment payment verified: ${fromAtomicUnits(totalSentToDev)} PAS sent to development address`
        );
      } else {
        // EXECUTION: Minimum amount to dev address + transaction fee covers operation cost
        if (totalSentToDev < minDevelopmentPayment) {
          logger.error('CONTRACT_ENGINE',
            `Execution payment insufficient to development address. Required: ${fromAtomicUnits(minDevelopmentPayment)} PAS minimum to ${developmentAddress}, Got: ${fromAtomicUnits(totalSentToDev)} PAS`
          );
          return false;
        }

        if (totalTransactionFee < requiredFee) {
          logger.error('CONTRACT_ENGINE',
            `Execution transaction fee insufficient. Required: ${fromAtomicUnits(requiredFee)} PAS transaction fee, Got: ${fromAtomicUnits(totalTransactionFee)} PAS`
          );
          return false;
        }

        logger.info('CONTRACT_ENGINE',
          `Execution payment verified: ${fromAtomicUnits(totalSentToDev)} PAS to dev address + ${fromAtomicUnits(totalTransactionFee)} PAS transaction fee`
        );
      }

      // Check transaction confirmations (must have at least required confirmations)
      const confirmations = this.getTransactionConfirmations(paymentTxId);
      if (confirmations < requiredConfirmations) {
        logger.error('CONTRACT_ENGINE',
          `Payment transaction needs more confirmations. Required: ${requiredConfirmations}, Got: ${confirmations}. Transaction: ${paymentTxId}`
        );
        return false;
      }

      if (isDeployment) {
        logger.info('CONTRACT_ENGINE',
          `Payment verified: ${paymentTxId} - ${fromAtomicUnits(totalSentToDev)} PAS to ${developmentAddress} for ${operation} by ${callerAddress} (${confirmations} confirmations)`
        );
      } else {
        logger.info('CONTRACT_ENGINE',
          `Payment verified: ${paymentTxId} - ${fromAtomicUnits(totalSentToDev)} PAS to dev + ${fromAtomicUnits(totalTransactionFee)} PAS fee for ${operation} by ${callerAddress} (${confirmations} confirmations)`
        );
      }
      return true;

    } catch (error) {
      logger.error('CONTRACT_ENGINE', `Payment verification failed: ${error.message}`);
      return false;
    }
  }

  /**
   * PAYMENT SYSTEM: Find transaction by ID in the blockchain
   * @param {string} txId - Transaction ID to find
   * @returns {Object|null} - Transaction object or null if not found
   */
  findTransactionById(txId) {
    try {
      // Search through all blocks in the blockchain
      for (const block of this.blockchain.chain) {
        if (block.transactions) {
          for (const transaction of block.transactions) {
            if (transaction.id === txId) {
              return transaction;
            }
          }
        }
      }

      // Also check pending transactions in mempool
      const pendingTxs = this.blockchain.memoryPool.getPendingTransactions();
      for (const transaction of pendingTxs) {
        if (transaction.id === txId) {
          return transaction;
        }
      }

      return null;
    } catch (error) {
      logger.error('CONTRACT_ENGINE', `Error finding transaction: ${error.message}`);
      return null;
    }
  }

  /**
   * PAYMENT SYSTEM: Check if transaction is confirmed (exists in a block)
   * @param {string} txId - Transaction ID to check
   * @returns {boolean} - True if transaction is in a block, false otherwise
   */
  isTransactionConfirmed(txId) {
    try {
      // Search through all blocks in the blockchain
      for (const block of this.blockchain.chain) {
        if (block.transactions) {
          for (const transaction of block.transactions) {
            if (transaction.id === txId) {
              return true;
            }
          }
        }
      }
      return false;
    } catch (error) {
      logger.error('CONTRACT_ENGINE', `Error checking transaction confirmation: ${error.message}`);
      return false;
    }
  }

  /**
   * PAYMENT SYSTEM: Get payment status for a transaction
   * @param {string} paymentTxId - Transaction ID to check
   * @returns {Object} - Payment status information
   */
  getPaymentStatus(paymentTxId) {
    if (this.paymentTracker.has(paymentTxId)) {
      const payment = this.paymentTracker.get(paymentTxId);

      // Check if this is a failed deployment that should be cleaned up
      if (payment.status === 'pending' && !payment.verified && payment.operation === 'deployment') {
        // Check if the contract actually exists
        const contractExists = this.contracts.has(payment.contractAddress);
        if (!contractExists) {
          logger.warn('CONTRACT_ENGINE', `Cleaning up failed deployment payment ${paymentTxId} - contract ${payment.contractAddress} was never created`);
          this.paymentTracker.delete(paymentTxId);
          return {
            verified: false,
            message: 'Previous deployment failed - payment available for retry'
          };
        }
      }

      return payment;
    }

    return {
      verified: false,
      message: 'Payment not found or not verified'
    };
  }

  /**
   * PAYMENT SYSTEM: Clean up failed deployments from payment tracker
   * This removes payments for contracts that were never actually deployed
   */
  cleanupFailedDeployments() {
    let cleanedCount = 0;
    const paymentsToDelete = [];

    for (const [paymentTxId, payment] of this.paymentTracker.entries()) {
      if (payment.status === 'pending' && !payment.verified && payment.operation === 'deployment') {
        // Check if the contract actually exists
        const contractExists = this.contracts.has(payment.contractAddress);
        if (!contractExists) {
          paymentsToDelete.push(paymentTxId);
          cleanedCount++;
        }
      }
    }

    // Remove failed payments
    paymentsToDelete.forEach(paymentTxId => {
      const payment = this.paymentTracker.get(paymentTxId);
      logger.info('CONTRACT_ENGINE', `Cleaned up failed deployment payment ${paymentTxId} for contract ${payment.contractAddress}`);
      this.paymentTracker.delete(paymentTxId);
    });

    if (cleanedCount > 0) {
      logger.info('CONTRACT_ENGINE', `Cleaned up ${cleanedCount} failed deployment payments`);
    }

    return cleanedCount;
  }

  /**
   * PAYMENT SYSTEM: Get number of confirmations for a transaction
   * @param {string} txId - Transaction ID to check
   * @returns {number} - Number of confirmations (0 if not found or not confirmed)
   */
  getTransactionConfirmations(txId) {
    try {
      // Find the block containing the transaction
      let transactionBlockIndex = -1;

      for (let i = 0; i < this.blockchain.chain.length; i++) {
        const block = this.blockchain.chain[i];
        if (block.transactions) {
          for (const transaction of block.transactions) {
            if (transaction.id === txId) {
              transactionBlockIndex = i;
              break;
            }
          }
        }
        if (transactionBlockIndex !== -1) break;
      }

      // If transaction not found in any block, it has 0 confirmations
      if (transactionBlockIndex === -1) {
        return 0;
      }

      // Calculate confirmations: current blockchain height - transaction block index
      const currentHeight = this.blockchain.chain.length - 1;
      const confirmations = currentHeight - transactionBlockIndex;

      // Confirmations should be at least 0
      return Math.max(0, confirmations);
    } catch (error) {
      logger.error('CONTRACT_ENGINE', `Error getting transaction confirmations: ${error.message}`);
      return 0;
    }
  }

  /**
   * Get contract information
   * @param {string} contractAddress - Contract address
   * @returns {Object} - Contract information
   */
  getContract(contractAddress) {
    const contract = this.contracts.get(contractAddress);
    if (!contract) {
      throw new Error(`Contract not found: ${contractAddress}`);
    }

    return {
      address: contractAddress,
      type: contract.type,
      owner: contract.owner,
      state: contract.getPublicState(),
      createdAt: contract.createdAt
    };
  }

  /**
   * Get all contracts
   * @returns {Array} - Array of contract information
   */
  getAllContracts() {
    const contracts = [];
    for (const [address, contract] of this.contracts.entries()) {
      contracts.push({
        address,
        type: contract.type,
        owner: contract.owner,
        state: contract.getPublicState(),
        createdAt: contract.createdAt
      });
    }
    return contracts;
  }

  /**
   * Serialize contracts for blockchain storage
   * @returns {Object} - Serialized contracts data
   */
  serialize() {
    const serialized = {
      contractCounter: this.contractCounter,
      contracts: {},
      // PAYMENT SYSTEM: Serialize payment tracking data
      paymentTracker: Object.fromEntries(this.paymentTracker)
    };

    for (const [address, contract] of this.contracts.entries()) {
      serialized.contracts[address] = contract.serialize();
    }

    return serialized;
  }

  /**
   * Deserialize contracts from blockchain storage
   * @param {Object} data - Serialized contracts data
   */
  deserialize(data) {
    if (!data) return;

    this.contractCounter = data.contractCounter || 0;
    this.contracts.clear();

    // PAYMENT SYSTEM: Restore payment tracking data
    if (data.paymentTracker) {
      this.paymentTracker = new Map(Object.entries(data.paymentTracker));
    }

    if (data.contracts) {
      for (const [address, contractData] of Object.entries(data.contracts)) {
        let contract;
        switch (contractData.type) {
          case 'TOKEN':
            contract = TokenContract.deserialize(contractData);
            break;
          default:
            logger.warn('CONTRACT_ENGINE', `Unknown contract type during deserialization: ${contractData.type}`);
            continue;
        }
        this.contracts.set(address, contract);
      }
    }

    logger.info('CONTRACT_ENGINE',
      `Deserialized ${this.contracts.size} contracts and ${this.paymentTracker.size} payment records`
    );
  }

  /**
   * Validate contract transaction before execution
   * @param {Object} transaction - Contract transaction
   * @returns {boolean} - Whether transaction is valid
   */
  validateContractTransaction(transaction) {
    try {
      // Basic validation
      if (transaction.contractAddress && !this.contracts.has(transaction.contractAddress)) {
        throw new Error('Contract does not exist');
      }

      // Method-specific validation would go here
      return true;
    } catch (error) {
      logger.error('CONTRACT_ENGINE', `Contract transaction validation failed: ${error.message}`);
      return false;
    }
  }
}

/**
 * TOKEN CONTRACT CLASS
 *
 * Unique Features:
 * - Multi-token support per contract (unlike ERC-20)
 * - Built-in permission system
 * - Atomic operations with rollback capability
 * - Native decimal handling
 */
class TokenContract {
  constructor(address, owner, initData) {
    this.address = address;
    this.type = 'TOKEN';
    this.owner = owner;
    this.createdAt = Date.now();

    // Token storage: tokenId -> token data
    this.tokens = new Map();

    // Balance storage: tokenId -> (address -> balance)
    this.balances = new Map();

    // Permission system: address -> permissions array
    this.permissions = new Map();

    // Set owner permissions
    this.permissions.set(owner, ['CREATE_TOKEN', 'MINT', 'BURN', 'MANAGE_PERMISSIONS']);

    // Initialize with provided data if any
    if (initData && initData.initialToken) {
      this._createInitialToken(initData.initialToken);
    }
  }

  /**
   * Create initial token during contract deployment
   * @param {Object} tokenData - Token creation data
   */
  _createInitialToken(tokenData) {
    const tokenId = tokenData.symbol || 'DEFAULT';
    this.tokens.set(tokenId, {
      id: tokenId,
      name: tokenData.name || 'Default Token',
      symbol: tokenData.symbol || 'DEFAULT',
      decimals: tokenData.decimals || 8,
      totalSupply: 0,
      maxSupply: tokenData.maxSupply ? toAtomicUnits(tokenData.maxSupply, tokenData.decimals) : null,
      createdAt: Date.now(),
      creator: this.owner
    });

    this.balances.set(tokenId, new Map());

    logger.info('TOKEN_CONTRACT', `Created initial token ${tokenId} in contract ${this.address}`);
  }

  /**
   * Execute contract method
   * @param {string} method - Method name
   * @param {Object} params - Method parameters
   * @param {string} caller - Address calling the method
   * @returns {Object} - Execution result
   */
  executeMethod(method, params, caller) {
    // Check if method exists
    const methodMap = {
      'createToken': this._createToken.bind(this),
      'mint': this._mint.bind(this),
      'burn': this._burn.bind(this),
      'transfer': this._transfer.bind(this),
      'grantPermission': this._grantPermission.bind(this),
      'revokePermission': this._revokePermission.bind(this)
    };

    if (!methodMap[method]) {
      throw new Error(`Method ${method} not supported`);
    }

    // Execute method
    return methodMap[method](params, caller);
  }

  /**
   * Create a new token
   * @param {Object} params - Token creation parameters
   * @param {string} caller - Address creating the token
   * @returns {Object} - Creation result
   */
  _createToken(params, caller) {
    // Check permission
    if (!this._hasPermission(caller, 'CREATE_TOKEN')) {
      throw new Error('Insufficient permissions to create token');
    }

    const { name, symbol, decimals = 8, maxSupply } = params;

    // Validate parameters
    if (!name || !symbol) {
      throw new Error('Token name and symbol are required');
    }

    if (this.tokens.has(symbol)) {
      throw new Error(`Token ${symbol} already exists`);
    }

    if (decimals < 0 || decimals > 18) {
      throw new Error('Decimals must be between 0 and 18');
    }

    // Create token
    const token = {
      id: symbol,
      name,
      symbol,
      decimals,
      totalSupply: 0,
      maxSupply: maxSupply ? toAtomicUnits(maxSupply, decimals) : null,
      createdAt: Date.now(),
      creator: caller
    };

    this.tokens.set(symbol, token);
    this.balances.set(symbol, new Map());

    logger.info('TOKEN_CONTRACT', `Created token ${symbol} (${name}) in contract ${this.address}`);

    return {
      tokenId: symbol,
      name,
      symbol,
      decimals,
      maxSupply: maxSupply || 'unlimited'
    };
  }

  /**
   * Mint tokens
   * @param {Object} params - Minting parameters
   * @param {string} caller - Address minting tokens
   * @returns {Object} - Minting result
   */
  _mint(params, caller) {
    // Check permission
    if (!this._hasPermission(caller, 'MINT')) {
      throw new Error('Insufficient permissions to mint tokens');
    }

    const { tokenId, to, amount } = params;

    // Validate parameters
    if (!tokenId || !to || !amount) {
      throw new Error('TokenId, recipient address, and amount are required');
    }

    const token = this.tokens.get(tokenId);
    if (!token) {
      throw new Error(`Token ${tokenId} does not exist`);
    }

    if (!InputValidator.validateCryptocurrencyAddress(to)) {
      throw new Error('Invalid recipient address');
    }

    const atomicAmount = toAtomicUnits(amount, token.decimals);
    if (atomicAmount <= 0) {
      throw new Error('Amount must be positive');
    }

    // Check max supply
    if (token.maxSupply && token.totalSupply + atomicAmount > token.maxSupply) {
      throw new Error('Minting would exceed maximum supply');
    }

    // Execute mint
    const balances = this.balances.get(tokenId);
    const currentBalance = balances.get(to) || 0;
    balances.set(to, currentBalance + atomicAmount);

    token.totalSupply += atomicAmount;

    logger.info('TOKEN_CONTRACT', `Minted ${amount} ${tokenId} to ${to} in contract ${this.address}`);

    return {
      tokenId,
      to,
      amount: fromAtomicUnits(atomicAmount, token.decimals),
      newBalance: fromAtomicUnits(balances.get(to), token.decimals),
      totalSupply: fromAtomicUnits(token.totalSupply, token.decimals)
    };
  }

  /**
   * Burn tokens
   * @param {Object} params - Burning parameters
   * @param {string} caller - Address burning tokens
   * @returns {Object} - Burning result
   */
  _burn(params, caller) {
    const { tokenId, from, amount } = params;

    // Validate parameters
    if (!tokenId || !from || !amount) {
      throw new Error('TokenId, address, and amount are required');
    }

    const token = this.tokens.get(tokenId);
    if (!token) {
      throw new Error(`Token ${tokenId} does not exist`);
    }

    // Check permission - either own tokens or have BURN permission
    if (from !== caller && !this._hasPermission(caller, 'BURN')) {
      throw new Error('Insufficient permissions to burn tokens');
    }

    const atomicAmount = toAtomicUnits(amount, token.decimals);
    if (atomicAmount <= 0) {
      throw new Error('Amount must be positive');
    }

    // Check balance
    const balances = this.balances.get(tokenId);
    const currentBalance = balances.get(from) || 0;
    if (currentBalance < atomicAmount) {
      throw new Error('Insufficient balance to burn');
    }

    // Execute burn
    balances.set(from, currentBalance - atomicAmount);
    token.totalSupply -= atomicAmount;

    logger.info('TOKEN_CONTRACT', `Burned ${amount} ${tokenId} from ${from} in contract ${this.address}`);

    return {
      tokenId,
      from,
      amount: fromAtomicUnits(atomicAmount, token.decimals),
      newBalance: fromAtomicUnits(balances.get(from), token.decimals),
      totalSupply: fromAtomicUnits(token.totalSupply, token.decimals)
    };
  }

  /**
   * Transfer tokens
   * @param {Object} params - Transfer parameters
   * @param {string} caller - Address initiating transfer
   * @returns {Object} - Transfer result
   */
  _transfer(params, caller) {
    const { tokenId, from, to, amount } = params;

    // Validate parameters
    if (!tokenId || !from || !to || !amount) {
      throw new Error('TokenId, from address, to address, and amount are required');
    }

    const token = this.tokens.get(tokenId);
    if (!token) {
      throw new Error(`Token ${tokenId} does not exist`);
    }

    // Check permission - can only transfer own tokens unless approved
    if (from !== caller) {
      throw new Error('Can only transfer your own tokens');
    }

    if (!InputValidator.validateCryptocurrencyAddress(to)) {
      throw new Error('Invalid recipient address');
    }

    const atomicAmount = toAtomicUnits(amount, token.decimals);
    if (atomicAmount <= 0) {
      throw new Error('Amount must be positive');
    }

    // Check balance
    const balances = this.balances.get(tokenId);
    const fromBalance = balances.get(from) || 0;
    if (fromBalance < atomicAmount) {
      throw new Error('Insufficient balance');
    }

    // Execute transfer
    const toBalance = balances.get(to) || 0;
    balances.set(from, fromBalance - atomicAmount);
    balances.set(to, toBalance + atomicAmount);

    logger.info('TOKEN_CONTRACT', `Transferred ${amount} ${tokenId} from ${from} to ${to} in contract ${this.address}`);

    return {
      tokenId,
      from,
      to,
      amount: fromAtomicUnits(atomicAmount, token.decimals),
      fromBalance: fromAtomicUnits(balances.get(from), token.decimals),
      toBalance: fromAtomicUnits(balances.get(to), token.decimals)
    };
  }

  /**
   * Grant permission to an address
   * @param {Object} params - Permission parameters
   * @param {string} caller - Address granting permission
   * @returns {Object} - Grant result
   */
  _grantPermission(params, caller) {
    // Only owner or addresses with MANAGE_PERMISSIONS can grant permissions
    if (!this._hasPermission(caller, 'MANAGE_PERMISSIONS')) {
      throw new Error('Insufficient permissions to grant permissions');
    }

    const { to, permission } = params;

    if (!InputValidator.validateCryptocurrencyAddress(to)) {
      throw new Error('Invalid address');
    }

    const validPermissions = ['CREATE_TOKEN', 'MINT', 'BURN', 'MANAGE_PERMISSIONS'];
    if (!validPermissions.includes(permission)) {
      throw new Error(`Invalid permission: ${permission}`);
    }

    // Get current permissions
    const permissions = this.permissions.get(to) || [];
    if (!permissions.includes(permission)) {
      permissions.push(permission);
      this.permissions.set(to, permissions);
    }

    logger.info('TOKEN_CONTRACT', `Granted ${permission} permission to ${to} in contract ${this.address}`);

    return {
      to,
      permission,
      allPermissions: permissions
    };
  }

  /**
   * Revoke permission from an address
   * @param {Object} params - Permission parameters
   * @param {string} caller - Address revoking permission
   * @returns {Object} - Revoke result
   */
  _revokePermission(params, caller) {
    // Only owner or addresses with MANAGE_PERMISSIONS can revoke permissions
    if (!this._hasPermission(caller, 'MANAGE_PERMISSIONS')) {
      throw new Error('Insufficient permissions to revoke permissions');
    }

    const { from, permission } = params;

    if (!InputValidator.validateCryptocurrencyAddress(from)) {
      throw new Error('Invalid address');
    }

    // Cannot revoke owner's permissions
    if (from === this.owner) {
      throw new Error('Cannot revoke owner permissions');
    }

    const permissions = this.permissions.get(from) || [];
    const index = permissions.indexOf(permission);
    if (index > -1) {
      permissions.splice(index, 1);
      this.permissions.set(from, permissions);
    }

    logger.info('TOKEN_CONTRACT', `Revoked ${permission} permission from ${from} in contract ${this.address}`);

    return {
      from,
      permission,
      remainingPermissions: permissions
    };
  }

  /**
   * Check if address has specific permission
   * @param {string} address - Address to check
   * @param {string} permission - Permission to check
   * @returns {boolean} - Whether address has permission
   */
  _hasPermission(address, permission) {
    const permissions = this.permissions.get(address) || [];
    return permissions.includes(permission);
  }

  /**
   * Get token balance for address
   * @param {string} tokenId - Token ID
   * @param {string} address - Address to check balance for
   * @returns {string} - Balance in human-readable format
   */
  getBalance(tokenId, address) {
    const token = this.tokens.get(tokenId);
    if (!token) {
      throw new Error(`Token ${tokenId} does not exist`);
    }

    const balances = this.balances.get(tokenId);
    const atomicBalance = balances.get(address) || 0;
    return fromAtomicUnits(atomicBalance, token.decimals);
  }

  /**
   * Get token information
   * @param {string} tokenId - Token ID
   * @returns {Object} - Token information
   */
  getToken(tokenId) {
    const token = this.tokens.get(tokenId);
    if (!token) {
      throw new Error(`Token ${tokenId} does not exist`);
    }

    return {
      id: token.id,
      name: token.name,
      symbol: token.symbol,
      decimals: token.decimals,
      totalSupply: fromAtomicUnits(token.totalSupply, token.decimals),
      maxSupply: token.maxSupply ? fromAtomicUnits(token.maxSupply, token.decimals) : 'unlimited',
      createdAt: token.createdAt,
      creator: token.creator
    };
  }

  /**
   * Get public contract state
   * @returns {Object} - Public contract state
   */
  getPublicState() {
    const tokens = {};
    for (const [tokenId, token] of this.tokens.entries()) {
      tokens[tokenId] = this.getToken(tokenId);
    }

    return {
      address: this.address,
      type: this.type,
      owner: this.owner,
      createdAt: this.createdAt,
      tokens,
      tokenCount: this.tokens.size
    };
  }

  /**
   * Serialize contract for storage
   * @returns {Object} - Serialized contract data
   */
  serialize() {
    const tokens = {};
    for (const [tokenId, token] of this.tokens.entries()) {
      tokens[tokenId] = { ...token };
    }

    const balances = {};
    for (const [tokenId, balanceMap] of this.balances.entries()) {
      balances[tokenId] = Object.fromEntries(balanceMap);
    }

    const permissions = Object.fromEntries(this.permissions);

    return {
      address: this.address,
      type: this.type,
      owner: this.owner,
      createdAt: this.createdAt,
      tokens,
      balances,
      permissions
    };
  }

  /**
   * Deserialize contract from storage
   * @param {Object} data - Serialized contract data
   * @returns {TokenContract} - Deserialized contract instance
   */
  static deserialize(data) {
    const contract = new TokenContract(data.address, data.owner, {});
    contract.type = data.type;
    contract.createdAt = data.createdAt;

    // Restore tokens
    for (const [tokenId, token] of Object.entries(data.tokens || {})) {
      contract.tokens.set(tokenId, token);
    }

    // Restore balances
    for (const [tokenId, balanceObj] of Object.entries(data.balances || {})) {
      contract.balances.set(tokenId, new Map(Object.entries(balanceObj)));
    }

    // Restore permissions
    for (const [address, permissionList] of Object.entries(data.permissions || {})) {
      contract.permissions.set(address, permissionList);
    }

    return contract;
  }
}

module.exports = { ContractEngine, TokenContract };