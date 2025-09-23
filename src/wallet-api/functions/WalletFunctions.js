/**
 * Comprehensive Wallet Functions for Pastella Wallet API
 * Handles all wallet operations for exchanges and third-party integration
 * Uses daemon API for all blockchain operations - NO direct blockchain.json access
 */

const fs = require('fs');
const path = require('path');

const axios = require('axios');

const Wallet = require('../../models/Wallet');
const { fromAtomicUnits, toAtomicUnits } = require('../../utils/atomicUnits');
const { SecurityUtils } = require('../../utils/crypto');
const logger = require('../../utils/logger');

/**
 *
 */
class WalletFunctions {
  /**
   *
   * @param config
   */
  constructor(config = {}) {
    this.wallets = new Map(); // walletName -> Wallet instance
    this.walletsDir = path.join(process.cwd(), 'wallets');

    // Daemon API configuration
    this.daemonConfig = {
      host: config.daemonHost || 'localhost',
      port: config.daemonPort || 22000,
      apiKey: config.daemonApiKey || null,
      timeout: config.daemonTimeout || 30000,
    };

    this.daemonBaseURL = `http://${this.daemonConfig.host}:${this.daemonConfig.port}`;

    // Setup axios instance for daemon communication
    this.daemonAPI = axios.create({
      baseURL: this.daemonBaseURL,
      timeout: this.daemonConfig.timeout,
      headers: {
        'Content-Type': 'application/json',
        ...(this.daemonConfig.apiKey && { 'X-API-Key': this.daemonConfig.apiKey }),
      },
    });

    // Ensure wallets directory exists
    if (!fs.existsSync(this.walletsDir)) {
      fs.mkdirSync(this.walletsDir, { recursive: true });
    }

    // Sync state tracking
    this.syncState = {
      isRunning: false,
      currentBlock: 0,
      targetBlock: 0,
      lastSyncedBlock: 0,
      syncInterval: null,
      isSynced: false,
    };

    // Auto-save state tracking
    this.autoSaveInterval = null;

    // UTXO Management System
    this.utxoCache = new Map(); // address -> { utxos: Map(txId:index -> utxoData), lastSync: timestamp }
    this.pendingTransactions = new Map(); // txId -> { utxos: [utxo], timestamp, confirmed: false }
    this.utxoSyncInterval = null;

    // Load global sync state from file
    this.loadGlobalSyncState();

    logger.info('WALLET_API', `Wallet API configured to use daemon at: ${this.daemonBaseURL}`);

    // Start auto-save functionality
    this.startAutoSave();

    // Start blockchain sync after a short delay to allow wallet loading
    setTimeout(() => {
      this.startBlockchainSync();
    }, 3000);

    // Start periodic UTXO sync (every 2 minutes)
    this.startUTXOSync();
  }

  /**
   * Handle daemon API errors with user-friendly messages
   * @param {Error} error - The error from daemon API call
   * @param {string} operation - Description of what operation failed
   * @returns {Error} - User-friendly error
   */
  handleDaemonError(error, operation) {
    if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND' || error.message.includes('connect ECONNREFUSED')) {
      return new Error(
        `Cannot connect to Pastella daemon at ${this.daemonBaseURL}. Please ensure the daemon is running and accessible. Operation: ${operation}`
      );
    }

    if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
      return new Error(
        `Lost connection to Pastella daemon during ${operation}. Please check daemon status and try again.`
      );
    }

    if (error.response?.status === 404) {
      return new Error(
        `Daemon endpoint not found for ${operation}. Please ensure you're using a compatible daemon version.`
      );
    }

    if (error.response?.status >= 500) {
      return new Error(`Daemon server error during ${operation}: ${error.response?.data?.error || error.message}`);
    }

    // Return original error if it's not a daemon connectivity issue
    return error;
  }

  /**
   * Check if daemon is accessible
   */
  async checkDaemonConnection() {
    try {
      const response = await this.daemonAPI.get('/api/info');
      return response.status === 200;
    } catch (error) {
      logger.error('WALLET_API', `Daemon connection failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Create a new wallet
   * @param walletName
   * @param password
   * @param seed
   */
  async createWallet(walletName, password, seed = null) {
    try {
      if (this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is already loaded`);
      }

      const walletPath = path.join(this.walletsDir, `${walletName}.wallet`);
      if (fs.existsSync(walletPath)) {
        throw new Error(`Wallet file '${walletName}.wallet' already exists`);
      }

      const wallet = new Wallet();

      if (seed) {
        await wallet.importFromSeed(seed, password);
      } else {
        await wallet.generateKeyPair(password);
      }

      // Save wallet to file
      await wallet.saveToFile(walletPath, password);

      // Load into memory
      this.wallets.set(walletName, wallet);

      const address = wallet.getAddress();
      logger.info('WALLET_API', `Created new wallet: ${walletName} with address: ${address}`);

      return {
        success: true,
        walletName,
        address,
        message: 'Wallet created successfully',
      };
    } catch (error) {
      logger.error('WALLET_API', `Error creating wallet ${walletName}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Load an existing wallet
   * @param walletName
   * @param password
   */
  async loadWallet(walletName, password) {
    try {
      if (this.wallets.has(walletName)) {
        const wallet = this.wallets.get(walletName);
        return {
          success: true,
          walletName,
          address: wallet.getAddress(),
          message: 'Wallet already loaded',
        };
      }

      const walletPath = path.join(this.walletsDir, `${walletName}.wallet`);
      if (!fs.existsSync(walletPath)) {
        throw new Error(`Wallet file '${walletName}.wallet' not found`);
      }

      const wallet = new Wallet();
      await wallet.loadFromFile(walletPath, password);

      this.wallets.set(walletName, wallet);

      // Load wallet state (transaction history, sync progress)
      await this.loadWalletState(walletName);

      const address = wallet.getAddress();
      logger.info('WALLET_API', `Loaded wallet: ${walletName} with address: ${address}`);

      return {
        success: true,
        walletName,
        address,
        message: 'Wallet loaded successfully',
      };
    } catch (error) {
      logger.error('WALLET_API', `Error loading wallet ${walletName}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Unload a wallet from memory
   * @param walletName
   */
  async unloadWallet(walletName) {
    try {
      if (!this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is not loaded`);
      }

      const wallet = this.wallets.get(walletName);
      wallet.unloadWallet();
      this.wallets.delete(walletName);

      logger.info('WALLET_API', `Unloaded wallet: ${walletName}`);

      return {
        success: true,
        walletName,
        message: 'Wallet unloaded successfully',
      };
    } catch (error) {
      logger.error('WALLET_API', `Error unloading wallet ${walletName}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Backup a wallet
   * @param walletName
   * @param backupPath
   */
  async backupWallet(walletName, backupPath = null) {
    try {
      if (!this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is not loaded`);
      }

      const sourceWalletPath = path.join(this.walletsDir, `${walletName}.wallet`);
      if (!fs.existsSync(sourceWalletPath)) {
        throw new Error(`Source wallet file not found: ${sourceWalletPath}`);
      }

      // Generate backup path if not provided
      if (!backupPath) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        backupPath = path.join(this.walletsDir, 'backups', `${walletName}-backup-${timestamp}.wallet`);
      }

      // Ensure backup directory exists
      const backupDir = path.dirname(backupPath);
      if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir, { recursive: true });
      }

      // Copy wallet file
      fs.copyFileSync(sourceWalletPath, backupPath);

      logger.info('WALLET_API', `Backed up wallet ${walletName} to: ${backupPath}`);

      return {
        success: true,
        walletName,
        backupPath,
        message: 'Wallet backed up successfully',
      };
    } catch (error) {
      logger.error('WALLET_API', `Error backing up wallet ${walletName}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get wallet information
   * @param walletName
   */
  async getWalletInfo(walletName) {
    try {
      if (!this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is not loaded`);
      }

      const wallet = this.wallets.get(walletName);
      const address = wallet.getAddress();

      // Get balance from daemon API
      const balanceResponse = await this.daemonAPI.get(`/api/wallet/balance/${address}`);
      const balance = balanceResponse.data.balance || 0;

      // Get transaction count from daemon API
      const transactionResponse = await this.daemonAPI.get(`/api/wallet/transactions/${address}`);
      const transactionCount = transactionResponse.data.transactions?.length || 0;

      return {
        success: true,
        walletName,
        address,
        balance,
        balanceAtomic: toAtomicUnits(balance),
        transactionCount,
        isLoaded: wallet.isLoaded(),
        lastUpdated: Date.now(),
      };
    } catch (error) {
      logger.error('WALLET_API', `Error getting wallet info for ${walletName}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get wallet balance
   * @param walletName
   */
  async getBalance(walletName) {
    try {
      if (!this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is not loaded`);
      }

      const wallet = this.wallets.get(walletName);
      const address = wallet.getAddress();

      // Get balance from daemon API (returns atomic units)
      const response = await this.daemonAPI.get(`/api/wallet/balance/${address}`);
      const balanceAtomic = response.data.balance || 0;

      return {
        success: true,
        walletName,
        address,
        balance: fromAtomicUnits(balanceAtomic),
        balanceAtomic,
      };
    } catch (error) {
      const friendlyError = this.handleDaemonError(error, `getting balance for wallet '${walletName}'`);
      logger.error('WALLET_API', `Error getting balance for ${walletName}: ${friendlyError.message}`);
      throw friendlyError;
    }
  }

  /**
   * Get all wallet balances
   */
  async getBalances() {
    try {
      const balances = [];

      for (const [walletName, wallet] of this.wallets) {
        try {
          const address = wallet.getAddress();

          // Get balance from daemon API (returns atomic units)
          const response = await this.daemonAPI.get(`/api/wallet/balance/${address}`);
          const balanceAtomic = response.data.balance || 0;

          balances.push({
            walletName,
            address,
            balance: fromAtomicUnits(balanceAtomic),
            balanceAtomic,
          });
        } catch (error) {
          logger.warn('WALLET_API', `Error getting balance for wallet ${walletName}: ${error.message}`);
          balances.push({
            walletName,
            address: wallet.getAddress(),
            balance: 0,
            balanceAtomic: 0,
            error: error.message,
          });
        }
      }

      return {
        success: true,
        wallets: balances,
        totalWallets: balances.length,
      };
    } catch (error) {
      const friendlyError = this.handleDaemonError(error, 'getting wallet balances');
      logger.error('WALLET_API', `Error getting wallet balances: ${friendlyError.message}`);
      throw friendlyError;
    }
  }

  /**
   * Get new address (for wallets, this returns the wallet's address)
   * @param walletName
   */
  async getNewAddress(walletName) {
    try {
      if (!this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is not loaded`);
      }

      const wallet = this.wallets.get(walletName);
      const address = wallet.getAddress();

      return {
        success: true,
        walletName,
        address,
        message: 'Wallet address retrieved',
      };
    } catch (error) {
      logger.error('WALLET_API', `Error getting new address for ${walletName}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get transaction by ID
   * @param txId
   */
  async getTransaction(txId) {
    try {
      // First, check if this transaction exists in any of our wallets
      let foundWallet = null;

      for (const [walletName, wallet] of this.wallets) {
        const address = wallet.getAddress();

        try {
          // Get all transactions for this wallet from daemon API
          const response = await this.daemonAPI.get(`/api/wallet/transactions/${address}`);
          const allTransactions = response.data.transactions || [];

          // Check if transaction exists in this wallet
          if (allTransactions.find(tx => tx.id === txId)) {
            foundWallet = { name: walletName, address };
            break;
          }
        } catch (daemonError) {
          logger.warn(
            'WALLET_API',
            `Error checking wallet ${walletName} for transaction ${txId}: ${daemonError.message}`
          );
        }
      }

      if (!foundWallet) {
        throw new Error(`Transaction not found in any loaded wallet: ${txId}`);
      }

      // Get full transaction details from daemon's blockchain transaction endpoint
      // Also get block info from the wallet transaction list
      let walletTransaction = null;
      try {
        const walletTxResponse = await this.daemonAPI.get(`/api/wallet/transactions/${foundWallet.address}`);
        const walletTransactions = walletTxResponse.data.transactions || [];
        walletTransaction = walletTransactions.find(tx => tx.id === txId);
      } catch (error) {
        logger.warn('WALLET_API', `Could not get wallet transaction info: ${error.message}`);
      }

      // Get full transaction details from blockchain
      try {
        const txResponse = await this.daemonAPI.get(`/api/blockchain/transactions/${txId}`);
        const fullTransaction = txResponse.data;

        if (!fullTransaction) {
          throw new Error(`Full transaction details not found: ${txId}`);
        }

        // Calculate transaction direction and wallet info based on inputs/outputs
        const walletAddress = foundWallet.address;
        let transactionType = 'unknown';
        let walletFrom = 'unknown';
        let walletTo = 'unknown';
        let amount = 0;

        // Check if it's a coinbase transaction
        const isCoinbase =
          fullTransaction.inputs &&
          fullTransaction.inputs.length === 1 &&
          fullTransaction.inputs[0].previousTransactionId === '0'.repeat(64);

        if (isCoinbase) {
          transactionType = 'coinbase';
          walletFrom = 'coinbase-reward';
          walletTo = foundWallet.name;
          // For coinbase, sum all outputs to our address
          amount = fullTransaction.outputs
            .filter(output => output.address === walletAddress)
            .reduce((sum, output) => sum + (output.amount || 0), 0);
        } else {
          // Regular transaction - analyze inputs and outputs
          const inputsFromWallet = fullTransaction.inputs.filter(input => input.address === walletAddress);
          const outputsToWallet = fullTransaction.outputs.filter(output => output.address === walletAddress);
          const outputsToOthers = fullTransaction.outputs.filter(output => output.address !== walletAddress);

          const totalInputFromWallet = inputsFromWallet.reduce((sum, input) => sum + (input.amount || 0), 0);
          const totalOutputToWallet = outputsToWallet.reduce((sum, output) => sum + (output.amount || 0), 0);
          const totalOutputToOthers = outputsToOthers.reduce((sum, output) => sum + (output.amount || 0), 0);

          if (inputsFromWallet.length > 0 && outputsToOthers.length > 0) {
            if (outputsToWallet.length > 0) {
              // Self transfer with change
              transactionType = 'self-transfer';
              walletFrom = foundWallet.name;
              walletTo = foundWallet.name;
              amount = totalOutputToOthers; // Amount actually sent out
            } else {
              // Outgoing transaction
              transactionType = 'outgoing';
              walletFrom = foundWallet.name;
              walletTo = outputsToOthers.length > 0 ? outputsToOthers[0].address : 'external-wallet';
              amount = totalOutputToOthers;
            }
          } else if (outputsToWallet.length > 0 && inputsFromWallet.length === 0) {
            // Incoming transaction - get sender address from previous transaction
            transactionType = 'incoming';
            walletTo = foundWallet.name;
            amount = totalOutputToWallet;

            // Try to get sender address by looking up the previous transaction
            if (fullTransaction.inputs && fullTransaction.inputs.length > 0) {
              try {
                const firstInput = fullTransaction.inputs[0];
                const prevTxResponse = await this.daemonAPI.get(`/api/blockchain/transactions/${firstInput.txId}`);
                const prevTransaction = prevTxResponse.data;

                if (prevTransaction && prevTransaction.outputs && prevTransaction.outputs[firstInput.outputIndex]) {
                  const senderAddress = prevTransaction.outputs[firstInput.outputIndex].address;
                  walletFrom = senderAddress;
                } else {
                  walletFrom = 'external-wallet';
                }
              } catch (prevTxError) {
                logger.warn('WALLET_API', `Could not get sender address: ${prevTxError.message}`);
                walletFrom = 'external-wallet';
              }
            } else {
              walletFrom = 'external-wallet';
            }
          }
        }

        return {
          success: true,
          transaction: {
            id: fullTransaction.id,
            type: isCoinbase ? 'coinbase' : 'transaction',

            // Transaction direction and wallet info
            direction:
              transactionType === 'incoming'
                ? 'received'
                : transactionType === 'outgoing' ? 'sent' :
                transactionType === 'self-transfer' ? 'self' :
                  transactionType === 'coinbase' ? 'received' : 'unknown',
            transactionType,
            walletFrom,
            walletTo,

            inputs: fullTransaction.inputs || [],
            outputs: fullTransaction.outputs || [],

            // Use calculated amounts
            amount: fromAtomicUnits(amount),
            amountAtomic: amount,
            fee: fromAtomicUnits(fullTransaction.fee || 0),
            feeAtomic: fullTransaction.fee || 0,
            timestamp: fullTransaction.timestamp,
            blockHeight: walletTransaction?.blockHeight || fullTransaction.blockHeight || null,
            blockHash: walletTransaction?.blockHash || fullTransaction.blockHash || null,
            confirmations: await this.calculateConfirmations(
              walletTransaction?.blockHeight || fullTransaction.blockHeight
            ),
            walletName: foundWallet.name,
          },
        };

      } catch (txError) {
        logger.error('WALLET_API', `Error getting full transaction details for ${txId}: ${txError.message}`);
        throw new Error(`Could not retrieve full transaction details: ${txError.message}`);
      }
    } catch (error) {
      logger.error('WALLET_API', `Error getting transaction ${txId}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Calculate transaction amount relative to wallet
   * @param transaction
   * @param walletAddress
   */
  calculateTransactionAmount(transaction, walletAddress) {
    let totalReceived = 0;
    let totalSent = 0;

    // Calculate received amount (outputs to this wallet)
    if (transaction.outputs) {
      transaction.outputs.forEach(output => {
        if (output.address === walletAddress) {
          totalReceived += output.amount || 0;
        }
      });
    }

    // Calculate sent amount (inputs from this wallet)
    if (transaction.inputs) {
      transaction.inputs.forEach(input => {
        if (input.address === walletAddress) {
          totalSent += input.amount || 0;
        }
      });
    }

    // Return net amount (received - sent)
    // Positive = received, Negative = sent
    return totalReceived - totalSent;
  }

  /**
   * Determine transaction direction relative to wallet
   * @param transaction
   * @param walletAddress
   */
  getTransactionDirection(transaction, walletAddress) {
    // Check if wallet address is in outputs (received)
    const isReceived = transaction.outputs?.some(output => output.address === walletAddress);

    // Check if wallet address is in inputs (sent)
    const isSent = transaction.inputs?.some(input => input.address === walletAddress);

    if (isReceived && isSent) return 'self'; // Self-transfer
    if (isReceived) return 'received';
    if (isSent) return 'sent';
    return 'unknown';
  }

  /**
   * Get transaction type (incoming/outgoing/self)
   * @param transaction
   * @param walletAddress
   */
  getTransactionType(transaction, walletAddress) {
    if (transaction.isCoinbase) return 'coinbase';

    const direction = this.getTransactionDirection(transaction, walletAddress);

    switch (direction) {
      case 'received':
        return 'incoming';
      case 'sent':
        return 'outgoing';
      case 'self':
        return 'self-transfer';
      default:
        return 'unknown';
    }
  }

  /**
   * Determine wallet FROM information
   * @param transaction
   * @param walletAddress
   * @param currentWalletName
   */
  getTransactionFromWallet(transaction, walletAddress, currentWalletName) {
    if (transaction.isCoinbase) {
      return 'coinbase-reward'; // Coinbase has no "from" wallet
    }
    
    const direction = this.getTransactionDirection(transaction, walletAddress);
    
    if (direction === 'sent' || direction === 'self') {
      return currentWalletName; // This wallet sent the transaction
    } if (direction === 'received') {
      // For received transactions, try to identify sender
      const senderAddresses = transaction.inputs?.map(input => input.address) || [];
      if (senderAddresses.length > 0) {
        return senderAddresses[0]; // Show first sender address
      }
      return 'external-wallet';
    }
    
    return 'unknown';
  }

  /**
   * Determine wallet TO information
   * @param transaction
   * @param walletAddress
   * @param currentWalletName
   */
  getTransactionToWallet(transaction, walletAddress, currentWalletName) {
    if (transaction.isCoinbase) {
      return currentWalletName; // Coinbase rewards come to this wallet
    }
    
    const direction = this.getTransactionDirection(transaction, walletAddress);
    
    if (direction === 'received' || direction === 'self') {
      return currentWalletName; // This wallet received the transaction
    } if (direction === 'sent') {
      // For sent transactions, try to identify recipient
      const recipientAddresses = transaction.outputs?.map(output => output.address) || [];
      if (recipientAddresses.length > 0) {
        return recipientAddresses[0]; // Show first recipient address
      }
      return 'external-wallet';
    }
    
    return 'unknown';
  }

  /**
   * Get wallet transactions
   * @param walletName
   * @param limit
   * @param offset
   */
  async getTransactions(walletName, limit = 50, offset = 0) {
    try {
      if (!this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is not loaded`);
      }

      const wallet = this.wallets.get(walletName);
      const address = wallet.getAddress();

      // Use synced transaction history if available, otherwise fall back to daemon API
      let allTransactions = wallet.transactionHistory || [];

      if (allTransactions.length === 0) {
        // Fallback to daemon API if no synced history
        const response = await this.daemonAPI.get(`/api/wallet/transactions/${address}`);
        allTransactions = response.data.transactions || [];
      }

      // Sort by timestamp (newest first)
      allTransactions.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

      // Apply pagination
      const paginatedTransactions = allTransactions.slice(offset, offset + limit);

      // Get full transaction details for each transaction
      const transactions = [];

      for (const tx of paginatedTransactions) {
        try {
          // Get full transaction details from daemon
          const txResponse = await this.daemonAPI.get(`/api/blockchain/transactions/${tx.id}`);
          const fullTransaction = txResponse.data;

          if (fullTransaction) {
            // Calculate transaction direction and amounts
            const isCoinbase =
              fullTransaction.inputs &&
              fullTransaction.inputs.length === 1 &&
              fullTransaction.inputs[0].previousTransactionId === '0'.repeat(64);

            let transactionType = 'unknown';
            let walletFrom = 'unknown';
            let walletTo = 'unknown';
            let amount = 0;
            let direction = 'unknown';

            if (isCoinbase) {
              transactionType = 'coinbase';
              direction = 'received';
              walletFrom = 'coinbase-reward';
              walletTo = walletName;
              amount = fullTransaction.outputs
                .filter(output => output.address === address)
                .reduce((sum, output) => sum + (output.amount || 0), 0);
            } else {
              // Analyze inputs and outputs
              // For inputs, we need to check if this wallet spent UTXOs (inputs reference previous transactions)
              // For outputs, check what addresses received funds

              const outputsToWallet = fullTransaction.outputs.filter(output => output.address === address);
              const outputsToOthers = fullTransaction.outputs.filter(output => output.address !== address);

              const totalOutputToWallet = outputsToWallet.reduce((sum, output) => sum + (output.amount || 0), 0);
              const totalOutputToOthers = outputsToOthers.reduce((sum, output) => sum + (output.amount || 0), 0);

              // Check if this wallet's address appears in any previous transactions (inputs)
              // We need to check if any input belongs to this wallet by looking at previous transaction outputs
              let walletOwnsInputs = false;

              for (const input of fullTransaction.inputs) {
                try {
                  // Get the previous transaction to see who owned the UTXO being spent
                  const prevTxResponse = await this.daemonAPI.get(`/api/blockchain/transactions/${input.txId}`);
                  const prevTx = prevTxResponse.data;

                  if (prevTx && prevTx.outputs && prevTx.outputs[input.outputIndex]) {
                    const inputOwnerAddress = prevTx.outputs[input.outputIndex].address;
                    if (inputOwnerAddress === address) {
                      walletOwnsInputs = true;
                      break; // Found at least one input owned by this wallet
                    }
                  }
                } catch (error) {
                  // Continue checking other inputs if one fails
                }
              }

              if (walletOwnsInputs && outputsToOthers.length > 0) {
                // This wallet spent money (owns inputs) and sent to others
                transactionType = 'outgoing';
                direction = 'sent';
                walletFrom = walletName;
                walletTo = outputsToOthers.length > 0 ? outputsToOthers[0].address : 'external-wallet';
                amount = totalOutputToOthers; // Amount sent to external addresses
              } else if (outputsToWallet.length > 0 && !walletOwnsInputs) {
                // Incoming transaction - get sender from previous transaction
                transactionType = 'incoming';
                direction = 'received';
                walletTo = walletName;
                amount = totalOutputToWallet;

                // Try to get sender address
                if (fullTransaction.inputs && fullTransaction.inputs.length > 0) {
                  try {
                    const firstInput = fullTransaction.inputs[0];
                    const prevTxResponse = await this.daemonAPI.get(`/api/blockchain/transactions/${firstInput.txId}`);
                    const prevTransaction = prevTxResponse.data;

                    if (prevTransaction && prevTransaction.outputs && prevTransaction.outputs[firstInput.outputIndex]) {
                      walletFrom = prevTransaction.outputs[firstInput.outputIndex].address;
                    } else {
                      walletFrom = 'external-wallet';
                    }
                  } catch (prevTxError) {
                    walletFrom = 'external-wallet';
                  }
                } else {
                  walletFrom = 'external-wallet';
                }
              }
            }

            transactions.push({
              id: tx.id,
              type: isCoinbase ? 'coinbase' : 'transaction',
              amount: fromAtomicUnits(amount),
              amountAtomic: amount,
              direction,
              transactionType,
              walletFrom,
              walletTo,
              fee: fromAtomicUnits(fullTransaction.fee || 0),
              feeAtomic: fullTransaction.fee || 0,
              timestamp: fullTransaction.timestamp || tx.timestamp,
              blockHeight: tx.blockHeight || null,
              blockHash: tx.blockHash || null,
              confirmations: await this.calculateConfirmations(tx.blockHeight),
            });
          }
        } catch (txError) {
          logger.warn('WALLET_API', `Could not get full details for transaction ${tx.id}: ${txError.message}`);
          // Fallback to basic transaction info
          transactions.push({
            id: tx.id,
            type: tx.type || 'transaction',
            amount: fromAtomicUnits(Math.abs(tx.amount || 0)),
            amountAtomic: Math.abs(tx.amount || 0),
            direction: tx.direction || 'unknown',
            transactionType: 'unknown',
            walletFrom: 'unknown',
            walletTo: 'unknown',
            fee: 0,
            feeAtomic: 0,
            timestamp: tx.timestamp,
            blockHeight: tx.blockHeight || null,
            blockHash: tx.blockHash || null,
            confirmations: await this.calculateConfirmations(tx.blockHeight),
          });
        }
      }

      return {
        success: true,
        walletName,
        transactions,
        pagination: {
          total: allTransactions.length,
          limit,
          offset,
          hasMore: offset + limit < allTransactions.length,
        },
      };
    } catch (error) {
      logger.error('WALLET_API', `Error getting transactions for ${walletName}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Send transaction
   * @param walletName
   * @param toAddress
   * @param amount - Amount in ATOMIC UNITS (e.g., 100000000 for 1 PAS)
   * @param fee - Fee in ATOMIC UNITS (optional)
   * @param tag
   * @param paymentId - Optional payment ID (64 hex chars)
   */
  async sendTransaction(walletName, toAddress, amount, fee = null, tag = null, paymentId = null) {
    try {
      if (!this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is not loaded`);
      }

      const wallet = this.wallets.get(walletName);
      const fromAddress = wallet.getAddress();

      // Amount and fee are already in atomic units - no conversion needed
      const atomicAmount = parseInt(amount);

      // Use default fee if not provided (100000 atomic units = 0.001 PAS)
      const atomicFee = fee ? parseInt(fee) : 100000;

      console.log(`🚀 WALLET_API: Starting transaction from ${walletName} (${fromAddress})`);
      console.log(`   Amount: ${atomicAmount} atomic units (${fromAtomicUnits(atomicAmount)} PAS)`);
      console.log(`   Fee: ${atomicFee} atomic units (${fromAtomicUnits(atomicFee)} PAS)`);

      // Get available UTXOs using UTXO management system
      console.log(`🔍 WALLET_API: Getting available UTXOs for address ${fromAddress}`);
      const availableUTXOs = await this.getAvailableUTXOs(fromAddress);

      console.log(`📊 WALLET_API: Found ${availableUTXOs.length} available UTXOs`);
      if (availableUTXOs.length === 0) {
        throw new Error('No unspent outputs available for this address');
      }

      // Validate UTXOs with daemon before spending (real-time check)
      console.log(`✅ WALLET_API: Validating ${availableUTXOs.length} UTXOs with daemon`);
      const validUTXOs = await this.validateUTXOsBeforeSpending(availableUTXOs);

      console.log(`🎯 WALLET_API: Validation result: ${validUTXOs.length}/${availableUTXOs.length} UTXOs are valid`);
      if (validUTXOs.length === 0) {
        throw new Error('No valid UTXOs available - all UTXOs may have been spent');
      }

      // Update wallet's internal state with validated UTXOs
      const totalBalance = validUTXOs.reduce((sum, utxo) => sum + utxo.amount, 0);
      wallet.balance = totalBalance;
      wallet.utxos = validUTXOs;

      // Debug balance calculation
      console.log(`💰 WALLET_API: Balance calculation for ${walletName}:`);
      console.log(`   Total valid UTXOs: ${validUTXOs.length}`);
      console.log(`   Total balance: ${totalBalance} atomic units (${fromAtomicUnits(totalBalance)} PAS)`);
      console.log(`   Amount needed: ${atomicAmount} atomic units (${fromAtomicUnits(atomicAmount)} PAS)`);
      console.log(`   Fee needed: ${atomicFee} atomic units (${fromAtomicUnits(atomicFee)} PAS)`);
      console.log(`   Total needed: ${atomicAmount + atomicFee} atomic units (${fromAtomicUnits(atomicAmount + atomicFee)} PAS)`);
      console.log(`   Sufficient? ${totalBalance >= (atomicAmount + atomicFee) ? '✅ YES' : '❌ NO'}`);

      // Validate balance before creating transaction
      if (totalBalance < atomicAmount + atomicFee) {
        throw new Error(`Insufficient balance: have ${fromAtomicUnits(totalBalance)} PAS, need ${fromAtomicUnits(atomicAmount + atomicFee)} PAS`);
      }

      // Create transaction using wallet method
      const transaction = wallet.createTransaction(toAddress, atomicAmount, atomicFee, null, undefined, paymentId);

      // Mark UTXOs as pending BEFORE submitting the transaction
      const usedUTXOs = transaction.inputs.map(input => {
        const utxo = validUTXOs.find(u => u.transactionId === input.txId && u.outputIndex === input.outputIndex);
        return { ...utxo, address: fromAddress };
      }).filter(Boolean);

      this.markUTXOsAsPending(usedUTXOs, transaction.id);

      // Submit transaction to daemon with error handling and auto-restructuring
      const submissionResult = await this.submitTransactionToDaemon(
        transaction,
        walletName,
        fromAddress,
        toAddress,
        atomicAmount,
        atomicFee,
        paymentId,
        usedUTXOs
      );

      if (!submissionResult.success) {
        // If submission failed, the method already handled cleanup
        throw new Error(submissionResult.error);
      }

      const result = submissionResult.data;

      logger.info(
        'WALLET_API',
        `Transaction sent from ${walletName} to ${toAddress}: ${fromAtomicUnits(atomicAmount)} PAS (TX: ${result.transactionId || 'pending'})`
      );

      return {
        success: true,
        transactionId: result.transactionId || `pending_${Date.now()}`,
        fromWallet: walletName,
        fromAddress,
        toAddress,
        // Both atomic and human-readable amounts
        amount: fromAtomicUnits(atomicAmount),
        amountAtomic: atomicAmount,
        fee: fromAtomicUnits(atomicFee),
        feeAtomic: atomicFee,
        paymentId,
        tag,
        timestamp: Date.now(),
        status: result.status || 'submitted',
      };
    } catch (error) {
      const friendlyError = this.handleDaemonError(error, `sending transaction from wallet '${walletName}'`);
      logger.error('WALLET_API', `Error sending transaction from ${walletName}: ${friendlyError.message}`);
      throw friendlyError;
    }
  }

  /**
   * Send multi-output transaction (send to multiple addresses in single transaction)
   * @param walletName
   * @param outputs - Array of {address, amount} objects
   * @param fee - Fee in ATOMIC UNITS (optional)
   * @param tag
   * @param paymentId - Optional payment ID (64 hex chars)
   */
  async sendMultiTransaction(walletName, outputs, fee = null, tag = null, paymentId = null) {
    try {
      if (!this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is not loaded`);
      }

      // Validate outputs array
      if (!Array.isArray(outputs) || outputs.length === 0) {
        throw new Error('outputs must be a non-empty array of {address, amount} objects');
      }

      // Validate each output and convert amounts to atomic units
      const atomicOutputs = [];
      let totalAtomicAmount = 0;

      for (const output of outputs) {
        if (!output.address || !output.amount) {
          throw new Error('Each output must have address and amount properties');
        }

        const atomicAmount = typeof output.amount === 'string' ? toAtomicUnits(output.amount) : parseInt(output.amount);
        if (isNaN(atomicAmount) || atomicAmount <= 0) {
          throw new Error(`Invalid amount for address ${output.address}: must be positive number`);
        }

        atomicOutputs.push({
          address: output.address,
          amount: atomicAmount,
        });
        totalAtomicAmount += atomicAmount;
      }

      const wallet = this.wallets.get(walletName);
      const fromAddress = wallet.getAddress();

      // Use default fee if not provided (100000 atomic units = 0.001 PAS)
      const atomicFee = fee ? parseInt(fee) : 100000;

      // Get available UTXOs using UTXO management system
      const availableUTXOs = await this.getAvailableUTXOs(fromAddress);

      if (availableUTXOs.length === 0) {
        throw new Error('No unspent outputs available for this address');
      }

      // Validate UTXOs with daemon before spending (real-time check)
      const validUTXOs = await this.validateUTXOsBeforeSpending(availableUTXOs);

      if (validUTXOs.length === 0) {
        throw new Error('No valid UTXOs available - all UTXOs may have been spent');
      }

      // Update wallet's internal state with validated UTXOs
      const totalBalance = validUTXOs.reduce((sum, utxo) => sum + utxo.amount, 0);
      wallet.balance = totalBalance;
      wallet.utxos = validUTXOs;

      // Check if wallet has sufficient balance
      if (totalBalance < totalAtomicAmount + atomicFee) {
        throw new Error(
          `Insufficient balance: ${fromAtomicUnits(totalBalance)} PAS (need ${fromAtomicUnits(totalAtomicAmount + atomicFee)} PAS for ${outputs.length} outputs plus fee)`
        );
      }

      // Create multi-output transaction using wallet method
      const transaction = wallet.createMultiTransaction(atomicOutputs, atomicFee, null, undefined, paymentId);

      // Mark UTXOs as pending BEFORE submitting the transaction
      const usedUTXOs = transaction.inputs.map(input => {
        const utxo = validUTXOs.find(u => u.transactionId === input.txId && u.outputIndex === input.outputIndex);
        return { ...utxo, address: fromAddress };
      }).filter(Boolean);

      this.markUTXOsAsPending(usedUTXOs, transaction.id);

      // Submit transaction to daemon with error handling and auto-restructuring
      const submissionResult = await this.submitMultiTransactionToDaemon(
        transaction,
        walletName,
        fromAddress,
        atomicOutputs,
        atomicFee,
        paymentId,
        usedUTXOs
      );

      if (!submissionResult.success) {
        // If submission failed, the method already handled cleanup
        throw new Error(submissionResult.error);
      }

      const result = submissionResult.data;

      logger.info(
        'WALLET_API',
        `Multi-output transaction sent from ${walletName}: ${outputs.length} outputs totaling ${fromAtomicUnits(totalAtomicAmount)} PAS (TX: ${result.transactionId || 'pending'})`
      );

      return {
        success: true,
        transactionId: result.transactionId || `pending_${Date.now()}`,
        fromWallet: walletName,
        fromAddress,
        outputs: outputs.map((output, index) => ({
          address: output.address,
          amount: fromAtomicUnits(atomicOutputs[index].amount),
          amountAtomic: atomicOutputs[index].amount,
        })),
        totalAmount: fromAtomicUnits(totalAtomicAmount),
        totalAmountAtomic: totalAtomicAmount,
        fee: fromAtomicUnits(atomicFee),
        feeAtomic: atomicFee,
        paymentId,
        tag,
        timestamp: Date.now(),
        status: result.status || 'submitted',
      };
    } catch (error) {
      const friendlyError = this.handleDaemonError(
        error,
        `sending multi-output transaction from wallet '${walletName}'`
      );
      logger.error('WALLET_API', `Error sending multi-output transaction from ${walletName}: ${friendlyError.message}`);
      throw friendlyError;
    }
  }

  /**
   * Import private key
   * @param walletName
   * @param privateKey
   * @param password
   */
  async importPrivKey(walletName, privateKey, password) {
    try {
      if (this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is already loaded`);
      }

      const walletPath = path.join(this.walletsDir, `${walletName}.wallet`);
      if (fs.existsSync(walletPath)) {
        throw new Error(`Wallet file '${walletName}.wallet' already exists`);
      }

      const wallet = new Wallet();
      await wallet.importFromPrivateKey(privateKey, password);

      // Save wallet to file
      await wallet.saveToFile(walletPath, password);

      // Load into memory
      this.wallets.set(walletName, wallet);

      const address = wallet.getAddress();
      logger.info('WALLET_API', `Imported private key to wallet: ${walletName} with address: ${address}`);

      return {
        success: true,
        walletName,
        address,
        message: 'Private key imported successfully',
      };
    } catch (error) {
      logger.error('WALLET_API', `Error importing private key to ${walletName}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Dump private key
   * @param walletName
   * @param password
   */
  async dumpPrivKey(walletName, password) {
    try {
      if (!this.wallets.has(walletName)) {
        throw new Error(`Wallet '${walletName}' is not loaded`);
      }

      const wallet = this.wallets.get(walletName);

      // Verify password and get private key
      const seedInfo = await wallet.showSeedInfo(password);

      logger.warn('WALLET_API', `Private key dumped for wallet: ${walletName}`);

      return {
        success: true,
        walletName,
        address: wallet.getAddress(),
        privateKey: seedInfo.privateKey,
        seed: seedInfo.seed,
        warning: 'Keep this private key secure and never share it!',
      };
    } catch (error) {
      logger.error('WALLET_API', `Error dumping private key for ${walletName}: ${error.message}`);
      throw error;
    }
  }

  /**
   * List available wallets
   */
  listWallets() {
    try {
      const walletFiles = fs
        .readdirSync(this.walletsDir)
        .filter(file => file.endsWith('.wallet'))
        .map(file => file.replace('.wallet', ''));

      const loadedWallets = Array.from(this.wallets.keys());

      return {
        success: true,
        availableWallets: walletFiles,
        loadedWallets,
        total: walletFiles.length,
      };
    } catch (error) {
      logger.error('WALLET_API', `Error listing wallets: ${error.message}`);
      throw error;
    }
  }

  /**
   * Start blockchain synchronization
   */
  async startBlockchainSync() {
    if (this.syncState.isRunning) {
      logger.info('WALLET_API', 'Sync already running');
      return;
    }

    if (this.wallets.size === 0) {
      logger.info('WALLET_API', 'No wallets loaded, skipping sync');
      return;
    }

    logger.info('WALLET_API', 'Starting blockchain sync...');
    this.syncState.isRunning = true;

    try {
      // Get current blockchain status
      const statusResponse = await this.daemonAPI.get('/api/blockchain/status');
      this.syncState.targetBlock = statusResponse.data.height || 0;

      logger.info('WALLET_API', `Target block height: ${this.syncState.targetBlock}`);

      // Perform initial sync
      await this.performFullSync();

      // Start periodic sync for new blocks
      this.startPeriodicSync();
    } catch (error) {
      logger.error('WALLET_API', `Error starting blockchain sync: ${error.message}`);
      this.syncState.isRunning = false;
    }
  }

  /**
   * Perform full blockchain sync for all loaded wallets
   */
  async performFullSync() {
    logger.info(
      'WALLET_API',
      `Starting full sync from block ${this.syncState.lastSyncedBlock} to ${this.syncState.targetBlock}`
    );

    for (
      let blockHeight = this.syncState.lastSyncedBlock + 1;
      blockHeight <= this.syncState.targetBlock;
      blockHeight++
    ) {
      try {
        // Process block for all wallets
        await this.processBlockForWallets(blockHeight);

        this.syncState.currentBlock = blockHeight;
        this.syncState.lastSyncedBlock = blockHeight;

        // Save sync state and wallet states every 100 blocks
        if (blockHeight % 100 === 0 || blockHeight === this.syncState.targetBlock) {
          const progress = ((blockHeight / this.syncState.targetBlock) * 100).toFixed(1);
          logger.info('WALLET_API', `Sync progress: ${progress}% (Block ${blockHeight}/${this.syncState.targetBlock})`);

          // Save global sync state
          this.saveGlobalSyncState();

          // Save all wallet states
          for (const walletName of this.wallets.keys()) {
            await this.saveWalletState(walletName);
          }
        }
      } catch (error) {
        logger.error('WALLET_API', `Error processing block ${blockHeight}: ${error.message}`);
        // Continue with next block on error
      }
    }

    this.syncState.isSynced = true;
    logger.info('WALLET_API', '✅ Blockchain sync complete - 100% synced!');
  }

  /**
   * Process a single block for all loaded wallets
   * @param blockHeight
   */
  async processBlockForWallets(blockHeight) {
    try {
      // Get block data from daemon
      const blockResponse = await this.daemonAPI.get(`/api/blockchain/block/${blockHeight}`);
      const block = blockResponse.data;

      if (!block || !block.transactions) {
        return;
      }

      // Process each transaction in the block
      for (const transaction of block.transactions) {
        await this.processTransactionForWallets(transaction, blockHeight, block.hash);
      }
    } catch (error) {
      // Block might not exist yet, continue
      if (error.response?.status !== 404) {
        logger.warn('WALLET_API', `Error getting block ${blockHeight}: ${error.message}`);
      }
    }
  }

  /**
   * Process a transaction for all loaded wallets
   * @param transaction
   * @param blockHeight
   * @param blockHash
   */
  async processTransactionForWallets(transaction, blockHeight, blockHash) {
    for (const [walletName, wallet] of this.wallets) {
      const address = wallet.getAddress();
      let isRelevant = false;
      let direction = '';
      let amount = 0;

      // Check if transaction involves this wallet
      const outputsToWallet = transaction.outputs?.filter(output => output.address === address) || [];

      // Check if wallet owns any inputs (by looking at previous transactions)
      let walletOwnsInputs = false;
      if (transaction.inputs) {
        for (const input of transaction.inputs) {
          try {
            const prevTxResponse = await this.daemonAPI.get(`/api/blockchain/transactions/${input.txId}`);
            const prevTx = prevTxResponse.data;
            if (prevTx?.outputs?.[input.outputIndex]?.address === address) {
              walletOwnsInputs = true;
              break;
            }
          } catch (error) {
            // Continue checking other inputs
          }
        }
      }

      if (outputsToWallet.length > 0) {
        // Incoming transaction
        isRelevant = true;
        direction = walletOwnsInputs ? 'self' : 'incoming';
        amount = outputsToWallet.reduce((sum, output) => sum + (output.amount || 0), 0);
      } else if (walletOwnsInputs) {
        // Outgoing transaction
        isRelevant = true;
        direction = 'outgoing';
        const outputsToOthers = transaction.outputs?.filter(output => output.address !== address) || [];
        amount = outputsToOthers.reduce((sum, output) => sum + (output.amount || 0), 0);
      }

      if (isRelevant) {
        // Log transaction in a single line
        const amountDisplay = fromAtomicUnits(amount);
        const directionIcon = direction === 'incoming' ? '⬇️' : direction === 'outgoing' ? '⬆️' : '🔄';

        logger.info(
          'WALLET_API',
          `${directionIcon} ${direction.toUpperCase()}: ${amountDisplay} PAS | ${walletName} | TX: ${transaction.id.substring(0, 8)}... | Block: ${blockHeight}`
        );

        // Update wallet transaction history
        wallet.transactionHistory = wallet.transactionHistory || [];

        // Check if transaction already exists to avoid duplicates
        const existingTx = wallet.transactionHistory.find(tx => tx.id === transaction.id);
        if (!existingTx) {
          wallet.transactionHistory.push({
            id: transaction.id,
            type: transaction.isCoinbase ? 'coinbase' : 'transaction',
            direction,
            amount,
            timestamp: transaction.timestamp,
            blockHeight,
            blockHash,
            confirmations: 0, // Will be updated later
          });
        }

        // Update wallet balance and UTXOs
        await this.updateWalletBalance(walletName);

        // Save wallet state to file
        await this.saveWalletState(walletName);
      }
    }
  }

  /**
   * Update wallet balance from daemon
   * @param walletName
   */
  async updateWalletBalance(walletName) {
    try {
      const wallet = this.wallets.get(walletName);
      if (!wallet) return;

      const address = wallet.getAddress();

      // Get balance and UTXOs from daemon
      const [balanceResponse, utxoResponse] = await Promise.all([
        this.daemonAPI.get(`/api/wallet/balance/${address}`),
        this.daemonAPI.get(`/api/wallet/utxos/${address}`),
      ]);

      wallet.balance = balanceResponse.data.balance || 0;
      wallet.utxos = utxoResponse.data.utxos || [];
    } catch (error) {
      logger.warn('WALLET_API', `Error updating balance for ${walletName}: ${error.message}`);
    }
  }

  /**
   * Start periodic sync to catch new blocks
   */
  startPeriodicSync() {
    if (this.syncState.syncInterval) {
      clearInterval(this.syncState.syncInterval);
    }

    // Check for new blocks every 30 seconds
    this.syncState.syncInterval = setInterval(async () => {
      try {
        const statusResponse = await this.daemonAPI.get('/api/blockchain/status');
        const currentHeight = statusResponse.data.height || 0;

        if (currentHeight > this.syncState.lastSyncedBlock) {
          logger.info('WALLET_API', `New blocks detected: ${this.syncState.lastSyncedBlock + 1} to ${currentHeight}`);

          this.syncState.targetBlock = currentHeight;

          // Sync new blocks
          for (let blockHeight = this.syncState.lastSyncedBlock + 1; blockHeight <= currentHeight; blockHeight++) {
            await this.processBlockForWallets(blockHeight);
            this.syncState.lastSyncedBlock = blockHeight;
            this.syncState.currentBlock = blockHeight;
          }

          // Save progress immediately after syncing new blocks
          await this.saveAllWallets();

          logger.info('WALLET_API', `✅ Synced to block ${currentHeight} and saved wallet states`);
        }
      } catch (error) {
        logger.error('WALLET_API', `Error in periodic sync: ${error.message}`);
      }
    }, 30000); // 30 seconds

    logger.info('WALLET_API', 'Periodic sync started (checking every 30 seconds)');
  }

  /**
   * Stop blockchain sync and auto-save
   */
  stopBlockchainSync() {
    this.syncState.isRunning = false;

    if (this.syncState.syncInterval) {
      clearInterval(this.syncState.syncInterval);
      this.syncState.syncInterval = null;
    }

    // Also stop auto-save and UTXO sync
    this.stopAutoSave();
    this.stopUTXOSync();

    logger.info('WALLET_API', 'Blockchain sync, auto-save, and UTXO sync stopped');
  }

  /**
   * Start auto-save functionality - saves all wallet files every 5 minutes
   */
  startAutoSave() {
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
    }

    // Auto-save all wallets every 5 minutes (300,000 ms)
    this.autoSaveInterval = setInterval(async () => {
      try {
        await this.saveAllWallets();
        logger.info('WALLET_API', '💾 Auto-save completed for all wallets');
      } catch (error) {
        logger.error('WALLET_API', `Auto-save error: ${error.message}`);
      }
    }, 300000); // 5 minutes

    logger.info('WALLET_API', 'Auto-save started (saving every 5 minutes)');
  }

  /**
   * Stop auto-save functionality
   */
  stopAutoSave() {
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
      this.autoSaveInterval = null;
      logger.info('WALLET_API', 'Auto-save stopped');
    }
  }

  /**
   * Save all loaded wallets and sync state
   */
  async saveAllWallets() {
    try {
      // Save global sync state
      await this.saveGlobalSyncState();

      // Save all individual wallet states
      const walletNames = Array.from(this.wallets.keys());
      let savedCount = 0;

      for (const walletName of walletNames) {
        try {
          await this.saveWalletState(walletName);
          savedCount++;
        } catch (error) {
          logger.error('WALLET_API', `Error saving wallet ${walletName}: ${error.message}`);
        }
      }

      if (walletNames.length > 0) {
        logger.info('WALLET_API', `Saved ${savedCount}/${walletNames.length} wallet files and sync state`);
      }

    } catch (error) {
      logger.error('WALLET_API', `Error in saveAllWallets: ${error.message}`);
      throw error;
    }
  }

  /**
   * Graceful shutdown - stops all timers and saves all data
   */
  async gracefulShutdown() {
    logger.info('WALLET_API', 'Starting graceful shutdown...');

    try {
      // Stop all timers
      this.stopBlockchainSync(); // This also stops auto-save

      // Final save of all wallet data
      await this.saveAllWallets();

      logger.info('WALLET_API', '✅ Graceful shutdown completed');
    } catch (error) {
      logger.error('WALLET_API', `Error during graceful shutdown: ${error.message}`);
      throw error;
    }
  }

  /**
   * Save wallet state including transaction history and sync progress to file
   * @param walletName
   */
  async saveWalletState(walletName) {
    try {
      const wallet = this.wallets.get(walletName);
      if (!wallet) return;

      // SECURITY: Validate wallet name and construct secure path
      const validatedWalletName = SecurityUtils.validateWalletName(walletName);
      const walletPath = SecurityUtils.validateFilePath(`${validatedWalletName}.wallet`, this.walletsDir, '.wallet');

      // Read existing wallet file
      const walletData = JSON.parse(fs.readFileSync(walletPath, 'utf8'));

      // Update with current state
      walletData.transactionHistory = wallet.transactionHistory || [];
      walletData.lastSyncedBlock = this.syncState.lastSyncedBlock;
      walletData.balance = wallet.balance || 0;
      walletData.utxos = wallet.utxos || [];
      walletData.lastSyncTime = Date.now();

      // Save back to file
      fs.writeFileSync(walletPath, JSON.stringify(walletData, null, 2));

    } catch (error) {
      logger.error('WALLET_API', `Error saving wallet state for ${walletName}: ${error.message}`);
    }
  }

  /**
   * Load wallet state from file including transaction history and sync progress
   * @param walletName
   */
  async loadWalletState(walletName) {
    try {
      const wallet = this.wallets.get(walletName);
      if (!wallet) return;

      // SECURITY: Validate wallet name and construct secure path
      const validatedWalletName = SecurityUtils.validateWalletName(walletName);
      const walletPath = SecurityUtils.validateFilePath(`${validatedWalletName}.wallet`, this.walletsDir, '.wallet');

      if (fs.existsSync(walletPath)) {
        const walletData = JSON.parse(fs.readFileSync(walletPath, 'utf8'));

        // Restore wallet state
        wallet.transactionHistory = walletData.transactionHistory || [];
        wallet.balance = walletData.balance || 0;
        wallet.utxos = walletData.utxos || [];

        // Restore sync progress
        if (walletData.lastSyncedBlock) {
          this.syncState.lastSyncedBlock = Math.max(this.syncState.lastSyncedBlock, walletData.lastSyncedBlock);
        }

        logger.info(
          'WALLET_API',
          `Loaded ${wallet.transactionHistory.length} transactions for ${walletName} (last sync: block ${walletData.lastSyncedBlock || 0})`
        );
      }
    } catch (error) {
      logger.error('WALLET_API', `Error loading wallet state for ${walletName}: ${error.message}`);
    }
  }

  /**
   * Load global sync state from persistent file
   */
  loadGlobalSyncState() {
    try {
      const syncStatePath = path.join(this.walletsDir, '.sync-state.json');
      if (fs.existsSync(syncStatePath)) {
        const savedState = JSON.parse(fs.readFileSync(syncStatePath, 'utf8'));

        this.syncState.lastSyncedBlock = savedState.lastSyncedBlock || 0;
        this.syncState.currentBlock = savedState.currentBlock || 0;
        this.syncState.isSynced = savedState.isSynced || false;

        logger.info('WALLET_API', `Loaded sync state: last synced block ${this.syncState.lastSyncedBlock}`);
      } else {
        logger.info('WALLET_API', 'No previous sync state found, starting fresh sync');
      }
    } catch (error) {
      logger.warn('WALLET_API', `Error loading sync state: ${error.message}`);
    }
  }

  /**
   * Save global sync state to persistent file
   */
  saveGlobalSyncState() {
    try {
      const syncStatePath = path.join(this.walletsDir, '.sync-state.json');
      const stateToSave = {
        lastSyncedBlock: this.syncState.lastSyncedBlock,
        currentBlock: this.syncState.currentBlock,
        targetBlock: this.syncState.targetBlock,
        isSynced: this.syncState.isSynced,
        lastSyncTime: Date.now(),
      };

      fs.writeFileSync(syncStatePath, JSON.stringify(stateToSave, null, 2));
      logger.debug('WALLET_API', `Saved sync state: block ${this.syncState.lastSyncedBlock}`);
    } catch (error) {
      logger.warn('WALLET_API', `Error saving sync state: ${error.message}`);
    }
  }

  /**
   * Calculate confirmations for a transaction at given block height
   * @param {number|null} blockHeight - The block height of the transaction
   * @returns {Promise<number>} Number of confirmations
   */
  async calculateConfirmations(blockHeight) {
    if (!blockHeight || blockHeight <= 0) {
      return 0; // Unconfirmed transaction
    }

    try {
      // Get current blockchain status
      const statusResponse = await this.daemonAPI.get('/api/blockchain/status');
      const currentHeight = statusResponse.data.height || statusResponse.data.chainLength || 0;

      if (currentHeight <= blockHeight) {
        return 0; // Current height is not higher than transaction block
      }

      // Confirmations = current height - transaction height + 1
      // (+1 because if tx is in block 100 and current is 100, it has 1 confirmation)
      return currentHeight - blockHeight + 1;
    } catch (error) {
      logger.warn('WALLET_API', `Could not calculate confirmations: ${error.message}`);
      return 0;
    }
  }

  // =============================================
  // UTXO MANAGEMENT SYSTEM
  // =============================================

  /**
   * Sync UTXOs from daemon and update local cache
   * @param {string} address - Wallet address to sync UTXOs for
   */
  async syncUTXOsFromDaemon(address) {
    try {
      const response = await this.daemonAPI.get(`/api/wallet/utxos/${address}`);
      const freshUTXOs = response.data.utxos || [];

      // Create UTXO map for fast lookup: "txId:index" -> utxoData
      const utxoMap = new Map();
      for (const utxo of freshUTXOs) {
        const key = `${utxo.transactionId}:${utxo.outputIndex}`;
        utxoMap.set(key, {
          ...utxo,
          address,
          isPending: false,
          lastChecked: Date.now(),
        });
      }

      // Update cache for this address
      this.utxoCache.set(address, {
        utxos: utxoMap,
        lastSync: Date.now(),
      });

      logger.debug('WALLET_API', `Synced ${freshUTXOs.length} UTXOs for address ${address}`);
      return utxoMap;
    } catch (error) {
      logger.error('WALLET_API', `Error syncing UTXOs for ${address}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get available UTXOs for an address (excluding pending ones)
   * @param {string} address - Wallet address
   * @param {boolean} forceSync - Force sync from daemon if true
   */
  async getAvailableUTXOs(address, forceSync = false) {
    try {
      let addressCache = this.utxoCache.get(address);

      // Sync from daemon if no cache or force sync or cache is older than 5 minutes
      const cacheAge = Date.now() - (addressCache?.lastSync || 0);
      if (!addressCache || forceSync || cacheAge > 300000) {
        await this.syncUTXOsFromDaemon(address);
        addressCache = this.utxoCache.get(address);
      }

      if (!addressCache) {
        return [];
      }

      // Filter out pending UTXOs and return available ones
      const availableUTXOs = [];
      for (const [key, utxo] of addressCache.utxos) {
        if (!utxo.isPending) {
          availableUTXOs.push(utxo);
        }
      }

      return availableUTXOs;
    } catch (error) {
      logger.error('WALLET_API', `Error getting available UTXOs for ${address}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Mark UTXOs as pending for a transaction
   * @param {Array} utxos - Array of UTXOs being spent
   * @param {string} txId - Transaction ID
   */
  markUTXOsAsPending(utxos, txId) {
    try {
      for (const utxo of utxos) {
        const address = utxo.address;
        const key = `${utxo.transactionId}:${utxo.outputIndex}`;

        // Update UTXO cache
        const addressCache = this.utxoCache.get(address);
        if (addressCache && addressCache.utxos.has(key)) {
          addressCache.utxos.get(key).isPending = true;
          addressCache.utxos.get(key).pendingTxId = txId;
        }
      }

      // Track pending transaction
      this.pendingTransactions.set(txId, {
        utxos: utxos.map(u => ({
          transactionId: u.transactionId,
          outputIndex: u.outputIndex,
          address: u.address,
        })),
        timestamp: Date.now(),
        confirmed: false,
      });

      logger.debug('WALLET_API', `Marked ${utxos.length} UTXOs as pending for transaction ${txId}`);
    } catch (error) {
      logger.error('WALLET_API', `Error marking UTXOs as pending: ${error.message}`);
    }
  }

  /**
   * Validate UTXOs with daemon before spending (real-time check)
   * @param {Array} utxos - UTXOs to validate
   * @returns {Array} Valid UTXOs that can be spent
   */
  async validateUTXOsBeforeSpending(utxos) {
    try {
      const validUTXOs = [];

      for (const utxo of utxos) {
        try {
          // Check if UTXO still exists on daemon
          const response = await this.daemonAPI.get(`/api/wallet/utxos/${utxo.address}`);
          const currentUTXOs = response.data.utxos || [];

          // Find if this UTXO is still available
          const isStillAvailable = currentUTXOs.some(
            u => u.transactionId === utxo.transactionId && u.outputIndex === utxo.outputIndex
          );

          if (isStillAvailable) {
            validUTXOs.push(utxo);
          } else {
            logger.warn('WALLET_API', `UTXO ${utxo.transactionId}:${utxo.outputIndex} is no longer available`);

            // Remove from local cache if it exists
            const address = utxo.address;
            const key = `${utxo.transactionId}:${utxo.outputIndex}`;
            const addressCache = this.utxoCache.get(address);
            if (addressCache && addressCache.utxos.has(key)) {
              addressCache.utxos.delete(key);
            }
          }
        } catch (error) {
          logger.warn('WALLET_API', `Error validating UTXO ${utxo.transactionId}:${utxo.outputIndex}: ${error.message}`);
        }
      }

      logger.debug('WALLET_API', `Validated ${validUTXOs.length}/${utxos.length} UTXOs as spendable`);
      return validUTXOs;
    } catch (error) {
      logger.error('WALLET_API', `Error validating UTXOs: ${error.message}`);
      return utxos; // Return original UTXOs if validation fails
    }
  }

  /**
   * Confirm a transaction (remove from pending, update UTXO cache)
   * @param {string} txId - Transaction ID that was confirmed
   */
  confirmTransaction(txId) {
    try {
      const pendingTx = this.pendingTransactions.get(txId);
      if (!pendingTx) {
        return;
      }

      // Remove confirmed UTXOs from cache and mark transaction as confirmed
      for (const utxo of pendingTx.utxos) {
        const address = utxo.address;
        const key = `${utxo.transactionId}:${utxo.outputIndex}`;

        const addressCache = this.utxoCache.get(address);
        if (addressCache && addressCache.utxos.has(key)) {
          // Remove the spent UTXO from cache
          addressCache.utxos.delete(key);
        }
      }

      // Mark as confirmed and keep for a while for tracking
      pendingTx.confirmed = true;
      pendingTx.confirmedAt = Date.now();

      logger.debug('WALLET_API', `Confirmed transaction ${txId} and removed ${pendingTx.utxos.length} UTXOs from cache`);
    } catch (error) {
      logger.error('WALLET_API', `Error confirming transaction ${txId}: ${error.message}`);
    }
  }

  /**
   * Reject/cancel a pending transaction (mark UTXOs as available again)
   * @param {string} txId - Transaction ID to reject
   */
  rejectTransaction(txId) {
    try {
      const pendingTx = this.pendingTransactions.get(txId);
      if (!pendingTx) {
        return;
      }

      // Mark UTXOs as available again
      for (const utxo of pendingTx.utxos) {
        const address = utxo.address;
        const key = `${utxo.transactionId}:${utxo.outputIndex}`;

        const addressCache = this.utxoCache.get(address);
        if (addressCache && addressCache.utxos.has(key)) {
          const cachedUTXO = addressCache.utxos.get(key);
          cachedUTXO.isPending = false;
          delete cachedUTXO.pendingTxId;
        }
      }

      // Remove from pending transactions
      this.pendingTransactions.delete(txId);

      logger.debug('WALLET_API', `Rejected transaction ${txId} and marked ${pendingTx.utxos.length} UTXOs as available`);
    } catch (error) {
      logger.error('WALLET_API', `Error rejecting transaction ${txId}: ${error.message}`);
    }
  }

  /**
   * Start periodic UTXO sync
   */
  startUTXOSync() {
    if (this.utxoSyncInterval) {
      clearInterval(this.utxoSyncInterval);
    }

    // Sync UTXOs every 2 minutes for all loaded wallet addresses
    this.utxoSyncInterval = setInterval(async () => {
      try {
        for (const [walletName, wallet] of this.wallets) {
          const address = wallet.getAddress();
          await this.syncUTXOsFromDaemon(address);
        }

        // Clean up old confirmed transactions (keep for 1 hour)
        this.cleanupOldTransactions();

        logger.debug('WALLET_API', `Periodic UTXO sync completed for ${this.wallets.size} wallets`);
      } catch (error) {
        logger.error('WALLET_API', `Error in periodic UTXO sync: ${error.message}`);
      }
    }, 120000); // 2 minutes

    logger.info('WALLET_API', 'UTXO sync started (syncing every 2 minutes)');
  }

  /**
   * Stop periodic UTXO sync
   */
  stopUTXOSync() {
    if (this.utxoSyncInterval) {
      clearInterval(this.utxoSyncInterval);
      this.utxoSyncInterval = null;
      logger.info('WALLET_API', 'UTXO sync stopped');
    }
  }

  /**
   * Clean up old confirmed transactions from pending list
   */
  cleanupOldTransactions() {
    try {
      const oneHourAgo = Date.now() - 3600000; // 1 hour
      let cleanedCount = 0;

      for (const [txId, pendingTx] of this.pendingTransactions) {
        if (pendingTx.confirmed && pendingTx.confirmedAt && pendingTx.confirmedAt < oneHourAgo) {
          this.pendingTransactions.delete(txId);
          cleanedCount++;
        }
      }

      if (cleanedCount > 0) {
        logger.debug('WALLET_API', `Cleaned up ${cleanedCount} old confirmed transactions`);
      }
    } catch (error) {
      logger.error('WALLET_API', `Error cleaning up old transactions: ${error.message}`);
    }
  }

  /**
   * Submit transaction to daemon with error handling and auto-restructuring
   * @param {Object} transaction - The transaction object
   * @param {string} walletName - Name of the wallet
   * @param {string} fromAddress - Sender address
   * @param {string} toAddress - Recipient address
   * @param {number} atomicAmount - Amount in atomic units
   * @param {number} atomicFee - Fee in atomic units
   * @param {string} paymentId - Optional payment ID
   * @param {Array} usedUTXOs - UTXOs used in the transaction
   * @param {number} retryCount - Current retry attempt (default: 0)
   * @returns {Object} Submission result
   */
  async submitTransactionToDaemon(transaction, walletName, fromAddress, toAddress, atomicAmount, atomicFee, paymentId, usedUTXOs, retryCount = 0) {
    const maxRetries = 2;

    try {
      console.log(`🚀 WALLET_API: Submitting transaction ${transaction.id} to daemon (attempt ${retryCount + 1}/${maxRetries + 1})`);

      const submitResponse = await this.daemonAPI.post('/api/transactions/submit', {
        transaction
      });

      const result = submitResponse.data;

      // Transaction was accepted
      console.log(`✅ WALLET_API: Transaction ${transaction.id} submitted successfully to daemon`);
      logger.info('WALLET_API', `Transaction ${transaction.id} submitted successfully to daemon`);

      return {
        success: true,
        data: result
      };

    } catch (submitError) {
      // Log the complete error details to console
      console.error(`❌ WALLET_API: Transaction ${transaction.id} submission failed:`);
      console.error(`   Error Message: ${submitError.message}`);
      console.error(`   Error Details: ${JSON.stringify(submitError.response?.data || 'No additional details', null, 2)}`);

      logger.error('WALLET_API', `Transaction ${transaction.id} submission failed: ${submitError.message}`);

      // Check if this is a UTXO-related error that we can retry
      const isUTXOError = this.isUTXORelatedError(submitError);

      if (isUTXOError && retryCount < maxRetries) {
        console.log(`🔄 WALLET_API: UTXO error detected, attempting to restructure transaction (retry ${retryCount + 1}/${maxRetries})`);
        logger.info('WALLET_API', `UTXO error detected for transaction ${transaction.id}, attempting restructure (retry ${retryCount + 1}/${maxRetries})`);

        try {
          // Reject current transaction to free up UTXOs
          this.rejectTransaction(transaction.id);

          // Get fresh UTXO state from daemon
          console.log(`🔍 WALLET_API: Fetching fresh UTXO state from daemon for address ${fromAddress}`);
          const freshUTXOs = await this.getAvailableUTXOs(fromAddress, true); // Force sync

          if (freshUTXOs.length === 0) {
            console.error(`❌ WALLET_API: No UTXOs available after refresh for address ${fromAddress}`);
            return {
              success: false,
              error: 'No UTXOs available after refresh - wallet may be empty or all UTXOs are spent'
            };
          }

          // Validate fresh UTXOs with daemon
          const validUTXOs = await this.validateUTXOsBeforeSpending(freshUTXOs);

          if (validUTXOs.length === 0) {
            console.error(`❌ WALLET_API: No valid UTXOs available after validation for address ${fromAddress}`);
            return {
              success: false,
              error: 'No valid UTXOs available after validation - all UTXOs may have been spent'
            };
          }

          console.log(`✅ WALLET_API: Found ${validUTXOs.length} valid UTXOs for restructuring transaction`);

          // Update wallet's internal state with fresh UTXOs
          const wallet = this.wallets.get(walletName);
          const totalBalance = validUTXOs.reduce((sum, utxo) => sum + utxo.amount, 0);
          wallet.balance = totalBalance;
          wallet.utxos = validUTXOs;

          // Check if we still have sufficient balance
          if (totalBalance < atomicAmount + atomicFee) {
            console.error(`❌ WALLET_API: Insufficient balance after refresh: ${totalBalance} < ${atomicAmount + atomicFee}`);
            return {
              success: false,
              error: `Insufficient balance after UTXO refresh: need ${atomicAmount + atomicFee}, have ${totalBalance}`
            };
          }

          // Create new transaction with fresh UTXOs
          console.log(`🔨 WALLET_API: Creating new transaction with fresh UTXOs`);
          const newTransaction = wallet.createTransaction(toAddress, atomicAmount, atomicFee, null, undefined, paymentId);

          // Mark new UTXOs as pending
          const newUsedUTXOs = newTransaction.inputs.map(input => {
            const utxo = validUTXOs.find(u => u.transactionId === input.txId && u.outputIndex === input.outputIndex);
            return { ...utxo, address: fromAddress };
          }).filter(Boolean);

          this.markUTXOsAsPending(newUsedUTXOs, newTransaction.id);

          // Recursive call with new transaction
          return await this.submitTransactionToDaemon(
            newTransaction,
            walletName,
            fromAddress,
            toAddress,
            atomicAmount,
            atomicFee,
            paymentId,
            newUsedUTXOs,
            retryCount + 1
          );

        } catch (restructureError) {
          console.error(`❌ WALLET_API: Transaction restructuring failed: ${restructureError.message}`);
          logger.error('WALLET_API', `Transaction restructuring failed: ${restructureError.message}`);

          // Clean up the failed transaction
          this.rejectTransaction(transaction.id);

          return {
            success: false,
            error: `Transaction restructuring failed: ${restructureError.message}`
          };
        }

      } else {
        // Non-UTXO error or max retries reached
        console.error(`❌ WALLET_API: Transaction ${transaction.id} permanently failed`);
        if (retryCount >= maxRetries) {
          console.error(`   Reason: Maximum retries (${maxRetries}) exceeded`);
        } else {
          console.error(`   Reason: Non-UTXO error or unrecoverable error`);
        }

        // Clean up the failed transaction
        this.rejectTransaction(transaction.id);

        return {
          success: false,
          error: `Transaction submission failed: ${submitError.message}${retryCount >= maxRetries ? ' (max retries exceeded)' : ''}`
        };
      }
    }
  }

  /**
   * Submit multi-output transaction to daemon with error handling and auto-restructuring
   * @param {Object} transaction - The transaction object
   * @param {string} walletName - Name of the wallet
   * @param {string} fromAddress - Sender address
   * @param {Array} atomicOutputs - Array of output objects with address and amount
   * @param {number} atomicFee - Fee in atomic units
   * @param {string} paymentId - Optional payment ID
   * @param {Array} usedUTXOs - UTXOs used in the transaction
   * @param {number} retryCount - Current retry attempt (default: 0)
   * @returns {Object} Submission result
   */
  async submitMultiTransactionToDaemon(transaction, walletName, fromAddress, atomicOutputs, atomicFee, paymentId, usedUTXOs, retryCount = 0) {
    const maxRetries = 2;

    try {
      console.log(`🚀 WALLET_API: Submitting multi-output transaction ${transaction.id} to daemon (attempt ${retryCount + 1}/${maxRetries + 1})`);

      const submitResponse = await this.daemonAPI.post('/api/transactions/submit', {
        transaction
      });

      const result = submitResponse.data;

      // Transaction was accepted
      console.log(`✅ WALLET_API: Multi-output transaction ${transaction.id} submitted successfully to daemon`);
      logger.info('WALLET_API', `Multi-output transaction ${transaction.id} submitted successfully to daemon`);

      return {
        success: true,
        data: result
      };

    } catch (submitError) {
      // Log the complete error details to console
      console.error(`❌ WALLET_API: Multi-output transaction ${transaction.id} submission failed:`);
      console.error(`   Error Message: ${submitError.message}`);
      console.error(`   Error Details: ${JSON.stringify(submitError.response?.data || 'No additional details', null, 2)}`);

      logger.error('WALLET_API', `Multi-output transaction ${transaction.id} submission failed: ${submitError.message}`);

      // Check if this is a UTXO-related error that we can retry
      const isUTXOError = this.isUTXORelatedError(submitError);

      if (isUTXOError && retryCount < maxRetries) {
        console.log(`🔄 WALLET_API: UTXO error detected, attempting to restructure multi-output transaction (retry ${retryCount + 1}/${maxRetries})`);
        logger.info('WALLET_API', `UTXO error detected for multi-output transaction ${transaction.id}, attempting restructure (retry ${retryCount + 1}/${maxRetries})`);

        try {
          // Reject current transaction to free up UTXOs
          this.rejectTransaction(transaction.id);

          // Get fresh UTXO state from daemon
          console.log(`🔍 WALLET_API: Fetching fresh UTXO state from daemon for address ${fromAddress}`);
          const freshUTXOs = await this.getAvailableUTXOs(fromAddress, true); // Force sync

          if (freshUTXOs.length === 0) {
            console.error(`❌ WALLET_API: No UTXOs available after refresh for address ${fromAddress}`);
            return {
              success: false,
              error: 'No UTXOs available after refresh - wallet may be empty or all UTXOs are spent'
            };
          }

          // Validate fresh UTXOs with daemon
          const validUTXOs = await this.validateUTXOsBeforeSpending(freshUTXOs);

          if (validUTXOs.length === 0) {
            console.error(`❌ WALLET_API: No valid UTXOs available after validation for address ${fromAddress}`);
            return {
              success: false,
              error: 'No valid UTXOs available after validation - all UTXOs may have been spent'
            };
          }

          console.log(`✅ WALLET_API: Found ${validUTXOs.length} valid UTXOs for restructuring multi-output transaction`);

          // Update wallet's internal state with fresh UTXOs
          const wallet = this.wallets.get(walletName);
          const totalBalance = validUTXOs.reduce((sum, utxo) => sum + utxo.amount, 0);
          wallet.balance = totalBalance;
          wallet.utxos = validUTXOs;

          // Calculate total amount needed
          const totalAtomicAmount = atomicOutputs.reduce((sum, output) => sum + output.amount, 0);

          // Check if we still have sufficient balance
          if (totalBalance < totalAtomicAmount + atomicFee) {
            console.error(`❌ WALLET_API: Insufficient balance after refresh: ${totalBalance} < ${totalAtomicAmount + atomicFee}`);
            return {
              success: false,
              error: `Insufficient balance after UTXO refresh: need ${totalAtomicAmount + atomicFee}, have ${totalBalance}`
            };
          }

          // Create new multi-output transaction with fresh UTXOs
          console.log(`🔨 WALLET_API: Creating new multi-output transaction with fresh UTXOs`);
          const newTransaction = wallet.createMultiTransaction(atomicOutputs, atomicFee, null, undefined, paymentId);

          // Mark new UTXOs as pending
          const newUsedUTXOs = newTransaction.inputs.map(input => {
            const utxo = validUTXOs.find(u => u.transactionId === input.txId && u.outputIndex === input.outputIndex);
            return { ...utxo, address: fromAddress };
          }).filter(Boolean);

          this.markUTXOsAsPending(newUsedUTXOs, newTransaction.id);

          // Recursive call with new transaction
          return await this.submitMultiTransactionToDaemon(
            newTransaction,
            walletName,
            fromAddress,
            atomicOutputs,
            atomicFee,
            paymentId,
            newUsedUTXOs,
            retryCount + 1
          );

        } catch (restructureError) {
          console.error(`❌ WALLET_API: Multi-output transaction restructuring failed: ${restructureError.message}`);
          logger.error('WALLET_API', `Multi-output transaction restructuring failed: ${restructureError.message}`);

          // Clean up the failed transaction
          this.rejectTransaction(transaction.id);

          return {
            success: false,
            error: `Multi-output transaction restructuring failed: ${restructureError.message}`
          };
        }

      } else {
        // Non-UTXO error or max retries reached
        console.error(`❌ WALLET_API: Multi-output transaction ${transaction.id} permanently failed`);
        if (retryCount >= maxRetries) {
          console.error(`   Reason: Maximum retries (${maxRetries}) exceeded`);
        } else {
          console.error(`   Reason: Non-UTXO error or unrecoverable error`);
        }

        // Clean up the failed transaction
        this.rejectTransaction(transaction.id);

        return {
          success: false,
          error: `Multi-output transaction submission failed: ${submitError.message}${retryCount >= maxRetries ? ' (max retries exceeded)' : ''}`
        };
      }
    }
  }

  /**
   * Check if an error is UTXO-related and can be retried
   * @param {Error} error - The error from daemon submission
   * @returns {boolean} True if this is a UTXO-related error
   */
  isUTXORelatedError(error) {
    if (!error.response?.data) {
      return false;
    }

    const errorData = error.response.data;
    const errorMessage = (errorData.error || errorData.details || error.message || '').toLowerCase();

    // Check for known UTXO-related error patterns
    const utxoErrorPatterns = [
      'double-spend',
      'double spend',
      'utxo',
      'already spent',
      'not found',
      'invalid input',
      'insufficient balance',
      'transaction rejected',
      'atomic utxo validation failed',
      'utxo is already reserved',
      'references non-existent',
      'input references'
    ];

    return utxoErrorPatterns.some(pattern => errorMessage.includes(pattern));
  }

  /**
   * Get UTXO cache status for debugging
   */
  getUTXOCacheStatus() {
    try {
      const status = {
        addresses: [],
        totalUTXOs: 0,
        pendingTransactions: this.pendingTransactions.size,
      };

      for (const [address, cache] of this.utxoCache) {
        const utxoCount = cache.utxos.size;
        const pendingCount = Array.from(cache.utxos.values()).filter(u => u.isPending).length;
        const availableCount = utxoCount - pendingCount;

        status.addresses.push({
          address,
          totalUTXOs: utxoCount,
          availableUTXOs: availableCount,
          pendingUTXOs: pendingCount,
          lastSync: new Date(cache.lastSync).toISOString(),
        });

        status.totalUTXOs += utxoCount;
      }

      return status;
    } catch (error) {
      logger.error('WALLET_API', `Error getting UTXO cache status: ${error.message}`);
      return { error: error.message };
    }
  }
}

module.exports = WalletFunctions;
