const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const fetch = require('node-fetch');

const { Transaction, TransactionInput, TransactionOutput } = require('../models/Transaction.js');
const { Wallet } = require('../models/Wallet.js');
const { toAtomicUnits, fromAtomicUnits, formatAtomicUnits } = require('../utils/atomicUnits.js');
const logger = require('../utils/logger.js');

/**
 * Network Wallet Manager - Pure API-based wallet that connects to any node
 * No blockchain.json dependency - syncs directly from network nodes
 */
class WalletManager {
  /**
   *
   */
  constructor() {
    this.wallets = new Map(); // Map<walletName, Wallet>
    this.currentWallet = null;
    this.connectedNode = null;
    this.nodeConfig = {
      host: '127.0.0.1',
      port: 22000,
      protocol: 'http',
    };

    // Wallet persistence for enhanced sync
    this.walletPath = null;
    this.walletPassword = null;
    this.autoSaveInterval = null;

    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
  }

  /**
   * Connect to a node
   * @param host
   * @param port
   * @param protocol
   */
  async connectToNode(host = '127.0.0.1', port = 22000, protocol = 'http') {
    try {
      this.nodeConfig = { host, port, protocol };
      const baseUrl = `${protocol}://${host}:${port}`;

      // Test connection by getting node status
      const response = await this.makeApiRequest(`${baseUrl}/api/status`);

      if (response.success) {
        this.connectedNode = baseUrl;
        logger.info('WALLET_MANAGER', `✅ Connected to node: ${baseUrl}`);
        logger.info('WALLET_MANAGER', `Node status: ${response.data.status || 'unknown'}`);
        return true;
      }
      throw new Error('Failed to get node status');
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to connect to node: ${error.message}`);
      this.connectedNode = null;
      return false;
    }
  }

  /**
   * Make API request to connected node
   * @param endpoint
   * @param options
   */
  async makeApiRequest(endpoint, options = {}) {
    try {
      const url = endpoint.startsWith('http') ? endpoint : `${this.connectedNode}${endpoint}`;

      const response = await fetch(url, {
        method: options.method || 'GET',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': options.apiKey || '',
          ...options.headers,
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      logger.error('WALLET_MANAGER', `API request failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Create new wallet
   * @param name
   * @param password
   */
  async createWallet(name, password) {
    try {
      if (this.wallets.has(name)) {
        throw new Error(`Wallet '${name}' already exists`);
      }

      const wallet = new Wallet();
      wallet.generateKeyPair();

      // Save wallet to file
      const walletPath = wallet.ensureWalletExtension(name);
      wallet.saveToFile(walletPath, password);

      // Store wallet reference and file info
      this.wallets.set(name, wallet);
      this.currentWallet = wallet;
      this.walletPath = walletPath;
      this.walletPassword = password;

      logger.info('WALLET_MANAGER', `✅ Wallet '${name}' created successfully`);
      logger.info('WALLET_MANAGER', `Address: ${wallet.getAddress()}`);
      console.log(`🔐 Created wallet: ${wallet.getAddress()}`);
      console.log(`💾 Saved to: ${walletPath}`);

      return wallet;
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to create wallet: ${error.message}`);
      console.log(`❌ Failed to create wallet '${name}': ${error.message}`);
      throw error;
    }
  }

  /**
   * Import wallet from seed phrase
   * @param name
   * @param seedPhrase
   * @param password
   */
  async importWalletFromSeed(name, seedPhrase, password) {
    try {
      if (this.wallets.has(name)) {
        throw new Error(`Wallet '${name}' already exists`);
      }

      const wallet = new Wallet();
      wallet.importFromSeed(seedPhrase, password);

      // Save wallet to file
      const walletPath = wallet.ensureWalletExtension(name);
      wallet.saveToFile(walletPath, password);

      // Store wallet reference and file info
      this.wallets.set(name, wallet);
      this.currentWallet = wallet;
      this.walletPath = walletPath;
      this.walletPassword = password;

      logger.info('WALLET_MANAGER', `✅ Wallet '${name}' imported from seed successfully`);
      logger.info('WALLET_MANAGER', `Address: ${wallet.getAddress()}`);
      console.log(`🔐 Imported wallet: ${wallet.getAddress()}`);
      console.log(`💾 Saved to: ${walletPath}`);

      return wallet;
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to import wallet from seed: ${error.message}`);
      console.log(`❌ Failed to import wallet from seed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Import wallet from private key
   * @param name
   * @param privateKey
   * @param password
   */
  async importWalletFromKey(name, privateKey, password) {
    try {
      if (this.wallets.has(name)) {
        throw new Error(`Wallet '${name}' already exists`);
      }

      const wallet = new Wallet();
      wallet.importFromPrivateKey(privateKey, password);

      // Save wallet to file
      const walletPath = wallet.ensureWalletExtension(name);
      wallet.saveToFile(walletPath, password);

      // Store wallet reference and file info
      this.wallets.set(name, wallet);
      this.currentWallet = wallet;
      this.walletPath = walletPath;
      this.walletPassword = password;

      logger.info('WALLET_MANAGER', `✅ Wallet '${name}' imported from private key successfully`);
      logger.info('WALLET_MANAGER', `Address: ${wallet.getAddress()}`);
      console.log(`🔐 Imported wallet: ${wallet.getAddress()}`);
      console.log(`💾 Saved to: ${walletPath}`);

      return wallet;
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to import wallet from private key: ${error.message}`);
      console.log(`❌ Failed to import wallet from private key: ${error.message}`);
      throw error;
    }
  }

  /**
   * Load wallet from file
   * @param name
   * @param password
   */
  async loadWallet(name, password) {
    try {
      const wallet = new Wallet();
      const walletPath = wallet.ensureWalletExtension(name);

      // Load wallet from file
      wallet.loadFromFile(walletPath, password);

      // Store wallet reference and file info
      this.currentWallet = wallet;
      this.walletPath = walletPath;
      this.walletPassword = password;
      this.wallets.set(name, wallet);

      logger.info('WALLET_MANAGER', `✅ Wallet '${name}' loaded successfully`);
      console.log(`🔐 Loaded wallet: ${wallet.getAddress()}`);

      return wallet;
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to load wallet: ${error.message}`);
      console.log(`❌ Failed to load wallet '${name}': ${error.message}`);
      throw error;
    }
  }

  /**
   * Get wallet balance from network
   * @param address
   */
  async getBalance(address) {
    try {
      if (!this.connectedNode) {
        throw new Error('Not connected to any node');
      }

      const response = await this.makeApiRequest(`/api/wallet/balance/${address}`);

      if (response.success) {
        return response.data.balance;
      }
      throw new Error(response.error || 'Failed to get balance');
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to get balance: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get wallet transactions from network
   * @param address
   */
  async getTransactions(address) {
    try {
      if (!this.connectedNode) {
        throw new Error('Not connected to any node');
      }

      const response = await this.makeApiRequest(`/api/wallet/transactions/${address}`);

      if (response.success) {
        return response.data.transactions;
      }
      throw new Error(response.error || 'Failed to get transactions');
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to get transactions: ${error.message}`);
      throw error;
    }
  }

  /**
   * Send transaction via network
   * @param toAddress
   * @param amount
   * @param fee
   */
  async sendTransaction(toAddress, amount, fee = 100000) {
    try {
      if (!this.currentWallet) {
        throw new Error('No wallet loaded');
      }

      if (!this.connectedNode) {
        throw new Error('Not connected to any node');
      }

      // Convert amount and fee to atomic units if they're not already
      const atomicAmount = typeof amount === 'string' ? toAtomicUnits(amount) : amount;
      const atomicFee = typeof fee === 'string' ? toAtomicUnits(fee) : fee;

      // Get current balance
      const balance = await this.getBalance(this.currentWallet.getAddress());

      if (balance < atomicAmount + atomicFee) {
        throw new Error(
          `Insufficient balance: ${formatAtomicUnits(balance)} PAS (need ${formatAtomicUnits(atomicAmount + atomicFee)} PAS)`
        );
      }

      // Create transaction
      const transaction = new Transaction();
      transaction.addInput(this.currentWallet.getAddress(), balance);
      transaction.addOutput(toAddress, atomicAmount);
      transaction.addOutput(this.currentWallet.getAddress(), balance - atomicAmount - atomicFee); // Change
      transaction.fee = atomicFee;

      // Sign transaction
      transaction.sign(this.currentWallet.getPrivateKey());

      // Submit to network
      const response = await this.makeApiRequest('/api/transactions/submit', {
        method: 'POST',
        body: {
          transaction: transaction.toJSON(),
        },
      });

      if (response.success) {
        logger.info('WALLET_MANAGER', `✅ Transaction sent successfully: ${response.data.transactionId}`);
        return response.data.transactionId;
      }
      throw new Error(response.error || 'Failed to send transaction');
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to send transaction: ${error.message}`);
      throw error;
    }
  }

  /**
   * Sync wallet with network
   * @param address
   */
  async syncWallet(address) {
    try {
      if (!this.connectedNode) {
        throw new Error('Not connected to any node');
      }

      logger.info('WALLET_MANAGER', `🔄 Syncing wallet ${address} with network...`);

      // Get balance
      const balance = await this.getBalance(address);

      // Get transactions
      const transactions = await this.getTransactions(address);

      // Get mempool status
      const mempoolResponse = await this.makeApiRequest('/api/memory-pool/status');
      const mempoolStatus = mempoolResponse.success ? mempoolResponse.data : null;

      logger.info('WALLET_MANAGER', `✅ Wallet synced successfully`);
      logger.info('WALLET_MANAGER', `Balance: ${formatAtomicUnits(balance)} PAS`);
      logger.info('WALLET_MANAGER', `Transactions: ${transactions.length}`);

      if (mempoolStatus) {
        logger.info('WALLET_MANAGER', `Mempool: ${mempoolStatus.poolSize} pending transactions`);
      }

      return {
        balance,
        transactions,
        mempoolStatus,
      };
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to sync wallet: ${error.message}`);
      throw error;
    }
  }

  /**
   * Export wallet credentials
   * @param {string} type - Type of export: 'private', 'seed', or 'address'
   */
  async exportWallet(type) {
    try {
      if (!this.currentWallet) {
        throw new Error('No wallet loaded. Use "load <name> <password>" first.');
      }

      console.log('🔐 Wallet Export');
      console.log('================');

      switch (type.toLowerCase()) {
        case 'private':
        case 'privatekey':
        case 'key':
          if (!this.currentWallet.privateKey) {
            throw new Error('Private key not available for this wallet');
          }
          console.log('⚠️  WARNING: Keep your private key safe! Anyone with this key can access your funds.');
          console.log('');
          console.log(`🔑 Private Key: ${this.currentWallet.privateKey}`);
          console.log('');
          console.log('💡 Use this key to import your wallet: key-import <name> <key> <password>');
          break;

        case 'seed':
        case 'mnemonic':
          if (!this.currentWallet.seed) {
            throw new Error('Seed phrase not available for this wallet');
          }
          console.log('⚠️  WARNING: Keep your seed phrase safe! Anyone with this seed can access your funds.');
          console.log('');
          console.log(`🌱 Seed Phrase: ${this.currentWallet.seed}`);
          console.log('');
          console.log('💡 Use this seed to import your wallet: seed-import <name> <seed> <password>');
          break;

        case 'address':
        case 'addr':
          const address = this.currentWallet.getAddress();
          console.log(`📍 Wallet Address: ${address}`);
          console.log('');
          console.log('💡 Share this address to receive PAS coins.');
          break;

        default:
          console.log('❌ Invalid export type. Use: private, seed, or address');
          console.log('');
          console.log('Examples:');
          console.log('  export private  - Export private key');
          console.log('  export seed     - Export seed phrase');
          console.log('  export address  - Export wallet address');
          return;
      }

      console.log('');
      console.log('🔒 Security Tips:');
      console.log('  • Never share your private key or seed phrase');
      console.log('  • Store backups in multiple secure locations');
      console.log('  • Use strong passwords for wallet files');
      console.log('  • Only the address is safe to share publicly');
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to export wallet: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get network status
   */
  async getNetworkStatus() {
    try {
      if (!this.connectedNode) {
        throw new Error('Not connected to any node');
      }

      const response = await this.makeApiRequest('/api/status');

      if (response.success) {
        return response.data;
      }
      throw new Error(response.error || 'Failed to get network status');
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to get network status: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get blockchain status
   */
  async getBlockchainStatus() {
    try {
      if (!this.connectedNode) {
        throw new Error('Not connected to any node');
      }

      const response = await this.makeApiRequest('/api/blockchain/status');

      if (response.success) {
        return response.data;
      }
      throw new Error(response.error || 'Failed to get blockchain status');
    } catch (error) {
      logger.error('WALLET_MANAGER', `Failed to get blockchain status: ${error.message}`);
      throw error;
    }
  }

  /**
   * Interactive CLI mode
   */
  async startInteractiveMode() {
    console.log('🔐 Pastella Network Wallet Manager');
    console.log('=====================================');
    console.log('Type "help" for available commands');
    console.log('');

    const prompt = () => {
      this.rl.question('wallet> ', async input => {
        try {
          await this.processCommand(input.trim());
        } catch (error) {
          console.error(`❌ Error: ${error.message}`);
        }
        prompt();
      });
    };

    prompt();
  }

  /**
   * Process CLI commands
   * @param command
   */
  async processCommand(command) {
    const parts = command.split(' ');
    const cmd = parts[0].toLowerCase();

    switch (cmd) {
      case 'help':
        this.showHelp();
        break;

      case 'connect':
        if (parts.length < 3) {
          console.log('Usage: connect <host> <port> [protocol]');
          return;
        }
        const host = parts[1];
        const port = parseInt(parts[2]);
        const protocol = parts[3] || 'http';
        await this.connectToNode(host, port, protocol);
        break;

      case 'create':
        if (parts.length < 3) {
          console.log('Usage: create <name> <password>');
          return;
        }
        await this.createWallet(parts[1], parts[2]);
        break;

      case 'seed-import':
        if (parts.length < 4) {
          console.log('Usage: seed-import <name> <seed-phrase> <password>');
          return;
        }
        const seedPhrase = parts.slice(2, -1).join(' ');
        const seedPassword = parts[parts.length - 1];
        await this.importWalletFromSeed(parts[1], seedPhrase, seedPassword);
        break;

      case 'key-import':
        if (parts.length < 4) {
          console.log('Usage: key-import <name> <private-key> <password>');
          return;
        }
        const privateKey = parts[2];
        const keyPassword = parts[3];
        await this.importWalletFromKey(parts[1], privateKey, keyPassword);
        break;

      case 'load':
        if (parts.length < 3) {
          console.log('Usage: load <name> <password>');
          return;
        }
        await this.loadWallet(parts[1], parts[2]);
        break;

      case 'balance':
        if (!this.currentWallet) {
          console.log('❌ No wallet loaded. Use "load <name> <password>" first.');
          return;
        }
        const balance = await this.getBalance(this.currentWallet.getAddress());
        console.log(`💰 Balance: ${formatAtomicUnits(balance)} PAS`);
        break;

      case 'send':
        if (parts.length < 4) {
          console.log('Usage: send <to-address> <amount> [fee]');
          return;
        }
        if (!this.currentWallet) {
          console.log('❌ No wallet loaded. Use "load <name> <password>" first.');
          return;
        }
        const amount = parseFloat(parts[2]);
        const fee = parts[3] ? parseFloat(parts[3]) : 100000; // 0.001 PAS in atomic units
        await this.sendTransaction(parts[1], amount, fee);
        break;

      case 'export':
        if (parts.length < 2) {
          console.log('❌ Usage: export <private|seed|address>');
          return;
        }
        await this.exportWallet(parts[1]);
        break;

      case 'sync':
        if (!this.currentWallet) {
          console.log('❌ No wallet loaded. Use "load <name> <password>" first.');
          return;
        }
        await this.syncWallet(this.currentWallet.getAddress());
        break;

      case 'resync':
        if (!this.currentWallet) {
          console.log('❌ No wallet loaded. Use "load <name> <password>" first.');
          return;
        }
        await this.resyncWallet();
        break;

      case 'sync_from':
        if (!this.currentWallet) {
          console.log('❌ No wallet loaded. Use "load <name> <password>" first.');
          return;
        }
        if (parts.length < 2) {
          console.log('❌ Usage: sync_from <block_height>');
          return;
        }
        const blockHeight = parseInt(parts[1]);
        if (isNaN(blockHeight) || blockHeight < 0) {
          console.log('❌ Invalid block height. Must be a positive number.');
          return;
        }
        await this.syncWalletFromBlock(blockHeight);
        break;

      case 'status':
        await this.showStatus();
        break;

      case 'quit':
      case 'exit':
        console.log('👋 Goodbye!');
        this.rl.close();
        process.exit(0);
        break;

      default:
        if (command.trim()) {
          console.log(`❓ Unknown command: ${cmd}. Type "help" for available commands.`);
        }
    }
  }

  /**
   * Show help
   */
  showHelp() {
    console.log('📚 Available Commands:');
    console.log('');
    console.log('🔌 Connection:');
    console.log('  connect <host> <port> [protocol]  - Connect to a node');
    console.log('');
    console.log('🔐 Wallet Management:');
    console.log('  create <name> <password>          - Create new wallet');
    console.log('  seed-import <name> <seed> <pass>  - Import from seed phrase');
    console.log('  key-import <name> <key> <pass>    - Import from private key');
    console.log('  load <name> <password>            - Load existing wallet');
    console.log('');
    console.log('💰 Operations:');
    console.log('  balance                            - Show current balance');
    console.log('  send <address> <amount> [fee]     - Send transaction');
    console.log('  export <private|seed|address>      - Export wallet credentials');
    console.log('');
    console.log('🔄 Synchronization:');
    console.log('  sync                               - Quick sync wallet with network');
    console.log('  resync                             - Full resync from blockchain');
    console.log('  sync_from <block_height>           - Sync from specific block height');
    console.log('');
    console.log('📊 Information:');
    console.log('  status                             - Show network status');
    console.log('  help                               - Show this help');
    console.log('  quit/exit                          - Exit wallet manager');
    console.log('');
  }

  /**
   * Show current status
   */
  async showStatus() {
    console.log('📊 Current Status:');
    console.log('==================');

    if (this.connectedNode) {
      console.log(`🔌 Connected to: ${this.connectedNode}`);

      try {
        const networkStatus = await this.getNetworkStatus();
        console.log(`🌐 Network: ${networkStatus.status || 'unknown'}`);

        const blockchainStatus = await this.getBlockchainStatus();
        console.log(`🔗 Blockchain: ${blockchainStatus.length || 0} blocks`);
        console.log(`⏰ Latest block: ${blockchainStatus.latestBlock || 'unknown'}`);
      } catch (error) {
        console.log(`❌ Failed to get status: ${error.message}`);
      }
    } else {
      console.log('❌ Not connected to any node');
    }

    if (this.currentWallet) {
      console.log(`🔐 Wallet: ${this.currentWallet.getAddress()}`);
    } else {
      console.log('🔐 No wallet loaded');
    }

    console.log(`📁 Wallets: ${this.wallets.size} available`);
    console.log('');
  }

  // Enhanced sync methods matching wallet-api security
  /**
   *
   */
  async resyncWallet() {
    if (!this.currentWallet || !this.currentWallet.isLoaded()) {
      console.log('❌ No wallet loaded');
      return;
    }

    try {
      console.log('🔄 Starting full wallet resync...');
      console.log('⚠️  This will sync from block 0 and may take some time');

      // Reset wallet sync state
      this.currentWallet.resetSyncState();

      // Clear transaction history
      this.currentWallet.clearTransactionHistory();

      // Start auto-save during sync
      this.startAutoSave();

      // Perform full sync from beginning
      await this.performBlockchainSync(0);

      // Save wallet with updated state
      if (this.walletPath && this.walletPassword) {
        this.currentWallet.saveToFile(this.walletPath, this.walletPassword);
        console.log('💾 Wallet state saved');
      }

      console.log('✅ Wallet resync completed');
    } catch (error) {
      console.error('❌ Error during wallet resync:', error.message);
    } finally {
      this.stopAutoSave();
    }
  }

  /**
   *
   */
  async syncWalletFromBlock(fromBlock) {
    if (!this.currentWallet || !this.currentWallet.isLoaded()) {
      console.log('❌ No wallet loaded');
      return;
    }

    if (!fromBlock || isNaN(fromBlock) || fromBlock < 0) {
      console.log('❌ Please provide a valid block height');
      console.log('   Usage: sync_from <block_height>');
      return;
    }

    try {
      console.log(`🔄 Starting wallet sync from block ${fromBlock}...`);

      // Update sync state to start from specified block
      const currentHeight = await this.getCurrentBlockHeight();
      if (fromBlock > currentHeight) {
        console.log(`❌ Block ${fromBlock} is higher than current blockchain height (${currentHeight})`);
        return;
      }

      // Clear transaction history newer than fromBlock
      this.clearTransactionsFromBlock(fromBlock);

      // Start auto-save during sync
      this.startAutoSave();

      // Perform sync from specified block
      await this.performBlockchainSync(fromBlock);

      // Save wallet with updated state
      if (this.walletPath && this.walletPassword) {
        this.currentWallet.saveToFile(this.walletPath, this.walletPassword);
        console.log('💾 Wallet state saved');
      }

      console.log(`✅ Wallet sync from block ${fromBlock} completed`);

    } catch (error) {
      console.error(`❌ Error during sync from block ${fromBlock}:`, error.message);
    } finally {
      this.stopAutoSave();
    }
  }

  // Blockchain sync implementation matching wallet-api security
  /**
   *
   */
  async performBlockchainSync(fromBlock = null) {
    try {
      console.log('🔗 Connecting to daemon for sync...');

      if (!this.connectedNode) {
        throw new Error('Not connected to any node');
      }

      // Get current blockchain status
      const statusResponse = await this.makeApiRequest('/api/blockchain/status');
      if (!statusResponse.success) {
        throw new Error('Cannot get blockchain status');
      }

      const targetBlock = statusResponse.data.height || 0;
      const startBlock = fromBlock !== null ? fromBlock : this.currentWallet.getSyncState().lastSyncedHeight;

      console.log(`📊 Sync range: Block ${startBlock} to ${targetBlock}`);

      if (startBlock >= targetBlock) {
        console.log('✅ Wallet is already synced');
        return;
      }

      // Process blocks in batches
      const batchSize = 100;
      let processedBlocks = 0;
      const totalBlocks = targetBlock - startBlock;

      for (let blockHeight = startBlock + 1; blockHeight <= targetBlock; blockHeight++) {
        try {
          await this.processBlockForWallet(blockHeight);
          processedBlocks++;

          // Update sync state
          this.currentWallet.updateSyncState(blockHeight, null, this.currentWallet.getTransactionHistory().length);

          // Log progress every 100 blocks or on completion
          if (blockHeight % batchSize === 0 || blockHeight === targetBlock) {
            const progress = ((processedBlocks / totalBlocks) * 100).toFixed(1);
            console.log(`⏳ Sync progress: ${progress}% (Block ${blockHeight}/${targetBlock})`);
          }

        } catch (blockError) {
          // Continue with next block on error (block might not exist yet)
          if (blockError.response?.status !== 404) {
            console.warn(`⚠️  Error processing block ${blockHeight}: ${blockError.message}`);
          }
        }
      }

      // Update wallet balance and UTXOs from daemon
      await this.updateWalletFromDaemon();

      console.log('✅ Blockchain sync completed successfully');
    } catch (error) {
      console.error('❌ Blockchain sync error:', error.message);
      throw error;
    }
  }

  // Process a single block for the current wallet
  /**
   *
   */
  async processBlockForWallet(blockHeight) {
    try {
      // Get block data from daemon
      const blockResponse = await this.makeApiRequest(`/api/blockchain/block/${blockHeight}`);
      if (!blockResponse.success) {
        throw new Error(`Block ${blockHeight} not found`);
      }

      const block = blockResponse.data;
      if (!block || !block.transactions) {
        return;
      }

      const walletAddress = this.currentWallet.getAddress();

      // Process each transaction in the block
      for (const transaction of block.transactions) {
        await this.processTransactionForWallet(transaction, blockHeight, block.hash, walletAddress);
      }

    } catch (error) {
      // Re-throw for caller to handle
      throw error;
    }
  }

  // Process a transaction for the current wallet
  /**
   *
   */
  async processTransactionForWallet(transaction, blockHeight, blockHash, walletAddress) {
    let isRelevant = false;
    let direction = '';
    let amount = 0;

    // Check if transaction involves this wallet
    const outputsToWallet = transaction.outputs?.filter(output => output.address === walletAddress) || [];

    // Check if wallet owns any inputs (by looking at previous transactions)
    let walletOwnsInputs = false;
    if (transaction.inputs && !transaction.isCoinbase) {
      for (const input of transaction.inputs) {
        try {
          const inputTxHash = input.txHash || input.txId;
          const prevTxResponse = await this.makeApiRequest(`/api/blockchain/transactions/${inputTxHash}`);
          if (prevTxResponse.success) {
            const prevTx = prevTxResponse.data;
            if (prevTx?.outputs?.[input.outputIndex]?.address === walletAddress) {
              walletOwnsInputs = true;
              break;
            }
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
      const outputsToOthers = transaction.outputs?.filter(output => output.address !== walletAddress) || [];
      amount = outputsToOthers.reduce((sum, output) => sum + (output.amount || 0), 0);
    }

    if (isRelevant) {
      // Display transaction in a single line with icons
      const amountDisplay = formatAtomicUnits(amount);
      const directionIcon = direction === 'incoming' ? '⬇️' : direction === 'outgoing' ? '⬆️' : '🔄';

      console.log(
        `${directionIcon} ${direction.toUpperCase()}: ${amountDisplay} PAS | TX: ${transaction.id.substring(0, 8)}... | Block: ${blockHeight}`

      // Update wallet transaction history
      const existingTx = this.currentWallet.getTransactionHistory().find(tx => tx.id === transaction.id);
      if (!existingTx) {
        // Add to transaction history using wallet method
        this.currentWallet.addTransactionToHistory({
          id: transaction.id,
          type: transaction.isCoinbase ? 'coinbase' : 'transaction',
          direction,
          amount,
          timestamp: transaction.timestamp,
          blockHeight,
          blockHash,
          confirmations: 0, // Will be updated with current block height
        });
      }
    }
  }

  // Update wallet balance and UTXOs from daemon (matching wallet-api)
  /**
   *
   */
  async updateWalletFromDaemon() {
    try {
      const address = this.currentWallet.getAddress();

      // Get balance and UTXOs from daemon
      const balanceResponse = await this.makeApiRequest(`/api/wallet/balance/${address}`);
      const utxoResponse = await this.makeApiRequest(`/api/wallet/utxos/${address}`);

      if (balanceResponse.success) {
        this.currentWallet.balance = balanceResponse.data.balance || 0;
      }

      if (utxoResponse.success) {
        this.currentWallet.utxos = utxoResponse.data.utxos || [];
      }

    } catch (error) {
      console.warn(`⚠️  Error updating wallet from daemon: ${error.message}`);
    }
  }

  // Get current blockchain height
  /**
   *
   */
  async getCurrentBlockHeight() {
    try {
      const response = await this.makeApiRequest('/api/blockchain/status');
      if (response.success) {
        return response.data.height || 0;
      }
      throw new Error('Cannot get blockchain status');
    } catch (error) {
      throw new Error(`Cannot get blockchain height: ${error.message}`);
    }
  }

  // Clear transactions from a specific block height
  /**
   *
   */
  clearTransactionsFromBlock(fromBlock) {
    if (!this.currentWallet.transactionHistory) {
      return;
    }

    const initialCount = this.currentWallet.transactionHistory.length;

    // Filter out transactions from blocks >= fromBlock
    const filteredHistory = this.currentWallet.transactionHistory.filter(
      tx => !tx.blockHeight || tx.blockHeight < fromBlock
    );

    this.currentWallet.transactionHistory = filteredHistory;
    const clearedCount = initialCount - filteredHistory.length;

    if (clearedCount > 0) {
      console.log(`🗑️  Cleared ${clearedCount} transactions from block ${fromBlock}+`);
    }
  }

  // Auto-save wallet periodically during sync (matching wallet-api)
  /**
   *
   */
  startAutoSave() {
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
    }

    // Auto-save every 2 minutes like the daemon does
    this.autoSaveInterval = setInterval(
      async () => {
        try {
          if (this.currentWallet && this.currentWallet.isLoaded() && this.walletPath && this.walletPassword) {
            this.currentWallet.saveToFile(this.walletPath, this.walletPassword);
            console.log('💾 Auto-saved wallet state');
          }
        } catch (error) {
          console.warn('⚠️  Auto-save failed:', error.message);
        }
      },
      2 * 60 * 1000
    ); // 2 minutes
  }

  /**
   *
   */
  stopAutoSave() {
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
      this.autoSaveInterval = null;
    }
  }
}

module.exports = WalletManager;
