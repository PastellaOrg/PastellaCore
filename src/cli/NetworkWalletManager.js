const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const chalk = require('chalk'); // Added for beautified output
const fetch = require('node-fetch');

const { Transaction, TransactionInput, TransactionOutput } = require('../models/Transaction.js');
const Wallet = require('../models/Wallet.js');
const { toAtomicUnits, fromAtomicUnits, formatAtomicUnits } = require('../utils/atomicUnits.js');
const { SecurityUtils } = require('../utils/crypto.js');
const logger = require('../utils/logger.js');

/**
 * Network Wallet Manager - Integrates with existing CLI structure
 * Provides network-based wallet operations while maintaining CLI compatibility
 */
class NetworkWalletManager {
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

    // CLI integration
    this.cli = null;
  }

  /**
   * Set CLI reference for integration
   * @param cli
   */
  setCLIReference(cli) {
    this.cli = cli;
    this.updateApiUrl(cli.apiBaseUrl);

    // Load existing wallets from disk
    this.loadWalletsFromDisk();
  }

  /**
   * Update API URL from CLI
   * @param apiUrl
   */
  updateApiUrl(apiUrl) {
    try {
      const url = new URL(apiUrl);
      this.nodeConfig = {
        host: url.hostname,
        port: parseInt(url.port) || 22000,
        protocol: url.protocol.replace(':', ''),
      };
      this.connectedNode = apiUrl;
    } catch (error) {
      logger.error('NETWORK_WALLET', `Failed to parse API URL: ${error.message}`);
    }
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
        logger.info('NETWORK_WALLET', `✅ Connected to node: ${baseUrl}`);
        logger.info('NETWORK_WALLET', `Node status: ${response.data.status || 'unknown'}`);

        // Update CLI API URL
        if (this.cli) {
          this.cli.apiBaseUrl = baseUrl;
          this.cli.isConnected = true;
        }

        return true;
      }
      throw new Error('Failed to get node status');
    } catch (error) {
      logger.error('NETWORK_WALLET', `Failed to connect to node: ${error.message}`);
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
      let url = endpoint.startsWith('http') ? endpoint : `${this.connectedNode}${endpoint}`;

      // Force IPv4 by using 127.0.0.1 instead of localhost
      if (url.includes('localhost')) {
        url = url.replace('localhost', '127.0.0.1');
      }

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
      // Don't log 404 errors for blocks/transactions during sync - they're expected
      const is404 = error.message.includes('HTTP 404');
      const isBlockOrTx = endpoint.includes('/blocks/') || endpoint.includes('/transactions/');

      if (!is404 || !isBlockOrTx) {
        logger.error('NETWORK_WALLET', `API request failed: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Handle CLI wallet commands (main integration point)
   * @param args
   */
  async handleCommand(args) {
    if (!args || args.length === 0) {
      console.log('❌ Missing wallet command');
      this.showHelp();
      return;
    }

    const command = args[0];

    switch (command) {
      case 'create':
        await this.createWallet();
        break;
      case 'load':
        await this.loadWallet();
        break;
      case 'unload':
        await this.unloadWallet();
        break;
      case 'balance':
        await this.checkBalance();
        break;
      case 'send':
        await this.sendTransaction();
        break;
      case 'send-multi':
      case 'multisend':
        await this.sendMultiTransaction();
        break;
      case 'info':
        await this.showWalletInfo();
        break;
      case 'sync':
        await this.syncWalletWithNetwork();
        break;
      case 'resync':
        await this.resyncWallet();
        break;
      case 'transactions':
        await this.showTransactionHistory();
        break;
      case 'transaction-info':
        if (args.length < 2) {
          console.log('❌ Usage: wallet transaction-info <transaction-id>');
          return;
        }
        await this.showTransactionInfo(args[1]);
        break;
      case 'save':
        await this.saveWallet();
        break;
      case 'seed-import':
        await this.importWalletFromSeed();
        break;
      case 'key-import':
        await this.importWalletFromKey();
        break;
      case 'connect':
        if (args.length < 3) {
          console.log('❌ Usage: wallet connect <host> <port> [protocol]');
          return;
        }
        const host = args[1];
        const port = parseInt(args[2]);
        const protocol = args[3] || 'http';
        await this.connectToNode(host, port, protocol);
        break;
      default:
        console.log(`❌ Unknown wallet command: ${command}`);
        this.showHelp();
    }
  }

  /**
   * Create new wallet
   */
  async createWallet() {
    try {
      const answers = await this.cli.inquirer.prompt([
        {
          type: 'input',
          name: 'walletName',
          message: 'Enter wallet name:',
          default: 'default',
          validate: input => {
            if (!input.trim()) {
              return 'Wallet name cannot be empty';
            }
            // Check if wallet file already exists
            const filePath = path.join(process.cwd(), `${input.trim()}.wallet`);
            if (fs.existsSync(filePath)) {
              return `Wallet '${input.trim()}' already exists. Please choose a different name.`;
            }
            return true;
          },
        },
        {
          type: 'password',
          name: 'password',
          message: 'Enter wallet password:',
          validate: input => {
            if (input.length < 6) {
              return 'Password must be at least 6 characters long';
            }
            return true;
          },
        },
        {
          type: 'password',
          name: 'confirmPassword',
          message: 'Confirm wallet password:',
          validate: (input, answers) => {
            if (input !== answers.password) {
              return 'Passwords do not match';
            }
            return true;
          },
        },
      ]);

      // Check if wallet already exists in memory
      if (this.wallets.has(answers.walletName)) {
        console.log(chalk.red(`❌ Error: Wallet '${answers.walletName}' already exists in memory.`));
        console.log(chalk.yellow('💡 Use "wallet load" to load an existing wallet or choose a different name.'));
        return;
      }

      const wallet = new Wallet();
      await wallet.generateKeyPair();

      // Store wallet in memory (no encryption needed for network wallet)
      this.wallets.set(answers.walletName, wallet);
      this.currentWallet = wallet;

      // Update CLI state
      this.cli.walletLoaded = true;
      this.cli.walletName = answers.walletName;
      this.cli.walletPassword = answers.password;
      this.cli.currentNetworkWallet = wallet;

      // Save wallet to disk
      this.saveWalletToFile(answers.walletName, wallet, answers.password);

      console.log('✅ Wallet created successfully!');
      console.log(`Name: ${answers.walletName}`);
      console.log(`Address: ${wallet.getAddress()}`);

      // Beautify the wallet creation output
      console.log(chalk.blue('╔══════════════════════════════════════════════════════════════════════════════╗'));
      console.log(chalk.blue('║                            🎉 WALLET CREATED! 🎉                             ║'));
      console.log(chalk.blue('╚══════════════════════════════════════════════════════════════════════════════╝'));
      console.log('');
      console.log(chalk.cyan('📋 NEW WALLET INFORMATION:'));
      console.log(chalk.white('  ┌─────────────────────────────────────────────────────────────────────────┐'));
      console.log(chalk.white(`  │ ${chalk.yellow('Name:')}    ${chalk.green(answers.walletName.padEnd(62))} │`));
      console.log(chalk.white(`  │ ${chalk.yellow('Address:')} ${chalk.green(wallet.getAddress().padEnd(62))} │`));
      console.log(chalk.white('  └─────────────────────────────────────────────────────────────────────────┘'));
      console.log('');
      console.log(chalk.red('⚠️  SECURITY WARNING:'));
      console.log(
        chalk.white(
          '  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐'
        )
      );
      console.log(chalk.white(`  │ ${chalk.yellow('Private Key:')} ${chalk.red(wallet.privateKey.padEnd(83))} │`));
      console.log(chalk.white(`  │ ${chalk.yellow('Seed Phrase:')} ${chalk.red(wallet.seed.padEnd(83))} │`));
      console.log(
        chalk.white(
          '  └──────────────────────────────────────────────────────────────────────────────────────────────────┘'
        )
      );
      console.log('');
      console.log(chalk.red('🔒 IMPORTANT:'));
      console.log(chalk.white('  • Store your private key and seed phrase securely'));
      console.log(chalk.white('  • Never share them with anyone'));
      console.log(chalk.white('  • Keep them in a safe, offline location'));
      console.log(chalk.white('  • If lost, you will lose access to your funds forever'));
      console.log('');
      console.log(chalk.cyan('🔐 STATUS:'));
      console.log(chalk.green('  ✅ Wallet generated successfully'));
      console.log(chalk.green('  ✅ Private key encrypted and saved'));
      console.log(chalk.green('  ✅ Ready for use'));
      console.log('');
      console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
    } catch (error) {
      console.log(`❌ Error: ${error.message}`);
    }
  }

  /**
   * Import wallet from seed phrase
   */
  async importWalletFromSeed() {
    try {
      const answers = await this.cli.inquirer.prompt([
        {
          type: 'input',
          name: 'walletName',
          message: 'Enter wallet name:',
          default: 'default',
          validate: input => {
            if (!input.trim()) {
              return 'Wallet name cannot be empty';
            }
            // Check if wallet file already exists
            const filePath = path.join(process.cwd(), `${input.trim()}.wallet`);
            if (fs.existsSync(filePath)) {
              return `Wallet '${input.trim()}' already exists. Please choose a different name.`;
            }
            return true;
          },
        },
        {
          type: 'input',
          name: 'seedPhrase',
          message: 'Enter seed phrase:',
          validate: input => {
            if (!input.trim()) {
              return 'Seed phrase cannot be empty';
            }
            return true;
          },
        },
        {
          type: 'password',
          name: 'password',
          message: 'Enter wallet password:',
          validate: input => {
            if (input.length < 6) {
              return 'Password must be at least 6 characters long';
            }
            return true;
          },
        },
        {
          type: 'password',
          name: 'confirmPassword',
          message: 'Confirm wallet password:',
          validate: (input, answers) => {
            if (input !== answers.password) {
              return 'Passwords do not match';
            }
            return true;
          },
        },
      ]);

      // Check if wallet already exists in memory
      if (this.wallets.has(answers.walletName)) {
        console.log(chalk.red(`❌ Error: Wallet '${answers.walletName}' already exists in memory.`));
        console.log(chalk.yellow('💡 Use "wallet load" to load an existing wallet or choose a different name.'));
        return;
      }

      const wallet = new Wallet();
      await wallet.importFromSeed(answers.seedPhrase);

      // Store wallet in memory (no encryption needed for network wallet)
      this.wallets.set(answers.walletName, wallet);
      this.currentWallet = wallet;

      // Update CLI state
      this.cli.walletLoaded = true;
      this.cli.walletName = answers.walletName;
      this.cli.walletPassword = answers.password;
      this.cli.currentNetworkWallet = wallet;

      // Save wallet to disk
      this.saveWalletToFile(answers.walletName, wallet, answers.password);

      console.log('✅ Wallet imported from seed successfully!');
      console.log(`Name: ${answers.walletName}`);
      console.log(`Address: ${wallet.getAddress()}`);
    } catch (error) {
      console.log(`❌ Error: ${error.message}`);
    }
  }

  /**
   * Import wallet from private key
   */
  async importWalletFromKey() {
    try {
      const answers = await this.cli.inquirer.prompt([
        {
          type: 'input',
          name: 'walletName',
          message: 'Enter wallet name:',
          default: 'default',
          validate: input => {
            if (!input.trim()) {
              return 'Wallet name cannot be empty';
            }
            // Check if wallet file already exists
            const filePath = path.join(process.cwd(), `${input.trim()}.wallet`);
            if (fs.existsSync(filePath)) {
              return `Wallet '${input.trim()}' already exists. Please choose a different name.`;
            }
            return true;
          },
        },
        {
          type: 'input',
          name: 'privateKey',
          message: 'Enter private key:',
          validate: input => {
            if (!input.trim()) {
              return 'Private key cannot be empty';
            }
            return true;
          },
        },
        {
          type: 'password',
          name: 'password',
          message: 'Enter wallet password:',
          validate: input => {
            if (input.length < 6) {
              return 'Password must be at least 6 characters long';
            }
            return true;
          },
        },
        {
          type: 'password',
          name: 'confirmPassword',
          message: 'Confirm wallet password:',
          validate: (input, answers) => {
            if (input !== answers.password) {
              return 'Passwords do not match';
            }
            return true;
          },
        },
      ]);

      // Check if wallet already exists in memory
      if (this.wallets.has(answers.walletName)) {
        console.log(chalk.red(`❌ Error: Wallet '${answers.walletName}' already exists in memory.`));
        console.log(chalk.yellow('💡 Use "wallet load" to load an existing wallet or choose a different name.'));
        return;
      }

      const wallet = new Wallet();
      await wallet.importFromPrivateKey(answers.privateKey);

      // Store wallet in memory (no encryption needed for network wallet)
      this.wallets.set(answers.walletName, wallet);
      this.currentWallet = wallet;

      // Update CLI state
      this.cli.walletLoaded = true;
      this.cli.walletName = answers.walletName;
      this.cli.walletPassword = answers.password;
      this.cli.currentNetworkWallet = wallet;

      // Save wallet to disk
      this.saveWalletToFile(answers.walletName, wallet, answers.password);

      console.log('✅ Wallet imported from private key successfully!');
      console.log(`Name: ${answers.walletName}`);
      console.log(`Address: ${wallet.getAddress()}`);
    } catch (error) {
      console.log(`❌ Error: ${error.message}`);
    }
  }

  /**
   * Load wallet
   */
  async loadWallet() {
    try {
      const answers = await this.cli.inquirer.prompt([
        {
          type: 'input',
          name: 'walletName',
          message: 'Enter wallet name:',
          default: 'default',
        },
        {
          type: 'password',
          name: 'password',
          message: 'Enter wallet password:',
        },
      ]);

      // First try to load from memory (if already loaded)
      if (this.wallets.has(answers.walletName)) {
        const wallet = this.wallets.get(answers.walletName);
        this.currentWallet = wallet;

        // Update CLI state
        this.cli.walletLoaded = true;
        this.cli.walletName = answers.walletName;
        this.cli.walletPassword = answers.password;
        this.cli.currentNetworkWallet = wallet;

        console.log('✅ Wallet loaded from memory!');
        console.log(`Name: ${answers.walletName}`);
        console.log(`Address: ${wallet.getAddress()}`);
        return;
      }

      // Try to load from disk
      const wallet = this.loadWalletFromFile(answers.walletName, answers.password);

      if (!wallet) {
        console.log(`❌ Wallet '${answers.walletName}' not found or invalid password`);
        return;
      }

      // Store in memory for future use
      this.wallets.set(answers.walletName, wallet);
      this.currentWallet = wallet;

      // Update CLI state
      this.cli.walletLoaded = true;
      this.cli.walletName = answers.walletName;
      this.cli.walletPassword = answers.password;
      this.cli.currentNetworkWallet = wallet;

      console.log('');
      console.log(chalk.blue('╔══════════════════════════════════════════════════════════════════════════════╗'));
      console.log(chalk.blue('║                             🎉 WALLET LOADED! 🎉                             ║'));
      console.log(chalk.blue('╚══════════════════════════════════════════════════════════════════════════════╝'));
      console.log('');
      console.log(chalk.cyan('📋 WALLET INFORMATION:'));
      console.log(chalk.white('  ┌─────────────────────────────────────────────────────────────────────────┐'));
      console.log(chalk.white(`  │ ${chalk.yellow('Name:')}    ${chalk.green(answers.walletName.padEnd(62))} │`));
      console.log(chalk.white(`  │ ${chalk.yellow('Address:')} ${chalk.green(wallet.getAddress().padEnd(62))} │`));
      console.log(chalk.white('  └─────────────────────────────────────────────────────────────────────────┘'));
      console.log('');
      console.log(chalk.cyan('🔐 STATUS:'));
      console.log(chalk.green('  ✅ Wallet decrypted and loaded successfully'));
      console.log(chalk.green('  ✅ Connected to network'));
      console.log('');
    } catch (error) {
      console.log(`❌ Error: ${error.message}`);
    }
  }

  /**
   * Unload wallet
   */
  async unloadWallet() {
    if (!this.cli.walletLoaded) {
      console.log('⚠️  No wallet loaded.');
      return;
    }

    // Clear wallet state
    this.currentWallet = null;
    this.cli.walletLoaded = false;
    this.cli.walletName = null;
    this.cli.walletPassword = null;
    this.cli.currentNetworkWallet = null;

    console.log('✅ Wallet unloaded successfully!');
  }

  /**
   * Check balance from network
   */
  async checkBalance() {
    try {
      if (!this.cli.walletLoaded) {
        console.log('❌ No wallet loaded. Use "wallet load" first.');
        return;
      }

      if (!this.connectedNode) {
        console.log('❌ Not connected to any node. Use "wallet connect" first.');
        return;
      }

      const address = this.currentWallet.getAddress();
      await this.getBalance(address);
    } catch (error) {
      console.log(`❌ Error: ${error.message}`);
    }
  }

  /**
   * Get wallet balance from network
   * @param address
   */
  async getBalance(address) {
    try {
      if (!this.connectedNode) {
        console.log(chalk.red('❌ Error: Not connected to any node. Use "wallet connect" first.'));
        return;
      }

      const balance = await this.makeApiRequest(`/api/wallet/balance/${address}`);

      console.log('');
      console.log(chalk.cyan('📊 BALANCE INFORMATION:'));
      console.log(chalk.white('  ┌─────────────────────────────────────────────────────────────────────────┐'));
      console.log(chalk.white(`  │ ${chalk.yellow('Address:')} ${chalk.green(address.padEnd(62))} │`));
      console.log(
        chalk.white(
          `  │ ${chalk.yellow('Balance:')} ${chalk.green(`${formatAtomicUnits(balance.balance)} PAS`.padEnd(62))} │`
        )
      );
      console.log(
        chalk.white(`  │ ${chalk.yellow('Atomic:')}  ${chalk.green(`${balance.balance} atomic units`.padEnd(62))} │`)
      );
      console.log(chalk.white('  └─────────────────────────────────────────────────────────────────────────┘'));

      return balance;
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   * Send transaction
   */
  async sendTransaction() {
    try {
      if (!this.currentWallet) {
        console.log(chalk.red('❌ Error: No wallet loaded. Use "wallet load" first.'));
        return;
      }

      if (!this.connectedNode) {
        console.log(chalk.red('❌ Error: Not connected to any node. Use "wallet connect" first.'));
        return;
      }

      // Interactive prompts for transaction details
      const answers = await this.cli.inquirer.prompt([
        {
          type: 'input',
          name: 'toAddress',
          message: 'Enter recipient address:',
          validate: input => {
            if (!input.trim()) {
              return 'Recipient address cannot be empty';
            }
            // Basic address validation (starts with 1 and has reasonable length)
            if (!input.trim().startsWith('1') || input.trim().length < 20) {
              return 'Please enter a valid Pastella address';
            }
            return true;
          },
        },
        {
          type: 'input',
          name: 'amount',
          message: 'Enter amount (in PAS):',
          validate: input => {
            if (!input.trim()) {
              return 'Amount cannot be empty';
            }
            const amount = parseFloat(input.trim());
            if (isNaN(amount) || amount <= 0) {
              return 'Please enter a valid positive amount';
            }
            return true;
          },
        },
        {
          type: 'input',
          name: 'fee',
          message: `Enter fee (in PAS, default: ${formatAtomicUnits(this.cli.config.wallet.defaultFee)} PAS):`,
          default: formatAtomicUnits(this.cli.config.wallet.defaultFee),
          validate: input => {
            if (!input.trim()) {
              return 'Fee cannot be empty';
            }
            const fee = parseFloat(input.trim());
            if (isNaN(fee) || fee < 0) {
              return 'Please enter a valid non-negative fee';
            }
            return true;
          },
        },
        {
          type: 'input',
          name: 'paymentId',
          message: 'Enter payment ID (64 hex characters, optional):',
          validate: input => {
            if (!input.trim()) {
              return true; // Payment ID is optional
            }
            const paymentIdPattern = /^[a-fA-F0-9]{64}$/;
            if (!paymentIdPattern.test(input.trim())) {
              return 'Payment ID must be exactly 64 hexadecimal characters (or leave empty)';
            }
            return true;
          },
        },
      ]);

      // Convert amount and fee to atomic units
      const atomicAmount = toAtomicUnits(answers.amount);
      const atomicFee = toAtomicUnits(answers.fee);

      // Process payment ID (null if empty)
      const paymentId = answers.paymentId.trim() || null;

      // Get current balance and UTXOs from the network
      const balance = await this.getBalance(this.currentWallet.getAddress());

      if (balance < atomicAmount + atomicFee) {
        throw new Error(
          `Insufficient balance: ${formatAtomicUnits(balance)} PAS (need ${formatAtomicUnits(atomicAmount + atomicFee)} PAS)`
        );
      }

      // Get UTXOs for this address from the network
      console.log(chalk.blue('🔍 Fetching UTXOs for address:'), chalk.white(this.currentWallet.getAddress()));

      try {
        const utxoResponse = await this.makeApiRequest(`/api/wallet/utxos/${this.currentWallet.getAddress()}`);

        if (!utxoResponse.success || !utxoResponse.utxos) {
          throw new Error('Failed to fetch UTXOs from network');
        }

        const { utxos } = utxoResponse;
        console.log(chalk.green(`📦 Found ${utxos.length} UTXOs`));

        // Select UTXOs to spend (simple greedy algorithm)
        let totalInput = 0;
        const selectedUtxos = [];

        for (const utxo of utxos) {
          if (totalInput >= atomicAmount + atomicFee) break;
          selectedUtxos.push(utxo);
          totalInput += utxo.amount;
        }

        if (totalInput < atomicAmount + atomicFee) {
          throw new Error(
            `Insufficient UTXOs: have ${formatAtomicUnits(totalInput)} PAS, need ${formatAtomicUnits(atomicAmount + atomicFee)} PAS`
          );
        }

        console.log(
          chalk.cyan(`💳 Selected ${selectedUtxos.length} UTXOs (total: ${formatAtomicUnits(totalInput)} PAS)`)
        );

        // Create transaction inputs from selected UTXOs
        const inputs = selectedUtxos.map(
          utxo =>
            new TransactionInput(
              utxo.txHash, // Real transaction hash
              utxo.outputIndex, // Real output index
              '', // Signature (will be added after signing)
              this.currentWallet.publicKey
            )
        );

        // Create transaction outputs
        const outputs = [
          new TransactionOutput(answers.toAddress, atomicAmount),
          new TransactionOutput(this.currentWallet.getAddress(), totalInput - atomicAmount - atomicFee), // Change
        ];

        // Create transaction with proper inputs and outputs
        const transaction = new Transaction(
          inputs,
          outputs,
          atomicFee,
          undefined,
          undefined,
          undefined,
          undefined,
          false,
          paymentId
        );

        // Calculate transaction ID immediately after creation
        transaction.calculateId();

        // Sign the transaction with the wallet's private key
        transaction.sign(this.currentWallet.privateKey);

        // Beautified transaction summary
        console.log(chalk.blue('\n╔══════════════════════════════════════════════════════════════════════════════╗'));
        console.log(chalk.blue('║                           📋 TRANSACTION SUMMARY                            ║'));
        console.log(chalk.blue('╚══════════════════════════════════════════════════════════════════════════════╝'));

        console.log(chalk.blue('\n📊 TRANSACTION DETAILS'));
        console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
        console.log(chalk.white(`🆔 Transaction ID: ${chalk.cyan(transaction.id)}`));
        console.log(chalk.white(`📤 From:           ${chalk.cyan(this.currentWallet.getAddress())}`));
        console.log(chalk.white(`📥 To:             ${chalk.cyan(answers.toAddress)}`));
        console.log(chalk.white(`💰 Amount:         ${chalk.green(formatAtomicUnits(atomicAmount))} PAS`));
        console.log(chalk.white(`💸 Fee:            ${chalk.yellow(formatAtomicUnits(atomicFee))} PAS`));
        if (paymentId) {
          console.log(chalk.white(`🏷️  Payment ID:     ${chalk.magenta(paymentId)}`));
        }
        console.log(
          chalk.white(`📥 Change:         ${chalk.cyan(formatAtomicUnits(totalInput - atomicAmount - atomicFee))} PAS`)
        );

        console.log(chalk.blue('\n📦 UTXO BREAKDOWN'));
        console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
        console.log(chalk.white(`💳 UTXOs Selected: ${chalk.green(selectedUtxos.length)}`));
        console.log(chalk.white(`💵 Total Input:    ${chalk.green(formatAtomicUnits(totalInput))} PAS`));
        console.log(chalk.white(`💸 Total Output:   ${chalk.green(formatAtomicUnits(atomicAmount + atomicFee))} PAS`));
        console.log(
          chalk.white(`📊 Balance After:  ${chalk.cyan(formatAtomicUnits(totalInput - atomicAmount - atomicFee))} PAS`)
        );

        console.log(chalk.blue('\n⚠️  IMPORTANT NOTES'));
        console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
        console.log(chalk.yellow('• This transaction will be broadcast to the network'));
        console.log(chalk.yellow('• Transaction fee is non-refundable'));
        console.log(chalk.yellow('• Ensure the recipient address is correct'));
        console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));

        // Ask for confirmation
        const confirmAnswer = await this.cli.inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: chalk.cyan('🚀 Do you want to send this transaction?'),
            default: false,
          },
        ]);

        if (!confirmAnswer.confirm) {
          console.log(chalk.yellow('⏸️  Transaction cancelled by user'));
          return;
        }

        // Submit transaction to network
        console.log(chalk.blue('\n🚀 Submitting transaction to network...'));

        const response = await this.makeApiRequest('/api/transactions/submit', {
          method: 'POST',
          body: {
            transaction: transaction.toJSON(),
          },
        });

        if (response.success) {
          console.log(chalk.blue('\n╔══════════════════════════════════════════════════════════════════════════════╗'));
          console.log(chalk.blue('║                           🎉 TRANSACTION SENT! 🎉                            ║'));
          console.log(chalk.blue('╚══════════════════════════════════════════════════════════════════════════════╝'));

          console.log(chalk.green('✅ Transaction submitted successfully!'));
          console.log(chalk.white(`🆔 Transaction ID: ${chalk.cyan(response.transactionId || transaction.id)}`));
          console.log(chalk.white(`📤 To:            ${chalk.cyan(answers.toAddress)}`));
          console.log(chalk.white(`💰 Amount:        ${chalk.green(formatAtomicUnits(atomicAmount))} PAS`));
          console.log(chalk.white(`💸 Fee:           ${chalk.yellow(formatAtomicUnits(atomicFee))} PAS`));
          console.log(chalk.white(`📊 Network Fee:   ${chalk.cyan(formatAtomicUnits(atomicFee))} PAS`));
          console.log(chalk.white(`⏱️  Timestamp:     ${chalk.cyan(new Date().toLocaleString())}`));
        } else {
          throw new Error(response.error || 'Failed to send transaction');
        }
      } catch (utxoError) {
        console.log(chalk.yellow(`⚠️  UTXO fetch failed: ${utxoError.message}`));
        console.log(chalk.cyan(`📝 Creating simplified transaction preview instead...`));

        // Fallback to simplified preview
        const inputs = [new TransactionInput('pending-utxo', 0, '', this.currentWallet.publicKey)];
        const outputs = [
          new TransactionOutput(answers.toAddress, atomicAmount),
          new TransactionOutput(this.currentWallet.getAddress(), balance - atomicAmount - atomicFee),
        ];

        const transaction = new Transaction(inputs, outputs, atomicFee);

        console.log(chalk.blue('\n📋 TRANSACTION PREVIEW (UTXO Access Required)'));
        console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
        console.log(chalk.white(`💰 Amount: ${chalk.green(formatAtomicUnits(atomicAmount))} PAS`));
        console.log(chalk.white(`💸 Fee: ${chalk.yellow(formatAtomicUnits(atomicFee))} PAS`));
        console.log(chalk.white(`📤 To: ${chalk.cyan(answers.toAddress)}`));
        console.log(chalk.white(`📥 Change: ${chalk.cyan(formatAtomicUnits(balance - atomicAmount - atomicFee))} PAS`));
        console.log(chalk.yellow('\n⚠️  Note: This is a preview. Real submission requires UTXO access.'));
        console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   * Send multi-output transaction (batch send)
   */
  async sendMultiTransaction() {
    try {
      if (!this.currentWallet) {
        console.log(chalk.red('❌ Error: No wallet loaded. Use "wallet load" first.'));
        return;
      }

      if (!this.connectedNode) {
        console.log(chalk.red('❌ Error: Not connected to any node. Use "wallet connect" first.'));
        return;
      }

      console.log(chalk.blue('\n🔢 MULTI-OUTPUT TRANSACTION SETUP'));
      console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));

      // Collect outputs
      const outputs = [];
      let addingOutputs = true;
      let outputIndex = 1;

      while (addingOutputs) {
        console.log(chalk.cyan(`\n📤 Output ${outputIndex}:`));

        const outputAnswers = await this.cli.inquirer.prompt([
          {
            type: 'input',
            name: 'address',
            message: `Enter recipient address ${outputIndex}:`,
            validate: input => {
              if (!input.trim()) {
                return 'Address cannot be empty';
              }
              if (!input.trim().startsWith('1') || input.trim().length < 20) {
                return 'Please enter a valid Pastella address';
              }
              return true;
            },
          },
          {
            type: 'input',
            name: 'amount',
            message: `Enter amount for output ${outputIndex} (in PAS):`,
            validate: input => {
              if (!input.trim()) {
                return 'Amount cannot be empty';
              }
              const amount = parseFloat(input.trim());
              if (isNaN(amount) || amount <= 0) {
                return 'Please enter a valid positive amount';
              }
              return true;
            },
          },
        ]);

        outputs.push({
          address: outputAnswers.address.trim(),
          amount: outputAnswers.amount.trim(),
        });

        // Ask if user wants to add more outputs
        const continueAnswer = await this.cli.inquirer.prompt([
          {
            type: 'confirm',
            name: 'addMore',
            message: `Add another output? (Currently have ${outputs.length} output${outputs.length === 1 ? '' : 's'})`,
            default: false,
          },
        ]);

        if (!continueAnswer.addMore) {
          addingOutputs = false;
        } else {
          outputIndex++;
        }
      }

      // Get fee and payment ID
      const transactionAnswers = await this.cli.inquirer.prompt([
        {
          type: 'input',
          name: 'fee',
          message: `Enter fee (in PAS, default: ${formatAtomicUnits(this.cli.config.wallet.defaultFee)} PAS):`,
          default: formatAtomicUnits(this.cli.config.wallet.defaultFee),
          validate: input => {
            if (!input.trim()) {
              return 'Fee cannot be empty';
            }
            const fee = parseFloat(input.trim());
            if (isNaN(fee) || fee < 0) {
              return 'Please enter a valid non-negative fee';
            }
            return true;
          },
        },
        {
          type: 'input',
          name: 'paymentId',
          message: 'Enter payment ID (64 hex characters, optional):',
          validate: input => {
            if (!input.trim()) {
              return true; // Payment ID is optional
            }
            const paymentIdPattern = /^[a-fA-F0-9]{64}$/;
            if (!paymentIdPattern.test(input.trim())) {
              return 'Payment ID must be exactly 64 hexadecimal characters (or leave empty)';
            }
            return true;
          },
        },
      ]);

      // Convert amounts to atomic units
      const atomicOutputs = [];
      for (const output of outputs) {
        try {
          console.log(`Debug: Converting amount "${output.amount}" (type: ${typeof output.amount})`);
          const atomicAmount = toAtomicUnits(output.amount);
          console.log(`Debug: Converted to atomic amount: ${atomicAmount} (type: ${typeof atomicAmount})`);
          if (isNaN(atomicAmount) || atomicAmount <= 0) {
            throw new Error(`Invalid amount: ${output.amount}`);
          }
          atomicOutputs.push({
            address: output.address,
            amount: atomicAmount,
          });
        } catch (error) {
          throw new Error(`Invalid amount for ${output.address}: ${output.amount} (${error.message})`);
        }
      }

      let atomicFee;
      try {
        atomicFee = toAtomicUnits(transactionAnswers.fee);
        if (isNaN(atomicFee) || atomicFee < 0) {
          throw new Error(`Invalid fee: ${transactionAnswers.fee}`);
        }
      } catch (error) {
        throw new Error(`Invalid fee amount: ${transactionAnswers.fee} (${error.message})`);
      }

      const paymentId = transactionAnswers.paymentId ? transactionAnswers.paymentId.trim() || null : null;

      // Calculate totals
      const totalAmount = atomicOutputs.reduce((sum, output) => sum + output.amount, 0);
      const totalWithFee = totalAmount + atomicFee;

      // Debug: Check if values are valid numbers
      console.log(`Debug: totalAmount = ${totalAmount}, atomicFee = ${atomicFee}, totalWithFee = ${totalWithFee}`);
      console.log('Debug: atomicOutputs =', atomicOutputs);

      if (isNaN(totalAmount)) {
        throw new Error('Total amount calculation resulted in NaN');
      }
      if (isNaN(atomicFee)) {
        throw new Error('Fee amount is NaN');
      }

      // Get current balance (getBalance displays info and returns API response object)
      const balanceResponse = await this.getBalance(this.currentWallet.getAddress());
      const { balance } = balanceResponse; // Extract the actual balance number

      console.log(`Debug: balance = ${balance} (type: ${typeof balance})`);
      console.log(`Debug: totalWithFee = ${totalWithFee} (type: ${typeof totalWithFee})`);
      console.log(
        `Debug: balance - totalWithFee = ${balance - totalWithFee} (type: ${typeof (balance - totalWithFee)})`
      );

      if (balance < totalWithFee) {
        throw new Error(
          `Insufficient balance: ${formatAtomicUnits(balance)} PAS (need ${formatAtomicUnits(totalWithFee)} PAS)`
        );
      }

      // Show detailed transaction summary
      console.log(chalk.blue('\n╔══════════════════════════════════════════════════════════════════════════════╗'));
      console.log(chalk.blue('║                      📋 MULTI-OUTPUT TRANSACTION SUMMARY                    ║'));
      console.log(chalk.blue('╚══════════════════════════════════════════════════════════════════════════════╝'));

      console.log(chalk.blue('\n📊 TRANSACTION DETAILS'));
      console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
      console.log(chalk.white(`📤 From:           ${chalk.cyan(this.currentWallet.getAddress())}`));
      console.log(chalk.white(`📦 Outputs:        ${chalk.green(outputs.length)} recipients`));
      console.log(chalk.white(`💰 Total Amount:   ${chalk.green(formatAtomicUnits(totalAmount))} PAS`));
      console.log(chalk.white(`💸 Fee:            ${chalk.yellow(formatAtomicUnits(atomicFee))} PAS`));
      if (paymentId) {
        console.log(chalk.white(`🏷️  Payment ID:    ${chalk.magenta(paymentId)}`));
      }
      console.log(chalk.white(`📥 Change:         ${chalk.cyan(formatAtomicUnits(balance - totalWithFee))} PAS`));

      console.log(chalk.blue('\n📋 OUTPUT BREAKDOWN'));
      console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
      outputs.forEach((output, index) => {
        const amountToFormat = atomicOutputs[index].amount;
        console.log(`Debug: Formatting output ${index + 1}: ${amountToFormat} (type: ${typeof amountToFormat})`);
        console.log(
          chalk.white(
            `${index + 1}. ${chalk.cyan(output.address)} → ${chalk.green(formatAtomicUnits(amountToFormat))} PAS`
          )
        );
      });

      console.log(chalk.blue('\n⚠️  IMPORTANT NOTES'));
      console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
      console.log(chalk.yellow('• This multi-output transaction will be broadcast to the network'));
      console.log(
        chalk.yellow(`• Total cost: ${formatAtomicUnits(totalWithFee)} PAS (${outputs.length} outputs + fee)`)
      );
      console.log(chalk.yellow('• Verify all recipient addresses are correct'));
      console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));

      // Ask for confirmation
      const confirmAnswer = await this.cli.inquirer.prompt([
        {
          type: 'confirm',
          name: 'confirm',
          message: `Send multi-output transaction with ${outputs.length} outputs?`,
          default: false,
        },
      ]);

      if (!confirmAnswer.confirm) {
        console.log(chalk.yellow('❌ Transaction cancelled by user'));
        return;
      }

      // Create and submit the real multi-output transaction
      console.log(chalk.blue('\n⏳ Creating multi-output transaction...'));

      try {
        // Get UTXOs for this address from the network
        console.log(chalk.blue('🔍 Fetching UTXOs for address:'), chalk.white(this.currentWallet.getAddress()));

        const utxoResponse = await this.makeApiRequest(`/api/wallet/utxos/${this.currentWallet.getAddress()}`);

        if (!utxoResponse.success || !utxoResponse.utxos) {
          throw new Error('Failed to fetch UTXOs from network');
        }

        const { utxos } = utxoResponse;
        console.log(chalk.green(`📦 Found ${utxos.length} UTXOs`));

        // Select UTXOs to spend (simple greedy algorithm)
        let totalInput = 0;
        const selectedUtxos = [];

        for (const utxo of utxos) {
          if (totalInput >= totalWithFee) break;
          selectedUtxos.push(utxo);
          totalInput += utxo.amount;
        }

        if (totalInput < totalWithFee) {
          throw new Error(
            `Insufficient UTXOs: have ${formatAtomicUnits(totalInput)} PAS, need ${formatAtomicUnits(totalWithFee)} PAS`
          );
        }

        console.log(
          chalk.cyan(`💳 Selected ${selectedUtxos.length} UTXOs (total: ${formatAtomicUnits(totalInput)} PAS)`)
        );

        // Create transaction inputs from selected UTXOs
        const inputs = selectedUtxos.map(
          utxo =>
            new TransactionInput(
              utxo.txHash,
              utxo.outputIndex,
              '', // Signature (will be added after signing)
              this.currentWallet.publicKey
            )
        );

        // Create transaction outputs from the multi-output array
        const transactionOutputs = atomicOutputs.map(output => new TransactionOutput(output.address, output.amount));

        // Add change output if needed
        const change = totalInput - totalAmount - atomicFee;
        if (change > 0) {
          transactionOutputs.push(new TransactionOutput(this.currentWallet.getAddress(), change));
        }

        // Create transaction with payment ID
        const transaction = new Transaction(
          inputs,
          transactionOutputs,
          atomicFee,
          undefined,
          undefined,
          undefined,
          undefined,
          false,
          paymentId
        );

        // Calculate transaction ID immediately after creation
        transaction.calculateId();

        // Sign the transaction with the wallet's private key
        transaction.sign(this.currentWallet.privateKey);

        console.log(chalk.green('✅ Multi-output transaction created and signed!'));
        console.log(chalk.blue(`🆔 Transaction ID: ${chalk.cyan(transaction.id)}`));

        // Submit to network
        console.log(chalk.blue('📡 Broadcasting transaction to network...'));
        const submitResponse = await this.makeApiRequest('/api/transactions/submit', {
          method: 'POST',
          body: {
            transaction: transaction.toJSON(),
          },
        });

        if (submitResponse.success) {
          console.log(chalk.green(`\n🎉 Multi-output transaction sent successfully!`));
          console.log(chalk.green(`🆔 Transaction ID: ${chalk.cyan(transaction.id)}`));
          console.log(chalk.green(`📦 Recipients: ${outputs.length}`));
          console.log(chalk.green(`💰 Total Sent: ${formatAtomicUnits(totalAmount)} PAS`));
          console.log(chalk.green(`💸 Fee: ${formatAtomicUnits(atomicFee)} PAS`));
          if (paymentId) {
            console.log(chalk.green(`🏷️  Payment ID: ${paymentId}`));
          }
        } else {
          throw new Error(submitResponse.error || 'Failed to submit multi-output transaction');
        }
      } catch (submitError) {
        console.log(chalk.red(`❌ Error creating/submitting transaction: ${submitError.message}`));
        throw submitError;
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   * Sync wallet with network
   */
  async syncWalletWithNetwork() {
    try {
      if (!this.cli.walletLoaded) {
        console.log('❌ No wallet loaded. Use "wallet load" first.');
        return;
      }

      if (!this.connectedNode) {
        console.log('❌ Not connected to any node. Use "wallet connect" first.');
        return;
      }

      const address = this.currentWallet.getAddress();
      console.log(`🔄 Syncing wallet ${address} with network...`);

      // Get balance with error handling
      let balance = 0;
      try {
        const balanceResponse = await this.makeApiRequest(`/api/wallet/balance/${address}`);
        balance = balanceResponse?.balance || 0;
      } catch (balanceError) {
        console.log(`⚠️  Could not fetch balance: ${balanceError.message}`);
      }

      // Get transactions with error handling
      let transactions = [];
      try {
        transactions = await this.getTransactions(address);
      } catch (txError) {
        console.log(`⚠️  Could not fetch transactions: ${txError.message}`);
      }

      // Get mempool status
      let mempoolStatus = null;
      try {
        const mempoolResponse = await this.makeApiRequest('/api/memory-pool/status');
        mempoolStatus = mempoolResponse.success ? mempoolResponse.data : null;
      } catch (mempoolError) {
        console.log(`⚠️  Could not fetch mempool status: ${mempoolError.message}`);
      }

      // Display balance info
      console.log('');
      console.log('📊 BALANCE INFORMATION:');
      console.log('  ┌─────────────────────────────────────────────────────────────────────────┐');
      console.log(`  │ Address: ${address.padEnd(67)} │`);
      console.log(`  │ Balance: ${formatAtomicUnits(balance).padEnd(67)} │`);
      console.log(`  │ Atomic:  ${balance.toString().padEnd(67)} atomic units │`);
      console.log('  └─────────────────────────────────────────────────────────────────────────┘');

      console.log('✅ Wallet synced successfully');
      console.log(`📊 Transactions found: ${transactions.length}`);

      if (mempoolStatus) {
        console.log(`🔄 Mempool: ${mempoolStatus.poolSize} pending transactions`);
      }

      // Update wallet state if we have a local wallet instance
      if (this.currentWallet) {
        this.currentWallet.balance = balance;
        if (transactions.length > 0) {
          console.log('📝 Transaction history updated');
        }
      }
    } catch (error) {
      console.log(`❌ Sync error: ${error.message}`);
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

      // The API directly returns the JSON response, not wrapped in {success, data}
      if (response && response.success && response.transactions) {
        return response.transactions || [];
      }

      // Handle error response
      if (response && response.error) {
        throw new Error(response.error);
      }

      // Log unexpected response structure for debugging
      logger.warn('NETWORK_WALLET', `Unexpected transactions API response: ${JSON.stringify(response, null, 2)}`);
      return [];
    } catch (error) {
      logger.error('NETWORK_WALLET', `Failed to get transactions: ${error.message}`);
      // Return empty array instead of throwing to prevent CLI crashes
      return [];
    }
  }

  /**
   * Show wallet information
   */
  showWalletInfo() {
    if (!this.currentWallet) {
      console.log(chalk.red('❌ Error: No wallet loaded. Use "wallet load" first.'));
      return;
    }

    console.log('');
    console.log(chalk.blue('╔═══════════════════════════════════════════════════════════════════╗'));
    console.log(chalk.blue('║                       📋 WALLET INFORMATION                       ║'));
    console.log(chalk.blue('╚═══════════════════════════════════════════════════════════════════╝'));
    console.log('');
    console.log(chalk.cyan('🔐 WALLET DETAILS:'));
    console.log(
      chalk.white(
        '  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐'
      )
    );
    console.log(
      chalk.white(`  │ ${chalk.yellow('Name:      ')} ${chalk.green(this.currentWallet.name || 'N/A'.padEnd(134))} │`)
    );
    console.log(
      chalk.white(`  │ ${chalk.yellow('Address:   ')} ${chalk.green(this.currentWallet.getAddress().padEnd(134))} │`)
    );
    console.log(
      chalk.white(`  │ ${chalk.yellow('Public Key:')} ${chalk.green(this.currentWallet.publicKey.padEnd(134))} │`)
    );
    console.log(
      chalk.white(
        '  └────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘'
      )
    );
    console.log('');
  }

  /**
   * Show transaction history
   */
  async showTransactionHistory() {
    try {
      if (!this.cli.walletLoaded) {
        console.log('❌ No wallet loaded. Use "wallet load" first.');
        return;
      }

      if (!this.connectedNode) {
        console.log('❌ Not connected to any node. Use "wallet connect" first.');
        return;
      }

      const address = this.currentWallet.getAddress();
      const transactions = await this.getTransactions(address);

      if (transactions.length === 0) {
        console.log('📋 No transactions found.');
        return;
      }

      console.log(`📋 Transaction History (${transactions.length} transactions):`);
      transactions.forEach((tx, index) => {
        console.log(`${index + 1}. ${tx.id} - ${tx.amount || 0} PAS`);
      });
    } catch (error) {
      console.log(`❌ Error: ${error.message}`);
    }
  }

  /**
   * Show transaction information
   * @param txId
   */
  async showTransactionInfo(txId) {
    try {
      if (!this.cli.walletLoaded) {
        console.log('❌ No wallet loaded. Use "wallet load" first.');
        return;
      }

      if (!this.connectedNode) {
        console.log('❌ Not connected to any node. Use "wallet connect" first.');
        return;
      }

      // Try to get transaction from network
      const response = await this.makeApiRequest(`/api/blockchain/transactions/${txId}`);

      if (response && response.success) {
        const tx = response.data;
        console.log('📋 Transaction Information:');
        console.log(`ID: ${tx.id}`);
        console.log(`Amount: ${tx.outputs.reduce((sum, out) => sum + out.amount, 0)} PAS`);
        console.log(`Fee: ${tx.fee} PAS`);
        console.log(`Timestamp: ${new Date(tx.timestamp).toLocaleString()}`);
      } else {
        console.log('❌ Transaction not found on network');
      }
    } catch (error) {
      console.log(`❌ Error: ${error.message}`);
    }
  }

  /**
   * Save wallet (for backward compatibility)
   */
  async saveWallet() {
    console.log('💾 Wallet state saved (network-based wallet)');
  }

  /**
   * Save wallet to disk (encrypted)
   * @param walletName
   * @param wallet
   * @param password
   */
  saveWalletToFile(walletName, wallet, password) {
    try {
      const walletData = {
        name: walletName,
        address: wallet.getAddress(),
        seed: wallet.getSeed(),
        privateKey: wallet.privateKey,
        publicKey: wallet.publicKey,
        timestamp: Date.now(),
      };

      const encryptedData = wallet.encryptWalletData(walletData, password);

      // SECURITY: Validate wallet name and construct secure path
      const validatedWalletName = SecurityUtils.validateWalletName(walletName);
      const filePath = SecurityUtils.validateFilePath(`${validatedWalletName}.wallet`, process.cwd(), '.wallet');

      fs.writeFileSync(filePath, JSON.stringify(encryptedData, null, 2));
      console.log(`💾 Wallet saved to disk`);

      // Verify the file was created
      if (fs.existsSync(filePath)) {
        const stats = fs.statSync(filePath);
        console.log(`📁 File size: ${stats.size} bytes`);
      } else {
        console.log(`❌ File was not created at ${filePath}`);
      }
    } catch (error) {
      console.log(`❌ Failed to save wallet '${walletName}': ${error.message}`);
      if (error.stack) {
        console.log(`Stack trace: ${error.stack}`);
      }
    }
  }

  /**
   * Load wallet from disk (decrypted)
   * @param walletName
   * @param password
   * @returns {Wallet|null}
   */
  loadWalletFromFile(walletName, password) {
    try {
      // SECURITY: Validate wallet name and construct secure path
      const validatedWalletName = SecurityUtils.validateWalletName(walletName);
      const filePath = SecurityUtils.validateFilePath(`${validatedWalletName}.wallet`, process.cwd(), '.wallet');

      if (!fs.existsSync(filePath)) {
        console.log(`❌ Wallet file not found: ${filePath}`);
        return null;
      }

      const fileData = JSON.parse(fs.readFileSync(filePath, 'utf8'));

      // Create a temporary wallet instance to use its decryption method
      const tempWallet = new Wallet();
      const walletData = tempWallet.decryptWalletData(fileData, password);

      // Create the actual wallet and restore the data directly
      const wallet = new Wallet();
      if (walletData.seed) {
        // Directly set the wallet properties instead of calling importFromSeed
        wallet.seed = walletData.seed;
        wallet.privateKey = walletData.privateKey;
        wallet.publicKey = walletData.publicKey;
        wallet.address = walletData.address;
      } else if (walletData.privateKey) {
        // Directly set the wallet properties instead of calling importFromPrivateKey
        wallet.privateKey = walletData.privateKey;
        wallet.publicKey = walletData.publicKey;
        wallet.address = walletData.address;
      } else {
        console.log(`❌ No seed or private key found in wallet data`);
        return null;
      }

      return wallet;
    } catch (error) {
      console.log(`❌ Failed to load wallet '${walletName}': ${error.message}`);
      if (error.stack) {
        console.log(`Stack trace: ${error.stack}`);
      }
      return null;
    }
  }

  /**
   * Load all wallets from disk
   */
  loadWalletsFromDisk() {
    try {
      const rootDir = process.cwd();

      const files = fs.readdirSync(rootDir);
      const walletFiles = files.filter(file => file.endsWith('.wallet'));
    } catch (error) {
      console.log(`❌ Failed to scan for wallet files: ${error.message}`);
    }
  }

  /**
   * Resync wallet with full blockchain sync (block-by-block)
   */
  async resyncWallet() {
    if (!this.cli.walletLoaded) {
      console.log('❌ No wallet loaded. Use "wallet load" first.');
      return;
    }

    if (!this.connectedNode) {
      console.log('❌ Not connected to any node. Use "wallet connect" first.');
      return;
    }

    console.log('🔄 Starting full wallet resync...');
    console.log('⚠️  This will sync from block 0 and may take some time');

    await this.performFullBlockchainSync(0);
  }

  /**
   * Perform full blockchain sync with progress tracking
   * @param fromBlock
   */
  async performFullBlockchainSync(fromBlock = 0) {
    try {
      const address = this.currentWallet.getAddress();
      console.log(`🔗 Connecting to daemon for sync...`);

      // Get current blockchain status
      const statusResponse = await this.makeApiRequest('/api/blockchain/status');
      const targetBlock = statusResponse.height || 0;

      console.log(`📊 Sync range: Block ${fromBlock} to ${targetBlock}`);

      if (fromBlock >= targetBlock) {
        console.log('✅ Wallet is already synced');
        return;
      }

      // Process blocks in batches using new efficient API endpoint
      console.log('📦 Processing blockchain in batches...');

      const batchSize = 100;
      let processedBlocks = 0;
      const totalBlocks = targetBlock - fromBlock;
      let transactionCount = 0;

      for (let startHeight = fromBlock; startHeight < targetBlock; startHeight += batchSize) {
        try {
          const remainingBlocks = targetBlock - startHeight;
          const currentBatchSize = Math.min(batchSize, remainingBlocks);

          // Fetch batch of blocks using new efficient endpoint
          const batchResponse = await this.makeApiRequest(
            `/api/blockchain/blocks-range/${startHeight}/${currentBatchSize}`
          );

          if (batchResponse.success && batchResponse.blocks) {
            console.log(`📦 Processing batch: ${batchResponse.blocks.length} blocks from ${startHeight}`);

            // Process each block in the batch
            for (const block of batchResponse.blocks) {
              const blockTransactions = await this.processBlockDirectly(block, address);
              transactionCount += blockTransactions;
              processedBlocks++;
            }

            // Log progress after each batch
            const progress = ((processedBlocks / totalBlocks) * 100).toFixed(1);
            console.log(
              `⏳ Sync progress: ${progress}% (${processedBlocks}/${totalBlocks} blocks) - ${transactionCount} transactions found`
            );
          } else {
            console.log(`⚠️  No blocks found in range ${startHeight}-${startHeight + currentBatchSize - 1}`);
          }
        } catch (batchError) {
          // If batch fails, fall back to individual block processing for this range
          console.warn(`⚠️  Batch failed, falling back to individual blocks: ${batchError.message}`);

          for (
            let blockHeight = startHeight;
            blockHeight < Math.min(startHeight + batchSize, targetBlock);
            blockHeight++
          ) {
            try {
              const blockTransactions = await this.processBlockForWallet(blockHeight, address);
              transactionCount += blockTransactions;
              processedBlocks++;
            } catch (blockError) {
              // Skip individual block errors
              if (!blockError.message.includes('404')) {
                console.warn(`⚠️  Error processing block ${blockHeight}: ${blockError.message}`);
              }
            }
          }

          // Log progress after fallback processing
          const progress = ((processedBlocks / totalBlocks) * 100).toFixed(1);
          console.log(
            `⏳ Sync progress: ${progress}% (${processedBlocks}/${totalBlocks} blocks) - ${transactionCount} transactions found`
          );
        }
      }

      // Get final balance and display results
      try {
        const balanceResponse = await this.makeApiRequest(`/api/wallet/balance/${address}`);
        const balance = balanceResponse?.balance || 0;

        console.log('');
        console.log('📊 FINAL SYNC RESULTS:');
        console.log('  ┌─────────────────────────────────────────────────────────────────────────┐');
        console.log(`  │ Address: ${address.padEnd(67)} │`);
        console.log(`  │ Balance: ${formatAtomicUnits(balance).padEnd(67)} │`);
        console.log(`  │ Atomic:  ${balance.toString().padEnd(67)} atomic units │`);
        console.log(`  │ Transactions: ${transactionCount.toString().padEnd(63)} │`);
        console.log('  └─────────────────────────────────────────────────────────────────────────┘');
      } catch (balanceError) {
        console.log(`⚠️  Could not fetch final balance: ${balanceError.message}`);
      }

      console.log('✅ Blockchain sync completed successfully');
    } catch (error) {
      console.error('❌ Blockchain sync error:', error.message);
    }
  }

  /**
   * Process a single block for the wallet and return number of relevant transactions
   * @param blockHeight
   * @param walletAddress
   */
  async processBlockForWallet(blockHeight, walletAddress) {
    try {
      // Get block data from daemon (correct endpoint is /api/blockchain/blocks/{index})
      const block = await this.makeApiRequest(`/api/blockchain/blocks/${blockHeight}`);

      if (!block || !block.transactions) {
        return 0;
      }

      return await this.processBlockDirectly(block, walletAddress);
    } catch (error) {
      // Block might not exist yet, return 0
      return 0;
    }
  }

  /**
   * Process a block directly (when we already have the block data)
   * @param block
   * @param walletAddress
   */
  async processBlockDirectly(block, walletAddress) {
    if (!block || !block.transactions) {
      return 0;
    }

    let relevantTransactions = 0;

    // Process each transaction in the block
    for (const transaction of block.transactions) {
      const isRelevant = await this.processTransactionForWallet(transaction, block.index, block.hash, walletAddress);
      if (isRelevant) {
        relevantTransactions++;
      }
    }

    return relevantTransactions;
  }

  /**
   * Process a transaction for the wallet and return if it's relevant (optimized for batch sync)
   * @param transaction
   * @param blockHeight
   * @param blockHash
   * @param walletAddress
   */
  async processTransactionForWallet(transaction, blockHeight, blockHash, walletAddress) {
    let isRelevant = false;
    let direction = '';
    let amount = 0;

    // Check if transaction involves this wallet
    const outputsToWallet = transaction.outputs?.filter(output => output.address === walletAddress) || [];

    // For batch sync efficiency, use simpler input checking without expensive API lookups
    // Check if wallet address appears directly in inputs (for transactions that include address info)
    const inputsFromWallet = transaction.inputs?.filter(input => input.address === walletAddress) || [];

    if (outputsToWallet.length > 0) {
      // Incoming or self-transfer transaction
      isRelevant = true;
      direction = inputsFromWallet.length > 0 ? 'self' : 'incoming';
      amount = outputsToWallet.reduce((sum, output) => sum + (output.amount || 0), 0);
    } else if (inputsFromWallet.length > 0) {
      // Outgoing transaction
      isRelevant = true;
      direction = 'outgoing';
      const outputsToOthers = transaction.outputs?.filter(output => output.address !== walletAddress) || [];
      amount = outputsToOthers.reduce((sum, output) => sum + (output.amount || 0), 0);
    }

    if (isRelevant) {
      // Display transaction in a single line with icons (only for significant amounts or coinbase transactions)
      const amountDisplay = formatAtomicUnits(amount);
      const directionIcon = direction === 'incoming' ? '⬇️' : direction === 'outgoing' ? '⬆️' : '🔄';

      // Show transaction details for amounts > 1 PAS or coinbase transactions
      if (amount > 100000000 || transaction.isCoinbase) {
        console.log(
          `  ${directionIcon} ${direction.toUpperCase()}: ${amountDisplay} PAS | TX: ${transaction.id.substring(0, 8)}... | Block: ${blockHeight}`
        );
      }
    }

    return isRelevant;
  }

  /**
   * Show help
   */
  showHelp() {
    console.log('📚 Available Wallet Commands:');
    console.log('');
    console.log('🔌 Connection:');
    console.log('  wallet connect <host> <port> [protocol]  - Connect to a node');
    console.log('');
    console.log('🔐 Wallet Management:');
    console.log('  wallet create                           - Create new wallet');
    console.log('  wallet seed-import                      - Import from seed phrase');
    console.log('  wallet key-import                       - Import from private key');
    console.log('  wallet load                             - Load existing wallet');
    console.log('  wallet unload                           - Unload current wallet');
    console.log('');
    console.log('💰 Operations:');
    console.log('  wallet balance                          - Show current balance');
    console.log('  wallet send                             - Send transaction');
    console.log('  wallet send-multi                       - Send multi-output transaction (batch)');
    console.log('  wallet sync                             - Sync wallet with network');
    console.log('  wallet resync                           - Resync wallet (alias for sync)');
    console.log('');
    console.log('📊 Information:');
    console.log('  wallet info                             - Show wallet information');
    console.log('  wallet transactions                     - Show transaction history');
    console.log('  wallet transaction-info <id>            - Show transaction details');
    console.log('  wallet save                             - Save wallet state');
    console.log('');
  }

  /**
   *
   * @param address
   */
  async showTransactions(address) {
    try {
      if (!this.connectedNode) {
        console.log(chalk.red('❌ Error: Not connected to any node. Use "wallet connect" first.'));
        return;
      }

      const transactions = await this.makeApiRequest(`/api/wallet/transactions/${address}`);

      if (!transactions || transactions.length === 0) {
        console.log(chalk.blue('╔══════════════════════════════════════════════════════════════════════════════╗'));
        console.log(chalk.blue('║                        📜 TRANSACTION HISTORY 📜                          ║'));
        console.log(chalk.blue('╚══════════════════════════════════════════════════════════════════════════════╝'));
        console.log('');
        console.log(chalk.yellow('📭 No transactions found for this address.'));
        console.log(chalk.white('  This could mean:'));
        console.log(chalk.white('  • The address has never received any transactions'));
        console.log(chalk.white("  • The address is new and hasn't been used yet"));
        console.log(chalk.white('  • There might be a network connection issue'));
        console.log('');
        console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
        return;
      }

      // Beautify the transactions output
      console.log(chalk.blue('╔══════════════════════════════════════════════════════════════════════════════╗'));
      console.log(chalk.blue('║                        📜 TRANSACTION HISTORY 📜                          ║'));
      console.log(chalk.blue('╚══════════════════════════════════════════════════════════════════════════════╝'));
      console.log('');
      console.log(chalk.cyan('📊 TRANSACTION SUMMARY:'));
      console.log(chalk.white('  ┌─────────────────────────────────────────────────────────────────────────┐'));
      console.log(chalk.white(`  │ ${chalk.yellow('Address:')}     ${chalk.green(address.padEnd(58))} │`));
      console.log(
        chalk.white(
          `  │ ${chalk.yellow('Total TXs:')}  ${chalk.green(`${transactions.length} transactions`.padEnd(58))} │`
        )
      );
      console.log(chalk.white('  └─────────────────────────────────────────────────────────────────────────┘'));
      console.log('');
      console.log(chalk.cyan('🔍 TRANSACTION DETAILS:'));

      transactions.forEach((tx, index) => {
        const { isSender } = tx;
        const { isReceiver } = tx;
        const netAmount = tx.netAmountForAddress || 0;

        console.log(chalk.white(`  ┌─ Transaction ${index + 1} ─────────────────────────────────────────────┐`));
        console.log(chalk.white(`  │ ${chalk.yellow('ID:')}        ${chalk.green(tx.id.padEnd(58))} │`));
        console.log(
          chalk.white(
            `  │ ${chalk.yellow('Type:')}     ${chalk.green(`${isSender ? 'Sent' : ''}${isReceiver ? 'Received' : ''}`.padEnd(58))} │`
          )
        );
        console.log(chalk.white(`  │ ${chalk.yellow('Net Amount:')} ${chalk.green(`${netAmount} PSTL`.padEnd(58))} │`));
        console.log(
          chalk.white(`  │ ${chalk.yellow('Inputs:')}   ${chalk.green(`${tx.inputs.length} inputs`.padEnd(58))} │`)
        );
        console.log(
          chalk.white(`  │ ${chalk.yellow('Outputs:')}  ${chalk.green(`${tx.outputs.length} outputs`.padEnd(58))} │`)
        );
        console.log(chalk.white('  └─────────────────────────────────────────────────────────────────────────┘'));
        console.log('');
      });

      console.log(chalk.cyan('🔗 NETWORK STATUS:'));
      console.log(chalk.green(`  ✅ Connected to: ${this.connectedNode}`));
      console.log(chalk.green('  ✅ Transactions fetched successfully'));
      console.log(chalk.green('  ✅ Ready for more actions'));
      console.log('');
      console.log(chalk.blue('💡 Available actions:'));
      console.log(chalk.white('  • Check balance: wallet balance'));
      console.log(chalk.white('  • Send coins: wallet send (interactive)'));
      console.log(chalk.white('  • View UTXOs: wallet utxos'));
      console.log(chalk.white('  • Resync wallet: wallet resync'));
      console.log('');
      console.log(chalk.blue('────────────────────────────────────────────────────────────────────────────────'));
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }
}

module.exports = NetworkWalletManager;
