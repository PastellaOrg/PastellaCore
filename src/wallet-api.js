/**
 * Pastella Wallet API Server
 * Comprehensive wallet management API for exchanges and third-party integration
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const cors = require('cors');
const express = require('express');
const helmet = require('helmet');

// Import wallet functions
const logger = require('./utils/logger');
const WalletFunctions = require('./wallet-api/functions/WalletFunctions');
const { authMiddleware } = require('./wallet-api/middleware/auth');

/**
 *
 */
class WalletAPIServer {
  /**
   *
   * @param config
   */
  constructor(config = {}) {
    this.config = {
      port: config.port || 3001,
      host: config.host || '127.0.0.1',
      apiKey: config.apiKey || this.generateAPIKey(),
      cors: config.cors || false,
      // Daemon connection settings
      daemonHost: config.daemonHost || 'localhost',
      daemonPort: config.daemonPort || 22000,
      daemonApiKey: config.daemonApiKey || null,
      daemonTimeout: config.daemonTimeout || 30000,
      ...config,
    };

    this.app = express();
    this.walletFunctions = new WalletFunctions({
      daemonHost: this.config.daemonHost,
      daemonPort: this.config.daemonPort,
      daemonApiKey: this.config.daemonApiKey,
      daemonTimeout: this.config.daemonTimeout,
    });
    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   *
   */
  generateAPIKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   *
   */
  setupMiddleware() {
    // Security middleware
    this.app.use(helmet());

    // CORS
    if (this.config.cors) {
      this.app.use(cors());
    }

    // Body parser
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Request logging
    this.app.use((req, res, next) => {
      logger.info('WALLET_API', `${req.method} ${req.path} - ${req.ip}`);
      next();
    });

    // API key authentication middleware
    this.app.use('/api', authMiddleware(this.config.apiKey));
  }

  /**
   *
   */
  setupRoutes() {
    // Health check (no auth required)
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: Date.now(),
        version: '1.0.0',
      });
    });

    // API info (no auth required)
    this.app.get('/info', (req, res) => {
      res.json({
        name: 'Pastella Wallet API',
        version: '1.0.0',
        description: 'Comprehensive wallet management API for exchanges and third-party integration',
        endpoints: [
          'POST /api/wallet/create',
          'POST /api/wallet/load',
          'POST /api/wallet/unload',
          'POST /api/wallet/backup',
          'GET /api/wallet/info',
          'GET /api/wallet/balance/:walletName',
          'GET /api/wallet/balances',
          'GET /api/wallet/address/new/:walletName',
          'GET /api/wallet/transaction/:txId',
          'GET /api/wallet/transactions/:walletName',
          'POST /api/wallet/send',
          'POST /api/wallet/send-multi',
          'POST /api/wallet/import/privkey',
          'POST /api/wallet/dump/privkey',
        ],
      });
    });

    // Wallet Management Endpoints
    this.setupWalletRoutes();
  }

  /**
   *
   */
  setupWalletRoutes() {
    const router = express.Router();

    // Create new wallet
    router.post('/wallet/create', async (req, res) => {
      try {
        const { walletName, password, seed } = req.body;

        if (!walletName || !password) {
          return res.status(400).json({ error: 'walletName and password are required' });
        }

        const result = await this.walletFunctions.createWallet(walletName, password, seed);
        res.json(result);
      } catch (error) {
        logger.error(`Error creating wallet: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Load existing wallet
    router.post('/wallet/load', async (req, res) => {
      try {
        const { walletName, password } = req.body;

        if (!walletName || !password) {
          return res.status(400).json({ error: 'walletName and password are required' });
        }

        const result = await this.walletFunctions.loadWallet(walletName, password);
        res.json(result);
      } catch (error) {
        logger.error(`Error loading wallet: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Unload wallet
    router.post('/wallet/unload', async (req, res) => {
      try {
        const { walletName } = req.body;

        if (!walletName) {
          return res.status(400).json({ error: 'walletName is required' });
        }

        const result = await this.walletFunctions.unloadWallet(walletName);
        res.json(result);
      } catch (error) {
        logger.error(`Error unloading wallet: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Backup wallet
    router.post('/wallet/backup', async (req, res) => {
      try {
        const { walletName, backupPath } = req.body;

        if (!walletName) {
          return res.status(400).json({ error: 'walletName is required' });
        }

        const result = await this.walletFunctions.backupWallet(walletName, backupPath);
        res.json(result);
      } catch (error) {
        logger.error(`Error backing up wallet: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Get wallet info
    router.get('/wallet/info/:walletName', async (req, res) => {
      try {
        const { walletName } = req.params;
        const result = await this.walletFunctions.getWalletInfo(walletName);
        res.json(result);
      } catch (error) {
        logger.error(`Error getting wallet info: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Get wallet balance
    router.get('/wallet/balance/:walletName', async (req, res) => {
      try {
        const { walletName } = req.params;
        const result = await this.walletFunctions.getBalance(walletName);
        res.json(result);
      } catch (error) {
        logger.error(`Error getting wallet balance: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Get all wallet balances
    router.get('/wallet/balances', async (req, res) => {
      try {
        const result = await this.walletFunctions.getBalances();
        res.json(result);
      } catch (error) {
        logger.error(`Error getting wallet balances: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Generate new address
    router.get('/wallet/address/new/:walletName', async (req, res) => {
      try {
        const { walletName } = req.params;
        const result = await this.walletFunctions.getNewAddress(walletName);
        res.json(result);
      } catch (error) {
        logger.error(`Error generating new address: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Get transaction by ID
    router.get('/wallet/transaction/:txId', async (req, res) => {
      try {
        const { txId } = req.params;
        const result = await this.walletFunctions.getTransaction(txId);
        res.json(result);
      } catch (error) {
        logger.error(`Error getting transaction: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Get wallet transactions
    router.get('/wallet/transactions/:walletName', async (req, res) => {
      try {
        const { walletName } = req.params;
        const { limit = 50, offset = 0 } = req.query;
        const result = await this.walletFunctions.getTransactions(walletName, parseInt(limit), parseInt(offset));
        res.json(result);
      } catch (error) {
        logger.error(`Error getting wallet transactions: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Send transaction
    router.post('/wallet/send', async (req, res) => {
      try {
        const { walletName, toAddress, amount, fee, tag, paymentId } = req.body;

        if (!walletName || !toAddress || !amount) {
          return res.status(400).json({
            error:
              'walletName, toAddress, and amount are required. Amount and fee must be in atomic units (e.g., 100000000 = 1 PAS)',
          });
        }

        // Validate amount is numeric and positive
        const atomicAmount = parseInt(amount);
        if (isNaN(atomicAmount) || atomicAmount <= 0) {
          return res.status(400).json({
            error: 'amount must be a positive integer in atomic units (e.g., 100000000 = 1 PAS)',
          });
        }

        // Validate payment ID if provided
        if (paymentId && paymentId.trim()) {
          const paymentIdPattern = /^[a-fA-F0-9]{64}$/;
          if (!paymentIdPattern.test(paymentId.trim())) {
            return res.status(400).json({
              error: 'paymentId must be exactly 64 hexadecimal characters',
            });
          }
        }

        const result = await this.walletFunctions.sendTransaction(walletName, toAddress, amount, fee, tag, paymentId);
        res.json(result);
      } catch (error) {
        logger.error('WALLET_API', `Error sending transaction: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Send multi-output transaction (batch send to multiple addresses)
    router.post('/wallet/send-multi', async (req, res) => {
      try {
        const { walletName, outputs, fee, tag, paymentId } = req.body;

        if (!walletName || !outputs || !Array.isArray(outputs) || outputs.length === 0) {
          return res.status(400).json({
            error:
              'walletName and outputs array are required. outputs must be array of {address, amount} objects. Amount and fee must be in atomic units (e.g., 100000000 = 1 PAS)',
          });
        }

        // Validate outputs array structure
        for (let i = 0; i < outputs.length; i++) {
          const output = outputs[i];
          if (!output.address || !output.amount) {
            return res.status(400).json({
              error: `Output ${i + 1}: Both address and amount are required`,
            });
          }

          // Validate amount is numeric and positive
          const atomicAmount = typeof output.amount === 'string' ? parseFloat(output.amount) : output.amount;
          if (isNaN(atomicAmount) || atomicAmount <= 0) {
            return res.status(400).json({
              error: `Output ${i + 1}: amount must be a positive number in atomic units (e.g., 100000000 = 1 PAS)`,
            });
          }
        }

        // Validate payment ID if provided
        if (paymentId && paymentId.trim()) {
          const paymentIdPattern = /^[a-fA-F0-9]{64}$/;
          if (!paymentIdPattern.test(paymentId.trim())) {
            return res.status(400).json({
              error: 'paymentId must be exactly 64 hexadecimal characters',
            });
          }
        }

        const result = await this.walletFunctions.sendMultiTransaction(walletName, outputs, fee, tag, paymentId);
        res.json(result);
      } catch (error) {
        logger.error('WALLET_API', `Error sending multi-output transaction: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Import private key
    router.post('/wallet/import/privkey', async (req, res) => {
      try {
        const { walletName, privateKey, password } = req.body;

        if (!walletName || !privateKey || !password) {
          return res.status(400).json({ error: 'walletName, privateKey, and password are required' });
        }

        const result = await this.walletFunctions.importPrivKey(walletName, privateKey, password);
        res.json(result);
      } catch (error) {
        logger.error(`Error importing private key: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    // Dump private key
    router.post('/wallet/dump/privkey', async (req, res) => {
      try {
        const { walletName, password } = req.body;

        if (!walletName || !password) {
          return res.status(400).json({ error: 'walletName and password are required' });
        }

        const result = await this.walletFunctions.dumpPrivKey(walletName, password);
        res.json(result);
      } catch (error) {
        logger.error(`Error dumping private key: ${error.message}`);
        res.status(500).json({ error: error.message });
      }
    });

    this.app.use('/api', router);
  }

  /**
   *
   */
  start() {
    return new Promise((resolve, reject) => {
      try {
        this.server = this.app.listen(this.config.port, this.config.host, () => {
          logger.info('WALLET_API', `Pastella Wallet API Server started on ${this.config.host}:${this.config.port}`);
          logger.info('WALLET_API', `API Key: ${this.config.apiKey}`);
          logger.info('WALLET_API', `Health check: http://${this.config.host}:${this.config.port}/health`);
          logger.info('WALLET_API', `API Info: http://${this.config.host}:${this.config.port}/info`);
          resolve(this);
        });

        this.server.on('error', error => {
          logger.error(`Wallet API Server error: ${error.message}`);
          reject(error);
        });
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   *
   */
  stop() {
    return new Promise(resolve => {
      if (this.server) {
        this.server.close(() => {
          logger.info('WALLET_API', 'Wallet API Server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

// CLI functionality
/**
 *
 */
function showHelp() {
  console.log(`
Pastella Wallet API Server
Usage: node wallet-api.js [WALLET_OPTIONS] [SERVER_OPTIONS]

WALLET OPTIONS (required - choose one):
  --create-wallet <name> --password <pwd>    Create new wallet with name and password
  --load-wallet <name> --password <pwd>      Load existing wallet with name and password

SERVER OPTIONS:
  --api-key <string>      API key for authentication (REQUIRED)
  --port <number>         Server port (default: 3001)
  --host <string>         Server host (default: 127.0.0.1)
  --cors                  Enable CORS
  --help                  Show this help message

EXAMPLES:
  node wallet-api.js --create-wallet "exchange-hot" --password "secure123" --port 3001 --api-key mykey
  node wallet-api.js --load-wallet "exchange-hot" --password "secure123" --host 0.0.0.0 --cors
  node wallet-api.js --load-wallet "my-wallet" --password "pass123" --api-key mykey

IMPORTANT - ATOMIC UNITS:
  - All transaction amounts and fees must be provided in ATOMIC UNITS
  - 1 PAS = 100,000,000 atomic units (8 decimals)
  - Example: To send 1.5 PAS, use amount: 150000000
  - Responses include both atomic units and human-readable amounts

API ENDPOINTS:
  POST /api/wallet/create           - Create new wallet
  POST /api/wallet/load             - Load existing wallet  
  POST /api/wallet/unload           - Unload wallet from memory
  POST /api/wallet/backup           - Backup wallet to file
  GET  /api/wallet/info/:name       - Get wallet information
  GET  /api/wallet/balance/:name    - Get wallet balance
  GET  /api/wallet/balances         - Get all wallet balances
  GET  /api/wallet/address/new/:name - Generate new address
  GET  /api/wallet/transaction/:txId - Get transaction details
  GET  /api/wallet/transactions/:name - Get wallet transactions
  POST /api/wallet/send             - Send transaction
  POST /api/wallet/send-multi       - Send multi-output transaction (batch)
  POST /api/wallet/import/privkey   - Import private key
  POST /api/wallet/dump/privkey     - Export private key

All API endpoints require authentication with X-API-Key header.
`);
}

// Parse command line arguments
/**
 *
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const config = {};

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--help':
      case '-h':
        showHelp();
        process.exit(0);
        break;
      case '--create-wallet':
        config.createWallet = args[++i];
        if (!config.createWallet) {
          console.error('Error: --create-wallet requires a wallet name');
          process.exit(1);
        }
        break;
      case '--load-wallet':
        config.loadWallet = args[++i];
        if (!config.loadWallet) {
          console.error('Error: --load-wallet requires a wallet name');
          process.exit(1);
        }
        break;
      case '--password':
        config.password = args[++i];
        if (!config.password) {
          console.error('Error: --password requires a password value');
          process.exit(1);
        }
        break;
      case '--port':
        config.port = parseInt(args[++i]);
        break;
      case '--host':
        config.host = args[++i];
        break;
      case '--api-key':
        config.apiKey = args[++i];
        break;
      case '--cors':
        config.cors = true;
        break;
      default:
        console.error(`Unknown option: ${args[i]}`);
        showHelp();
        process.exit(1);
    }
  }

  // Validate wallet arguments
  const hasCreateWallet = !!config.createWallet;
  const hasLoadWallet = !!config.loadWallet;
  const hasPassword = !!config.password;

  if (!hasCreateWallet && !hasLoadWallet) {
    console.error('Error: Must specify either --create-wallet or --load-wallet');
    showHelp();
    process.exit(1);
  }

  if (hasCreateWallet && hasLoadWallet) {
    console.error('Error: Cannot specify both --create-wallet and --load-wallet');
    showHelp();
    process.exit(1);
  }

  if (!hasPassword) {
    console.error('Error: --password is required');
    showHelp();
    process.exit(1);
  }

  if (!config.apiKey) {
    console.error('Error: --api-key is required');
    showHelp();
    process.exit(1);
  }

  return config;
}

// Main execution
if (require.main === module) {
  // Check if no arguments provided, show help
  if (process.argv.length <= 2) {
    showHelp();
    process.exit(1);
  }

  const config = parseArgs();

  const server = new WalletAPIServer(config);

  // Initialize wallet on startup
  server
    .start()
    .then(async () => {
      try {
        // Check daemon connection first
        logger.info('WALLET_API', 'Checking daemon connection...');
        const isDaemonConnected = await server.walletFunctions.checkDaemonConnection();

        if (!isDaemonConnected) {
          logger.error(
            'WALLET_API',
            'Cannot connect to Pastella daemon. Please ensure daemon is running and accessible.'
          );
          logger.error(
            'WALLET_API',
            `Expected daemon at: http://${server.walletFunctions.daemonHost}:${server.walletFunctions.daemonPort}`
          );
          await server.stop();
          process.exit(1);
        }

        logger.info('WALLET_API', 'Daemon connection successful ✓');

        // Initialize wallet after daemon connection confirmed
        if (config.createWallet) {
          logger.info('WALLET_API', `Creating wallet: ${config.createWallet}`);
          await server.walletFunctions.createWallet(config.createWallet, config.password);
          logger.info('WALLET_API', `Wallet '${config.createWallet}' created successfully`);
        } else if (config.loadWallet) {
          logger.info('WALLET_API', `Loading wallet: ${config.loadWallet}`);
          await server.walletFunctions.loadWallet(config.loadWallet, config.password);
          logger.info('WALLET_API', `Wallet '${config.loadWallet}' loaded successfully`);
        }

        logger.info('WALLET_API', '🚀 Wallet API ready for requests');
      } catch (error) {
        logger.error('WALLET_API', `Failed to initialize: ${error.message}`);
        await server.stop();
        process.exit(1);
      }
    })
    .catch(error => {
      logger.error('WALLET_API', `Failed to start Wallet API Server: ${error.message}`);
      process.exit(1);
    });

  // Graceful shutdown
  process.on('SIGINT', async () => {
    logger.info('WALLET_API', 'Received SIGINT, shutting down gracefully...');
    await server.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    logger.info('WALLET_API', 'Received SIGTERM, shutting down gracefully...');
    await server.stop();
    process.exit(0);
  });
}

module.exports = WalletAPIServer;
