const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { TRANSACTION_TAGS } = require('../utils/constants');
const { CryptoUtils } = require('../utils/crypto');

const { Transaction, TransactionInput, TransactionOutput } = require('./Transaction');

/**
 *
 */
class Wallet {
  /**
   *
   */
  constructor() {
    this.privateKey = null;
    this.publicKey = null;
    this.address = null;
    this.seed = null;
    this.balance = 0;
    this.utxos = [];

    // Transaction history for wallet
    this.transactionHistory = [];

    // Sync state for persistent wallet synchronization
    this.syncState = {
      lastSyncedHeight: 0,
      lastSyncedHash: null,
      lastSyncTime: null,
      totalTransactions: 0,
      lastBalance: 0,
    };
  }

  /**
   *
   * @param password
   */
  generateKeyPair(password) {
    const keyPair = CryptoUtils.generateKeyPair();
    this.privateKey = keyPair.privateKey;
    this.publicKey = keyPair.publicKey;
    this.seed = keyPair.seed;
    this.address = CryptoUtils.publicKeyToAddress(this.publicKey);

    return {
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      seed: this.seed,
      address: this.address,
    };
  }

  /**
   *
   * @param seed
   * @param password
   */
  importFromSeed(seed, password) {
    try {
      const keyPair = CryptoUtils.importFromSeed(seed);
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
      this.seed = seed;
      this.address = CryptoUtils.publicKeyToAddress(this.publicKey);

      return {
        privateKey: this.privateKey,
        publicKey: this.publicKey,
        seed: this.seed,
        address: this.address,
      };
    } catch (error) {
      throw new Error(`Failed to import from seed: ${error.message}`);
    }
  }

  /**
   *
   * @param privateKeyHex
   * @param password
   */
  importFromPrivateKey(privateKeyHex, password) {
    try {
      const keyPair = CryptoUtils.importPrivateKey(privateKeyHex);
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
      this.address = CryptoUtils.publicKeyToAddress(this.publicKey);

      return {
        privateKey: this.privateKey,
        publicKey: this.publicKey,
        address: this.address,
      };
    } catch (error) {
      throw new Error(`Failed to import private key: ${error.message}`);
    }
  }

  /**
   *
   */
  getAddress() {
    return this.address;
  }

  /**
   *
   */
  getSeed() {
    return this.seed;
  }

  /**
   *
   * @param password
   */
  showSeedInfo(password) {
    if (!this.seed) {
      throw new Error('No seed available for this wallet');
    }

    return {
      privateKey: this.privateKey,
      seed: this.seed,
    };
  }

  /**
   *
   * @param data
   * @param password
   */
  encryptWalletData(data, password) {
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
      encrypted,
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
    };
  }

  /**
   *
   * @param encryptedData
   * @param password
   */
  decryptWalletData(encryptedData, password) {
    try {
      const key = crypto.pbkdf2Sync(password, Buffer.from(encryptedData.salt, 'hex'), 100000, 32, 'sha256');
      const iv = Buffer.from(encryptedData.iv, 'hex');

      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return JSON.parse(decrypted);
    } catch (error) {
      throw new Error('Invalid password or corrupted wallet file');
    }
  }

  /**
   *
   * @param filename
   */
  ensureWalletExtension(filename) {
    if (!filename.endsWith('.wallet')) {
      return `${filename}.wallet`;
    }
    return filename;
  }

  /**
   *
   * @param filePath
   * @param password
   */
  saveToFile(filePath, password) {
    try {
      const walletData = {
        privateKey: this.privateKey,
        publicKey: this.publicKey,
        address: this.address,
        seed: this.seed,
        balance: this.balance,
        utxos: this.utxos,
        transactionHistory: this.transactionHistory,
        syncState: this.syncState,
      };

      const encryptedData = this.encryptWalletData(walletData, password);

      // Ensure directory exists
      const dir = path.dirname(filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      fs.writeFileSync(filePath, JSON.stringify(encryptedData, null, 2));
      return true;
    } catch (error) {
      throw new Error(`Failed to save wallet: ${error.message}`);
    }
  }

  /**
   *
   * @param filePath
   * @param password
   */
  loadFromFile(filePath, password) {
    try {
      if (!fs.existsSync(filePath)) {
        throw new Error('Wallet file not found');
      }

      const fileData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const walletData = this.decryptWalletData(fileData, password);

      this.privateKey = walletData.privateKey;
      this.publicKey = walletData.publicKey;
      this.address = walletData.address;
      this.seed = walletData.seed;
      this.balance = walletData.balance || 0;
      this.utxos = walletData.utxos || [];
      this.transactionHistory = walletData.transactionHistory || [];
      this.syncState = walletData.syncState || {
        lastSyncedHeight: 0,
        lastSyncedHash: null,
        lastSyncTime: null,
        totalTransactions: 0,
        lastBalance: 0,
      };

      return true;
    } catch (error) {
      throw new Error(`Failed to load wallet: ${error.message}`);
    }
  }

  /**
   *
   * @param name
   * @param password
   */
  load(name, password) {
    try {
      const filePath = this.ensureWalletExtension(name);
      return this.loadFromFile(filePath, password);
    } catch (error) {
      throw new Error(`Failed to load wallet '${name}': ${error.message}`);
    }
  }

  /**
   *
   * @param blockchain
   * @param onTransactionDetected
   */
  updateBalance(blockchain, onTransactionDetected = null) {
    const oldBalance = this.balance;
    const oldUtxoCount = this.utxos.length;
    const oldUtxoKeys = new Set(this.utxos.map(utxo => `${utxo.txHash}:${utxo.outputIndex}`));

    this.utxos = blockchain.getUTXOsForAddress(this.address);
    this.balance = this.utxos.reduce((total, utxo) => total + utxo.amount, 0);

    // Check for new transactions (received or sent)
    if (onTransactionDetected && (this.balance !== oldBalance || this.utxos.length !== oldUtxoCount)) {
      // Find new UTXOs (received transactions)
      const newUtxos = this.utxos.filter(utxo => !oldUtxoKeys.has(`${utxo.txHash}:${utxo.outputIndex}`));

      // Find spent UTXOs (sent transactions)
      const newUtxoKeys = new Set(this.utxos.map(utxo => `${utxo.txHash}:${utxo.outputIndex}`));
      const spentUtxos = this.utxos.filter(
        utxo =>
          oldUtxoKeys.has(`${utxo.txHash}:${utxo.outputIndex}`) &&
          !newUtxoKeys.has(`${utxo.txHash}:${utxo.outputIndex}`)
      );

      // Group new UTXOs by transaction
      const newTransactions = new Map();
      newUtxos.forEach(utxo => {
        if (!newTransactions.has(utxo.txHash)) {
          newTransactions.set(utxo.txHash, {
            type: 'received',
            txHash: utxo.txHash,
            blockHeight: this.findBlockHeightForTransaction(blockchain, utxo.txHash),
            outputs: [],
          });
        }
        newTransactions.get(utxo.txHash).outputs.push({
          address: this.address,
          amount: utxo.amount,
        });
      });

      // Report new received transactions
      newTransactions.forEach(transaction => {
        const totalAmount = transaction.outputs.reduce((sum, output) => sum + output.amount, 0);
        onTransactionDetected('received', totalAmount, {
          txHash: transaction.txHash,
          blockHeight: transaction.blockHeight,
          address: this.address,
          amount: totalAmount,
        });
      });

      // For sent transactions, we need to look at the blockchain to find the actual transaction details
      // This is more complex as we need to find the transaction that spent our UTXOs
      const balanceChange = this.balance - oldBalance;
      if (balanceChange < 0) {
        // This indicates we spent coins, but we don't have detailed info from UTXOs alone
        // We'll report the total amount sent
        onTransactionDetected('sent', Math.abs(balanceChange), {
          address: this.address,
          amount: Math.abs(balanceChange),
        });
      }
    }

    return this.balance;
  }

  /**
   * Find the block height for a given transaction hash
   * @param blockchain
   * @param txHash
   */
  findBlockHeightForTransaction(blockchain, txHash) {
    for (let i = 0; i < blockchain.chain.length; i++) {
      const block = blockchain.chain[i];
      if (block.transactions.some(tx => tx.id === txHash)) {
        return block.index;
      }
    }
    return null;
  }

  /**
   *
   */
  getBalance() {
    return this.balance;
  }

  /**
   *
   */
  getUTXOCount() {
    return this.utxos.length;
  }

  /**
   *
   * @param toAddress
   * @param amount
   * @param fee
   * @param blockchain
   * @param tag
   * @param paymentId
   */
  createTransaction(toAddress, amount, fee, blockchain, tag = TRANSACTION_TAGS.TRANSACTION, paymentId = null) {
    // Users can only create TRANSACTION tagged transactions
    if (tag !== TRANSACTION_TAGS.TRANSACTION) {
      throw new Error('Users can only create TRANSACTION tagged transactions. Other tags are reserved for system use.');
    }

    if (amount + fee > this.balance) {
      throw new Error('Insufficient balance');
    }

    // Find UTXOs to spend
    const utxosToSpend = [];
    let totalInput = 0;

    for (const utxo of this.utxos) {
      if (totalInput >= amount + fee) break;
      utxosToSpend.push(utxo);
      totalInput += utxo.amount;
    }

    if (totalInput < amount + fee) {
      throw new Error('Insufficient UTXOs to cover transaction');
    }

    // Create transaction inputs
    const inputs = utxosToSpend.map(
      utxo =>
        new TransactionInput(
          utxo.txHash, // Changed from utxo.txId to utxo.txHash
          utxo.outputIndex,
          null, // signature will be set later
          this.publicKey
        )
    );

    // Create transaction outputs
    const outputs = [new TransactionOutput(toAddress, amount)];

    // Add change output if needed
    const change = totalInput - amount - fee;
    if (change > 0) {
      outputs.push(new TransactionOutput(this.address, change));
    }

    // Create transaction with tag and payment ID (automatically includes replay protection)
    const transaction = new Transaction(inputs, outputs, fee, tag, null, null, null, false, paymentId);

    // Verify replay protection fields are present
    if (!transaction.nonce || !transaction.expiresAt) {
      throw new Error('Transaction creation failed: Missing replay protection fields');
    }

    // Sign the transaction
    const txData = transaction.getDataToSign();
    for (let i = 0; i < inputs.length; i++) {
      const signature = CryptoUtils.sign(txData, this.privateKey);
      transaction.inputs[i].signature = signature;
    }

    transaction.id = transaction.calculateId();
    return transaction;
  }

  /**
   * Create multi-output transaction (send to multiple addresses in single transaction)
   * @param outputs - Array of {address, amount} objects
   * @param fee
   * @param blockchain
   * @param tag
   * @param paymentId
   */
  createMultiTransaction(outputs, fee, blockchain, tag = TRANSACTION_TAGS.TRANSACTION, paymentId = null) {
    // Users can only create TRANSACTION tagged transactions
    if (tag !== TRANSACTION_TAGS.TRANSACTION) {
      throw new Error('Users can only create TRANSACTION tagged transactions. Other tags are reserved for system use.');
    }

    // Validate outputs array
    if (!Array.isArray(outputs) || outputs.length === 0) {
      throw new Error('outputs must be a non-empty array');
    }

    // Validate each output
    let totalAmount = 0;
    for (const output of outputs) {
      if (!output.address || typeof output.amount !== 'number' || output.amount <= 0) {
        throw new Error('Each output must have valid address and positive amount');
      }
      totalAmount += output.amount;
    }

    if (totalAmount + fee > this.balance) {
      throw new Error('Insufficient balance for multi-output transaction');
    }

    // Find UTXOs to spend
    const utxosToSpend = [];
    let totalInput = 0;

    for (const utxo of this.utxos) {
      if (totalInput >= totalAmount + fee) break;
      utxosToSpend.push(utxo);
      totalInput += utxo.amount;
    }

    if (totalInput < totalAmount + fee) {
      throw new Error('Insufficient UTXOs to cover multi-output transaction');
    }

    // Create transaction inputs
    const inputs = utxosToSpend.map(
      utxo =>
        new TransactionInput(
          utxo.txHash,
          utxo.outputIndex,
          null, // signature will be set later
          this.publicKey
        )
    );

    // Create transaction outputs from the provided outputs array
    const transactionOutputs = outputs.map(output => new TransactionOutput(output.address, output.amount));

    // Add change output if needed
    const change = totalInput - totalAmount - fee;
    if (change > 0) {
      transactionOutputs.push(new TransactionOutput(this.address, change));
    }

    // Create transaction with tag and payment ID (automatically includes replay protection)
    const transaction = new Transaction(inputs, transactionOutputs, fee, tag, null, null, null, false, paymentId);

    // Verify replay protection fields are present
    if (!transaction.nonce || !transaction.expiresAt) {
      throw new Error('Transaction creation failed: Missing replay protection fields');
    }

    // Sign the transaction
    const txData = transaction.getDataToSign();
    for (let i = 0; i < inputs.length; i++) {
      const signature = CryptoUtils.sign(txData, this.privateKey);
      transaction.inputs[i].signature = signature;
    }

    transaction.id = transaction.calculateId();
    return transaction;
  }

  /**
   *
   */
  getInfo() {
    return {
      address: this.address,
      balance: this.balance,
      utxoCount: this.utxos.length,
      hasSeed: !!this.seed,
    };
  }

  /**
   *
   */
  isLoaded() {
    return !!(this.privateKey && this.publicKey && this.address);
  }

  /**
   *
   * @param filePath
   * @param password
   */
  saveWallet(filePath = null, password = null) {
    if (!this.isLoaded()) {
      throw new Error('No wallet loaded to save');
    }

    if (!filePath) {
      throw new Error('File path is required for saving wallet');
    }

    try {
      this.saveToFile(filePath, password);
      return true;
    } catch (error) {
      throw new Error(`Failed to save wallet: ${error.message}`);
    }
  }

  /**
   *
   */
  unloadWallet() {
    this.privateKey = null;
    this.publicKey = null;
    this.address = null;
    this.seed = null;
    this.balance = 0;
    this.utxos = [];
    this.transactionHistory = [];
    this.syncState = {
      lastSyncedHeight: 0,
      lastSyncedHash: null,
      lastSyncTime: null,
      totalTransactions: 0,
      lastBalance: 0,
    };
    return true;
  }

  // Sync state methods
  /**
   *
   */
  getSyncState() {
    return this.syncState;
  }

  /**
   *
   * @param height
   * @param hash
   * @param transactionCount
   */
  updateSyncState(height, hash, transactionCount = 0) {
    this.syncState.lastSyncedHeight = height;
    this.syncState.lastSyncedHash = hash;
    this.syncState.lastSyncTime = Date.now();
    this.syncState.totalTransactions = transactionCount;
    this.syncState.lastBalance = this.balance;
  }

  /**
   *
   */
  resetSyncState() {
    this.syncState = {
      lastSyncedHeight: 0,
      lastSyncedHash: null,
      lastSyncTime: null,
      totalTransactions: 0,
      lastBalance: 0,
    };
  }

  /**
   *
   * @param currentHeight
   */
  isFullySynced(currentHeight) {
    return this.syncState.lastSyncedHeight >= currentHeight;
  }

  /**
   *
   * @param currentHeight
   */
  getSyncProgress(currentHeight) {
    if (currentHeight === 0) return 100;
    return Math.round((this.syncState.lastSyncedHeight / currentHeight) * 100);
  }

  // Transaction history methods
  /**
   *
   * @param transaction
   */
  addTransactionToHistory(transaction) {
    // Add transaction to history if not already present
    const exists = this.transactionHistory.find(tx => tx.id === transaction.id);
    if (!exists) {
      this.transactionHistory.unshift(transaction); // Add to beginning (most recent first)
    }
  }

  /**
   *
   */
  getTransactionHistory() {
    return this.transactionHistory;
  }

  /**
   *
   * @param page
   * @param pageSize
   */
  getTransactionHistoryPage(page, pageSize = 10) {
    const startIndex = page * pageSize;
    const endIndex = startIndex + pageSize;
    return this.transactionHistory.slice(startIndex, endIndex);
  }

  /**
   *
   * @param pageSize
   */
  getTransactionHistoryPages(pageSize = 10) {
    return Math.ceil(this.transactionHistory.length / pageSize);
  }

  /**
   *
   */
  clearTransactionHistory() {
    this.transactionHistory = [];
  }
}

module.exports = Wallet;
