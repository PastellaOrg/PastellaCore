const crypto = require('crypto');
const secp256k1 = require('secp256k1');
const path = require('path');
const { WordList } = require('./wordList');

/**
 * CRITICAL: Safe arithmetic operations to prevent integer overflow/underflow
 */
class SafeMath {
  static MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

  static MIN_SAFE_INTEGER = Number.MIN_SAFE_INTEGER;

  /**
   * CRITICAL: Safe addition with overflow protection
   * @param a
   * @param b
   */
  static safeAdd(a, b) {
    const result = BigInt(a) + BigInt(b);

    // Check if result exceeds safe integer bounds
    if (result > BigInt(this.MAX_SAFE_INTEGER)) {
      throw new Error(`Integer overflow detected: ${a} + ${b} = ${result} exceeds maximum safe integer`);
    }

    if (result < BigInt(this.MIN_SAFE_INTEGER)) {
      throw new Error(`Integer underflow detected: ${a} + ${b} = ${result} below minimum safe integer`);
    }

    return Number(result);
  }

  /**
   * CRITICAL: Safe subtraction with underflow protection
   * @param a
   * @param b
   */
  static safeSub(a, b) {
    const result = BigInt(a) - BigInt(b);

    // Check if result exceeds safe integer bounds
    if (result > BigInt(this.MAX_SAFE_INTEGER)) {
      throw new Error(`Integer overflow detected: ${a} - ${b} = ${result} exceeds maximum safe integer`);
    }

    if (result < BigInt(this.MIN_SAFE_INTEGER)) {
      throw new Error(`Integer underflow detected: ${a} - ${b} = ${result} below minimum safe integer`);
    }

    return Number(result);
  }

  /**
   * CRITICAL: Safe multiplication with overflow protection
   * @param a
   * @param b
   */
  static safeMul(a, b) {
    const result = BigInt(a) * BigInt(b);

    // Check if result exceeds safe integer bounds
    if (result > BigInt(this.MAX_SAFE_INTEGER)) {
      throw new Error(`Integer overflow detected: ${a} * ${b} = ${result} exceeds maximum safe integer`);
    }

    if (result < BigInt(this.MIN_SAFE_INTEGER)) {
      throw new Error(`Integer underflow detected: ${a} * ${b} = ${result} below minimum safe integer`);
    }

    return Number(result);
  }

  /**
   * CRITICAL: Safe division with division by zero protection
   * @param a
   * @param b
   */
  static safeDiv(a, b) {
    if (b === 0) {
      throw new Error('Division by zero detected');
    }

    const result = BigInt(a) / BigInt(b);

    // Check if result exceeds safe integer bounds
    if (result > BigInt(this.MAX_SAFE_INTEGER)) {
      throw new Error(`Integer overflow detected: ${a} / ${b} = ${result} exceeds maximum safe integer`);
    }

    if (result < BigInt(this.MIN_SAFE_INTEGER)) {
      throw new Error(`Integer underflow detected: ${a} / ${b} = ${result} below minimum safe integer`);
    }

    return Number(result);
  }

  /**
   * CRITICAL: Safe modulo with division by zero protection
   * @param a
   * @param b
   */
  static safeMod(a, b) {
    if (b === 0) {
      throw new Error('Modulo by zero detected');
    }

    const result = BigInt(a) % BigInt(b);

    // Check if result exceeds safe integer bounds
    if (result > BigInt(this.MAX_SAFE_INTEGER)) {
      throw new Error(`Integer overflow detected: ${a} % ${b} = ${result} exceeds maximum safe integer`);
    }

    if (result < BigInt(this.MIN_SAFE_INTEGER)) {
      throw new Error(`Integer underflow detected: ${a} % ${b} = ${result} below minimum safe integer`);
    }

    return Number(result);
  }

  /**
   * CRITICAL: Validate amount is within safe bounds
   * @param amount
   */
  static validateAmount(amount) {
    if (typeof amount !== 'number' || isNaN(amount)) {
      throw new Error('Invalid amount: must be a valid number');
    }

    if (amount > this.MAX_SAFE_INTEGER) {
      throw new Error(`Amount ${amount} exceeds maximum safe integer`);
    }

    if (amount < this.MIN_SAFE_INTEGER) {
      throw new Error(`Amount ${amount} below minimum safe integer`);
    }

    if (amount < 0) {
      throw new Error(`Amount ${amount} cannot be negative`);
    }

    return true;
  }

  /**
   * CRITICAL: Safe balance calculation
   * @param balances
   */
  static safeBalanceCalculation(balances) {
    if (!Array.isArray(balances)) {
      throw new Error('Balances must be an array');
    }

    let total = BigInt(0);

    for (const balance of balances) {
      if (typeof balance !== 'number' || isNaN(balance)) {
        throw new Error('Invalid balance in array');
      }

      if (balance < 0) {
        throw new Error(`Negative balance detected: ${balance}`);
      }

      total += BigInt(balance);

      // Check for overflow during accumulation
      if (total > BigInt(this.MAX_SAFE_INTEGER)) {
        throw new Error(`Balance overflow detected during calculation`);
      }
    }

    return Number(total);
  }
}

/**
 * CRITICAL: Security utilities for preventing common vulnerabilities
 */
class SecurityUtils {
  /**
   * Validate file path to prevent directory traversal attacks
   * @param {string} userPath - User-provided path
   * @param {string} allowedDir - Allowed base directory
   * @param {string} fileExtension - Expected file extension (optional)
   * @returns {string} - Validated safe path
   */
  static validateFilePath(userPath, allowedDir, fileExtension = null) {
    if (!userPath || typeof userPath !== 'string') {
      throw new Error('Invalid file path: must be a non-empty string');
    }

    if (!allowedDir || typeof allowedDir !== 'string') {
      throw new Error('Invalid allowed directory: must be a non-empty string');
    }

    // Remove any path traversal attempts
    const sanitizedPath = userPath.replace(/\.\./g, '').replace(/[\/\\]/g, '');

    // Validate filename contains only safe characters
    if (!/^[a-zA-Z0-9._-]+$/.test(sanitizedPath)) {
      throw new Error(`Invalid characters in filename: "${sanitizedPath}". Only alphanumeric, dots, hyphens, and underscores allowed.`);
    }

    // Validate file extension if specified
    if (fileExtension && !sanitizedPath.endsWith(fileExtension)) {
      throw new Error(`Invalid file extension. Expected: ${fileExtension}`);
    }

    // Construct the full path
    const fullPath = path.join(allowedDir, sanitizedPath);
    const resolvedPath = path.resolve(fullPath);
    const resolvedAllowedDir = path.resolve(allowedDir);

    // Ensure the resolved path is within the allowed directory
    if (!resolvedPath.startsWith(resolvedAllowedDir + path.sep) && resolvedPath !== resolvedAllowedDir) {
      throw new Error('Path traversal attempt detected: access outside allowed directory forbidden');
    }

    return resolvedPath;
  }

  /**
   * Validate wallet name for secure file operations
   * @param {string} walletName - User-provided wallet name
   * @returns {string} - Validated wallet name
   */
  static validateWalletName(walletName) {
    if (!walletName || typeof walletName !== 'string') {
      throw new Error('Invalid wallet name: must be a non-empty string');
    }

    const sanitized = walletName.trim();

    // Validate length
    if (sanitized.length < 1 || sanitized.length > 64) {
      throw new Error('Wallet name must be between 1 and 64 characters');
    }

    // Validate characters (alphanumeric, hyphens, underscores only)
    if (!/^[a-zA-Z0-9_-]+$/.test(sanitized)) {
      throw new Error('Wallet name can only contain letters, numbers, hyphens, and underscores');
    }

    // Prevent reserved names
    const reserved = ['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9'];
    if (reserved.includes(sanitized.toLowerCase())) {
      throw new Error(`Wallet name "${sanitized}" is reserved and cannot be used`);
    }

    return sanitized;
  }
}

/**
 *
 */
class CryptoUtils {
  /**
   *
   * @param data
   */
  static hash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   *
   * @param data
   */
  static doubleHash(data) {
    return this.hash(this.hash(data));
  }

  /**
   *
   * @param data
   */
  static ripemd160(data) {
    return crypto.createHash('ripemd160').update(data).digest('hex');
  }

  /**
   *
   * @param transactionHashes
   */
  static calculateMerkleRoot(transactionHashes) {
    if (transactionHashes.length === 0) return this.hash('empty');
    if (transactionHashes.length === 1) return this.hash(transactionHashes[0]);

    const leaves = transactionHashes.map(hash => this.hash(hash));

    while (leaves.length > 1) {
      const newLeaves = [];
      for (let i = 0; i < leaves.length; i += 2) {
        const left = leaves[i];
        const right = i + 1 < leaves.length ? leaves[i + 1] : left;
        newLeaves.push(this.hash(left + right));
      }
      leaves.splice(0, leaves.length, ...newLeaves);
    }

    return leaves[0];
  }

  /**
   * Generate a secure 12-word BIP39 seed phrase with proper entropy and checksum
   * Implements BIP39 standard for cryptographically secure seed phrase generation
   */
  static generateSeed() {
    const words = WordList.getBIP39Wordlist();
    let attempts = 0;
    const maxAttempts = 100;

    while (attempts < maxAttempts) {
      attempts++;

      // Generate 128 bits of entropy (for 12-word phrase)
      const entropyBytes = crypto.randomBytes(16); // 128 bits

      // Convert entropy to binary string
      let entropyBits = '';
      for (let i = 0; i < entropyBytes.length; i++) {
        entropyBits += entropyBytes[i].toString(2).padStart(8, '0');
      }

      // Calculate checksum (first 4 bits of SHA256 hash of entropy)
      const entropyHash = crypto.createHash('sha256').update(entropyBytes).digest();
      const checksumBits = entropyHash[0].toString(2).padStart(8, '0').substring(0, 4);

      // Combine entropy + checksum = 132 bits total
      const totalBits = entropyBits + checksumBits;

      // Split into 12 groups of 11 bits each
      const selectedWords = [];
      for (let i = 0; i < 12; i++) {
        const bits11 = totalBits.substring(i * 11, (i + 1) * 11);
        const wordIndex = parseInt(bits11, 2);

        if (wordIndex >= words.length) {
          // Invalid index, regenerate
          break;
        }

        selectedWords.push(words[wordIndex]);
      }

      // Ensure we have exactly 12 valid words
      if (selectedWords.length === 12) {
        const seedPhrase = selectedWords.join(' ');

        // Validate the generated seed phrase
        if (this.validateSeedEntropy(seedPhrase, entropyBytes)) {
          return seedPhrase;
        }
      }
    }

    throw new Error('Failed to generate secure seed phrase after maximum attempts');
  }

  /**
   * Validate seed phrase entropy and checksum according to BIP39
   * @param {string} seedPhrase - The seed phrase to validate
   * @param {Buffer} expectedEntropy - Expected entropy bytes for validation
   * @returns {boolean} - True if valid, false otherwise
   */
  static validateSeedEntropy(seedPhrase, expectedEntropy = null) {
    try {
      const words = seedPhrase.trim().toLowerCase().split(/\s+/);
      if (words.length !== 12) {
        return false;
      }

      const wordlist = WordList.getBIP39Wordlist();
      let totalBits = '';

      // Convert words to binary representation
      for (const word of words) {
        const wordIndex = wordlist.indexOf(word);
        if (wordIndex === -1) {
          return false; // Invalid word
        }
        totalBits += wordIndex.toString(2).padStart(11, '0');
      }

      // Extract entropy and checksum
      const entropyBits = totalBits.substring(0, 128); // First 128 bits
      const providedChecksum = totalBits.substring(128, 132); // Last 4 bits

      // Convert entropy bits back to bytes
      const entropyBytes = Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        const byteBits = entropyBits.substring(i * 8, (i + 1) * 8);
        entropyBytes[i] = parseInt(byteBits, 2);
      }

      // Calculate expected checksum
      const entropyHash = crypto.createHash('sha256').update(entropyBytes).digest();
      const expectedChecksum = entropyHash[0].toString(2).padStart(8, '0').substring(0, 4);

      // Verify checksum matches
      const checksumValid = providedChecksum === expectedChecksum;

      // If expectedEntropy provided, verify entropy matches
      const entropyValid = !expectedEntropy || entropyBytes.equals(expectedEntropy);

      // Validate entropy quality - ensure not all zeros or all ones
      const entropyValue = entropyBytes.reduce((sum, byte) => sum + byte, 0);
      const entropyQualityValid = entropyValue > 16 && entropyValue < (255 * 16 - 16);

      return checksumValid && entropyValid && entropyQualityValid;

    } catch (error) {
      return false;
    }
  }

  /**
   *
   * @param seed
   */
  static seedToPrivateKey(seed) {
    return this.hash(seed);
  }

  /**
   *
   */
  static generateKeyPair() {
    // Generate seed phrase first (BIP39 standard)
    const seed = this.generateSeed();

    // Derive private key FROM the seed (deterministic)
    const keyPair = this.importFromSeed(seed);

    return {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      seed: seed,
    };
  }

  /**
   *
   * @param privateKeyHex
   */
  static privateKeyToPublicKey(privateKeyHex) {
    const privateKeyBuffer = Buffer.from(privateKeyHex, 'hex');

    // Use secp256k1 to derive public key
    const publicKey = secp256k1.publicKeyCreate(privateKeyBuffer, false);

    // Convert to hex string
    let hexString = '';
    for (let i = 0; i < publicKey.length; i++) {
      const hex = publicKey[i].toString(16);
      hexString += hex.length === 1 ? `0${hex}` : hex;
    }

    return hexString;
  }

  /**
   *
   * @param privateKeyHex
   */
  static importPrivateKey(privateKeyHex) {
    // Validate private key format
    if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new Error('Invalid private key format');
    }

    // Derive public key from private key
    const publicKey = this.privateKeyToPublicKey(privateKeyHex);

    return {
      privateKey: privateKeyHex,
      publicKey,
    };
  }

  /**
   * Import wallet from seed phrase (BIP39-compatible)
   * @param seed - 12-word seed phrase separated by spaces
   */
  static importFromSeed(seed) {
    if (!seed || typeof seed !== 'string') {
      throw new Error('Invalid seed: must be a non-empty string');
    }

    // Validate seed format (12 words separated by spaces)
    const words = seed.trim().split(/\s+/);
    if (words.length !== 12) {
      throw new Error('Invalid seed phrase: must contain exactly 12 words');
    }

    // Validate each word exists in the BIP39 wordlist
    const wordlist = WordList.getBIP39Wordlist();
    for (const word of words) {
      if (!wordlist.includes(word.toLowerCase())) {
        throw new Error(`Invalid word in seed phrase: "${word}"`);
      }
    }

    // Validate BIP39 checksum
    if (!this.validateSeedEntropy(seed)) {
      throw new Error('Seed phrase checksum validation failed. The phrase may be corrupted or invalid.');
    }

    // Derive private key from seed using deterministic hash
    // This creates a deterministic private key from the seed phrase
    const seedHash = this.hash(seed.toLowerCase().trim());

    // Ensure the derived key is valid for secp256k1 (must be < curve order)
    let privateKeyHex = seedHash;
    let attempts = 0;
    const maxAttempts = 1000;

    while (attempts < maxAttempts) {
      const privateKeyBuffer = Buffer.from(privateKeyHex, 'hex');

      // Check if private key is valid for secp256k1 curve
      if (secp256k1.privateKeyVerify(privateKeyBuffer)) {
        break;
      }

      // If invalid, hash the previous result and try again
      privateKeyHex = this.hash(privateKeyHex);
      attempts++;
    }

    if (attempts >= maxAttempts) {
      throw new Error('Failed to derive valid private key from seed after maximum attempts');
    }

    // Derive public key from the private key
    const publicKey = this.privateKeyToPublicKey(privateKeyHex);

    return {
      privateKey: privateKeyHex,
      publicKey,
      seed: seed.toLowerCase().trim(), // Store normalized seed
    };
  }

  /**
   *
   * @param seed
   */
  static generateKeyPairFromSeed(seed) {
    return this.importFromSeed(seed);
  }

  /**
   *
   * @param publicKey
   */
  static publicKeyToAddress(publicKey) {
    // Convert public key to Buffer
    const publicKeyBuffer = Buffer.from(publicKey, 'hex');

    // SHA256 hash of public key
    const sha256Hash = crypto.createHash('sha256').update(publicKeyBuffer).digest();

    // RIPEMD160 hash of SHA256 hash
    const ripemd160Hash = crypto.createHash('ripemd160').update(sha256Hash).digest();

    // Add version byte (0x00 for mainnet)
    const versionedPayload = Buffer.concat([Buffer.from([0x00]), ripemd160Hash]);

    // Double SHA256 for checksum
    const checksum = crypto
      .createHash('sha256')
      .update(crypto.createHash('sha256').update(versionedPayload).digest())
      .digest()
      .slice(0, 4);

    // Combine versioned payload with checksum
    const binaryAddr = Buffer.concat([versionedPayload, checksum]);

    // Base58 encode
    return this.base58Encode(binaryAddr);
  }

  /**
   *
   * @param buffer
   */
  static base58Encode(buffer) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let num = BigInt(`0x${buffer.toString('hex')}`);
    let str = '';

    while (num > 0) {
      const remainder = Number(num % BigInt(58));
      str = alphabet[remainder] + str;
      num /= BigInt(58);
    }

    // Handle leading zeros
    for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
      str = `1${str}`;
    }

    return str;
  }

  /**
   *
   * @param data
   * @param privateKeyHex
   */
  static sign(data, privateKeyHex) {
    const privateKeyBuffer = Buffer.from(privateKeyHex, 'hex');
    const dataHash = crypto.createHash('sha256').update(data).digest();

    // Sign the hash with secp256k1 using ecdsaSign
    const signature = secp256k1.ecdsaSign(dataHash, privateKeyBuffer);

    // Convert signature to hex string manually to avoid toString('hex') issues
    let hexString = '';
    for (let i = 0; i < signature.signature.length; i++) {
      const hex = signature.signature[i].toString(16);
      hexString += hex.length === 1 ? `0${hex}` : hex;
    }
    return hexString;
  }

  /**
   *
   * @param data
   * @param signature
   * @param publicKeyHex
   */
  static verify(data, signature, publicKeyHex) {
    const dataHash = crypto.createHash('sha256').update(data).digest();

    // Convert signature to Buffer if it's a hex string
    let signatureBuffer;
    if (typeof signature === 'string') {
      signatureBuffer = Buffer.from(signature, 'hex');
    } else {
      signatureBuffer = signature;
    }

    // Convert public key to Buffer if it's a hex string
    let publicKeyBuffer;
    if (typeof publicKeyHex === 'string') {
      publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');
    } else {
      publicKeyBuffer = publicKeyHex;
    }

    // Verify the signature with secp256k1 using ecdsaVerify
    return secp256k1.ecdsaVerify(signatureBuffer, dataHash, publicKeyBuffer);
  }

  /**
   *
   * @param privateKeyHex
   * @param publicKeyHex
   */
  static verifyKeyPair(privateKeyHex, publicKeyHex) {
    try {
      const derivedPublicKey = this.privateKeyToPublicKey(privateKeyHex);
      return derivedPublicKey === publicKeyHex;
    } catch (error) {
      return false;
    }
  }
}

module.exports = {
  CryptoUtils,
  SafeMath,
  SecurityUtils,
};
