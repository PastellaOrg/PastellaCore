const crypto = require('crypto');

/**
 * Velora Algorithm - GPU-Optimized Memory Walker
 * ASIC-resistant algorithm using random memory access patterns
 */
class VeloraUtils {
  // Static cache shared across all instances
  static _scratchpadCache = new Map();

  /**
   *
   */
  constructor() {
    // Velora parameters
    this.SCRATCHPAD_SIZE = 64 * 1024 * 1024; // 64MB scratchpad
    this.SCRATCHPAD_WORDS = this.SCRATCHPAD_SIZE / 4; // 16,777,216 words (32-bit integers)
    this.MEMORY_READS = 1000;
    this.MIXING_ROUNDS = 2;
    this.MIXING_CONSTANT = 0x5bd1e995;
    this.EPOCH_LENGTH = 10000; // Change pattern every 10000 blocks

    // GPU.js configuration
    this.GPU_CONFIG = {
      threads: 4096,
      batchSize: 100000,
      precision: 'single',
    };

    // Cache scratchpad per epoch to prevent regeneration
    this._scratchpadCache = VeloraUtils._scratchpadCache;
    this._currentEpoch = -1;
  }

  /**
   * Fast 32-bit PRNG (xorshift32)
   * @param state
   */
  xorshift32(state) {
    state ^= (state << 13) >>> 0;
    state ^= (state >>> 17) >>> 0;
    state ^= (state << 5) >>> 0;
    return state >>> 0;
  }

  /**
   * Derive 32-bit seed from a hex string
   * @param hex
   */
  seedFromHex(hex) {
    const buf = Buffer.from(hex, 'hex');
    // Mix 4 words if available
    let s = 0;
    for (let i = 0; i < buf.length; i += 4) {
      const v = buf.readUInt32LE(i % (buf.length - (buf.length % 4 || 4)));
      s = (s ^ v) >>> 0;
      s = this.xorshift32(s);
    }
    // Ensure non-zero
    return (s || 0x9e3779b9) >>> 0;
  }

  /**
   * Generate epoch seed for pattern generation
   * @param {number} blockNumber
   * @returns {string} hex seed
   */
  generateEpochSeed(blockNumber) {
    const epoch = Math.floor(blockNumber / this.EPOCH_LENGTH);
    const seed = `velora-epoch-${epoch}`;
    return crypto.createHash('sha256').update(seed).digest('hex');
  }

  /**
   * Generate scratchpad for the current epoch (PRNG-based, fast)
   * @param {string} epochSeed
   * @returns {Uint32Array} scratchpad data
   */
  generateScratchpad(epochSeed) {
    // FIXED: Use epoch seed directly without double hashing as per specification
    // Initialize scratchpad
    const scratchpad = new Uint32Array(this.SCRATCHPAD_WORDS);

    // Use simple xorshift32 as per specification - seed directly from epoch seed
    let state = this.seedFromHex(epochSeed);

    for (let i = 0; i < this.SCRATCHPAD_WORDS; i++) {
      state = this.xorshift32(state);
      scratchpad[i] = state >>> 0;
    }

    return scratchpad;
  }

  /**
   * Mix the scratchpad to increase entropy
   * @param {Uint32Array} scratchpad
   * @param {string} seed
   */
  mixScratchpad(scratchpad, seed) {
    // Extract seed number from epoch seed - match miner's approach
    const seedBuffer = Buffer.from(seed, 'hex');
    const first4Bytes = seedBuffer.slice(0, 4);
    const seedHex = first4Bytes.toString('hex');
    const seedNum = parseInt(seedHex, 16); // Parse as big-endian hex like miner

    // Mix the scratchpad using the seed - CORRECT SPEC IMPLEMENTATION
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < scratchpad.length; i++) {
        // Calculate mix index as per specification
        const mixIndex = (i + seedNum + round) % scratchpad.length;
        const v = scratchpad[mixIndex];
        let x = scratchpad[i];

        // Apply the 4-step mixing algorithm from specification
        x = (x ^ v) >>> 0;
        x = (x + ((v << 13) >>> 0)) >>> 0;
        x = (x ^ (x >>> 17)) >>> 0;
        x = Math.imul(x, 0x5bd1e995) >>> 0;

        scratchpad[i] = x >>> 0;
      }
    }
  }

  /**
   * Generate memory access pattern for the current block (ENHANCED - PRNG-based, fast)
   * @param {number} blockNumber - Block height in the blockchain
   * @param {number} nonce - Mining nonce for proof-of-work
   * @param {number} timestamp - Block creation timestamp in milliseconds
   * @param {string} previousHash - Hash of the previous block
   * @param {string} merkleRoot - Merkle root of all transactions
   * @param {number} difficulty - Current network difficulty target
   * @returns {number[]} array of memory indices
   */
  generateMemoryPattern(blockNumber, nonce, timestamp, previousHash, merkleRoot, difficulty) {
    const pattern = new Array(this.MEMORY_READS);

    // ENHANCED: Seed PRNG from ALL input parameters as specified in VELORA_ALGO.md
    const blockNumberBuf = Buffer.alloc(8);
    blockNumberBuf.writeBigUInt64LE(BigInt(blockNumber), 0);

    const nonceBuf = Buffer.alloc(8);
    nonceBuf.writeBigUInt64LE(BigInt(nonce), 0);

    const timestampBuf = Buffer.alloc(8);
    timestampBuf.writeBigUInt64LE(BigInt(timestamp), 0);

    const difficultyBuf = Buffer.alloc(4);
    difficultyBuf.writeUInt32LE(difficulty, 0);

    // ENHANCED: Include all parameters in seed data as per specification
    const seedData = Buffer.concat([
      blockNumberBuf,
      nonceBuf,
      timestampBuf,
      Buffer.from(previousHash, 'hex'),
      Buffer.from(merkleRoot, 'hex'),
      difficultyBuf,
    ]);

    const seedHex = crypto.createHash('sha256').update(seedData).digest('hex');

    let state = this.seedFromHex(seedHex);

    const words = this.SCRATCHPAD_WORDS;
    for (let i = 0; i < this.MEMORY_READS; i++) {
      state = this.xorshift32(state);
      pattern[i] = state % words;
    }

    return pattern;
  }

  /**
   * Execute memory walk and generate hash (ENHANCED)
   * @param {Uint32Array} scratchpad
   * @param {number[]} pattern
   * @param {number} nonce
   * @param {number} timestamp
   * @returns {string} final hash
   */
  executeMemoryWalk(scratchpad, pattern, nonce, timestamp) {
    let accumulator = 0;

    // Convert nonce and timestamp to buffers for mixing
    const nonceBuffer = Buffer.alloc(8);
    nonceBuffer.writeBigUInt64LE(BigInt(nonce), 0);

    const timestampBuffer = Buffer.alloc(8);
    timestampBuffer.writeBigUInt64LE(BigInt(timestamp), 0);

    // DEBUG: Log the buffer contents for comparison
    console.log('=== BUFFER DEBUG ===');
    console.log(`Nonce: ${nonce}, Nonce Buffer (hex): ${nonceBuffer.toString('hex')}`);
    console.log(`Timestamp: ${timestamp}, Timestamp Buffer (hex): ${timestampBuffer.toString('hex')}`);
    console.log('=== END BUFFER DEBUG ===');

    for (let i = 0; i < pattern.length; i++) {
      const readPos = pattern[i] % this.SCRATCHPAD_WORDS;
      const value = scratchpad[readPos];

      // CORRECT SPEC IMPLEMENTATION - 6-step accumulator algorithm
      accumulator = (accumulator ^ value) >>> 0;
      accumulator = (accumulator + ((value << i % 32) >>> 0)) >>> 0;
      accumulator = (accumulator ^ (accumulator >>> 13)) >>> 0;
      accumulator = Math.imul(accumulator, 0x5bd1e995) >>> 0;

      // Mix in nonce and timestamp as per specification
      // SPECIFICATION COMPLIANCE: Use (i % 4) for proper 4-byte alignment
      // This cycles through 4 different positions, reading 4 bytes each
      const nonceIndex = i % 4; // Cycle through positions 0, 1, 2, 3
      const timestampIndex = i % 4; // Cycle through positions 0, 1, 2, 3

      const nonceWord = nonceBuffer.readUInt32LE(nonceIndex);
      const timestampWord = timestampBuffer.readUInt32LE(timestampIndex);

      // DEBUG: Log the mixing values for comparison
      if (i < 10) {
        console.log(
          `  Mix[${i}]: nonceIndex=${nonceIndex}, nonceWord=0x${nonceWord.toString(16).padStart(8, '0')}, timestampIndex=${timestampIndex}, timestampWord=0x${timestampWord.toString(16).padStart(8, '0')}`
        );
      }

      accumulator = (accumulator ^ nonceWord ^ timestampWord) >>> 0;
    }

    return accumulator;
  }

  /**
   * Main Velora hash function (ENHANCED - matches VELORA_ALGO.md specification)
   * @param {number} blockNumber - Block height in the blockchain
   * @param {number} nonce - Mining nonce for proof-of-work
   * @param {number} timestamp - Block creation timestamp in milliseconds
   * @param {string} previousHash - Hash of the previous block
   * @param {string} merkleRoot - Merkle root of all transactions
   * @param {number} difficulty - Current network difficulty target
   * @param {Uint32Array} cache - optional, will generate if not provided
   * @returns {string} final hash
   */
  veloraHash(blockNumber, nonce, timestamp, previousHash, merkleRoot, difficulty, cache = null) {
    try {
      // Generate epoch seed
      const epochSeed = this.generateEpochSeed(blockNumber);

      // Generate or use provided scratchpad (cached per-epoch)
      let scratchpad;

      // Force cache population if not present
      if (!VeloraUtils._scratchpadCache.has(epochSeed)) {
        const freshScratchpad = this.generateScratchpad(epochSeed);

        // Mix the scratchpad after generation (like miner does)
        this.mixScratchpad(freshScratchpad, epochSeed);

        // Cache the MIXED scratchpad, not the original
        VeloraUtils._scratchpadCache.set(epochSeed, Array.from(freshScratchpad));
        scratchpad = freshScratchpad;
      } else {
        scratchpad = new Uint32Array(VeloraUtils._scratchpadCache.get(epochSeed));
      }

      // ENHANCED: Generate memory access pattern with ALL parameters
      const pattern = this.generateMemoryPattern(blockNumber, nonce, timestamp, previousHash, merkleRoot, difficulty);

      // DEBUG: Log the pattern generation
      console.log('Pattern first 10 elements:', pattern.slice(0, 10).join(', '));

      // DEBUG: Log first 20 scratchpad values for comparison with miner
      console.log('=== SCRATCHPAD COMPARISON DEBUG ===');
      for (let i = 0; i < 20; i++) {
        const scratchpadHex = scratchpad[i].toString(16).padStart(8, '0');
        console.log(`Scratchpad[${i}] = 0x${scratchpadHex} (${scratchpad[i]})`);
      }
      console.log('=== END SCRATCHPAD COMPARISON DEBUG ===');

      // ENHANCED: Execute memory walk with timestamp parameter
      const accumulator = this.executeMemoryWalk(scratchpad, pattern, nonce, timestamp);

      // ENHANCED: Final hash with ALL parameters as per specification
      const finalHash = this.generateFinalHash(
        blockNumber,
        nonce,
        timestamp,
        previousHash,
        merkleRoot,
        difficulty,
        accumulator
      );

      return finalHash;
    } catch (error) {
      throw new Error(`Velora hash generation failed: ${error.message}`);
    }
  }

  /**
   * ENHANCED: Generate final hash with all parameters as specified in VELORA_ALGO.md
   * @param {number} blockNumber
   * @param {number} nonce
   * @param {number} timestamp
   * @param {string} previousHash
   * @param {string} merkleRoot
   * @param {number} difficulty
   * @param {number} accumulator
   * @returns {string} final hash
   */
  generateFinalHash(blockNumber, nonce, timestamp, previousHash, merkleRoot, difficulty, accumulator) {
    // ENHANCED: Include ALL parameters in final hash as per specification
    const blockNumberBuffer = Buffer.alloc(8);
    blockNumberBuffer.writeBigUInt64LE(BigInt(blockNumber), 0);

    const nonceBuffer = Buffer.alloc(8);
    nonceBuffer.writeBigUInt64LE(BigInt(nonce), 0);

    const timestampBuffer = Buffer.alloc(8);
    timestampBuffer.writeBigUInt64LE(BigInt(timestamp), 0);

    const difficultyBuffer = Buffer.alloc(4);
    difficultyBuffer.writeUInt32LE(difficulty, 0);

    const accumulatorBuffer = Buffer.alloc(4);
    accumulatorBuffer.writeUInt32LE(accumulator >>> 0, 0);

    // ENHANCED: Final data includes ALL parameters as specified
    // Total length: 8 + 8 + 8 + 32 + 32 + 4 + 4 = 96 bytes
    const finalData = Buffer.concat([
      blockNumberBuffer,
      nonceBuffer,
      timestampBuffer,
      Buffer.from(previousHash, 'hex'),
      Buffer.from(merkleRoot, 'hex'),
      difficultyBuffer,
      accumulatorBuffer,
    ]);

    // 🎯 CRITICAL DEBUG: Show exact 96-byte input data for comparison with miner
    console.log('=== 🎯 DAEMON FINAL HASH - 96-BYTE INPUT DEBUG ===');
    console.log(`Block number: ${blockNumber}`);
    console.log(`Nonce: ${nonce}`);
    console.log(`Timestamp: ${timestamp}`);
    console.log(`Previous hash: ${previousHash}`);
    console.log(`Merkle root: ${merkleRoot}`);
    console.log(`Difficulty: ${difficulty}`);
    console.log(`Accumulator: ${accumulator}`);
    console.log(`Final data length: ${finalData.length} bytes (should be 96)`);

    // Show exact 96-byte input data as hex (matching miner format)
    console.log('=== EXACT 96-BYTE INPUT FOR SHA-256 (DAEMON) ===');
    let hexOutput = '';
    for (let i = 0; i < finalData.length; i++) {
      hexOutput += finalData[i].toString(16).padStart(2, '0');
      if ((i + 1) % 16 === 0) {
        console.log(hexOutput);
        hexOutput = '';
      } else if ((i + 1) % 8 === 0) {
        hexOutput += ' ';
      }
    }
    if (hexOutput.length > 0) console.log(hexOutput);
    console.log('=== END 96-BYTE INPUT (DAEMON) ===');

    const finalHash = crypto.createHash('sha256').update(finalData).digest();
    const finalHashHex = finalHash.toString('hex');
    console.log(`Daemon computed hash: ${finalHashHex}`);
    console.log('=== END DAEMON FINAL HASH DEBUG ===');

    return finalHashHex;
  }

  /**
   * Verify a Velora hash (ENHANCED - matches new signature)
   * @param {number} blockNumber
   * @param {number} nonce
   * @param {number} timestamp
   * @param {string} previousHash
   * @param {string} merkleRoot
   * @param {number} difficulty
   * @param {string} targetHash
   * @param {Uint32Array} cache - optional
   */
  verifyHash(blockNumber, nonce, timestamp, previousHash, merkleRoot, difficulty, targetHash, cache = null) {
    try {
      console.log('=== HASH VERIFICATION DEBUG ===');
      console.log(`Verifying hash for block ${blockNumber}, nonce ${nonce}, difficulty ${difficulty}`);
      console.log(`Target Hash: ${targetHash}`);

      const calculatedHash = this.veloraHash(
        blockNumber,
        nonce,
        timestamp,
        previousHash,
        merkleRoot,
        difficulty,
        cache
      );
      console.log(`Calculated Hash: ${calculatedHash}`);

      const hashesMatch = calculatedHash === targetHash;
      console.log(`Hashes Match: ${hashesMatch}`);

      if (hashesMatch) {
        console.log('Hash validation passed, proceeding to difficulty check...');

        // Calculate target from difficulty
        const target = this.calculateTarget(difficulty);
        console.log(`Target for difficulty ${difficulty}: 0x${target}`);

        // Convert hash to BigInt for comparison
        const hashBigInt = BigInt(`0x${calculatedHash}`);
        const targetBigInt = BigInt(`0x${target}`);

        console.log(`Hash as BigInt: ${hashBigInt.toString()}`);
        console.log(`Target as BigInt: ${targetBigInt.toString()}`);

        // Check if hash meets difficulty (hash <= target)
        const meetsDifficulty = hashBigInt <= targetBigInt;
        console.log(`Hash <= Target: ${hashBigInt.toString()} <= ${targetBigInt.toString()} = ${meetsDifficulty}`);

        if (meetsDifficulty) {
          console.log('✅ Hash meets difficulty requirements');
        } else {
          console.log('❌ Hash does NOT meet difficulty requirements');
        }

        console.log('=== END HASH VERIFICATION DEBUG ===');
        return meetsDifficulty;
      }
      console.log('❌ Hash validation failed - hashes do not match');
      console.log('=== END HASH VERIFICATION DEBUG ===');
      return false;
    } catch (error) {
      console.log(`❌ Hash verification error: ${error.message}`);
      console.log('=== END HASH VERIFICATION DEBUG ===');
      return false;
    }
  }

  /**
   * Calculate target from difficulty
   * @param {number} difficulty
   * @returns {string} target hash
   */
  calculateTarget(difficulty) {
    const maxTarget = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
    const target = maxTarget / BigInt(difficulty);

    // DEBUG: Add difficulty calculation debugging
    console.log('=== DIFFICULTY CALCULATION DEBUG ===');
    console.log(`Input Difficulty: ${difficulty}`);
    console.log(`Max Target (hex): 0x${maxTarget.toString(16)}`);
    console.log(`Max Target (decimal): ${maxTarget.toString()}`);
    console.log(`Calculated Target (hex): 0x${target.toString(16).padStart(64, '0')}`);
    console.log(`Calculated Target (decimal): ${target.toString()}`);
    console.log('=== END DIFFICULTY CALCULATION DEBUG ===');

    return target.toString(16).padStart(64, '0');
  }

  /**
   * Check if hash meets difficulty
   * @param {string} hash
   * @param {number} difficulty
   * @returns {boolean} true if meets difficulty
   */
  meetsDifficulty(hash, difficulty) {
    const target = this.calculateTarget(difficulty);
    return BigInt(`0x${hash}`) <= BigInt(`0x${target}`);
  }

  /**
   * Get algorithm info
   * @returns {object} algorithm information
   */
  getAlgorithmInfo() {
    return {
      name: 'Velora',
      version: '1.0.1',
      scratchpadSize: this.SCRATCHPAD_SIZE,
      memoryReads: this.MEMORY_READS,
      epochLength: this.EPOCH_LENGTH,
      description: 'GPU-Optimized Memory Walker - ASIC Resistant (Enhanced Security)',
      enhancedFeatures: [
        'Timestamp validation',
        'Previous hash validation',
        'Merkle root validation',
        'Difficulty validation',
        'Enhanced input parameter security',
        '64-bit block number support',
        'Integrated scratchpad mixing',
      ],
      dataLength:
        '96 bytes (blockNumber: 8, nonce: 8, timestamp: 8, previousHash: 32, merkleRoot: 32, difficulty: 4, accumulator: 4)',
    };
  }
}

module.exports = VeloraUtils;
