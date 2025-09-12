const crypto = require('crypto');

const keccak256 = require('keccak256');

/**
 * KawPow Algorithm Implementation
 * KawPow is a memory-hard algorithm that combines ProgPoW with Keccak256
 * This is a simplified implementation focusing on the core mining logic
 */

/**
 *
 */
class KawPowUtils {
  /**
   *
   */
  constructor() {
    // ProgPoW parameters (simplified for GPU mining)
    this.PROGPOW_PERIOD = 50;
    this.PROGPOW_LANES = 16;
    this.PROGPOW_REGS = 32;
    this.PROGPOW_CACHE_BYTES = 16 * 1024; // 16KB cache
    this.PROGPOW_CNT_CACHE = 11;
    this.PROGPOW_CNT_MATH = 18;
    this.PROGPOW_CNT_MATH_VM = 11;

    // Keccak256 parameters
    this.KECCAK256_BLOCK_SIZE = 136;
    this.KECCAK256_DIGEST_SIZE = 32;
  }

  /**
   * Generate seed hash for ProgPoW
   * @param blockNumber
   */
  generateSeedHash(blockNumber) {
    const seed = keccak256(Buffer.from(blockNumber.toString(), 'hex'));
    return seed.toString('hex');
  }

  /**
   * Generate cache for ProgPoW
   * @param {string} seed - Seed hash for cache generation
   * @param {number} size - Number of cache entries (not bytes)
   */
  generateCache(seed, size = 1000) {
    // Create array with exactly the requested number of entries
    const cache = new Array(size);
    const seedBuffer = Buffer.from(seed, 'hex');

    // Initialize cache with seed
    for (let i = 0; i < cache.length; i++) {
      cache[i] = keccak256(Buffer.concat([seedBuffer, Buffer.from(i.toString(), 'hex')])).readUInt32LE(0);
    }

    // Generate cache using Keccak256
    for (let i = 0; i < this.PROGPOW_CNT_CACHE; i++) {
      for (let j = 0; j < cache.length; j++) {
        const idx = cache[j] % cache.length;
        const val = cache[idx];
        cache[j] = keccak256(
          Buffer.from([val & 0xff, (val >> 8) & 0xff, (val >> 16) & 0xff, (val >> 24) & 0xff])
        ).readUInt32LE(0);
      }
    }

    return cache;
  }

  /**
   * ProgPoW hash function
   * @param blockNumber
   * @param headerHash
   * @param nonce
   * @param cache
   */
  progPowHash(blockNumber, headerHash, nonce, cache) {
    const seed = this.generateSeedHash(blockNumber);
    const mix = new Array(this.PROGPOW_LANES);

    // Initialize mix with header hash and nonce
    for (let i = 0; i < this.PROGPOW_LANES; i++) {
      mix[i] = keccak256(
        Buffer.concat([
          Buffer.from(headerHash, 'hex'),
          Buffer.from(nonce.toString(), 'hex'),
          Buffer.from(i.toString(), 'hex'),
        ])
      ).readUInt32LE(0);
    }

    // ProgPoW mixing rounds
    for (let round = 0; round < this.PROGPOW_CNT_MATH; round++) {
      for (let lane = 0; lane < this.PROGPOW_LANES; lane++) {
        const cacheIndex = (mix[lane] + round) % cache.length;
        const cacheValue = cache[cacheIndex];

        // Mixing operations
        mix[lane] = this.mix(mix[lane], cacheValue, round);
      }
    }

    // Final mix reduction
    let finalMix = 0;
    for (let i = 0; i < this.PROGPOW_LANES; i++) {
      finalMix ^= mix[i];
    }

    return finalMix;
  }

  /**
   * Mixing function for ProgPoW
   * @param a
   * @param b
   * @param c
   */
  mix(a, b, c) {
    // Simplified mixing operations suitable for GPU
    let result = a + b + c;
    result ^= result >>> 13;
    result *= 0x5bd1e995;
    result ^= result >>> 15;
    result *= 0x5bd1e995;
    return result;
  }

  /**
   * KawPow hash function (ProgPoW + Keccak256)
   * @param blockNumber
   * @param headerHash
   * @param nonce
   * @param cache
   */
  kawPowHash(blockNumber, headerHash, nonce, cache) {
    // First, run ProgPoW
    const progPowResult = this.progPowHash(blockNumber, headerHash, nonce, cache);

    // Then, apply Keccak256
    const finalHash = keccak256(
      Buffer.concat([
        Buffer.from(headerHash, 'hex'),
        Buffer.from(nonce.toString(), 'hex'),
        Buffer.from(progPowResult.toString(16).padStart(8, '0'), 'hex'),
      ])
    );

    return finalHash.toString('hex');
  }

  /**
   * Verify if hash meets difficulty target
   * @param hash
   * @param target
   */
  verifyHash(hash, target) {
    try {
      const hashBigInt = BigInt(`0x${hash}`);
      const targetBigInt = BigInt(`0x${target}`);
      return hashBigInt <= targetBigInt;
    } catch (error) {
      return false;
    }
  }

  /**
   * Calculate target from difficulty
   * @param difficulty
   */
  calculateTarget(difficulty) {
    const maxTarget = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const targetHex = BigInt(`0x${maxTarget}`) / BigInt(difficulty);
    return targetHex.toString(16).padStart(64, '0');
  }

  /**
   * Generate mining data for GPU
   * @param blockNumber
   * @param headerHash
   * @param nonce
   * @param cache
   */
  generateMiningData(blockNumber, headerHash, nonce, cache) {
    return {
      blockNumber,
      headerHash,
      nonce,
      cache: cache.slice(0, 1000), // Limit cache size for GPU transfer
      seed: this.generateSeedHash(blockNumber),
    };
  }

  /**
   * Process GPU mining results
   * @param results
   * @param blockNumber
   * @param headerHash
   * @param cache
   */
  processGPUResults(results, blockNumber, headerHash, cache) {
    const validResults = [];

    for (const result of results) {
      if (result && result.nonce !== undefined) {
        const hash = this.kawPowHash(blockNumber, headerHash, result.nonce, cache);
        validResults.push({
          nonce: result.nonce,
          hash,
          isValid: true,
        });
      }
    }

    return validResults;
  }

  /**
   * Optimize cache for GPU transfer
   * @param cache
   * @param maxSize
   */
  optimizeCacheForGPU(cache, maxSize = 1000) {
    if (cache.length <= maxSize) {
      return cache;
    }

    // Sample cache entries for GPU processing
    const optimized = [];
    const step = Math.floor(cache.length / maxSize);

    for (let i = 0; i < maxSize; i++) {
      optimized.push(cache[i * step]);
    }

    return optimized;
  }

  /**
   * Generate cache key for block
   * @param blockNumber
   * @param headerHash
   */
  generateCacheKey(blockNumber, headerHash) {
    return `cache_${blockNumber}_${headerHash.substring(0, 16)}`;
  }

  /**
   * Validate cache integrity
   * @param cache
   * @param expectedSize
   */
  validateCache(cache, expectedSize) {
    if (!Array.isArray(cache) || cache.length !== expectedSize) {
      return false;
    }

    for (const item of cache) {
      if (typeof item !== 'number' || item < 0 || item > 0xffffffff) {
        return false;
      }
    }

    return true;
  }
}

module.exports = KawPowUtils;
