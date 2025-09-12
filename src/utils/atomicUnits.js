/**
 * Atomic Units Utility
 * Converts between decimal units (e.g., 0.50 PAS) and atomic units (e.g., 50000000)
 */

const fs = require('fs');
const path = require('path');

// Get config decimals
/**
 *
 */
function getConfigDecimals() {
  try {
    const configPath = path.join(process.cwd(), 'config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    return config.decimals || 8;
  } catch (error) {
    console.warn('Warning: Could not read config.json, using default 8 decimals');
    return 8;
  }
}

const DECIMALS = getConfigDecimals();
const ATOMIC_MULTIPLIER = 10 ** DECIMALS;

/**
 * Convert decimal amount to atomic units
 * @param {number|string} decimalAmount - Amount in decimal units (e.g., 0.50)
 * @returns {number} Amount in atomic units (e.g., 50000000)
 */
function toAtomicUnits(decimalAmount) {
  let amount = decimalAmount;
  if (typeof amount === 'string') {
    amount = parseFloat(amount);
  }

  if (Number.isNaN(amount)) {
    throw new Error('Invalid decimal amount');
  }

  // Round to avoid floating point precision issues
  return Math.round(amount * ATOMIC_MULTIPLIER);
}

/**
 * Convert atomic units to decimal amount
 * @param {number} atomicAmount - Amount in atomic units (e.g., 50000000)
 * @returns {number} Amount in decimal units (e.g., 0.50)
 */
function fromAtomicUnits(atomicAmount) {
  if (typeof atomicAmount !== 'number' || Number.isNaN(atomicAmount)) {
    throw new Error('Invalid atomic amount');
  }

  return atomicAmount / ATOMIC_MULTIPLIER;
}

/**
 * Format atomic units as decimal string with proper precision
 * @param {number} atomicAmount - Amount in atomic units
 * @returns {string} Formatted decimal string
 */
function formatAtomicUnits(atomicAmount) {
  const decimal = fromAtomicUnits(atomicAmount);
  return decimal.toFixed(DECIMALS);
}

/**
 * Get the atomic multiplier (10^decimals)
 * @returns {number} Atomic multiplier
 */
function getAtomicMultiplier() {
  return ATOMIC_MULTIPLIER;
}

/**
 * Get the number of decimals from config
 * @returns {number} Number of decimals
 */
function getDecimals() {
  return DECIMALS;
}

/**
 * Calculate the halved coinbase reward based on current block height
 * @param {number} blockHeight - Current block height
 * @param {number} baseReward - Base coinbase reward in atomic units
 * @param {number} halvingBlocks - Number of blocks between halvings
 * @returns {number} Halved reward in atomic units
 */
function calculateHalvedReward(blockHeight, baseReward, halvingBlocks) {
  if (blockHeight <= 0) {
    return baseReward;
  }

  // Calculate how many halvings have occurred
  const halvings = Math.floor(blockHeight / halvingBlocks);

  // Apply halving: reward = baseReward / (2^halvings)
  const halvedReward = Math.floor(baseReward / 2 ** halvings);

  // Ensure reward doesn't go below 1 atomic unit
  return Math.max(halvedReward, 1);
}

/**
 * Get halving information for a given block height
 * @param {number} blockHeight - Current block height
 * @param {number} baseReward - Base coinbase reward in atomic units
 * @param {number} halvingBlocks - Number of blocks between halvings
 * @returns {object} Halving information
 */
function getHalvingInfo(blockHeight, baseReward, halvingBlocks) {
  if (blockHeight <= 0) {
    return {
      currentReward: baseReward,
      halvings: 0,
      nextHalving: halvingBlocks,
      blocksUntilHalving: halvingBlocks,
      halvingBlock: halvingBlocks,
    };
  }

  const halvings = Math.floor(blockHeight / halvingBlocks);
  const currentReward = calculateHalvedReward(blockHeight, baseReward, halvingBlocks);
  const nextHalving = (halvings + 1) * halvingBlocks;
  const blocksUntilHalving = nextHalving - blockHeight;

  return {
    currentReward,
    halvings,
    nextHalving,
    blocksUntilHalving,
    halvingBlock: nextHalving,
  };
}

module.exports = {
  toAtomicUnits,
  fromAtomicUnits,
  formatAtomicUnits,
  getAtomicMultiplier,
  getDecimals,
  calculateHalvedReward,
  getHalvingInfo,
  DECIMALS,
  ATOMIC_MULTIPLIER,
};
