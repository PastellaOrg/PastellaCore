const chalk = require('chalk');

/**
 * Validate wallet address format
 * @param address
 */
function validateAddress(address) {
  // Basic validation: check if it's a string and has the expected format
  if (typeof address !== 'string' || address.length < 26 || address.length > 35) {
    return false;
  }

  // Check if it starts with common cryptocurrency address prefixes
  // For this implementation, we'll use a simple format check
  const addressRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
  return addressRegex.test(address);
}

/**
 * Format hash rate with appropriate units (H/s, KH/s, MH/s, GH/s)
 * @param hashRate
 */
function formatHashRate(hashRate) {
  if (hashRate === 0) return '0 H/s';

  if (hashRate >= 1000000000) {
    return `${(hashRate / 1000000000).toFixed(2)} GH/s`;
  }
  if (hashRate >= 1000000) {
    return `${(hashRate / 1000000).toFixed(2)} MH/s`;
  }
  if (hashRate >= 1000) {
    return `${(hashRate / 1000).toFixed(2)} KH/s`;
  }
  return `${hashRate.toFixed(2)} H/s`;
}

/**
 * Generate CLI prompt based on wallet status
 * @param walletLoaded
 * @param walletName
 */
function generatePrompt(walletLoaded, walletName) {
  let prompt = '';

  // Add wallet name if loaded
  if (walletLoaded && walletName) {
    prompt += chalk.blue('[') + chalk.green(walletName) + chalk.blue('] ');
  }

  prompt += chalk.blue('pastella>');
  return prompt;
}

module.exports = {
  validateAddress,
  formatHashRate,
  generatePrompt,
};
