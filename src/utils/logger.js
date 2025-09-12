const chalk = require('chalk');

/**
 *
 */
class Logger {
  /**
   *
   */
  constructor() {
    this.modules = {
      API: 'API',
      P2P: 'P2P',
      BLOCKCHAIN: 'BLOCKCHAIN',
      NETWORK: 'NETWORK',
      SYNC: 'SYNC',
      SYSTEM: 'SYSTEM',
      CHECKPOINT_MANAGER: 'CHECKPOINT_MANAGER',
      SEED_NODE_MANAGER: 'SEED_NODE_MANAGER',
      PEER_REPUTATION: 'PEER_REPUTATION',
      IDENTITY: 'IDENTITY',
      RATE_LIMITER: 'RATE_LIMITER',
      NETWORK_SYNC: 'NETWORK_SYNC',
      AUTH: 'AUTH',
      BLOCKS: 'BLOCKS',
      WALLET_API: 'WALLET_API',
    };

    this.levels = {
      INFO: 'INFO',
      WARN: 'WARN',
      ERROR: 'ERROR',
      DEBUG: 'DEBUG',
    };

    this.debugMode = false;
  }

  /**
   * Enable or disable debug mode
   * @param enabled
   */
  setDebugMode(enabled) {
    this.debugMode = enabled;
  }

  /**
   * Get current timestamp in the required format
   */
  getTimestamp() {
    const now = new Date();
    const day = String(now.getDate()).padStart(2, '0');
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const year = now.getFullYear();
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    const milliseconds = String(now.getMilliseconds()).padStart(3, '0');

    return `${day}-${month}-${year} ${hours}:${minutes}:${seconds}.${milliseconds}`;
  }

  /**
   * Pad module name to ensure alignment
   * @param module
   */
  padModule(module) {
    const maxLength = Math.max(...Object.values(this.modules).map(m => m.length));
    return module.padEnd(maxLength);
  }

  /**
   * Get colored module name
   * @param module
   */
  getColoredModule(module) {
    const colors = {
      API: chalk.cyan,
      P2P: chalk.blue,
      BLOCKCHAIN: chalk.green,
      NETWORK: chalk.blue,
      SYNC: chalk.cyan,
      SYSTEM: chalk.white,
      CHECKPOINT_MANAGER: chalk.cyan.bold,
      SEED_NODE_MANAGER: chalk.blue.bold,
      PEER_REPUTATION: chalk.magenta.bold,
      IDENTITY: chalk.green.bold,
      RATE_LIMITER: chalk.yellow.bold,
      NETWORK_SYNC: chalk.blue.bold,
      AUTH: chalk.yellow,
      BLOCKS: chalk.green.bold,
    };

    return colors[module] ? colors[module](`[${module}]`) : chalk.white(`[${module}]`);
  }

  /**
   * Get colored log level
   * @param level
   */
  getColoredLevel(level) {
    const colors = {
      INFO: chalk.green,
      WARN: chalk.yellow,
      ERROR: chalk.red,
      DEBUG: chalk.gray,
    };

    return colors[level] ? colors[level](`[${level}]`) : chalk.white(`[${level}]`);
  }

  /**
   * Log a message with the specified module and level
   * @param module
   * @param level
   * @param message
   */
  log(module, level, message) {
    // Skip DEBUG messages if debug mode is disabled
    if (level === 'DEBUG' && !this.debugMode) {
      return;
    }

    const timestamp = chalk.gray(`[${this.getTimestamp()}]`);
    const coloredModule = this.getColoredModule(module);
    const coloredLevel = this.getColoredLevel(level);

    // Add spacing between module and level brackets
    const maxLength = Math.max(...Object.values(this.modules).map(m => m.length));
    const spacing = ' '.repeat(Math.max(0, maxLength - module.length + 1));

    console.log(`${timestamp} ${coloredModule}${spacing} ${coloredLevel} ${message}`);
  }

  /**
   * Convenience methods for different log levels
   * @param module
   * @param message
   */
  info(module, message) {
    this.log(module, 'INFO', message);
  }

  /**
   *
   * @param module
   * @param message
   */
  warn(module, message) {
    this.log(module, 'WARN', message);
  }

  /**
   *
   * @param module
   * @param message
   */
  error(module, message) {
    this.log(module, 'ERROR', message);
  }

  /**
   *
   * @param module
   * @param message
   */
  debug(module, message) {
    this.log(module, 'DEBUG', message);
  }
}

module.exports = new Logger();
