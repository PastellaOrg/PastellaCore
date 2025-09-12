const fs = require('fs');
const path = require('path');

const logger = require('../utils/logger.js');

/**
 * Checkpoint Manager - Handles blockchain checkpoint validation
 * CRITICAL: Stops daemon if invalid checkpoints are detected
 */
class CheckpointManager {
  /**
   *
   * @param dataDir
   */
  constructor(dataDir = './data') {
    this.dataDir = dataDir;
    this.checkpointsPath = path.join(dataDir, 'checkpoints.json');
    this.checkpoints = [];
    this.metadata = {};
    this.isValid = true;
    this.validationErrors = [];

    logger.debug('CHECKPOINT_MANAGER', `Initializing CheckpointManager: dataDir=${dataDir}`);
  }

  /**
   * Load checkpoints from file
   */
  loadCheckpoints() {
    try {
      logger.debug('CHECKPOINT_MANAGER', `Loading checkpoints from: ${this.checkpointsPath}`);

      if (!fs.existsSync(this.checkpointsPath)) {
        logger.warn('CHECKPOINT_MANAGER', `Checkpoints file not found: ${this.checkpointsPath}`);
        logger.info('CHECKPOINT_MANAGER', `No checkpoints loaded - continuing without checkpoint validation`);
        return true;
      }

      const checkpointData = fs.readFileSync(this.checkpointsPath, 'utf8');
      const parsed = JSON.parse(checkpointData);

      this.checkpoints = parsed.checkpoints || [];
      this.metadata = parsed.metadata || {};

      logger.debug('CHECKPOINT_MANAGER', `Loaded ${this.checkpoints.length} checkpoints`);
      logger.debug('CHECKPOINT_MANAGER', `Checkpoint metadata: ${JSON.stringify(this.metadata)}`);

      // Validate checkpoint structure
      if (!this.validateCheckpointStructure()) {
        logger.error('CHECKPOINT_MANAGER', `Checkpoint structure validation failed`);
        return false;
      }

      return true;
    } catch (error) {
      logger.error('CHECKPOINT_MANAGER', `Failed to load checkpoints: ${error.message}`);
      logger.error('CHECKPOINT_MANAGER', `Error stack: ${error.stack}`);
      return false;
    }
  }

  /**
   * Validate checkpoint structure
   */
  validateCheckpointStructure() {
    logger.debug('CHECKPOINT_MANAGER', `Validating checkpoint structure...`);

    if (!Array.isArray(this.checkpoints)) {
      this.addValidationError('checkpoints_not_array', 'Checkpoints must be an array');
      return false;
    }

    for (let i = 0; i < this.checkpoints.length; i++) {
      const checkpoint = this.checkpoints[i];

      if (!checkpoint || typeof checkpoint !== 'object') {
        this.addValidationError('invalid_checkpoint_object', `Checkpoint ${i} is not a valid object`);
        return false;
      }

      if (typeof checkpoint.height !== 'number' || checkpoint.height < 0) {
        this.addValidationError('invalid_height', `Checkpoint ${i} has invalid height: ${checkpoint.height}`);
        return false;
      }

      if (!checkpoint.hash || typeof checkpoint.hash !== 'string') {
        this.addValidationError('invalid_hash', `Checkpoint ${i} has invalid hash: ${checkpoint.hash}`);
        return false;
      }

      if (checkpoint.hash.length !== 64) {
        this.addValidationError(
          'invalid_hash_length',
          `Checkpoint ${i} hash length invalid: ${checkpoint.hash.length} (expected 64)`
        );
        return false;
      }

      // Check for duplicate heights
      const duplicateHeight = this.checkpoints.findIndex((cp, idx) => idx !== i && cp.height === checkpoint.height);
      if (duplicateHeight !== -1) {
        this.addValidationError(
          'duplicate_height',
          `Checkpoint ${i} has duplicate height ${checkpoint.height} with checkpoint ${duplicateHeight}`
        );
        return false;
      }
    }

    logger.debug('CHECKPOINT_MANAGER', `Checkpoint structure validation passed`);
    return true;
  }

  /**
   * Validate checkpoints against blockchain
   * CRITICAL: This method will stop the daemon if invalid checkpoints are found
   * @param blockchain
   */
  validateCheckpoints(blockchain) {
    logger.debug('CHECKPOINT_MANAGER', `Validating checkpoints against blockchain...`);
    logger.debug('CHECKPOINT_MANAGER', `Blockchain height: ${blockchain.chain.length}`);

    if (this.checkpoints.length === 0) {
      logger.info('CHECKPOINT_MANAGER', `No checkpoints to validate`);
      return true;
    }

    this.validationErrors = [];
    let validCheckpoints = 0;
    let invalidCheckpoints = 0;

    for (const checkpoint of this.checkpoints) {
      logger.debug(
        'CHECKPOINT_MANAGER',
        `Validating checkpoint at height ${checkpoint.height}: ${checkpoint.hash.substring(0, 16)}...`
      );

      // Check if checkpoint height exists in blockchain
      if (checkpoint.height >= blockchain.chain.length) {
        logger.debug(
          'CHECKPOINT_MANAGER',
          `Checkpoint height ${checkpoint.height} exceeds blockchain height ${blockchain.chain.length} - skipping`
        );
        continue;
      }

      const block = blockchain.chain[checkpoint.height];
      if (!block) {
        logger.debug('CHECKPOINT_MANAGER', `Block at height ${checkpoint.height} not found in blockchain`);
        continue;
      }

      // Validate block hash against checkpoint
      if (block.hash !== checkpoint.hash) {
        const error = `Checkpoint validation FAILED at height ${checkpoint.height}`;
        const details = `Expected: ${checkpoint.hash}, Got: ${block.hash}`;

        logger.error('CHECKPOINT_MANAGER', `❌ ${error}`);
        logger.error('CHECKPOINT_MANAGER', `   ${details}`);

        this.addValidationError('hash_mismatch', error, details);
        invalidCheckpoints++;

        // CRITICAL: Stop daemon immediately for invalid checkpoints
        this.handleInvalidCheckpoint(error, details, checkpoint, block);
        return false; // This will stop the validation process
      }

      logger.debug('CHECKPOINT_MANAGER', `✅ Checkpoint at height ${checkpoint.height} validated successfully`);
      validCheckpoints++;
    }

    logger.info(
      'CHECKPOINT_MANAGER',
      `Checkpoint validation completed: ${validCheckpoints} valid, ${invalidCheckpoints} invalid`
    );

    if (invalidCheckpoints > 0) {
      logger.error('CHECKPOINT_MANAGER', `❌ ${invalidCheckpoints} invalid checkpoints detected - daemon stopped`);
      return false;
    }

    logger.info('CHECKPOINT_MANAGER', `✅ All checkpoints validated successfully`);
    return true;
  }

  /**
   * CRITICAL: Handle invalid checkpoint detection
   * This method will stop the daemon and provide clear instructions
   * @param error
   * @param details
   * @param checkpoint
   * @param actualBlock
   */
  handleInvalidCheckpoint(error, details, checkpoint, actualBlock) {
    logger.error('CHECKPOINT_MANAGER', `🚨 CRITICAL: INVALID CHECKPOINT DETECTED!`);
    logger.error('CHECKPOINT_MANAGER', `🚨 The daemon will now stop to prevent further corruption.`);
    logger.error('CHECKPOINT_MANAGER', `🚨`);
    logger.error('CHECKPOINT_MANAGER', `🚨 CHECKPOINT DETAILS:`);
    logger.error('CHECKPOINT_MANAGER', `🚨   Height: ${checkpoint.height}`);
    logger.error('CHECKPOINT_MANAGER', `🚨   Expected Hash: ${checkpoint.hash}`);
    logger.error('CHECKPOINT_MANAGER', `🚨   Description: ${checkpoint.description || 'No description'}`);
    logger.error('CHECKPOINT_MANAGER', `🚨`);
    logger.error('CHECKPOINT_MANAGER', `🚨 ACTUAL BLOCK:`);
    logger.error('CHECKPOINT_MANAGER', `🚨   Height: ${actualBlock.index}`);
    logger.error('CHECKPOINT_MANAGER', `🚨   Actual Hash: ${actualBlock.hash}`);
    logger.error('CHECKPOINT_MANAGER', `🚨   Timestamp: ${new Date(actualBlock.timestamp).toISOString()}`);
    logger.error('CHECKPOINT_MANAGER', `🚨`);
    logger.error('CHECKPOINT_MANAGER', `🚨 IMMEDIATE ACTION REQUIRED:`);
    logger.error('CHECKPOINT_MANAGER', `🚨   1. STOP THE DAEMON (Ctrl+C)`);
    logger.error('CHECKPOINT_MANAGER', `🚨   2. DELETE the corrupted blockchain data:`);
    logger.error('CHECKPOINT_MANAGER', `🚨      rm -rf ./data/blockchain.json`);
    logger.error('CHECKPOINT_MANAGER', `🚨   3. RESYNC from a trusted source`);
    logger.error('CHECKPOINT_MANAGER', `🚨   4. Restart the daemon`);
    logger.error('CHECKPOINT_MANAGER', `🚨`);
    logger.error('CHECKPOINT_MANAGER', `🚨 This error indicates blockchain corruption or a fork.`);
    logger.error('CHECKPOINT_MANAGER', `🚨 Continuing would risk further data corruption.`);
    logger.error('CHECKPOINT_MANAGER', `🚨`);

    // Force process exit to stop the daemon
    logger.error('CHECKPOINT_MANAGER', `🚨 FORCING DAEMON SHUTDOWN...`);
    process.exit(1);
  }

  /**
   * Add validation error
   * @param type
   * @param message
   * @param details
   */
  addValidationError(type, message, details = null) {
    const error = {
      type,
      message,
      details,
      timestamp: new Date().toISOString(),
    };

    this.validationErrors.push(error);
    this.isValid = false;

    logger.error('CHECKPOINT_MANAGER', `Validation error: ${type} - ${message}`);
    if (details) {
      logger.error('CHECKPOINT_MANAGER', `Details: ${details}`);
    }
  }

  /**
   * Get checkpoint at specific height
   * @param height
   */
  getCheckpoint(height) {
    return this.checkpoints.find(cp => cp.height === height);
  }

  /**
   * Get all checkpoints
   */
  getAllCheckpoints() {
    return [...this.checkpoints];
  }

  /**
   * Get checkpoint statistics
   */
  getCheckpointStats() {
    return {
      total: this.checkpoints.length,
      valid: this.isValid,
      validationErrors: this.validationErrors.length,
      metadata: this.metadata,
    };
  }

  /**
   * Add new checkpoint
   * @param height
   * @param hash
   * @param description
   */
  addCheckpoint(height, hash, description = '') {
    logger.debug('CHECKPOINT_MANAGER', `Adding checkpoint: height=${height}, hash=${hash.substring(0, 16)}...`);

    // Check for duplicates
    if (this.checkpoints.find(cp => cp.height === height)) {
      logger.warn('CHECKPOINT_MANAGER', `Checkpoint at height ${height} already exists`);
      return false;
    }

    const checkpoint = {
      height: parseInt(height),
      hash,
      description,
    };

    this.checkpoints.push(checkpoint);
    this.saveCheckpoints();

    logger.info('CHECKPOINT_MANAGER', `Checkpoint added at height ${height}`);
    return true;
  }

  /**
   * Update checkpoint
   * @param height
   * @param hash
   * @param description
   */
  updateCheckpoint(height, hash, description = '') {
    logger.debug('CHECKPOINT_MANAGER', `Updating checkpoint at height ${height}`);

    const index = this.checkpoints.findIndex(cp => cp.height === height);
    if (index === -1) {
      logger.warn('CHECKPOINT_MANAGER', `Checkpoint at height ${height} not found`);
      return false;
    }

    this.checkpoints[index] = {
      height: parseInt(height),
      hash,
      description: description || this.checkpoints[index].description,
    };

    this.saveCheckpoints();

    logger.info('CHECKPOINT_MANAGER', `Checkpoint updated at height ${height}`);
    return true;
  }

  /**
   * Remove checkpoint
   * @param height
   */
  removeCheckpoint(height) {
    logger.debug('CHECKPOINT_MANAGER', `Removing checkpoint at height ${height}`);

    const index = this.checkpoints.findIndex(cp => cp.height === height);
    if (index === -1) {
      logger.warn('CHECKPOINT_MANAGER', `Checkpoint at height ${height} not found`);
      return false;
    }

    this.checkpoints.splice(index, 1);
    this.saveCheckpoints();

    logger.info('CHECKPOINT_MANAGER', `Checkpoint removed at height ${height}`);
    return true;
  }

  /**
   * Clear all checkpoints
   */
  clearCheckpoints() {
    logger.debug('CHECKPOINT_MANAGER', `Clearing all checkpoints`);

    this.checkpoints = [];
    this.saveCheckpoints();

    logger.info('CHECKPOINT_MANAGER', `All checkpoints cleared`);
    return true;
  }

  /**
   * Save checkpoints to file
   */
  saveCheckpoints() {
    try {
      const data = {
        checkpoints: this.checkpoints,
        metadata: {
          ...this.metadata,
          lastUpdated: new Date().toISOString(),
        },
      };

      fs.writeFileSync(this.checkpointsPath, JSON.stringify(data, null, 2));
      logger.debug('CHECKPOINT_MANAGER', `Checkpoints saved to: ${this.checkpointsPath}`);
      return true;
    } catch (error) {
      logger.error('CHECKPOINT_MANAGER', `Failed to save checkpoints: ${error.message}`);
      return false;
    }
  }
}

module.exports = CheckpointManager;
