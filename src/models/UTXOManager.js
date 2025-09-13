const logger = require('../utils/logger');

/**
 * UTXO Manager - Handles all UTXO operations and validation
 */
class UTXOManager {
  /**
   *
   */
  constructor() {
    this.utxos = [];
    this.utxoSet = new Map(); // Map of UTXO: txHash:outputIndex -> {address, amount}
  }

  /**
   * Find a specific UTXO by transaction hash and output index
   * @param txHash
   * @param outputIndex
   */
  findUTXO(txHash, outputIndex) {
    const utxoKey = `${txHash}:${outputIndex}`;
    const utxo = this.utxoSet.get(utxoKey);

    if (utxo) {
      return {
        txHash,
        outputIndex,
        amount: utxo.amount,
        address: utxo.address,
      };
    }

    return null;
  }

  /**
   * Check if a UTXO is already spent
   * @param txHash
   * @param outputIndex
   */
  isUTXOSpent(txHash, outputIndex) {
    // Check if this UTXO exists in our current UTXO set
    return !this.findUTXO(txHash, outputIndex);
  }

  /**
   * Update UTXO set when adding a block
   * @param block
   */
  updateUTXOSet(block) {
    block.transactions.forEach(transaction => {
      // Remove spent UTXOs
      transaction.inputs.forEach(input => {
        // Handle both txHash and txId field names for compatibility
        const inputTxHash = input.txHash || input.txId;
        const utxoKey = `${inputTxHash}:${input.outputIndex}`;

        if (this.utxoSet.has(utxoKey)) {
          this.utxoSet.delete(utxoKey);
          logger.debug('UTXO', `Removed spent UTXO: ${utxoKey}`);
        }
      });

      // Add new UTXOs
      transaction.outputs.forEach((output, index) => {
        const utxoKey = `${transaction.id}:${index}`;
        this.utxoSet.set(utxoKey, {
          address: output.address,
          amount: output.amount,
        });
        logger.debug('UTXO', `Added new UTXO: ${utxoKey} (${output.amount} to ${output.address})`);
      });
    });
  }

  /**
   * Rebuild UTXO set from entire chain
   * @param chain
   */
  rebuildUTXOSet(chain) {
    this.utxoSet.clear();
    chain.forEach(block => {
      this.updateUTXOSet(block);
    });
  }

  /**
   * Clear all UTXOs (for testing/reset purposes)
   */
  clearUTXOs() {
    this.utxos = [];
    this.utxoSet.clear();
    logger.info('UTXO_MANAGER', 'All UTXOs cleared');
  }

  /**
   * Get balance for an address
   * @param address
   */
  getBalance(address) {
    let balance = 0;

    this.utxoSet.forEach(utxo => {
      if (utxo.address === address) {
        balance += utxo.amount;
      }
    });

    return balance;
  }

  /**
   * Get UTXOs for an address
   * @param address
   */
  getUTXOsForAddress(address) {
    const utxos = [];

    this.utxoSet.forEach((utxo, key) => {
      if (utxo.address === address) {
        const [txHash, outputIndex] = key.split(':');
        utxos.push({
          txHash,
          outputIndex: parseInt(outputIndex),
          amount: utxo.amount,
        });
      }
    });

    return utxos;
  }

  /**
   * Clean up orphaned UTXOs that are no longer referenced
   * @param chain
   */
  cleanupOrphanedUTXOs(chain) {
    const initialCount = this.utxos.length;
    let cleanedCount = 0;

    // Find orphaned UTXOs by checking if they're still referenced in the chain
    this.utxos = this.utxos.filter(utxo => {
      // Check if this UTXO is still valid by looking for the transaction in the chain
      const blockIndex = this.findBlockContainingTransaction(utxo.txHash, chain);
      if (blockIndex === -1) {
        // UTXO references a transaction that's not in the chain - orphaned
        logger.debug('UTXO_MANAGER', `Removing orphaned UTXO ${utxo.txHash}:${utxo.outputIndex}`);
        cleanedCount++;
        return false;
      }
      return true;
    });

    if (cleanedCount > 0) {
      logger.info('UTXO_MANAGER', `Cleaned up ${cleanedCount} orphaned UTXOs`);
    }

    return { cleaned: cleanedCount, remaining: this.utxos.length };
  }

  /**
   * Find block index containing a specific transaction
   * @param txHash
   * @param chain
   */
  findBlockContainingTransaction(txHash, chain) {
    for (let i = 0; i < chain.length; i++) {
      const block = chain[i];
      if (block.transactions.some(tx => tx.id === txHash)) {
        return i;
      }
    }
    return -1; // Transaction not found in any block
  }

  /**
   * Get all UTXOs
   */
  getAllUTXOs() {
    const allUTXOs = [];
    
    // Convert from Map format to array with proper structure
    for (const [utxoKey, utxo] of this.utxoSet) {
      const [txHash, outputIndex] = utxoKey.split(':');
      allUTXOs.push({
        txHash,
        outputIndex: parseInt(outputIndex),
        address: utxo.address,
        amount: utxo.amount
      });
    }
    
    return allUTXOs;
  }

  /**
   * Get UTXO count
   */
  getUTXOCount() {
    return this.utxos.length;
  }

  /**
   * Add UTXO to the set
   * @param utxo
   */
  addUTXO(utxo) {
    this.utxos.push(utxo);
  }

  /**
   * Remove UTXO from the set
   * @param txHash
   * @param outputIndex
   */
  removeUTXO(txHash, outputIndex) {
    this.utxos = this.utxos.filter(utxo => !(utxo.txHash === txHash && utxo.outputIndex === outputIndex));
  }

  /**
   * Clear all UTXOs
   */
  clear() {
    this.utxos = [];
    this.utxoSet.clear();
  }
}

module.exports = UTXOManager;
