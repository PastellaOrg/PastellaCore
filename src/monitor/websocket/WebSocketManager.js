const logger = require('../../utils/logger');

/**
 * WEBSOCKET MANAGER
 *
 * Handles real-time updates for monitoring dashboard
 * Features 61-65: Real-time features
 */
class WebSocketManager {
  constructor(io, services) {
    this.io = io;
    this.services = services;

    // Track connected clients and their subscriptions
    this.connectedClients = new Map();
    this.rooms = {
      dashboard: 'dashboard-updates',
      blocks: 'block-updates',
      transactions: 'transaction-updates',
      peers: 'peer-updates',
      logs: 'log-updates',
      security: 'security-updates',
      analytics: 'analytics-updates'
    };

    logger.debug('WEBSOCKET_MANAGER', 'WebSocket manager initialized');
  }

  /**
   * Handle client joining dashboard room
   */
  joinDashboard(socket) {
    socket.join(this.rooms.dashboard);
    logger.debug('WEBSOCKET_MANAGER', `Client ${socket.id} joined dashboard room`);

    // Send initial dashboard data
    this.sendDashboardUpdate(socket);
  }

  /**
   * Handle client joining blocks room
   */
  joinBlocks(socket) {
    socket.join(this.rooms.blocks);
    logger.debug('WEBSOCKET_MANAGER', `Client ${socket.id} joined blocks room`);

    // Send initial block data
    this.sendBlockUpdate(socket);
  }

  /**
   * Handle client joining transactions room
   */
  joinTransactions(socket) {
    socket.join(this.rooms.transactions);
    logger.debug('WEBSOCKET_MANAGER', `Client ${socket.id} joined transactions room`);

    // Send initial transaction data
    this.sendTransactionUpdate(socket);
  }

  /**
   * Handle client joining peers room
   */
  joinPeers(socket) {
    socket.join(this.rooms.peers);
    logger.debug('WEBSOCKET_MANAGER', `Client ${socket.id} joined peers room`);

    // Send initial peer data
    this.sendPeerUpdate(socket);
  }

  /**
   * Handle client joining logs room
   */
  joinLogs(socket) {
    socket.join(this.rooms.logs);
    logger.debug('WEBSOCKET_MANAGER', `Client ${socket.id} joined logs room`);

    // Send initial log data
    this.sendLogUpdate(socket);
  }

  /**
   * Broadcast dashboard update to all subscribed clients
   */
  broadcastDashboardUpdate() {
    try {
      const data = this.getDashboardUpdateData();
      this.io.to(this.rooms.dashboard).emit('dashboard-update', data);
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error broadcasting dashboard update: ${error.message}`);
    }
  }

  /**
   * Broadcast block update to all subscribed clients
   */
  broadcastBlockUpdate() {
    try {
      const data = this.getBlockUpdateData();
      this.io.to(this.rooms.blocks).emit('block-update', data);
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error broadcasting block update: ${error.message}`);
    }
  }

  /**
   * Broadcast transaction update to all subscribed clients
   */
  broadcastTransactionUpdate() {
    try {
      const data = this.getTransactionUpdateData();
      this.io.to(this.rooms.transactions).emit('transaction-update', data);
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error broadcasting transaction update: ${error.message}`);
    }
  }

  /**
   * Broadcast peer update to all subscribed clients
   */
  broadcastPeerUpdate() {
    try {
      const data = this.getPeerUpdateData();
      this.io.to(this.rooms.peers).emit('peer-update', data);
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error broadcasting peer update: ${error.message}`);
    }
  }

  /**
   * Broadcast security alert
   */
  broadcastSecurityAlert(alert) {
    try {
      this.io.emit('security-alert', {
        type: alert.type || 'warning',
        message: alert.message,
        timestamp: new Date().toISOString(),
        severity: alert.severity || 'medium',
        details: alert.details || {}
      });
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error broadcasting security alert: ${error.message}`);
    }
  }

  /**
   * Broadcast new block notification
   */
  broadcastNewBlock(block) {
    try {
      this.io.emit('new-block', {
        hash: block.hash,
        index: block.index,
        timestamp: block.timestamp,
        transactions: block.transactions?.length || 0,
        difficulty: block.difficulty,
        miner: this.extractMinerAddress(block),
        size: JSON.stringify(block).length
      });
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error broadcasting new block: ${error.message}`);
    }
  }

  /**
   * Broadcast new transaction notification
   */
  broadcastNewTransaction(transaction) {
    try {
      this.io.emit('new-transaction', {
        id: transaction.id,
        inputs: transaction.inputs?.length || 0,
        outputs: transaction.outputs?.length || 0,
        amount: this.calculateTransactionAmount(transaction),
        fee: transaction.fee || 0,
        timestamp: transaction.timestamp,
        isCoinbase: transaction.isCoinbase || false
      });
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error broadcasting new transaction: ${error.message}`);
    }
  }

  /**
   * Send dashboard update to specific socket
   */
  sendDashboardUpdate(socket) {
    try {
      const data = this.getDashboardUpdateData();
      socket.emit('dashboard-update', data);
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error sending dashboard update: ${error.message}`);
    }
  }

  /**
   * Send block update to specific socket
   */
  sendBlockUpdate(socket) {
    try {
      const data = this.getBlockUpdateData();
      socket.emit('block-update', data);
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error sending block update: ${error.message}`);
    }
  }

  /**
   * Send transaction update to specific socket
   */
  sendTransactionUpdate(socket) {
    try {
      const data = this.getTransactionUpdateData();
      socket.emit('transaction-update', data);
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error sending transaction update: ${error.message}`);
    }
  }

  /**
   * Send peer update to specific socket
   */
  sendPeerUpdate(socket) {
    try {
      const data = this.getPeerUpdateData();
      socket.emit('peer-update', data);
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error sending peer update: ${error.message}`);
    }
  }

  /**
   * Send log update to specific socket
   */
  sendLogUpdate(socket) {
    try {
      const data = this.getLogUpdateData();
      socket.emit('log-update', data);
    } catch (error) {
      logger.error('WEBSOCKET_MANAGER', `Error sending log update: ${error.message}`);
    }
  }

  // Data collection methods

  getDashboardUpdateData() {
    return {
      timestamp: new Date().toISOString(),
      node: this.services.nodeInfo.getNodeVersion(),
      blockchain: this.services.blockchain.getCurrentBlockchainStatus(),
      network: this.services.network.getNetworkStatus(),
      performance: this.services.performance ? this.services.performance.getCurrentPerformance() : { status: 'not_available' },
      security: this.services.security ? this.services.security.getSecurityStatus() : { status: 'not_available' }
    };
  }

  getBlockUpdateData() {
    return {
      timestamp: new Date().toISOString(),
      recent: this.services.blockchain.getRecentBlocks(10),
      status: this.services.blockchain.getCurrentBlockchainStatus(),
      statistics: this.services.blockchain.getBlockchainStatistics()
    };
  }

  getTransactionUpdateData() {
    return {
      timestamp: new Date().toISOString(),
      mempool: this.services.transaction ? this.services.transaction.getMempoolStatus() : { status: 'not_available' },
      recent: this.services.transaction ? this.services.transaction.getRecentTransactions(20) : [],
      statistics: this.services.transaction ? this.services.transaction.getTransactionStatistics() : { status: 'not_available' }
    };
  }

  getPeerUpdateData() {
    return {
      timestamp: new Date().toISOString(),
      peers: this.services.network.getConnectedPeers(),
      statistics: this.services.network.getNetworkStatistics(),
      reputation: this.services.network.getPeerReputationSummary()
    };
  }

  getLogUpdateData() {
    return {
      timestamp: new Date().toISOString(),
      recent: this.services.log ? this.services.log.getRecentLogs(50) : [],
      statistics: this.services.log ? this.services.log.getLogStatistics() : { status: 'not_available' }
    };
  }

  // Helper methods

  extractMinerAddress(block) {
    try {
      const coinbaseTx = block.transactions?.find(tx => tx.isCoinbase);
      return coinbaseTx?.outputs?.[0]?.address || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  calculateTransactionAmount(tx) {
    try {
      return tx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
    } catch {
      return 0;
    }
  }

  /**
   * Get connection statistics
   */
  getConnectionStats() {
    return {
      total: this.io.engine.clientsCount,
      rooms: {
        dashboard: this.io.sockets.adapter.rooms.get(this.rooms.dashboard)?.size || 0,
        blocks: this.io.sockets.adapter.rooms.get(this.rooms.blocks)?.size || 0,
        transactions: this.io.sockets.adapter.rooms.get(this.rooms.transactions)?.size || 0,
        peers: this.io.sockets.adapter.rooms.get(this.rooms.peers)?.size || 0,
        logs: this.io.sockets.adapter.rooms.get(this.rooms.logs)?.size || 0
      }
    };
  }
}

module.exports = WebSocketManager;