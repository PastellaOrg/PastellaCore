const path = require('path');

const WebSocket = require('ws');

const Block = require('../models/Block.js');
const Transaction = require('../models/Transaction.js');
const logger = require('../utils/logger.js');
const MessageValidator = require('../utils/MessageValidator.js');

/**
 * Message Handler - Handles all message processing and routing
 */
class MessageHandler {
  /**
   *
   * @param blockchain
   * @param peerReputation
   * @param config
   * @param forkManager
   */
  constructor(blockchain, peerReputation, config, forkManager = null) {
    logger.debug('MESSAGE_HANDLER', `Initializing MessageHandler...`);
    logger.debug(
      'MESSAGE_HANDLER',
      `Blockchain instance: ${blockchain ? 'present' : 'null'}, type: ${typeof blockchain}`
    );
    logger.debug(
      'MESSAGE_HANDLER',
      `PeerReputation instance: ${peerReputation ? 'present' : 'null'}, type: ${typeof peerReputation}`
    );
    logger.debug(
      'MESSAGE_HANDLER',
      `Config instance: ${config ? 'present' : 'null'}, networkId: ${config?.networkId || 'undefined'}`
    );
    logger.debug(
      'MESSAGE_HANDLER',
      `ForkManager instance: ${forkManager ? 'present' : 'null'}`
    );

    this.blockchain = blockchain;
    this.peerReputation = peerReputation;
    this.config = config;
    this.forkManager = forkManager;
    this.p2pNetwork = null; // Will be set by P2PNetwork after initialization
    this.messageHandlers = new Map();
    this.messageValidator = new MessageValidator(config);
    this.messageValidationStats = {
      totalMessages: 0,
      validMessages: 0,
      invalidMessages: 0,
      validationErrors: new Map(), // Map<errorType, count>
    };

    // Transaction relay loop prevention
    this.seenTransactions = new Map(); // Map<transactionId, timestamp>
    this.maxSeenTransactions = 10000; // Limit cache size

    // Message deduplication to prevent flooding attacks
    this.seenMessages = new Map(); // Map<messageHash, {timestamp, count, peerAddress}>

    // Version check tracking for mandatory fork compatibility
    this.pendingVersionChecks = new Map(); // Map<peerAddress, {timestamp, timeoutId, ws}>
    this.versionCheckTimeout = 5000; // 5 seconds timeout for version response (reduced for faster enforcement)
    this.versionValidatedPeers = new Set(); // Track peers that passed version validation
    this.maxSeenMessages = 5000; // Limit cache size
    this.messageTTL = 60000; // 1 minute TTL for seen messages
    this.maxDuplicatesPerPeer = 3; // Max allowed duplicates per peer

    // Per-peer rate limiting
    this.peerMessageRates = new Map(); // Map<peerAddress, {count, windowStart}>
    this.rateWindow = 10000; // 10 second rate window
    this.maxMessagesPerWindow = 100; // Max messages per peer per window
    this.seenTransactionTTL = 300000; // 5 minutes TTL

    logger.debug('MESSAGE_HANDLER', `MessageHandler components initialized:`);
    logger.debug('MESSAGE_HANDLER', `  MessageHandlers Map: ${this.messageHandlers.size} handlers`);
    logger.debug('MESSAGE_HANDLER', `  MessageValidator: ${this.messageValidator ? 'present' : 'null'}`);
    logger.debug(
      'MESSAGE_HANDLER',
      `  MessageValidationStats: initialized with ${this.messageValidationStats.totalMessages} total messages`
    );

    logger.debug('MESSAGE_HANDLER', `Setting up message handlers...`);
    this.setupMessageHandlers();
    logger.debug('MESSAGE_HANDLER', `MessageHandler initialized successfully`);
  }

  /**
   * Set P2PNetwork reference for cross-component communication
   * @param p2pNetwork
   */
  setP2PNetworkReference(p2pNetwork) {
    this.p2pNetwork = p2pNetwork;
    logger.debug('MESSAGE_HANDLER', `P2PNetwork reference set`);
  }

  /**
   * Setup message handlers
   */
  setupMessageHandlers() {
    logger.debug('MESSAGE_HANDLER', `Setting up message handlers...`);

    // Core blockchain message handlers
    logger.debug('MESSAGE_HANDLER', `Setting up core blockchain message handlers...`);
    this.messageHandlers.set('QUERY_LATEST', this.handleQueryLatest.bind(this));
    this.messageHandlers.set('QUERY_ALL', this.handleQueryAll.bind(this));
    this.messageHandlers.set('RESPONSE_BLOCKCHAIN', this.handleResponseBlockchain.bind(this));
    this.messageHandlers.set('QUERY_TRANSACTION_POOL', this.handleQueryTransactionPool.bind(this));
    this.messageHandlers.set('RESPONSE_TRANSACTION_POOL', this.handleResponseTransactionPool.bind(this));
    this.messageHandlers.set('NEW_BLOCK', this.handleNewBlock.bind(this));
    this.messageHandlers.set('NEW_TRANSACTION', this.handleNewTransaction.bind(this));
    this.messageHandlers.set('SEED_NODE_INFO', this.handleSeedNodeInfo.bind(this));

    // Fork version compatibility message handlers
    this.messageHandlers.set('VERSION_CHECK', this.handleVersionCheck.bind(this));
    this.messageHandlers.set('VERSION_RESPONSE', this.handleVersionResponse.bind(this));

    // Mempool synchronization message handlers (Bitcoin-style)
    logger.debug('MESSAGE_HANDLER', `Setting up mempool synchronization handlers...`);
    this.messageHandlers.set('MEMPOOL_SYNC_REQUEST', this.handleMempoolSyncRequest.bind(this));
    this.messageHandlers.set('MEMPOOL_SYNC_RESPONSE', this.handleMempoolSyncResponse.bind(this));
    this.messageHandlers.set('MEMPOOL_INV', this.handleMempoolInv.bind(this));
    this.messageHandlers.set('MEMPOOL_GETDATA', this.handleMempoolGetData.bind(this));
    this.messageHandlers.set('MEMPOOL_TX', this.handleMempoolTx.bind(this));
    this.messageHandlers.set('MEMPOOL_NOTFOUND', this.handleMempoolNotFound.bind(this));
    this.messageHandlers.set('MEMPOOL_REJECT', this.handleMempoolReject.bind(this));

    // Peer discovery and sharing handlers
    logger.debug('MESSAGE_HANDLER', `Setting up peer discovery handlers...`);
    this.messageHandlers.set('PEER_LIST_REQUEST', this.handlePeerListRequest.bind(this));
    this.messageHandlers.set('PEER_LIST_SHARE', this.handlePeerListShare.bind(this));

    // Health check handlers
    this.messageHandlers.set('PING', this.handlePing.bind(this));
    this.messageHandlers.set('PONG', this.handlePong.bind(this));

    logger.debug('MESSAGE_HANDLER', `Core blockchain handlers configured: ${this.messageHandlers.size} handlers`);

    // Authentication message handlers
    logger.debug('MESSAGE_HANDLER', `Setting up authentication message handlers...`);
    this.messageHandlers.set('HANDSHAKE', this.handleHandshake.bind(this));
    this.messageHandlers.set('HANDSHAKE_ACCEPTED', this.handleHandshakeAccepted.bind(this));
    this.messageHandlers.set('HANDSHAKE_REJECTED', this.handleHandshakeRejected.bind(this));
    this.messageHandlers.set('HANDSHAKE_ERROR', this.handleHandshakeError.bind(this));
    this.messageHandlers.set('AUTH_CHALLENGE', this.handleAuthChallenge.bind(this));
    this.messageHandlers.set('AUTH_RESPONSE', this.handleAuthResponse.bind(this));
    this.messageHandlers.set('AUTH_SUCCESS', this.handleAuthSuccess.bind(this));
    this.messageHandlers.set('AUTH_FAILURE', this.handleAuthFailure.bind(this));
    logger.debug('MESSAGE_HANDLER', `Authentication handlers configured: ${this.messageHandlers.size} total handlers`);

    // Partition handling message handlers
    logger.debug('MESSAGE_HANDLER', `Setting up partition handling message handlers...`);
    this.messageHandlers.set('HEALTH_STATUS', this.handleHealthStatus.bind(this));
    this.messageHandlers.set('REQUEST_PEER_LIST', this.handleRequestPeerList.bind(this));
    this.messageHandlers.set('HEARTBEAT', this.handleHeartbeat.bind(this));
    logger.debug(
      'MESSAGE_HANDLER',
      `Partition handling handlers configured: ${this.messageHandlers.size} total handlers`
    );

    logger.debug(
      'MESSAGE_HANDLER',
      `All message handlers configured successfully: ${this.messageHandlers.size} total handlers`
    );

    // Start periodic cleanup to prevent memory leaks
    this.startPeriodicCleanup();
  }

  /**
   * Start periodic cleanup of expired data to prevent memory leaks
   */
  startPeriodicCleanup() {
    // Clean up every 30 seconds
    this.cleanupInterval = setInterval(() => {
      this.cleanupSeenTransactions();
      this.cleanupSeenMessages();

      // Clean up old rate limiting data
      const now = Date.now();
      for (const [peerAddress, rateInfo] of this.peerMessageRates.entries()) {
        if (now - rateInfo.windowStart > this.rateWindow * 2) {
          this.peerMessageRates.delete(peerAddress);
        }
      }

      logger.debug('MESSAGE_HANDLER', `Periodic cleanup completed: ${this.seenMessages.size} seen messages, ${this.seenTransactions.size} seen transactions, ${this.peerMessageRates.size} peer rates`);
    }, 30000); // 30 seconds

    logger.debug('MESSAGE_HANDLER', `Periodic cleanup started (30s interval)`);
  }

  /**
   * Stop periodic cleanup (for shutdown)
   */
  stopPeriodicCleanup() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
      logger.debug('MESSAGE_HANDLER', `Periodic cleanup stopped`);
    }
  }

  /**
   * Handle incoming message
   * @param ws
   * @param message
   * @param peerAddress
   * @param isPeerAuthenticated
   */
  async handleMessage(ws, message, peerAddress, isPeerAuthenticated) {
    logger.debug('MESSAGE_HANDLER', `Handling incoming message from peer ${peerAddress}...`);
    logger.debug(
      'MESSAGE_HANDLER',
      `Message type: ${message?.type}, WebSocket: ${ws ? 'present' : 'null'}, Authenticated: ${isPeerAuthenticated}`
    );
    logger.debug('MESSAGE_HANDLER', `Message content: ${JSON.stringify(message)}`);

    // Update message statistics
    this.messageValidationStats.totalMessages++;
    logger.debug(
      'MESSAGE_HANDLER',
      `Message statistics updated: totalMessages=${this.messageValidationStats.totalMessages}`
    );

    // Comprehensive message validation
    logger.debug('MESSAGE_HANDLER', `Validating message from peer ${peerAddress}...`);
    const validation = this.messageValidator.validateMessage(message, peerAddress);
    logger.debug('MESSAGE_HANDLER', `Message validation result: ${JSON.stringify(validation)}`);

    if (!validation.valid) {
      this.messageValidationStats.invalidMessages++;
      logger.debug(
        'MESSAGE_HANDLER',
        `Message validation failed, updating statistics: invalidMessages=${this.messageValidationStats.invalidMessages}`
      );

      // Track validation errors
      const errorType = validation.error || 'unknown_error';
      const currentCount = this.messageValidationStats.validationErrors.get(errorType) || 0;
      this.messageValidationStats.validationErrors.set(errorType, currentCount + 1);
      logger.debug('MESSAGE_HANDLER', `Validation error tracking updated: ${errorType}=${currentCount + 1}`);

      logger.warn('MESSAGE_HANDLER', `[MESSAGE_VALIDATION] Invalid message from ${peerAddress}: ${validation.error}`);
      if (validation.details) {
        logger.debug('MESSAGE_HANDLER', `[MESSAGE_VALIDATION] Details: ${validation.details}`);
      }
      logger.debug('MESSAGE_HANDLER', `[MESSAGE_VALIDATION] Invalid message content: ${JSON.stringify(message)}`);

      logger.debug('MESSAGE_HANDLER', `Updating peer reputation for invalid message...`);
      this.peerReputation.updatePeerReputation(peerAddress, 'invalid_message', {
        reason: 'message_validation_failed',
        error: validation.error,
        details: validation.details,
      });
      logger.debug('MESSAGE_HANDLER', `Peer reputation updated for invalid message`);
      return false;
    }

    this.messageValidationStats.validMessages++;
    logger.debug(
      'MESSAGE_HANDLER',
      `Message validation passed, updating statistics: validMessages=${this.messageValidationStats.validMessages}`
    );

    // Check for rate limiting (prevent spam attacks)
    if (this.isRateLimited(peerAddress)) {
      logger.warn('MESSAGE_HANDLER', `🚨 RATE LIMITED: Blocking message from ${peerAddress} (type: ${message.type})`);
      this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', {
        reason: 'rate_limit_exceeded',
        messageType: message.type
      });
      return false;
    }

    // Check for duplicate messages (prevent flooding attacks)
    if (this.isDuplicateMessage(message, peerAddress)) {
      logger.debug('MESSAGE_HANDLER', `🔄 DUPLICATE: Blocking duplicate message from ${peerAddress} (type: ${message.type})`);

      // Apply reputation penalties based on message type
      const maintenanceMessages = ['QUERY_LATEST', 'PING', 'PONG', 'QUERY_TRANSACTION', 'MEMPOOL_SYNC_REQUEST', 'HEARTBEAT', 'RESPONSE_BLOCKCHAIN'];
      const isMaintenanceMessage = maintenanceMessages.includes(message.type);
      const seenInfo = this.seenMessages.get(this.generateMessageHash(message, peerAddress));

      if (seenInfo && seenInfo.count > this.maxDuplicatesPerPeer) {
        if (!isMaintenanceMessage) {
          // Only penalize reputation for non-maintenance messages (actual flooding)
          this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', {
            reason: 'message_flooding',
            messageType: message.type,
            duplicateCount: seenInfo.count
          });
          logger.debug('MESSAGE_HANDLER', `Applied reputation penalty for flooding: ${message.type} from ${peerAddress}`);
        } else {
          // For maintenance messages, just log without reputation penalty
          logger.debug('MESSAGE_HANDLER', `High duplicate count for maintenance message ${message.type} from ${peerAddress} (${seenInfo.count} times) - no reputation penalty`);
        }
      }
      return false;
    }

    // Check authentication for sensitive operations
    const sensitiveOperations = ['NEW_BLOCK', 'NEW_TRANSACTION', 'RESPONSE_BLOCKCHAIN', 'RESPONSE_TRANSACTION_POOL'];
    if (sensitiveOperations.includes(message.type) && !isPeerAuthenticated) {
      logger.warn(
        'MESSAGE_HANDLER',
        `[AUTH] Unauthenticated peer ${peerAddress} attempted sensitive operation: ${message.type}`
      );

      // Debug: Log authentication state
      if (this.p2pNetwork?.authenticatedPeers) {
        const authInfo = this.p2pNetwork.authenticatedPeers.get(peerAddress);
        logger.debug(
          'MESSAGE_HANDLER',
          `[AUTH_DEBUG] Peer ${peerAddress} auth state: ${authInfo ? 'authenticated' : 'not authenticated'}`
        );
        if (authInfo) {
          logger.debug(
            'MESSAGE_HANDLER',
            `[AUTH_DEBUG] Auth details: nodeId=${authInfo.nodeId}, networkId=${authInfo.networkId}, at=${new Date(authInfo.authenticatedAt).toISOString()}`
          );
        }
      }

      this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', { reason: 'unauthorized_operation' });
      return false;
    }

    const handler = this.messageHandlers.get(message.type);
    if (handler) {
      try {
        await handler(ws, message, peerAddress);
        // Update reputation for successful message handling
        this.peerReputation.updatePeerReputation(peerAddress, 'good_behavior', {
          reason: 'message_handled_successfully',
        });
        return true;
      } catch (error) {
        logger.error(
          'MESSAGE_HANDLER',
          `[MESSAGE_HANDLER] Error handling message from ${peerAddress}: ${error.message}`
        );
        this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', {
          reason: 'message_handler_error',
          error: error.message,
        });
        return false;
      }
    } else {
      logger.warn('MESSAGE_HANDLER', `Unknown message type: ${message.type} from ${peerAddress}`);
      this.peerReputation.updatePeerReputation(peerAddress, 'invalid_message', { reason: 'unknown_message_type' });
      return false;
    }
  }

  /**
   * Check if peer has completed mandatory version validation
   * @param peerAddress - Peer address to check
   * @param messageType - Message type for logging
   * @returns {boolean} True if peer is validated or fork manager is disabled
   */
  isPeerVersionValidated(peerAddress, messageType) {
    // If no fork manager, allow all operations (backward compatibility)
    if (!this.forkManager) {
      return true;
    }

    // Check if peer has completed version validation
    const isValidated = this.versionValidatedPeers.has(peerAddress);

    if (!isValidated) {
      logger.warn('MESSAGE_HANDLER', `BLOCKED: ${messageType} from ${peerAddress} - version validation required`);
      logger.warn('MESSAGE_HANDLER', `Peer must respond to VERSION_CHECK before blockchain operations are allowed`);
      return false;
    }

    return true;
  }

  /**
   * Handle query latest block
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleQueryLatest(ws, message, peerAddress) {
    // MANDATORY: Check version validation before responding to blockchain queries
    if (!this.isPeerVersionValidated(peerAddress, 'QUERY_LATEST')) {
      return; // Block operation until version validation completes
    }

    logger.debug('MESSAGE_HANDLER', `Latest block queried by ${peerAddress}`);
    const latestBlock = this.blockchain.getLatestBlock();
    const response = {
      type: 'RESPONSE_BLOCKCHAIN',
      data: [latestBlock],
    };
    this.sendMessage(ws, response);
  }

  /**
   * Handle query all blocks
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleQueryAll(ws, message, peerAddress) {
    // MANDATORY: Check version validation before responding to blockchain queries
    if (!this.isPeerVersionValidated(peerAddress, 'QUERY_ALL')) {
      return; // Block operation until version validation completes
    }

    logger.debug('MESSAGE_HANDLER', `All blocks queried by ${peerAddress}`);
    const response = {
      type: 'RESPONSE_BLOCKCHAIN',
      data: this.blockchain.chain,
    };
    this.sendMessage(ws, response);
  }

  /**
   * Handle blockchain response
   * @param ws
   * @param message
   * @param peerAddress
   */
  async handleResponseBlockchain(ws, message, peerAddress) {
    // CRITICAL: Block blockchain sync until version validation completes
    if (!this.isPeerVersionValidated(peerAddress, 'RESPONSE_BLOCKCHAIN')) {
      return; // Block operation until version validation completes
    }

    logger.debug(
      'MESSAGE_HANDLER',
      `Blockchain response received from ${peerAddress} with ${message.data.length} blocks`
    );

    const receivedChain = message.data;
    if (receivedChain.length === 0) {
      logger.warn('MESSAGE_HANDLER', 'Received empty blockchain from peer');
      return;
    }

    const latestBlockReceived = receivedChain[receivedChain.length - 1];
    const latestBlockHeld = this.blockchain.getLatestBlock();

    if (latestBlockReceived.index > latestBlockHeld.index) {
      logger.info(
        'MESSAGE_HANDLER',
        `Received longer blockchain from ${peerAddress}. New length: ${receivedChain.length}`
      );

      // Check if we received a complete chain or just partial data
      if (receivedChain.length === 1 && latestBlockReceived.index > 0) {
        // We received only one block with high index, need to request full chain
        logger.info('MESSAGE_HANDLER', `Received single block ${latestBlockReceived.index}, requesting full chain`);
        this.sendMessage(ws, { type: 'QUERY_ALL' });
        return;
      }

      // Convert received JSON blocks to Block instances for validation
      try {
        const convertedChain = receivedChain.map(blockData => {
          if (blockData instanceof Block) {
            return blockData; // Already a Block instance
          }
          return Block.fromJSON(blockData); // Convert JSON to Block instance
        });

        // Check if the converted chain is valid
        const isValidChain = this.blockchain.isValidChain(convertedChain);

        if (isValidChain) {
          logger.info('MESSAGE_HANDLER', 'Received chain is valid, verifying consistency with local chain');

          // CRITICAL: Verify that the received chain is consistent with our local chain
          const localHeight = this.blockchain.chain.length;
          const chainConsistencyCheck = this.verifyChainConsistency(convertedChain, this.blockchain.chain);

          if (!chainConsistencyCheck.consistent) {
            logger.error('MESSAGE_HANDLER', `Chain consistency check failed: ${chainConsistencyCheck.reason}`);
            logger.error('MESSAGE_HANDLER', `Mismatch at block ${chainConsistencyCheck.blockIndex}: ${chainConsistencyCheck.details}`);
            logger.warn('MESSAGE_HANDLER', 'Rejecting inconsistent chain - potential fork or corrupted data');
            return;
          }

          logger.info('MESSAGE_HANDLER', `Chain consistency verified up to block ${localHeight - 1}`);

          const blocksToAdd = convertedChain.slice(localHeight); // Only get the new blocks

          if (blocksToAdd.length === 0) {
            logger.info('MESSAGE_HANDLER', 'No new blocks to add - chains are already synchronized');
            return;
          }

          logger.info('MESSAGE_HANDLER', `Adding ${blocksToAdd.length} new blocks (from height ${localHeight} to ${convertedChain.length - 1})`);

          // Add only the new blocks
          let addedCount = 0;
          let blockAddError = null;
          const totalBlocksToAdd = blocksToAdd.length;
          const saveInterval = 100; // Save every 100 blocks
          const fastSyncThreshold = 50; // Use fast sync for bulk operations (50+ blocks)
          const useFastSync = totalBlocksToAdd >= fastSyncThreshold;

          if (useFastSync) {
            logger.info('MESSAGE_HANDLER', `🚀 Using fast sync mode for ${totalBlocksToAdd} blocks (threshold: ${fastSyncThreshold})`);
            logger.info('MESSAGE_HANDLER', `Fast sync will skip expensive operations and rebuild state at the end`);
          }

          logger.info('MESSAGE_HANDLER', `Starting sync of ${totalBlocksToAdd} blocks with periodic saves every ${saveInterval} blocks`);

          for (const block of blocksToAdd) {
            try {
              if (this.blockchain.addBlock(block, false, true, useFastSync)) { // skipValidation=false, useBlockDifficulty=true, fastSyncMode=useFastSync
                logger.debug('MESSAGE_HANDLER', `Added block ${block.index} to blockchain`);
                addedCount++;

                // Periodic save every 100 blocks to preserve progress
                if (addedCount % saveInterval === 0) {
                  try {
                    const blockchainPath = path.join(
                      this.config?.storage?.dataDir || './data',
                      this.config?.storage?.blockchainFile || 'blockchain.json'
                    );
                    this.blockchain.saveToFile(blockchainPath);
                    logger.info('MESSAGE_HANDLER', `📄 Periodic save: Saved blockchain progress at ${addedCount}/${totalBlocksToAdd} blocks (current height: ${block.index})`);
                  } catch (saveError) {
                    logger.warn('MESSAGE_HANDLER', `Failed to save blockchain during sync: ${saveError.message}`);
                  }
                }
              } else {
                logger.error('MESSAGE_HANDLER', `Failed to add block ${block.index} - unknown error`);
                blockAddError = `Failed to add block ${block.index}`;
                break; // Stop adding if we encounter an error
              }
            } catch (error) {
              logger.error('MESSAGE_HANDLER', `Error adding block ${block.index}: ${error.message}`);
              blockAddError = error.message;

              // Check for transaction ID collision - this indicates corrupted blockchain data
              if (error.message && error.message.includes('Transaction ID collision detected')) {
                logger.error('MESSAGE_HANDLER', '🚨 BLOCKCHAIN CORRUPTION DETECTED: Transaction ID collision during sync');
                logger.error('MESSAGE_HANDLER', 'This indicates the local blockchain data is corrupted and needs complete resync');
                logger.warn('MESSAGE_HANDLER', 'Initiating full blockchain resync from genesis block...');

                // Perform complete blockchain reset and resync
                await this.performFullBlockchainResync(ws, peerAddress);
                return; // Exit early - full resync will handle everything
              }

              break; // Stop adding if we encounter an error
            }
          }

          if (addedCount === blocksToAdd.length) {
            logger.info('MESSAGE_HANDLER', `Successfully added all ${addedCount} blocks to blockchain`);

            // Perform final state rebuild if fast sync was used
            if (useFastSync && addedCount > 0) {
              logger.info('MESSAGE_HANDLER', '🔄 Fast sync complete, starting final state rebuild...');
              try {
                const rebuildSuccess = this.blockchain.performFinalStateRebuild(localHeight);
                if (rebuildSuccess) {
                  logger.info('MESSAGE_HANDLER', '✅ Final state rebuild completed successfully');
                } else {
                  logger.error('MESSAGE_HANDLER', '❌ Final state rebuild failed - blockchain state may be inconsistent');
                }
              } catch (error) {
                logger.error('MESSAGE_HANDLER', `❌ Final state rebuild error: ${error.message}`);

                // Check for transaction ID collision during rebuild
                if (error.message && error.message.includes('Transaction ID collision detected')) {
                  logger.error('MESSAGE_HANDLER', '🚨 Transaction ID collision during state rebuild - triggering full resync');
                  await this.performFullBlockchainResync(ws, peerAddress);
                  return;
                }
              }
            }
          } else {
            logger.warn('MESSAGE_HANDLER', `Only added ${addedCount} out of ${blocksToAdd.length} blocks - sync incomplete`);
            if (blockAddError) {
              logger.warn('MESSAGE_HANDLER', `Sync stopped due to error: ${blockAddError}`);
            }
          }

          // Save blockchain after syncing new blocks
          try {
            const blockchainPath = path.join(
              this.config?.storage?.dataDir || './data',
              this.config?.storage?.blockchainFile || 'blockchain.json'
            );
            this.blockchain.saveToFile(blockchainPath);
            logger.debug('MESSAGE_HANDLER', `Blockchain saved after adding ${addedCount} blocks`);
          } catch (error) {
            logger.warn('MESSAGE_HANDLER', `Failed to save blockchain after sync: ${error.message}`);
          }
        } else {
          logger.warn('MESSAGE_HANDLER', 'Received chain is invalid, rejecting sync');
          // If chain is invalid, request full chain to get correct data
          logger.info('MESSAGE_HANDLER', 'Requesting full chain due to validation failure');
          this.sendMessage(ws, { type: 'QUERY_ALL' });
        }
      } catch (error) {
        logger.error('MESSAGE_HANDLER', `Error validating received chain: ${error.message}`);
        // If validation throws error, request full chain
        logger.info('MESSAGE_HANDLER', 'Requesting full chain due to validation error');
        this.sendMessage(ws, { type: 'QUERY_ALL' });
      }
    } else {
      logger.debug('MESSAGE_HANDLER', 'Received blockchain is not longer than current blockchain');
    }
  }

  /**
   * Handle transaction pool query
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleQueryTransactionPool(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Transaction pool queried by ${peerAddress}`);
    const response = {
      type: 'RESPONSE_TRANSACTION_POOL',
      data: this.blockchain.getPendingTransactions(),
    };
    this.sendMessage(ws, response);
  }

  /**
   * Handle transaction pool response
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleResponseTransactionPool(ws, message, peerAddress) {
    logger.debug(
      'MESSAGE_HANDLER',
      `Transaction pool response received from ${peerAddress} with ${message.data.length} transactions`
    );

    const receivedTransactions = message.data;
    receivedTransactions.forEach(transaction => {
      try {
        // Pass transaction data directly - addPendingTransaction handles conversion
        this.blockchain.addPendingTransaction(transaction);
      } catch (error) {
        logger.warn('MESSAGE_HANDLER', `Failed to add transaction from peer: ${error.message}`);
        logger.warn('MESSAGE_HANDLER', `Error stack: ${error.stack}`);
      }
    });
  }

  /**
   * Handle new block announcement
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleNewBlock(ws, message, peerAddress) {
    // MANDATORY: Check version validation before processing new blocks
    if (!this.isPeerVersionValidated(peerAddress, 'NEW_BLOCK')) {
      return; // Block operation until version validation completes
    }

    logger.debug('MESSAGE_HANDLER', `New block announced by ${peerAddress}`);

    try {
      // Convert plain object to proper Block instance
      const newBlock = Block.fromJSON(message.data);

      if (this.blockchain.addBlock(newBlock)) {
        logger.info('MESSAGE_HANDLER', 'New block added from peer');

        // CRITICAL: Invalidate mempool transactions that are now in the block (Bitcoin-style)
        this.invalidateMempoolTransactions(newBlock);

        // Save blockchain immediately
        try {
          this.blockchain.saveToDefaultFile();
          logger.debug('MESSAGE_HANDLER', `Blockchain saved immediately after adding network block ${newBlock.index}`);
        } catch (error) {
          logger.warn('MESSAGE_HANDLER', `Failed to save blockchain immediately: ${error.message}`);
        }
      }
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to process new block from ${peerAddress}: ${error.message}`);
      logger.error('MESSAGE_HANDLER', `Error stack: ${error.stack}`);
    }
  }

  /**
   * Invalidate mempool transactions that are now in the blockchain (Bitcoin-style)
   * @param block
   */
  invalidateMempoolTransactions(block) {
    try {
      if (!block.transactions || block.transactions.length === 0) {
        return;
      }

      const blockTransactionHashes = block.transactions.map(tx => tx.hash);
      const pendingTransactions = this.blockchain.memoryPool.getPendingTransactions();

      // Find transactions in mempool that are now in the block
      const transactionsToRemove = pendingTransactions.filter(tx => blockTransactionHashes.includes(tx.hash));

      if (transactionsToRemove.length > 0) {
        logger.info(
          'MESSAGE_HANDLER',
          `Removing ${transactionsToRemove.length} transactions from mempool (now in block ${block.index})`
        );

        // Remove transactions from mempool
        this.blockchain.memoryPool.removeTransactions(transactionsToRemove);

        // Log the cleanup
        transactionsToRemove.forEach(tx => {
          logger.debug(
            'MESSAGE_HANDLER',
            `Removed transaction ${tx.hash} from mempool (included in block ${block.index})`
          );
        });
      }
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to invalidate mempool transactions: ${error.message}`);
    }
  }

  /**
   * Handle new transaction
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleNewTransaction(ws, message, peerAddress) {
    // MANDATORY: Check version validation before processing new transactions
    if (!this.isPeerVersionValidated(peerAddress, 'NEW_TRANSACTION')) {
      return; // Block operation until version validation completes
    }

    logger.info('MESSAGE_HANDLER', `📥 NEW TRANSACTION received from ${peerAddress}`);
    logger.debug('MESSAGE_HANDLER', `Transaction ID: ${message.data?.id || 'unknown'}`);

    try {
      // Pass transaction data directly - addPendingTransaction handles conversion
      const transactionData = message.data;
      const transactionId = transactionData.id;

      logger.debug('MESSAGE_HANDLER', `Processing transaction: ${transactionId}`);

      // Check if we've already seen this transaction to prevent relay loops
      if (this.hasSeenTransaction(transactionId)) {
        logger.debug('MESSAGE_HANDLER', `🔄 Transaction ${transactionId} already seen, skipping relay to prevent loop`);
        return;
      }

      // Mark transaction as seen first (before processing to prevent race conditions)
      this.markTransactionAsSeen(transactionId);

      if (this.blockchain.addPendingTransaction(transactionData)) {
        logger.info('MESSAGE_HANDLER', `✅ New transaction ${transactionId} added to mempool from peer ${peerAddress}`);

        // Relay to other peers (Bitcoin-style relay) - now loop-safe
        this.broadcastTransactionToOtherPeers(transactionData, peerAddress);
      } else {
        logger.warn('MESSAGE_HANDLER', `❌ Transaction ${transactionId} rejected by mempool (duplicate/invalid)`);
      }
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `💥 Failed to process new transaction from ${peerAddress}: ${error.message}`);
      logger.error('MESSAGE_HANDLER', `Error stack: ${error.stack}`);
    }
  }

  /**
   * Handle mempool synchronization request (Bitcoin-style)
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleMempoolSyncRequest(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Mempool sync request from ${peerAddress}`);

    try {
      const pendingTransactions = this.blockchain.memoryPool.getPendingTransactions();
      const mempoolHashes = pendingTransactions.map(tx => tx.hash);

      // Send mempool inventory (list of transaction hashes)
      this.sendMessage(ws, {
        type: 'MEMPOOL_INV',
        data: {
          transactionHashes: mempoolHashes,
          count: mempoolHashes.length,
          timestamp: Date.now(),
        },
      });

      logger.debug('MESSAGE_HANDLER', `Sent mempool inventory to ${peerAddress}: ${mempoolHashes.length} transactions`);
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to send mempool inventory to ${peerAddress}: ${error.message}`);
    }
  }

  /**
   * Handle mempool inventory response (Bitcoin-style)
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleMempoolInv(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Mempool inventory from ${peerAddress}: ${message.data.count} transactions`);

    try {
      const peerTransactionHashes = message.data.transactionHashes || [];
      const localTransactionHashes = this.blockchain.memoryPool.getPendingTransactions().map(tx => tx.hash);

      // Find transactions we don't have
      const missingTransactions = peerTransactionHashes.filter(hash => !localTransactionHashes.includes(hash));

      if (missingTransactions.length > 0) {
        logger.debug(
          'MESSAGE_HANDLER',
          `Requesting ${missingTransactions.length} missing transactions from ${peerAddress}`
        );

        // Request missing transactions
        this.sendMessage(ws, {
          type: 'MEMPOOL_GETDATA',
          data: {
            transactionHashes: missingTransactions,
            count: missingTransactions.length,
          },
        });
      } else {
        logger.debug('MESSAGE_HANDLER', `Mempool already synchronized with ${peerAddress}`);
      }
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to process mempool inventory from ${peerAddress}: ${error.message}`);
    }
  }

  /**
   * Handle mempool getdata request (Bitcoin-style)
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleMempoolGetData(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Mempool getdata request from ${peerAddress}: ${message.data.count} transactions`);

    try {
      const requestedHashes = message.data.transactionHashes || [];
      const pendingTransactions = this.blockchain.memoryPool.getPendingTransactions();

      // Send requested transactions
      for (const hash of requestedHashes) {
        const transaction = pendingTransactions.find(tx => tx.hash === hash);

        if (transaction) {
          this.sendMessage(ws, {
            type: 'MEMPOOL_TX',
            data: {
              transaction,
              hash,
            },
          });
        } else {
          // Transaction not found in our mempool
          this.sendMessage(ws, {
            type: 'MEMPOOL_NOTFOUND',
            data: {
              hash,
              reason: 'Transaction not in mempool',
            },
          });
        }
      }

      logger.debug(
        'MESSAGE_HANDLER',
        `Processed getdata request from ${peerAddress}: ${requestedHashes.length} transactions`
      );
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to process getdata request from ${peerAddress}: ${error.message}`);
    }
  }

  /**
   * Handle mempool transaction (Bitcoin-style)
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleMempoolTx(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Mempool transaction received from ${peerAddress}`);

    try {
      const transactionData = message.data.transaction;
      const transactionHash = message.data.hash;

      // Validate transaction hash directly from data
      if (transactionData.hash !== transactionHash) {
        logger.warn('MESSAGE_HANDLER', `Transaction hash mismatch from ${peerAddress}`);
        this.sendMessage(ws, {
          type: 'MEMPOOL_REJECT',
          data: {
            hash: transactionHash,
            reason: 'Transaction hash mismatch',
            code: 0x01,
          },
        });
        return;
      }

      // Check if we've already seen this transaction to prevent relay loops
      if (this.hasSeenTransaction(transactionHash)) {
        logger.debug('MESSAGE_HANDLER', `🔄 Mempool transaction ${transactionHash} already seen, skipping relay to prevent loop`);
        return;
      }

      // Mark transaction as seen first (before processing to prevent race conditions)
      this.markTransactionAsSeen(transactionHash);

      // Add transaction to mempool
      if (this.blockchain.addPendingTransaction(transactionData)) {
        logger.info('MESSAGE_HANDLER', `Transaction ${transactionHash} added to mempool from ${peerAddress}`);

        // Relay to other peers (Bitcoin-style) - now loop-safe
        this.broadcastTransactionToOtherPeers(transactionData, peerAddress);
      } else {
        logger.warn('MESSAGE_HANDLER', `Failed to add transaction ${transactionHash} to mempool`);
      }
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to process mempool transaction from ${peerAddress}: ${error.message}`);
    }
  }

  /**
   * Handle mempool not found response (Bitcoin-style)
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleMempoolNotFound(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Mempool not found response from ${peerAddress}: ${message.data.hash}`);
    // Transaction was requested but not found - this is normal, just log it
  }

  /**
   * Handle mempool reject response (Bitcoin-style)
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleMempoolReject(ws, message, peerAddress) {
    logger.warn(
      'MESSAGE_HANDLER',
      `Mempool reject from ${peerAddress}: ${message.data.reason} (hash: ${message.data.hash})`
    );
    // Transaction was rejected by peer - log for debugging
  }

  /**
   * Handle mempool sync response (Bitcoin-style)
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleMempoolSyncResponse(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Mempool sync response from ${peerAddress}`);
    // Handle any additional sync response data if needed
  }

  /**
   * Handle seed node info
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleSeedNodeInfo(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Seed node info received from ${peerAddress}`);
    // Handle seed node information if needed
  }

  /**
   * Handle handshake
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleHandshake(ws, message, peerAddress) {
    logger.info('MESSAGE_HANDLER', `HANDSHAKE RECEIVED from ${peerAddress} - Processing handshake request`);
    logger.debug('MESSAGE_HANDLER', `Handshake message data: ${JSON.stringify(message.data)}`);

    try {
      // Validate handshake message structure
      if (!message.data || !message.data.networkId) {
        logger.warn('MESSAGE_HANDLER', `Invalid handshake from ${peerAddress}: missing networkId`);
        this.sendMessage(ws, {
          type: 'HANDSHAKE_REJECTED',
          data: {
            reason: 'Invalid handshake format',
            timestamp: Date.now(),
          },
        });
        return;
      }

      const peerNetworkId = message.data.networkId;
      const localNetworkId = this.config?.networkId || 'unknown';

      // Check if network IDs match
      if (peerNetworkId !== localNetworkId) {
        logger.warn(
          'MESSAGE_HANDLER',
          `Network ID mismatch from ${peerAddress}: expected ${localNetworkId}, got ${peerNetworkId}`
        );

        // Send rejection message with network ID info
        this.sendMessage(ws, {
          type: 'HANDSHAKE_REJECTED',
          data: {
            reason: 'Network ID mismatch',
            expectedNetworkId: localNetworkId,
            receivedNetworkId: peerNetworkId,
            timestamp: Date.now(),
            message: 'This node is running on a different network. Please check your configuration.',
          },
        });

        // Close connection after sending rejection
        setTimeout(() => {
          try {
            ws.close(1000, 'Network ID mismatch');
          } catch (error) {
            logger.debug('MESSAGE_HANDLER', `Error closing connection: ${error.message}`);
          }
        }, 1000);

        return;
      }

      // Network ID matches - proceed with handshake
      logger.info('MESSAGE_HANDLER', `Network ID match with ${peerAddress}: ${peerNetworkId}`);

      // Send successful handshake response
      logger.info('MESSAGE_HANDLER', `Sending HANDSHAKE_ACCEPTED to ${peerAddress}`);
      this.sendMessage(ws, {
        type: 'HANDSHAKE_ACCEPTED',
        data: {
          networkId: localNetworkId,
          nodeVersion: '1.0.0',
          timestamp: Date.now(),
          message: 'Network ID verified successfully',
        },
      });

      // CRITICAL FIX: Mark the peer as authenticated immediately after sending handshake response
      if (this.p2pNetwork) {
        this.p2pNetwork.authenticatedPeers.set(peerAddress, {
          nodeId: message.data.nodeId || 'unknown',
          networkId: peerNetworkId,
          authenticatedAt: Date.now(),
        });
        logger.info('MESSAGE_HANDLER', `Peer ${peerAddress} marked as authenticated after successful handshake`);
      }

      // Update peer reputation for successful handshake
      this.peerReputation.updatePeerReputation(peerAddress, 'good_behavior', {
        reason: 'successful_handshake',
        networkId: peerNetworkId,
      });

      // Update connection state to connected
      if (this.p2pNetwork && this.p2pNetwork.connectionStates) {
        this.p2pNetwork.connectionStates.set(peerAddress, 'connected');
        logger.debug('MESSAGE_HANDLER', `Connection state updated to 'connected' for ${peerAddress}`);
      }

      // Enhanced seed node detection using listening port
      const peerListeningPort = message.data.listeningPort;
      let isSeedNode = false;

      if (peerListeningPort) {
        // Store the peer's listening port for future reference
        if (this.p2pNetwork?.peerManager) {
          this.p2pNetwork.peerManager.setPeerListeningPort(ws, peerListeningPort);
        }

        // Check if peer is a seed node by their listening port
        isSeedNode = this.p2pNetwork?.peerManager?.isSeedNodeByListeningPort(peerAddress, peerListeningPort);
        logger.debug(
          'MESSAGE_HANDLER',
          `Peer ${peerAddress} listening on port ${peerListeningPort}, seed node: ${isSeedNode}`
        );
      } else {
        // Fallback to direct address check
        isSeedNode = this.p2pNetwork?.peerManager?.isSeedNodeAddress(peerAddress);
      }

      // Check if this is a seed node and log it
      if (isSeedNode) {
        logger.info(
          'MESSAGE_HANDLER',
          `Seed node handshake completed successfully with ${peerAddress} (listening on port ${peerListeningPort})`
        );
      } else {
        logger.info('MESSAGE_HANDLER', `Peer handshake completed successfully with ${peerAddress}`);
      }

      logger.info('MESSAGE_HANDLER', `Handshake completed successfully with ${peerAddress}`);

      // Check for bidirectional connections after handshake completion
      if (isSeedNode && peerListeningPort) {
        const [peerIP] = peerAddress.split(':');
        const targetAddress = `${peerIP}:${peerListeningPort}`;
        const existingAddresses = this.p2pNetwork.peerManager.getPeerAddresses();

        const hasOutgoingToSameSeedNode = existingAddresses.includes(targetAddress);

        if (hasOutgoingToSameSeedNode) {
          logger.info('MESSAGE_HANDLER', `🚫 Closing bidirectional connection from seed node ${peerAddress} (already connected to ${targetAddress})`);
          ws.close();
          return;
        }
      }

      // MEMPOOL SYNC: Request current mempool from newly connected peer
      try {
        const mempoolSyncMessage = {
          type: 'MEMPOOL_SYNC_REQUEST',
          timestamp: Date.now(),
          networkId: this.blockchain.config?.networkId || 'unknown',
        };

        this.sendMessage(ws, mempoolSyncMessage);
        logger.debug('MESSAGE_HANDLER', `Mempool sync request sent to newly connected peer ${peerAddress}`);
      } catch (error) {
        logger.debug('MESSAGE_HANDLER', `Failed to request mempool sync from ${peerAddress}: ${error.message}`);
      }
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Error during handshake with ${peerAddress}: ${error.message}`);

      // Send error response
      this.sendMessage(ws, {
        type: 'HANDSHAKE_ERROR',
        data: {
          reason: 'Internal error during handshake',
          timestamp: Date.now(),
        },
      });
    }
  }

  /**
   * Handle handshake accepted response
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleHandshakeAccepted(ws, message, peerAddress) {
    logger.info('MESSAGE_HANDLER', `Handshake accepted by ${peerAddress}: ${message.data.networkId}`);

    // Clear any pending handshake timeout
    if (this.p2pNetwork && this.p2pNetwork.pendingHandshakes) {
      const timeout = this.p2pNetwork.pendingHandshakes.get(peerAddress);
      if (timeout) {
        clearTimeout(timeout);
        this.p2pNetwork.pendingHandshakes.delete(peerAddress);
      }
    }

    // Mark peer as authenticated
    if (this.p2pNetwork) {
      this.p2pNetwork.authenticatedPeers.set(peerAddress, {
        nodeId: message.data.nodeId || 'unknown',
        networkId: message.data.networkId,
        authenticatedAt: Date.now(),
      });
    }

    // Update peer reputation
    this.peerReputation.updatePeerReputation(peerAddress, 'good_behavior', {
      reason: 'handshake_accepted',
      networkId: message.data.networkId,
    });

    // Update connection state to connected
    if (this.p2pNetwork && this.p2pNetwork.connectionStates) {
      this.p2pNetwork.connectionStates.set(peerAddress, 'connected');
      logger.debug('MESSAGE_HANDLER', `Connection state updated to 'connected' for ${peerAddress}`);
    }
  }

  /**
   * Handle handshake rejected response
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleHandshakeRejected(ws, message, peerAddress) {
    logger.warn('MESSAGE_HANDLER', `Handshake rejected by ${peerAddress}: ${message.data.reason}`);

    // Clear any pending handshake timeout
    if (this.p2pNetwork && this.p2pNetwork.pendingHandshakes) {
      const timeout = this.p2pNetwork.pendingHandshakes.get(peerAddress);
      if (timeout) {
        clearTimeout(timeout);
        this.p2pNetwork.pendingHandshakes.delete(peerAddress);
      }
    }

    // Log the rejection reason
    if (message.data.expectedNetworkId && message.data.receivedNetworkId) {
      logger.warn(
        'MESSAGE_HANDLER',
        `Network ID mismatch: expected ${message.data.expectedNetworkId}, received ${message.data.receivedNetworkId}`
      );
    }

    // Update peer reputation
    this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', {
      reason: 'handshake_rejected',
      details: message.data.reason,
    });

    // Close connection after a short delay
    setTimeout(() => {
      try {
        ws.close(1000, 'Handshake rejected');
      } catch (error) {
        logger.debug('MESSAGE_HANDLER', `Error closing connection: ${error.message}`);
      }
    }, 1000);
  }

  /**
   * Handle handshake error response
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleHandshakeError(ws, message, peerAddress) {
    logger.error('MESSAGE_HANDLER', `Handshake error from ${peerAddress}: ${message.data.reason}`);

    // Clear any pending handshake timeout
    if (this.p2pNetwork && this.p2pNetwork.pendingHandshakes) {
      const timeout = this.p2pNetwork.pendingHandshakes.get(peerAddress);
      if (timeout) {
        clearTimeout(timeout);
        this.p2pNetwork.pendingHandshakes.delete(peerAddress);
      }
    }

    // Update peer reputation
    this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', {
      reason: 'handshake_error',
      details: message.data.reason,
    });

    // Close connection after a short delay
    setTimeout(() => {
      try {
        ws.close(1000, 'Handshake error');
      } catch (error) {
        logger.debug('MESSAGE_HANDLER', `Error closing connection: ${error.message}`);
      }
    }, 1000);
  }

  /**
   * Handle authentication challenge
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleAuthChallenge(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Auth challenge received from ${peerAddress}`);
    // Handle authentication challenge
  }

  /**
   * Handle authentication response
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleAuthResponse(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Auth response received from ${peerAddress}`);
    // Handle authentication response
  }

  /**
   * Handle authentication success
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleAuthSuccess(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Auth success received from ${peerAddress}`);
    // Handle authentication success
  }

  /**
   * Handle authentication failure
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleAuthFailure(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Auth failure received from ${peerAddress}`);
    // Handle authentication failure
  }

  /**
   * Handle health status
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleHealthStatus(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Health status received from ${peerAddress}: ${JSON.stringify(message.data)}`);

    // Update peer reputation for good communication
    this.peerReputation.updatePeerReputation(peerAddress, 'good_behavior', { reason: 'health_status_received' });
  }

  /**
   * Handle peer list request
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleRequestPeerList(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Peer list requested by ${peerAddress}`);

    // Send our peer list back
    const peerList = this.getPeerList();
    const response = {
      type: 'PEER_LIST_RESPONSE',
      data: {
        peers: peerList.map(peer => peer.url),
        timestamp: Date.now(),
        requester: message.data.requester,
      },
    };

    this.sendMessage(ws, response);
    this.peerReputation.updatePeerReputation(peerAddress, 'good_behavior', { reason: 'peer_list_provided' });
  }

  /**
   * Handle heartbeat
   * @param ws
   * @param message
   * @param peerAddress
   */
  handleHeartbeat(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Heartbeat received from ${peerAddress}, sequence: ${message.data.sequence}`);

    // Update peer reputation for maintaining connection
    this.peerReputation.updatePeerReputation(peerAddress, 'good_behavior', { reason: 'heartbeat_received' });
  }

  /**
   * Send message to peer
   * @param ws
   * @param message
   */
  sendMessage(ws, message) {
    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
        return true;
      }
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to send message: ${error.message}`);
    }
    return false;
  }

  /**
   * Get peer list (placeholder - should be implemented by main network)
   */
  getPeerList() {
    // This should be implemented by the main P2PNetwork class
    // For now, return empty array - the main P2PNetwork class will override this
    return [];
  }

  /**
   * Get message validation statistics
   */
  getMessageValidationStats() {
    return {
      ...this.messageValidationStats,
      validationErrors: Object.fromEntries(this.messageValidationStats.validationErrors),
    };
  }

  /**
   * Reset message validation statistics
   */
  resetMessageValidationStats() {
    this.messageValidationStats = {
      totalMessages: 0,
      validMessages: 0,
      invalidMessages: 0,
      validationErrors: new Map(),
    };
  }

  /**
   * Broadcast transaction to other peers (Bitcoin-style relay)
   * @param transaction
   * @param excludePeer
   */
  broadcastTransactionToOtherPeers(transaction, excludePeer) {
    try {
      if (!this.p2pNetwork) {
        logger.debug('MESSAGE_HANDLER', 'P2P network not available for transaction relay');
        return;
      }

      // Use the P2P network's broadcast method
      const broadcastCount = this.p2pNetwork.broadcastNewTransaction(transaction);
      logger.debug('MESSAGE_HANDLER', `Transaction ${transaction.hash} relayed to ${broadcastCount} peers`);
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to relay transaction: ${error.message}`);
    }
  }

  /**
   * Check if a transaction has already been seen/relayed
   * @param {string} transactionId - The transaction ID to check
   * @returns {boolean} True if transaction has been seen before
   */
  hasSeenTransaction(transactionId) {
    this.cleanupSeenTransactions();
    return this.seenTransactions.has(transactionId);
  }

  /**
   * Mark a transaction as seen to prevent relay loops
   * @param {string} transactionId - The transaction ID to mark as seen
   */
  markTransactionAsSeen(transactionId) {
    this.seenTransactions.set(transactionId, Date.now());

    // Limit cache size to prevent memory leaks
    if (this.seenTransactions.size > this.maxSeenTransactions) {
      const oldestEntries = Array.from(this.seenTransactions.entries())
        .sort((a, b) => a[1] - b[1])
        .slice(0, this.seenTransactions.size - this.maxSeenTransactions + 1000);

      for (const [txId] of oldestEntries) {
        this.seenTransactions.delete(txId);
      }

      logger.debug('MESSAGE_HANDLER', `Cleaned up ${oldestEntries.length} old seen transactions`);
    }
  }

  /**
   * Clean up expired seen transactions based on TTL
   */
  cleanupSeenTransactions() {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [txId, timestamp] of this.seenTransactions.entries()) {
      if (now - timestamp > this.seenTransactionTTL) {
        this.seenTransactions.delete(txId);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.debug('MESSAGE_HANDLER', `Cleaned up ${cleanedCount} expired seen transactions`);
    }
  }

  /**
   * Generate a hash for message deduplication
   * @param {Object} message - The message to hash
   * @param {string} peerAddress - The peer address
   * @returns {string} Message hash
   */
  generateMessageHash(message, peerAddress) {
    const crypto = require('crypto');
    const messageString = JSON.stringify({ type: message.type, data: message.data, peer: peerAddress });
    return crypto.createHash('sha256').update(messageString).digest('hex');
  }

  /**
   * Check if we've seen this message recently (prevent flooding)
   * Smart duplicate detection that treats different message types appropriately
   * @param {Object} message - The message to check
   * @param {string} peerAddress - The peer address
   * @returns {boolean} True if message should be blocked
   */
  isDuplicateMessage(message, peerAddress) {
    const messageHash = this.generateMessageHash(message, peerAddress);
    const now = Date.now();

    // Clean up expired messages first
    this.cleanupSeenMessages();

    // Define message categories with different rules
    const maintenanceMessages = ['QUERY_LATEST', 'PING', 'PONG', 'QUERY_TRANSACTION', 'MEMPOOL_SYNC_REQUEST', 'HEARTBEAT', 'RESPONSE_BLOCKCHAIN'];
    const isMaintenanceMessage = maintenanceMessages.includes(message.type);

    // Different rules for different message types
    const rules = isMaintenanceMessage ? {
      maxDuplicates: 10,           // Allow more duplicates for maintenance messages
      timeWindow: 60000,           // 60 seconds window for maintenance messages
      noReputationPenalty: true,   // Don't penalize reputation for sync messages
      logLevel: 'debug'            // Less noisy logging for normal sync behavior
    } : {
      maxDuplicates: this.maxDuplicatesPerPeer, // Strict limit for content messages
      timeWindow: this.messageTTL, // Standard TTL
      noReputationPenalty: false,  // Apply reputation penalties
      logLevel: 'warn'             // Alert for actual flooding
    };

    const seenInfo = this.seenMessages.get(messageHash);
    if (seenInfo) {
      // Check if enough time has passed for maintenance messages
      if (isMaintenanceMessage && (now - seenInfo.timestamp) > rules.timeWindow) {
        // Reset the seen message for maintenance messages after time window
        this.seenMessages.set(messageHash, {
          timestamp: now,
          count: 1,
          peerAddress,
          messageType: message.type
        });
        logger.debug('MESSAGE_HANDLER', `Allowing ${message.type} after time window from ${peerAddress}`);
        return false; // Allow message after time window
      }

      // Update duplicate count
      seenInfo.count++;
      seenInfo.timestamp = now;

      if (seenInfo.count > rules.maxDuplicates) {
        if (rules.logLevel === 'warn') {
          logger.warn('MESSAGE_HANDLER', `🚨 FLOODING DETECTED: Peer ${peerAddress} sent duplicate message ${seenInfo.count} times`);
          logger.warn('MESSAGE_HANDLER', `Message type: ${message.type}`);
        } else {
          logger.debug('MESSAGE_HANDLER', `High duplicate count for ${message.type} from ${peerAddress}: ${seenInfo.count} times (normal for sync)`);
        }
        return true; // Block this message
      }

      const logMessage = isMaintenanceMessage ?
        `Duplicate ${message.type} from ${peerAddress} (count: ${seenInfo.count}, normal sync behavior)` :
        `Duplicate message from ${peerAddress} (count: ${seenInfo.count})`;

      logger.debug('MESSAGE_HANDLER', logMessage);
      return true; // Block duplicate
    }

    // Mark message as seen
    this.seenMessages.set(messageHash, {
      timestamp: now,
      count: 1,
      peerAddress,
      messageType: message.type
    });

    return false; // Allow message
  }

  /**
   * Check rate limiting for peer
   * @param {string} peerAddress - The peer address
   * @returns {boolean} True if rate limit exceeded
   */
  isRateLimited(peerAddress) {
    const now = Date.now();
    const peerRate = this.peerMessageRates.get(peerAddress);

    if (!peerRate) {
      // First message from this peer
      this.peerMessageRates.set(peerAddress, { count: 1, windowStart: now });
      return false;
    }

    // Check if window expired
    if (now - peerRate.windowStart > this.rateWindow) {
      // Reset window
      peerRate.count = 1;
      peerRate.windowStart = now;
      return false;
    }

    // Increment count
    peerRate.count++;

    if (peerRate.count > this.maxMessagesPerWindow) {
      logger.warn('MESSAGE_HANDLER', `🚨 RATE LIMIT EXCEEDED: Peer ${peerAddress} sent ${peerRate.count} messages in ${this.rateWindow}ms`);
      return true;
    }

    return false;
  }

  /**
   * Clean up expired seen messages based on TTL
   */
  cleanupSeenMessages() {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [messageHash, info] of this.seenMessages.entries()) {
      if (now - info.timestamp > this.messageTTL) {
        this.seenMessages.delete(messageHash);
        cleanedCount++;
      }
    }

    // Limit cache size to prevent memory leaks
    if (this.seenMessages.size > this.maxSeenMessages) {
      const oldestEntries = Array.from(this.seenMessages.entries())
        .sort((a, b) => a[1].timestamp - b[1].timestamp)
        .slice(0, this.seenMessages.size - this.maxSeenMessages + 1000);

      for (const [messageHash] of oldestEntries) {
        this.seenMessages.delete(messageHash);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.debug('MESSAGE_HANDLER', `Cleaned up ${cleanedCount} expired/old seen messages`);
    }
  }

  /**
   * Handle peer list request - send our known peers to requesting node
   * @param {WebSocket} ws
   * @param {Object} message
   * @param {string} peerAddress
   */
  handlePeerListRequest(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Peer list request from ${peerAddress}`);

    try {
      // Get peers to share from PeerDiscovery if available
      let peersToShare = [];

      if (this.peerDiscovery) {
        peersToShare = this.peerDiscovery.getPeersToShare(10);
      } else {
        // Fallback: use currently connected peers
        const connectedPeers = this.peerManager.getAllPeers();
        peersToShare = connectedPeers.map(peer => {
          const address = this.peerManager.getPeerAddress(peer);
          return {
            address: address,
            port: 23000,
            reputation: 500,
            lastSeen: Date.now()
          };
        }).slice(0, 10);
      }

      // Send peer list
      this.sendMessage(ws, {
        type: 'PEER_LIST_SHARE',
        data: {
          peers: peersToShare,
          timestamp: Date.now()
        }
      });

      logger.debug('MESSAGE_HANDLER', `Sent ${peersToShare.length} peers to ${peerAddress}`);

    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to handle peer list request from ${peerAddress}: ${error.message}`);
    }
  }

  /**
   * Handle received peer list from another node
   * @param {WebSocket} ws
   * @param {Object} message
   * @param {string} peerAddress
   */
  handlePeerListShare(ws, message, peerAddress) {
    logger.debug('MESSAGE_HANDLER', `Received peer list from ${peerAddress}`);

    try {
      const { peers } = message.data;

      if (!Array.isArray(peers)) {
        logger.warn('MESSAGE_HANDLER', `Invalid peer list format from ${peerAddress}`);
        return;
      }

      // Process peer list with PeerDiscovery if available
      if (this.peerDiscovery) {
        this.peerDiscovery.processPeerShare(peers, peerAddress);
      } else {
        // Fallback: log the received peers
        logger.info('MESSAGE_HANDLER', `Received ${peers.length} peers from ${peerAddress} (PeerDiscovery not available)`);
      }

    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to process peer list from ${peerAddress}: ${error.message}`);
    }
  }

  /**
   * Handle PING message - respond with PONG
   * @param {WebSocket} ws
   * @param {Object} message
   * @param {string} peerAddress
   */
  handlePing(ws, message, peerAddress) {
    try {
      // Respond with PONG
      this.sendMessage(ws, {
        type: 'PONG',
        timestamp: Date.now()
      });

      logger.debug('MESSAGE_HANDLER', `Responded to PING from ${peerAddress}`);
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to handle PING from ${peerAddress}: ${error.message}`);
    }
  }

  /**
   * Handle PONG message - used for connection health monitoring
   * @param {WebSocket} ws
   * @param {Object} message
   * @param {string} peerAddress
   */
  handlePong(ws, message, peerAddress) {
    try {
      logger.debug('MESSAGE_HANDLER', `PONG received from ${peerAddress}`);

      // Update last activity time if PeerDiscovery is available
      if (this.peerDiscovery) {
        // Mark peer as active (update last seen)
        const peerInfo = this.peerDiscovery.knownPeers.get(peerAddress);
        if (peerInfo) {
          peerInfo.lastSeen = Date.now();
        }
      }
    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Failed to handle PONG from ${peerAddress}: ${error.message}`);
    }
  }

  /**
   * CRITICAL: Verify that the received chain is consistent with the local chain
   * @param {Array} receivedChain - The received blockchain to check
   * @param {Array} localChain - The local blockchain to compare against
   * @returns {Object} - {consistent: boolean, reason: string, blockIndex?: number, details?: string}
   */
  verifyChainConsistency(receivedChain, localChain) {
    const localHeight = localChain.length;
    const receivedHeight = receivedChain.length;

    // If received chain is shorter than local chain, it's definitely inconsistent
    if (receivedHeight < localHeight) {
      return {
        consistent: false,
        reason: `Received chain is shorter than local chain (received: ${receivedHeight}, local: ${localHeight})`,
        blockIndex: receivedHeight
      };
    }

    // Compare each block in the local chain with the corresponding block in the received chain
    for (let i = 0; i < localHeight; i++) {
      const localBlock = localChain[i];
      const receivedBlock = receivedChain[i];

      // Check if block exists at this index
      if (!receivedBlock) {
        return {
          consistent: false,
          reason: `Missing block at index ${i} in received chain`,
          blockIndex: i
        };
      }

      // Check block index consistency
      if (localBlock.index !== receivedBlock.index) {
        return {
          consistent: false,
          reason: `Block index mismatch at position ${i}`,
          blockIndex: i,
          details: `Local: ${localBlock.index}, Received: ${receivedBlock.index}`
        };
      }

      // Check block hash consistency (most important check)
      if (localBlock.hash !== receivedBlock.hash) {
        return {
          consistent: false,
          reason: `Block hash mismatch at index ${i}`,
          blockIndex: i,
          details: `Local: ${localBlock.hash?.substring(0, 16)}..., Received: ${receivedBlock.hash?.substring(0, 16)}...`
        };
      }

      // Check previous hash consistency
      if (localBlock.previousHash !== receivedBlock.previousHash) {
        return {
          consistent: false,
          reason: `Previous hash mismatch at index ${i}`,
          blockIndex: i,
          details: `Local: ${localBlock.previousHash?.substring(0, 16)}..., Received: ${receivedBlock.previousHash?.substring(0, 16)}...`
        };
      }

      // Check timestamp consistency (should be exact match for deterministic blocks)
      if (localBlock.timestamp !== receivedBlock.timestamp) {
        return {
          consistent: false,
          reason: `Timestamp mismatch at index ${i}`,
          blockIndex: i,
          details: `Local: ${localBlock.timestamp}, Received: ${receivedBlock.timestamp}`
        };
      }

      logger.debug('MESSAGE_HANDLER', `Block ${i} consistency check passed: ${localBlock.hash?.substring(0, 16)}...`);
    }

    logger.info('MESSAGE_HANDLER', `Chain consistency verified: all ${localHeight} local blocks match received chain`);

    return {
      consistent: true,
      reason: `All ${localHeight} blocks verified successfully`
    };
  }

  /**
   * CRITICAL: Perform complete blockchain resync from genesis when corruption is detected
   * @param {WebSocket} ws - WebSocket connection to the peer
   * @param {string} peerAddress - Address of the peer
   */
  async performFullBlockchainResync(ws, peerAddress) {
    try {
      logger.warn('MESSAGE_HANDLER', '🔄 INITIATING FULL BLOCKCHAIN RESYNC');
      logger.warn('MESSAGE_HANDLER', 'This will reset the entire blockchain and resync from genesis block');

      // Step 1: Clear the corrupted blockchain completely
      logger.info('MESSAGE_HANDLER', 'Step 1: Clearing corrupted blockchain data...');
      this.blockchain.clearChain();
      logger.info('MESSAGE_HANDLER', 'Local blockchain cleared - starting fresh from genesis');

      // Step 2: Reinitialize blockchain with genesis block
      logger.info('MESSAGE_HANDLER', 'Step 2: Reinitializing blockchain with genesis block...');
      // Use the configured miner address or a default one for genesis
      const genesisAddress = this.config?.mining?.address || 'PAS1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8h7h0';
      this.blockchain.initialize(genesisAddress, this.config, true); // suppressLogging = true
      logger.info('MESSAGE_HANDLER', `Genesis block reinitialized for address: ${genesisAddress}`);

      // Step 3: Request full blockchain from the peer
      logger.info('MESSAGE_HANDLER', 'Step 3: Requesting complete blockchain from peer...');
      logger.info('MESSAGE_HANDLER', `Requesting full chain from ${peerAddress} for complete resync`);

      // Send QUERY_ALL to get the complete blockchain
      const queryMessage = {
        type: 'QUERY_ALL',
        timestamp: Date.now(),
        reason: 'full_blockchain_resync_after_corruption'
      };

      this.sendMessage(ws, queryMessage);

      // Step 4: Save the reset state
      logger.info('MESSAGE_HANDLER', 'Step 4: Saving reset blockchain state...');
      try {
        const blockchainPath = path.join(
          this.config?.storage?.dataDir || './data',
          this.config?.storage?.blockchainFile || 'blockchain.json'
        );
        this.blockchain.saveToFile(blockchainPath);
        logger.info('MESSAGE_HANDLER', 'Reset blockchain saved - ready for full resync');
      } catch (saveError) {
        logger.error('MESSAGE_HANDLER', `Failed to save reset blockchain: ${saveError.message}`);
      }

      logger.warn('MESSAGE_HANDLER', '✅ Full blockchain resync initiated successfully');
      logger.warn('MESSAGE_HANDLER', 'Waiting for peer to send complete blockchain...');

    } catch (error) {
      logger.error('MESSAGE_HANDLER', `Critical error during full blockchain resync: ${error.message}`);
      logger.error('MESSAGE_HANDLER', `Error stack: ${error.stack}`);

      // If resync fails, we're in a critical state - log clearly
      logger.error('MESSAGE_HANDLER', '💥 CRITICAL: Full blockchain resync failed!');
      logger.error('MESSAGE_HANDLER', 'Manual intervention may be required');
      logger.error('MESSAGE_HANDLER', 'Consider deleting blockchain data files and restarting the daemon');
    }
  }

  /**
   * Handle version check message from peer
   * @param {WebSocket} ws - WebSocket connection
   * @param {Object} message - Version check message
   * @param {string} peerAddress - Peer address
   */
  handleVersionCheck(ws, message, peerAddress) {
    logger.info('MESSAGE_HANDLER', `📥 VERSION_CHECK received from ${peerAddress}`);
    logger.debug('MESSAGE_HANDLER', `Version check message data: ${JSON.stringify(message.data)}`);

    if (!this.forkManager) {
      logger.error('MESSAGE_HANDLER', 'ForkManager not available for version checking');
      this.disconnectPeerWithReason(ws, peerAddress, 'Server configuration error');
      return;
    }

    // Get our version info
    const ourVersionInfo = this.forkManager.getVersionInfo();

    // Send our version response
    const response = {
      type: 'VERSION_RESPONSE',
      data: ourVersionInfo
    };

    logger.info('MESSAGE_HANDLER', `📤 Sending VERSION_RESPONSE to ${peerAddress}: v${ourVersionInfo.version}`);
    this.sendMessage(ws, response);

    // If peer sent their version info, validate it and clear timeout
    if (message.data && typeof message.data.version === 'number') {
      logger.info('MESSAGE_HANDLER', `✅ Peer ${peerAddress} provided version data: v${message.data.version}`);
      this.clearVersionCheckTimeout(peerAddress);
      this.validatePeerVersion(ws, peerAddress, message.data);
    } else {
      logger.warn('MESSAGE_HANDLER', `⚠️ Peer ${peerAddress} sent VERSION_CHECK without valid version data`);
      logger.warn('MESSAGE_HANDLER', `Message data: ${JSON.stringify(message.data)}`);
      // Don't clear timeout - peer must send proper version info
    }
  }

  /**
   * Handle version response from peer
   * @param {WebSocket} ws - WebSocket connection
   * @param {Object} message - Version response message
   * @param {string} peerAddress - Peer address
   */
  handleVersionResponse(ws, message, peerAddress) {
    logger.info('MESSAGE_HANDLER', `📥 VERSION_RESPONSE received from ${peerAddress}`);
    logger.debug('MESSAGE_HANDLER', `Version response data: ${JSON.stringify(message.data)}`);

    if (!this.forkManager) {
      logger.error('MESSAGE_HANDLER', 'ForkManager not available for version validation');
      this.disconnectPeerWithReason(ws, peerAddress, 'Server configuration error');
      return;
    }

    if (!message.data || typeof message.data.version !== 'number') {
      logger.error('MESSAGE_HANDLER', `❌ INVALID VERSION_RESPONSE from ${peerAddress}`);
      logger.error('MESSAGE_HANDLER', `Expected version number, got: ${JSON.stringify(message.data)}`);
      logger.error('MESSAGE_HANDLER', `⚠️ DISCONNECTING: Invalid version information`);
      this.disconnectPeerWithReason(ws, peerAddress, 'Invalid version information - version number required');
      return;
    }

    logger.info('MESSAGE_HANDLER', `✅ Valid VERSION_RESPONSE from ${peerAddress}: v${message.data.version}`);

    // Clear version check timeout - peer responded with valid data
    this.clearVersionCheckTimeout(peerAddress);

    this.validatePeerVersion(ws, peerAddress, message.data);
  }

  /**
   * Validate peer version and disconnect if incompatible
   * @param {WebSocket} ws - WebSocket connection
   * @param {string} peerAddress - Peer address
   * @param {Object} peerVersionInfo - Peer version information
   */
  validatePeerVersion(ws, peerAddress, peerVersionInfo) {
    const validation = this.forkManager.validatePeerVersionInfo(peerVersionInfo);

    logger.info('MESSAGE_HANDLER', `🔍 Version Validation for ${peerAddress}:`);
    logger.info('MESSAGE_HANDLER', `   Peer Version: ${peerVersionInfo.version}`);
    logger.info('MESSAGE_HANDLER', `   Peer Fork: ${peerVersionInfo.forkName || 'Unknown'}`);
    logger.info('MESSAGE_HANDLER', `   Compatible: ${validation.success ? '✅ YES' : '❌ NO'}`);

    if (!validation.success) {
      logger.warn('MESSAGE_HANDLER', '🚫 INCOMPATIBLE PEER VERSION DETECTED');
      logger.warn('MESSAGE_HANDLER', `   Reason: ${validation.message}`);

      if (validation.upgradeRequired) {
        logger.warn('MESSAGE_HANDLER', '   ⚠️  Peer needs to upgrade their daemon');
      }

      // Disconnect the peer with a clear reason
      this.disconnectPeerWithReason(ws, peerAddress, `Version incompatibility: ${validation.message}`);
      return;
    }

    logger.info('MESSAGE_HANDLER', `✅ Peer ${peerAddress} version validated successfully`);

    // Log compatibility details
    if (validation.peerFork) {
      logger.debug('MESSAGE_HANDLER', `   Peer Fork Details: ${validation.peerFork.name} - ${validation.peerFork.description}`);
    }

    // CRITICAL: Add peer to validated set to allow blockchain operations
    this.versionValidatedPeers.add(peerAddress);
    logger.info('MESSAGE_HANDLER', `🎯 Peer ${peerAddress} added to validated peers - blockchain operations now ALLOWED`);
    logger.debug('MESSAGE_HANDLER', `Total validated peers: ${this.versionValidatedPeers.size}`);
  }

  /**
   * Clean up peer-related data when peer disconnects
   * @param {string} peerAddress - Peer address to clean up
   */
  cleanupPeerData(peerAddress) {
    logger.debug('MESSAGE_HANDLER', `🧹 Cleaning up data for disconnected peer ${peerAddress}`);

    // Remove from validated peers
    const wasValidated = this.versionValidatedPeers.delete(peerAddress);
    if (wasValidated) {
      logger.debug('MESSAGE_HANDLER', `Removed ${peerAddress} from validated peers list`);
    }

    // Clear version check timeout if still pending
    const pendingCheck = this.pendingVersionChecks.get(peerAddress);
    if (pendingCheck) {
      if (pendingCheck.timeoutId) {
        clearTimeout(pendingCheck.timeoutId);
      }
      this.pendingVersionChecks.delete(peerAddress);
      logger.debug('MESSAGE_HANDLER', `Cleared pending version check for ${peerAddress}`);
    }

    // Clean up other peer-related data
    this.peerMessageRates.delete(peerAddress);

    logger.debug('MESSAGE_HANDLER', `✅ Cleanup completed for ${peerAddress}`);
    logger.debug('MESSAGE_HANDLER', `Remaining validated peers: ${this.versionValidatedPeers.size}`);
  }

  /**
   * Disconnect a peer with a specific reason and logging
   * @param {WebSocket} ws - WebSocket connection
   * @param {string} peerAddress - Peer address
   * @param {string} reason - Disconnection reason
   */
  disconnectPeerWithReason(ws, peerAddress, reason) {
    logger.warn('MESSAGE_HANDLER', `Disconnecting peer ${peerAddress}: ${reason}`);

    // Send disconnection message if connection is still open
    if (ws.readyState === 1) {
      try {
        const disconnectMessage = {
          type: 'DISCONNECT',
          data: {
            reason: reason,
            timestamp: Date.now()
          }
        };
        this.sendMessage(ws, disconnectMessage);
      } catch (error) {
        logger.debug('MESSAGE_HANDLER', `Failed to send disconnect message to ${peerAddress}: ${error.message}`);
      }

      // Close the connection
      setTimeout(() => {
        if (ws.readyState === 1) {
          ws.close(1000, reason);
        }
      }, 100); // Small delay to ensure message is sent
    }

    // Update peer reputation if available
    if (this.peerReputation) {
      this.peerReputation.updatePeerReputation(peerAddress, 'bad_behavior', { reason: reason });
    }

    // Clean up peer data (version validation, timeouts, etc.)
    this.cleanupPeerData(peerAddress);
  }

  /**
   * Initiate version check with a peer
   * MANDATORY: Peer must respond within timeout or will be disconnected
   * @param {WebSocket} ws - WebSocket connection
   * @param {string} peerAddress - Peer address
   */
  initiateVersionCheck(ws, peerAddress) {
    if (!this.forkManager) {
      logger.warn('MESSAGE_HANDLER', 'ForkManager not available - skipping version check');
      return;
    }

    logger.info('MESSAGE_HANDLER', `Initiating MANDATORY version check with ${peerAddress}`);

    const ourVersionInfo = this.forkManager.getVersionInfo();
    const message = {
      type: 'VERSION_CHECK',
      data: ourVersionInfo
    };

    // Set up timeout for version response - MANDATORY for all peers
    const timeoutId = setTimeout(() => {
      this.handleVersionCheckTimeout(peerAddress, ws);
    }, this.versionCheckTimeout);

    // Track pending version check
    this.pendingVersionChecks.set(peerAddress, {
      timestamp: Date.now(),
      timeoutId,
      ws
    });

    logger.debug('MESSAGE_HANDLER', `Version check timeout set: ${this.versionCheckTimeout}ms for ${peerAddress}`);
    this.sendMessage(ws, message);
  }

  /**
   * Handle version check timeout - disconnect non-compliant peers
   * @param {string} peerAddress - Peer address that timed out
   * @param {WebSocket} ws - WebSocket connection
   */
  handleVersionCheckTimeout(peerAddress, ws) {
    if (this.pendingVersionChecks.has(peerAddress)) {
      logger.error('MESSAGE_HANDLER', `VERSION CHECK TIMEOUT: Peer ${peerAddress} did not respond to version check`);
      logger.error('MESSAGE_HANDLER', `DISCONNECTING: Peer lacks fork compatibility mechanism - connection rejected`);

      // Clean up tracking
      this.pendingVersionChecks.delete(peerAddress);

      // Disconnect the non-compliant peer
      this.disconnectPeerWithReason(ws, peerAddress, 'Version check timeout - fork compatibility required');
    }
  }

  /**
   * Clear version check timeout for a peer that responded
   * @param {string} peerAddress - Peer address that responded
   */
  clearVersionCheckTimeout(peerAddress) {
    const pendingCheck = this.pendingVersionChecks.get(peerAddress);
    if (pendingCheck) {
      logger.debug('MESSAGE_HANDLER', `✅ Clearing version check timeout for ${peerAddress}`);
      clearTimeout(pendingCheck.timeoutId);
      this.pendingVersionChecks.delete(peerAddress);
    }
  }

  /**
   * Set PeerDiscovery instance for enhanced peer management
   * @param {PeerDiscovery} peerDiscovery
   */
  setPeerDiscovery(peerDiscovery) {
    this.peerDiscovery = peerDiscovery;
    logger.debug('MESSAGE_HANDLER', 'PeerDiscovery instance set for message handler');
  }
}

module.exports = MessageHandler;
