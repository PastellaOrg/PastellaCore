const WebSocket = require('ws');

const logger = require('../utils/logger');

/**
 * Peer Manager - Handles all peer connection management
 */
class PeerManager {
  /**
   *
   * @param maxPeers
   */
  constructor(maxPeers = 10) {
    logger.debug('PEER_MANAGER', `Initializing PeerManager: maxPeers=${maxPeers}`);

    this.peers = new Set();
    this.maxPeers = maxPeers;
    this.peerAddresses = new Map(); // Map<WebSocket, string> for address tracking

    logger.debug('PEER_MANAGER', `PeerManager configuration:`);
    logger.debug('PEER_MANAGER', `  Max Peers: ${this.maxPeers}`);
    logger.debug('PEER_MANAGER', `  Initial peer count: ${this.peers.size}`);

    logger.debug('PEER_MANAGER', `PeerManager initialized successfully`);
  }

  /**
   * Add a new peer connection
   * @param ws
   * @param peerAddress
   */
  addPeer(ws, peerAddress) {
    logger.debug(
      'PEER_MANAGER',
      `Adding peer: address=${peerAddress}, currentPeers=${this.peers.size}, maxPeers=${this.maxPeers}`
    );
    logger.debug('PEER_MANAGER', `WebSocket instance: ${ws ? 'present' : 'null'}, type: ${typeof ws}`);

    if (this.peers.size >= this.maxPeers) {
      logger.warn('PEER_MANAGER', `Max peers reached (${this.maxPeers}), rejecting connection`);
      logger.debug('PEER_MANAGER', `Cannot accept peer ${peerAddress}: peer limit exceeded`);
      return false;
    }

    logger.debug('PEER_MANAGER', `Adding peer ${peerAddress} to peer set and address map...`);
    this.peers.add(ws);
    this.peerAddresses.set(ws, peerAddress);

    logger.info('PEER_MANAGER', `Peer added: ${peerAddress} (${this.peers.size}/${this.maxPeers})`);
    logger.debug('PEER_MANAGER', `Peer added successfully: address=${peerAddress}, newPeerCount=${this.peers.size}`);
    return true;
  }

  /**
   * Set peer listening port for seed node detection
   * @param ws
   * @param listeningPort
   */
  setPeerListeningPort(ws, listeningPort) {
    this.peerListeningPorts = this.peerListeningPorts || new Map();
    this.peerListeningPorts.set(ws, listeningPort);
    logger.debug('PEER_MANAGER', `Set peer ${this.getPeerAddress(ws)} listening port: ${listeningPort}`);
  }

  /**
   * Remove a peer connection
   * @param ws
   */
  removePeer(ws) {
    const peerAddress = this.peerAddresses.get(ws);
    this.peers.delete(ws);
    this.peerAddresses.delete(ws);

    if (peerAddress) {
      logger.info('PEER_MANAGER', `Peer removed: ${peerAddress} (${this.peers.size}/${this.maxPeers})`);
      return peerAddress;
    }
    return null;
  }

  /**
   * Get peer address from WebSocket
   * @param ws
   */
  getPeerAddress(ws) {
    return this.peerAddresses.get(ws) || 'unknown';
  }

  /**
   * Check if peer exists
   * @param ws
   */
  hasPeer(ws) {
    return this.peers.has(ws);
  }

  /**
   * Get current peer count
   */
  getPeerCount() {
    return this.peers.size;
  }

  /**
   * Get all peers
   */
  getAllPeers() {
    return Array.from(this.peers);
  }

  /**
   * Get peer list for network sharing
   */
  getPeerList() {
    return Array.from(this.peerAddresses.entries()).map(([ws, address]) => {
      // Get the listening port for this peer if available
      const listeningPort = this.peerListeningPorts ? this.peerListeningPorts.get(ws) : null;

      // Check if this is a seed node by listening port (more accurate)
      let isSeedNode = false;
      if (listeningPort) {
        isSeedNode = this.isSeedNodeByListeningPort(address, listeningPort);
      } else {
        // Fallback to direct address check
        isSeedNode = this.isSeedNodeAddress(address);
      }

      return {
        url: `ws://${address}`,
        address,
        listeningPort,
        isSeedNode,
      };
    });
  }

  /**
   * Check if an address is a seed node
   * @param address
   */
  isSeedNodeAddress(address) {
    // This will be set by the P2PNetwork when it has access to seed node config
    return this.seedNodeAddresses ? this.seedNodeAddresses.has(address) : false;
  }

  /**
   * Check if a peer is a seed node by their listening port
   * This handles the case where a seed node connects from a random outgoing port
   * @param peerAddress - The address the peer connected from (e.g., 127.0.0.1:52672)
   * @param peerListeningPort - The port the peer is listening on (e.g., 23001)
   */
  isSeedNodeByListeningPort(peerAddress, peerListeningPort) {
    if (!this.seedNodeAddresses) return false;

    // Check if the peer's listening port matches any seed node
    const peerHost = peerAddress.split(':')[0];
    const seedNodeMatch = Array.from(this.seedNodeAddresses).some(seedAddress => {
      const [seedHost, seedPort] = seedAddress.split(':');
      return seedHost === peerHost && seedPort === peerListeningPort.toString();
    });

    return seedNodeMatch;
  }

  /**
   * Set seed node addresses for detection
   * @param seedNodeAddresses
   */
  setSeedNodeAddresses(seedNodeAddresses) {
    this.seedNodeAddresses = new Set(seedNodeAddresses);
  }

  /**
   * Check if we can accept more peers
   */
  canAcceptPeers() {
    return this.peers.size < this.maxPeers;
  }

  /**
   * Get peer addresses
   */
  getPeerAddresses() {
    return Array.from(this.peerAddresses.values());
  }

  /**
   * Clear all peers
   */
  clearPeers() {
    this.peers.clear();
    this.peerAddresses.clear();
    logger.info('PEER_MANAGER', 'All peers cleared');
  }

  /**
   * Set maximum peer limit
   * @param maxPeers
   */
  setMaxPeers(maxPeers) {
    this.maxPeers = maxPeers;
    logger.info('PEER_MANAGER', `Max peers set to: ${maxPeers}`);
  }

  /**
   * Get peer statistics
   */
  getPeerStats() {
    return {
      currentPeers: this.peers.size,
      maxPeers: this.maxPeers,
      availableSlots: this.maxPeers - this.peers.size,
      peerAddresses: this.getPeerAddresses(),
    };
  }
}

module.exports = PeerManager;
