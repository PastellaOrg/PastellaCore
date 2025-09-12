const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const logger = require('../utils/logger');

/**
 *
 */
class NodeIdentity {
  /**
   *
   * @param nodeId
   * @param privateKey
   * @param dataDir
   */
  constructor(nodeId = null, privateKey = null, dataDir = './data') {
    this.nodeId = nodeId;
    this.privateKey = privateKey;
    this.publicKey = null;
    this.dataDir = dataDir;
    this.identityFile = path.join(dataDir, 'node-identity.json');

    if (nodeId && privateKey) {
      this.publicKey = this.derivePublicKey(privateKey);
    } else {
      this.loadOrGenerateIdentity();
    }
  }

  /**
   * Load existing identity or generate new one
   */
  loadOrGenerateIdentity() {
    try {
      if (fs.existsSync(this.identityFile)) {
        const identityData = JSON.parse(fs.readFileSync(this.identityFile, 'utf8'));
        this.nodeId = identityData.nodeId;
        this.privateKey = identityData.privateKey;
        this.publicKey = identityData.publicKey;
        logger.info('IDENTITY', `Loaded existing node identity: ${this.nodeId}`);
      } else {
        this.generateNewIdentity();
        this.saveIdentity();
        logger.info('IDENTITY', `Generated new node identity: ${this.nodeId}`);
      }
    } catch (error) {
      logger.error('IDENTITY', `Error loading identity: ${error.message}`);
      this.generateNewIdentity();
      this.saveIdentity();
    }
  }

  /**
   * Generate new cryptographic identity
   */
  generateNewIdentity() {
    // Generate a unique node ID (32 bytes)
    this.nodeId = crypto.randomBytes(32).toString('hex');

    // Generate ECDSA key pair for signing
    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp256k1',
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    this.privateKey = keyPair.privateKey;
    this.publicKey = keyPair.publicKey;
  }

  /**
   * Derive public key from private key
   * @param privateKey
   */
  derivePublicKey(privateKey) {
    try {
      const keyPair = crypto.createPrivateKey(privateKey);
      const publicKey = crypto.createPublicKey(keyPair);
      return publicKey.export({ type: 'spki', format: 'pem' });
    } catch (error) {
      logger.error('IDENTITY', `Error deriving public key: ${error.message}`);
      return null;
    }
  }

  /**
   * Save identity to file
   */
  saveIdentity() {
    try {
      // Ensure data directory exists
      const dataDir = path.dirname(this.identityFile);
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }

      const identityData = {
        nodeId: this.nodeId,
        privateKey: this.privateKey,
        publicKey: this.publicKey,
        createdAt: new Date().toISOString(),
      };

      fs.writeFileSync(this.identityFile, JSON.stringify(identityData, null, 2));
      logger.debug('IDENTITY', 'Node identity saved to file');
    } catch (error) {
      logger.error('IDENTITY', `Error saving identity: ${error.message}`);
    }
  }

  /**
   * Sign data with private key
   * @param data
   */
  sign(data) {
    try {
      const sign = crypto.createSign('SHA256');
      sign.update(data);
      const signature = sign.sign(this.privateKey, 'base64');
      return signature;
    } catch (error) {
      logger.error('IDENTITY', `Error signing data: ${error.message}`);
      return null;
    }
  }

  /**
   * Verify signature with public key
   * @param data
   * @param signature
   * @param publicKey
   */
  verify(data, signature, publicKey) {
    try {
      const verify = crypto.createVerify('SHA256');
      verify.update(data);
      return verify.verify(publicKey, signature, 'base64');
    } catch (error) {
      logger.error('IDENTITY', `Error verifying signature: ${error.message}`);
      return false;
    }
  }

  /**
   * Create authentication challenge
   */
  createChallenge() {
    const challenge = crypto.randomBytes(32).toString('hex');
    const timestamp = Date.now();
    const challengeData = {
      challenge,
      timestamp,
      nodeId: this.nodeId,
    };

    return {
      challenge,
      timestamp,
      nodeId: this.nodeId,
      signature: this.sign(JSON.stringify(challengeData)),
    };
  }

  /**
   * Verify authentication challenge response
   * @param challenge
   * @param response
   * @param peerNodeId
   * @param peerPublicKey
   */
  verifyChallengeResponse(challenge, response, peerNodeId, peerPublicKey) {
    try {
      // Verify the challenge response
      const expectedData = JSON.stringify({
        challenge,
        timestamp: response.timestamp,
        nodeId: peerNodeId,
      });

      if (!this.verify(expectedData, response.signature, peerPublicKey)) {
        logger.warn('IDENTITY', `Invalid challenge response signature from ${peerNodeId}`);
        return false;
      }

      // Check timestamp (prevent replay attacks)
      const now = Date.now();
      const timeDiff = Math.abs(now - response.timestamp);
      const maxTimeDiff = 5 * 60 * 1000; // 5 minutes

      if (timeDiff > maxTimeDiff) {
        logger.warn('IDENTITY', `Challenge response too old from ${peerNodeId} (${timeDiff}ms)`);
        return false;
      }

      // Verify node ID matches
      if (response.nodeId !== peerNodeId) {
        logger.warn('IDENTITY', `Node ID mismatch in challenge response from ${peerNodeId}`);
        return false;
      }

      return true;
    } catch (error) {
      logger.error('IDENTITY', `Error verifying challenge response: ${error.message}`);
      return false;
    }
  }

  /**
   * Create challenge response
   * @param challenge
   * @param timestamp
   */
  createChallengeResponse(challenge, timestamp) {
    const responseData = {
      challenge,
      timestamp,
      nodeId: this.nodeId,
    };

    return {
      challenge,
      timestamp,
      nodeId: this.nodeId,
      signature: this.sign(JSON.stringify(responseData)),
    };
  }

  /**
   * Get identity info (public data only)
   */
  getIdentityInfo() {
    return {
      nodeId: this.nodeId,
      publicKey: this.publicKey,
    };
  }

  /**
   * Validate peer identity
   * @param peerNodeId
   * @param peerPublicKey
   */
  validatePeerIdentity(peerNodeId, peerPublicKey) {
    // Basic validation
    if (!peerNodeId || typeof peerNodeId !== 'string' || peerNodeId.length !== 64) {
      logger.warn('IDENTITY', 'Invalid peer node ID format');
      return false;
    }

    if (!peerPublicKey || typeof peerPublicKey !== 'string') {
      logger.warn('IDENTITY', 'Invalid peer public key format');
      return false;
    }

    // Check if it's our own identity
    if (peerNodeId === this.nodeId) {
      logger.warn('IDENTITY', 'Peer has same node ID as self');
      return false;
    }

    // Validate public key format
    try {
      crypto.createPublicKey(peerPublicKey);
    } catch (error) {
      logger.warn('IDENTITY', `Invalid peer public key: ${error.message}`);
      return false;
    }

    return true;
  }

  /**
   * Create handshake message
   */
  createHandshake() {
    const handshakeData = {
      nodeId: this.nodeId,
      publicKey: this.publicKey,
      timestamp: Date.now(),
      version: '1.0.0',
    };

    return {
      type: 'HANDSHAKE',
      data: handshakeData,
      signature: this.sign(JSON.stringify(handshakeData)),
    };
  }

  /**
   * Verify handshake message
   * @param handshake
   */
  verifyHandshake(handshake) {
    try {
      if (!handshake || !handshake.data || !handshake.signature) {
        logger.warn('IDENTITY', 'Invalid handshake message structure');
        return false;
      }

      const { data, signature } = handshake;

      // Verify signature
      if (!this.verify(JSON.stringify(data), signature, data.publicKey)) {
        logger.warn('IDENTITY', 'Invalid handshake signature');
        return false;
      }

      // Validate identity
      if (!this.validatePeerIdentity(data.nodeId, data.publicKey)) {
        return false;
      }

      // Check timestamp
      const now = Date.now();
      const timeDiff = Math.abs(now - data.timestamp);
      const maxTimeDiff = 10 * 60 * 1000; // 10 minutes

      if (timeDiff > maxTimeDiff) {
        logger.warn('IDENTITY', `Handshake too old (${timeDiff}ms)`);
        return false;
      }

      return true;
    } catch (error) {
      logger.error('IDENTITY', `Error verifying handshake: ${error.message}`);
      return false;
    }
  }
}

module.exports = NodeIdentity;
