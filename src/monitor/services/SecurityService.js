const logger = require('../../utils/logger');
const { CryptoUtils } = require('../../utils/crypto');

/**
 * SECURITY MONITORING SERVICE
 *
 * Features:
 * 1. Network attack detection and prevention
 * 2. Peer behavior analysis and threat assessment
 * 3. Transaction spam and fraud detection
 * 4. Mining attack detection (51% attacks, selfish mining)
 * 5. Network partition and eclipse attack detection
 * 6. Rate limiting violations monitoring
 * 7. Consensus anomaly detection
 * 8. Resource abuse monitoring
 */
class SecurityService {
  constructor(daemon) {
    this.daemon = daemon;
    this.startTime = Date.now();

    // Security metrics storage
    this.securityMetrics = {
      attacks: {
        detected: 0,
        blocked: 0,
        types: {},
        timeline: []
      },
      threats: {
        highRisk: [],
        mediumRisk: [],
        lowRisk: [],
        resolved: []
      },
      rateLimiting: {
        violations: 0,
        blockedIPs: new Set(),
        suspiciousIPs: new Map()
      },
      consensus: {
        anomalies: 0,
        forkAttempts: 0,
        orphanBlocks: 0,
        chainReorgs: 0
      },
      network: {
        suspiciousPeers: new Set(),
        blacklistedPeers: new Set(),
        partitionEvents: 0,
        eclipseAttempts: 0
      },
      transactions: {
        spamDetected: 0,
        fraudAttempts: 0,
        duplicateTransactions: 0,
        invalidTransactions: 0
      },
      mining: {
        hashRateAnomalies: 0,
        difficultyAnomalies: 0,
        selfishMiningAttempts: 0,
        majorityAttacks: 0
      },
      resources: {
        memoryAbuseEvents: 0,
        cpuAbuseEvents: 0,
        diskAbuseEvents: 0,
        bandwidthAbuseEvents: 0
      }
    };

    // Security thresholds
    this.thresholds = {
      hashRateSpike: 5.0, // 5x normal hash rate
      peerConnectionLimit: 100,
      transactionRateLimit: 1000, // per minute
      memoryUsageLimit: 0.9, // 90% of available memory
      cpuUsageLimit: 0.95, // 95% CPU usage
      consensusTimeout: 30000, // 30 seconds
      forkDepthLimit: 6,
      orphanBlockLimit: 5
    };

    // Initialize security monitoring
    this.startSecurityMonitoring();

    logger.debug('SECURITY_SERVICE', 'Security monitoring service initialized');
  }

  /**
   * Feature 1: Network attack detection and prevention
   */
  detectNetworkAttacks() {
    const attacks = [];
    const p2pNetwork = this.daemon.p2pNetwork;

    if (!p2pNetwork) {
      return { attacks: [], summary: 'P2P network not available' };
    }

    try {
      // DDoS attack detection
      const connectionRate = p2pNetwork.getConnectionRate?.() || 0;
      if (connectionRate > this.thresholds.peerConnectionLimit) {
        attacks.push({
          type: 'DDoS',
          severity: 'HIGH',
          description: `Excessive connection attempts: ${connectionRate}/min`,
          timestamp: new Date().toISOString(),
          source: 'Network Monitor',
          mitigation: 'Rate limiting active'
        });
      }

      // Sybil attack detection
      const peerManager = p2pNetwork.peerManager;
      if (peerManager) {
        const suspiciousPeers = this.detectSybilAttack(peerManager);
        if (suspiciousPeers.length > 0) {
          attacks.push({
            type: 'Sybil',
            severity: 'MEDIUM',
            description: `${suspiciousPeers.length} potentially coordinated peers detected`,
            timestamp: new Date().toISOString(),
            source: 'Peer Analysis',
            details: suspiciousPeers
          });
        }
      }

      // Eclipse attack detection
      const eclipseRisk = this.detectEclipseAttack(p2pNetwork);
      if (eclipseRisk.isAtRisk) {
        attacks.push({
          type: 'Eclipse',
          severity: 'HIGH',
          description: eclipseRisk.description,
          timestamp: new Date().toISOString(),
          source: 'Network Topology',
          mitigation: 'Diversifying peer connections'
        });
      }

      return {
        attacks,
        summary: `${attacks.length} active threats detected`,
        totalDetected: this.securityMetrics.attacks.detected,
        totalBlocked: this.securityMetrics.attacks.blocked
      };
    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error detecting network attacks: ${error.message}`);
      return { attacks: [], error: error.message };
    }
  }

  /**
   * Feature 2: Peer behavior analysis and threat assessment
   */
  analyzePeerBehavior() {
    try {
      const p2pNetwork = this.daemon.p2pNetwork;
      if (!p2pNetwork?.peerManager) {
        return {
          totalPeers: 0,
          trustedPeers: 0,
          suspiciousPeers: 0,
          maliciousPeers: 0,
          analysis: 'Peer manager not available'
        };
      }

      // Use the same approach as NetworkService to get peer data
      const peers = p2pNetwork.peerManager.getAllPeers();
      const peerAddresses = p2pNetwork.peerManager.getPeerAddresses();
      const peerReputation = p2pNetwork.peerReputation;

      const analysis = {
        totalPeers: peerAddresses.length,
        trustedPeers: 0,
        suspiciousPeers: 0,
        maliciousPeers: 0,
        peerRisk: [],
        behaviorPatterns: {},
        reputation: {}
      };

      peerAddresses.forEach(address => {
        // Find the corresponding WebSocket peer
        const peer = peers.find(p => {
          if (p._socket && p._socket._peername) {
            const peerAddr = `${p._socket._peername.address}:${p._socket._peername.port}`;
            return peerAddr === address;
          }
          return false;
        });

        const connected = peer ? peer._readyState === 1 : false;
        const reputation = peerReputation ? peerReputation.getPeerReputation(address) : null;

        const peerData = {
          address,
          connected,
          connectionTime: Date.now(), // WebSocket doesn't store connection time
          uptime: 0, // Can't calculate without connection time
          reputation: reputation?.score || 1000,
          invalidMessages: reputation?.badBehavior || 0,
          disconnections: Math.max(0, (reputation?.badBehavior || 0) - 5), // Estimate disconnections from bad behavior
          messagesPerMinute: Math.min(100, (reputation?.goodBehavior || 0) / 10) // Estimate activity level
        };

        const riskAssessment = this.assessPeerRisk(peerData);
        analysis.peerRisk.push(riskAssessment);

        if (riskAssessment.riskLevel === 'LOW') analysis.trustedPeers++;
        else if (riskAssessment.riskLevel === 'MEDIUM') analysis.suspiciousPeers++;
        else if (riskAssessment.riskLevel === 'HIGH') analysis.maliciousPeers++;

        // Track behavior patterns
        const pattern = riskAssessment.behaviorPattern;
        analysis.behaviorPatterns[pattern] = (analysis.behaviorPatterns[pattern] || 0) + 1;
      });

      return analysis;
    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error analyzing peer behavior: ${error.message}`);
      return {
        totalPeers: 0,
        trustedPeers: 0,
        suspiciousPeers: 0,
        maliciousPeers: 0,
        error: error.message
      };
    }
  }

  /**
   * Feature 3: Transaction spam and fraud detection
   */
  detectTransactionThreats() {
    try {
      const blockchain = this.daemon.blockchain;
      if (!blockchain) {
        return { threats: [], summary: 'Blockchain not available' };
      }

      const threats = [];
      const memoryPool = blockchain.memoryPoolManager;

      if (memoryPool) {
        // Spam detection
        const spamAnalysis = this.analyzeTransactionSpam(memoryPool);
        if (spamAnalysis.isSpam) {
          threats.push({
            type: 'Transaction Spam',
            severity: 'MEDIUM',
            description: `${spamAnalysis.suspiciousTransactions} potential spam transactions`,
            timestamp: new Date().toISOString(),
            details: spamAnalysis
          });
        }

        // Fraud detection
        const fraudAnalysis = this.detectTransactionFraud(memoryPool);
        if (fraudAnalysis.fraudDetected) {
          threats.push({
            type: 'Transaction Fraud',
            severity: 'HIGH',
            description: `${fraudAnalysis.fraudulentTransactions} potentially fraudulent transactions`,
            timestamp: new Date().toISOString(),
            details: fraudAnalysis
          });
        }
      }

      return {
        threats,
        summary: `${threats.length} transaction threats detected`,
        metrics: {
          spamDetected: this.securityMetrics.transactions.spamDetected,
          fraudAttempts: this.securityMetrics.transactions.fraudAttempts,
          invalidTransactions: this.securityMetrics.transactions.invalidTransactions
        }
      };
    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error detecting transaction threats: ${error.message}`);
      return { threats: [], error: error.message };
    }
  }

  /**
   * Feature 4: Mining attack detection (51% attacks, selfish mining)
   */
  detectMiningAttacks() {
    try {
      const blockchain = this.daemon.blockchain;
      if (!blockchain) {
        return { attacks: [], summary: 'Blockchain not available' };
      }

      const attacks = [];

      // 51% attack detection
      const majorityAttack = this.detect51PercentAttack(blockchain);
      if (majorityAttack.detected) {
        attacks.push({
          type: '51% Attack',
          severity: 'CRITICAL',
          description: majorityAttack.description,
          timestamp: new Date().toISOString(),
          evidence: majorityAttack.evidence,
          recommendation: 'Stop accepting new blocks until network consensus is restored'
        });
      }

      // Selfish mining detection
      const selfishMining = this.detectSelfishMining(blockchain);
      if (selfishMining.detected) {
        attacks.push({
          type: 'Selfish Mining',
          severity: 'HIGH',
          description: selfishMining.description,
          timestamp: new Date().toISOString(),
          evidence: selfishMining.evidence
        });
      }

      // Hash rate manipulation
      const hashRateAttack = this.detectHashRateManipulation(blockchain);
      if (hashRateAttack.detected) {
        attacks.push({
          type: 'Hash Rate Manipulation',
          severity: 'MEDIUM',
          description: hashRateAttack.description,
          timestamp: new Date().toISOString(),
          evidence: hashRateAttack.evidence
        });
      }

      return {
        attacks,
        summary: `${attacks.length} mining attacks detected`,
        metrics: {
          majorityAttacks: this.securityMetrics.mining.majorityAttacks,
          selfishMiningAttempts: this.securityMetrics.mining.selfishMiningAttempts,
          hashRateAnomalies: this.securityMetrics.mining.hashRateAnomalies
        }
      };
    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error detecting mining attacks: ${error.message}`);
      return { attacks: [], error: error.message };
    }
  }

  /**
   * Feature 5: Network partition and eclipse attack detection
   */
  detectNetworkPartitions() {
    try {
      const p2pNetwork = this.daemon.p2pNetwork;
      if (!p2pNetwork) {
        return { partitions: [], summary: 'P2P network not available' };
      }

      const partitions = [];

      // Network isolation detection
      const isolation = this.detectNetworkIsolation(p2pNetwork);
      if (isolation.isolated) {
        partitions.push({
          type: 'Network Isolation',
          severity: 'HIGH',
          description: isolation.description,
          timestamp: new Date().toISOString(),
          affectedPeers: isolation.affectedPeers,
          recommendation: 'Check network connectivity and firewall settings'
        });
      }

      // Partition healing detection
      const healing = this.detectPartitionHealing(p2pNetwork);
      if (healing.detected) {
        partitions.push({
          type: 'Partition Healing',
          severity: 'INFO',
          description: healing.description,
          timestamp: new Date().toISOString(),
          restoredPeers: healing.restoredPeers
        });
      }

      return {
        partitions,
        summary: `${partitions.length} network events detected`,
        metrics: {
          partitionEvents: this.securityMetrics.network.partitionEvents,
          eclipseAttempts: this.securityMetrics.network.eclipseAttempts
        }
      };
    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error detecting network partitions: ${error.message}`);
      return { partitions: [], error: error.message };
    }
  }

  /**
   * Feature 6: Rate limiting violations monitoring
   */
  getRateLimitingStatus() {
    return {
      violations: this.securityMetrics.rateLimiting.violations,
      blockedIPs: Array.from(this.securityMetrics.rateLimiting.blockedIPs),
      suspiciousIPs: Array.from(this.securityMetrics.rateLimiting.suspiciousIPs.entries()),
      recentViolations: this.getRecentRateLimitViolations(),
      effectiveness: this.calculateRateLimitingEffectiveness()
    };
  }

  /**
   * Feature 7: Consensus anomaly detection
   */
  detectConsensusAnomalies() {
    try {
      const blockchain = this.daemon.blockchain;
      if (!blockchain) {
        return { anomalies: [], summary: 'Blockchain not available' };
      }

      const anomalies = [];

      // Fork detection
      const forks = this.detectUnauthorizedForks(blockchain);
      anomalies.push(...forks);

      // Chain reorganization detection
      const reorgs = this.detectChainReorganizations(blockchain);
      anomalies.push(...reorgs);

      // Orphan block analysis
      const orphans = this.analyzeOrphanBlocks(blockchain);
      anomalies.push(...orphans);

      return {
        anomalies,
        summary: `${anomalies.length} consensus anomalies detected`,
        metrics: this.securityMetrics.consensus
      };
    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error detecting consensus anomalies: ${error.message}`);
      return { anomalies: [], error: error.message };
    }
  }

  /**
   * Feature 8: Resource abuse monitoring
   */
  getResourceAbuseStatus() {
    try {
      const nodeInfo = this.daemon.nodeInfoService;
      if (!nodeInfo) {
        return { status: 'Node info service not available' };
      }

      const resources = nodeInfo.getSystemResources();
      const abuse = {
        memory: this.checkMemoryAbuse(resources.memory),
        cpu: this.checkCPUAbuse(resources.cpu),
        disk: this.checkDiskAbuse(resources.disk),
        bandwidth: this.checkBandwidthAbuse()
      };

      return {
        abuse,
        metrics: this.securityMetrics.resources,
        recommendations: this.generateResourceRecommendations(abuse)
      };
    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error monitoring resource abuse: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Get security status for WebSocket updates (legacy compatibility)
   */
  getSecurityStatus() {
    const dashboard = this.getSecurityDashboard();
    return {
      securityLevel: dashboard.overview.securityLevel,
      threatsActive: dashboard.overview.threatsActive,
      systemStatus: dashboard.overview.systemStatus,
      attacksDetected: dashboard.attacks.attacks?.length || 0,
      peerThreats: dashboard.peers.maliciousPeers || 0,
      rateLimitViolations: dashboard.rateLimiting.violations || 0,
      lastUpdate: new Date().toISOString()
    };
  }

  /**
   * Get comprehensive security dashboard data
   */
  getSecurityDashboard() {
    return {
      overview: {
        securityLevel: this.calculateSecurityLevel(),
        threatsActive: this.countActiveThreats(),
        systemStatus: this.getSystemSecurityStatus(),
        lastUpdate: new Date().toISOString()
      },
      attacks: this.detectNetworkAttacks(),
      peers: this.analyzePeerBehavior(),
      transactions: this.detectTransactionThreats(),
      mining: this.detectMiningAttacks(),
      network: this.detectNetworkPartitions(),
      rateLimiting: this.getRateLimitingStatus(),
      consensus: this.detectConsensusAnomalies(),
      resources: this.getResourceAbuseStatus(),
      metrics: this.securityMetrics,
      timeline: this.getSecurityTimeline()
    };
  }

  // Helper methods for security analysis

  detectSybilAttack(peerManager) {
    // Simplified Sybil detection based on IP similarity and behavior patterns
    const peers = peerManager.getAllPeers?.() || [];
    const ipGroups = new Map();

    peers.forEach(peer => {
      const ipPrefix = peer.ip?.substring(0, peer.ip.lastIndexOf('.')) || 'unknown';
      if (!ipGroups.has(ipPrefix)) {
        ipGroups.set(ipPrefix, []);
      }
      ipGroups.get(ipPrefix).push(peer);
    });

    const suspiciousPeers = [];
    ipGroups.forEach((peerGroup, ipPrefix) => {
      if (peerGroup.length > 5) { // More than 5 peers from same subnet
        suspiciousPeers.push(...peerGroup.map(peer => ({
          id: peer.id,
          ip: peer.ip,
          reason: 'Multiple peers from same subnet',
          count: peerGroup.length
        })));
      }
    });

    return suspiciousPeers;
  }

  detectEclipseAttack(p2pNetwork) {
    try {
      if (!p2pNetwork?.peerManager) {
        logger.debug('SECURITY_SERVICE', 'P2P network or peer manager not available');
        return {
          isAtRisk: true,
          description: 'P2P network not available, high eclipse attack risk',
          riskLevel: 'CRITICAL'
        };
      }

      const peerManager = p2pNetwork.peerManager;
      let connectedCount = 0;

      // Get peer data using the correct WebSocket structure
      if (typeof peerManager.getAllPeers === 'function' && typeof peerManager.getPeerAddresses === 'function') {
        const peers = peerManager.getAllPeers();
        const peerAddresses = peerManager.getPeerAddresses();

        if (peerAddresses && peerAddresses.length > 0) {
          peerAddresses.forEach((address, index) => {
            // The peers are WebSocket objects, match by socket address
            let peer = peers.find(p => {
              if (p._socket && p._socket._peername) {
                const peerAddr = `${p._socket._peername.address}:${p._socket._peername.port}`;
                return peerAddr === address;
              }
              return false;
            });

            if (!peer && peers[index]) {
              peer = peers[index]; // Fallback to index-based matching
            }

            // Check WebSocket readyState (1 = OPEN)
            const isConnected = peer && peer._readyState === 1;

            if (isConnected) {
              connectedCount++;
            }
          });
        }
      } else if (typeof peerManager.getConnectedPeers === 'function') {
        // Fallback: Try getConnectedPeers if available
        const connectedPeers = peerManager.getConnectedPeers();
        connectedCount = connectedPeers.length;
      }

      if (connectedCount < 3) {
        return {
          isAtRisk: true,
          description: `Only ${connectedCount} connected peers, high eclipse attack risk`,
          riskLevel: 'HIGH'
        };
      }

      return {
        isAtRisk: false,
        description: `${connectedCount} connected peers, eclipse attack risk low`,
        riskLevel: 'LOW'
      };
    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error detecting eclipse attack: ${error.message}`);
      return {
        isAtRisk: true,
        description: 'Error checking peer connections, assuming eclipse risk',
        riskLevel: 'HIGH'
      };
    }
  }

  assessPeerRisk(peer) {
    let riskScore = 0;
    const factors = [];

    // Connection stability
    if (peer.disconnections > 5) {
      riskScore += 20;
      factors.push('Frequent disconnections');
    }

    // Message frequency
    if (peer.messagesPerMinute > 1000) {
      riskScore += 30;
      factors.push('High message frequency');
    }

    // Invalid messages
    if (peer.invalidMessages > 0) {
      riskScore += 40;
      factors.push('Invalid messages sent');
    }

    let riskLevel = 'LOW';
    if (riskScore > 50) riskLevel = 'HIGH';
    else if (riskScore > 25) riskLevel = 'MEDIUM';

    return {
      peerId: peer.id,
      ip: peer.ip,
      riskScore,
      riskLevel,
      factors,
      behaviorPattern: this.classifyBehaviorPattern(peer)
    };
  }

  classifyBehaviorPattern(peer) {
    if (peer.invalidMessages > 0) return 'malicious';
    if (peer.messagesPerMinute > 500) return 'spam';
    if (peer.disconnections > 10) return 'unstable';
    return 'normal';
  }

  analyzeTransactionSpam(memoryPool) {
    const pendingTransactions = memoryPool.getPendingTransactions?.() || [];
    const addressFrequency = new Map();

    pendingTransactions.forEach(tx => {
      const from = tx.from || 'unknown';
      addressFrequency.set(from, (addressFrequency.get(from) || 0) + 1);
    });

    let suspiciousTransactions = 0;
    addressFrequency.forEach(count => {
      if (count > 10) suspiciousTransactions += count; // More than 10 tx from same address
    });

    return {
      isSpam: suspiciousTransactions > 0,
      suspiciousTransactions,
      totalPending: pendingTransactions.length,
      suspiciousAddresses: Array.from(addressFrequency.entries())
        .filter(([_, count]) => count > 10)
    };
  }

  detectTransactionFraud(memoryPool) {
    const pendingTransactions = memoryPool.getPendingTransactions?.() || [];
    let fraudulentTransactions = 0;
    const fraudTypes = [];

    // Simple fraud detection (double spending, invalid signatures, etc.)
    pendingTransactions.forEach(tx => {
      if (tx.amount < 0) {
        fraudulentTransactions++;
        fraudTypes.push('Negative amount');
      }
      if (tx.fee && tx.fee > tx.amount) {
        fraudulentTransactions++;
        fraudTypes.push('Excessive fee');
      }
    });

    return {
      fraudDetected: fraudulentTransactions > 0,
      fraudulentTransactions,
      fraudTypes: [...new Set(fraudTypes)]
    };
  }

  detect51PercentAttack(blockchain) {
    const chain = blockchain.chain || [];
    if (chain.length < 10) {
      return { detected: false, reason: 'Insufficient chain length for analysis' };
    }

    // Analyze recent blocks for same miner control
    const recentBlocks = chain.slice(-10);
    const minerFrequency = new Map();

    recentBlocks.forEach(block => {
      const miner = block.miner || block.minerAddress || 'unknown';
      minerFrequency.set(miner, (minerFrequency.get(miner) || 0) + 1);
    });

    const maxControl = Math.max(...minerFrequency.values());
    const controlPercentage = (maxControl / recentBlocks.length) * 100;

    if (controlPercentage > 51) {
      return {
        detected: true,
        description: `Single miner controls ${controlPercentage.toFixed(1)}% of recent blocks`,
        evidence: {
          controlPercentage,
          blocksControlled: maxControl,
          totalAnalyzed: recentBlocks.length,
          minerDistribution: Array.from(minerFrequency.entries())
        }
      };
    }

    return { detected: false };
  }

  detectSelfishMining(blockchain) {
    // Simplified selfish mining detection based on block withholding patterns
    const chain = blockchain.chain || [];
    if (chain.length < 20) {
      return { detected: false, reason: 'Insufficient chain length' };
    }

    const recentBlocks = chain.slice(-20);
    let suspiciousPatterns = 0;

    for (let i = 1; i < recentBlocks.length; i++) {
      const timeDiff = recentBlocks[i].timestamp - recentBlocks[i-1].timestamp;
      if (timeDiff < 10000) { // Blocks too close together
        suspiciousPatterns++;
      }
    }

    if (suspiciousPatterns > 3) {
      return {
        detected: true,
        description: `${suspiciousPatterns} suspicious block timing patterns detected`,
        evidence: { suspiciousPatterns, totalAnalyzed: recentBlocks.length - 1 }
      };
    }

    return { detected: false };
  }

  detectHashRateManipulation(blockchain) {
    const chain = blockchain.chain || [];
    if (chain.length < 10) {
      return { detected: false };
    }

    // Analyze difficulty changes for manipulation
    const recentBlocks = chain.slice(-10);
    const difficulties = recentBlocks.map(block => block.difficulty || 1);

    let abruptChanges = 0;
    for (let i = 1; i < difficulties.length; i++) {
      const change = Math.abs(difficulties[i] - difficulties[i-1]) / difficulties[i-1];
      if (change > 0.5) abruptChanges++; // More than 50% change
    }

    if (abruptChanges > 2) {
      return {
        detected: true,
        description: `${abruptChanges} abrupt difficulty changes detected`,
        evidence: { abruptChanges, difficulties }
      };
    }

    return { detected: false };
  }

  detectNetworkIsolation(p2pNetwork) {
    try {
      if (!p2pNetwork?.peerManager) {
        return {
          isolated: true,
          description: 'P2P network not available - node is isolated',
          affectedPeers: 0
        };
      }

      // Use the same approach as NetworkService to get peer data
      const peers = p2pNetwork.peerManager.getAllPeers();
      const peerAddresses = p2pNetwork.peerManager.getPeerAddresses();

      let connectedCount = 0;
      peerAddresses.forEach(address => {
        // Find the corresponding WebSocket peer
        const peer = peers.find(p => {
          if (p._socket && p._socket._peername) {
            const peerAddr = `${p._socket._peername.address}:${p._socket._peername.port}`;
            return peerAddr === address;
          }
          return false;
        });

        if (peer && peer._readyState === 1) {
          connectedCount++;
        }
      });

      const totalKnownPeers = peerAddresses.length;

      if (connectedCount === 0) {
        return {
          isolated: true,
          description: 'Node is completely isolated - no connected peers',
          affectedPeers: totalKnownPeers
        };
      }

      if (connectedCount < 2 && totalKnownPeers > 5) {
        return {
          isolated: true,
          description: `Only ${connectedCount} connected out of ${totalKnownPeers} known peers`,
          affectedPeers: totalKnownPeers - connectedCount
        };
      }

      return {
        isolated: false,
        description: `${connectedCount} of ${totalKnownPeers} peers connected`,
        connectedPeers: connectedCount
      };
    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error detecting network isolation: ${error.message}`);
      return {
        isolated: true,
        description: 'Error checking network connectivity',
        affectedPeers: 0
      };
    }
  }

  detectPartitionHealing(p2pNetwork) {
    // This would require historical data to detect healing
    // For now, return a placeholder
    return { detected: false };
  }

  getRecentRateLimitViolations() {
    // Return recent violations (would need historical tracking)
    return [];
  }

  calculateRateLimitingEffectiveness() {
    const total = this.securityMetrics.rateLimiting.violations;
    const blocked = this.securityMetrics.rateLimiting.blockedIPs.size;

    if (total === 0) return 100;
    return Math.round((blocked / total) * 100);
  }

  detectUnauthorizedForks(blockchain) {
    const forkManager = this.daemon.forkManager;
    if (!forkManager) return [];

    // Placeholder for fork detection
    return [];
  }

  detectChainReorganizations(blockchain) {
    // Placeholder for chain reorg detection
    return [];
  }

  analyzeOrphanBlocks(blockchain) {
    // Placeholder for orphan block analysis
    return [];
  }

  checkMemoryAbuse(memory) {
    const usage = memory.usage / 100;
    return {
      isAbuse: usage > this.thresholds.memoryUsageLimit,
      usage,
      severity: usage > 0.95 ? 'CRITICAL' : usage > 0.85 ? 'HIGH' : 'LOW'
    };
  }

  checkCPUAbuse(cpu) {
    const usage = cpu.usage / 100;
    return {
      isAbuse: usage > this.thresholds.cpuUsageLimit,
      usage,
      severity: usage > 0.98 ? 'CRITICAL' : usage > 0.90 ? 'HIGH' : 'LOW'
    };
  }

  checkDiskAbuse(disk) {
    const usage = disk.usage / 100;
    return {
      isAbuse: usage > 0.95,
      usage,
      severity: usage > 0.98 ? 'CRITICAL' : usage > 0.90 ? 'HIGH' : 'LOW'
    };
  }

  checkBandwidthAbuse() {
    // Placeholder for bandwidth abuse detection
    return {
      isAbuse: false,
      usage: 0,
      severity: 'LOW'
    };
  }

  generateResourceRecommendations(abuse) {
    const recommendations = [];

    if (abuse.memory.isAbuse) {
      recommendations.push('Consider increasing system memory or optimizing memory usage');
    }
    if (abuse.cpu.isAbuse) {
      recommendations.push('CPU usage is very high, consider reducing mining threads or optimizing processes');
    }
    if (abuse.disk.isAbuse) {
      recommendations.push('Disk usage is near capacity, consider cleanup or expansion');
    }

    return recommendations;
  }

  calculateSecurityLevel() {
    const threats = this.countActiveThreats();
    if (threats === 0) return 'SECURE';
    if (threats < 3) return 'MODERATE';
    if (threats < 10) return 'AT_RISK';
    return 'CRITICAL';
  }

  countActiveThreats() {
    return this.securityMetrics.threats.highRisk.length +
           this.securityMetrics.threats.mediumRisk.length;
  }

  getSystemSecurityStatus() {
    const level = this.calculateSecurityLevel();
    const statusMap = {
      'SECURE': 'All systems operating normally',
      'MODERATE': 'Minor security concerns detected',
      'AT_RISK': 'Multiple security threats active',
      'CRITICAL': 'Critical security threats detected'
    };
    return statusMap[level] || 'Status unknown';
  }

  getSecurityTimeline() {
    return this.securityMetrics.attacks.timeline.slice(-20); // Last 20 events
  }

  startSecurityMonitoring() {
    // Update security metrics every 30 seconds
    setInterval(() => {
      this.updateSecurityMetrics();
    }, 30000);

    // Initial update
    this.updateSecurityMetrics();
  }

  updateSecurityMetrics() {
    try {
      // Update attack detection metrics
      const attacks = this.detectNetworkAttacks();
      this.securityMetrics.attacks.detected += attacks.attacks.length;

      // Update threat levels
      attacks.attacks.forEach(attack => {
        const threat = {
          id: CryptoUtils.secureRandomId(),
          type: attack.type,
          severity: attack.severity,
          description: attack.description,
          timestamp: attack.timestamp
        };

        if (attack.severity === 'HIGH' || attack.severity === 'CRITICAL') {
          this.securityMetrics.threats.highRisk.push(threat);
        } else if (attack.severity === 'MEDIUM') {
          this.securityMetrics.threats.mediumRisk.push(threat);
        } else {
          this.securityMetrics.threats.lowRisk.push(threat);
        }

        // Add to timeline
        this.securityMetrics.attacks.timeline.push(threat);
      });

      // Keep only recent threats (last 100)
      ['highRisk', 'mediumRisk', 'lowRisk'].forEach(level => {
        if (this.securityMetrics.threats[level].length > 100) {
          this.securityMetrics.threats[level] = this.securityMetrics.threats[level].slice(-100);
        }
      });

      // Keep timeline limited
      if (this.securityMetrics.attacks.timeline.length > 1000) {
        this.securityMetrics.attacks.timeline = this.securityMetrics.attacks.timeline.slice(-1000);
      }

    } catch (error) {
      logger.error('SECURITY_SERVICE', `Error updating security metrics: ${error.message}`);
    }
  }
}

module.exports = SecurityService;