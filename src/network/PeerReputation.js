const fs = require('fs');
const path = require('path');

const logger = require('../utils/logger');

/**
 * CRITICAL: Enhanced peer reputation system with manipulation protection
 */
class PeerReputation {
  /**
   *
   * @param dataDir
   */
  constructor(dataDir = './data') {
    this.peerReputation = new Map(); // Map<peerAddress, reputationData>
    this.peerReputationFile = path.join(dataDir, 'peer-reputation.json');
    this.reputationConfig = {
      maxScore: 1000,
      minScore: -1000,
      initialScore: 100,
      scoreDecayRate: 0.95, // Score decays by 5% per day
      manipulationThreshold: 5, // Suspicious reputation changes
      cooldownPeriod: 60000, // 1 minute cooldown between score changes
      maxScoreChange: 100, // Maximum score change per action
      goodBehaviorBonus: 10, // Bonus for good behavior
      badBehaviorPenalty: 20, // Penalty for bad behavior
      banThreshold: -500, // Score threshold for banning
      banDuration: 24 * 60 * 60 * 1000, // 24 hours ban duration
      suspiciousPatterns: new Set(), // Track suspicious reputation patterns
      reputationHistory: new Map(), // Track reputation change history
      lastScoreChanges: new Map(), // Track last score change time per peer
    };

    // Load existing reputation data
    this.loadPeerReputation();

    // Start reputation monitoring
    this.startReputationMonitoring();
  }

  /**
   * CRITICAL: Start reputation monitoring to detect manipulation
   */
  startReputationMonitoring() {
    setInterval(() => {
      this.detectReputationManipulation();
      this.cleanupOldData();
    }, 30000); // Check every 30 seconds
  }

  /**
   * CRITICAL: Detect reputation manipulation patterns
   */
  detectReputationManipulation() {
    try {
      const suspiciousPeers = [];

      for (const [peerAddress, reputationData] of this.peerReputation.entries()) {
        const history = this.reputationConfig.reputationHistory.get(peerAddress) || [];

        if (history.length >= this.reputationConfig.manipulationThreshold) {
          // Check for rapid score changes
          const recentChanges = history.slice(-this.reputationConfig.manipulationThreshold);
          const scoreChanges = recentChanges.map(change => change.scoreChange);

          // Detect suspicious patterns
          const rapidChanges = scoreChanges.filter(change => Math.abs(change) > this.reputationConfig.maxScoreChange);
          const alternatingChanges = this.detectAlternatingPattern(scoreChanges);
          const coordinatedChanges = this.detectCoordinatedChanges(peerAddress, recentChanges);

          if (rapidChanges.length > 0 || alternatingChanges || coordinatedChanges) {
            suspiciousPeers.push({
              address: peerAddress,
              patterns: {
                rapidChanges: rapidChanges.length,
                alternatingChanges,
                coordinatedChanges,
              },
              recentHistory: recentChanges,
            });

            // Flag peer as suspicious
            this.reputationConfig.suspiciousPatterns.add(peerAddress);
            logger.warn('PEER_REPUTATION', `⚠️  Suspicious reputation pattern detected for peer ${peerAddress}`);
          }
        }
      }

      if (suspiciousPeers.length > 0) {
        logger.warn(
          'PEER_REPUTATION',
          `🚨 Detected ${suspiciousPeers.length} peers with suspicious reputation patterns`
        );
      }
    } catch (error) {
      logger.error('PEER_REPUTATION', `Reputation manipulation detection failed: ${error.message}`);
    }
  }

  /**
   * CRITICAL: Detect alternating positive/negative score changes
   * @param scoreChanges
   */
  detectAlternatingPattern(scoreChanges) {
    if (scoreChanges.length < 3) return false;

    let alternatingCount = 0;
    for (let i = 1; i < scoreChanges.length; i++) {
      const prev = scoreChanges[i - 1];
      const curr = scoreChanges[i];

      if ((prev > 0 && curr < 0) || (prev < 0 && curr > 0)) {
        alternatingCount++;
      }
    }

    return alternatingCount >= scoreChanges.length * 0.7; // 70% alternating pattern
  }

  /**
   * CRITICAL: Detect coordinated reputation changes
   * @param peerAddress
   * @param recentChanges
   */
  detectCoordinatedChanges(peerAddress, recentChanges) {
    // Check if multiple peers are changing this peer's reputation simultaneously
    const recentTime = Date.now() - 60000; // Last minute
    const simultaneousChanges = recentChanges.filter(change => change.timestamp > recentTime);

    return simultaneousChanges.length > 3; // More than 3 changes in 1 minute
  }

  /**
   * Load peer reputation from file
   */
  loadPeerReputation() {
    try {
      if (fs.existsSync(this.peerReputationFile)) {
        const data = fs.readFileSync(this.peerReputationFile, 'utf8');
        const parsed = JSON.parse(data);

        // Restore reputation data
        if (parsed.peerReputation) {
          for (const [address, repData] of Object.entries(parsed.peerReputation)) {
            this.peerReputation.set(address, repData);
          }
        }

        // Restore reputation history
        if (parsed.reputationHistory) {
          for (const [address, history] of Object.entries(parsed.reputationHistory)) {
            this.reputationConfig.reputationHistory.set(address, history);
          }
        }

        logger.info('PEER_REPUTATION', `Loaded reputation data for ${this.peerReputation.size} peers`);
      }
    } catch (error) {
      logger.error('PEER_REPUTATION', `Failed to load reputation data: ${error.message}`);
    }
  }

  /**
   * Save peer reputation to file
   */
  savePeerReputation() {
    try {
      const data = {
        peerReputation: Object.fromEntries(this.peerReputation),
        reputationHistory: Object.fromEntries(this.reputationConfig.reputationHistory),
        timestamp: Date.now(),
      };

      fs.writeFileSync(this.peerReputationFile, JSON.stringify(data, null, 2));
      logger.debug('PEER_REPUTATION', 'Reputation data saved to file');
    } catch (error) {
      logger.error('PEER_REPUTATION', `Failed to save reputation data: ${error.message}`);
    }
  }

  /**
   * Get reputation data for a specific peer
   * @param peerAddress
   */
  getReputationData(peerAddress) {
    return this.peerReputation.get(peerAddress) || null;
  }

  /**
   * Update peer reputation based on behavior
   * @param peerAddress
   * @param behavior
   * @param details
   */
  updatePeerReputation(peerAddress, behavior, details = {}) {
    let reputationData = this.getReputationData(peerAddress);
    const now = Date.now();

    // If no reputation data exists, create new entry
    if (!reputationData) {
      reputationData = {
        score: this.reputationConfig.initialScore,
        lastUpdated: now,
        changeCount: 0,
        positiveChanges: 0,
        negativeChanges: 0,
        behaviors: [],
        bannedUntil: null,
        banReason: null,
        lastScoreChange: now,
      };
      // Add to reputation map
      this.peerReputation.set(peerAddress, reputationData);
    }

    // Apply score change based on behavior
    let scoreChange = 0;
    let behaviorType = 'neutral';

    switch (behavior) {
      case 'connect':
        scoreChange = this.reputationConfig.goodBehaviorBonus;
        behaviorType = 'good';
        break;
      case 'disconnect':
        scoreChange = -5; // Small penalty for disconnection
        behaviorType = 'neutral';
        break;
      case 'message_received':
        scoreChange = 1; // Small bonus for communication
        behaviorType = 'good';
        break;
      case 'good_behavior':
        scoreChange = this.reputationConfig.goodBehaviorBonus;
        behaviorType = 'good';
        break;
      case 'bad_behavior':
        scoreChange = -this.reputationConfig.badBehaviorPenalty;
        behaviorType = 'bad';
        break;
      case 'invalid_message':
        scoreChange = -20; // Penalty for invalid messages
        behaviorType = 'bad';
        break;
      default:
        scoreChange = 0;
        behaviorType = 'neutral';
    }

    // Update score
    reputationData.score = Math.max(
      this.reputationConfig.minScore,
      Math.min(this.reputationConfig.maxScore, reputationData.score + scoreChange)
    );

    // Record behavior
    reputationData.behaviors.push({
      type: behaviorType,
      behavior,
      scoreChange,
      details,
      timestamp: now,
    });

    // Keep only last 100 behaviors to prevent memory bloat
    if (reputationData.behaviors.length > 100) {
      reputationData.behaviors = reputationData.behaviors.slice(-100);
    }

    reputationData.lastUpdated = now;

    // Check if peer should be banned
    if (reputationData.score <= this.reputationConfig.banThreshold && !reputationData.bannedUntil) {
      reputationData.bannedUntil = now + this.reputationConfig.banDuration;
      logger.warn('PEER_REPUTATION', `Peer ${peerAddress} banned due to low reputation (${reputationData.score})`);
    }

    // Log significant reputation changes
    if (Math.abs(scoreChange) >= 20) {
      logger.info(
        'PEER_REPUTATION',
        `Peer ${peerAddress} reputation ${scoreChange > 0 ? '+' : ''}${scoreChange} (${behavior}) - New score: ${reputationData.score}`
      );
    }

    return reputationData;
  }

  /**
   * Check if peer is banned
   * @param peerAddress
   */
  isPeerBanned(peerAddress) {
    const reputation = this.peerReputation.get(peerAddress);
    if (!reputation) return false;

    return reputation.score <= this.reputationConfig.minScore;
  }

  /**
   * Get peer score
   * @param peerAddress
   */
  getPeerScore(peerAddress) {
    const reputation = this.peerReputation.get(peerAddress);
    return reputation ? reputation.score : this.reputationConfig.initialScore;
  }

  /**
   * Get peer reputation
   * @param peerAddress
   */
  getPeerReputation(peerAddress) {
    return (
      this.peerReputation.get(peerAddress) || {
        score: this.reputationConfig.initialScore,
        lastUpdated: Date.now(),
        changeCount: 0,
        positiveChanges: 0,
        negativeChanges: 0,
      }
    );
  }

  /**
   * Unban peer
   * @param peerAddress
   */
  unbanPeer(peerAddress) {
    const reputation = this.peerReputation.get(peerAddress);
    if (reputation) {
      reputation.score = this.reputationConfig.initialScore;
      reputation.lastUpdated = Date.now();
      this.savePeerReputation();
      logger.info('PEER_REPUTATION', `Peer ${peerAddress} unbanned`);
    }
  }

  /**
   * Ban peer
   * @param peerAddress
   * @param reason
   */
  banPeer(peerAddress, reason = '') {
    const reputation = this.peerReputation.get(peerAddress) || {
      score: this.reputationConfig.initialScore,
      lastUpdated: Date.now(),
      changeCount: 0,
      positiveChanges: 0,
      negativeChanges: 0,
    };

    reputation.score = this.reputationConfig.minScore;
    reputation.lastUpdated = Date.now();
    reputation.banReason = reason;

    this.peerReputation.set(peerAddress, reputation);
    this.savePeerReputation();

    logger.warn('PEER_REPUTATION', `Peer ${peerAddress} banned: ${reason}`);
  }

  /**
   * Apply score decay over time
   */
  applyScoreDecay() {
    const now = Date.now();
    const decayInterval = 24 * 60 * 60 * 1000; // 24 hours

    for (const [peerAddress, reputation] of this.peerReputation.entries()) {
      const timeSinceLastUpdate = now - reputation.lastUpdated;

      if (timeSinceLastUpdate > decayInterval) {
        // Apply decay
        reputation.score = Math.max(
          this.reputationConfig.minScore,
          reputation.score * this.reputationConfig.scoreDecayRate
        );
        reputation.lastUpdated = now;
      }
    }

    this.savePeerReputation();
  }

  /**
   * Get reputation statistics
   */
  getReputationStats() {
    const stats = {
      totalPeers: this.peerReputation.size,
      bannedPeers: 0,
      goodPeers: 0,
      averageScore: 0,
      scoreDistribution: {
        excellent: 0, // 800-1000
        good: 0, // 600-799
        average: 0, // 400-599
        poor: 0, // 200-399
        bad: 0, // 0-199
      },
    };

    let totalScore = 0;

    for (const reputation of this.peerReputation.values()) {
      totalScore += reputation.score;

      if (reputation.score <= this.reputationConfig.minScore) {
        stats.bannedPeers++;
      } else if (reputation.score >= 600) {
        stats.goodPeers++;
      }

      // Categorize by score
      if (reputation.score >= 800) stats.scoreDistribution.excellent++;
      else if (reputation.score >= 600) stats.scoreDistribution.good++;
      else if (reputation.score >= 400) stats.scoreDistribution.average++;
      else if (reputation.score >= 200) stats.scoreDistribution.poor++;
      else stats.scoreDistribution.bad++;
    }

    stats.averageScore = stats.totalPeers > 0 ? (totalScore / stats.totalPeers).toFixed(2) : 0;

    return stats;
  }

  /**
   * Cleanup old data
   */
  cleanupOldData() {
    try {
      const cutoffTime = Date.now() - 30 * 24 * 60 * 60 * 1000; // 30 days

      // Cleanup old reputation history
      for (const [peerAddress, history] of this.reputationConfig.reputationHistory.entries()) {
        const filteredHistory = history.filter(record => record.timestamp > cutoffTime);
        if (filteredHistory.length === 0) {
          this.reputationConfig.reputationHistory.delete(peerAddress);
        } else {
          this.reputationConfig.reputationHistory.set(peerAddress, filteredHistory);
        }
      }

      // Cleanup old last score changes
      for (const [peerAddress, lastChange] of this.reputationConfig.lastScoreChanges.entries()) {
        if (lastChange < cutoffTime) {
          this.reputationConfig.lastScoreChanges.delete(peerAddress);
        }
      }
    } catch (error) {
      logger.error('PEER_REPUTATION', `Data cleanup failed: ${error.message}`);
    }
  }

  /**
   * Reset peer reputation
   * @param peerAddress
   */
  resetPeerReputation(peerAddress) {
    this.peerReputation.delete(peerAddress);
    this.reputationConfig.reputationHistory.delete(peerAddress);
    this.reputationConfig.lastScoreChanges.delete(peerAddress);
    this.reputationConfig.suspiciousPatterns.delete(peerAddress);

    this.savePeerReputation();
    logger.info('PEER_REPUTATION', `Reputation reset for peer ${peerAddress}`);
  }

  /**
   * Get banned peers
   */
  getBannedPeers() {
    const bannedPeers = [];

    for (const [peerAddress, reputation] of this.peerReputation.entries()) {
      if (reputation.score <= this.reputationConfig.minScore) {
        bannedPeers.push({
          address: peerAddress,
          score: reputation.score,
          banReason: reputation.banReason || 'Low reputation score',
          lastUpdated: reputation.lastUpdated,
        });
      }
    }

    return bannedPeers;
  }

  /**
   * CRITICAL: Get enhanced reputation status
   */
  getReputationStatus() {
    const totalPeers = this.peerReputation.size;
    const suspiciousPeers = this.reputationConfig.suspiciousPatterns.size;
    const averageScore =
      totalPeers > 0
        ? Array.from(this.peerReputation.values()).reduce((sum, rep) => sum + rep.score, 0) / totalPeers
        : 0;

    return {
      totalPeers,
      suspiciousPeers,
      averageScore: averageScore.toFixed(2),
      reputationRange: {
        min: this.reputationConfig.minScore,
        max: this.reputationConfig.maxScore,
      },
      manipulationThreshold: this.reputationConfig.manipulationThreshold,
      cooldownPeriod: this.reputationConfig.cooldownPeriod,
      maxScoreChange: this.reputationConfig.maxScoreChange,
      suspiciousPatterns: Array.from(this.reputationConfig.suspiciousPatterns),
    };
  }
}

module.exports = PeerReputation;
