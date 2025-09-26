const logger = require('../../utils/logger');
const { fromAtomicUnits } = require('../../utils/atomicUnits');

/**
 * Mining Monitoring Service
 * Implements features 28-33: Mining information and statistics
 */
class MiningService {
  constructor(daemon) {
    this.daemon = daemon;
    this.blockchain = daemon.blockchain;
    this.p2pNetwork = daemon.p2pNetwork;

    // Mining statistics tracking
    this.miningStats = {
      startTime: Date.now(),
      blocksFound: 0,
      totalHashRate: 0,
      averageBlockTime: 0,
      lastBlockTime: 0,
      difficultyHistory: [],
      rewardsEarned: 0
    };

    logger.debug('MINING_SERVICE', 'Mining monitoring service initialized');
  }

  /**
   * Feature 28: Mining status and hashrate monitoring
   */
  getMiningStatus() {
    try {
      if (!this.blockchain) {
        return { enabled: false, error: 'Blockchain not available' };
      }

      const latestBlock = this.blockchain.getLatestBlock();
      const chain = this.blockchain.chain || [];
      const recentBlocks = chain.slice(-10); // Last 10 blocks for analysis

      // Calculate network hash rate estimation
      const networkHashRate = this.estimateNetworkHashRate(recentBlocks);

      // Get current difficulty
      const currentDifficulty = latestBlock?.difficulty || 0;

      // Calculate average block time
      const averageBlockTime = this.calculateAverageBlockTime(recentBlocks);

      // Get mining algorithm info
      const algorithm = latestBlock?.algorithm || 'Velora';

      // Check if node is currently mining (this would need to be implemented based on mining setup)
      const isMining = false; // Placeholder - would check actual mining status

      return {
        enabled: true,
        status: {
          isMining: isMining,
          algorithm: algorithm,
          difficulty: currentDifficulty,
          networkHashRate: networkHashRate,
          averageBlockTime: averageBlockTime,
          lastBlockTime: latestBlock?.timestamp || 0,
          timeSinceLastBlock: latestBlock ? Date.now() - latestBlock.timestamp : 0
        },
        network: {
          totalBlocks: chain.length,
          totalWork: this.calculateTotalWork(chain),
          estimatedMiners: Math.max(1, Math.floor(networkHashRate / 1000000)) // Rough estimate
        },
        performance: {
          blocksPerHour: this.calculateBlocksPerHour(recentBlocks),
          hashRateEfficiency: this.calculateHashRateEfficiency(currentDifficulty, averageBlockTime),
          networkHealth: this.assessNetworkHealth(recentBlocks)
        },
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('MINING_SERVICE', `Error getting mining status: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Feature 29: Difficulty adjustment tracking and predictions
   */
  getDifficultyAnalysis() {
    try {
      if (!this.blockchain || !this.blockchain.chain) {
        return { error: 'Blockchain not available' };
      }

      const chain = this.blockchain.chain;
      const latestBlock = chain[chain.length - 1];
      const currentDifficulty = latestBlock?.difficulty || 0;

      // Get difficulty adjustment parameters
      const difficultyBlocks = this.blockchain.config?.blockchain?.difficultyBlocks || 2016;
      const targetBlockTime = this.blockchain.config?.blockchain?.blockTime || 15000; // 15 seconds default

      // Calculate blocks until next adjustment
      const blocksSinceAdjustment = chain.length % difficultyBlocks;
      const blocksUntilAdjustment = difficultyBlocks - blocksSinceAdjustment;

      // Get recent difficulty history
      const difficultyHistory = [];
      for (let i = Math.max(0, chain.length - 100); i < chain.length; i += Math.max(1, Math.floor(difficultyBlocks / 10))) {
        if (chain[i]) {
          difficultyHistory.push({
            blockIndex: i,
            difficulty: chain[i].difficulty,
            timestamp: chain[i].timestamp,
            algorithm: chain[i].algorithm || 'Velora'
          });
        }
      }

      // Calculate recent blocks for time analysis
      const recentBlocks = chain.slice(-Math.min(difficultyBlocks, chain.length));
      const averageBlockTime = this.calculateAverageBlockTime(recentBlocks);

      // Predict next difficulty adjustment
      const timeDeviation = averageBlockTime - targetBlockTime;
      const adjustmentFactor = targetBlockTime / averageBlockTime;
      const predictedDifficulty = currentDifficulty * adjustmentFactor;

      // Analyze difficulty trend
      const trend = this.analyzeDifficultyTrend(difficultyHistory);

      return {
        enabled: true,
        current: {
          difficulty: currentDifficulty,
          algorithm: latestBlock?.algorithm || 'Velora',
          blockIndex: chain.length - 1,
          timestamp: latestBlock?.timestamp
        },
        adjustment: {
          blocksUntilNext: blocksUntilAdjustment,
          estimatedTimeUntilNext: blocksUntilAdjustment * averageBlockTime,
          targetBlockTime: targetBlockTime,
          actualBlockTime: averageBlockTime,
          adjustmentFactor: adjustmentFactor,
          predictedDifficulty: predictedDifficulty,
          predictedChange: ((predictedDifficulty - currentDifficulty) / currentDifficulty) * 100
        },
        history: difficultyHistory,
        analysis: {
          trend: trend,
          volatility: this.calculateDifficultyVolatility(difficultyHistory),
          efficiency: this.calculateMiningEfficiency(averageBlockTime, targetBlockTime),
          stability: this.assessDifficultyStability(difficultyHistory)
        },
        statistics: {
          minDifficulty: Math.min(...difficultyHistory.map(d => d.difficulty)),
          maxDifficulty: Math.max(...difficultyHistory.map(d => d.difficulty)),
          averageDifficulty: difficultyHistory.reduce((sum, d) => sum + d.difficulty, 0) / difficultyHistory.length
        }
      };
    } catch (error) {
      logger.error('MINING_SERVICE', `Error analyzing difficulty: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Feature 30: Mining reward information and halving countdown
   */
  getMiningRewards() {
    try {
      if (!this.blockchain) {
        return { error: 'Blockchain not available' };
      }

      const config = this.blockchain.config?.blockchain || {};
      const chain = this.blockchain.chain || [];
      const currentHeight = chain.length;

      // Get reward parameters
      const baseReward = config.coinbaseReward || 5000000000; // 50 PAS in atomic units
      const halvingBlocks = config.halvingBlocks || 210000;

      // Calculate current reward (with halvings)
      const halvingEpoch = Math.floor(currentHeight / halvingBlocks);
      const currentReward = baseReward / Math.pow(2, halvingEpoch);

      // Calculate next halving
      const nextHalvingHeight = (halvingEpoch + 1) * halvingBlocks;
      const blocksUntilHalving = Math.max(0, nextHalvingHeight - currentHeight);
      const nextReward = baseReward / Math.pow(2, halvingEpoch + 1);

      // Estimate time until halving
      const recentBlocks = chain.slice(-100);
      const averageBlockTime = this.calculateAverageBlockTime(recentBlocks);
      const estimatedTimeUntilHalving = blocksUntilHalving * averageBlockTime;

      // Calculate total supply and rewards paid
      let totalSupply = 0;
      let totalRewardsPaid = 0;

      chain.forEach(block => {
        if (block.transactions && Array.isArray(block.transactions)) {
          block.transactions.forEach(tx => {
            if (tx.tag === 'COINBASE' || tx.tag === 'PREMINE') {
              const reward = tx.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;
              totalSupply += reward;
              totalRewardsPaid += reward;
            }
          });
        }
      });

      // Calculate mining profitability estimates
      const networkHashRate = this.estimateNetworkHashRate(recentBlocks);
      const dailyBlocks = (24 * 60 * 60 * 1000) / averageBlockTime;
      const dailyRewards = dailyBlocks * currentReward;

      return {
        enabled: true,
        current: {
          blockReward: fromAtomicUnits(currentReward),
          atomicBlockReward: currentReward,
          height: currentHeight,
          halvingEpoch: halvingEpoch,
          totalHalvings: halvingEpoch
        },
        halving: {
          nextHalvingHeight: nextHalvingHeight,
          blocksUntilHalving: blocksUntilHalving,
          nextReward: fromAtomicUnits(nextReward),
          atomicNextReward: nextReward,
          estimatedTimeUntilHalving: estimatedTimeUntilHalving,
          percentageToNextHalving: ((currentHeight % halvingBlocks) / halvingBlocks) * 100
        },
        supply: {
          totalSupply: fromAtomicUnits(totalSupply),
          atomicTotalSupply: totalSupply,
          totalRewardsPaid: fromAtomicUnits(totalRewardsPaid),
          atomicTotalRewardsPaid: totalRewardsPaid,
          percentageOfMaxSupply: (totalSupply / (21000000 * 100000000)) * 100 // Assuming 21M max supply like Bitcoin
        },
        economics: {
          dailyBlocks: Math.round(dailyBlocks),
          dailyRewards: fromAtomicUnits(dailyRewards),
          atomicDailyRewards: dailyRewards,
          inflationRate: (dailyRewards * 365) / totalSupply * 100,
          networkValue: this.estimateNetworkValue(totalSupply, currentReward)
        },
        history: this.getRewardHistory(chain, 10) // Last 10 blocks
      };
    } catch (error) {
      logger.error('MINING_SERVICE', `Error getting mining rewards: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Feature 31: Block time analysis and network stability
   */
  getBlockTimeAnalysis() {
    try {
      if (!this.blockchain || !this.blockchain.chain) {
        return { error: 'Blockchain not available' };
      }

      const chain = this.blockchain.chain;
      const targetBlockTime = this.blockchain.config?.blockchain?.blockTime || 15000; // 15 seconds

      // Analyze different time periods
      const periods = {
        last10: chain.slice(-10),
        last100: chain.slice(-100),
        last1000: chain.slice(-1000),
        all: chain
      };

      const analysis = {};

      Object.keys(periods).forEach(period => {
        const blocks = periods[period];
        if (blocks.length < 2) return;

        const blockTimes = [];
        for (let i = 1; i < blocks.length; i++) {
          const timeDiff = blocks[i].timestamp - blocks[i-1].timestamp;
          blockTimes.push(timeDiff);
        }

        blockTimes.sort((a, b) => a - b);

        const average = blockTimes.reduce((sum, time) => sum + time, 0) / blockTimes.length;
        const median = blockTimes[Math.floor(blockTimes.length / 2)];
        const min = blockTimes[0];
        const max = blockTimes[blockTimes.length - 1];

        // Calculate standard deviation
        const variance = blockTimes.reduce((sum, time) => sum + Math.pow(time - average, 2), 0) / blockTimes.length;
        const standardDeviation = Math.sqrt(variance);

        // Calculate percentiles
        const p25 = blockTimes[Math.floor(blockTimes.length * 0.25)];
        const p75 = blockTimes[Math.floor(blockTimes.length * 0.75)];

        analysis[period] = {
          blocks: blocks.length,
          average: Math.round(average),
          median: Math.round(median),
          min: min,
          max: max,
          standardDeviation: Math.round(standardDeviation),
          variance: Math.round(variance),
          percentiles: {
            p25: p25,
            p75: p75
          },
          targetDeviation: Math.round(average - targetBlockTime),
          efficiency: Math.round((targetBlockTime / average) * 100),
          stability: this.calculateStabilityScore(standardDeviation, average)
        };
      });

      // Detect trends
      const recentTrend = this.detectBlockTimeTrend(periods.last100);

      // Network health assessment
      const networkHealth = this.assessNetworkHealth(periods.last100);

      return {
        enabled: true,
        target: {
          blockTime: targetBlockTime,
          blocksPerHour: Math.round((60 * 60 * 1000) / targetBlockTime),
          blocksPerDay: Math.round((24 * 60 * 60 * 1000) / targetBlockTime)
        },
        analysis: analysis,
        trends: {
          recent: recentTrend,
          overall: this.detectBlockTimeTrend(periods.all)
        },
        health: networkHealth,
        recommendations: this.generateBlockTimeRecommendations(analysis, targetBlockTime)
      };
    } catch (error) {
      logger.error('MINING_SERVICE', `Error analyzing block times: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Feature 32: Miner statistics and leaderboard (if available)
   */
  getMinerStatistics() {
    try {
      if (!this.blockchain || !this.blockchain.chain) {
        return { error: 'Blockchain not available' };
      }

      const chain = this.blockchain.chain;
      const recentBlocks = chain.slice(-1000); // Analyze last 1000 blocks

      const minerStats = new Map();
      let totalBlocks = 0;

      // Analyze blocks to extract miner information
      recentBlocks.forEach(block => {
        if (block.transactions && Array.isArray(block.transactions)) {
          // Look for coinbase transaction to identify miner
          const coinbaseTx = block.transactions.find(tx => tx.tag === 'COINBASE');
          if (coinbaseTx && coinbaseTx.outputs && coinbaseTx.outputs.length > 0) {
            const minerAddress = coinbaseTx.outputs[0].address;
            const reward = coinbaseTx.outputs.reduce((sum, output) => sum + (output.amount || 0), 0);

            if (!minerStats.has(minerAddress)) {
              minerStats.set(minerAddress, {
                address: minerAddress,
                blocksFound: 0,
                totalRewards: 0,
                lastBlockTime: 0,
                averageBlockTime: 0,
                blockTimes: [],
                hashRate: 0
              });
            }

            const stats = minerStats.get(minerAddress);
            stats.blocksFound++;
            stats.totalRewards += reward;
            stats.lastBlockTime = block.timestamp;
            stats.blockTimes.push(block.timestamp);

            totalBlocks++;
          }
        }
      });

      // Calculate additional statistics for each miner
      const minerLeaderboard = Array.from(minerStats.values()).map(stats => {
        // Calculate average block time for this miner
        if (stats.blockTimes.length > 1) {
          stats.blockTimes.sort();
          const timeDiffs = [];
          for (let i = 1; i < stats.blockTimes.length; i++) {
            timeDiffs.push(stats.blockTimes[i] - stats.blockTimes[i-1]);
          }
          stats.averageBlockTime = timeDiffs.reduce((sum, time) => sum + time, 0) / timeDiffs.length;
        }

        // Calculate hash rate estimate (very rough)
        const networkHashRate = this.estimateNetworkHashRate(recentBlocks);
        stats.hashRate = (stats.blocksFound / totalBlocks) * networkHashRate;

        // Calculate market share
        stats.marketShare = (stats.blocksFound / totalBlocks) * 100;

        // Convert rewards to readable format
        stats.totalRewardsFormatted = fromAtomicUnits(stats.totalRewards);

        return stats;
      });

      // Sort by blocks found (descending)
      minerLeaderboard.sort((a, b) => b.blocksFound - a.blocksFound);

      // Calculate network distribution
      const herfindahlIndex = minerLeaderboard.reduce((sum, miner) => {
        return sum + Math.pow(miner.marketShare, 2);
      }, 0);

      const decentralization = this.assessDecentralization(herfindahlIndex, minerLeaderboard.length);

      return {
        enabled: true,
        overview: {
          totalMiners: minerStats.size,
          totalBlocksAnalyzed: totalBlocks,
          analysisDepth: recentBlocks.length,
          timespan: recentBlocks.length > 0 ?
            recentBlocks[recentBlocks.length - 1].timestamp - recentBlocks[0].timestamp : 0
        },
        leaderboard: minerLeaderboard.slice(0, 20), // Top 20 miners
        distribution: {
          herfindahlIndex: Math.round(herfindahlIndex),
          decentralization: decentralization,
          top5Share: minerLeaderboard.slice(0, 5).reduce((sum, miner) => sum + miner.marketShare, 0),
          top10Share: minerLeaderboard.slice(0, 10).reduce((sum, miner) => sum + miner.marketShare, 0)
        },
        statistics: {
          averageBlocksPerMiner: totalBlocks / minerStats.size,
          mostActiveAddress: minerLeaderboard[0]?.address || 'Unknown',
          mostRecentBlock: Math.max(...Array.from(minerStats.values()).map(m => m.lastBlockTime)),
          totalHashRate: this.estimateNetworkHashRate(recentBlocks)
        }
      };
    } catch (error) {
      logger.error('MINING_SERVICE', `Error getting miner statistics: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Feature 33: Mining pool information and connectivity
   */
  getMiningPoolInfo() {
    try {
      // This would typically connect to known mining pools or analyze network data
      // For now, provide a basic structure with placeholder data

      return {
        enabled: true,
        pools: [
          {
            name: 'Local Mining',
            hashRate: this.estimateNetworkHashRate(this.blockchain?.chain?.slice(-100) || []),
            miners: 1,
            fee: 0,
            status: 'online',
            url: 'localhost:3333',
            algorithm: 'Velora'
          }
        ],
        connectivity: {
          connectedPools: 0,
          totalHashRate: this.estimateNetworkHashRate(this.blockchain?.chain?.slice(-100) || []),
          averageFee: 0,
          poolDistribution: {
            'Solo Mining': 100
          }
        },
        recommendations: {
          suggestedPools: [],
          optimalSettings: {
            algorithm: 'Velora',
            difficulty: this.blockchain?.getLatestBlock()?.difficulty || 1000,
            expectedReward: this.calculateExpectedReward()
          }
        }
      };
    } catch (error) {
      logger.error('MINING_SERVICE', `Error getting mining pool info: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  // Helper Methods

  estimateNetworkHashRate(blocks) {
    if (!blocks || blocks.length < 2) return 0;

    let totalDifficulty = 0;
    let totalTime = 0;

    for (let i = 1; i < blocks.length; i++) {
      const timeDiff = blocks[i].timestamp - blocks[i-1].timestamp;
      if (timeDiff > 0) {
        totalDifficulty += blocks[i].difficulty || 0;
        totalTime += timeDiff;
      }
    }

    if (totalTime === 0) return 0;

    // Hash rate = (total difficulty * 2^32) / total time in seconds
    // Simplified calculation
    return Math.round((totalDifficulty * 1000) / (totalTime / 1000));
  }

  calculateAverageBlockTime(blocks) {
    if (!blocks || blocks.length < 2) return 0;

    let totalTime = 0;
    let validIntervals = 0;

    for (let i = 1; i < blocks.length; i++) {
      const timeDiff = blocks[i].timestamp - blocks[i-1].timestamp;
      if (timeDiff > 0) {
        totalTime += timeDiff;
        validIntervals++;
      }
    }

    return validIntervals > 0 ? totalTime / validIntervals : 0;
  }

  calculateTotalWork(chain) {
    return chain.reduce((sum, block) => sum + (block.difficulty || 0), 0);
  }

  calculateBlocksPerHour(blocks) {
    const averageBlockTime = this.calculateAverageBlockTime(blocks);
    return averageBlockTime > 0 ? (60 * 60 * 1000) / averageBlockTime : 0;
  }

  calculateHashRateEfficiency(difficulty, blockTime) {
    const targetTime = 15000; // 15 seconds
    return blockTime > 0 ? (targetTime / blockTime) * 100 : 0;
  }

  assessNetworkHealth(blocks) {
    const averageBlockTime = this.calculateAverageBlockTime(blocks);
    const targetTime = 15000;
    const deviation = Math.abs(averageBlockTime - targetTime) / targetTime * 100;

    if (deviation < 10) return 'excellent';
    if (deviation < 25) return 'good';
    if (deviation < 50) return 'fair';
    return 'poor';
  }

  analyzeDifficultyTrend(history) {
    if (history.length < 2) return 'insufficient_data';

    const recent = history.slice(-5);
    const older = history.slice(-10, -5);

    if (recent.length === 0 || older.length === 0) return 'insufficient_data';

    const recentAvg = recent.reduce((sum, d) => sum + d.difficulty, 0) / recent.length;
    const olderAvg = older.reduce((sum, d) => sum + d.difficulty, 0) / older.length;

    const change = ((recentAvg - olderAvg) / olderAvg) * 100;

    if (change > 5) return 'increasing';
    if (change < -5) return 'decreasing';
    return 'stable';
  }

  calculateDifficultyVolatility(history) {
    if (history.length < 2) return 0;

    const difficulties = history.map(d => d.difficulty);
    const mean = difficulties.reduce((sum, d) => sum + d, 0) / difficulties.length;
    const variance = difficulties.reduce((sum, d) => sum + Math.pow(d - mean, 2), 0) / difficulties.length;

    return Math.sqrt(variance) / mean * 100; // Coefficient of variation
  }

  calculateMiningEfficiency(actualTime, targetTime) {
    return (targetTime / actualTime) * 100;
  }

  assessDifficultyStability(history) {
    const volatility = this.calculateDifficultyVolatility(history);

    if (volatility < 5) return 'very_stable';
    if (volatility < 15) return 'stable';
    if (volatility < 30) return 'moderate';
    return 'volatile';
  }

  calculateStabilityScore(standardDeviation, average) {
    const coefficient = standardDeviation / average;
    if (coefficient < 0.1) return 'excellent';
    if (coefficient < 0.3) return 'good';
    if (coefficient < 0.5) return 'fair';
    return 'poor';
  }

  detectBlockTimeTrend(blocks) {
    if (!blocks || blocks.length < 10) return 'insufficient_data';

    const halfPoint = Math.floor(blocks.length / 2);
    const firstHalf = blocks.slice(0, halfPoint);
    const secondHalf = blocks.slice(halfPoint);

    const firstHalfAvg = this.calculateAverageBlockTime(firstHalf);
    const secondHalfAvg = this.calculateAverageBlockTime(secondHalf);

    const change = ((secondHalfAvg - firstHalfAvg) / firstHalfAvg) * 100;

    if (change > 10) return 'increasing';
    if (change < -10) return 'decreasing';
    return 'stable';
  }

  generateBlockTimeRecommendations(analysis, targetTime) {
    const recommendations = [];

    if (analysis.last100 && analysis.last100.average > targetTime * 1.2) {
      recommendations.push('Consider increasing mining power to reduce block times');
    }

    if (analysis.last100 && analysis.last100.average < targetTime * 0.8) {
      recommendations.push('Block times are faster than target - difficulty may increase');
    }

    if (analysis.last100 && analysis.last100.standardDeviation > analysis.last100.average * 0.5) {
      recommendations.push('High block time variability detected - check network stability');
    }

    return recommendations;
  }

  getRewardHistory(chain, limit = 10) {
    const recent = chain.slice(-limit);
    return recent.map(block => {
      const coinbaseTx = block.transactions?.find(tx => tx.tag === 'COINBASE');
      const reward = coinbaseTx?.outputs?.reduce((sum, output) => sum + (output.amount || 0), 0) || 0;

      return {
        blockIndex: block.index,
        timestamp: block.timestamp,
        reward: fromAtomicUnits(reward),
        atomicReward: reward,
        difficulty: block.difficulty,
        miner: coinbaseTx?.outputs?.[0]?.address || 'Unknown'
      };
    });
  }

  estimateNetworkValue(supply, reward) {
    // Very simplified network value estimation
    return {
      marketCap: 'Unknown',
      dailyIssuance: fromAtomicUnits(reward * 5760), // Assuming 15s blocks = 5760 blocks/day
      inflationRate: 'Unknown'
    };
  }

  assessDecentralization(herfindahlIndex, minerCount) {
    if (herfindahlIndex < 1000) return 'highly_decentralized';
    if (herfindahlIndex < 2500) return 'decentralized';
    if (herfindahlIndex < 5000) return 'moderately_centralized';
    return 'centralized';
  }

  calculateExpectedReward() {
    const latestBlock = this.blockchain?.getLatestBlock();
    const difficulty = latestBlock?.difficulty || 1000;
    const baseReward = this.blockchain?.config?.blockchain?.coinbaseReward || 5000000000;

    return fromAtomicUnits(baseReward);
  }
}

module.exports = MiningService;