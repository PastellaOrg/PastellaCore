const chalk = require('chalk');

/**
 *
 */
class NetworkManager {
  /**
   *
   * @param cli
   */
  constructor(cli) {
    this.cli = cli;
  }

  // Chain commands
  /**
   *
   * @param args
   */
  async handleChainCommand(args) {
    if (!args || args.length === 0) {
      console.log(chalk.red('❌ Missing chain command'));
      return;
    }

    const subCmd = args[0].toLowerCase();
    switch (subCmd) {
      case 'status':
        await this.showChainStatus();
        break;
      case 'security':
        await this.showChainSecurity();
        break;
      case 'replay-protection':
        await this.showReplayProtectionStatus();
        break;
      case 'rate-limits':
        if (args[1] === 'reset') {
          if (args[2] === 'all') {
            await this.resetAllRateLimits();
          } else if (args[2]) {
            await this.resetRateLimitsForIP(args[2]);
          } else {
            await this.showRateLimitStats();
          }
        } else {
          await this.showRateLimitStats();
        }
        break;
      case 'reset':
        await this.resetBlockchain();
        break;
      case 'blocks':
        await this.showBlocks(args[1] || '10');
        break;
      case 'block':
        if (args.length < 2) {
          console.log(chalk.red('❌ Usage: chain block <index>'));
          return;
        }
        await this.showBlock(args[1]);
        break;
      case 'transactions':
        await this.showPendingTransactions();
        break;
      case 'validate':
        await this.validateChain(args[1] || 'checkpoint');
        break;
      case 'checkpoints':
        await this.manageCheckpoints(args[1], args[2]);
        break;
      default:
        console.log(chalk.red(`❌ Unknown chain command: ${subCmd}`));
    }
  }

  /**
   *
   */
  async showChainStatus() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/blockchain/status');

      console.log(chalk.blue('🔗 Blockchain Status:'));
      console.log(chalk.cyan(`Network ID: ${response.networkId || 'unknown'}`));
      console.log(chalk.cyan(`Height: ${response.length}`));
      console.log(chalk.cyan(`Difficulty: ${response.difficulty}`));
      console.log(chalk.cyan(`Pending Transactions: ${response.pendingTransactions || 0}`));

      if (response.chainWork) {
        console.log(chalk.cyan(`Chain Work: ${response.chainWork}`));
      }
      if (response.securityLevel) {
        console.log(chalk.cyan(`Security Level: ${response.securityLevel}`));
      }

      if (response.latestBlock) {
        console.log(chalk.cyan(`Latest Block: ${response.latestBlock.hash.substring(0, 16)}...`));
        console.log(chalk.cyan(`Block Time: ${new Date(response.latestBlock.timestamp).toLocaleString()}`));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async showChainSecurity() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/blockchain/security-analysis', 'GET');
      if (response) {
        console.log(chalk.red('═══════════════════════════════════════════════════════════════'));
        console.log(chalk.red.bold('                    CHAIN SECURITY REPORT'));
        console.log(chalk.red('═══════════════════════════════════════════════════════════════'));
        console.log(chalk.cyan('  Timestamp:'), chalk.white(response.timestamp));
        console.log('');

        console.log(chalk.cyan('  Blockchain Status:'));
        console.log(chalk.white(`    Height: ${response.blockchain.height}`));
        console.log(chalk.white(`    Difficulty: ${response.blockchain.difficulty}`));
        console.log(chalk.white(`    Last Block: ${response.blockchain.lastBlockHash.substring(0, 16)}...`));
        console.log('');

        console.log(chalk.cyan('  Consensus Status:'));
        console.log(chalk.white(`    Security Level: ${response.consensus.securityLevel}/100`));
        console.log(chalk.white(`    Network Partition: ${response.consensus.networkPartition ? '⚠️  YES' : '✅ NO'}`));

        console.log('');

        if (response.threats.length > 0) {
          console.log(chalk.red('  🚨 ACTIVE THREATS:'));
          response.threats.forEach((threat, index) => {
            const severityColor =
              threat.severity === 'HIGH' ? chalk.red : threat.severity === 'MEDIUM' ? chalk.yellow : chalk.blue;
            console.log(severityColor(`    ${index + 1}. [${threat.severity}] ${threat.type}`));
            console.log(chalk.white(`       ${threat.description}`));
            console.log(chalk.gray(`       Recommendation: ${threat.recommendation}`));
            console.log('');
          });
        } else {
          console.log(chalk.green('  ✅ No active threats detected'));
          console.log('');
        }

        if (response.recommendations.length > 0) {
          console.log(chalk.cyan('  📋 SECURITY RECOMMENDATIONS:'));
          response.recommendations.forEach((rec, index) => {
            const priorityColor =
              rec.priority === 'HIGH' ? chalk.red : rec.priority === 'MEDIUM' ? chalk.yellow : chalk.blue;
            console.log(priorityColor(`    ${index + 1}. [${rec.priority}] ${rec.action}`));
            console.log(chalk.white(`       ${rec.description}`));
          });
        }

        console.log(chalk.red('═══════════════════════════════════════════════════════════════'));
      }
    } catch (error) {
      console.log(chalk.red('❌ Failed to get chain security report:'), error.message);
    }
  }

  /**
   *
   */
  async showReplayProtectionStatus() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/blockchain/replay-protection');
      if (response) {
        console.log(chalk.yellow('═══════════════════════════════════════════════════════════════'));
        console.log(chalk.yellow.bold('                REPLAY ATTACK PROTECTION STATUS'));
        console.log(chalk.yellow('═══════════════════════════════════════════════════════════════'));
        console.log(chalk.cyan('  Protection Status:'), chalk.green('✅ ENABLED'));
        console.log(chalk.cyan('  Total Pending Transactions:'), chalk.white(response.totalPending || 0));
        console.log(chalk.cyan('  Valid Transactions:'), chalk.green(response.valid || 0));
        console.log(chalk.cyan('  Expired Transactions:'), chalk.red(response.expired || 0));
        console.log(chalk.cyan('  Expiring Soon (< 1 hour):'), chalk.yellow(response.expiringSoon || 0));
        console.log(chalk.cyan('  Last Cleanup:'), chalk.white(response.lastCleanup || 'Never'));

        if (response.expired > 0) {
          console.log(chalk.yellow('\n  🔄 Auto-cleanup will remove expired transactions'));
        }

        if (response.expiringSoon > 0) {
          console.log(chalk.yellow('\n  ⏰ Some transactions will expire soon'));
        }

        console.log(chalk.yellow('═══════════════════════════════════════════════════════════════'));
      }
    } catch (error) {
      console.log(chalk.red('❌ Failed to get replay protection status:'), error.message);
    }
  }

  /**
   *
   */
  async showRateLimitStats() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/rate-limits/stats');
      if (response && response.success) {
        const stats = response.data;

        console.log(chalk.blue('═══════════════════════════════════════════════════════════════'));
        console.log(chalk.blue.bold('                    RATE LIMITING STATISTICS'));
        console.log(chalk.blue('═══════════════════════════════════════════════════════════════'));
        console.log(chalk.cyan('  Total Tracked IPs:'), chalk.white(stats.totalTrackedIPs || 0));
        console.log(chalk.cyan('  Total Requests:'), chalk.white(stats.totalRequests || 0));

        if (stats.endpointStats && Object.keys(stats.endpointStats).length > 0) {
          console.log(chalk.cyan('\n  📊 Endpoint Statistics:'));
          for (const [endpoint, endpointData] of Object.entries(stats.endpointStats)) {
            console.log(chalk.cyan(`    ${endpoint}:`));
            console.log(chalk.white(`      Requests: ${endpointData.requests}`));
            console.log(chalk.white(`      Unique IPs: ${endpointData.ips}`));
          }
        }

        console.log(chalk.blue('═══════════════════════════════════════════════════════════════'));
        console.log(chalk.gray('💡 Use "chain rate-limits reset <ip>" to reset limits for specific IP'));
        console.log(chalk.gray('💡 Use "chain rate-limits reset-all" to reset all limits'));
      }
    } catch (error) {
      console.log(chalk.red('❌ Failed to get rate limit stats:'), error.message);
    }
  }

  /**
   *
   * @param ip
   */
  async resetRateLimitsForIP(ip) {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      console.log(chalk.yellow(`🔄 Resetting rate limits for IP: ${ip}`));

      const response = await this.cli.makeApiRequest(`/api/rate-limits/reset/${ip}`, 'POST');
      if (response && response.success) {
        console.log(chalk.green('✅ Rate limits reset successfully!'));
        console.log(chalk.cyan(`  Reset ${response.resetEndpoints} endpoint(s) for IP ${ip}`));
      } else {
        console.log(chalk.red('❌ Failed to reset rate limits'));
      }
    } catch (error) {
      console.log(chalk.red('❌ Failed to reset rate limits:'), error.message);
    }
  }

  /**
   *
   */
  async resetAllRateLimits() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      console.log(chalk.yellow('🔄 Resetting all rate limits...'));

      const response = await this.cli.makeApiRequest('/api/rate-limits/reset-all', 'POST');
      if (response && response.success) {
        console.log(chalk.green('✅ All rate limits reset successfully!'));
        console.log(chalk.cyan(`  Reset ${response.resetEntries} entries`));
      } else {
        console.log(chalk.red('❌ Failed to reset all rate limits'));
      }
    } catch (error) {
      console.log(chalk.red('❌ Failed to reset all rate limits:'), error.message);
    }
  }

  /**
   *
   */
  async resetBlockchain() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      console.log(chalk.red('⚠️  WARNING: This will completely reset your blockchain!'));
      console.log(chalk.red('⚠️  All blocks, transactions, and balances will be lost!'));
      console.log(chalk.red('⚠️  This action cannot be undone!'));
      console.log('');

      const response = await this.cli.makeApiRequest('/api/blockchain/reset', 'POST');
      if (response && response.success) {
        console.log(chalk.green('✅ Blockchain reset successfully!'));
        console.log(chalk.cyan('  New genesis block created with mandatory replay protection'));
        console.log(chalk.cyan('  All future transactions will require protection fields'));
        console.log(chalk.cyan('  Start mining to build your new secure chain'));
      } else {
        console.log(chalk.red('❌ Failed to reset blockchain:'), response?.error || 'Unknown error');
      }
    } catch (error) {
      console.log(chalk.red('❌ Failed to reset blockchain:'), error.message);
    }
  }

  /**
   *
   * @param limit
   */
  async showBlocks(limit) {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest(`/api/blockchain/blocks?limit=${limit}`);

      console.log(chalk.blue(`🔗 Recent blocks (${response.blocks.length}):`));
      response.blocks.forEach(block => {
        console.log(chalk.cyan(`${block.index}. Block ${block.index}`));
        console.log(`   Hash: ${block.hash}`);
        console.log(`   Previous: ${block.previousHash}`);
        console.log(`   Transactions: ${block.transactions.length}`);
        console.log(`   Timestamp: ${new Date(block.timestamp).toLocaleString()}`);
        console.log('');
      });
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   * @param index
   */
  async showBlock(index) {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest(`/api/blockchain/blocks/${index}`);

      console.log(chalk.blue(`🔗 Block ${response.index}:`));
      console.log(chalk.cyan(`Hash: ${response.hash}`));
      console.log(chalk.cyan(`Previous Hash: ${response.previousHash}`));
      console.log(chalk.cyan(`Merkle Root: ${response.merkleRoot}`));
      console.log(chalk.cyan(`Nonce: ${response.nonce}`));
      console.log(chalk.cyan(`Difficulty: ${response.difficulty}`));
      console.log(chalk.cyan(`Timestamp: ${new Date(response.timestamp).toLocaleString()}`));
      console.log(chalk.cyan(`Transactions: ${response.transactions.length}`));
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async showPendingTransactions() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/blockchain/transactions');

      if (response.transactions.length === 0) {
        console.log(chalk.yellow('No pending transactions.'));
        return;
      }

      console.log(chalk.blue(`📋 Pending transactions (${response.transactions.length}):`));
      response.transactions.forEach((tx, index) => {
        console.log(chalk.cyan(`${index + 1}. Transaction ${tx.id.substring(0, 8)}...`));
        console.log(`   Fee: ${tx.fee} PAS`);
        console.log(`   Outputs: ${tx.outputs.length}`);
        console.log(`   Timestamp: ${new Date(tx.timestamp).toLocaleString()}`);
        console.log('');
      });
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  // Network commands
  /**
   *
   * @param args
   */
  async handleNetworkCommand(args) {
    if (!args || args.length === 0) {
      console.log(chalk.red('❌ Missing network command'));
      return;
    }

    const subCmd = args[0].toLowerCase();
    switch (subCmd) {
      case 'status':
        await this.showNetworkStatus();
        break;
      case 'peers':
        await this.showPeers();
        break;
      case 'connect':
        if (args.length < 3) {
          console.log(chalk.red('❌ Usage: network connect <host> <port>'));
          return;
        }
        await this.connectToPeer(args[1], args[2]);
        break;
      case 'reputation':
        await this.showReputationStats();
        break;
      case 'peer-reputation':
        if (args.length < 2) {
          console.log(chalk.red('❌ Usage: network peer-reputation <peer-address>'));
          return;
        }
        await this.showPeerReputation(args[1]);
        break;
      case 'identity':
        await this.showNodeIdentity();
        break;
      case 'authenticated':
        await this.showAuthenticatedPeers();
        break;
      case 'message-validation':
        await this.showMessageValidationStats();
        break;
      case 'message-validation-reset':
        await this.resetMessageValidationStats();
        break;
      case 'partition-stats':
        await this.showPartitionStats();
        break;
      case 'partition-reset':
        await this.resetPartitionStats();
        break;
      default:
        console.log(chalk.red(`❌ Unknown network command: ${subCmd}`));
        console.log(
          chalk.cyan(
            'Available commands: status, peers, connect, reputation, peer-reputation, identity, authenticated, message-validation, message-validation-reset, partition-stats, partition-reset'
          )
        );
    }
  }

  /**
   *
   */
  async showNetworkStatus() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/network/status');

      console.log(chalk.blue('🌐 Network Status:'));
      console.log(chalk.cyan(`Status: ${response.isRunning ? 'Running' : 'Stopped'}`));
      console.log(chalk.cyan(`Port: ${response.port}`));
      console.log(chalk.cyan(`Peers: ${response.peerCount}/${response.maxPeers}`));
      console.log(
        chalk.cyan(`Seed Nodes: ${response.connectedSeedNodes}/${response.minSeedConnections} (min required)`)
      );

      // Show reputation information if available
      if (response.reputation) {
        console.log(chalk.cyan(`Reputation System: Active`));
        console.log(chalk.green(`  Good Peers: ${response.reputation.goodPeers}`));
        console.log(chalk.yellow(`  Bad Peers: ${response.reputation.badPeers}`));
        console.log(chalk.red(`  Banned Peers: ${response.reputation.bannedPeers}`));
        console.log(chalk.cyan(`  Average Score: ${response.reputation.averageScore}`));
      }

      // Show message validation information if available
      if (response.messageValidation) {
        console.log(chalk.cyan(`Message Validation: Active`));
        console.log(chalk.green(`  Valid Messages: ${response.messageValidation.validMessages}`));
        console.log(chalk.red(`  Invalid Messages: ${response.messageValidation.invalidMessages}`));
        console.log(chalk.cyan(`  Validation Rate: ${response.messageValidation.validationRate}%`));
        console.log(chalk.cyan(`  Supported Types: ${response.messageValidation.supportedMessageTypes}`));
      }

      // Show partition handling information if available
      if (response.partitionHandling) {
        const partitionStatus = response.partitionHandling.isPartitioned
          ? chalk.red('Partitioned')
          : chalk.green('Healthy');
        console.log(chalk.cyan(`Partition Handling: ${partitionStatus}`));
        console.log(chalk.cyan(`  Total Partitions: ${response.partitionHandling.totalPartitions}`));
        console.log(
          chalk.cyan(
            `  Recovery Success Rate: ${response.partitionHandling.totalPartitions > 0 ? Math.round((response.partitionHandling.successfulRecoveries / response.partitionHandling.totalPartitions) * 100) : 0}%`
          )
        );
        if (response.partitionHandling.isPartitioned) {
          console.log(
            chalk.red(
              `  Current Partition Duration: ${Math.round(response.partitionHandling.partitionDuration / 1000)}s`
            )
          );
        }
      }

      if (response.networkSyncStatus) {
        const syncStatus = response.networkSyncStatus;
        console.log(chalk.cyan(`Sync Status: ${syncStatus.isSyncing ? 'Syncing' : 'Idle'}`));
        if (syncStatus.lastSyncTime) {
          console.log(chalk.cyan(`Last Sync: ${new Date(syncStatus.lastSyncTime).toLocaleString()}`));
        }
        console.log(chalk.cyan(`Sync Attempts: ${syncStatus.syncAttempts}/${syncStatus.maxSyncAttempts}`));
      }

      if (response.seedNodes && response.seedNodes.length > 0) {
        console.log(chalk.cyan(`Available Seed Nodes: ${response.seedNodes.length}`));
        response.seedNodes.forEach((node, index) => {
          console.log(chalk.gray(`  ${index + 1}. ${node}`));
        });
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async showPeers() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/network/peers');

      if (response.length === 0) {
        console.log(chalk.yellow('No peers connected.'));
        return;
      }

      console.log(chalk.blue(`🌐 Connected peers (${response.length}):`));
      response.forEach((peer, index) => {
        const statusColor = peer.readyState === 1 ? chalk.green : chalk.red;
        const statusText = peer.readyState === 1 ? 'Connected' : 'Disconnected';
        const authColor = peer.authenticated ? chalk.green : chalk.red;
        const authText = peer.authenticated ? 'Authenticated' : 'Not Authenticated';

        console.log(chalk.cyan(`${index + 1}. ${peer.url}`));
        console.log(`   Status: ${statusColor(statusText)}`);
        console.log(`   Authentication: ${authColor(authText)}`);

        if (peer.authenticated && peer.nodeId) {
          console.log(`   Node ID: ${peer.nodeId.substring(0, 16)}...`);
          console.log(`   Authenticated: ${new Date(peer.authenticatedAt).toLocaleString()}`);
        }

        // Show reputation information if available
        if (peer.reputation) {
          const scoreColor =
            peer.reputation.score >= 150 ? chalk.green : peer.reputation.score <= 50 ? chalk.red : chalk.yellow;
          console.log(`   Reputation Score: ${scoreColor(peer.reputation.score)}`);
          console.log(`   Messages: ${peer.reputation.messageCount} (${peer.reputation.invalidMessageCount} invalid)`);
          if (peer.reputation.banned) {
            console.log(chalk.red(`   BANNED until ${new Date(peer.reputation.banExpiry).toLocaleString()}`));
          }
        }

        console.log('');
      });
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   * @param host
   * @param port
   */
  async connectToPeer(host, port) {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      await this.cli.makeApiRequest('/api/network/connect', 'POST', {
        host,
        port: parseInt(port),
      });

      console.log(chalk.green(`✅ Connecting to peer ${host}:${port}`));
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  // Daemon commands
  /**
   *
   * @param args
   */
  async handleDaemonCommand(args) {
    if (!args || args.length === 0) {
      console.log(chalk.red('❌ Missing daemon command'));
      return;
    }

    const subCmd = args[0].toLowerCase();
    switch (subCmd) {
      case 'status':
        await this.showDaemonStatus();
        break;
      default:
        console.log(chalk.red(`❌ Unknown daemon command: ${subCmd}`));
    }
  }

  /**
   *
   */
  async showDaemonStatus() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/daemon/status');

      console.log(chalk.blue('🚀 Daemon Status:'));

      // Handle different response structures safely
      if (response && typeof response === 'object') {
        console.log(chalk.cyan(`Status: ${response.isRunning ? 'Running' : 'Stopped'}`));

        if (response.api && typeof response.api === 'object') {
          console.log(chalk.cyan(`API Server: ${response.api.isRunning ? 'Running' : 'Stopped'}`));
          if (response.api.port) {
            console.log(chalk.cyan(`API Port: ${response.api.port}`));
          }
        }

        if (response.network && typeof response.network === 'object') {
          console.log(chalk.cyan(`P2P Network: ${response.network.isRunning ? 'Running' : 'Stopped'}`));
          if (response.network.port) {
            console.log(chalk.cyan(`P2P Port: ${response.network.port}`));
          }
        }
      } else {
        console.log(chalk.cyan('Status: Running (API connected)'));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  // Reputation commands
  /**
   *
   */
  async showReputationStats() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/network/reputation');

      console.log(chalk.blue('🏆 Network Reputation Statistics:'));
      console.log(chalk.cyan(`Total Peers Tracked: ${response.reputation.totalPeers}`));
      console.log(chalk.green(`Good Peers (Score ≥150): ${response.reputation.goodPeers}`));
      console.log(chalk.yellow(`Bad Peers (Score ≤50): ${response.reputation.badPeers}`));
      console.log(chalk.red(`Banned Peers: ${response.reputation.bannedPeers}`));
      console.log(chalk.cyan(`Average Score: ${response.reputation.averageScore}`));
      console.log(chalk.gray(`Last Updated: ${new Date(response.timestamp).toLocaleString()}`));
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   * @param peerAddress
   */
  async showPeerReputation(peerAddress) {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest(`/api/network/reputation/${encodeURIComponent(peerAddress)}`);

      console.log(chalk.blue(`🏆 Peer Reputation: ${response.peerAddress}`));
      console.log(chalk.cyan(`Score: ${response.reputation.score}`));
      console.log(chalk.cyan(`Banned: ${response.reputation.banned ? 'Yes' : 'No'}`));
      if (response.reputation.banExpiry) {
        console.log(chalk.cyan(`Ban Expiry: ${new Date(response.reputation.banExpiry).toLocaleString()}`));
      }
      console.log(chalk.cyan(`Connection Count: ${response.reputation.connectionCount}`));
      console.log(chalk.green(`Good Actions: ${response.reputation.goodActions}`));
      console.log(chalk.red(`Bad Actions: ${response.reputation.badActions}`));
      console.log(chalk.cyan(`Messages Received: ${response.reputation.messageCount}`));
      console.log(chalk.red(`Invalid Messages: ${response.reputation.invalidMessageCount}`));
      console.log(chalk.cyan(`Sync Attempts: ${response.reputation.syncAttempts}`));
      console.log(chalk.green(`Successful Syncs: ${response.reputation.successfulSyncs}`));
      console.log(chalk.gray(`Last Seen: ${new Date(response.reputation.lastSeen).toLocaleString()}`));
      console.log(chalk.gray(`Last Updated: ${new Date(response.timestamp).toLocaleString()}`));
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  // Node Identity commands
  /**
   *
   */
  async showNodeIdentity() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/network/status');

      console.log(chalk.blue('🆔 Node Identity:'));
      if (response.nodeIdentity) {
        console.log(chalk.cyan(`Node ID: ${response.nodeIdentity.nodeId}`));
        console.log(chalk.cyan(`Public Key: ${response.nodeIdentity.publicKey ? 'Available' : 'Not available'}`));
      } else {
        console.log(chalk.yellow('⚠️  Node identity information not available'));
      }

      console.log(chalk.blue('\n🔐 Authentication Status:'));
      if (response.authentication) {
        console.log(chalk.cyan(`Authenticated Peers: ${response.authentication.authenticatedPeers}`));
        console.log(chalk.cyan(`Total Peers: ${response.authentication.totalPeers}`));
        console.log(chalk.cyan(`Authentication Rate: ${response.authentication.authenticationRate}%`));
      } else {
        console.log(chalk.yellow('⚠️  Authentication information not available'));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async showAuthenticatedPeers() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/network/peers');

      console.log(chalk.blue('🔐 Authenticated Peers:'));

      const authenticatedPeers = response.filter(peer => peer.authenticated);

      if (authenticatedPeers.length === 0) {
        console.log(chalk.yellow('⚠️  No authenticated peers found'));
        return;
      }

      authenticatedPeers.forEach((peer, index) => {
        console.log(chalk.cyan(`${index + 1}. ${peer.url}`));
        console.log(`   Node ID: ${peer.nodeId}`);
        console.log(`   Authenticated: ${new Date(peer.authenticatedAt).toLocaleString()}`);
        console.log(`   Reputation Score: ${peer.reputation.score}`);
        console.log(`   Seed Node: ${peer.isSeedNode ? 'Yes' : 'No'}`);
        console.log('');
      });

      console.log(chalk.gray(`Total authenticated peers: ${authenticatedPeers.length}`));
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async showMessageValidationStats() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/network/message-validation');

      console.log(chalk.blue('🔍 Message Validation Statistics:'));
      console.log(chalk.cyan(`Total Messages: ${response.totalMessages.toLocaleString()}`));
      console.log(chalk.green(`Valid Messages: ${response.validMessages.toLocaleString()}`));
      console.log(chalk.red(`Invalid Messages: ${response.invalidMessages.toLocaleString()}`));

      const { validationRate } = response;
      const rateColor = validationRate >= 95 ? chalk.green : validationRate >= 80 ? chalk.yellow : chalk.red;
      console.log(chalk.cyan(`Validation Rate: ${rateColor(`${validationRate}%`)}`));

      console.log(chalk.cyan(`Supported Message Types: ${response.validatorStats.messageTypes}`));

      // Show error breakdown if there are errors
      if (response.errorBreakdown && Object.keys(response.errorBreakdown).length > 0) {
        console.log(chalk.yellow('\nError Breakdown:'));
        Object.entries(response.errorBreakdown).forEach(([errorType, count]) => {
          console.log(chalk.red(`  ${errorType}: ${count}`));
        });
      }

      // Show validation rules
      console.log(chalk.cyan('\nValidation Rules:'));
      console.log(
        chalk.gray(
          `  Max Message Size: ${(response.validatorStats.validationRules.maxMessageSize / 1024 / 1024).toFixed(1)} MB`
        )
      );
      console.log(
        chalk.gray(
          `  Max Timestamp Drift: ${response.validatorStats.validationRules.maxTimestampDrift / 1000 / 60} minutes`
        )
      );
      console.log(
        chalk.gray(
          `  Max Block Size: ${(response.validatorStats.validationRules.maxBlockSize / 1024 / 1024).toFixed(1)} MB`
        )
      );
      console.log(
        chalk.gray(
          `  Max Transaction Size: ${(response.validatorStats.validationRules.maxTransactionSize / 1024).toFixed(1)} KB`
        )
      );

      if (response.timestamp) {
        console.log(chalk.gray(`\nLast Updated: ${new Date(response.timestamp).toLocaleString()}`));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async resetMessageValidationStats() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/network/message-validation/reset', 'POST');

      console.log(chalk.green('✅ Message validation statistics reset successfully.'));
      if (response.timestamp) {
        console.log(chalk.gray(`Reset at: ${new Date(response.timestamp).toLocaleString()}`));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async showPartitionStats() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/network/partition-stats');

      if (response.success && response.data) {
        const stats = response.data;

        console.log(chalk.blue('🔗 Network Partition Statistics:'));
        console.log(chalk.cyan(`Status: ${stats.isPartitioned ? chalk.red('Partitioned') : chalk.green('Healthy')}`));
        console.log(chalk.cyan(`Total Partitions: ${stats.totalPartitions}`));
        console.log(chalk.cyan(`Current Partitions: ${stats.currentPartitions}`));

        if (stats.isPartitioned && stats.partitionDuration > 0) {
          console.log(chalk.cyan(`Partition Duration: ${Math.round(stats.partitionDuration / 1000)}s`));
        }

        console.log(chalk.cyan(`Recovery Attempts: ${stats.recoveryAttempts}`));
        console.log(chalk.green(`Successful Recoveries: ${stats.successfulRecoveries}`));
        console.log(chalk.red(`Failed Recoveries: ${stats.failedRecoveries}`));
        console.log(chalk.cyan(`Disconnected Peers: ${stats.disconnectedPeers}`));
        console.log(
          chalk.cyan(`Recovery In Progress: ${stats.recoveryInProgress ? chalk.yellow('Yes') : chalk.gray('No')}`)
        );

        if (stats.lastHealthCheck) {
          console.log(chalk.cyan(`Last Health Check: ${new Date(stats.lastHealthCheck).toLocaleString()}`));
        }
      } else {
        console.log(chalk.red('❌ Failed to get partition statistics'));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async resetPartitionStats() {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      const response = await this.cli.makeApiRequest('/api/network/partition-reset', 'POST');

      if (response.success && response.message) {
        console.log(chalk.green(`✅ ${response.message}`));
        console.log(chalk.gray(`Reset at: ${new Date(response.timestamp).toLocaleString()}`));
      } else {
        console.log(chalk.red('❌ Failed to reset partition statistics'));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   * Validate blockchain using different methods
   * @param method
   */
  async validateChain(method = 'checkpoint') {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      console.log(chalk.blue('🔍 Blockchain Validation:'));

      if (method === 'checkpoint' || method === 'fast') {
        console.log(chalk.yellow('Using checkpoint validation (fast mode)...'));
        const response = await this.cli.makeApiRequest('/api/blockchain/validate-checkpoints', 'POST');

        if (response.success) {
          console.log(chalk.green('✅ Checkpoint validation completed successfully!'));
          if (response.checkpointsUsed > 0) {
            console.log(chalk.cyan(`Used ${response.checkpointsUsed} checkpoints for fast validation`));
          }
          if (response.blocksValidated > 0) {
            console.log(chalk.cyan(`Validated ${response.blocksValidated} blocks in detail`));
          }
          if (response.validationTime) {
            console.log(chalk.cyan(`Total validation time: ${response.validationTime}ms`));
          }
        } else {
          console.log(chalk.red('❌ Checkpoint validation failed:'), response.error);
        }
      } else if (method === 'full' || method === 'complete') {
        console.log(chalk.yellow('Using full validation (complete mode)...'));
        const response = await this.cli.makeApiRequest('/api/blockchain/validate-full', 'POST');

        if (response.success) {
          console.log(chalk.green('✅ Full validation completed successfully!'));
          if (response.blocksValidated > 0) {
            console.log(chalk.cyan(`Validated ${response.blocksValidated} blocks in detail`));
          }
          if (response.validationTime) {
            console.log(chalk.cyan(`Total validation time: ${response.validationTime}ms`));
          }
        } else {
          console.log(chalk.red('❌ Full validation failed:'), response.error);
        }
      } else {
        console.log(chalk.red('❌ Unknown validation method. Use "checkpoint" or "full"'));
        console.log(chalk.gray('Available methods:'));
        console.log(chalk.gray('  checkpoint (fast) - Use checkpoints for fast validation'));
        console.log(chalk.gray('  full (complete)  - Validate every block in detail'));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   * Manage checkpoints
   * @param action
   * @param height
   */
  async manageCheckpoints(action, height) {
    try {
      const connected = await this.cli.checkDaemonConnection();
      if (!connected) {
        console.log(chalk.red('❌ Cannot connect to daemon. Make sure the daemon is running.'));
        return;
      }

      if (!action) {
        console.log(chalk.blue('🔍 Checkpoint Management:'));
        console.log(chalk.gray('Available actions:'));
        console.log(chalk.gray('  list     - Show all checkpoints'));
        console.log(chalk.gray('  add      - Add checkpoint at specific height'));
        console.log(chalk.gray('  update   - Update all checkpoints'));
        console.log(chalk.gray('  clear    - Clear all checkpoints'));
        return;
      }

      switch (action.toLowerCase()) {
        case 'list':
          await this.listCheckpoints();
          break;
        case 'add':
          if (!height) {
            console.log(chalk.red('❌ Usage: chain checkpoints add <height>'));
            return;
          }
          await this.addCheckpoint(parseInt(height));
          break;
        case 'update':
          await this.updateCheckpoints();
          break;
        case 'clear':
          await this.clearCheckpoints();
          break;
        default:
          console.log(chalk.red(`❌ Unknown checkpoint action: ${action}`));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async listCheckpoints() {
    try {
      const response = await this.cli.makeApiRequest('/api/blockchain/checkpoints');

      if (response.success && response.checkpoints) {
        console.log(chalk.blue('🔍 Current Checkpoints:'));
        response.checkpoints.forEach(cp => {
          const status = cp.hash ? chalk.green('✅ Active') : chalk.yellow('⏳ Pending');
          console.log(chalk.cyan(`Height ${cp.height}: ${status}`));
          if (cp.hash) {
            console.log(chalk.gray(`  Hash: ${cp.hash.substring(0, 16)}...`));
            if (cp.lastUpdated) {
              console.log(chalk.gray(`  Updated: ${new Date(cp.lastUpdated).toLocaleString()}`));
            }
          }
          if (cp.description) {
            console.log(chalk.gray(`  Description: ${cp.description}`));
          }
          console.log('');
        });
      } else {
        console.log(chalk.red('❌ Failed to get checkpoints'));
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   * @param height
   */
  async addCheckpoint(height) {
    try {
      const response = await this.cli.makeApiRequest('/api/blockchain/checkpoints/add', 'POST', { height });

      if (response.success) {
        console.log(chalk.green(`✅ Checkpoint added at height ${height}`));
        if (response.hash) {
          console.log(chalk.cyan(`Hash: ${response.hash.substring(0, 16)}...`));
        }
      } else {
        console.log(chalk.red('❌ Failed to add checkpoint:'), response.error);
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async updateCheckpoints() {
    try {
      const response = await this.cli.makeApiRequest('/api/blockchain/checkpoints/update', 'POST');

      if (response.success) {
        console.log(chalk.green('✅ Checkpoints updated successfully'));
        if (response.updated > 0) {
          console.log(chalk.cyan(`${response.updated} checkpoints were updated`));
        } else {
          console.log(chalk.cyan('No checkpoints needed updating'));
        }
      } else {
        console.log(chalk.red('❌ Failed to update checkpoints:'), response.error);
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }

  /**
   *
   */
  async clearCheckpoints() {
    try {
      const response = await this.cli.makeApiRequest('/api/blockchain/checkpoints/clear', 'POST');

      if (response.success) {
        console.log(chalk.green('✅ All checkpoints cleared successfully'));
      } else {
        console.log(chalk.red('❌ Failed to clear checkpoints:'), response.error);
      }
    } catch (error) {
      console.log(chalk.red(`❌ Error: ${error.message}`));
    }
  }
}

module.exports = NetworkManager;
