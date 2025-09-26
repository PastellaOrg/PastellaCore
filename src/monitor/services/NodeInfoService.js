const os = require('os');
const fs = require('fs');
const path = require('path');

const logger = require('../../utils/logger');
const { fromAtomicUnits } = require('../../utils/atomicUnits');

/**
 * NODE INFORMATION SERVICE
 *
 * Features:
 * 1. Node version, daemon uptime, and current status
 * 2. System resources (CPU usage, memory usage, disk space)
 * 3. Network ID and node identity information
 * 4. Configuration summary display
 * 5. Fork version and compatibility status
 */
class NodeInfoService {
  constructor(daemon) {
    this.daemon = daemon;
    this.startTime = Date.now();

    // System monitoring
    this.systemStats = {
      cpu: { usage: 0, cores: os.cpus().length },
      memory: { used: 0, total: os.totalmem(), usage: 0 },
      disk: { used: 0, total: 0, usage: 0 },
      uptime: os.uptime()
    };

    // Start system monitoring
    this.startSystemMonitoring();

    logger.debug('NODE_INFO_SERVICE', 'Node information service initialized');
  }

  /**
   * Feature 1: Node version, daemon uptime, and current status
   */
  getNodeVersion() {
    try {
      const packageJson = require('../../../package.json');

      return {
        version: packageJson.version,
        name: packageJson.name,
        description: packageJson.description,
        uptime: Date.now() - this.startTime,
        startTime: new Date(this.startTime).toISOString(),
        status: this.daemon.isRunning ? 'running' : 'stopped',
        processId: process.pid,
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        environment: process.env.NODE_ENV || 'development'
      };
    } catch (error) {
      logger.error('NODE_INFO_SERVICE', `Error getting node version: ${error.message}`);
      return {
        version: 'unknown',
        uptime: Date.now() - this.startTime,
        status: 'error',
        error: error.message
      };
    }
  }

  /**
   * Feature 2: System resources (CPU usage, memory usage, disk space)
   */
  getSystemResources() {
    return {
      cpu: {
        usage: this.systemStats.cpu.usage,
        cores: this.systemStats.cpu.cores,
        model: os.cpus()[0]?.model || 'Unknown',
        speed: os.cpus()[0]?.speed || 0,
        loadAverage: os.loadavg()
      },
      memory: {
        used: this.systemStats.memory.used,
        total: this.systemStats.memory.total,
        free: os.freemem(),
        usage: this.systemStats.memory.usage,
        available: os.freemem(),
        formatted: {
          used: this.formatBytes(this.systemStats.memory.used),
          total: this.formatBytes(this.systemStats.memory.total),
          free: this.formatBytes(os.freemem()),
          available: this.formatBytes(os.freemem())
        }
      },
      disk: {
        used: this.systemStats.disk.used,
        total: this.systemStats.disk.total,
        free: this.systemStats.disk.total - this.systemStats.disk.used,
        usage: this.systemStats.disk.usage,
        formatted: {
          used: this.formatBytes(this.systemStats.disk.used),
          total: this.formatBytes(this.systemStats.disk.total),
          free: this.formatBytes(this.systemStats.disk.total - this.systemStats.disk.used)
        }
      },
      uptime: {
        system: os.uptime(),
        process: process.uptime(),
        formatted: {
          system: this.formatUptime(os.uptime()),
          process: this.formatUptime(process.uptime())
        }
      }
    };
  }

  /**
   * Feature 3: Network ID and node identity information
   */
  getNetworkIdentity() {
    try {
      const config = this.daemon.blockchain?.config || {};
      const p2pNetwork = this.daemon.p2pNetwork;
      const nodeIdentity = p2pNetwork?.nodeIdentity;

      return {
        networkId: config.networkId || 'unknown',
        nodeId: nodeIdentity?.nodeId || 'unknown',
        publicKey: nodeIdentity?.publicKey || 'unknown',
        address: nodeIdentity?.address || 'unknown',
        listeningPort: config.network?.p2pPort || 0,
        apiPort: config.api?.port || 0,
        networkType: this.detectNetworkType(config.networkId),
        genesis: {
          hash: config.blockchain?.genesis?.hash || 'unknown',
          timestamp: config.blockchain?.genesis?.timestamp || 0,
          premineAddress: config.blockchain?.genesis?.premineAddress || 'unknown',
          premineAmount: config.blockchain?.genesis?.premineAmount ?
            fromAtomicUnits(config.blockchain.genesis.premineAmount) : 0
        }
      };
    } catch (error) {
      logger.error('NODE_INFO_SERVICE', `Error getting network identity: ${error.message}`);
      return {
        networkId: 'error',
        error: error.message
      };
    }
  }

  /**
   * Feature 4: Configuration summary display
   */
  getConfigurationSummary() {
    try {
      const config = this.daemon.blockchain?.config || {};

      return {
        basic: {
          name: config.name || 'Unknown',
          ticker: config.ticker || 'UNK',
          decimals: config.decimals || 8,
          networkId: config.networkId || 'unknown'
        },
        blockchain: {
          blockTime: config.blockchain?.blockTime || 60000,
          maxBlockSize: config.blockchain?.maxBlockSize || 1000000,
          coinbaseReward: config.blockchain?.coinbaseReward ?
            fromAtomicUnits(config.blockchain.coinbaseReward) : 0,
          halvingBlocks: config.blockchain?.halvingBlocks || 210000,
          difficultyAlgorithm: config.blockchain?.difficultyAlgorithm || 'unknown',
          difficultyBlocks: config.blockchain?.difficultyBlocks || 2016,
          algorithm: config.blockchain?.genesis?.algorithm || 'unknown'
        },
        network: {
          p2pPort: config.network?.p2pPort || 0,
          maxPeers: config.network?.maxPeers || 8,
          minSeedConnections: config.network?.minSeedConnections || 3,
          seedNodes: config.network?.seedNodes || [],
          enabled: config.network?.enabled !== false
        },
        api: {
          port: config.api?.port || 3000,
          enabled: config.api?.enabled !== false,
          rateLimit: config.api?.rateLimit || {}
        },
        storage: {
          dataDir: config.storage?.dataDir || './data',
          blockchainFile: config.storage?.blockchainFile || 'blockchain.json'
        },
        mining: {
          enabled: config.mining?.enabled || false,
          threads: config.mining?.threads || 1,
          algorithm: config.mining?.algorithm || config.blockchain?.genesis?.algorithm
        }
      };
    } catch (error) {
      logger.error('NODE_INFO_SERVICE', `Error getting configuration: ${error.message}`);
      return {
        error: error.message
      };
    }
  }

  /**
   * Feature 5: Fork version and compatibility status
   */
  getForkVersionStatus() {
    try {
      const forkManager = this.daemon.forkManager;

      if (!forkManager) {
        return {
          enabled: false,
          reason: 'Fork manager not available'
        };
      }

      const versionInfo = forkManager.getVersionInfo();
      const networkParticipation = forkManager.checkNetworkParticipation();
      const currentFork = forkManager.getCurrentFork();
      const allForks = (typeof forkManager.getAllForks === 'function') ?
        forkManager.getAllForks() : [];

      return {
        enabled: true,
        current: {
          version: versionInfo.version,
          minimumAcceptableVersion: versionInfo.minimumAcceptableVersion,
          forkName: versionInfo.forkName,
          features: versionInfo.features || []
        },
        participation: {
          canParticipate: networkParticipation.canParticipate,
          blockReason: networkParticipation.blockReason,
          upgradeRequired: networkParticipation.upgradeRequired
        },
        currentFork: currentFork ? {
          name: currentFork.name,
          description: currentFork.description,
          minimumVersion: currentFork.minimumVersion,
          features: currentFork.features || []
        } : null,
        allForks: allForks.map(fork => ({
          height: fork.height,
          name: fork.name,
          description: fork.description,
          minimumVersion: fork.minimumVersion,
          features: fork.features || [],
          active: fork === currentFork
        })),
        compatibility: {
          enforced: true,
          timeoutMs: 5000
        }
      };
    } catch (error) {
      logger.error('NODE_INFO_SERVICE', `Error getting fork version status: ${error.message}`);
      return {
        enabled: false,
        error: error.message
      };
    }
  }

  /**
   * Get complete node information (all features combined)
   */
  getCompleteNodeInfo() {
    return {
      version: this.getNodeVersion(),
      system: this.getSystemResources(),
      network: this.getNetworkIdentity(),
      config: this.getConfigurationSummary(),
      fork: this.getForkVersionStatus(),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Start system resource monitoring
   */
  startSystemMonitoring() {
    // Update system stats every 5 seconds
    setInterval(() => {
      this.updateSystemStats();
    }, 5000);

    // Initial update
    this.updateSystemStats();
  }

  /**
   * Update system statistics
   */
  updateSystemStats() {
    try {
      // Memory stats
      const memUsed = this.systemStats.memory.total - os.freemem();
      this.systemStats.memory.used = memUsed;
      this.systemStats.memory.usage = (memUsed / this.systemStats.memory.total) * 100;

      // CPU usage (simplified calculation)
      this.updateCPUUsage();

      // Disk usage
      this.updateDiskUsage();

    } catch (error) {
      logger.error('NODE_INFO_SERVICE', `Error updating system stats: ${error.message}`);
    }
  }

  /**
   * Update CPU usage
   */
  updateCPUUsage() {
    // This is a simplified CPU usage calculation
    // For production, you might want to use a more sophisticated method
    const cpus = os.cpus();
    let totalIdle = 0;
    let totalTick = 0;

    cpus.forEach(cpu => {
      for (let type in cpu.times) {
        totalTick += cpu.times[type];
      }
      totalIdle += cpu.times.idle;
    });

    const idle = totalIdle / cpus.length;
    const total = totalTick / cpus.length;
    const usage = 100 - ~~(100 * idle / total);

    this.systemStats.cpu.usage = Math.max(0, Math.min(100, usage));
  }

  /**
   * Update disk usage
   */
  updateDiskUsage() {
    try {
      const dataDir = this.daemon.blockchain?.dataDir || './data';
      const stats = fs.statSync(dataDir);

      // This is a simplified disk calculation
      // For actual disk space, you'd need platform-specific code
      this.systemStats.disk.used = this.getDirSize(dataDir);
      this.systemStats.disk.total = Math.max(this.systemStats.disk.used, 1000000000); // Default 1GB minimum
      this.systemStats.disk.usage = (this.systemStats.disk.used / this.systemStats.disk.total) * 100;
    } catch (error) {
      // Fallback values
      this.systemStats.disk.used = 0;
      this.systemStats.disk.total = 1000000000;
      this.systemStats.disk.usage = 0;
    }
  }

  /**
   * Get directory size recursively
   */
  getDirSize(dirPath) {
    try {
      let size = 0;
      const files = fs.readdirSync(dirPath);

      files.forEach(file => {
        const filePath = path.join(dirPath, file);
        const stats = fs.statSync(filePath);

        if (stats.isDirectory()) {
          size += this.getDirSize(filePath);
        } else {
          size += stats.size;
        }
      });

      return size;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Detect network type from network ID
   */
  detectNetworkType(networkId) {
    if (!networkId) return 'unknown';

    if (networkId.includes('mainnet') || networkId.includes('pastella-14082025')) {
      return 'mainnet';
    } else if (networkId.includes('testnet')) {
      return 'testnet';
    } else if (networkId.includes('devnet') || networkId.includes('dev')) {
      return 'devnet';
    } else {
      return 'custom';
    }
  }

  /**
   * Format bytes to human readable format
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 B';

    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Format uptime to human readable format
   */
  formatUptime(seconds) {
    const days = Math.floor(seconds / (24 * 60 * 60));
    const hours = Math.floor((seconds % (24 * 60 * 60)) / (60 * 60));
    const minutes = Math.floor((seconds % (60 * 60)) / 60);
    const secs = Math.floor(seconds % 60);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

    return parts.join(' ');
  }
}

module.exports = NodeInfoService;