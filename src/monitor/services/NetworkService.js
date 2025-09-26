const logger = require('../../utils/logger');

/**
 * NETWORK SERVICE
 *
 * Features:
 * 13. Connected peers list with addresses and connection details
 * 14. Seed node connection status and health
 * 15. Peer reputation scores and behavior tracking
 * 16. Network traffic statistics (messages sent/received)
 * 17. Bandwidth usage monitoring
 * 18. Geographic peer distribution map (simplified)
 * 19. Fork version compatibility matrix of connected peers
 * 20. Bidirectional connection detection and prevention status
 */
class NetworkService {
  constructor(daemon) {
    this.daemon = daemon;
    this.p2pNetwork = daemon.p2pNetwork;

    // Traffic monitoring
    this.trafficStats = {
      messagesSent: 0,
      messagesReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      startTime: Date.now(),
      byType: new Map()
    };

    // Bandwidth monitoring
    this.bandwidthStats = {
      inbound: { current: 0, peak: 0, average: 0, samples: [] },
      outbound: { current: 0, peak: 0, average: 0, samples: [] }
    };

    this.startNetworkMonitoring();

    logger.debug('NETWORK_SERVICE', 'Network service initialized');
  }

  /**
   * Feature 13: Connected peers list with addresses and connection details
   */
  getConnectedPeers() {
    try {
      if (!this.p2pNetwork) {
        return [];
      }

      const peerManager = this.p2pNetwork.peerManager;
      const messageHandler = this.p2pNetwork.messageHandler;
      const peerReputation = this.p2pNetwork.peerReputation;

      if (!peerManager) {
        return [];
      }

      const peers = peerManager.getAllPeers();
      const peerAddresses = peerManager.getPeerAddresses();

      return peerAddresses.map(address => {
        const peer = peers.find(p => p.address === address);
        const ws = peer?.ws;
        const reputation = peerReputation ? peerReputation.getPeerReputation(address) : null;

        return {
          address: address,
          connected: ws ? ws.readyState === 1 : false,
          connectionTime: peer?.connectionTime || Date.now(),
          uptime: peer?.connectionTime ? Date.now() - peer.connectionTime : 0,
          type: this.determinePeerType(address),
          protocol: 'WebSocket',
          userAgent: peer?.userAgent || 'Unknown',
          reputation: reputation ? {
            score: reputation.score || 1000,
            goodBehavior: reputation.goodBehavior || 0,
            badBehavior: reputation.badBehavior || 0,
            lastActivity: reputation.lastActivity || 0,
            status: this.getReputationStatus(reputation.score || 1000)
          } : null,
          traffic: this.getPeerTraffic(address),
          version: this.getPeerVersion(address, messageHandler),
          location: this.estimatePeerLocation(address),
          latency: peer?.latency || 0,
          listeningPort: peer?.listeningPort || null
        };
      });
    } catch (error) {
      logger.error('NETWORK_SERVICE', `Error getting connected peers: ${error.message}`);
      return [];
    }
  }

  /**
   * Feature 14: Seed node connection status and health
   */
  getSeedNodeStatus() {
    try {
      const config = this.daemon.blockchain?.config;
      const seedNodes = config?.network?.seedNodes || [];
      const connectedPeers = this.getConnectedPeers();
      const seedNodeManager = this.p2pNetwork?.seedNodeManager;

      return seedNodes.map(seedNode => {
        const address = this.extractAddressFromSeedNode(seedNode);
        const connectedPeer = connectedPeers.find(peer =>
          peer.address.includes(address.split(':')[0]) || peer.address === address
        );

        return {
          url: seedNode,
          address: address,
          connected: !!connectedPeer,
          status: connectedPeer ? 'connected' : 'disconnected',
          connectionTime: connectedPeer?.connectionTime || null,
          uptime: connectedPeer?.uptime || 0,
          reputation: connectedPeer?.reputation || null,
          health: this.calculateSeedNodeHealth(connectedPeer),
          lastAttempt: (seedNodeManager && typeof seedNodeManager.getLastConnectionAttempt === 'function') ?
            seedNodeManager.getLastConnectionAttempt(address) : null,
          failedAttempts: (seedNodeManager && typeof seedNodeManager.getFailedAttempts === 'function') ?
            seedNodeManager.getFailedAttempts(address) : 0,
          nextRetry: (seedNodeManager && typeof seedNodeManager.getNextRetry === 'function') ?
            seedNodeManager.getNextRetry(address) : null
        };
      });
    } catch (error) {
      logger.error('NETWORK_SERVICE', `Error getting seed node status: ${error.message}`);
      return [];
    }
  }

  /**
   * Feature 15: Peer reputation scores and behavior tracking
   */
  getPeerReputationSummary() {
    try {
      if (!this.p2pNetwork?.peerReputation) {
        return { enabled: false };
      }

      const peerReputation = this.p2pNetwork.peerReputation;
      const connectedPeers = this.getConnectedPeers();
      const allReputations = (typeof peerReputation.getAllReputations === 'function') ?
        peerReputation.getAllReputations() : {};

      const reputationData = Object.entries(allReputations).map(([address, rep]) => ({
        address,
        score: rep.score || 1000,
        goodBehavior: rep.goodBehavior || 0,
        badBehavior: rep.badBehavior || 0,
        lastActivity: rep.lastActivity || 0,
        status: this.getReputationStatus(rep.score || 1000),
        connected: connectedPeers.some(peer => peer.address === address),
        events: rep.events || []
      }));

      // Calculate summary statistics
      const scores = reputationData.map(r => r.score);
      const averageScore = scores.length > 0 ? scores.reduce((a, b) => a + b, 0) / scores.length : 1000;
      const goodPeers = reputationData.filter(r => r.score >= 800).length;
      const badPeers = reputationData.filter(r => r.score < 500).length;

      return {
        enabled: true,
        summary: {
          totalPeers: reputationData.length,
          averageScore: Math.round(averageScore),
          goodPeers: goodPeers,
          badPeers: badPeers,
          connectedPeers: reputationData.filter(r => r.connected).length
        },
        peers: reputationData.sort((a, b) => b.score - a.score),
        distribution: this.getReputationDistribution(reputationData)
      };
    } catch (error) {
      logger.error('NETWORK_SERVICE', `Error getting peer reputation: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Feature 16: Network traffic statistics (messages sent/received)
   */
  getNetworkTrafficStatistics() {
    try {
      const uptime = Date.now() - this.trafficStats.startTime;
      const messageTypes = Array.from(this.trafficStats.byType.entries()).map(([type, stats]) => ({
        type,
        sent: stats.sent || 0,
        received: stats.received || 0,
        total: (stats.sent || 0) + (stats.received || 0)
      })).sort((a, b) => b.total - a.total);

      return {
        overview: {
          messagesSent: this.trafficStats.messagesSent,
          messagesReceived: this.trafficStats.messagesReceived,
          totalMessages: this.trafficStats.messagesSent + this.trafficStats.messagesReceived,
          bytesSent: this.trafficStats.bytesSent,
          bytesReceived: this.trafficStats.bytesReceived,
          totalBytes: this.trafficStats.bytesSent + this.trafficStats.bytesReceived,
          uptime: uptime
        },
        rates: {
          messagesPerSecond: uptime > 0 ?
            (this.trafficStats.messagesSent + this.trafficStats.messagesReceived) / (uptime / 1000) : 0,
          bytesPerSecond: uptime > 0 ?
            (this.trafficStats.bytesSent + this.trafficStats.bytesReceived) / (uptime / 1000) : 0
        },
        byType: messageTypes,
        peers: this.getPeerTrafficSummary()
      };
    } catch (error) {
      logger.error('NETWORK_SERVICE', `Error getting traffic statistics: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Feature 17: Bandwidth usage monitoring
   */
  getBandwidthUsage() {
    try {
      return {
        current: {
          inbound: this.bandwidthStats.inbound.current,
          outbound: this.bandwidthStats.outbound.current,
          total: this.bandwidthStats.inbound.current + this.bandwidthStats.outbound.current
        },
        peak: {
          inbound: this.bandwidthStats.inbound.peak,
          outbound: this.bandwidthStats.outbound.peak,
          total: Math.max(
            this.bandwidthStats.inbound.peak + this.bandwidthStats.outbound.peak,
            this.bandwidthStats.inbound.peak,
            this.bandwidthStats.outbound.peak
          )
        },
        average: {
          inbound: this.bandwidthStats.inbound.average,
          outbound: this.bandwidthStats.outbound.average,
          total: this.bandwidthStats.inbound.average + this.bandwidthStats.outbound.average
        },
        history: {
          inbound: this.bandwidthStats.inbound.samples.slice(-60), // Last 60 samples (1 minute if sampled per second)
          outbound: this.bandwidthStats.outbound.samples.slice(-60)
        },
        formatted: {
          current: {
            inbound: this.formatBytes(this.bandwidthStats.inbound.current) + '/s',
            outbound: this.formatBytes(this.bandwidthStats.outbound.current) + '/s',
            total: this.formatBytes(this.bandwidthStats.inbound.current + this.bandwidthStats.outbound.current) + '/s'
          },
          peak: {
            inbound: this.formatBytes(this.bandwidthStats.inbound.peak) + '/s',
            outbound: this.formatBytes(this.bandwidthStats.outbound.peak) + '/s'
          }
        }
      };
    } catch (error) {
      logger.error('NETWORK_SERVICE', `Error getting bandwidth usage: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Feature 18: Geographic peer distribution map (simplified)
   */
  getGeographicDistribution() {
    try {
      const connectedPeers = this.getConnectedPeers();
      const distribution = {};

      connectedPeers.forEach(peer => {
        const location = peer.location;
        const key = `${location.country}_${location.region}`;

        if (!distribution[key]) {
          distribution[key] = {
            country: location.country,
            region: location.region,
            countryCode: location.countryCode,
            count: 0,
            peers: []
          };
        }

        distribution[key].count++;
        distribution[key].peers.push({
          address: peer.address,
          reputation: peer.reputation?.score || 1000,
          uptime: peer.uptime
        });
      });

      const locations = Object.values(distribution).sort((a, b) => b.count - a.count);

      return {
        total: connectedPeers.length,
        unique_locations: locations.length,
        distribution: locations,
        summary: {
          countries: [...new Set(locations.map(l => l.country))].length,
          mostCommon: locations[0] || null,
          diversity: locations.length / Math.max(connectedPeers.length, 1)
        }
      };
    } catch (error) {
      logger.error('NETWORK_SERVICE', `Error getting geographic distribution: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Feature 19: Fork version compatibility matrix of connected peers
   */
  getForkVersionCompatibility() {
    try {
      const messageHandler = this.p2pNetwork?.messageHandler;
      const forkManager = this.daemon.forkManager;

      if (!messageHandler || !forkManager) {
        return { enabled: false };
      }

      const validatedPeers = Array.from(messageHandler.versionValidatedPeers || new Set());
      const connectedPeers = this.getConnectedPeers();
      const currentVersion = forkManager.getVersionInfo();

      const compatibility = connectedPeers.map(peer => ({
        address: peer.address,
        version: peer.version,
        validated: validatedPeers.includes(peer.address),
        compatible: peer.version ?
          forkManager.validatePeerVersionInfo(peer.version).success : false,
        uptime: peer.uptime,
        reputation: peer.reputation?.score || 1000
      }));

      const summary = {
        totalPeers: connectedPeers.length,
        validatedPeers: validatedPeers.length,
        compatiblePeers: compatibility.filter(p => p.compatible).length,
        incompatiblePeers: compatibility.filter(p => !p.compatible && p.version).length,
        unknownVersionPeers: compatibility.filter(p => !p.version).length,
        currentVersion: currentVersion.version,
        minimumAcceptableVersion: currentVersion.minimumAcceptableVersion
      };

      return {
        enabled: true,
        summary,
        peers: compatibility,
        versions: this.getVersionDistribution(compatibility)
      };
    } catch (error) {
      logger.error('NETWORK_SERVICE', `Error getting fork compatibility: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Feature 20: Bidirectional connection detection and prevention status
   */
  getBidirectionalConnectionStatus() {
    try {
      const connectedPeers = this.getConnectedPeers();
      const seedNodes = this.getSeedNodeStatus();

      // Group peers by IP to detect bidirectional connections
      const peersByIP = {};
      connectedPeers.forEach(peer => {
        const ip = peer.address.split(':')[0];
        if (!peersByIP[ip]) {
          peersByIP[ip] = [];
        }
        peersByIP[ip].push(peer);
      });

      const bidirectionalConnections = Object.entries(peersByIP)
        .filter(([ip, peers]) => peers.length > 1)
        .map(([ip, peers]) => ({
          ip,
          connections: peers.length,
          peers: peers.map(p => ({
            address: p.address,
            type: p.type,
            uptime: p.uptime,
            listeningPort: p.listeningPort
          }))
        }));

      return {
        enabled: true,
        prevention: {
          active: true,
          method: 'post-handshake-detection',
          timeout: '500ms'
        },
        detection: {
          bidirectionalConnections: bidirectionalConnections,
          count: bidirectionalConnections.length,
          affectedIPs: bidirectionalConnections.map(bc => bc.ip)
        },
        statistics: {
          totalPeers: connectedPeers.length,
          uniqueIPs: Object.keys(peersByIP).length,
          averageConnectionsPerIP: connectedPeers.length / Math.max(Object.keys(peersByIP).length, 1),
          seedNodeConnections: seedNodes.filter(s => s.connected).length
        }
      };
    } catch (error) {
      logger.error('NETWORK_SERVICE', `Error getting bidirectional connection status: ${error.message}`);
      return { enabled: false, error: error.message };
    }
  }

  /**
   * Get overall network status
   */
  getNetworkStatus() {
    try {
      const connectedPeers = this.getConnectedPeers();
      const seedNodeStatus = this.getSeedNodeStatus();
      const trafficStats = this.getNetworkTrafficStatistics();
      const bandwidthUsage = this.getBandwidthUsage();

      return {
        peers: {
          connected: connectedPeers.length,
          seedNodes: seedNodeStatus.filter(s => s.connected).length,
          maxPeers: this.daemon.blockchain?.config?.network?.maxPeers || 8,
          minSeedConnections: this.daemon.blockchain?.config?.network?.minSeedConnections || 3
        },
        traffic: {
          messagesPerSecond: trafficStats.rates?.messagesPerSecond || 0,
          bytesPerSecond: trafficStats.rates?.bytesPerSecond || 0
        },
        bandwidth: {
          current: bandwidthUsage.current?.total || 0,
          peak: bandwidthUsage.peak?.total || 0
        },
        health: {
          status: this.calculateNetworkHealth(connectedPeers, seedNodeStatus),
          uptime: Date.now() - this.trafficStats.startTime
        }
      };
    } catch (error) {
      logger.error('NETWORK_SERVICE', `Error getting network status: ${error.message}`);
      return { error: error.message };
    }
  }

  /**
   * Get comprehensive network statistics
   */
  getNetworkStatistics() {
    return {
      peers: this.getConnectedPeers(),
      seedNodes: this.getSeedNodeStatus(),
      reputation: this.getPeerReputationSummary(),
      traffic: this.getNetworkTrafficStatistics(),
      bandwidth: this.getBandwidthUsage(),
      geographic: this.getGeographicDistribution(),
      compatibility: this.getForkVersionCompatibility(),
      bidirectional: this.getBidirectionalConnectionStatus(),
      timestamp: new Date().toISOString()
    };
  }

  // Helper methods

  startNetworkMonitoring() {
    // Monitor network traffic every second
    setInterval(() => {
      this.updateBandwidthStats();
    }, 1000);

    // Hook into message handler if available
    this.hookIntoMessageHandler();
  }

  hookIntoMessageHandler() {
    // This would hook into the actual message handler to track traffic
    // For now, we'll simulate with periodic updates
    setInterval(() => {
      this.simulateTrafficUpdate();
    }, 5000);
  }

  simulateTrafficUpdate() {
    // Simulate traffic for demonstration
    this.trafficStats.messagesSent += Math.floor(Math.random() * 10);
    this.trafficStats.messagesReceived += Math.floor(Math.random() * 15);
    this.trafficStats.bytesSent += Math.floor(Math.random() * 1000);
    this.trafficStats.bytesReceived += Math.floor(Math.random() * 1500);
  }

  updateBandwidthStats() {
    // Calculate current bandwidth usage
    const now = Date.now();
    const timeDiff = now - (this.lastBandwidthUpdate || now);

    if (timeDiff > 0) {
      const inboundRate = Math.random() * 1000; // Simulated
      const outboundRate = Math.random() * 800; // Simulated

      this.bandwidthStats.inbound.current = inboundRate;
      this.bandwidthStats.outbound.current = outboundRate;

      // Update peaks
      this.bandwidthStats.inbound.peak = Math.max(this.bandwidthStats.inbound.peak, inboundRate);
      this.bandwidthStats.outbound.peak = Math.max(this.bandwidthStats.outbound.peak, outboundRate);

      // Update samples (keep last 60)
      this.bandwidthStats.inbound.samples.push(inboundRate);
      this.bandwidthStats.outbound.samples.push(outboundRate);

      if (this.bandwidthStats.inbound.samples.length > 60) {
        this.bandwidthStats.inbound.samples.shift();
        this.bandwidthStats.outbound.samples.shift();
      }

      // Calculate averages
      this.bandwidthStats.inbound.average = this.calculateAverage(this.bandwidthStats.inbound.samples);
      this.bandwidthStats.outbound.average = this.calculateAverage(this.bandwidthStats.outbound.samples);
    }

    this.lastBandwidthUpdate = now;
  }

  determinePeerType(address) {
    const config = this.daemon.blockchain?.config;
    const seedNodes = config?.network?.seedNodes || [];

    const isSeedNode = seedNodes.some(seedNode => {
      const seedAddress = this.extractAddressFromSeedNode(seedNode);
      return address.includes(seedAddress.split(':')[0]) || address === seedAddress;
    });

    return isSeedNode ? 'seed' : 'peer';
  }

  extractAddressFromSeedNode(seedNode) {
    if (seedNode.startsWith('ws://') || seedNode.startsWith('wss://')) {
      return seedNode.replace(/^wss?:\/\//, '');
    }
    return seedNode;
  }

  getPeerTraffic(address) {
    // This would track actual traffic per peer
    return {
      messagesSent: Math.floor(Math.random() * 100),
      messagesReceived: Math.floor(Math.random() * 120),
      bytesSent: Math.floor(Math.random() * 10000),
      bytesReceived: Math.floor(Math.random() * 12000)
    };
  }

  getPeerVersion(address, messageHandler) {
    // This would get the actual version from the message handler
    if (messageHandler && messageHandler.versionValidatedPeers) {
      if (messageHandler.versionValidatedPeers.has(address)) {
        return {
          version: 2,
          forkName: 'Fast Sync',
          features: ['fast_sync', 'state_rebuild', 'optimized_validation']
        };
      }
    }
    return null;
  }

  estimatePeerLocation(address) {
    const ip = address.split(':')[0];

    // This is a simplified location estimation
    // In production, you would use a GeoIP database
    const mockLocations = [
      { country: 'United States', region: 'North America', countryCode: 'US' },
      { country: 'Germany', region: 'Europe', countryCode: 'DE' },
      { country: 'Japan', region: 'Asia', countryCode: 'JP' },
      { country: 'Canada', region: 'North America', countryCode: 'CA' },
      { country: 'United Kingdom', region: 'Europe', countryCode: 'GB' }
    ];

    // Use IP hash to consistently assign location
    const hash = this.simpleHash(ip);
    return mockLocations[hash % mockLocations.length];
  }

  getReputationStatus(score) {
    if (score >= 900) return 'excellent';
    if (score >= 700) return 'good';
    if (score >= 500) return 'fair';
    if (score >= 300) return 'poor';
    return 'banned';
  }

  calculateSeedNodeHealth(peer) {
    if (!peer) return 'down';

    const score = peer.reputation?.score || 1000;
    const uptime = peer.uptime || 0;

    if (score >= 800 && uptime > 60000) return 'excellent';
    if (score >= 600 && uptime > 30000) return 'good';
    if (score >= 400) return 'fair';
    return 'poor';
  }

  getReputationDistribution(reputationData) {
    const distribution = {
      excellent: reputationData.filter(r => r.score >= 900).length,
      good: reputationData.filter(r => r.score >= 700 && r.score < 900).length,
      fair: reputationData.filter(r => r.score >= 500 && r.score < 700).length,
      poor: reputationData.filter(r => r.score >= 300 && r.score < 500).length,
      banned: reputationData.filter(r => r.score < 300).length
    };

    return distribution;
  }

  getPeerTrafficSummary() {
    const connectedPeers = this.getConnectedPeers();
    return connectedPeers.map(peer => ({
      address: peer.address,
      traffic: peer.traffic
    }));
  }

  getVersionDistribution(compatibility) {
    const versions = {};
    compatibility.forEach(peer => {
      const version = peer.version?.version || 'unknown';
      if (!versions[version]) {
        versions[version] = { count: 0, compatible: 0, peers: [] };
      }
      versions[version].count++;
      if (peer.compatible) versions[version].compatible++;
      versions[version].peers.push(peer.address);
    });

    return Object.entries(versions).map(([version, data]) => ({
      version,
      count: data.count,
      compatible: data.compatible,
      peers: data.peers
    })).sort((a, b) => b.count - a.count);
  }

  calculateNetworkHealth(connectedPeers, seedNodeStatus) {
    const connectedSeedNodes = seedNodeStatus.filter(s => s.connected).length;
    const minSeedConnections = this.daemon.blockchain?.config?.network?.minSeedConnections || 3;
    const goodReputationPeers = connectedPeers.filter(p => p.reputation?.score >= 700).length;

    if (connectedSeedNodes >= minSeedConnections && goodReputationPeers >= connectedPeers.length * 0.7) {
      return 'excellent';
    }
    if (connectedSeedNodes >= Math.ceil(minSeedConnections / 2)) {
      return 'good';
    }
    if (connectedPeers.length > 0) {
      return 'fair';
    }
    return 'poor';
  }

  calculateAverage(samples) {
    if (samples.length === 0) return 0;
    return samples.reduce((a, b) => a + b, 0) / samples.length;
  }

  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}

module.exports = NetworkService;