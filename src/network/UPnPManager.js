const natUpnp = require('nat-upnp');
const https = require('https');
const http = require('http');
const logger = require('../utils/logger');

/**
 * UPnP Manager for automatic port mapping and public IP discovery
 *
 * Features:
 * 1. Detects public IP using multiple fallback services
 * 2. Automatically maps router ports using UPnP
 * 3. Periodic renewal to keep mappings active
 * 4. Graceful error handling and fallback strategies
 * 5. Clean shutdown with proper port cleanup
 */
class UPnPManager {
  constructor(internalPort = 23000, externalPort = 23000) {
    this.internalPort = internalPort;
    this.externalPort = externalPort;
    this.client = null;
    this.publicIP = null;
    this.isEnabled = false;
    this.mappingActive = false;

    // Renewal settings
    this.renewalInterval = null;
    this.renewalIntervalMs = 12 * 60 * 60 * 1000; // 12 hours
    this.leaseTime = 24 * 60 * 60; // 24 hours in seconds

    // Public IP detection services (with fallbacks)
    this.ipDetectionServices = [
      'https://api.ipify.org',
      'https://icanhazip.com/s',
      'https://ifconfig.me/ip',
      'http://ipv4.icanhazip.com',
      'https://httpbin.org/ip'
    ];

    // Cache public IP to avoid excessive requests
    this.ipCacheTime = 30 * 60 * 1000; // 30 minutes
    this.lastIPCheck = 0;
  }

  /**
   * Initialize UPnP manager and attempt port mapping
   */
  async initialize() {
    try {
      logger.info('UPNP', 'Initializing UPnP manager...');

      // Create UPnP client
      this.client = natUpnp.createClient();

      // Detect public IP first
      await this.detectPublicIP();

      // Attempt port mapping
      await this.createPortMapping();

      // Start periodic renewal if mapping successful
      if (this.mappingActive) {
        this.startPeriodicRenewal();
        this.isEnabled = true;
        logger.info('UPNP', `UPnP successfully initialized. External address: ${this.publicIP}:${this.externalPort}`);
      }

      return this.isEnabled;
    } catch (error) {
      logger.warn('UPNP', `UPnP initialization failed: ${error.message}`);
      this.isEnabled = false;
      return false;
    }
  }

  /**
   * Detect public IP address using multiple fallback services
   */
  async detectPublicIP() {
    // Use cached IP if still valid
    if (this.publicIP && (Date.now() - this.lastIPCheck) < this.ipCacheTime) {
      logger.debug('UPNP', `Using cached public IP: ${this.publicIP}`);
      return this.publicIP;
    }

    for (const service of this.ipDetectionServices) {
      try {
        logger.debug('UPNP', `Detecting public IP using: ${service}`);

        const ip = await this.fetchPublicIP(service);
        if (this.isValidIPv4(ip)) {
          this.publicIP = ip;
          this.lastIPCheck = Date.now();
          logger.info('UPNP', `Detected public IP: ${this.publicIP}`);
          return this.publicIP;
        }
      } catch (error) {
        logger.debug('UPNP', `IP detection failed for ${service}: ${error.message}`);
        continue;
      }
    }

    throw new Error('Failed to detect public IP from all services');
  }

  /**
   * Fetch public IP from a specific service
   */
  fetchPublicIP(url) {
    return new Promise((resolve, reject) => {
      const isHttps = url.startsWith('https://');
      const client = isHttps ? https : http;

      const options = {
        timeout: 5000,
        headers: {
          'User-Agent': 'Pastella-Node/1.0'
        }
      };

      const req = client.get(url, options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            // Handle different response formats
            let ip = data.trim();

            // Some services return JSON
            if (data.startsWith('{')) {
              const parsed = JSON.parse(data);
              ip = parsed.ip || parsed.origin || parsed.query;
            }

            // Extract IP from potential HTML/text response
            const ipMatch = ip.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
            if (ipMatch) {
              resolve(ipMatch[1]);
            } else {
              reject(new Error('No valid IP found in response'));
            }
          } catch (error) {
            reject(new Error(`Failed to parse response: ${error.message}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.setTimeout(5000);
    });
  }

  /**
   * Validate IPv4 address format
   */
  isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;

    return parts.every(part => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255 && part === num.toString();
    });
  }

  /**
   * Create UPnP port mapping
   */
  async createPortMapping() {
    if (!this.client) {
      throw new Error('UPnP client not initialized');
    }

    try {
      logger.info('UPNP', `Creating port mapping: ${this.externalPort} → ${this.internalPort}`);

      // Create port mapping with lease time
      await new Promise((resolve, reject) => {
        this.client.portMapping({
          public: this.externalPort,
          private: this.internalPort,
          ttl: this.leaseTime,
          description: 'Pastella P2P Node'
        }, (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });

      // Verify mapping was created
      await this.verifyPortMapping();

      this.mappingActive = true;
      logger.info('UPNP', `Port mapping created successfully: ${this.externalPort} → ${this.internalPort}`);

    } catch (error) {
      logger.warn('UPNP', `Failed to create port mapping: ${error.message}`);
      throw error;
    }
  }

  /**
   * Verify that port mapping exists and is working
   */
  async verifyPortMapping() {
    if (!this.client) return false;

    try {
      const mappings = await new Promise((resolve, reject) => {
        this.client.getMappings((error, results) => {
          if (error) {
            reject(error);
          } else {
            resolve(results || []);
          }
        });
      });

      // Check if our mapping exists
      const ourMapping = mappings.find(mapping =>
        mapping.public.port === this.externalPort &&
        mapping.private.port === this.internalPort
      );

      if (ourMapping) {
        logger.debug('UPNP', `Port mapping verified: ${JSON.stringify(ourMapping)}`);
        return true;
      } else {
        logger.warn('UPNP', 'Port mapping not found in router mappings');
        return false;
      }
    } catch (error) {
      logger.debug('UPNP', `Failed to verify port mapping: ${error.message}`);
      return false;
    }
  }

  /**
   * Start periodic renewal of port mapping
   */
  startPeriodicRenewal() {
    if (this.renewalInterval) {
      clearInterval(this.renewalInterval);
    }

    this.renewalInterval = setInterval(async () => {
      try {
        logger.debug('UPNP', 'Renewing port mapping...');

        // Check if mapping still exists
        const isValid = await this.verifyPortMapping();

        if (!isValid) {
          logger.warn('UPNP', 'Port mapping lost, recreating...');
          await this.createPortMapping();
        } else {
          // Renew the mapping
          await this.createPortMapping();
          logger.debug('UPNP', 'Port mapping renewed successfully');
        }

        // Also refresh public IP periodically
        await this.detectPublicIP();

      } catch (error) {
        logger.error('UPNP', `Failed to renew port mapping: ${error.message}`);
        // Don't disable UPnP entirely on renewal failure
        // The mapping might still be active
      }
    }, this.renewalIntervalMs);

    logger.debug('UPNP', `Started periodic renewal every ${this.renewalIntervalMs / 1000 / 60} minutes`);
  }

  /**
   * Get the external address that other peers can connect to
   */
  getExternalAddress() {
    if (this.isEnabled && this.publicIP && this.mappingActive) {
      return `${this.publicIP}:${this.externalPort}`;
    }
    return null;
  }

  /**
   * Check if UPnP is available and working
   */
  isAvailable() {
    return this.isEnabled && this.mappingActive;
  }

  /**
   * Get current status information
   */
  getStatus() {
    return {
      enabled: this.isEnabled,
      mappingActive: this.mappingActive,
      publicIP: this.publicIP,
      externalPort: this.externalPort,
      internalPort: this.internalPort,
      externalAddress: this.getExternalAddress(),
      lastIPCheck: new Date(this.lastIPCheck).toISOString()
    };
  }

  /**
   * Clean shutdown - remove port mappings
   */
  async shutdown() {
    logger.info('UPNP', 'Shutting down UPnP manager...');

    // Stop renewal timer
    if (this.renewalInterval) {
      clearInterval(this.renewalInterval);
      this.renewalInterval = null;
    }

    // Remove port mapping
    if (this.client && this.mappingActive) {
      try {
        await new Promise((resolve, reject) => {
          this.client.portUnmapping({
            public: this.externalPort,
            private: this.internalPort
          }, (error) => {
            if (error) {
              reject(error);
            } else {
              resolve();
            }
          });
        });

        logger.info('UPNP', 'Port mapping removed successfully');
      } catch (error) {
        logger.warn('UPNP', `Failed to remove port mapping: ${error.message}`);
      }
    }

    // Reset state
    this.isEnabled = false;
    this.mappingActive = false;
    this.client = null;

    logger.info('UPNP', 'UPnP manager shutdown complete');
  }
}

module.exports = UPnPManager;