const fs = require('fs');
const path = require('path');

/**
 * Load configuration file from the correct location
 * - When running as compiled executable (pkg), reads from bundled config.json
 * - When running with Node.js, reads from project root config.json
 * @param {string} customPath - Optional custom path to config file
 * @returns {Object} Configuration object
 */
function loadConfig(customPath = null) {
  let configPath;

  if (customPath) {
    // Use custom path if provided
    configPath = path.resolve(customPath);
  } else if (process.pkg) {
    // Running as compiled executable - read from snapshot
    configPath = path.join(path.dirname(process.execPath), 'config.json');

    // First try to load from external config.json next to executable
    if (fs.existsSync(configPath)) {
      console.log(`Loading config from: ${configPath}`);
    } else {
      // Fall back to bundled config.json inside executable
      configPath = path.join(__dirname, '../../config.json');
      console.log('Using bundled config.json from executable');
    }
  } else {
    // Running with Node.js - read from project root
    configPath = path.join(process.cwd(), 'config.json');
  }

  try {
    const configData = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(configData);
  } catch (error) {
    console.error(`Error loading config from ${configPath}:`, error.message);
    throw new Error(`Failed to load configuration file: ${error.message}`);
  }
}

/**
 * Load package.json metadata
 * @returns {Object} Package metadata
 */
function loadPackageJson() {
  try {
    if (process.pkg) {
      // Running as compiled executable - return embedded version info
      return {
        name: 'pastella-cryptocurrency',
        version: '1.0.0',
        description: 'Pastella (PAS) - A NodeJS cryptocurrency implementation'
      };
    } else {
      // Running with Node.js - read actual package.json
      const packagePath = path.join(process.cwd(), 'package.json');
      return JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    }
  } catch (error) {
    console.error('Error loading package.json:', error.message);
    return {
      name: 'pastella-cryptocurrency',
      version: '1.0.0',
      description: 'Pastella (PAS) - A NodeJS cryptocurrency implementation'
    };
  }
}

module.exports = {
  loadConfig,
  loadPackageJson
};
