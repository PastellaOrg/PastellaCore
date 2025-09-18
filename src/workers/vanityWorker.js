const { parentPort, workerData } = require('worker_threads');
const Wallet = require('../models/Wallet');

/**
 * Vanity address worker thread
 * Generates wallets until finding one matching the target pattern
 */

const { targetPattern, workerId } = workerData;

let attempts = 0;
let found = false;
const startTime = Date.now();

// Report progress every 1000 attempts
const reportInterval = 1000;

try {
  while (!found) {
    attempts++;

    // Generate a new wallet
    const wallet = new Wallet();
    wallet.generateKeyPair();

    // Check if address matches pattern
    const address = wallet.getAddress();
    if (address.toLowerCase().startsWith(`1${targetPattern.toLowerCase()}`)) {
      // Found matching address!
      parentPort.postMessage({
        type: 'success',
        workerId,
        attempts,
        wallet: {
          address: wallet.getAddress(),
          privateKey: wallet.privateKey,
          publicKey: wallet.publicKey,
          seed: wallet.getSeed()
        },
        elapsedTime: Date.now() - startTime
      });
      found = true;
      break;
    }

    // Report progress periodically
    if (attempts % reportInterval === 0) {
      parentPort.postMessage({
        type: 'progress',
        workerId,
        attempts,
        elapsedTime: Date.now() - startTime
      });
    }
  }
} catch (error) {
  parentPort.postMessage({
    type: 'error',
    workerId,
    error: error.message,
    attempts,
    elapsedTime: Date.now() - startTime
  });
}