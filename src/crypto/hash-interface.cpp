#include "hash.h"
#include <mutex>
#include <cstring>

namespace Crypto {
    // Global blockchain interface for RandomX seed hash access
    // This will be set by the daemon during initialization
    std::function<Crypto::Hash(uint32_t)> g_getBlockHashByIndex;

    // Mutex for thread-safe access to blockchain interface
    std::mutex g_blockchainInterfaceMutex;

    // Thread-safe wrapper for getting block hash
    Hash getBlockHashByIndexSafe(uint32_t blockIndex) {
        std::lock_guard<std::mutex> lock(g_blockchainInterfaceMutex);
        if (g_getBlockHashByIndex) {
            try {
                Hash result = g_getBlockHashByIndex(blockIndex);

                return result;
            } catch (...) {
                // Return empty hash if any exception occurs during blockchain access
                Hash emptyHash;
                memset(&emptyHash, 0, sizeof(Hash));
                return emptyHash;
            }
        }
        // Return empty hash if interface not available
        Hash emptyHash;
        memset(&emptyHash, 0, sizeof(Hash));
        return emptyHash;
    }

    // Recursive-safe version that avoids deadlocks when called from within addBlock
    Hash getBlockHashByIndexSafeRecursive(uint32_t blockIndex) {
        // Direct call without mutex - assume caller handles thread safety
        // This is safe because it's only called from within addBlock which already holds the blockchain lock
        if (g_getBlockHashByIndex) {
            try {
                Hash result = g_getBlockHashByIndex(blockIndex);

                return result;
            } catch (...) {
                Hash emptyHash;
                memset(&emptyHash, 0, sizeof(Hash));
                return emptyHash;
            }
        }
        // Return empty hash if interface not available
        Hash emptyHash;
        memset(&emptyHash, 0, sizeof(Hash));
        return emptyHash;
    }
}