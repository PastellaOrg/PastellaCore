// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2014-2018, The Aeon Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "argon2.h"

#include <CryptoTypes.h>
#include <stddef.h>

// Standard Cryptonight Definitions
#define CN_PAGE_SIZE 2097152
#define CN_SCRATCHPAD 2097152
#define CN_ITERATIONS 1048576

// Standard CryptoNight Lite Definitions
#define CN_LITE_PAGE_SIZE 2097152
#define CN_LITE_SCRATCHPAD 1048576
#define CN_LITE_ITERATIONS 524288

// Standard CryptoNight Dark
#define CN_DARK_PAGE_SIZE 524288
#define CN_DARK_SCRATCHPAD 524288
#define CN_DARK_ITERATIONS 262144

// Standard CryptoNight Turtle
#define CN_TURTLE_PAGE_SIZE 262144
#define CN_TURTLE_SCRATCHPAD 262144
#define CN_TURTLE_ITERATIONS 131072

// CryptoNight Soft Shell Definitions
#define CN_SOFT_SHELL_MEMORY 262144 // This defines the lowest memory utilization for our curve
#define CN_SOFT_SHELL_WINDOW 2048 // This defines how many blocks we cycle through as part of our algo sine wave
#define CN_SOFT_SHELL_MULTIPLIER 3 // This defines how big our steps are for each block and
// ultimately determines how big our sine wave is. A smaller value means a bigger wave
#define CN_SOFT_SHELL_ITER (CN_SOFT_SHELL_MEMORY / 2)
#define CN_SOFT_SHELL_PAD_MULTIPLIER (CN_SOFT_SHELL_WINDOW / CN_SOFT_SHELL_MULTIPLIER)
#define CN_SOFT_SHELL_ITER_MULTIPLIER (CN_SOFT_SHELL_PAD_MULTIPLIER / 2)

#if (((CN_SOFT_SHELL_WINDOW * CN_SOFT_SHELL_PAD_MULTIPLIER) + CN_SOFT_SHELL_MEMORY) > CN_PAGE_SIZE)
#error The CryptoNight Soft Shell Parameters you supplied will exceed normal paging operations.
#endif

// Chukwa Definitions
#define CHUKWA_HASHLEN 32 // The length of the resulting hash in bytes
#define CHUKWA_SALTLEN 16 // The length of our salt in bytes
#define CHUKWA_THREADS 1 // How many threads to use at once
#define CHUKWA_ITERS 3 // How many iterations we perform as part of our slow-hash
#define CHUKWA_MEMORY 512 // This value is in KiB (0.5MB)

namespace Crypto
{
    extern "C"
    {
#include "hash-ops.h"
    }

    // Global blockchain interface for RandomX seed hash access
    // This will be set by the daemon during initialization
    extern std::function<Crypto::Hash(uint32_t)> g_getBlockHashByIndex;

    // Thread-safe wrapper for getting block hash
    Hash getBlockHashByIndexSafe(uint32_t blockIndex);

    // Recursive-safe version that avoids deadlocks when called from within addBlock
    Hash getBlockHashByIndexSafeRecursive(uint32_t blockIndex);

    // Argon2 optimization tracking - now handled by RandomX
    // static bool argon2_optimization_selected = false;

    /*
      Cryptonight hash functions
    */

    inline void cn_fast_hash(const void *data, size_t length, Hash &hash)
    {
        cn_fast_hash(data, length, reinterpret_cast<char *>(&hash));
    }

    inline Hash cn_fast_hash(const void *data, size_t length)
    {
        Hash h;
        cn_fast_hash(data, length, reinterpret_cast<char *>(&h));
        return h;
    }

    // Standard CryptoNight
    inline void cn_slow_hash_v0(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data, length, reinterpret_cast<char *>(&hash), 0, 0, 0, CN_PAGE_SIZE, CN_SCRATCHPAD, CN_ITERATIONS);
    }

    inline void cn_slow_hash_v1(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data, length, reinterpret_cast<char *>(&hash), 0, 1, 0, CN_PAGE_SIZE, CN_SCRATCHPAD, CN_ITERATIONS);
    }

    inline void cn_slow_hash_v2(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data, length, reinterpret_cast<char *>(&hash), 0, 2, 0, CN_PAGE_SIZE, CN_SCRATCHPAD, CN_ITERATIONS);
    }

    // Standard CryptoNight Lite
    inline void cn_lite_slow_hash_v0(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            1,
            0,
            0,
            CN_LITE_PAGE_SIZE,
            CN_LITE_SCRATCHPAD,
            CN_LITE_ITERATIONS);
    }

    inline void cn_lite_slow_hash_v1(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            1,
            1,
            0,
            CN_LITE_PAGE_SIZE,
            CN_LITE_SCRATCHPAD,
            CN_LITE_ITERATIONS);
    }

    inline void cn_lite_slow_hash_v2(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            1,
            2,
            0,
            CN_LITE_PAGE_SIZE,
            CN_LITE_SCRATCHPAD,
            CN_LITE_ITERATIONS);
    }

    // Standard CryptoNight Dark
    inline void cn_dark_slow_hash_v0(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            0,
            0,
            0,
            CN_DARK_PAGE_SIZE,
            CN_DARK_SCRATCHPAD,
            CN_DARK_ITERATIONS);
    }

    inline void cn_dark_slow_hash_v1(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            0,
            1,
            0,
            CN_DARK_PAGE_SIZE,
            CN_DARK_SCRATCHPAD,
            CN_DARK_ITERATIONS);
    }

    inline void cn_dark_slow_hash_v2(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            0,
            2,
            0,
            CN_DARK_PAGE_SIZE,
            CN_DARK_SCRATCHPAD,
            CN_DARK_ITERATIONS);
    }

    // Standard CryptoNight Dark Lite
    inline void cn_dark_lite_slow_hash_v0(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            1,
            0,
            0,
            CN_DARK_PAGE_SIZE,
            CN_DARK_SCRATCHPAD,
            CN_DARK_ITERATIONS);
    }

    inline void cn_dark_lite_slow_hash_v1(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            1,
            1,
            0,
            CN_DARK_PAGE_SIZE,
            CN_DARK_SCRATCHPAD,
            CN_DARK_ITERATIONS);
    }

    inline void cn_dark_lite_slow_hash_v2(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            1,
            2,
            0,
            CN_DARK_PAGE_SIZE,
            CN_DARK_SCRATCHPAD,
            CN_DARK_ITERATIONS);
    }

    // Standard CryptoNight Turtle
    inline void cn_turtle_slow_hash_v0(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            0,
            0,
            0,
            CN_TURTLE_PAGE_SIZE,
            CN_TURTLE_SCRATCHPAD,
            CN_TURTLE_ITERATIONS);
    }

    inline void cn_turtle_slow_hash_v1(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            0,
            1,
            0,
            CN_TURTLE_PAGE_SIZE,
            CN_TURTLE_SCRATCHPAD,
            CN_TURTLE_ITERATIONS);
    }

    inline void cn_turtle_slow_hash_v2(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            0,
            2,
            0,
            CN_TURTLE_PAGE_SIZE,
            CN_TURTLE_SCRATCHPAD,
            CN_TURTLE_ITERATIONS);
    }

    // Standard CryptoNight Turtle Lite
    inline void cn_turtle_lite_slow_hash_v0(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            1,
            0,
            0,
            CN_TURTLE_PAGE_SIZE,
            CN_TURTLE_SCRATCHPAD,
            CN_TURTLE_ITERATIONS);
    }

    inline void cn_turtle_lite_slow_hash_v1(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            1,
            1,
            0,
            CN_TURTLE_PAGE_SIZE,
            CN_TURTLE_SCRATCHPAD,
            CN_TURTLE_ITERATIONS);
    }

    inline void cn_turtle_lite_slow_hash_v2(const void *data, size_t length, Hash &hash)
    {
        cn_slow_hash(
            data,
            length,
            reinterpret_cast<char *>(&hash),
            1,
            2,
            0,
            CN_TURTLE_PAGE_SIZE,
            CN_TURTLE_SCRATCHPAD,
            CN_TURTLE_ITERATIONS);
    }

    // CryptoNight Soft Shell
    inline void cn_soft_shell_slow_hash_v0(const void *data, size_t length, Hash &hash, uint32_t height)
    {
        uint32_t base_offset = (height % CN_SOFT_SHELL_WINDOW);
        int32_t offset = (height % (CN_SOFT_SHELL_WINDOW * 2)) - (base_offset * 2);
        if (offset < 0)
        {
            offset = base_offset;
        }

        uint32_t scratchpad = CN_SOFT_SHELL_MEMORY + (static_cast<uint32_t>(offset) * CN_SOFT_SHELL_PAD_MULTIPLIER);
        scratchpad = (static_cast<uint64_t>(scratchpad / 128)) * 128;
        uint32_t iterations = CN_SOFT_SHELL_ITER + (static_cast<uint32_t>(offset) * CN_SOFT_SHELL_ITER_MULTIPLIER);
        uint32_t pagesize = scratchpad;

        cn_slow_hash(data, length, reinterpret_cast<char *>(&hash), 1, 0, 0, pagesize, scratchpad, iterations);
    }

    inline void cn_soft_shell_slow_hash_v1(const void *data, size_t length, Hash &hash, uint32_t height)
    {
        uint32_t base_offset = (height % CN_SOFT_SHELL_WINDOW);
        int32_t offset = (height % (CN_SOFT_SHELL_WINDOW * 2)) - (base_offset * 2);
        if (offset < 0)
        {
            offset = base_offset;
        }

        uint32_t scratchpad = CN_SOFT_SHELL_MEMORY + (static_cast<uint32_t>(offset) * CN_SOFT_SHELL_PAD_MULTIPLIER);
        scratchpad = (static_cast<uint64_t>(scratchpad / 128)) * 128;
        uint32_t iterations = CN_SOFT_SHELL_ITER + (static_cast<uint32_t>(offset) * CN_SOFT_SHELL_ITER_MULTIPLIER);
        uint32_t pagesize = scratchpad;

        cn_slow_hash(data, length, reinterpret_cast<char *>(&hash), 1, 1, 0, pagesize, scratchpad, iterations);
    }

    inline void cn_soft_shell_slow_hash_v2(const void *data, size_t length, Hash &hash, uint32_t height)
    {
        uint32_t base_offset = (height % CN_SOFT_SHELL_WINDOW);
        int32_t offset = (height % (CN_SOFT_SHELL_WINDOW * 2)) - (base_offset * 2);
        if (offset < 0)
        {
            offset = base_offset;
        }

        uint32_t scratchpad = CN_SOFT_SHELL_MEMORY + (static_cast<uint32_t>(offset) * CN_SOFT_SHELL_PAD_MULTIPLIER);
        scratchpad = (static_cast<uint64_t>(scratchpad / 128)) * 128;
        uint32_t iterations = CN_SOFT_SHELL_ITER + (static_cast<uint32_t>(offset) * CN_SOFT_SHELL_ITER_MULTIPLIER);
        uint32_t pagesize = scratchpad;

        cn_slow_hash(data, length, reinterpret_cast<char *>(&hash), 1, 2, 0, pagesize, scratchpad, iterations);
    }

    inline void chukwa_slow_hash(const void *data, size_t length, Hash &hash)
    {
        // Chukwa algorithm temporarily disabled due to RandomX migration
        // RandomX includes its own Argon2 implementation
        // Falling back to a basic hash for now
        cn_fast_hash(data, length, hash);
    }

    inline void tree_hash(const Hash *hashes, size_t count, Hash &root_hash)
    {
        tree_hash(reinterpret_cast<const char(*)[HASH_SIZE]>(hashes), count, reinterpret_cast<char *>(&root_hash));
    }

    inline void tree_branch(const Hash *hashes, size_t count, Hash *branch)
    {
        tree_branch(
            reinterpret_cast<const char(*)[HASH_SIZE]>(hashes), count, reinterpret_cast<char(*)[HASH_SIZE]>(branch));
    }

    inline void
        tree_hash_from_branch(const Hash *branch, size_t depth, const Hash &leaf, const void *path, Hash &root_hash)
    {
        tree_hash_from_branch(
            reinterpret_cast<const char(*)[HASH_SIZE]>(branch),
            depth,
            reinterpret_cast<const char *>(&leaf),
            path,
            reinterpret_cast<char *>(&root_hash));
    }

    // RandomX hash function with height for proper seed hash calculation
    inline void randomx_slow_hash_with_height(const void *data, size_t length, uint32_t height, Hash &hash)
    {
        // Calculate RandomX seed hash based on block height
        uint64_t seed_height = rx_seedheight(height);
        Hash seed_hash;

        // Initialize to zeros for early blocks where we can't get the blockchain data
        memset(&seed_hash, 0, sizeof(Hash));

        // Get actual seed hash from blockchain using thread-safe interface
        // Use the thread-safe version to ensure we get the most recent block hash
        if (g_getBlockHashByIndex) {
            try {
                seed_hash = getBlockHashByIndexSafe(static_cast<uint32_t>(seed_height));
            } catch (...) {
                // Fallback to zeros if blockchain access fails
                memset(&seed_hash, 0, sizeof(Hash));
            }
        }

        try {
            rx_slow_hash(reinterpret_cast<const char *>(&seed_hash), data, length, reinterpret_cast<char *>(&hash));
        } catch (...) {
            // If RandomX fails during shutdown, provide a basic hash
            cn_fast_hash(data, length, hash);
        }
    }

    // RandomX hash function - wrapper for Pastella algorithm mapping (height-less fallback)
    inline void randomx_slow_hash(const void *data, size_t length, Hash &hash)
    {
        // Default height-less version for compatibility
        randomx_slow_hash_with_height(data, length, 1, hash);
    }
} // namespace Crypto