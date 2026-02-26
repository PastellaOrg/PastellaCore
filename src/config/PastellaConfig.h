// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2026, The Pastella Team
//
// Please see the included LICENSE file for more information.

#pragma once

#include <boost/uuid/uuid.hpp>
#include <crypto/hash.h>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <string>

namespace Pastella
{
  namespace parameters
  {
    const uint64_t DIFFICULTY_TARGET                                       = 30;                              /* Every block takes 30 seconds */
    const uint64_t PASTELLA_PUBLIC_ADDRESS_BASE58_PREFIX                   = 0x198004;                        /* Wallet address prefix: PAS */
    const uint32_t PASTELLA_MAX_BLOCK_NUMBER                               = 500000000;
    const size_t   PASTELLA_MAX_BLOCK_BLOB_SIZE                            = 500000000;
    const size_t   PASTELLA_MAX_TX_SIZE                                    = 1000000000;
    const uint32_t PASTELLA_MINED_MONEY_UNLOCK_WINDOW                      = 10;
    const uint64_t PASTELLA_BLOCK_FUTURE_TIME_LIMIT                        = 6 * DIFFICULTY_TARGET;
    const size_t   BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW                       = 11;

    const uint64_t MONEY_SUPPLY                                            = UINT64_C(16'000'000'00000000);   /* Total Supply: 16'000'000 PAS */
    const uint64_t BLOCK_REWARD                                            = UINT64_C(4'00000000);            /* Miner Reward: 4.00000000 PAS */
    const uint64_t GENESIS_BLOCK_REWARD                                    = UINT64_C(800'000'00000000);      /* Premine Reward: 800'000.00000000 PAS (5%) */

    /* Halving configuration - yearly halvings */
    const uint32_t YEARLY_BLOCK_COUNT                                      = 365 * 24 * 60 * 60 / DIFFICULTY_TARGET;  /* 1,051,200 blocks per year */
    const uint32_t HALVING_INTERVAL                                        = YEARLY_BLOCK_COUNT;                      /* Halving every year */

    /* Halving heights array (when each halving occurs) - calculated for multiple years */
    const uint32_t HALVING_HEIGHTS[] = {
        HALVING_INTERVAL * 1,    /* Year 1: 1,051,200 */
        HALVING_INTERVAL * 2,    /* Year 2: 2,102,400 */
        HALVING_INTERVAL * 3,    /* Year 3: 3,153,600 */
        HALVING_INTERVAL * 4,    /* Year 4: 4,204,800 */
        HALVING_INTERVAL * 5,    /* Year 5: 5,256,000 */
        HALVING_INTERVAL * 6,    /* Year 6: 6,307,200 */
        HALVING_INTERVAL * 7,    /* Year 7: 7,358,400 */
        HALVING_INTERVAL * 8,    /* Year 8: 8,409,600 */
        HALVING_INTERVAL * 9,    /* Year 9: 9,460,800 */
        HALVING_INTERVAL * 10    /* Year 10: 10,512,000 */
    };

    const uint32_t HALVING_HEIGHTS_COUNT                                   = sizeof(HALVING_HEIGHTS) / sizeof(*HALVING_HEIGHTS);

    const uint64_t STARTING_DIFFICULTY                                     = 1000;        /* Starting difficulty for new blockchain (before enough blocks for LWMA-2) */

    /* Simple Reward Staking Configuration */
    namespace staking {
      /* Lock-up period options (in days) */
      const uint32_t MIN_LOCK_PERIOD_DAYS[] = {30, 90, 180, 365};
      const uint32_t MIN_LOCK_PERIOD_DAYS_COUNT = sizeof(MIN_LOCK_PERIOD_DAYS) / sizeof(*MIN_LOCK_PERIOD_DAYS);

      /* Reward rates (annual percentage, 100 = 100%) */
      const uint32_t ANNUAL_REWARD_RATES[] = {2, 8, 18, 50};
      const uint32_t ANNUAL_REWARD_RATES_COUNT = sizeof(ANNUAL_REWARD_RATES) / sizeof(*ANNUAL_REWARD_RATES);

      /* Minimum staking amount (in atomic units) */
      const uint64_t MIN_STAKING_AMOUNT = 100000000;      /* 1.0 PAS */

      /* Staking transaction type identifiers */
      const uint8_t STAKING_TX_TYPE = 101;

      /* Staking activation height */
      const uint32_t STAKING_ENABLE_HEIGHT = 10;          /* Staking only allowed from this height */

      /* Static assertions for consistency */
      static_assert(MIN_LOCK_PERIOD_DAYS_COUNT == ANNUAL_REWARD_RATES_COUNT, "Lock periods and reward rates must match");
      static_assert(MIN_LOCK_PERIOD_DAYS_COUNT == 4, "Must have exactly 4 staking tiers");
    }

    /* Governance Configuration */
    namespace governance {
      /* Governance activation height */
      const uint32_t GOVERNANCE_ENABLE_HEIGHT = 10000000;     /* Governance enabled at this height */

      /* Proposal duration (in blocks, 30s per block) */
      const uint32_t PROPOSAL_DURATION_BLOCKS = 3360;         /* 7 days = 7 * 24 * 60 * 2 blocks */

      /* Minimum stake required to create a proposal */
      const uint64_t MIN_PROPOSAL_STAKE = 100000000;          /* 1.0 PAS */

      /* Proposal creation fee */
      const uint64_t PROPOSAL_FEE = 10000000;                 /* 0.1 PAS */

      /* Vote types */
      const uint8_t VOTE_AGAINST = 0;
      const uint8_t VOTE_FOR = 1;
      const uint8_t VOTE_ABSTAIN = 2;

      /* Proposal types */
      const uint8_t PROPOSAL_TYPE_PARAMETER = 0;          /* Change blockchain parameters */
      const uint8_t PROPOSAL_TYPE_UPGRADE = 1;            /* Protocol upgrade */
      const uint8_t PROPOSAL_TYPE_TREASURY = 2;           /* Treasury spending */

      /* Governance transaction type identifiers */
      const uint8_t PROPOSAL_TX_TYPE = 102;
      const uint8_t VOTE_TX_TYPE = 103;

      /* Voting thresholds (percentage required to pass) */
      const uint8_t SIMPLE_MAJORITY_THRESHOLD = 51;       /* 51% for basic proposals */
      const uint8_t SUPERMAJORITY_THRESHOLD = 67;         /* 67% for upgrades */
      const uint8_t CONSENSUS_THRESHOLD = 75;             /* 75% for constitutional changes */

      /* Voting power multipliers based on lock duration */
      const uint8_t LOCK_MULTIPLIER_30_DAYS = 1;          /* 1x voting power */
      const uint8_t LOCK_MULTIPLIER_90_DAYS = 2;          /* 2x voting power */
      const uint8_t LOCK_MULTIPLIER_180_DAYS = 3;         /* 3x voting power */
      const uint8_t LOCK_MULTIPLIER_360_DAYS = 4;         /* 4x voting power */
    }

    const uint64_t LWMA_2_DIFFICULTY_BLOCK_INDEX                           = 0;

    /* Genesis block recipient address - plain readable address */
    const char GENESIS_RECIPIENT_ADDRESS[] =
      "PAS18z7m9DGbJFoVv6HiGoiwxNG5mLoniSEFWkguBKt59JSHPHjYaa";

    /* Genesis coinbase transaction hex */
    const char GENESIS_COINBASE_TX_HEX[] =
      "010001ff00018080d49ca7981202004a339087cd0d26f4923abe48fac9a50f948b5e4b96d4c05ebfb4d18adb0a232101adc26f2449801fe5ac287736ac47cb489871048e87c7f477e5c4de66b9129bde";

    static_assert(sizeof(GENESIS_COINBASE_TX_HEX) / sizeof(*GENESIS_COINBASE_TX_HEX) != 1, "GENESIS_COINBASE_TX_HEX must not be empty.");
    static_assert(sizeof(GENESIS_RECIPIENT_ADDRESS) / sizeof(*GENESIS_RECIPIENT_ADDRESS) != 1, "GENESIS_RECIPIENT_ADDRESS must not be empty.");

    /* This is the unix timestamp of the first "mined" block (technically block 2, not the genesis block)
       You can get this value by doing "print_block 2" in Pastellad. It is used to know what timestamp
       to import from when the block height cannot be found in the node or the node is offline. */
    const uint64_t GENESIS_BLOCK_TIMESTAMP                               = 1772132400;                    /* 08:00 PM GMT+1, 26th of February 2026 */
    const size_t   PASTELLA_REWARD_BLOCKS_WINDOW                         = 100;
    const size_t   PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE               = 100000;                        /* size of block (bytes) after which reward for block calculated using block size */
    const size_t   PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE_V2            = 20000;
    const size_t   PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE_V1            = 10000;
    const size_t   PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE_CURRENT       = PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE;
    const size_t   PASTELLA_BLOCK_REDUCTION_SIZE                         = 50000;
    const size_t   PASTELLA_BLOCK_REDUCTION_RATE                         = 2;                             /* rotating 2 reduced blocks + 1 full block */
    const size_t   PASTELLA_COINBASE_BLOB_RESERVED_SIZE                  = 600;
    static_assert(PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE > PASTELLA_BLOCK_REDUCTION_SIZE, "Reduction can not be bigger than full.");
    static_assert(PASTELLA_BLOCK_GRANTED_FULL_REWARD_ZONE * 30 / 100 < PASTELLA_BLOCK_REDUCTION_SIZE, "Reduction is too small.");

    const size_t   PASTELLA_DISPLAY_DECIMAL_POINT                        = 8;
    const uint64_t MINIMUM_FEE = UINT64_C(1000);
    
    /* New fee V2
       Fee per byte is rounded up in chunks. This helps makes estimates
       more accurate. It's suggested to make this a power of two, to relate
       to the underlying storage cost / page sizes for storing a transaction. */
    const uint64_t FEE_PER_BYTE_CHUNK_SIZE                                 = 256;

    /* Fee to charge per byte of transaction. Will be applied in chunks, see
       above. This value comes out to 1.953125. We use this value instead of
       something like 200 because it makes for pretty resulting fees
       - 5 PAS vs 5.12 PAS. You can read this as.. the fee per chunk
       is 512000 atomic units. The fee per byte is 512000 / chunk size. */
    const double   MINIMUM_FEE_PER_BYTE_V1                                 = 100 / FEE_PER_BYTE_CHUNK_SIZE;

    /* Height for our first fee to byte change to take effect. */
    const uint64_t MINIMUM_FEE_PER_BYTE_V1_HEIGHT = 10000000; // 10M
    
    /* Backward compatibility */
    const uint64_t ACCEPTABLE_FEE                                          = UINT64_C(1000);     /* with this fee, tx is always accepted whatever size - 0.00000100 PAS */

    const uint64_t DEFAULT_DUST_THRESHOLD                                  = UINT64_C(0);
    const uint64_t DEFAULT_DUST_THRESHOLD_V2                               = UINT64_C(0);
    const uint32_t DUST_THRESHOLD_V2_HEIGHT                                = 0;
    const uint64_t EXPECTED_NUMBER_OF_BLOCKS_PER_DAY                       = 24 * 60 * 60 / DIFFICULTY_TARGET;

    const size_t   DIFFICULTY_WINDOW                                       = 60;
    const uint64_t DIFFICULTY_BLOCKS_COUNT                                 = DIFFICULTY_WINDOW + 1;
    const size_t   DIFFICULTY_CUT                                          = 60;
    const size_t   DIFFICULTY_LAG                                          = 0;
    
    const size_t   MAX_BLOCK_SIZE_INITIAL                                  = 100000;
    const uint64_t MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR                   = 100 * 1024;
    const uint64_t MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR                 = 365 * 24 * 60 * 60 / DIFFICULTY_TARGET;
    const uint64_t MAX_EXTRA_SIZE                                          = 140000;
    const uint64_t MAX_EXTRA_SIZE_V2                                       = 1024;
    const uint64_t MAX_EXTRA_SIZE_V2_HEIGHT                                = 0;

    /* 30,000,000 PAS -> Max supply / mixin+1 outputs                 */
    /* This is enforced on the daemon side. An output > 30,000,000 causes an invalid block.   */
    const uint64_t MAX_OUTPUT_SIZE_NODE                                    = 30'000'000'00000000;

    /* 500,000 PAS */
    /* This is enforced on the client side. An output > 500,000 will not be created in a transaction */
    const uint64_t MAX_OUTPUT_SIZE_CLIENT                                  = 500'000'00000000;
    const uint64_t MAX_OUTPUT_SIZE_HEIGHT                                  = 500000;

    /* For new projects forked from this code base, the values immediately below
       should be changed to 0 to prevent issues with transaction processing
       and other possible unexpected behavior */
    const uint64_t TRANSACTION_SIGNATURE_COUNT_VALIDATION_HEIGHT           = 250;
    const uint64_t BLOCK_BLOB_SHUFFLE_CHECK_HEIGHT                         = 250;
    const uint64_t TRANSACTION_INPUT_BLOCKTIME_VALIDATION_HEIGHT           = 250;

    /* This describes how many blocks of "wiggle" room transactions have regarding
       when the outputs can be spent based on a reasonable belief that the outputs
       would unlock in the current block period */
    const uint64_t PASTELLA_LOCKED_TX_ALLOWED_DELTA_BLOCKS               = 1;
    const uint64_t PASTELLA_LOCKED_TX_ALLOWED_DELTA_SECONDS              = DIFFICULTY_TARGET * PASTELLA_LOCKED_TX_ALLOWED_DELTA_BLOCKS;

    const uint64_t PASTELLA_MEMPOOL_TX_LIVETIME                          = 60 * 60 * 24;     // seconds, one day
    const uint64_t PASTELLA_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME           = 60 * 60 * 24 * 7; // seconds, one week
    const uint64_t PASTELLA_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL       = 7;

    const size_t   NORMAL_TX_MAX_OUTPUT_COUNT_V1                           = 90;
    const size_t   NORMAL_TX_MAX_OUTPUT_COUNT_V1_HEIGHT                    = 250;
    const uint32_t UPGRADE_HEIGHT_V2                                       = 1;
    const unsigned UPGRADE_VOTING_THRESHOLD                                = 90;
    const uint32_t UPGRADE_VOTING_WINDOW                                   = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;
    const uint32_t UPGRADE_WINDOW                                          = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;
    
    static_assert(0 < UPGRADE_VOTING_THRESHOLD && UPGRADE_VOTING_THRESHOLD <= 100, "Bad UPGRADE_VOTING_THRESHOLD");
    static_assert(UPGRADE_VOTING_WINDOW > 1, "Bad UPGRADE_VOTING_WINDOW");

    /* Hard fork block heights */
    const uint64_t FORK_HEIGHTS[] = {
      250,    /* 0 ~ TRANSACTION_SIGNATURE_COUNT_VALIDATION, BLOCK_BLOB_SHUFFLE_CHECK, TRANSACTION_INPUT_BLOCKTIME_VALIDATION, NORMAL_TX_MAX_OUTPUT_COUNT_V1 */
      500000  /* 1 ~ MAX_OUTPUT_SIZE */
    };

    /* MAKE SURE TO UPDATE THIS VALUE WITH EVERY MAJOR RELEASE BEFORE A FORK - Count from 0 */
    const uint64_t SOFTWARE_SUPPORTED_FORK_INDEX                           = 1;
    const uint64_t FORK_HEIGHTS_SIZE                                       = sizeof(FORK_HEIGHTS) / sizeof(*FORK_HEIGHTS);
    const uint8_t  CURRENT_FORK_INDEX                                      = FORK_HEIGHTS_SIZE == 0 ? 0 : SOFTWARE_SUPPORTED_FORK_INDEX;
    //static_assert(CURRENT_FORK_INDEX >= 0, "CURRENT FORK INDEX must be >= 0");
    static_assert(FORK_HEIGHTS_SIZE == 0 || CURRENT_FORK_INDEX < FORK_HEIGHTS_SIZE, "CURRENT_FORK_INDEX out of range of FORK_HEIGHTS!");

    const char PASTELLA_BLOCKS_FILENAME[]                                = "blocks.bin";
    const char PASTELLA_BLOCKINDEXES_FILENAME[]                          = "blockindexes.bin";
    const char PASTELLA_POOLDATA_FILENAME[]                              = "poolstate.bin";
    const char P2P_NET_DATA_FILENAME[]                                     = "p2pstate.bin";
    const char MINER_CONFIG_FILE_NAME[]                                    = "miner_conf.json";
  }

  /* Global staking namespace accessible from namespace */
  namespace staking = Pastella::parameters::staking;

  /* Global governance namespace accessible from namespace */
  namespace governance = Pastella::parameters::governance;

  const char    COIN_NAME[]                                          = "Pastella";
  const uint8_t TRANSACTION_VERSION_1                                      = 1;
  const uint8_t TRANSACTION_VERSION_2                                      = 2;
  const uint8_t CURRENT_TRANSACTION_VERSION                                = TRANSACTION_VERSION_1;

  const uint8_t BLOCK_MAJOR_VERSION_1                                      = 1;                /* Height 1 */
  const uint8_t BLOCK_MAJOR_VERSION_2                                      = 2;                /* UPGRADE_HEIGHT_V2 */

  const uint8_t BLOCK_MINOR_VERSION_0                                      = 0;
  const uint8_t BLOCK_MINOR_VERSION_1                                      = 1;

  const std::unordered_map<uint8_t, std::function<void(const void *data, size_t length, Crypto::Hash &hash)>>
    HASHING_ALGORITHMS_BY_BLOCK_VERSION = {
      {BLOCK_MAJOR_VERSION_1, Crypto::randomx_slow_hash},              /* Height 1 - RandomX */
      {BLOCK_MAJOR_VERSION_2, Crypto::randomx_slow_hash}               /* UPGRADE_HEIGHT_V2 - RandomX */
    };


  const size_t   BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT                    = 10000;           // by default, blocks ids count in synchronizing
  const uint64_t BLOCKS_SYNCHRONIZING_DEFAULT_COUNT                        = 20;              // by default, blocks count in blocks downloading
  const size_t   COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT                     = 100;
  const int      P2P_DEFAULT_PORT                                          = 21000;           // P2P Port
  const int      RPC_DEFAULT_PORT                                          = 21001;           // RPC Port
  const int      SERVICE_DEFAULT_PORT                                      = 21002;           // Service Port
  const size_t   P2P_LOCAL_WHITE_PEERLIST_LIMIT                            = 1000;
  const size_t   P2P_LOCAL_GRAY_PEERLIST_LIMIT                             = 5000;

  const uint8_t  P2P_CURRENT_VERSION                                       = 1;                // Current version
  const uint8_t  P2P_MINIMUM_VERSION                                       = 1;                // Minimum supported version
  const uint8_t  P2P_UPGRADE_WINDOW                                        = 1;                // Version to upgrade from

  const uint8_t  P2P_LITE_BLOCKS_PROPOGATION_VERSION                       = 0;
  const size_t   P2P_CONNECTION_MAX_WRITE_BUFFER_SIZE                      = 32 * 1024 * 1024; // 32 MB
  const uint32_t P2P_DEFAULT_CONNECTIONS_COUNT                             = 32;               // 32 Connections
  const size_t   P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT                 = 70;
  const uint32_t P2P_DEFAULT_HANDSHAKE_INTERVAL                            = 60;               // 60 Seconds
  const uint32_t P2P_DEFAULT_PACKET_MAX_SIZE                               = 50000000;         // 50,000,000 bytes maximum packet size
  const uint32_t P2P_DEFAULT_PEERS_IN_HANDSHAKE                            = 250;

  const uint32_t P2P_DEFAULT_CONNECTION_TIMEOUT                            = 5000;             // 5 Seconds
  const uint32_t P2P_DEFAULT_PING_CONNECTION_TIMEOUT                       = 2000;             // 2 Seconds
  const uint64_t P2P_DEFAULT_INVOKE_TIMEOUT                                = 60 * 2 * 1000;    // 2 Minutes
  const size_t   P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT                      = 5000;             // 5 Seconds
  const char     P2P_STAT_TRUSTED_PUB_KEY[]                                = "";

  #if !defined(USE_LEVELDB)
    const uint64_t DATABASE_WRITE_BUFFER_MB_DEFAULT_SIZE                   = 256;            // 256 MB
    const uint64_t DATABASE_READ_BUFFER_MB_DEFAULT_SIZE                    = 64;             // 64 MB
    const uint32_t DATABASE_DEFAULT_MAX_OPEN_FILES                         = 50;             // 500 Files
    const uint16_t DATABASE_DEFAULT_BACKGROUND_THREADS_COUNT               = 4;              // 4 DB Threads
    const uint64_t DATABASE_MAX_BYTES_FOR_LEVEL_BASE                       = 512;            // 512 MB
  #else
    const uint64_t DATABASE_WRITE_BUFFER_MB_DEFAULT_SIZE                   = 64;             // 64 MB
    const uint64_t DATABASE_READ_BUFFER_MB_DEFAULT_SIZE                    = 64;             // 64 MB
    const uint32_t DATABASE_DEFAULT_MAX_OPEN_FILES                         = 128;            // 128 Files
    const uint16_t DATABASE_DEFAULT_BACKGROUND_THREADS_COUNT               = 8;              // 8 DB Threads
  #endif

  const char LATEST_VERSION_URL[]                                          = "https://github.com/PastellaProject/Pastella/releases";
  const std::string LICENSE_URL                                            = "https://github.com/PastellaProject/Pastella/blob/master/LICENSE";

  const static boost::uuids::uuid PASTELLA_NETWORK = {
    {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x90, 0x9a, 0xbc, 0xde}
  };

  const char *const SEED_NODES[] = {
    "seed.pastella.org:21000",
    "seed.pastella.org:21100",
    "seed.pastella.org:21200"
  };
}
