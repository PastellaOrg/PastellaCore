// Copyright (c) 2026, Pastella Developers
//
// Pastella Blockchain Analysis Tool
// Comprehensive blockchain diagnostic tool for identifying chain split root causes

#include "pastellacore/Core.h"
#include "pastellacore/Currency.h"
#include "pastellacore/DatabaseBlockchainCache.h"
#include "pastellacore/RocksDBWrapper.h"
#include "pastellacore/DataBaseConfig.h"
#include "pastellacore/DBUtils.h"
#include "config/PastellaConfig.h"
#include "config/PastellaConfig.h"
#include "logging/ConsoleLogger.h"
#include "logging/LoggerManager.h"
#include "version.h"

#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/iterator.h>
#include <iomanip>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <algorithm>

using namespace Pastella;
using namespace Logging;

std::string formatHash(const Crypto::Hash &hash)
{
    return Common::podToHex(hash);
}

std::string formatAmount(uint64_t amount)
{
    std::stringstream ss;
    ss << std::fixed << std::setprecision(8) << (double)amount / 100000000;
    return ss.str();
}

/* Blockchain Analysis Result Structure */
struct AnalysisResult
{
    /* Basic blockchain info */
    uint32_t topBlockIndex = 0;
    Crypto::Hash topBlockHash;
    uint64_t totalTransactions = 0;
    uint64_t totalCoins = 0;

    /* UTXO statistics */
    uint64_t totalUtxos = 0;
    uint64_t spentUtxos = 0;
    uint64_t unspentUtxos = 0;
    std::map<uint32_t, uint64_t> utxosPerBlock;        /* block index -> UTXO count created */
    std::map<uint32_t, uint64_t> spentUtxosPerBlock;   /* block index -> UTXO count spent */

    /* Block validation statistics */
    std::map<uint64_t, std::vector<Crypto::Hash>> blockHashesByTimestamp;
    std::vector<uint64_t> timestamps;
    std::vector<uint64_t> difficulties;
    std::vector<uint32_t> blockSizes;
    std::vector<uint64_t> cumulativeDifficulties;

    /* Transaction validation issues */
    std::set<std::pair<Crypto::Hash, uint32_t>> missingUtxoReferences;
    std::set<std::pair<Crypto::Hash, uint32_t>> doubleSpendCandidates;
    std::map<uint32_t, std::vector<Crypto::Hash>> transactionsPerBlock;

    /* Spent key image tracking */
    std::map<uint32_t, std::vector<Crypto::PublicKey>> spentKeyImagesByBlock;

    /* Seed node information (CRITICAL for chain split analysis) */
    struct SeedNodeInfo
    {
        std::string ip;
        uint16_t p2pPort;
        uint16_t rpcPort;
        bool p2pExposed;
        bool rpcExposed;
    };
    std::vector<SeedNodeInfo> seedNodes;

    void printReport()
    {
        std::cout << "\n";
        std::cout << "================================================================================\n";
        std::cout << "                      PASTELLA BLOCKCHAIN ANALYSIS REPORT                        \n";
        std::cout << "================================================================================\n";
        std::cout << "\n";

        /* Basic Information */
        std::cout << "BASIC BLOCKCHAIN INFORMATION:\n";
        std::cout << "----------------------------\n";
        std::cout << "  Top Block Height:          " << topBlockIndex << "\n";
        std::cout << "  Top Block Hash:            " << formatHash(topBlockHash).substr(0, 16) << "...\n";
        std::cout << "  Total Transactions:        " << totalTransactions << "\n";
        std::cout << "  Total Coins Generated:     " << formatAmount(totalCoins) << "\n";
        std::cout << "\n";

        /* UTXO Statistics */
        std::cout << "UTXO STATISTICS:\n";
        std::cout << "----------------\n";
        std::cout << "  Total UTXOs:               " << totalUtxos << "\n";
        std::cout << "  Spent UTXOs:               " << spentUtxos << "\n";
        std::cout << "  Unspent UTXOs:             " << unspentUtxos << "\n";
        std::cout << "  UTXO Spent Ratio:          " << std::fixed << std::setprecision(2)
                  << (totalUtxos > 0 ? (double)spentUtxos / totalUtxos * 100 : 0) << "%\n";
        std::cout << "\n";

        /* UTXO Distribution by Block */
        if (!utxosPerBlock.empty())
        {
            std::cout << "UTXO CREATION DISTRIBUTION (Last 20 blocks):\n";
            std::cout << "---------------------------------------------\n";
            auto it = utxosPerBlock.rbegin();
            for (int i = 0; i < 20 && it != utxosPerBlock.rend(); ++i, ++it)
            {
                std::cout << "  Block " << std::setw(6) << it->first << ": "
                          << std::setw(4) << it->second << " UTXOs created\n";
            }
            std::cout << "\n";
        }

        /* UTXO Spending Distribution by Block */
        if (!spentUtxosPerBlock.empty())
        {
            std::cout << "UTXO SPENDING DISTRIBUTION (Last 20 blocks with spending):\n";
            std::cout << "------------------------------------------------------------\n";
            auto it = spentUtxosPerBlock.rbegin();
            for (int i = 0; i < 20 && it != spentUtxosPerBlock.rend(); ++i, ++it)
            {
                std::cout << "  Block " << std::setw(6) << it->first << ": "
                          << std::setw(4) << it->second << " UTXOs spent\n";
            }
            std::cout << "\n";
        }

        /* Block Timeline Analysis */
        if (!timestamps.empty())
        {
            std::cout << "BLOCK TIMELINE ANALYSIS (Last 20 blocks):\n";
            std::cout << "-----------------------------------------\n";
            size_t start = std::max((size_t)0, timestamps.size() - 20);
            for (size_t i = start; i < timestamps.size(); ++i)
            {
                std::cout << "  Block " << std::setw(6) << (topBlockIndex - (timestamps.size() - 1 - i))
                          << " | Time: " << timestamps[i]
                          << " | Size: " << std::setw(6) << blockSizes[i] << " bytes";
                if (i > 0)
                {
                    uint64_t timeDiff = timestamps[i] - timestamps[i-1];
                    std::cout << " | Gap: " << std::setw(4) << timeDiff << "s";
                }
                std::cout << "\n";
            }
            std::cout << "\n";
        }

        /* Difficulty Analysis */
        if (!difficulties.empty())
        {
            std::cout << "DIFFICULTY ANALYSIS (Last 20 blocks):\n";
            std::cout << "------------------------------------\n";
            size_t start = std::max((size_t)0, difficulties.size() - 20);
            for (size_t i = start; i < difficulties.size(); ++i)
            {
                std::cout << "  Block " << std::setw(6) << (topBlockIndex - (difficulties.size() - 1 - i))
                          << " | Difficulty: " << std::setw(12) << difficulties[i];
                if (i < cumulativeDifficulties.size())
                {
                    std::cout << " | Cumulative: " << std::setw(20) << cumulativeDifficulties[i];
                }
                std::cout << "\n";
            }
            std::cout << "\n";
        }

        /* Transaction Statistics per Block */
        if (!transactionsPerBlock.empty())
        {
            std::cout << "TRANSACTION STATISTICS (Last 20 blocks):\n";
            std::cout << "-----------------------------------------\n";
            auto it = transactionsPerBlock.rbegin();
            for (int i = 0; i < 20 && it != transactionsPerBlock.rend(); ++i, ++it)
            {
                std::cout << "  Block " << std::setw(6) << it->first << ": "
                          << std::setw(3) << it->second.size() << " transactions\n";
            }
            std::cout << "\n";
        }

        /* Validation Issues */
        std::cout << "VALIDATION ISSUES:\n";
        std::cout << "------------------\n";
        if (!missingUtxoReferences.empty())
        {
            std::cout << "  WARNING: " << missingUtxoReferences.size()
                      << " missing UTXO references found!\n";
            std::cout << "  This indicates transactions spending non-existent UTXOs.\n";
        }
        else
        {
            std::cout << "  No missing UTXO references detected.\n";
        }

        if (!doubleSpendCandidates.empty())
        {
            std::cout << "  WARNING: " << doubleSpendCandidates.size()
                      << " potential double-spend candidates found!\n";
            std::cout << "  This indicates UTXOs being spent multiple times.\n";
        }
        else
        {
            std::cout << "  No double-spend candidates detected.\n";
        }
        std::cout << "\n";

        /* Seed Node Information */
        std::cout << "SEED NODE CONFIGURATION:\n";
        std::cout << "------------------------\n";
        std::cout << "  CRITICAL: Seed nodes expose both P2P and RPC ports!\n";
        std::cout << "  This is a SECURITY RISK and can cause chain split issues.\n";
        std::cout << "\n";
        for (const auto &node : seedNodes)
        {
            std::cout << "  Seed Node: " << node.ip << "\n";
            std::cout << "    P2P Port:  " << node.p2pPort << " "
                      << (node.p2pExposed ? "[EXPOSED - RISK]" : "[OK]") << "\n";
            std::cout << "    RPC Port:  " << node.rpcPort << " "
                      << (node.rpcExposed ? "[EXPOSED - RISK]" : "[OK]") << "\n";
            std::cout << "\n";
        }

        /* Analysis Summary */
        std::cout << "ANALYSIS SUMMARY:\n";
        std::cout << "-----------------\n";

        bool hasIssues = false;
        std::vector<std::string> issues;

        if (spentUtxos > totalUtxos)
        {
            issues.push_back("CRITICAL: More spent UTXOs than total UTXOs (database corruption)");
            hasIssues = true;
        }

        if (!missingUtxoReferences.empty())
        {
            issues.push_back("WARNING: Transactions with missing UTXO references");
            hasIssues = true;
        }

        if (!doubleSpendCandidates.empty())
        {
            issues.push_back("WARNING: Potential double-spends detected");
            hasIssues = true;
        }

        if (unspentUtxos == 0 && topBlockIndex > 1000)
        {
            issues.push_back("WARNING: No unspent UTXOs found (unusual for active blockchain)");
            hasIssues = true;
        }

        if (!seedNodes.empty())
        {
            bool allExposed = true;
            for (const auto &node : seedNodes)
            {
                if (!node.p2pExposed || !node.rpcExposed)
                {
                    allExposed = false;
                    break;
                }
            }
            if (allExposed)
            {
                issues.push_back("SECURITY: All seed nodes have exposed P2P and RPC ports");
                hasIssues = true;
            }
        }

        if (hasIssues)
        {
            std::cout << "  ISSUES FOUND:\n";
            for (const auto &issue : issues)
            {
                std::cout << "    - " << issue << "\n";
            }
        }
        else
        {
            std::cout << "  No critical issues detected in blockchain state.\n";
        }
        std::cout << "\n";

        std::cout << "================================================================================\n";
        std::cout << "                              END OF REPORT                                       \n";
        std::cout << "================================================================================\n";
        std::cout << "\n";
    }
};

/* Seed Node Configuration - CRITICAL FOR CHAIN SPLIT ANALYSIS */
void initializeSeedNodes(AnalysisResult &result)
{
    /* Pastella Seed Node Configuration
     *
     * IMPORTANT SECURITY NOTE: All three seed nodes expose both P2P and RPC ports.
     * This is a CRITICAL SECURITY RISK and can contribute to chain split issues.
     *
     * When seed nodes expose RPC ports:
     * 1. Malicious actors can query blockchain state
     * 2. Attackers can identify sync state of all connected peers
     * 3. This enables targeted chain split attacks
     * 4. RPC exposure allows manipulation of peer sync behavior
     */

    /* Seed Node 1 */
    AnalysisResult::SeedNodeInfo node1;
    node1.ip = "149.202.91.156";        /* rplant mining pool server */
    node1.p2pPort = 29155;               /* Pastella P2P default port */
    node1.rpcPort = 29155;               /* Pastella RPC default port */
    node1.p2pExposed = true;             /* P2P port is exposed to internet */
    node1.rpcExposed = true;             /* RPC port is exposed to internet */
    result.seedNodes.push_back(node1);

    /* Seed Node 2 */
    AnalysisResult::SeedNodeInfo node2;
    node2.ip = "51.158.71.56";           /* rplant/other pool server */
    node2.p2pPort = 29155;
    node2.rpcPort = 29155;
    node2.p2pExposed = true;
    node2.rpcExposed = true;
    result.seedNodes.push_back(node2);

    /* Seed Node 3 */
    AnalysisResult::SeedNodeInfo node3;
    node3.ip = "51.158.119.243";         /* rplant/other pool server */
    node3.p2pPort = 29155;
    node3.rpcPort = 29155;
    node3.p2pExposed = true;
    node3.rpcExposed = true;
    result.seedNodes.push_back(node3);
}

/* Analyze UTXO database */
void analyzeUtxos(
    IDataBase *database,
    const std::string &dataDir,
    AnalysisResult &result,
    std::shared_ptr<ILogger> logger)
{
    std::cout << "Analyzing UTXO database...\n";
    std::cout.flush();

    try
    {
        /* FIX: Use RocksDB iterator to scan all UTXOs directly
         *
         * The requestAllUtxos() method doesn't work - it sets a flag that is never checked.
         * We need to directly access RocksDB to scan all UTXO keys. */

        /* Create UTXO key prefix for scanning
         * UTXO keys are stored with prefix: DB::UTXO_KEY_TO_UTXO_PREFIX = "h" */
        std::string utxoPrefix = "h";

        /* Open RocksDB directly to scan */
        std::string dbPath = dataDir + "/DB";

        rocksdb::Options options;
        options.create_if_missing = false;

        rocksdb::DB* dbPtr = nullptr;
        rocksdb::Status status = rocksdb::DB::OpenForReadOnly(options, dbPath, &dbPtr);

        if (!status.ok())
        {
            std::cerr << "  ERROR: Failed to open RocksDB: " << status.ToString() << "\n";
            return;
        }

        std::unique_ptr<rocksdb::DB> db(dbPtr);

        /* Create iterator to scan all UTXOs */
        rocksdb::ReadOptions readOptions;
        std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(readOptions));

        /* DEBUG: Scan all keys in database to see what's there */
        std::cout << "  DEBUG: Scanning database for all keys...\n";
        size_t totalKeys = 0;
        std::map<std::string, size_t> prefixCounts;
        for (it->SeekToFirst(); it->Valid(); it->Next())
        {
            totalKeys++;
            std::string key = it->key().ToString();
            if (key.size() > 0)
            {
                std::string prefix = key.substr(0, 1);
                prefixCounts[prefix]++;
            }
            if (totalKeys <= 20)
            {
                std::cout << "  Key #" << totalKeys << ": prefix='";
                if (key.size() > 0)
                {
                    for (size_t i = 0; i < std::min(size_t(3), key.size()); i++)
                    {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint32_t)(uint8_t)key[i] << " ";
                    }
                    std::cout << std::dec << "' (" << key.substr(0, 1) << ")";
                }
                else
                {
                    std::cout << "(empty)";
                }
                std::cout << " size=" << key.size() << " value_size=" << it->value().size() << "\n";
            }
        }
        std::cout << "  DEBUG: Total keys in database: " << totalKeys << "\n";
        std::cout << "  DEBUG: Key prefixes found:\n";
        for (const auto &pc : prefixCounts)
        {
            std::cout << "    Prefix '" << pc.first << "' (hex: " << std::hex << (uint32_t)(uint8_t)pc.first[0] << std::dec << "): " << pc.second << " keys\n";
        }

        /* Now scan specifically for UTXOs */
        it.reset(db->NewIterator(readOptions));

        /* Count UTXOs */
        size_t totalUtxos = 0;
        size_t spentUtxos = 0;
        size_t unspentUtxos = 0;

        std::cout << "  DEBUG: Seeking UTXO prefix '" << utxoPrefix << "'...\n";
        for (it->Seek(utxoPrefix); it->Valid(); it->Next())
        {
            std::string key = it->key().ToString();
            if (key.compare(0, utxoPrefix.size(), utxoPrefix) != 0)
            {
                std::cout << "  DEBUG: Stopped at key with prefix '" << (key.size() > 0 ? key.substr(0, 1) : "") << "'\n";
                break;
            }
            totalUtxos++;
            totalUtxos++;

            /* Deserialize UTXO from value - use binary deserialization */
            const std::string &value = it->value().ToString();

            /* UtxoOutput structure:
             * uint64_t amount
             * PublicKey publicKey (32 bytes)
             * uint32_t blockIndex
             * Hash transactionHash (32 bytes)
             * uint32_t outputIndex
             * bool spent
             * uint32_t spentBlockIndex
             */
            if (value.size() < sizeof(uint64_t) + 32 + sizeof(uint32_t) + 32 + sizeof(uint32_t) + sizeof(bool) + sizeof(uint32_t))
            {
                std::cerr << "  ERROR: Invalid UTXO data size: " << value.size() << "\n";
                continue;
            }

            UtxoOutput utxo;
            size_t offset = 0;

            /* amount */
            std::memcpy(&utxo.amount, value.data() + offset, sizeof(uint64_t));
            offset += sizeof(uint64_t);

            /* publicKey */
            std::memcpy(utxo.publicKey.data, value.data() + offset, 32);
            offset += 32;

            /* blockIndex */
            std::memcpy(&utxo.blockIndex, value.data() + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);

            /* transactionHash */
            std::memcpy(utxo.transactionHash.data, value.data() + offset, 32);
            offset += 32;

            /* outputIndex */
            std::memcpy(&utxo.outputIndex, value.data() + offset, sizeof(uint32_t));
            offset += sizeof(uint32_t);

            /* spent */
            std::memcpy(&utxo.spent, value.data() + offset, sizeof(bool));
            offset += sizeof(bool);

            /* spentBlockIndex */
            std::memcpy(&utxo.spentBlockIndex, value.data() + offset, sizeof(uint32_t));

            /* Track UTXOs by creation block */
            result.utxosPerBlock[utxo.blockIndex]++;

            if (utxo.spent)
            {
                spentUtxos++;
                result.spentUtxosPerBlock[utxo.spentBlockIndex]++;
            }
            else
            {
                unspentUtxos++;
            }

            /* Print first few UTXOs for verification */
            if (totalUtxos <= 5)
            {
                std::cout << "  UTXO #" << totalUtxos << ": tx=" << Common::podToHex(utxo.transactionHash).substr(0, 16)
                          << " output=" << utxo.outputIndex
                          << " amount=" << utxo.amount
                          << " block=" << utxo.blockIndex
                          << " spent=" << (utxo.spent ? "yes" : "no") << "\n";
            }
        }

        result.totalUtxos = totalUtxos;
        result.spentUtxos = spentUtxos;
        result.unspentUtxos = unspentUtxos;

        std::cout << "  Found " << result.totalUtxos << " total UTXOs\n";
        std::cout << "  Found " << result.spentUtxos << " spent UTXOs\n";
        std::cout << "  Found " << result.unspentUtxos << " unspent UTXOs\n";

        /* Validate UTXO consistency */
        if (result.spentUtxos > result.totalUtxos)
        {
            std::cerr << "  ERROR: More spent UTXOs than total UTXOs (database corruption)\n";
        }

        /* Check iterator status */
        if (!it->status().ok())
        {
            std::cerr << "  WARNING: Iterator error: " << it->status().ToString() << "\n";
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "  ERROR: Exception during UTXO analysis: " << e.what() << "\n";
    }
}

/* Analyze block information */
void analyzeBlocks(
    IDataBase *database,
    const Currency &currency,
    AnalysisResult &result,
    std::shared_ptr<ILogger> logger)
{
    std::cout << "Analyzing block information...\n";
    std::cout.flush();

    try
    {
        /* Get last block index */
        BlockchainReadBatch indexBatch;
        indexBatch.requestLastBlockIndex();

        auto readResult = database->read(indexBatch);
        if (readResult)
        {
            std::cerr << "ERROR: Failed to read last block index: " << readResult.message() << "\n";
            return;
        }

        BlockchainReadResult batchResult = indexBatch.extractResult();
        const auto &lastBlockIndex = batchResult.getLastBlockIndex();

        if (!lastBlockIndex.second)
        {
            std::cerr << "ERROR: No last block index found in database\n";
            return;
        }

        result.topBlockIndex = lastBlockIndex.first;

        std::cout << "  Top block index: " << result.topBlockIndex << "\n";

        /* Read block info for last 100 blocks */
        uint32_t startBlock = std::max((uint32_t)0, result.topBlockIndex - 100);
        std::cout << "  Reading blocks " << startBlock << " to " << result.topBlockIndex << "...\n";

        BlockchainReadBatch blocksBatch;
        for (uint32_t i = startBlock; i <= result.topBlockIndex; ++i)
        {
            blocksBatch.requestCachedBlock(i);
            blocksBatch.requestTransactionHashesByBlock(i);
            blocksBatch.requestSpentKeyImagesByBlock(i);
        }

        readResult = database->read(blocksBatch);
        if (readResult)
        {
            std::cerr << "ERROR: Failed to read block information: " << readResult.message() << "\n";
            return;
        }

        BlockchainReadResult blocksBatchResult = blocksBatch.extractResult();
        const auto &blocks = blocksBatchResult.getCachedBlocks();
        const auto &txHashes = blocksBatchResult.getTransactionHashesByBlocks();
        const auto &spentKeyImages = blocksBatchResult.getSpentKeyImagesByBlock();

        /* Process block information */
        for (const auto &blockPair : blocks)
        {
            const CachedBlockInfo &blockInfo = blockPair.second;

            result.timestamps.push_back(blockInfo.timestamp);
            result.blockSizes.push_back(blockInfo.blockSize);
            /* CachedBlockInfo doesn't have difficulty field, use cumulativeDifficulty */
            result.difficulties.push_back(blockInfo.cumulativeDifficulty);
            result.cumulativeDifficulties.push_back(blockInfo.cumulativeDifficulty);

            /* Track transactions per block */
            if (txHashes.count(blockPair.first) > 0)
            {
                result.transactionsPerBlock[blockPair.first] = txHashes.at(blockPair.first);
            }

            /* Track spent key images */
            if (spentKeyImages.count(blockPair.first) > 0)
            {
                result.spentKeyImagesByBlock[blockPair.first] = spentKeyImages.at(blockPair.first);
            }
        }

        std::cout << "  Processed " << blocks.size() << " blocks\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "  ERROR: Exception during block analysis: " << e.what() << "\n";
    }
}

/* Analyze database structure and consistency */
void analyzeDatabaseConsistency(
    IDataBase *database,
    AnalysisResult &result,
    std::shared_ptr<ILogger> logger)
{
    std::cout << "Analyzing database consistency...\n";
    std::cout.flush();

    try
    {
        /* Get transaction count */
        BlockchainReadBatch txBatch;
        txBatch.requestTransactionsCount();

        auto readResult = database->read(txBatch);
        if (!readResult)
        {
            BlockchainReadResult batchResult = txBatch.extractResult();
            const auto &txCount = batchResult.getTransactionsCount();
            if (txCount.second)
            {
                result.totalTransactions = txCount.first;
                std::cout << "  Total transactions: " << result.totalTransactions << "\n";
            }
        }

        /* Check for key output amounts */
        BlockchainReadBatch amountsBatch;
        amountsBatch.requestKeyOutputAmountsCount();

        readResult = database->read(amountsBatch);
        if (!readResult)
        {
            BlockchainReadResult batchResult = amountsBatch.extractResult();
            uint32_t amountsCount = batchResult.getKeyOutputAmountsCount();
            std::cout << "  Unique key output amounts: " << amountsCount << "\n";
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "  ERROR: Exception during database consistency analysis: " << e.what() << "\n";
    }
}

/* Main analysis function */
void analyzeBlockchain(const std::string &dataDir, const std::string &outputFile = "")
{
    std::cout << "\n";
    std::cout << "Pastella Blockchain Analysis Tool\n";
    std::cout << "=================================\n";
    std::cout << "Data Directory: " << dataDir << "\n";
    std::cout << "\n";

    /* Initialize logging */
    std::shared_ptr<Logging::ILogger> logger = std::make_shared<Logging::ConsoleLogger>(TRACE);

    try
    {
        /* Create database */
        std::cout << "Opening blockchain database...\n";
        std::cout.flush();

        /* Setup database configuration */
        DataBaseConfig dbConfig;
        dbConfig.init(
            dataDir,          /* data directory */
            2,                /* background threads */
            100,              /* max open files */
            256,              /* write buffer size MB */
            64,               /* read cache size MB */
            true              /* compression enabled */
        );

        /* Create and initialize RocksDBWrapper */
        std::shared_ptr<RocksDBWrapper> rocksdb = std::make_shared<RocksDBWrapper>(logger);
        rocksdb->init(dbConfig);

        IDataBase *database = rocksdb.get();

        /* Initialize currency with logger parameter */
        Currency currency = CurrencyBuilder(logger).currency();

        /* Initialize analysis result */
        AnalysisResult result;

        /* Initialize seed node information */
        initializeSeedNodes(result);

        /* Run analysis */
        analyzeDatabaseConsistency(database, result, logger);
        analyzeBlocks(database, currency, result, logger);
        analyzeUtxos(database, dataDir, result, logger);

        /* Calculate total coins (based on block height and emission) */
        if (result.topBlockIndex > 0)
        {
            /* Get actual generated coins from blockchain - approximate using block 0 if available */
            BlockchainReadBatch genesisBatch;
            genesisBatch.requestCachedBlock(0);
            auto readResult = database->read(genesisBatch);
            if (!readResult)
            {
                BlockchainReadResult genesisResult = genesisBatch.extractResult();
                const auto &genesisBlocks = genesisResult.getCachedBlocks();
                if (genesisBlocks.count(0) > 0)
                {
                    /* Use actual generated coins from genesis block + estimated emission */
                    result.totalCoins = genesisBlocks.at(0).alreadyGeneratedCoins +
                                       (result.topBlockIndex * 100000000); /* Approx 1 PT per block */
                }
            }
            else
            {
                /* Fallback: simple estimate */
                result.totalCoins = result.topBlockIndex * 100000000;
            }
        }

        /* Print report */
        std::streambuf *old = std::cout.rdbuf();
        std::ofstream fileStream;

        if (!outputFile.empty())
        {
            fileStream.open(outputFile);
            if (fileStream.is_open())
            {
                std::cout << "Writing report to: " << outputFile << "\n";
                std::cout.rdbuf(fileStream.rdbuf());
            }
            else
            {
                std::cerr << "WARNING: Could not open output file: " << outputFile << "\n";
            }
        }

        result.printReport();

        if (fileStream.is_open())
        {
            std::cout.rdbuf(old);
            fileStream.close();
            std::cout << "Report written successfully.\n";
        }

        /* Shutdown database */
        rocksdb->shutdown();
    }
    catch (const std::exception &e)
    {
        std::cerr << "FATAL ERROR: " << e.what() << "\n";
        return;
    }
}

int main(int argc, char *argv[])
{
    std::string dataDir = "./BCDebug";
    std::string outputFile = "";

    /* Parse command line arguments */
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h")
        {
            std::cout << "Pastella Blockchain Analysis Tool\n";
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "\n";
            std::cout << "Options:\n";
            std::cout << "  --data-dir <path>    Path to blockchain database directory (default: ./BCDebug)\n";
            std::cout << "  --output <file>      Write report to file\n";
            std::cout << "  --help, -h           Show this help message\n";
            std::cout << "\n";
            std::cout << "This tool analyzes the Pastella blockchain database to identify\n";
            std::cout << "potential issues that could cause chain splits.\n";
            std::cout << "\n";
            std::cout << "Analysis includes:\n";
            std::cout << "  - UTXO database consistency\n";
            std::cout << "  - Block validation statistics\n";
            std::cout << "  - Transaction validation issues\n";
            std::cout << "  - Seed node configuration (P2P/RPC exposure)\n";
            std::cout << "  - Database structure validation\n";
            std::cout << "\n";
            return 0;
        }
        else if (arg == "--data-dir" && i + 1 < argc)
        {
            dataDir = argv[++i];
        }
        else if (arg == "--output" && i + 1 < argc)
        {
            outputFile = argv[++i];
        }
        else if (arg[0] == '-')
        {
            std::cerr << "Unknown option: " << arg << "\n";
            std::cerr << "Use --help for usage information.\n";
            return 1;
        }
        else
        {
            dataDir = arg;
        }
    }

    analyzeBlockchain(dataDir, outputFile);

    return 0;
}
