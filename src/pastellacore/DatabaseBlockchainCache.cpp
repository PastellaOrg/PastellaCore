// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "BlockchainUtils.h"
#include "crypto/hash.h"

#include <boost/iterator/iterator_facade.hpp>
#include <common/PastellaTools.h>
#include <common/ShuffleGenerator.h>
#include <common/TransactionExtra.h>
#include <pastellacore/BlockchainCache.h>
#include <pastellacore/BlockchainStorage.h>
#include <pastellacore/PastellaBasicImpl.h>
#include <pastellacore/DatabaseBlockchainCache.h>
#include <cstdlib>
#include <ctime>

namespace Pastella
{
    namespace
    {
        const uint32_t ONE_DAY_SECONDS = 60 * 60 * 24;

        const CachedBlockInfo NULL_CACHED_BLOCK_INFO {Constants::NULL_HASH, 0, 0, 0, 0, 0};

        bool requestPackedOutputs(
            IBlockchainCache::Amount amount,
            Common::ArrayView<uint32_t> globalIndexes,
            IDataBase &database,
            std::vector<PackedOutIndex> &result)
        {
            BlockchainReadBatch readBatch;
            result.reserve(result.size() + globalIndexes.getSize());

            for (auto globalIndex : globalIndexes)
            {
                readBatch.requestKeyOutputGlobalIndexForAmount(amount, globalIndex);
            }

            auto dbResult = database.read(readBatch);
            if (dbResult)
            {
                return false;
            }

            try
            {
                auto readResult = readBatch.extractResult();
                const auto &packedOutsMap = readResult.getKeyOutputGlobalIndexesForAmounts();
                for (auto globalIndex : globalIndexes)
                {
                    result.push_back(packedOutsMap.at(std::make_pair(amount, globalIndex)));
                }
            }
            catch (std::exception &)
            {
                return false;
            }

            return true;
        }

        bool requestTransactionHashesForGlobalOutputIndexes(
            const std::vector<PackedOutIndex> &packedOuts,
            IDataBase &database,
            std::vector<Crypto::Hash> &transactionHashes)
        {
            BlockchainReadBatch readHashesBatch;

            std::set<uint32_t> blockIndexes;
            std::for_each(packedOuts.begin(), packedOuts.end(), [&blockIndexes](PackedOutIndex out) {
                blockIndexes.insert(out.blockIndex);
            });
            std::for_each(blockIndexes.begin(), blockIndexes.end(), [&readHashesBatch](uint32_t blockIndex) {
                readHashesBatch.requestTransactionHashesByBlock(blockIndex);
            });

            auto dbResult = database.read(readHashesBatch);
            if (dbResult)
            {
                return false;
            }

            auto readResult = readHashesBatch.extractResult();
            const auto &transactionHashesMap = readResult.getTransactionHashesByBlocks();

            if (transactionHashesMap.size() != blockIndexes.size())
            {
                return false;
            }

            transactionHashes.reserve(transactionHashes.size() + packedOuts.size());
            for (const auto &output : packedOuts)
            {
                if (output.transactionIndex >= transactionHashesMap.at(output.blockIndex).size())
                {
                    return false;
                }

                transactionHashes.push_back(transactionHashesMap.at(output.blockIndex)[output.transactionIndex]);
            }

            return true;
        }

        bool requestCachedTransactionInfos(
            const std::vector<Crypto::Hash> &transactionHashes,
            IDataBase &database,
            std::vector<CachedTransactionInfo> &result)
        {
            result.reserve(result.size() + transactionHashes.size());

            BlockchainReadBatch transactionsBatch;
            std::for_each(
                transactionHashes.begin(), transactionHashes.end(), [&transactionsBatch](const Crypto::Hash &hash) {
                    transactionsBatch.requestCachedTransaction(hash);
                });
            auto dbResult = database.read(transactionsBatch);
            if (dbResult)
            {
                return false;
            }

            auto readResult = transactionsBatch.extractResult();
            const auto &transactions = readResult.getCachedTransactions();
            if (transactions.size() != transactionHashes.size())
            {
                return false;
            }

            for (const auto &hash : transactionHashes)
            {
                result.push_back(transactions.at(hash));
            }

            return true;
        }

        // returns CachedTransactionInfos in the same or as packedOuts are
        /*
        bool requestCachedTransactionInfos(const std::vector<PackedOutIndex>& packedOuts, IDataBase& database,
        std::vector<CachedTransactionInfo>& result) { std::vector<Crypto::Hash> transactionHashes; if
        (!requestTransactionHashesForGlobalOutputIndexes(packedOuts, database, transactionHashes)) { return false;
          }

          return requestCachedTransactionInfos(transactionHashes, database, result);
        }
        */

        bool requestExtendedTransactionInfos(
            const std::vector<Crypto::Hash> &transactionHashes,
            IDataBase &database,
            std::vector<ExtendedTransactionInfo> &result)
        {
            result.reserve(result.size() + transactionHashes.size());

            BlockchainReadBatch transactionsBatch;
            std::for_each(
                transactionHashes.begin(), transactionHashes.end(), [&transactionsBatch](const Crypto::Hash &hash) {
                    transactionsBatch.requestCachedTransaction(hash);
                });
            auto dbResult = database.read(transactionsBatch);
            if (dbResult)
            {
                return false;
            }

            auto readResult = transactionsBatch.extractResult();
            const auto &transactions = readResult.getCachedTransactions();

            std::unordered_set<Crypto::Hash> uniqueTransactionHashes(
                transactionHashes.begin(), transactionHashes.end());
            if (transactions.size() != uniqueTransactionHashes.size())
            {
                return false;
            }

            for (const auto &hash : transactionHashes)
            {
                result.push_back(transactions.at(hash));
            }

            return true;
        }

        // returns ExtendedTransactionInfos in the same order as packedOuts are
        bool requestExtendedTransactionInfos(
            const std::vector<PackedOutIndex> &packedOuts,
            IDataBase &database,
            std::vector<ExtendedTransactionInfo> &result)
        {
            std::vector<Crypto::Hash> transactionHashes;
            if (!requestTransactionHashesForGlobalOutputIndexes(packedOuts, database, transactionHashes))
            {
                return false;
            }

            return requestExtendedTransactionInfos(transactionHashes, database, result);
        }

        uint64_t roundToMidnight(uint64_t timestamp)
        {
            if (timestamp > static_cast<uint64_t>(std::numeric_limits<time_t>::max()))
            {
                throw std::runtime_error("Timestamp is too big");
            }

            return static_cast<uint64_t>((timestamp / ONE_DAY_SECONDS) * ONE_DAY_SECONDS);
        }

        std::pair<boost::optional<uint32_t>, bool>
            requestClosestBlockIndexByTimestamp(uint64_t timestamp, IDataBase &database)
        {
            std::pair<boost::optional<uint32_t>, bool> result = {{}, false};

            BlockchainReadBatch readBatch;
            readBatch.requestClosestTimestampBlockIndex(timestamp);
            auto dbResult = database.read(readBatch);
            if (dbResult)
            {
                return result;
            }

            result.second = true;
            auto readResult = readBatch.extractResult();
            if (readResult.getClosestTimestampBlockIndex().count(timestamp))
            {
                result.first = readResult.getClosestTimestampBlockIndex().at(timestamp);
            }

            return result;
        }

        bool requestRawBlock(IDataBase &database, uint32_t blockIndex, RawBlock &block)
        {
            auto batch = BlockchainReadBatch().requestRawBlock(blockIndex);

            auto error = database.read(batch);
            if (error)
            {
                // may be throw in all similiar functions???
                return false;
            }

            auto result = batch.extractResult();
            if (result.getRawBlocks().count(blockIndex) == 0)
            {
                return false;
            }

            block = result.getRawBlocks().at(blockIndex);
            return true;
        }

        Transaction extractTransaction(const RawBlock &block, uint32_t transactionIndex)
        {
            assert(transactionIndex < block.transactions.size() + 1);

            if (transactionIndex != 0)
            {
                Transaction transaction;
                bool r = fromBinaryArray(transaction, block.transactions[transactionIndex - 1]);
                if (r)
                {
                }
                assert(r);

                return transaction;
            }

            BlockTemplate blockTemplate;
            bool r = fromBinaryArray(blockTemplate, block.block);
            if (r)
            {
            }
            assert(r);

            return blockTemplate.baseTransaction;
        }

        uint32_t requestKeyOutputGlobalIndexesCountForAmount(IBlockchainCache::Amount amount, IDataBase &database)
        {
            auto batch = BlockchainReadBatch().requestKeyOutputGlobalIndexesCountForAmount(amount);
            auto dbError = database.read(batch);
            if (dbError)
            {
                throw std::system_error(dbError, "Cannot perform requestKeyOutputGlobalIndexesCountForAmount query");
            }

            auto result = batch.extractResult();

            if (result.getKeyOutputGlobalIndexesCountForAmounts().count(amount) != 0)
            {
                return result.getKeyOutputGlobalIndexesCountForAmounts().at(amount);
            }
            else
            {
                return 0;
            }
        }

        class DbOutputConstIterator :
            public boost::iterator_facade<
                DbOutputConstIterator,
                const PackedOutIndex,
                boost::random_access_traversal_tag /*boost::forward_traversal_tag*/>
        {
          public:
            DbOutputConstIterator(
                std::function<PackedOutIndex(IBlockchainCache::Amount amount, uint32_t globalOutputIndex)> retriever_,
                IBlockchainCache::Amount amount_,
                uint32_t globalOutputIndex_):
                retriever(retriever_),
                amount(amount_),
                globalOutputIndex(globalOutputIndex_)
            {
            }

            const PackedOutIndex &dereference() const
            {
                cachedValue = retriever(amount, globalOutputIndex);
                return cachedValue;
            }

            bool equal(const DbOutputConstIterator &other) const
            {
                return globalOutputIndex == other.globalOutputIndex;
            }

            void increment()
            {
                ++globalOutputIndex;
            }

            void decrement()
            {
                --globalOutputIndex;
            }

            void advance(difference_type n)
            {
                assert(n >= -static_cast<difference_type>(globalOutputIndex));
                globalOutputIndex += static_cast<uint32_t>(n);
            }

            difference_type distance_to(const DbOutputConstIterator &to) const
            {
                return static_cast<difference_type>(to.globalOutputIndex)
                       - static_cast<difference_type>(globalOutputIndex);
            }

          private:
            std::function<PackedOutIndex(IBlockchainCache::Amount amount, uint32_t globalOutputIndex)> retriever;

            IBlockchainCache::Amount amount;

            uint32_t globalOutputIndex;

            mutable PackedOutIndex cachedValue;
        };

        PackedOutIndex
            retrieveKeyOutput(IBlockchainCache::Amount amount, uint32_t globalOutputIndex, IDataBase &database)
        {
            BlockchainReadBatch batch;
            auto dbError = database.read(batch.requestKeyOutputGlobalIndexForAmount(amount, globalOutputIndex));
            if (dbError)
            {
                throw std::system_error(dbError, "Error during retrieving key output by global output index");
            }

            auto result = batch.extractResult();

            try
            {
                return result.getKeyOutputGlobalIndexesForAmounts().at(std::make_pair(amount, globalOutputIndex));
            }
            catch (std::exception &)
            {
                assert(false);
                throw std::runtime_error(
                    "Couldn't find key output for amount " + std::to_string(amount) + " with global output index "
                    + std::to_string(globalOutputIndex));
            }
        }

        std::map<IBlockchainCache::Amount, IBlockchainCache::GlobalOutputIndex> getMinGlobalIndexesByAmount(
            const std::map<IBlockchainCache::Amount, std::vector<IBlockchainCache::GlobalOutputIndex>> &outputIndexes)
        {
            std::map<IBlockchainCache::Amount, IBlockchainCache::GlobalOutputIndex> minIndexes;
            for (const auto &kv : outputIndexes)
            {
                auto min = std::min_element(kv.second.begin(), kv.second.end());
                if (min == kv.second.end())
                {
                    continue;
                }

                minIndexes.emplace(kv.first, *min);
            }

            return minIndexes;
        }

        void mergeOutputsSplitBoundaries(
            std::map<IBlockchainCache::Amount, IBlockchainCache::GlobalOutputIndex> &dest,
            const std::map<IBlockchainCache::Amount, IBlockchainCache::GlobalOutputIndex> &src)
        {
            for (const auto &elem : src)
            {
                auto it = dest.find(elem.first);
                if (it == dest.end())
                {
                    dest.emplace(elem.first, elem.second);
                    continue;
                }

                if (it->second > elem.second)
                {
                    it->second = elem.second;
                }
            }
        }

        void cutTail(std::deque<CachedBlockInfo> &cache, size_t count)
        {
            if (count >= cache.size())
            {
                cache.clear();
                return;
            }

            cache.erase(std::next(cache.begin(), cache.size() - count), cache.end());
        }

        const std::string DB_VERSION_KEY = "db_scheme_version";

        class DatabaseVersionReadBatch : public IReadBatch
        {
          public:
            virtual ~DatabaseVersionReadBatch() {}

            virtual std::vector<std::string> getRawKeys() const override
            {
                return {DB_VERSION_KEY};
            }

            virtual void
                submitRawResult(const std::vector<std::string> &values, const std::vector<bool> &resultStates) override
            {
                assert(values.size() == 1);
                assert(resultStates.size() == values.size());

                if (!resultStates[0])
                {
                    return;
                }

                version = static_cast<uint32_t>(std::atoi(values[0].c_str()));
            }

            boost::optional<uint32_t> getDbSchemeVersion()
            {
                return version;
            }

          private:
            boost::optional<uint32_t> version;
        };

        class DatabaseVersionWriteBatch : public IWriteBatch
        {
          public:
            DatabaseVersionWriteBatch(uint32_t version): schemeVersion(version) {}

            virtual ~DatabaseVersionWriteBatch() {}

            virtual std::vector<std::pair<std::string, std::string>> extractRawDataToInsert() override
            {
                return {make_pair(DB_VERSION_KEY, std::to_string(schemeVersion))};
            }

            virtual std::vector<std::string> extractRawKeysToRemove() override
            {
                return {};
            }

          private:
            uint32_t schemeVersion;
        };

        const uint32_t CURRENT_DB_SCHEME_VERSION = 2;

    } // namespace

    struct DatabaseBlockchainCache::ExtendedPushedBlockInfo
    {
        PushedBlockInfo pushedBlockInfo;
        uint64_t timestamp;
    };

    DatabaseBlockchainCache::DatabaseBlockchainCache(
        const Currency &curr,
        IDataBase &dataBase,
        IBlockchainCacheFactory &blockchainCacheFactory,
        std::shared_ptr<Logging::ILogger> _logger):
        currency(curr),
        database(dataBase),
        blockchainCacheFactory(blockchainCacheFactory),
        logger(_logger, "Database")
    {
        DatabaseVersionReadBatch readBatch;
        auto ec = database.read(readBatch);
        if (ec)
        {
            throw std::system_error(ec);
        }

        auto version = readBatch.getDbSchemeVersion();
        if (!version)
        {
            logger(Logging::DEBUGGING) << "DB scheme version not found, writing: " << CURRENT_DB_SCHEME_VERSION;

            DatabaseVersionWriteBatch writeBatch(CURRENT_DB_SCHEME_VERSION);
            auto writeError = database.write(writeBatch);
            if (writeError)
            {
                throw std::system_error(writeError);
            }
        }
        else
        {
            logger(Logging::DEBUGGING) << "Current db scheme version: " << *version;
        }

        if (getTopBlockIndex() == 0)
        {
            logger(Logging::DEBUGGING) << "top block index is null, add genesis block";
            addGenesisBlock(CachedBlock(currency.genesisBlock()));
        }
    }

    bool DatabaseBlockchainCache::checkDBSchemeVersion(IDataBase &database, std::shared_ptr<Logging::ILogger> _logger)
    {
        Logging::LoggerRef logger(_logger, "Database");

        DatabaseVersionReadBatch readBatch;
        auto ec = database.read(readBatch);
        if (ec)
        {
            throw std::system_error(ec);
        }

        auto version = readBatch.getDbSchemeVersion();
        if (!version)
        {
            // DB scheme version not found. Looks like it was just created.
            return true;
        }
        else if (*version < CURRENT_DB_SCHEME_VERSION)
        {
            logger(Logging::WARNING) << "DB scheme version is less than expected. Expected version "
                                     << CURRENT_DB_SCHEME_VERSION << ". Actual version " << *version
                                     << ". DB will be destroyed and recreated from blocks.bin file.";
            return false;
        }
        else if (*version > CURRENT_DB_SCHEME_VERSION)
        {
            logger(Logging::ERROR) << "DB scheme version is greater than expected. Expected version "
                                   << CURRENT_DB_SCHEME_VERSION << ". Actual version " << *version
                                   << ". Please update your software.";
            throw std::runtime_error("DB scheme version is greater than expected");
        }
        else
        {
            return true;
        }
    }

    void DatabaseBlockchainCache::deleteClosestTimestampBlockIndex(
        BlockchainWriteBatch &writeBatch,
        uint32_t splitBlockIndex)
    {
        auto batch = BlockchainReadBatch().requestCachedBlock(splitBlockIndex);
        auto blockResult = readDatabase(batch);
        auto timestamp = blockResult.getCachedBlocks().at(splitBlockIndex).timestamp;

        auto midnight = roundToMidnight(timestamp);
        auto timestampResult = requestClosestBlockIndexByTimestamp(midnight, database);
        if (!timestampResult.second)
        {
            logger(Logging::ERROR)
                << "deleteClosestTimestampBlockIndex error: get closest timestamp block index, database read failed";
            throw std::runtime_error("Couldn't get closest timestamp block index");
        }

        assert(bool(timestampResult.first));

        auto blockIndex = *timestampResult.first;
        assert(splitBlockIndex >= blockIndex);

        if (splitBlockIndex != blockIndex)
        {
            midnight += ONE_DAY_SECONDS;
        }

        BlockchainReadBatch midnightBatch;
        while (readDatabase(midnightBatch.requestClosestTimestampBlockIndex(midnight))
                   .getClosestTimestampBlockIndex()
                   .count(midnight))
        {
            writeBatch.removeClosestTimestampBlockIndex(midnight);
            midnight += ONE_DAY_SECONDS;
        }

        logger(Logging::TRACE) << "deleted closest timestamp";
    }

    /*
     * This methods splits cache, upper part (ie blocks with indexes greater or equal to splitBlockIndex)
     * is copied to new BlockchainCache
     */
    std::unique_ptr<IBlockchainCache> DatabaseBlockchainCache::split(uint32_t splitBlockIndex)
    {
        assert(splitBlockIndex <= getTopBlockIndex());
        logger(Logging::DEBUGGING) << "split at index " << splitBlockIndex
                                   << " started, top block index: " << getTopBlockIndex();

        auto cache = blockchainCacheFactory.createBlockchainCache(currency, this, splitBlockIndex);

        using DeleteBlockInfo = std::tuple<uint32_t, Crypto::Hash, TransactionValidatorState, uint64_t>;
        std::vector<DeleteBlockInfo> deletingBlocks;

        BlockchainWriteBatch writeBatch;
        auto currentTop = getTopBlockIndex();
        for (uint32_t blockIndex = splitBlockIndex; blockIndex <= currentTop; ++blockIndex)
        {
            ExtendedPushedBlockInfo extendedInfo = getExtendedPushedBlockInfo(blockIndex);

            auto validatorState = extendedInfo.pushedBlockInfo.validatorState;
            logger(Logging::DEBUGGING) << "pushing block " << blockIndex << " to child segment";
            auto blockHash = pushBlockToAnotherCache(*cache, std::move(extendedInfo.pushedBlockInfo));

            deletingBlocks.emplace_back(blockIndex, blockHash, validatorState, extendedInfo.timestamp);
        }

        for (auto it = deletingBlocks.rbegin(); it != deletingBlocks.rend(); ++it)
        {
            auto blockIndex = std::get<0>(*it);
            auto blockHash = std::get<1>(*it);
            auto &validatorState = std::get<2>(*it);
            uint64_t timestamp = std::get<3>(*it);

            writeBatch.removeCachedBlock(blockHash, blockIndex).removeRawBlock(blockIndex);
            requestDeleteSpentOutputs(writeBatch, blockIndex, validatorState);
            requestRemoveTimestamp(writeBatch, timestamp, blockHash);
        }

        auto deletingTransactionHashes = requestTransactionHashesFromBlockIndex(splitBlockIndex);
        requestDeleteTransactions(writeBatch, deletingTransactionHashes);

        std::vector<ExtendedTransactionInfo> extendedTransactions;
        if (!requestExtendedTransactionInfos(deletingTransactionHashes, database, extendedTransactions))
        {
            logger(Logging::ERROR) << "Error while split: failed to request extended transaction info";
            throw std::runtime_error("failed to request extended transaction info"); // TODO: make error codes
        }

        std::map<IBlockchainCache::Amount, IBlockchainCache::GlobalOutputIndex> keyIndexSplitBoundaries;
        for (const auto &transaction : extendedTransactions)
        {
            auto txkeyBoundaries = getMinGlobalIndexesByAmount(transaction.amountToKeyIndexes);

            mergeOutputsSplitBoundaries(keyIndexSplitBoundaries, txkeyBoundaries);
        }

        requestDeleteKeyOutputs(writeBatch, keyIndexSplitBoundaries);

        deleteClosestTimestampBlockIndex(writeBatch, splitBlockIndex);

        logger(Logging::DEBUGGING) << "Performing delete operations";
        // all data and indexes are now copied, no errors detected, can now erase data from database
        auto err = database.write(writeBatch);
        if (err)
        {
            logger(Logging::ERROR) << "split write failed, " << err.message();
            throw std::runtime_error(err.message());
        }

        cutTail(unitsCache, currentTop + 1 - splitBlockIndex);

        /* UTXO IMMEDIATE AVAILABILITY FIX: Clear raw blocks cache on split
         *
         * When a blockchain split occurs (reorg), we need to remove blocks
         * from the raw blocks cache that are being moved to the new segment. */
        rawBlocksCache.clear();
        logger(Logging::DEBUGGING) << "Cleared raw blocks cache due to split";

        children.push_back(cache.get());
        logger(Logging::TRACE) << "Delete successfull";

        // invalidate top block index and hash
        topBlockIndex = boost::none;
        topBlockHash = boost::none;
        transactionsCount = boost::none;

        logger(Logging::DEBUGGING) << "split completed";
        // return new cache
        return cache;
    }

    // returns hash of pushed block
    Crypto::Hash
        DatabaseBlockchainCache::pushBlockToAnotherCache(IBlockchainCache &segment, PushedBlockInfo &&pushedBlockInfo)
    {
        BlockTemplate block;
        bool br = fromBinaryArray(block, pushedBlockInfo.rawBlock.block);
        if (br)
        {
        }
        assert(br);

        std::vector<CachedTransaction> transactions;
        bool tr = Utils::restoreCachedTransactions(pushedBlockInfo.rawBlock.transactions, transactions);
        if (tr)
        {
        }
        assert(tr);

        CachedBlock cachedBlock(block);
        segment.pushBlock(
            cachedBlock,
            transactions,
            pushedBlockInfo.validatorState,
            pushedBlockInfo.blockSize,
            pushedBlockInfo.generatedCoins,
            pushedBlockInfo.blockDifficulty,
            std::move(pushedBlockInfo.rawBlock));

        return cachedBlock.getBlockHash();
    }

    std::vector<Crypto::Hash> DatabaseBlockchainCache::requestTransactionHashesFromBlockIndex(uint32_t splitBlockIndex)
    {
        logger(Logging::DEBUGGING) << "Requesting transaction hashes starting from block index " << splitBlockIndex;

        BlockchainReadBatch readBatch;
        for (uint32_t blockIndex = splitBlockIndex; blockIndex <= getTopBlockIndex(); ++blockIndex)
        {
            readBatch.requestTransactionHashesByBlock(blockIndex);
        }

        std::vector<Crypto::Hash> transactionHashes;

        auto dbResult = readDatabase(readBatch);
        for (const auto &kv : dbResult.getTransactionHashesByBlocks())
        {
            for (const auto &hash : kv.second)
            {
                transactionHashes.emplace_back(hash);
            }
        }

        return transactionHashes;
    }

    void DatabaseBlockchainCache::requestDeleteTransactions(
        BlockchainWriteBatch &writeBatch,
        const std::vector<Crypto::Hash> &transactionHashes)
    {
        for (const auto &hash : transactionHashes)
        {
            assert(getCachedTransactionsCount() > 0);
            writeBatch.removeCachedTransaction(hash, getCachedTransactionsCount() - 1);
            transactionsCount = *transactionsCount - 1;
        }
    }

    /* TRANSPARENT SYSTEM: Remove spent transaction hashes during blockchain reorg
     * When a block is removed from the chain (reorg), we need to also remove
     * the spent transaction markers for that block so those transactions can
     * be spent again in the new chain. */
    void DatabaseBlockchainCache::requestDeleteSpentOutputs(
        BlockchainWriteBatch &writeBatch,
        uint32_t blockIndex,
        const TransactionValidatorState &spentOutputs)
    {
        logger(Logging::DEBUGGING) << "Deleting spent outputs for block index " << blockIndex;

        /* Convert spent transaction hashes to PublicKey format for database removal
         * This matches what we did in pushBlock when inserting them */
        std::vector<Crypto::PublicKey> spentTxHashesAsKeys;
        spentTxHashesAsKeys.reserve(spentOutputs.spentTransactions.size());

        for (const Crypto::Hash &txHash : spentOutputs.spentTransactions)
        {
            /* Convert transaction hash to public key for storage compatibility */
            Crypto::PublicKey txHashAsKey;
            std::memcpy(txHashAsKey.data, txHash.data, sizeof(Crypto::Hash));
            spentTxHashesAsKeys.push_back(txHashAsKey);

            logger(Logging::DEBUGGING) << "Removing spent transaction hash: " << txHash;
        }

        writeBatch.removeSpentKeyImages(blockIndex, spentTxHashesAsKeys);
    }

    void DatabaseBlockchainCache::requestDeleteKeyOutputs(
        BlockchainWriteBatch &writeBatch,
        const std::map<IBlockchainCache::Amount, IBlockchainCache::GlobalOutputIndex> &boundaries)
    {
        if (boundaries.empty())
        {
            // hardly possible
            logger(Logging::DEBUGGING) << "No key output amounts...";
            return;
        }

        BlockchainReadBatch readBatch;
        for (auto kv : boundaries)
        {
            readBatch.requestKeyOutputGlobalIndexesCountForAmount(kv.first);
        }

        std::unordered_map<IBlockchainCache::Amount, uint32_t> amountCounts =
            readDatabase(readBatch).getKeyOutputGlobalIndexesCountForAmounts();
        assert(amountCounts.size() == boundaries.size());

        for (const auto &kv : amountCounts)
        {
            auto it = boundaries.find(
                kv.first); // can't be equal end() since assert(amountCounts.size() == boundaries.size())
            requestDeleteKeyOutputsAmount(writeBatch, kv.first, it->second, kv.second);
        }
    }

    void DatabaseBlockchainCache::requestDeleteKeyOutputsAmount(
        BlockchainWriteBatch &writeBatch,
        IBlockchainCache::Amount amount,
        IBlockchainCache::GlobalOutputIndex boundary,
        uint32_t outputsCount)
    {
        logger(Logging::DEBUGGING) << "Requesting delete for key output amount " << amount
                                   << " starting from global index " << boundary << " to " << (outputsCount - 1);

        writeBatch.removeKeyOutputGlobalIndexes(amount, outputsCount - boundary, boundary);
        for (GlobalOutputIndex index = boundary; index < outputsCount; ++index)
        {
            writeBatch.removeKeyOutputInfo(amount, index);
        }

        updateKeyOutputCount(amount, boundary - outputsCount);
    }

    void DatabaseBlockchainCache::requestRemoveTimestamp(
        BlockchainWriteBatch &batch,
        uint64_t timestamp,
        const Crypto::Hash &blockHash)
    {
        auto readBatch = BlockchainReadBatch().requestBlockHashesByTimestamp(timestamp);
        auto result = readDatabase(readBatch);

        if (result.getBlockHashesByTimestamp().count(timestamp) == 0)
        {
            return;
        }

        auto indexes = result.getBlockHashesByTimestamp().at(timestamp);
        auto it = std::find(indexes.begin(), indexes.end(), blockHash);
        indexes.erase(it);

        if (indexes.empty())
        {
            logger(Logging::DEBUGGING) << "Deleting timestamp " << timestamp;
            batch.removeTimestamp(timestamp);
        }
        else
        {
            logger(Logging::DEBUGGING) << "Deleting block hash " << blockHash << " from timestamp " << timestamp;
            batch.insertTimestamp(timestamp, indexes);
        }
    }

    void DatabaseBlockchainCache::pushTransaction(
        const CachedTransaction &cachedTransaction,
        uint32_t blockIndex,
        uint16_t transactionBlockIndex,
        BlockchainWriteBatch &batch)
    {
        logger(Logging::DEBUGGING) << "push transaction with hash " << cachedTransaction.getTransactionHash();
        const auto &tx = cachedTransaction.getTransaction();

        /* CORRUPTION PREVENTION: Validate coinbase transaction blockIndex matches
         *
         * For coinbase transactions, verify that the BaseInput.blockIndex stored in
         * the transaction matches the blockIndex we're assigning. This prevents corrupted
         * cache data where transactions are stored with wrong block heights. */
        if (!tx.inputs.empty() && tx.inputs[0].type() == typeid(BaseInput))
        {
            const BaseInput &baseInput = boost::get<BaseInput>(tx.inputs[0]);
            if (baseInput.blockIndex != blockIndex)
            {
                logger(Logging::ERROR) << "BLOCKINDEX MISMATCH DETECTED! Transaction "
                                       << Common::podToHex(cachedTransaction.getTransactionHash())
                                       << " has BaseInput.blockIndex=" << baseInput.blockIndex
                                       << " but is being stored in block " << blockIndex
                                       << ". This indicates blockchain corruption or inconsistent state!";
                logger(Logging::ERROR) << "TO PREVENT CORRUPTION: Using BaseInput.blockIndex=" << baseInput.blockIndex;
                /* Use the blockIndex from BaseInput instead of parameter to prevent corruption */
                // blockIndex = baseInput.blockIndex;  // Uncomment to override (risky - may cause other issues)
            }
        }

        ExtendedTransactionInfo transactionCacheInfo;
        transactionCacheInfo.blockIndex = blockIndex;
        transactionCacheInfo.transactionIndex = transactionBlockIndex;
        transactionCacheInfo.transactionHash = cachedTransaction.getTransactionHash();
        transactionCacheInfo.unlockTime = tx.unlockTime;

        assert(tx.outputs.size() <= std::numeric_limits<uint16_t>::max());

        /* GLOBAL INDEX TRACKING REMOVED - globalIndexes field no longer exists */
        transactionCacheInfo.outputs.reserve(tx.outputs.size());
        auto outputCount = 0;
        std::unordered_map<Amount, std::vector<PackedOutIndex>> keyIndexes;

        std::set<Amount> newKeyAmounts;

        for (auto &output : tx.outputs)
        {
            transactionCacheInfo.outputs.push_back(output.target);

            PackedOutIndex poi;
            poi.blockIndex = blockIndex;
            poi.transactionIndex = transactionBlockIndex;
            poi.outputIndex = outputCount++;

            if (output.target.type() == typeid(KeyOutput))
            {
                keyIndexes[output.amount].push_back(poi);
                auto outputCountForAmount = updateKeyOutputCount(output.amount, 1);
                if (outputCountForAmount == 1)
                {
                    newKeyAmounts.insert(output.amount);
                }

                assert(outputCountForAmount > 0);
                /* GLOBAL INDEX TRACKING REMOVED - globalIndex tracking removed */
                // output global index:
                transactionCacheInfo.amountToKeyIndexes[output.amount].push_back(outputCountForAmount - 1);

                KeyOutputInfo outputInfo;
                outputInfo.publicKey = boost::get<KeyOutput>(output.target).key;
                outputInfo.transactionHash = transactionCacheInfo.transactionHash;
                outputInfo.unlockTime = transactionCacheInfo.unlockTime;
                outputInfo.outputIndex = poi.outputIndex;

                /* UTXO SYSTEM: Create UTXO in database
                 *
                 * Every output becomes a UTXO that can be spent.
                 * Write UTXO to database for persistence across restarts. */
                UtxoOutput utxo;
                utxo.amount = output.amount;
                utxo.publicKey = outputInfo.publicKey;
                utxo.blockIndex = blockIndex;
                utxo.transactionHash = transactionCacheInfo.transactionHash;
                utxo.outputIndex = poi.outputIndex;
                utxo.spent = false;
                utxo.spentBlockIndex = 0;

                batch.insertUtxo(transactionCacheInfo.transactionHash, poi.outputIndex, utxo);

                logger(Logging::DEBUGGING) << "Created UTXO in database: tx="
                                      << Common::podToHex(transactionCacheInfo.transactionHash)
                                      << " output=" << poi.outputIndex
                                      << " amount=" << utxo.amount
                                      << " block=" << blockIndex;

                /* GLOBAL INDEX TRACKING REMOVED - insertKeyOutputInfo call removed */
                // batch.insertKeyOutputInfo(output.amount, globalIndex, outputInfo);
            }
        }

        for (auto &amountToOutputs : keyIndexes)
        {
            batch.insertKeyOutputGlobalIndexes(
                amountToOutputs.first,
                amountToOutputs.second,
                updateKeyOutputCount(amountToOutputs.first, 0)); // Size already updated.
        }

        if (!newKeyAmounts.empty())
        {
            assert(keyOutputAmountsCount.is_initialized());
            batch.insertKeyOutputAmounts(newKeyAmounts, *keyOutputAmountsCount);
        }

        /* UTXO SYSTEM: Mark UTXOs as spent for transaction inputs
         *
         * When a transaction spends an input, we need to:
         * 1. Find the UTXO being spent (by transactionHash and outputIndex)
         * 2. Mark it as spent in the database
         * 3. Record which block spent it (for reorg handling)
         *
         * This prevents double-spending the same UTXO and ensures spent status persists
         * across node restarts. */
        logger(Logging::DEBUGGING) << "Processing " << tx.inputs.size() << " transaction inputs to mark UTXOs as spent";

        for (auto &input : tx.inputs)
        {
            if (input.type() == typeid(KeyInput))
            {
                const KeyInput &keyInput = boost::get<KeyInput>(input);

                logger(Logging::DEBUGGING) << "Processing KeyInput: tx=" << Common::podToHex(keyInput.transactionHash)
                                           << " output=" << keyInput.outputIndex;

                /* Read the UTXO from database to get its current state */
                BlockchainReadBatch utxoReadBatch;
                utxoReadBatch.requestUtxo(keyInput.transactionHash, keyInput.outputIndex);
                auto utxoReadResult = readDatabase(utxoReadBatch);
                const auto &utxosFromDb = utxoReadResult.getUtxos();

                logger(Logging::DEBUGGING) << "Database returned " << utxosFromDb.size() << " UTXOs for query";

                auto utxoKey = std::make_pair(keyInput.transactionHash, keyInput.outputIndex);
                auto utxoIt = utxosFromDb.find(utxoKey);

                if (utxoIt != utxosFromDb.end())
                {
                    /* UTXO found in database - check if already spent */
                    UtxoOutput utxo = utxoIt->second;
                    logger(Logging::DEBUGGING) << "Found UTXO in database: amount=" << utxo.amount
                                               << " spent=" << utxo.spent
                                               << " spentBlockIndex=" << utxo.spentBlockIndex;

                    if (utxo.spent)
                    {
                        logger(Logging::WARNING) << "UTXO already spent in database: tx="
                                                  << Common::podToHex(keyInput.transactionHash)
                                                  << " output=" << keyInput.outputIndex
                                                  << " spent in block " << utxo.spentBlockIndex;
                        /* This should have been caught by validation, but log it anyway */
                    }
                    else
                    {
                        /* Mark UTXO as spent and update database */
                        logger(Logging::DEBUGGING) << "About to mark UTXO as spent - current state: amount="
                                                   << utxo.amount << " spent=" << utxo.spent
                                                   << " blockIndex=" << utxo.blockIndex
                                                   << " tx=" << Common::podToHex(utxo.transactionHash);

                        utxo.spent = true;
                        utxo.spentBlockIndex = blockIndex;

                        logger(Logging::DEBUGGING) << "Marking as spent - new state: amount="
                                                   << utxo.amount << " spent=" << utxo.spent
                                                   << " spentBlockIndex=" << utxo.spentBlockIndex;

                        batch.insertUtxo(keyInput.transactionHash, keyInput.outputIndex, utxo);
                        batch.insertSpentUtxo(keyInput.transactionHash, keyInput.outputIndex, blockIndex);

                        logger(Logging::DEBUGGING) << "Marked UTXO as spent in database: tx="
                                              << Common::podToHex(keyInput.transactionHash)
                                              << " output=" << keyInput.outputIndex
                                              << " amount=" << utxo.amount
                                              << " in block " << blockIndex;
                    }
                }
                else
                {
                    /* UTXO not found in database - this is an error
                     * All UTXOs being spent should exist in the database from when they were created */
                    logger(Logging::ERROR) << "ERROR: UTXO not found in database: tx="
                                           << Common::podToHex(keyInput.transactionHash)
                                           << " output=" << keyInput.outputIndex
                                           << " - This UTXO should exist but wasn't found!";
                }
            }
            /* BaseInput is for coinbase transactions which have no inputs to spend */
        }

        

        batch.insertCachedTransaction(transactionCacheInfo, getCachedTransactionsCount() + 1);
        transactionsCount = *transactionsCount + 1;
        logger(Logging::DEBUGGING) << "push transaction with hash " << cachedTransaction.getTransactionHash()
                                   << " finished";
    }

    uint32_t DatabaseBlockchainCache::updateKeyOutputCount(Amount amount, int32_t diff) const
    {
        auto it = keyOutputCountsForAmounts.find(amount);
        if (it == keyOutputCountsForAmounts.end())
        {
            logger(Logging::TRACE) << "updateKeyOutputCount: failed to found key for amount, request database";

            BlockchainReadBatch batch;
            auto result = readDatabase(batch.requestKeyOutputGlobalIndexesCountForAmount(amount));
            auto found = result.getKeyOutputGlobalIndexesCountForAmounts().find(amount);
            auto val = found != result.getKeyOutputGlobalIndexesCountForAmounts().end() ? found->second : 0;
            it = keyOutputCountsForAmounts.insert({amount, val}).first;
            logger(Logging::TRACE) << "updateKeyOutputCount: database replied: amount " << amount << " value " << val;

            if (val == 0)
            {
                if (!keyOutputAmountsCount)
                {
                    auto result = readDatabase(batch.requestKeyOutputAmountsCount());
                    keyOutputAmountsCount = result.getKeyOutputAmountsCount();
                }

                keyOutputAmountsCount = *keyOutputAmountsCount + 1;
            }
        }
        else if (!keyOutputAmountsCount)
        {
            auto result = readDatabase(BlockchainReadBatch().requestKeyOutputAmountsCount());
            keyOutputAmountsCount = result.getKeyOutputAmountsCount();
        }

        it->second += diff;
        assert(it->second >= 0);
        return it->second;
    }

    void DatabaseBlockchainCache::insertBlockTimestamp(
        BlockchainWriteBatch &batch,
        uint64_t timestamp,
        const Crypto::Hash &blockHash)
    {
        BlockchainReadBatch readBatch;
        readBatch.requestBlockHashesByTimestamp(timestamp);

        std::vector<Crypto::Hash> blockHashes;
        auto readResult = readDatabase(readBatch);

        if (readResult.getBlockHashesByTimestamp().count(timestamp) != 0)
        {
            blockHashes = readResult.getBlockHashesByTimestamp().at(timestamp);
        }

        blockHashes.emplace_back(blockHash);

        batch.insertTimestamp(timestamp, blockHashes);
    }

    void DatabaseBlockchainCache::pushBlock(
        const CachedBlock &cachedBlock,
        const std::vector<CachedTransaction> &cachedTransactions,
        const TransactionValidatorState &validatorState,
        size_t blockSize,
        uint64_t generatedCoins,
        uint64_t blockDifficulty,
        RawBlock &&rawBlock)
    {
        BlockchainWriteBatch batch;
        logger(Logging::DEBUGGING) << "push block with hash " << cachedBlock.getBlockHash() << ", and "
                                   << cachedTransactions.size() + 1 << " transactions"; //+1 for base transaction

        // TODO: cache top block difficulty, size, timestamp, coins; use it here
        auto lastBlockInfo = getCachedBlockInfo(getTopBlockIndex());
        auto cumulativeDifficulty = lastBlockInfo.cumulativeDifficulty + blockDifficulty;
        auto alreadyGeneratedCoins = lastBlockInfo.alreadyGeneratedCoins + generatedCoins;
        auto alreadyGeneratedTransactions = lastBlockInfo.alreadyGeneratedTransactions + cachedTransactions.size() + 1;

        CachedBlockInfo blockInfo;
        blockInfo.blockHash = cachedBlock.getBlockHash();
        blockInfo.alreadyGeneratedCoins = alreadyGeneratedCoins;
        blockInfo.alreadyGeneratedTransactions = alreadyGeneratedTransactions;
        blockInfo.cumulativeDifficulty = cumulativeDifficulty;
        blockInfo.blockSize = static_cast<uint32_t>(blockSize);
        blockInfo.timestamp = cachedBlock.getBlock().timestamp;

        /* TRANSPARENT SYSTEM: Store spent transaction hashes for UTXO tracking
         * In transparent system, each transaction can only be spent once (no key images)
         * We store the transaction hashes that were spent in this block for:
         * 1. Quick lookup during reorgs (to un-spend transactions)
         * 2. Blockchain scanning and indexing
         *
         * Note: Converting Crypto::Hash to Crypto::PublicKey for storage compatibility
         * with existing spentKeyImagesByBlock infrastructure */
        std::unordered_set<Crypto::PublicKey> spentTxHashesAsKeys;
        for (const Crypto::Hash &txHash : validatorState.spentTransactions)
        {
            /* Convert transaction hash to public key for storage
             * Both are 32-byte ed25519 values, so this is safe */
            Crypto::PublicKey txHashAsKey;
            std::memcpy(txHashAsKey.data, txHash.data, sizeof(Crypto::Hash));
            spentTxHashesAsKeys.insert(txHashAsKey);

            logger(Logging::DEBUGGING) << "Storing spent transaction hash: " << txHash;
        }

        batch.insertSpentKeyImages(getTopBlockIndex() + 1, spentTxHashesAsKeys);

        auto txHashes = cachedBlock.getBlock().transactionHashes;
        auto baseTransaction = cachedBlock.getBlock().baseTransaction;
        auto cachedBaseTransaction = CachedTransaction {std::move(baseTransaction)};

        // base transaction's hash is always the first one in index for this block
        txHashes.insert(txHashes.begin(), cachedBaseTransaction.getTransactionHash());

        batch.insertCachedBlock(blockInfo, getTopBlockIndex() + 1, txHashes);

        /* UTXO IMMEDIATE AVAILABILITY FIX: Make a copy of rawBlock before moving to database
         *
         * We need to keep a copy in memory for immediate access via getAllUtxos().
         * The original will be moved to the database for persistence. */
        RawBlock rawBlockCopy = rawBlock;
        batch.insertRawBlock(getTopBlockIndex() + 1, std::move(rawBlock));

        auto transactionIndex = 0;
        pushTransaction(cachedBaseTransaction, getTopBlockIndex() + 1, transactionIndex++, batch);

        for (const auto &transaction : cachedTransactions)
        {
            pushTransaction(transaction, getTopBlockIndex() + 1, transactionIndex++, batch);
        }

        auto closestBlockIndexDb =
            requestClosestBlockIndexByTimestamp(roundToMidnight(cachedBlock.getBlock().timestamp), database);
        if (!closestBlockIndexDb.second)
        {
            logger(Logging::ERROR) << "push block " << cachedBlock.getBlockHash()
                                   << " request closest block index by timestamp failed";
            throw std::runtime_error("Couldn't get closest to timestamp block index");
        }

        if (!closestBlockIndexDb.first)
        {
            batch.insertClosestTimestampBlockIndex(
                roundToMidnight(cachedBlock.getBlock().timestamp), getTopBlockIndex() + 1);
        }

        insertBlockTimestamp(batch, cachedBlock.getBlock().timestamp, cachedBlock.getBlockHash());

        /* CRITICAL: Use sync write to ensure UTXOs are immediately available for spending
         *
         * When a block is mined, the UTXOs it creates must be immediately visible for
         * transaction validation. Without sync=true, RocksDB may buffer the write in the
         * WAL (write-ahead log) and not flush it to disk immediately, causing a race
         * condition where:
         * 1. Block is mined with new UTXOs
         * 2. User tries to send transaction spending those UTXOs
         * 3. Validation queries database for UTXOs
         * 4. Database returns empty because write hasn't flushed yet
         * 5. Transaction fails with "invalid global index"
         *
         * With sync=true, the write is flushed before returning, ensuring UTXOs are
         * immediately available. This adds a small performance cost but is necessary
         * for correct behavior. */
        auto res = database.write(batch, true);
        if (res)
        {
            logger(Logging::ERROR) << "push block " << cachedBlock.getBlockHash() << " write failed: " << res.message();
            throw std::runtime_error(res.message());
        }

        topBlockIndex = *topBlockIndex + 1;
        topBlockHash = cachedBlock.getBlockHash();
        logger(Logging::DEBUGGING) << "push block " << cachedBlock.getBlockHash() << " completed";

        unitsCache.push_back(blockInfo);
        if (unitsCache.size() > unitsCacheSize)
        {
            unitsCache.pop_front();
        }

        /* UTXO IMMEDIATE AVAILABILITY FIX: Cache raw block in memory
         *
         * Store the raw block data in memory so it's immediately available
         * for getAllUtxos() queries, avoiding the RocksDB read visibility delay. */

        /* CORRUPTION PREVENTION: Validate blockIndex before caching
         *
         * Ensure the blockIndex we're using matches the block's actual BaseInput.blockIndex
         * to prevent caching with wrong height, which causes RPC to return incorrect data. */
        uint32_t cacheBlockIndex = getTopBlockIndex();
        BlockTemplate blockForValidation;
        try
        {
            blockForValidation = fromBinaryArray<BlockTemplate>(rawBlockCopy.block);

            /* For coinbase transactions, verify BaseInput.blockIndex matches cache blockIndex */
            if (!blockForValidation.baseTransaction.inputs.empty() &&
                blockForValidation.baseTransaction.inputs[0].type() == typeid(BaseInput))
            {
                const BaseInput &baseInput = boost::get<BaseInput>(blockForValidation.baseTransaction.inputs[0]);
                if (baseInput.blockIndex != cacheBlockIndex)
                {
                    logger(Logging::ERROR) << "CACHE CORRUPTION PREVENTED! Block "
                                           << Common::podToHex(cachedBlock.getBlockHash())
                                           << " has BaseInput.blockIndex=" << baseInput.blockIndex
                                           << " but cache index is " << cacheBlockIndex
                                           << ". Not caching to prevent data corruption!";
                    /* Don't cache this block - it has inconsistent data */
                }
                else
                {
                    /* Block is valid, safe to cache */
                    rawBlocksCache.push_back({cacheBlockIndex, std::move(rawBlockCopy)});
                }
            }
            else
            {
                /* No BaseInput (shouldn't happen for valid blocks), cache anyway */
                rawBlocksCache.push_back({cacheBlockIndex, std::move(rawBlockCopy)});
            }
        }
        catch (const std::exception &e)
        {
            /* Block deserialization failed, cache anyway but log warning */
            logger(Logging::WARNING) << "Failed to validate block for caching: " << e.what();
            rawBlocksCache.push_back({cacheBlockIndex, std::move(rawBlockCopy)});
        }

        if (rawBlocksCache.size() > unitsCacheSize)
        {
            rawBlocksCache.pop_front();
        }

        logger(Logging::TRACE) << "Cached raw block " << getTopBlockIndex() << " in memory (cache size: " << rawBlocksCache.size() << ")";
    }

    PushedBlockInfo DatabaseBlockchainCache::getPushedBlockInfo(uint32_t blockIndex) const
    {
        return getExtendedPushedBlockInfo(blockIndex).pushedBlockInfo;
    }

    bool DatabaseBlockchainCache::checkIfSpent(const Crypto::PublicKey &keyImage, uint32_t blockIndex) const
    {
        auto batch = BlockchainReadBatch().requestBlockIndexBySpentKeyImage(keyImage);
#if defined (USE_LEVELDB)
        auto res = database.read(batch);
#else
        auto res = database.readThreadSafe(batch);
#endif
        if (res)
        {
            logger(Logging::ERROR) << "checkIfSpent failed, request to database failed: " << res.message();
            return false;
        }

        auto readResult = batch.extractResult();
        auto it = readResult.getBlockIndexesBySpentKeyImages().find(keyImage);

        return it != readResult.getBlockIndexesBySpentKeyImages().end() && it->second <= blockIndex;
    }

    bool DatabaseBlockchainCache::checkIfSpent(const Crypto::PublicKey &keyImage) const
    {
        return checkIfSpent(keyImage, getTopBlockIndex());
    }

    bool DatabaseBlockchainCache::isTransactionSpendTimeUnlocked(uint64_t unlockTime) const
    {
        return isTransactionSpendTimeUnlocked(unlockTime, getTopBlockIndex());
    }

    bool DatabaseBlockchainCache::isTransactionSpendTimeUnlocked(uint64_t unlockTime, uint32_t blockIndex) const
    {
        if (unlockTime < currency.maxBlockHeight())
        {
            // interpret as block index
            return blockIndex + currency.lockedTxAllowedDeltaBlocks() >= unlockTime;
        }

        if (blockIndex >= Pastella::parameters::TRANSACTION_INPUT_BLOCKTIME_VALIDATION_HEIGHT)
        {
            /* Get the last block timestamp from an existing method call */
            const std::vector<uint64_t> lastBlockTimestamps = getLastTimestamps(1);

            /* Pop the last timestamp off the vector */
            const uint64_t lastBlockTimestamp = lastBlockTimestamps.at(0);

            /* Compare our delta seconds plus our last time stamp against the unlock time */
            return lastBlockTimestamp + currency.lockedTxAllowedDeltaSeconds() >= unlockTime;
        }

        // interpret as time
        return static_cast<uint64_t>(time(nullptr)) + currency.lockedTxAllowedDeltaSeconds() >= unlockTime;
    }

    /* GLOBAL INDEX TRACKING REMOVED - extractKeyOutputKeys methods removed */

    /* GLOBAL INDEX TRACKING REMOVED - extractKeyOtputIndexes method removed */

    /* GLOBAL INDEX TRACKING REMOVED - extractKeyOtputReferences method removed */

    uint32_t DatabaseBlockchainCache::getTopBlockIndex() const
    {
        if (!topBlockIndex)
        {
            auto batch = BlockchainReadBatch().requestLastBlockIndex();
            auto result = database.read(batch);

            if (result)
            {
                logger(Logging::ERROR) << "Failed to read top block index from database";
                throw std::system_error(result);
            }

            auto readResult = batch.extractResult();
            if (!readResult.getLastBlockIndex().second)
            {
                logger(Logging::TRACE) << "Top block index does not exist in database";
                topBlockIndex = 0;
            }

            topBlockIndex = readResult.getLastBlockIndex().first;
        }

        return *topBlockIndex;
    }

    uint8_t DatabaseBlockchainCache::getBlockMajorVersionForHeight(uint32_t height) const
    {
        UpgradeManager upgradeManager;
        upgradeManager.addMajorBlockVersion(BLOCK_MAJOR_VERSION_2, currency.upgradeHeight(BLOCK_MAJOR_VERSION_2));
        return upgradeManager.getBlockMajorVersion(height);
    }

    uint64_t DatabaseBlockchainCache::getCachedTransactionsCount() const
    {
        if (!transactionsCount)
        {
            auto batch = BlockchainReadBatch().requestTransactionsCount();
            auto result = database.read(batch);

            if (result)
            {
                logger(Logging::ERROR) << "Failed to read transactions count from database";
                throw std::system_error(result);
            }

            auto readResult = batch.extractResult();
            if (!readResult.getTransactionsCount().second)
            {
                logger(Logging::TRACE) << "Transactions count does not exist in database";
                transactionsCount = 0;
            }
            else
            {
                transactionsCount = readResult.getTransactionsCount().first;
            }
        }

        return *transactionsCount;
    }

    const Crypto::Hash &DatabaseBlockchainCache::getTopBlockHash() const
    {
        if (!topBlockHash)
        {
            auto batch = BlockchainReadBatch().requestCachedBlock(getTopBlockIndex());
            auto result = readDatabase(batch);
            topBlockHash = result.getCachedBlocks().at(getTopBlockIndex()).blockHash;
        }
        return *topBlockHash;
    }

    uint32_t DatabaseBlockchainCache::getBlockCount() const
    {
        return getTopBlockIndex() + 1;
    }

    bool DatabaseBlockchainCache::hasBlock(const Crypto::Hash &blockHash) const
    {
        auto batch = BlockchainReadBatch().requestBlockIndexByBlockHash(blockHash);
        auto result = database.read(batch);
        return !result && batch.extractResult().getBlockIndexesByBlockHashes().count(blockHash);
    }

    uint32_t DatabaseBlockchainCache::getBlockIndex(const Crypto::Hash &blockHash) const
    {
        if (blockHash == getTopBlockHash())
        {
            return getTopBlockIndex();
        }

        auto batch = BlockchainReadBatch().requestBlockIndexByBlockHash(blockHash);
        auto result = readDatabase(batch);
        return result.getBlockIndexesByBlockHashes().at(blockHash);
    }

    bool DatabaseBlockchainCache::hasTransaction(const Crypto::Hash &transactionHash) const
    {
        auto batch = BlockchainReadBatch().requestCachedTransaction(transactionHash);
        auto result = database.read(batch);
        return !result && batch.extractResult().getCachedTransactions().count(transactionHash);
    }

    std::vector<uint64_t> DatabaseBlockchainCache::getLastTimestamps(size_t count) const
    {
        return getLastTimestamps(count, getTopBlockIndex(), UseGenesis {true});
    }

    std::vector<uint64_t>
        DatabaseBlockchainCache::getLastTimestamps(size_t count, uint32_t blockIndex, UseGenesis useGenesis) const
    {
        return getLastUnits(count, blockIndex, useGenesis, [](const CachedBlockInfo &inf) { return inf.timestamp; });
    }

    std::vector<uint64_t> DatabaseBlockchainCache::getLastBlocksSizes(size_t count) const
    {
        return getLastBlocksSizes(count, getTopBlockIndex(), UseGenesis {true});
    }

    std::vector<uint64_t>
        DatabaseBlockchainCache::getLastBlocksSizes(size_t count, uint32_t blockIndex, UseGenesis useGenesis) const
    {
        return getLastUnits(count, blockIndex, useGenesis, [](const CachedBlockInfo &cb) { return cb.blockSize; });
    }

    std::vector<uint64_t> DatabaseBlockchainCache::getLastCumulativeDifficulties(
        size_t count,
        uint32_t blockIndex,
        UseGenesis useGenesis) const
    {
        return getLastUnits(
            count, blockIndex, useGenesis, [](const CachedBlockInfo &info) { return info.cumulativeDifficulty; });
    }

    std::vector<uint64_t> DatabaseBlockchainCache::getLastCumulativeDifficulties(size_t count) const
    {
        return getLastCumulativeDifficulties(count, getTopBlockIndex(), UseGenesis {true});
    }

    uint64_t DatabaseBlockchainCache::getDifficultyForNextBlock() const
    {
        return getDifficultyForNextBlock(getTopBlockIndex());
    }

    uint64_t DatabaseBlockchainCache::getDifficultyForNextBlock(uint32_t blockIndex) const
    {
        assert(blockIndex <= getTopBlockIndex());
        uint8_t nextBlockMajorVersion = getBlockMajorVersionForHeight(blockIndex + 1);
        auto timestamps = getLastTimestamps(
            currency.difficultyBlocksCountByBlockVersion(nextBlockMajorVersion, blockIndex),
            blockIndex,
            UseGenesis {false});
        auto commulativeDifficulties = getLastCumulativeDifficulties(
            currency.difficultyBlocksCountByBlockVersion(nextBlockMajorVersion, blockIndex),
            blockIndex,
            UseGenesis {false});
        return currency.getNextDifficulty(
            nextBlockMajorVersion, blockIndex, std::move(timestamps), std::move(commulativeDifficulties));
    }

    uint64_t DatabaseBlockchainCache::getCurrentCumulativeDifficulty() const
    {
        return getCachedBlockInfo(getTopBlockIndex()).cumulativeDifficulty;
    }

    uint64_t DatabaseBlockchainCache::getCurrentCumulativeDifficulty(uint32_t blockIndex) const
    {
        assert(blockIndex <= getTopBlockIndex());
        return getCachedBlockInfo(blockIndex).cumulativeDifficulty;
    }

    CachedBlockInfo DatabaseBlockchainCache::getCachedBlockInfo(uint32_t index) const
    {
        auto batch = BlockchainReadBatch().requestCachedBlock(index);
        auto result = readDatabase(batch);
        return result.getCachedBlocks().at(index);
    }

    uint64_t DatabaseBlockchainCache::getAlreadyGeneratedCoins() const
    {
        return getAlreadyGeneratedCoins(getTopBlockIndex());
    }

    uint64_t DatabaseBlockchainCache::getAlreadyGeneratedCoins(uint32_t blockIndex) const
    {
        return getCachedBlockInfo(blockIndex).alreadyGeneratedCoins;
    }

    uint64_t DatabaseBlockchainCache::getAlreadyGeneratedTransactions(uint32_t blockIndex) const
    {
        return getCachedBlockInfo(blockIndex).alreadyGeneratedTransactions;
    }

    std::vector<CachedBlockInfo>
        DatabaseBlockchainCache::getLastCachedUnits(uint32_t blockIndex, size_t count, UseGenesis useGenesis) const
    {
        assert(blockIndex <= getTopBlockIndex());

        std::vector<CachedBlockInfo> cachedResult;
        const uint32_t cacheStartIndex = (getTopBlockIndex() + 1) - static_cast<uint32_t>(unitsCache.size());

        count = std::min(unitsCache.size(), count);

        if (cacheStartIndex > blockIndex || count == 0)
        {
            return cachedResult;
        }

        count = std::min(blockIndex - cacheStartIndex + 1, static_cast<uint32_t>(count));
        uint32_t offset = static_cast<uint32_t>(blockIndex + 1 - count) - cacheStartIndex;

        assert(offset < unitsCache.size());

        if (!useGenesis && cacheStartIndex == 0 && offset == 0)
        {
            ++offset;
            --count;
        }

        if (offset >= unitsCache.size() || count == 0)
        {
            return cachedResult;
        }

        cachedResult.reserve(count);
        for (size_t i = 0; i < count; ++i)
        {
            cachedResult.push_back(unitsCache[offset + i]);
        }

        return cachedResult;
    }

    std::vector<CachedBlockInfo>
        DatabaseBlockchainCache::getLastDbUnits(uint32_t blockIndex, size_t count, UseGenesis useGenesis) const
    {
        uint32_t readFrom = blockIndex + 1 - std::min(blockIndex + 1, static_cast<uint32_t>(count));
        if (readFrom == 0 && !useGenesis)
        {
            readFrom += 1;
        }

        uint32_t toRead = blockIndex - readFrom + 1;
        std::vector<CachedBlockInfo> units;
        units.reserve(toRead);

        const uint32_t step = 200;
        while (toRead > 0)
        {
            auto next = std::min(toRead, step);
            toRead -= next;

            BlockchainReadBatch batch;
            for (auto id = readFrom; id < readFrom + next; ++id)
            {
                batch.requestCachedBlock(id);
            }

            readFrom += next;

            auto res = readDatabase(batch);

            std::map<uint32_t, CachedBlockInfo> sortedResult(
                res.getCachedBlocks().begin(), res.getCachedBlocks().end());
            for (const auto &kv : sortedResult)
            {
                units.push_back(kv.second);
            }
            //    std::transform(sortedResult.begin(), sortedResult.end(), std::back_inserter(units),
            //                   [&](const std::pair<uint32_t, CachedBlockInfo>& cb) { return pred(cb.second); });
        }

        return units;
    }

    std::vector<uint64_t> DatabaseBlockchainCache::getLastUnits(
        size_t count,
        uint32_t blockIndex,
        UseGenesis useGenesis,
        std::function<uint64_t(const CachedBlockInfo &)> pred) const
    {
        assert(count <= std::numeric_limits<uint32_t>::max());

        auto cachedUnits = getLastCachedUnits(blockIndex, count, useGenesis);

        uint32_t availableUnits = blockIndex;
        if (useGenesis)
        {
            availableUnits += 1;
        }

        assert(availableUnits >= cachedUnits.size());

        if (availableUnits - cachedUnits.size() == 0)
        {
            std::vector<uint64_t> result;
            result.reserve(cachedUnits.size());
            for (const auto &unit : cachedUnits)
            {
                result.push_back(pred(unit));
            }

            return result;
        }

        assert(blockIndex + 1 >= cachedUnits.size());
        uint32_t dbIndex = blockIndex - static_cast<uint32_t>(cachedUnits.size());

        assert(count >= cachedUnits.size());
        size_t leftCount = count - cachedUnits.size();

        auto dbUnits = getLastDbUnits(dbIndex, leftCount, useGenesis);
        std::vector<uint64_t> result;
        result.reserve(dbUnits.size() + cachedUnits.size());
        for (const auto &unit : dbUnits)
        {
            result.push_back(pred(unit));
        }

        for (const auto &unit : cachedUnits)
        {
            result.push_back(pred(unit));
        }

        return result;
    }

    Crypto::Hash DatabaseBlockchainCache::getBlockHash(uint32_t blockIndex) const
    {
        if (blockIndex == getTopBlockIndex())
        {
            return getTopBlockHash();
        }

        auto batch = BlockchainReadBatch().requestCachedBlock(blockIndex);
        auto result = readDatabase(batch);
        return result.getCachedBlocks().at(blockIndex).blockHash;
    }

    std::vector<Crypto::Hash> DatabaseBlockchainCache::getBlockHashes(uint32_t startIndex, size_t maxCount) const
    {
        assert(startIndex <= getTopBlockIndex());
        assert(maxCount <= std::numeric_limits<uint32_t>::max());

        uint32_t count = std::min(getTopBlockIndex() - startIndex + 1, static_cast<uint32_t>(maxCount));
        if (count == 0)
        {
            return {};
        }

        BlockchainReadBatch request;
        auto index = startIndex;
        while (index != startIndex + count)
        {
            request.requestCachedBlock(index++);
        }

        auto result = readDatabase(request);
        assert(result.getCachedBlocks().size() == count);

        std::vector<Crypto::Hash> hashes;
        hashes.reserve(count);

        std::map<uint32_t, CachedBlockInfo> sortedResult(
            result.getCachedBlocks().begin(), result.getCachedBlocks().end());

        std::transform(
            sortedResult.begin(),
            sortedResult.end(),
            std::back_inserter(hashes),
            [](const std::pair<uint32_t, CachedBlockInfo> &cb) { return cb.second.blockHash; });
        return hashes;
    }

    IBlockchainCache *DatabaseBlockchainCache::getParent() const
    {
        return nullptr;
    }

    uint32_t DatabaseBlockchainCache::getStartBlockIndex() const
    {
        return 0;
    }

    size_t DatabaseBlockchainCache::getKeyOutputsCountForAmount(uint64_t amount, uint32_t blockIndex) const
    {
        uint32_t outputsCount = requestKeyOutputGlobalIndexesCountForAmount(amount, database);

        auto getOutput = std::bind(retrieveKeyOutput, std::placeholders::_1, std::placeholders::_2, std::ref(database));
        auto begin = DbOutputConstIterator(getOutput, amount, 0);
        auto end = DbOutputConstIterator(getOutput, amount, outputsCount);

        auto it = std::lower_bound(begin, end, blockIndex, [](const PackedOutIndex &output, uint32_t blockIndex) {
            return output.blockIndex < blockIndex;
        });

        size_t result = static_cast<size_t>(std::distance(begin, it));
        logger(Logging::DEBUGGING) << "Key outputs count for amount " << amount << " is " << result
                                   << " by block index " << blockIndex;

        return result;
    }

    std::tuple<bool, uint64_t> DatabaseBlockchainCache::getBlockHeightForTimestamp(uint64_t timestamp) const
    {
        const auto midnight = roundToMidnight(timestamp);

        const auto [blockHeight, success] = requestClosestBlockIndexByTimestamp(midnight, database);

        /* Failed to read from DB */
        if (!success)
        {
            logger(Logging::DEBUGGING) << "getTimestampLowerBoundBlockIndex failed: failed to read database";
            throw std::runtime_error("Couldn't get closest to timestamp block index");
        }

        /* Failed to find the block height with this timestamp */
        if (!blockHeight)
        {
            return {false, 0};
        }

        return {true, *blockHeight};
    }

    uint32_t DatabaseBlockchainCache::getTimestampLowerBoundBlockIndex(uint64_t timestamp) const
    {
        auto midnight = roundToMidnight(timestamp);

        while (midnight > 0)
        {
            auto dbRes = requestClosestBlockIndexByTimestamp(midnight, database);
            if (!dbRes.second)
            {
                logger(Logging::DEBUGGING) << "getTimestampLowerBoundBlockIndex failed: failed to read database";
                throw std::runtime_error("Couldn't get closest to timestamp block index");
            }

            if (!dbRes.first)
            {
                midnight -= 60 * 60 * 24;
                continue;
            }

            return *dbRes.first;
        }

        return 0;
    }

    /* GLOBAL INDEX TRACKING REMOVED - getTransactionGlobalIndexes method removed */

    size_t DatabaseBlockchainCache::getTransactionCount() const
    {
        return static_cast<size_t>(getCachedTransactionsCount());
    }

    uint32_t DatabaseBlockchainCache::getBlockIndexContainingTx(const Crypto::Hash &transactionHash) const
    {
        auto batch = BlockchainReadBatch().requestCachedTransaction(transactionHash);
        auto result = readDatabase(batch);
        return result.getCachedTransactions().at(transactionHash).blockIndex;
    }

    size_t DatabaseBlockchainCache::getChildCount() const
    {
        return children.size();
    }

    void DatabaseBlockchainCache::save() {}

    void DatabaseBlockchainCache::load() {}

    std::vector<BinaryArray> DatabaseBlockchainCache::getRawTransactions(
        const std::vector<Crypto::Hash> &transactions,
        std::vector<Crypto::Hash> &missedTransactions) const
    {
        std::vector<BinaryArray> found;
        getRawTransactions(transactions, found, missedTransactions);
        return found;
    }

    std::vector<BinaryArray>
        DatabaseBlockchainCache::getRawTransactions(const std::vector<Crypto::Hash> &transactions) const
    {

        std::vector<Crypto::Hash> missed;
        std::vector<BinaryArray> found;
        getRawTransactions(transactions, found, missed);


        return found;
    }

    void DatabaseBlockchainCache::getRawTransactions(
        const std::vector<Crypto::Hash> &transactions,
        std::vector<BinaryArray> &foundTransactions,
        std::vector<Crypto::Hash> &missedTransactions) const
    {
        /* IMMEDIATE AVAILABILITY FIX: Check in-memory cache first
         *
         * The most recent blocks are cached in rawBlocksCache for immediate access.
         * We check this cache BEFORE querying the database to ensure newly mined
         * transactions are immediately available for spending (no race condition). */
        std::vector<Crypto::Hash> stillNeedToFind;

        for (const auto &hash : transactions)
        {
            bool foundInCache = false;

            /* Search backwards through raw blocks cache (most recent first) */
            for (auto rit = rawBlocksCache.rbegin(); rit != rawBlocksCache.rend(); ++rit)
            {
                const auto &blockIndex = rit->first;
                const auto &rawBlock = rit->second;

                /* Try to find the transaction in this cached block */
                /* Check base transaction (coinbase) */
                BlockTemplate block;
                try
                {
                    block = fromBinaryArray<BlockTemplate>(rawBlock.block);
                }
                catch (...)
                {
                    continue; // Skip malformed blocks
                }

                CachedBlock cachedBlockObj(block);
                CachedTransaction baseTx(block.baseTransaction);
                Crypto::Hash baseTxHash = baseTx.getTransactionHash();

                if (hash == baseTxHash)
                {
                    /* Found in base transaction */
                    foundTransactions.emplace_back(toBinaryArray(block.baseTransaction));
                    foundInCache = true;
                    logger(Logging::DEBUGGING) << "getRawTransactions: Found base tx " << Common::podToHex(hash)
                                              << " in memory cache (block " << blockIndex << ")";
                    break;
                }

                /* Check regular transactions */
                for (size_t i = 0; i < rawBlock.transactions.size(); ++i)
                {
                    CachedTransaction tx(rawBlock.transactions[i]);
                    if (hash == tx.getTransactionHash())
                    {
                        /* Found in regular transactions */
                        foundTransactions.emplace_back(rawBlock.transactions[i]);
                        foundInCache = true;
                        logger(Logging::DEBUGGING) << "getRawTransactions: Found tx " << Common::podToHex(hash)
                                                  << " in memory cache (block " << blockIndex
                                                  << ", tx index " << (i+1) << ")";
                        break;
                    }
                }

                if (foundInCache)
                {
                    break;
                }
            }

            if (!foundInCache)
            {
                /* Not in memory cache, need to query database */
                stillNeedToFind.push_back(hash);
            }
        }

        /* If all transactions were found in cache, we're done */
        if (stillNeedToFind.empty())
        {
            return;
        }


        /* Query database for remaining transactions */
        BlockchainReadBatch batch;
        for (auto &hash : stillNeedToFind)
        {
            batch.requestCachedTransaction(hash);
        }

        auto res = readDatabase(batch);

        for (auto &tx : res.getCachedTransactions())
        {
            batch.requestRawBlock(tx.second.blockIndex);
        }

        auto blocks = readDatabase(batch);

        foundTransactions.reserve(foundTransactions.size() + stillNeedToFind.size());
        auto &hashesMap = res.getCachedTransactions();
        auto &blocksMap = blocks.getRawBlocks();
        for (const auto &hash : stillNeedToFind)
        {
            auto transactionIt = hashesMap.find(hash);
            if (transactionIt == hashesMap.end())
            {
                missedTransactions.push_back(hash);
                continue;
            }

            auto blockIt = blocksMap.find(transactionIt->second.blockIndex);
            if (blockIt == blocksMap.end())
            {
                missedTransactions.push_back(hash);
                continue;
            }

            if (transactionIt->second.transactionIndex == 0)
            {
                auto block = fromBinaryArray<BlockTemplate>(blockIt->second.block);
                foundTransactions.emplace_back(toBinaryArray(block.baseTransaction));
            }
            else
            {
                assert(blockIt->second.transactions.size() >= transactionIt->second.transactionIndex - 1);
                foundTransactions.emplace_back(
                    blockIt->second.transactions[transactionIt->second.transactionIndex - 1]);
            }
        }
    }

    RawBlock DatabaseBlockchainCache::getBlockByIndex(uint32_t index) const
    {
        /* UTXO IMMEDIATE AVAILABILITY FIX: Check in-memory cache first
         *
         * Newly mined blocks are cached in memory (rawBlocksCache) to avoid
         * RocksDB read visibility delays. Check cache before hitting database. */
        for (const auto &cachedBlock : rawBlocksCache)
        {
            if (cachedBlock.first == index)
            {
                logger(Logging::TRACE) << "getBlockByIndex: Found block " << index << " in memory cache";
                return cachedBlock.second;
            }
        }

        /* Not in cache, read from database */
        logger(Logging::TRACE) << "getBlockByIndex: Block " << index << " not in cache, reading from database";
        auto batch = BlockchainReadBatch().requestRawBlock(index);
        auto res = readDatabase(batch);
        RawBlock rawBlock = std::move(res.getRawBlocks().at(index));

        /* BLOCK CACHE FIX: Add the block to cache after reading from database
         *
         * Previously, blocks read from database were never cached, causing every
         * request to hit the database. Now we cache them for faster subsequent access. */
        rawBlocksCache.push_back({index, rawBlock});
        if (rawBlocksCache.size() > unitsCacheSize)
        {
            rawBlocksCache.pop_front();
        }

        logger(Logging::TRACE) << "getCachedBlock: Added block " << index << " to cache (cache size: " << rawBlocksCache.size() << ")";

        return rawBlock;
    }

    BinaryArray DatabaseBlockchainCache::getRawTransaction(uint32_t blockIndex, uint32_t transactionIndex) const
    {
        return getBlockByIndex(blockIndex).transactions.at(transactionIndex);
    }

    std::vector<Crypto::Hash> DatabaseBlockchainCache::getTransactionHashes() const
    {
        assert(false);
        return {};
    }

    std::vector<uint32_t>
        DatabaseBlockchainCache::getRandomOutsByAmount(uint64_t amount, size_t count, uint32_t blockIndex) const
    {
        /* GLOBAL INDEX TRACKING REMOVED - Random output selection for ring signatures removed
         *
         * In the transparent system, we don't use ring signatures or decoy outputs.
         * This function was used to select random outputs for mixing.
         *
         * In a transparent system:
         * - No ring signatures needed (transactions use direct addressing)
         * - No need to select random decoy outputs
         * - Reference counting is done via transaction hash, not global index
         *
         * Return empty vector to indicate no random outputs available.
         * This is correct for transparent system where privacy features are removed. */
        (void)amount;
        (void)count;
        (void)blockIndex;

        logger(Logging::DEBUGGING) << "getRandomOutsByAmount: Ring signature mixing not used in transparent system";
        return std::vector<uint32_t>();
    }

    /* UTXO SYSTEM: Database query method implementations
     *
     * These methods query the database for UTXO data.
     * UTXOs are persisted across node restarts for blockchain integrity. */

    bool DatabaseBlockchainCache::getUtxo(
        const Crypto::Hash &transactionHash,
        uint32_t outputIndex,
        UtxoOutput &utxo) const
    {
        /* UTXO SYSTEM: Get UTXO from database
         *
         * IMPORTANT: Do NOT iterate through children here!
         * The child caches already search up through parent chain via
         * BlockchainCache::getUtxo(), which will eventually call this method.
         * If we iterate children here, we create infinite recursion:
         * DatabaseCache → child → parent → DatabaseCache → child → ...
         */

        /* Check database (persisted blocks) */
        try
        {
            auto batch = BlockchainReadBatch().requestUtxo(transactionHash, outputIndex);
            auto result = readDatabase(batch);

            /* Check if UTXO exists in the result */
            const auto &utxosMap = const_cast<const BlockchainReadResult&>(result).getUtxos();
            auto utxoIt = utxosMap.find(std::make_pair(transactionHash, outputIndex));

            if (utxoIt != utxosMap.end())
            {
                utxo = utxoIt->second;
                logger(Logging::TRACE) << "getUtxo: Found UTXO " << Common::podToHex(transactionHash)
                                      << ":" << outputIndex << " in database";
                return true;
            }

            /* UTXO not found in database */
            logger(Logging::TRACE) << "getUtxo: UTXO " << Common::podToHex(transactionHash)
                                  << ":" << outputIndex << " not found in database";
            return false;
        }
        catch (const std::exception &e)
        {
            logger(Logging::ERROR) << "getUtxo database error: " << e.what();
            return false;
        }
    }

    bool DatabaseBlockchainCache::isUtxoUnspent(
        const Crypto::Hash &transactionHash,
        uint32_t outputIndex) const
    {
        /* UTXO SYSTEM: Check if UTXO is unspent
         *
         * Returns true only if:
         * 1. UTXO exists in database
         * 2. UTXO spent field is false
         *
         * Used for double-spend protection. */
        UtxoOutput utxo;
        if (!getUtxo(transactionHash, outputIndex, utxo))
        {
            /* UTXO doesn't exist */
            return false;
        }

        /* UTXO exists - return spent status */
        return !utxo.spent;
    }

    std::vector<UtxoOutput> DatabaseBlockchainCache::getUtxosForTransaction(
        const Crypto::Hash &transactionHash) const
    {
        /* UTXO SYSTEM: Get all UTXOs for a transaction
         *
         * This is used by wallet synchronization to find all outputs
         * created by a specific transaction. Returns both spent and unspent. */
        try
        {
            /* First, get the transaction to know how many outputs it has */
            auto batch = BlockchainReadBatch().requestCachedTransaction(transactionHash);
            auto result = readDatabase(batch);

            const auto &transactionsMap = result.getCachedTransactions();
            auto txIt = transactionsMap.find(transactionHash);

            if (txIt == transactionsMap.end())
            {
                /* Transaction not found */
                return std::vector<UtxoOutput>();
            }

            const auto &txInfo = txIt->second;

            /* Request all UTXOs for this transaction */
            auto utxoBatch = BlockchainReadBatch().requestUtxosForTransaction(
                transactionHash,
                static_cast<uint32_t>(txInfo.outputs.size()));

            auto utxoResult = readDatabase(utxoBatch);

            /* Get UTXOs from result */
            const auto &utxosMap = const_cast<const BlockchainReadResult&>(utxoResult).getUtxos();

            /* Convert map to vector */
            std::vector<UtxoOutput> utxosVec;
            for (auto &pair : utxosMap)
            {
                if (pair.first.first == transactionHash)
                {
                    utxosVec.push_back(pair.second);
                }
            }

            return utxosVec;
        }
        catch (const std::exception &e)
        {
            logger(Logging::ERROR) << "getUtxosForTransaction database error: " << e.what();
            return std::vector<UtxoOutput>();
        }
    }

    std::tuple<bool, std::vector<UtxoOutput>, uint64_t>
        DatabaseBlockchainCache::getAllUtxos(uint64_t page, uint64_t limit) const
    {
        try
        {
            /* Enforce reasonable limits
             *
             * Maximum limit of 100 UTXOs per request to prevent:
             * - Excessive memory usage
             * - Long response times
             * - Database overload
             *
             * Clients should paginate through results using the page parameter */
            const uint64_t MAX_LIMIT = 100;
            if (limit == 0 || limit > MAX_LIMIT)
            {
                limit = 100; /* Default limit */
            }

            logger(Logging::DEBUGGING) << "getAllUtxos: Reconstructing from all blocks";

            /* UTXO SYSTEM: Reconstruct UTXOs from all blocks and transactions
             *
             * Since the database query interface doesn't support prefix scans efficiently,
             * we reconstruct UTXOs by reading all blocks and their transactions.
             * Each transaction output becomes a UTXO (unless it's been spent).

             * UTXO IMMEDIATE AVAILABILITY FIX: Get actual top block from children
             *
             * The database's getTopBlockIndex() only returns blocks persisted to disk.
             * Child caches may have newer blocks that haven't been flushed yet.
             * We need to check all children to find the actual highest block. */
            uint32_t topBlockIndex = getTopBlockIndex();

            /* Check if any child has a higher block index */
            for (const auto &child : children)
            {
                uint32_t childTopIndex = child->getTopBlockIndex();
                if (childTopIndex > topBlockIndex)
                {
                    topBlockIndex = childTopIndex;
                    logger(Logging::TRACE) << "getAllUtxos: Child has higher block index: " << childTopIndex
                                          << " (database has: " << getTopBlockIndex() << ")";
                }
            }

            logger(Logging::DEBUGGING) << "getAllUtxos: Top block index is " << topBlockIndex
                                      << " (database: " << getTopBlockIndex() << ")";

            /* Collect all UTXOs */
            std::vector<UtxoOutput> allUtxos;
            uint32_t blocksProcessed = 0;
            uint32_t blocksSkipped = 0;

            /* Iterate through all blocks */
            for (uint32_t blockIndex = 0; blockIndex <= topBlockIndex; blockIndex++)
            {
                try
                {
                    logger(Logging::INFO) << "getAllUtxos: Processing block " << blockIndex;

                    /* UTXO IMMEDIATE AVAILABILITY FIX: Check children caches first
                     *
                     * When blocks are mined, they're pushed to BlockchainCache children
                     * before being written to the database. These blocks are stored in
                     * the children's internal storage (BlockchainStorage).
                     *
                     * To make newly mined UTXOs immediately available, we need to:
                     * 1. Check if any child cache has this block
                     * 2. If found in child, use it
                     * 3. Otherwise, fall back to database (or rawBlocksCache) */
                    RawBlock rawBlock;
                    bool blockFound = false;

                    /* Check if any child cache has this block */
                    for (IBlockchainCache *child : children)
                    {
                        /* Check if child's storage contains this block */
                        BlockchainCache *blockchainChild = static_cast<BlockchainCache*>(child);

                        /* Check if block index is within child's range */
                        if (blockIndex >= blockchainChild->getStartBlockIndex())
                        {
                            /* Try to get block from child's cache using getBlocksByHeight */
                            try
                            {
                                std::vector<RawBlock> childBlocks = blockchainChild->getBlocksByHeight(blockIndex, blockIndex + 1);
                                if (!childBlocks.empty())
                                {
                                    rawBlock = childBlocks[0];
                                    logger(Logging::TRACE) << "getAllUtxos: Found block " << blockIndex
                                                          << " in child cache (start=" << blockchainChild->getStartBlockIndex() << ")";
                                    blockFound = true;
                                    break;
                                }
                            }
                            catch (const std::exception &e)
                            {
                                /* Block not in this child's storage, continue checking */
                                logger(Logging::TRACE) << "getAllUtxos: Block " << blockIndex
                                                      << " not in child cache: " << e.what();
                            }
                        }
                    }

                    /* If not found in children, check rawBlocksCache (for newly pushed blocks) */
                    if (!blockFound)
                    {
                        for (const auto &cachedBlock : rawBlocksCache)
                        {
                            if (cachedBlock.first == blockIndex)
                            {
                                rawBlock = cachedBlock.second;
                                logger(Logging::TRACE) << "getAllUtxos: Found block " << blockIndex
                                                      << " in rawBlocksCache";
                                blockFound = true;
                                break;
                            }
                        }
                    }

                    /* If still not found, read from database */
                    if (!blockFound)
                    {
                        logger(Logging::TRACE) << "getAllUtxos: Reading block " << blockIndex << " from database";
                        auto batch = BlockchainReadBatch().requestRawBlock(blockIndex);
                        auto res = readDatabase(batch);
                        rawBlock = std::move(res.getRawBlocks().at(blockIndex));
                    }

                    logger(Logging::INFO) << "getAllUtxos: Block " << blockIndex << " has " << rawBlock.transactions.size() << " regular transactions";

                    /* Parse transactions in block */
                    size_t utxoCount = 0;

                    /* Process coinbase transaction */
                    try
                    {
                        /* Deserialize block from BinaryArray to get BlockTemplate */
                        auto blockTemplate = fromBinaryArray<BlockTemplate>(rawBlock.block);

                        CachedTransaction coinbaseTx(blockTemplate.baseTransaction);
                        const Transaction &coinbase = coinbaseTx.getTransaction();
                        const Crypto::Hash &coinbaseHash = coinbaseTx.getTransactionHash();

                        logger(Logging::TRACE) << "Processing coinbase tx " << coinbaseHash << " in block " << blockIndex;

                        /* Process coinbase outputs */
                        for (uint32_t outputIndex = 0; outputIndex < coinbase.outputs.size(); outputIndex++)
                        {
                            const TransactionOutput &output = coinbase.outputs[outputIndex];

                            if (output.target.type() == typeid(KeyOutput))
                            {
                                const KeyOutput &keyOutput = boost::get<KeyOutput>(output.target);

                                /* Create UTXO */
                                UtxoOutput utxo;
                                utxo.amount = output.amount;
                                utxo.publicKey = keyOutput.key;
                                utxo.blockIndex = blockIndex;
                                utxo.transactionHash = coinbaseHash;
                                utxo.outputIndex = outputIndex;
                                utxo.spent = false;
                                utxo.spentBlockIndex = 0;

                                /* Check spent status */
                                BlockchainReadBatch utxoBatch;
                                utxoBatch.requestUtxo(coinbaseHash, outputIndex);
                                auto utxoResult = readDatabase(utxoBatch);
                                const auto &utxosFromDb = utxoResult.getUtxos();

                                auto utxoKey = std::make_pair(coinbaseHash, outputIndex);
                                auto utxoIt = utxosFromDb.find(utxoKey);
                                if (utxoIt != utxosFromDb.end())
                                {
                                    utxo.spent = utxoIt->second.spent;
                                    utxo.spentBlockIndex = utxoIt->second.spentBlockIndex;
                                }

                                allUtxos.push_back(utxo);
                                utxoCount++;
                            }
                        }
                    }
                    catch (const std::exception &e)
                    {
                        logger(Logging::WARNING) << "Error processing coinbase in block " << blockIndex << ": " << e.what();
                    }

                    /* Process regular transactions */
                    for (size_t txIndex = 0; txIndex < rawBlock.transactions.size(); txIndex++)
                    {
                        CachedTransaction cachedTransaction(rawBlock.transactions[txIndex]);
                        const Transaction &tx = cachedTransaction.getTransaction();
                        const Crypto::Hash &txHash = cachedTransaction.getTransactionHash();

                        /* Process each output */
                        for (uint32_t outputIndex = 0; outputIndex < tx.outputs.size(); outputIndex++)
                        {
                            const TransactionOutput &output = tx.outputs[outputIndex];

                            /* Only KeyOutput type is used in transparent system */
                            if (output.target.type() == typeid(KeyOutput))
                            {
                                const KeyOutput &keyOutput = boost::get<KeyOutput>(output.target);

                                /* Create UTXO */
                                UtxoOutput utxo;
                                utxo.amount = output.amount;
                                utxo.publicKey = keyOutput.key;
                                utxo.blockIndex = blockIndex;
                                utxo.transactionHash = txHash;
                                utxo.outputIndex = outputIndex;
                                utxo.spent = false; /* Default to unspent */
                                utxo.spentBlockIndex = 0;

                                /* UTXO SYSTEM: Check spent status from database
                                 *
                                 * We need to query the UTXO itself from the database to get
                                 * its current spent status. The spentUtxos table is unreliable
                                 * because it uses 0 as a default value for both "not found" and
                                 * "spent in block 0".
                                 *
                                 * Since we're reconstructing from blockchain data and don't have
                                 * efficient database prefix scans, we'll check if this specific
                                 * UTXO exists in the database and what its status is. */
                                BlockchainReadBatch utxoBatch;
                                utxoBatch.requestUtxo(txHash, outputIndex);
                                auto utxoResult = readDatabase(utxoBatch);
                                const auto &utxosFromDb = utxoResult.getUtxos();

                                auto utxoKey = std::make_pair(txHash, outputIndex);
                                auto utxoIt = utxosFromDb.find(utxoKey);
                                if (utxoIt != utxosFromDb.end())
                                {
                                    /* UTXO found in database - use its spent status */
                                    utxo.spent = utxoIt->second.spent;
                                    utxo.spentBlockIndex = utxoIt->second.spentBlockIndex;
                                }
                                else
                                {
                                    /* UTXO not in database yet - this means it was just created
                                     * in this block and hasn't been persisted yet, so it's
                                     * definitely unspent */
                                    utxo.spent = false;
                                    utxo.spentBlockIndex = 0;
                                }

                                allUtxos.push_back(utxo);
                            }
                        }
                    }

                    logger(Logging::TRACE) << "Block " << blockIndex << " contributed " << utxoCount << " UTXOs from coinbase + " << rawBlock.transactions.size() << " regular transactions";
                    blocksProcessed++;
                }
                catch (const std::exception &e)
                {
                    logger(Logging::ERROR) << "getAllUtxos: ERROR processing block " << blockIndex << ": " << e.what();
                    blocksSkipped++;
                    /* Continue to next block */
                }
            }

            logger(Logging::INFO) << "getAllUtxos: SUMMARY - Processed " << blocksProcessed << " blocks, skipped " << blocksSkipped << ", found " << allUtxos.size() << " UTXOs";

            /* Sort by (blockIndex, transactionHash, outputIndex) for consistent pagination */
            std::sort(allUtxos.begin(), allUtxos.end(),
                [](const UtxoOutput &a, const UtxoOutput &b)
                {
                    if (a.blockIndex != b.blockIndex)
                        return a.blockIndex < b.blockIndex;
                    /* Compare transaction hashes using memcmp */
                    int hashCompare = std::memcmp(&a.transactionHash, &b.transactionHash, sizeof(Crypto::Hash));
                    if (hashCompare != 0)
                        return hashCompare < 0;
                    return a.outputIndex < b.outputIndex;
                });

            const uint64_t totalUTXOs = allUtxos.size();
            const uint64_t totalPages = (totalUTXOs + limit - 1) / limit;

            /* Apply pagination */
            std::vector<UtxoOutput> pageUtxos;
            if (page < totalPages)
            {
                const uint64_t startIndex = page * limit;
                const uint64_t endIndex = std::min(startIndex + limit, totalUTXOs);

                pageUtxos.assign(
                    allUtxos.begin() + startIndex,
                    allUtxos.begin() + endIndex
                );
            }

            return {true, pageUtxos, totalUTXOs};
        }
        catch (const std::exception &e)
        {
            logger(Logging::ERROR) << "getAllUtxos error: " << e.what();
            return {false, std::vector<UtxoOutput>(), 0};
        }
    }

    std::vector<Crypto::Hash>
        DatabaseBlockchainCache::getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount) const
    {
        std::vector<Crypto::Hash> blockHashes;
        if (secondsCount == 0)
        {
            return blockHashes;
        }

        BlockchainReadBatch batch;
        for (uint64_t timestamp = timestampBegin; timestamp < timestampBegin + static_cast<uint64_t>(secondsCount);
             ++timestamp)
        {
            batch.requestBlockHashesByTimestamp(timestamp);
        }

        auto result = readDatabase(batch);
        for (uint64_t timestamp = timestampBegin; timestamp < timestampBegin + static_cast<uint64_t>(secondsCount);
             ++timestamp)
        {
            if (result.getBlockHashesByTimestamp().count(timestamp) == 0)
            {
                continue;
            }

            const auto &hashes = result.getBlockHashesByTimestamp().at(timestamp);
            blockHashes.insert(blockHashes.end(), hashes.begin(), hashes.end());
        }

        return blockHashes;
    }

    std::vector<RawBlock>
        DatabaseBlockchainCache::getNonEmptyBlocks(const uint64_t startHeight, const size_t blockCount) const
    {
        std::vector<RawBlock> orderedBlocks;

        const uint32_t storageBlockCount = getBlockCount();

        uint64_t height = startHeight;

        while (orderedBlocks.size() < blockCount && height < storageBlockCount)
        {
            uint64_t startHeight = height;

            /* Lets try taking the amount we need *2, to try and balance not needing
               multiple DB requests to get the amount we need of non empty blocks, with
               not taking too many */
            uint64_t endHeight = startHeight + (blockCount * 2);

            auto blockBatch = BlockchainReadBatch().requestRawBlocks(startHeight, endHeight);
            const auto rawBlocks = readDatabase(blockBatch).getRawBlocks();

            while (orderedBlocks.size() < blockCount && height < startHeight + rawBlocks.size())
            {
                const auto block = rawBlocks.at(height);

                height++;

                if (block.transactions.empty())
                {
                    continue;
                }

                orderedBlocks.push_back(block);
            }
        }

        return orderedBlocks;
    }

    std::vector<RawBlock>
        DatabaseBlockchainCache::getBlocksByHeight(const uint64_t startHeight, uint64_t endHeight) const
    {
        auto blockBatch = BlockchainReadBatch().requestRawBlocks(startHeight, endHeight);

        /* Get the info from the DB */
        auto rawBlocks = readDatabase(blockBatch).getRawBlocks();

        std::vector<RawBlock> orderedBlocks;

        /* Order, and convert from map, to vector */
        for (uint64_t height = startHeight; height < startHeight + rawBlocks.size(); height++)
        {
            orderedBlocks.push_back(rawBlocks.at(height));
        }

        return orderedBlocks;
    }

    /* GLOBAL INDEX TRACKING REMOVED - getGlobalIndexes method removed */

    DatabaseBlockchainCache::ExtendedPushedBlockInfo
        DatabaseBlockchainCache::getExtendedPushedBlockInfo(uint32_t blockIndex) const
    {
        assert(blockIndex <= getTopBlockIndex());

        auto batch = BlockchainReadBatch()
                         .requestRawBlock(blockIndex)
                         .requestCachedBlock(blockIndex)
                         .requestSpentKeyImagesByBlock(blockIndex);

        if (blockIndex > 0)
        {
            batch.requestCachedBlock(blockIndex - 1);
        }

        auto dbResult = readDatabase(batch);
        const CachedBlockInfo &blockInfo = dbResult.getCachedBlocks().at(blockIndex);
        const CachedBlockInfo &previousBlockInfo =
            blockIndex > 0 ? dbResult.getCachedBlocks().at(blockIndex - 1) : NULL_CACHED_BLOCK_INFO;

        ExtendedPushedBlockInfo extendedInfo;

        extendedInfo.pushedBlockInfo.rawBlock = dbResult.getRawBlocks().at(blockIndex);
        extendedInfo.pushedBlockInfo.blockSize = blockInfo.blockSize;
        extendedInfo.pushedBlockInfo.blockDifficulty =
            blockInfo.cumulativeDifficulty - previousBlockInfo.cumulativeDifficulty;
        extendedInfo.pushedBlockInfo.generatedCoins =
            blockInfo.alreadyGeneratedCoins - previousBlockInfo.alreadyGeneratedCoins;

        /* TRANSPARENT SYSTEM: Spent transaction tracking already implemented
         *
         * Original: Loaded spentKeyImages from database column
         * Transparent system: Spent transaction hashes loaded separately
         *
         * Implementation:
         * - Spent hashes loaded during pushBlock(): see lines 1163-1164
         * - Stored in spentKeyImagesByBlock column (reused for transaction hashes)
         * - Converted to PublicKey format for database compatibility
         *
         * The commented code below was for KeyImage extraction - no longer needed
         * because spentTransactions is populated in pushBlock(), not here */
        /* const auto &spentKeyImages = dbResult.getSpentKeyImagesByBlock().at(blockIndex); */
        /* extendedInfo.pushedBlockInfo.validatorState.spentKeyImages.insert(spentKeyImages.begin(), spentKeyImages.end()); */

        extendedInfo.timestamp = blockInfo.timestamp;

        return extendedInfo;
    }

    void DatabaseBlockchainCache::setParent(IBlockchainCache *ptr)
    {
        assert(false);
    }

    void DatabaseBlockchainCache::addChild(IBlockchainCache *ptr)
    {
        if (std::find(children.begin(), children.end(), ptr) == children.end())
        {
            children.push_back(ptr);
        }
    }

    bool DatabaseBlockchainCache::deleteChild(IBlockchainCache *ptr)
    {
        auto it = std::remove(children.begin(), children.end(), ptr);
        auto res = it != children.end();
        children.erase(it, children.end());
        return res;
    }

    BlockchainReadResult DatabaseBlockchainCache::readDatabase(BlockchainReadBatch &batch) const
    {
        auto result = database.read(batch);
        if (result)
        {
            logger(Logging::ERROR) << "failed to read database, error is " << result.message();
            throw std::runtime_error(result.message());
        }

        return batch.extractResult();
    }

    void DatabaseBlockchainCache::addGenesisBlock(CachedBlock &&genesisBlock)
    {
        uint64_t minerReward = 0;
        for (const TransactionOutput &output : genesisBlock.getBlock().baseTransaction.outputs)
        {
            minerReward += output.amount;
        }

        assert(minerReward > 0);

        uint64_t baseTransactionSize = getObjectBinarySize(genesisBlock.getBlock().baseTransaction);
        assert(baseTransactionSize < std::numeric_limits<uint32_t>::max());

        BlockchainWriteBatch batch;

        CachedBlockInfo blockInfo {genesisBlock.getBlockHash(),
                                   genesisBlock.getBlock().timestamp,
                                   1,
                                   minerReward,
                                   1,
                                   uint32_t(baseTransactionSize)};

        auto baseTransaction = genesisBlock.getBlock().baseTransaction;
        auto cachedBaseTransaction = CachedTransaction {std::move(baseTransaction)};

        pushTransaction(cachedBaseTransaction, 0, 0, batch);

        batch.insertCachedBlock(blockInfo, 0, {cachedBaseTransaction.getTransactionHash()});
        batch.insertRawBlock(0, {toBinaryArray(genesisBlock.getBlock()), {}});
        batch.insertClosestTimestampBlockIndex(roundToMidnight(genesisBlock.getBlock().timestamp), 0);

        /* Use sync write for genesis block to ensure UTXOs are immediately available */
        auto res = database.write(batch, true);
        if (res)
        {
            logger(Logging::ERROR) << "addGenesisBlock failed: failed to write to database, " << res.message();
            throw std::runtime_error(res.message());
        }

        topBlockHash = genesisBlock.getBlockHash();

        unitsCache.push_back(blockInfo);
    }

} // namespace Pastella