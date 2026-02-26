// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "BlockchainCache.h"

#include <config/WalletConfig.h>
#include "TransactionValidatiorState.h"
#include "common/PastellaTools.h"
#include "common/ShuffleGenerator.h"
#include "common/StdInputStream.h"
#include "common/StdOutputStream.h"
#include "common/TransactionExtra.h"
#include "pastellacore/BlockchainStorage.h"
#include "pastellacore/PastellaBasicImpl.h"
#include "serialization/PastellaSerialization.h"
#include "serialization/SerializationOverloads.h"

#include <boost/functional/hash.hpp>
#include <fstream>
#include <tuple>

namespace Pastella
{
    namespace
    {
        UseGenesis addGenesisBlock = UseGenesis(true);

        UseGenesis skipGenesisBlock = UseGenesis(false);

        template<class T, class F>
        void splitGlobalIndexes(
            T &sourceContainer,
            T &destinationContainer,
            uint32_t splitBlockIndex,
            F lowerBoundFunction)
        {
            for (auto it = sourceContainer.begin(); it != sourceContainer.end();)
            {
                auto newCacheOutputsIteratorStart =
                    lowerBoundFunction(it->second.outputs.begin(), it->second.outputs.end(), splitBlockIndex);

                auto &indexesForAmount = destinationContainer[it->first];
                auto newCacheOutputsCount =
                    static_cast<uint32_t>(std::distance(newCacheOutputsIteratorStart, it->second.outputs.end()));
                indexesForAmount.outputs.reserve(newCacheOutputsCount);

                indexesForAmount.startIndex =
                    it->second.startIndex + static_cast<uint32_t>(it->second.outputs.size()) - newCacheOutputsCount;

                std::move(
                    newCacheOutputsIteratorStart,
                    it->second.outputs.end(),
                    std::back_inserter(indexesForAmount.outputs));
                it->second.outputs.erase(newCacheOutputsIteratorStart, it->second.outputs.end());

                if (indexesForAmount.outputs.empty())
                {
                    destinationContainer.erase(it->first);
                }

                if (it->second.outputs.empty())
                {
                    // if we gave all of our outputs we don't need this amount entry any more
                    it = sourceContainer.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }
    } // namespace

    void SpentKeyImage::serialize(ISerializer &s)
    {
        s(blockIndex, "block_index");
        s(keyImage, "key_image");
    }

    void CachedTransactionInfo::serialize(ISerializer &s)
    {
        s(blockIndex, "block_index");
        s(transactionIndex, "transaction_index");
        s(transactionHash, "transaction_hash");
        s(unlockTime, "unlock_time");
        s(outputs, "outputs");
    }

    void CachedBlockInfo::serialize(ISerializer &s)
    {
        s(blockHash, "block_hash");
        s(timestamp, "timestamp");
        s(blockSize, "block_size");
        s(cumulativeDifficulty, "cumulative_difficulty");
        s(alreadyGeneratedCoins, "already_generated_coins");
        s(alreadyGeneratedTransactions, "already_generated_transaction_count");
    }

    /* UTXO SYSTEM: UTXO serialization for database persistence */

    /* GLOBAL INDEX TRACKING REMOVED - OutputGlobalIndexesForAmount::serialize removed */

    bool serialize(PackedOutIndex &value, Common::StringView name, Pastella::ISerializer &serializer)
    {
        return serializer(value.packedValue, name);
    }

    BlockchainCache::BlockchainCache(
        const std::string &filename,
        const Currency &currency,
        std::shared_ptr<Logging::ILogger> logger_,
        IBlockchainCache *parent,
        uint32_t splitBlockIndex):
        filename(filename),
        currency(currency),
        logger(logger_, "BlockchainCache"),
        parent(parent),
        storage(new BlockchainStorage(100))
    {
        if (parent == nullptr)
        {
            startIndex = 0;

            const CachedBlock genesisBlock(currency.genesisBlock());

            uint64_t minerReward = 0;
            for (const TransactionOutput &output : genesisBlock.getBlock().baseTransaction.outputs)
            {
                minerReward += output.amount;
            }

            assert(minerReward > 0);

            uint64_t coinbaseTransactionSize = getObjectBinarySize(genesisBlock.getBlock().baseTransaction);
            assert(coinbaseTransactionSize < std::numeric_limits<uint64_t>::max());

            std::vector<CachedTransaction> transactions;
            TransactionValidatorState validatorState;
            doPushBlock(
                genesisBlock,
                transactions,
                validatorState,
                coinbaseTransactionSize,
                minerReward,
                1,
                {toBinaryArray(genesisBlock.getBlock())});
        }
        else
        {
            startIndex = splitBlockIndex;
        }

        logger(Logging::DEBUGGING) << "BlockchainCache with start block index: " << startIndex << " created";
    }

    void BlockchainCache::pushBlock(
        const CachedBlock &cachedBlock,
        const std::vector<CachedTransaction> &cachedTransactions,
        const TransactionValidatorState &validatorState,
        size_t blockSize,
        uint64_t generatedCoins,
        uint64_t blockDifficulty,
        RawBlock &&rawBlock)
    {
        // we have to call this function from constructor so it has to be non-virtual
        doPushBlock(
            cachedBlock,
            cachedTransactions,
            validatorState,
            blockSize,
            generatedCoins,
            blockDifficulty,
            std::move(rawBlock));
    }

    void BlockchainCache::doPushBlock(
        const CachedBlock &cachedBlock,
        const std::vector<CachedTransaction> &cachedTransactions,
        const TransactionValidatorState &validatorState,
        size_t blockSize,
        uint64_t generatedCoins,
        uint64_t blockDifficulty,
        RawBlock &&rawBlock)
    {
        logger(Logging::DEBUGGING) << "Pushing block " << cachedBlock.getBlockHash() << " at index "
                                   << cachedBlock.getBlockIndex();

        assert(blockSize > 0);
        assert(blockDifficulty > 0);

        uint64_t cumulativeDifficulty = 0;
        uint64_t alreadyGeneratedCoins = 0;
        uint64_t alreadyGeneratedTransactions = 0;

        if (getBlockCount() == 0)
        {
            if (parent != nullptr)
            {
                cumulativeDifficulty = parent->getCurrentCumulativeDifficulty(cachedBlock.getBlockIndex() - 1);
                alreadyGeneratedCoins = parent->getAlreadyGeneratedCoins(cachedBlock.getBlockIndex() - 1);
                alreadyGeneratedTransactions = parent->getAlreadyGeneratedTransactions(cachedBlock.getBlockIndex() - 1);
            }

            cumulativeDifficulty += blockDifficulty;
            alreadyGeneratedCoins += generatedCoins;
            alreadyGeneratedTransactions += cachedTransactions.size() + 1;
        }
        else
        {
            auto &lastBlockInfo = blockInfos.get<BlockIndexTag>().back();

            cumulativeDifficulty = lastBlockInfo.cumulativeDifficulty + blockDifficulty;
            alreadyGeneratedCoins = lastBlockInfo.alreadyGeneratedCoins + generatedCoins;
            alreadyGeneratedTransactions = lastBlockInfo.alreadyGeneratedTransactions + cachedTransactions.size() + 1;

            /* Debug logging for alreadyGeneratedCoins accumulation */
            std::cout << "DEBUG_CACHE_ACCUMULATION: Height " << cachedBlock.getBlockIndex()
                      << " lastBlockInfo.alreadyGeneratedCoins: " << lastBlockInfo.alreadyGeneratedCoins
                      << " generatedCoins: " << generatedCoins
                      << " new alreadyGeneratedCoins: " << alreadyGeneratedCoins
                      << " (" << (alreadyGeneratedCoins / 100000000.0) << " " << WalletConfig::ticker << ")" << std::endl;
        }

        CachedBlockInfo blockInfo;
        blockInfo.blockHash = cachedBlock.getBlockHash();
        blockInfo.alreadyGeneratedCoins = alreadyGeneratedCoins;
        blockInfo.alreadyGeneratedTransactions = alreadyGeneratedTransactions;
        blockInfo.cumulativeDifficulty = cumulativeDifficulty;
        blockInfo.blockSize = static_cast<uint32_t>(blockSize);
        blockInfo.timestamp = cachedBlock.getBlock().timestamp;

        assert(!hasBlock(blockInfo.blockHash));

        blockInfos.get<BlockIndexTag>().push_back(std::move(blockInfo));

        auto blockIndex = cachedBlock.getBlockIndex();
        assert(blockIndex == blockInfos.size() + startIndex - 1);

        /* TRANSPARENT SYSTEM: Spent transaction tracking already implemented
         *
         * Original: Tracked spentKeyImages set in blockchain cache
         * Transparent system: Uses spentTransactions set (transaction hashes)
         *
         * Implementation:
         * - Spent tracking during validation: ValidateTransaction.cpp:448-460
         * - Database persistence: DatabaseBlockchainCache.cpp:1163-1164
         * - Reorg handling: requestDeleteSpentOutputs() in DatabaseBlockchainCache.cpp:862-889
         *
         * This function no longer needs to track spentKeyImages - that's done elsewhere */

        logger(Logging::DEBUGGING) << "Spent tracking moved to validation layer (spentTransactions set)";

        assert(cachedTransactions.size() <= std::numeric_limits<uint16_t>::max());

        auto transactionBlockIndex = 0;
        auto baseTransaction = cachedBlock.getBlock().baseTransaction;
        pushTransaction(CachedTransaction(std::move(baseTransaction)), blockIndex, transactionBlockIndex++);

        for (auto &cachedTransaction : cachedTransactions)
        {
            pushTransaction(cachedTransaction, blockIndex, transactionBlockIndex++);
        }

        storage->pushBlock(std::move(rawBlock));

        logger(Logging::DEBUGGING) << "Block " << cachedBlock.getBlockHash() << " successfully pushed";
    }

    PushedBlockInfo BlockchainCache::getPushedBlockInfo(uint32_t blockIndex) const
    {
        assert(blockIndex >= startIndex);
        assert(blockIndex < startIndex + getBlockCount());

        auto localIndex = blockIndex - startIndex;
        const auto &cachedBlock = blockInfos.get<BlockIndexTag>()[localIndex];

        PushedBlockInfo pushedBlockInfo;
        pushedBlockInfo.rawBlock = storage->getBlockByIndex(localIndex);
        pushedBlockInfo.blockSize = cachedBlock.blockSize;

        if (blockIndex > startIndex)
        {
            const auto &previousBlock = blockInfos.get<BlockIndexTag>()[localIndex - 1];
            pushedBlockInfo.blockDifficulty = cachedBlock.cumulativeDifficulty - previousBlock.cumulativeDifficulty;
            pushedBlockInfo.generatedCoins = cachedBlock.alreadyGeneratedCoins - previousBlock.alreadyGeneratedCoins;
        }
        else
        {
            if (parent == nullptr)
            {
                pushedBlockInfo.blockDifficulty = cachedBlock.cumulativeDifficulty;
                pushedBlockInfo.generatedCoins = cachedBlock.alreadyGeneratedCoins;
            }
            else
            {
                uint64_t cumulativeDifficulty =
                    parent->getLastCumulativeDifficulties(1, startIndex - 1, addGenesisBlock)[0];
                uint64_t alreadyGeneratedCoins = parent->getAlreadyGeneratedCoins(startIndex - 1);

                pushedBlockInfo.blockDifficulty = cachedBlock.cumulativeDifficulty - cumulativeDifficulty;
                pushedBlockInfo.generatedCoins = cachedBlock.alreadyGeneratedCoins - alreadyGeneratedCoins;
            }
        }

        pushedBlockInfo.validatorState = fillOutputsSpentByBlock(blockIndex);

        return pushedBlockInfo;
    }

    // Returns upper part of segment. [this] remains lower part.
    // All of indexes on blockIndex == splitBlockIndex belong to upper part
    // TODO: first move containers to new cache, then copy elements back. This can be much more effective, cause we
    // usualy split blockchain near its top.
    std::unique_ptr<IBlockchainCache> BlockchainCache::split(uint32_t splitBlockIndex)
    {
        logger(Logging::DEBUGGING) << "Splitting at block index: " << splitBlockIndex
                                   << ", top block index: " << getTopBlockIndex();

        assert(splitBlockIndex > startIndex);
        assert(splitBlockIndex <= getTopBlockIndex());

        std::unique_ptr<BlockchainStorage> newStorage = storage->splitStorage(splitBlockIndex - startIndex);

        std::unique_ptr<BlockchainCache> newCache(
            new BlockchainCache(filename, currency, logger.getLogger(), this, splitBlockIndex));

        newCache->storage = std::move(newStorage);

        splitSpentKeyImages(*newCache, splitBlockIndex);
        splitTransactions(*newCache, splitBlockIndex);
        splitBlocks(*newCache, splitBlockIndex);
        splitKeyOutputsGlobalIndexes(*newCache, splitBlockIndex);

        fixChildrenParent(newCache.get());
        newCache->children = children;
        children = {newCache.get()};

        logger(Logging::DEBUGGING) << "Split successfully completed";

        return newCache;
    }

    void BlockchainCache::splitSpentKeyImages(BlockchainCache &newCache, uint32_t splitBlockIndex)
    {
        /* TRANSPARENT SYSTEM: Spent transaction split not needed here
         *
         * Original: Split spentKeyImages set during blockchain reorganization
         * Transparent system: SpentTransactions tracking handled at validation layer
         *
         * Split logic happens in:
         * - TransactionValidatorState::excludeFromState() - removes spent status on reorg
         * - Database persistence handles split implicitly via transaction hashes
         *
         * This function is now a no-op - spent tracking is validation-layer concern */
        (void)newCache;
        (void)splitBlockIndex;
        logger(Logging::DEBUGGING) << "Spent key images split removed in Phase A";
    }

    void BlockchainCache::splitTransactions(BlockchainCache &newCache, uint32_t splitBlockIndex)
    {
        auto &transactionsIndex = transactions.get<BlockIndexTag>();
        auto lowerBound = transactionsIndex.lower_bound(splitBlockIndex);

        for (auto it = lowerBound; it != transactionsIndex.end(); ++it)
        {
        }

        newCache.transactions.get<BlockIndexTag>().insert(lowerBound, transactionsIndex.end());
        transactionsIndex.erase(lowerBound, transactionsIndex.end());

        logger(Logging::DEBUGGING) << "Transactions split completed";
    }

    void BlockchainCache::splitBlocks(BlockchainCache &newCache, uint32_t splitBlockIndex)
    {
        auto &blocksIndex = blockInfos.get<BlockIndexTag>();
        auto bound = std::next(blocksIndex.begin(), splitBlockIndex - startIndex);
        std::move(bound, blocksIndex.end(), std::back_inserter(newCache.blockInfos.get<BlockIndexTag>()));
        blocksIndex.erase(bound, blocksIndex.end());

        logger(Logging::DEBUGGING) << "Blocks split completed";
    }

    void BlockchainCache::splitKeyOutputsGlobalIndexes(BlockchainCache &newCache, uint32_t splitBlockIndex)
    {
        (void)newCache;
        (void)splitBlockIndex;
    }

    void BlockchainCache::addSpentKeyImage(const Crypto::PublicKey &keyImage, uint32_t blockIndex)
    {
        assert(!checkIfSpent(keyImage, blockIndex - 1)); // Changed from "assert(!checkIfSpent(keyImage, blockIndex));"
        // to prevent fail when pushing block from DatabaseBlockchainCache.
        // In case of pushing external block double spend within block
        // should be checked by Core.
        spentKeyImages.get<BlockIndexTag>().insert(SpentKeyImage {blockIndex, keyImage});
    }

    std::vector<Crypto::Hash> BlockchainCache::getTransactionHashes() const
    {
        auto &txInfos = transactions.get<TransactionHashTag>();
        std::vector<Crypto::Hash> hashes;
        for (auto &tx : txInfos)
        {
            // skip base transaction
            if (tx.transactionIndex != 0)
            {
                hashes.push_back(tx.transactionHash);
            }
        }
        return hashes;
    }

    /* UTXO SYSTEM: Query method implementations */

    bool BlockchainCache::getUtxo(
        const Crypto::Hash &transactionHash,
        uint32_t outputIndex,
        UtxoOutput &utxo) const
    {
        /* UTXO SYSTEM: Get specific UTXO by (transactionHash, outputIndex)
         * Search in local cache first, then parent caches if not found */
        auto &utxoIndex = utxos.get<UtxoKeyTag>();
        auto it = utxoIndex.find(boost::make_tuple(transactionHash, outputIndex));

        if (it != utxoIndex.end())
        {
            utxo = *it;
            return true;
        }

        /* Not found in local cache, check parent */
        if (parent != nullptr)
        {
            return parent->getUtxo(transactionHash, outputIndex, utxo);
        }

        return false;
    }

    bool BlockchainCache::isUtxoUnspent(
        const Crypto::Hash &transactionHash,
        uint32_t outputIndex) const
    {
        /* UTXO SYSTEM: Check if UTXO exists and is unspent
         * Returns true only if UTXO exists AND spent == false */
        UtxoOutput utxo;
        if (!getUtxo(transactionHash, outputIndex, utxo))
        {
            return false; /* UTXO doesn't exist */
        }

        return !utxo.spent; /* UTXO exists, return spent status */
    }

    std::vector<UtxoOutput> BlockchainCache::getUtxosForTransaction(
        const Crypto::Hash &transactionHash) const
    {
        /* UTXO SYSTEM: Get all UTXOs created by a transaction
         * Returns all UTXOs (spent and unspent) from this transaction */
        std::vector<UtxoOutput> result;
        auto &utxoIndex = utxos.get<UtxoKeyTag>();

        /* Find all UTXOs with this transaction hash
         * Since we have a composite key (transactionHash, outputIndex),
         * we need to iterate through all output indices */
        for (auto &utxo : utxoIndex)
        {
            if (utxo.transactionHash == transactionHash)
            {
                result.push_back(utxo);
            }
        }

        /* Also check parent cache */
        if (parent != nullptr)
        {
            auto parentUtxos = parent->getUtxosForTransaction(transactionHash);
            result.insert(result.end(), parentUtxos.begin(), parentUtxos.end());
        }

        return result;
    }

    std::tuple<bool, std::vector<UtxoOutput>, uint64_t> BlockchainCache::getAllUtxos(
        uint64_t page,
        uint64_t limit) const
    {
        /* UTXO SYSTEM: Get all UTXOs with pagination
         *
         * BlockchainCache is an in-memory cache and doesn't have direct access
         * to all UTXOs. Delegate to parent cache (eventually reaching DatabaseBlockchainCache). */

        if (parent != nullptr)
        {
            return parent->getAllUtxos(page, limit);
        }

        /* No parent - return empty result */
        return {false, std::vector<UtxoOutput>(), 0};
    }

    void BlockchainCache::pushTransaction(
        const CachedTransaction &cachedTransaction,
        uint32_t blockIndex,
        uint16_t transactionInBlockIndex)
    {
        logger(Logging::DEBUGGING) << "Adding transaction " << cachedTransaction.getTransactionHash() << " at block "
                                   << blockIndex << ", index in block " << transactionInBlockIndex;

        const auto &tx = cachedTransaction.getTransaction();

        CachedTransactionInfo transactionCacheInfo;
        transactionCacheInfo.blockIndex = blockIndex;
        transactionCacheInfo.transactionIndex = transactionInBlockIndex;
        transactionCacheInfo.transactionHash = cachedTransaction.getTransactionHash();
        transactionCacheInfo.unlockTime = tx.unlockTime;

        assert(tx.outputs.size() <= std::numeric_limits<uint16_t>::max());

        /* GLOBAL INDEX TRACKING REMOVED - globalIndexes field no longer exists
         * In transparent system, outputs are not tracked by global index.
         * Reserve and populate only the outputs vector. */
        transactionCacheInfo.outputs.reserve(tx.outputs.size());

        logger(Logging::DEBUGGING) << "Adding " << tx.outputs.size() << " transaction outputs";
        auto outputCount = 0;
        for (auto &output : tx.outputs)
        {
            transactionCacheInfo.outputs.push_back(output.target);

            PackedOutIndex poi;
            poi.blockIndex = blockIndex;
            poi.transactionIndex = transactionInBlockIndex;
            poi.outputIndex = outputCount;

            /* UTXO SYSTEM: Create UTXO for each transaction output
             *
             * In transparent system, every output becomes a UTXO that can be spent
             * UTXOs are tracked by (transactionHash, outputIndex) composite key
             * This allows direct reference without global indexes */
            UtxoOutput utxo;
            utxo.amount = output.amount;
            utxo.blockIndex = blockIndex;
            utxo.transactionHash = cachedTransaction.getTransactionHash();
            utxo.outputIndex = outputCount;
            utxo.spent = false;
            utxo.spentBlockIndex = 0;

            /* Extract public key from output target
             * All outputs in transparent system are KeyOutput type */
            if (output.target.type() == typeid(KeyOutput))
            {
                const KeyOutput &keyOutput = boost::get<KeyOutput>(output.target);
                utxo.publicKey = keyOutput.key;
            }
            else
            {
                logger(Logging::ERROR) << "Output " << outputCount << " is not a KeyOutput type";
                throw std::runtime_error("Invalid output type in transaction");
            }

            /* Add UTXO to container
             * Container indexed by (transactionHash, outputIndex) composite key
             * Fast lookup for spends and balance queries */
            utxos.get<UtxoKeyTag>().insert(utxo);

            logger(Logging::TRACE) << "Created UTXO: tx=" << utxo.transactionHash
                                   << " output=" << utxo.outputIndex
                                   << " amount=" << utxo.amount
                                   << " key=" << Common::podToHex(utxo.publicKey);

            outputCount++;
        }

        assert(transactions.get<TransactionHashTag>().count(transactionCacheInfo.transactionHash) == 0);
        transactions.get<TransactionInBlockTag>().insert(std::move(transactionCacheInfo));

        /* UTXO SYSTEM: Mark UTXOs as spent for transaction inputs
         *
         * When a transaction spends an input, we need to:
         * 1. Find the UTXO being spent (by transactionHash and outputIndex)
         * 2. Mark it as spent
         * 3. Record which block spent it (for reorg handling)
         *
         * This prevents double-spending the same UTXO */
        for (auto &input : tx.inputs)
        {
            /* TRANSPARENT SYSTEM: Only KeyInput type exists (no BaseInput for regular transactions)
             * KeyInput directly references the UTXO being spent */
            if (input.type() == typeid(KeyInput))
            {
                const KeyInput &keyInput = boost::get<KeyInput>(input);

                /* Find the UTXO being spent */
                auto &utxoIndex = utxos.get<UtxoKeyTag>();
                auto utxoIt = utxoIndex.find(boost::make_tuple(keyInput.transactionHash, keyInput.outputIndex));

                if (utxoIt != utxoIndex.end())
                {
                    /* UTXO found in local cache - mark as spent */
                    UtxoOutput utxo = *utxoIt;
                    if (utxo.spent)
                    {
                        logger(Logging::WARNING) << "UTXO already spent: tx=" << keyInput.transactionHash
                                                  << " output=" << keyInput.outputIndex
                                                  << " spent in block " << utxo.spentBlockIndex;
                        /* This should have been caught by validation, but log it anyway */
                    }
                    else
                    {
                        /* Mark UTXO as spent */
                        utxoIndex.modify(utxoIt, [blockIndex](UtxoOutput &u) {
                            u.spent = true;
                            u.spentBlockIndex = blockIndex;
                        });

                        logger(Logging::TRACE) << "Marked UTXO as spent: tx=" << keyInput.transactionHash
                                               << " output=" << keyInput.outputIndex
                                               << " in block " << blockIndex;
                    }
                }
                else
                {
                    /* UTXO not found in local cache - check parent
                     * Parent UTXOs are immutable, so we create a local copy marked as spent */
                    if (parent != nullptr)
                    {
                        UtxoOutput parentUtxo;
                        if (parent->getUtxo(keyInput.transactionHash, keyInput.outputIndex, parentUtxo))
                        {
                            if (parentUtxo.spent)
                            {
                                logger(Logging::WARNING) << "Parent UTXO already spent: tx=" << keyInput.transactionHash
                                                          << " output=" << keyInput.outputIndex;
                            }
                            else
                            {
                                /* Create local copy of parent UTXO marked as spent */
                                parentUtxo.spent = true;
                                parentUtxo.spentBlockIndex = blockIndex;
                                utxoIndex.insert(parentUtxo);

                                logger(Logging::TRACE) << "Created local spent UTXO copy: tx=" << keyInput.transactionHash
                                                       << " output=" << keyInput.outputIndex;
                            }
                        }
                        else
                        {
                            logger(Logging::ERROR) << "UTXO not found: tx=" << keyInput.transactionHash
                                                   << " output=" << keyInput.outputIndex;
                        }
                    }
                    else
                    {
                        logger(Logging::ERROR) << "UTXO not found and no parent: tx=" << keyInput.transactionHash
                                               << " output=" << keyInput.outputIndex;
                    }
                }
            }
            /* BaseInput is for coinbase transactions which have no inputs to spend */
        }

        

        logger(Logging::DEBUGGING) << "Transaction " << cachedTransaction.getTransactionHash()
                                   << " successfully added";
    }

    /* GLOBAL INDEX TRACKING REMOVED - insertKeyOutputToGlobalIndex() function removed
     *
     * In the transparent system, we no longer maintain global output indexes.
     * This function was used to track key outputs by amount across the blockchain,
     * which is necessary for the ring signature mixing in CryptoNote.
     *
     * In the transparent system:
     * - Outputs are tracked by their actual addresses, not by global index
     * - Ring signatures are not used (no need for decoy outputs)
     * - Reference counting is done via transaction hash, not global index */

    bool BlockchainCache::checkIfSpent(const Crypto::PublicKey &keyImage, uint32_t blockIndex) const
    {
        if (blockIndex < startIndex)
        {
            assert(parent != nullptr);
            return parent->checkIfSpent(keyImage, blockIndex);
        }

        auto it = spentKeyImages.get<KeyImageTag>().find(keyImage);
        if (it == spentKeyImages.get<KeyImageTag>().end())
        {
            return parent != nullptr ? parent->checkIfSpent(keyImage, blockIndex) : false;
        }

        return it->blockIndex <= blockIndex;
    }

    bool BlockchainCache::checkIfSpent(const Crypto::PublicKey &keyImage) const
    {
        if (spentKeyImages.get<KeyImageTag>().count(keyImage) != 0)
        {
            return true;
        }

        return parent != nullptr && parent->checkIfSpent(keyImage);
    }

    uint32_t BlockchainCache::getBlockCount() const
    {
        return static_cast<uint32_t>(blockInfos.size());
    }

    bool BlockchainCache::hasBlock(const Crypto::Hash &blockHash) const
    {
        return blockInfos.get<BlockHashTag>().count(blockHash) != 0;
    }

    uint32_t BlockchainCache::getBlockIndex(const Crypto::Hash &blockHash) const
    {
        //  assert(blockInfos.get<BlockHashTag>().count(blockHash) > 0);
        const auto hashIt = blockInfos.get<BlockHashTag>().find(blockHash);
        if (hashIt == blockInfos.get<BlockHashTag>().end())
        {
            throw std::runtime_error("no such block");
        }

        const auto rndIt = blockInfos.project<BlockIndexTag>(hashIt);
        return static_cast<uint32_t>(std::distance(blockInfos.get<BlockIndexTag>().begin(), rndIt)) + startIndex;
    }

    Crypto::Hash BlockchainCache::getBlockHash(uint32_t blockIndex) const
    {
        if (blockIndex < startIndex)
        {
            assert(parent != nullptr);
            return parent->getBlockHash(blockIndex);
        }

        assert(blockIndex - startIndex < blockInfos.size());
        return blockInfos.get<BlockIndexTag>()[blockIndex - startIndex].blockHash;
    }

    std::vector<Crypto::Hash> BlockchainCache::getBlockHashes(uint32_t startBlockIndex, size_t maxCount) const
    {
        size_t blocksLeft;
        size_t start = 0;
        std::vector<Crypto::Hash> hashes;

        if (startBlockIndex < startIndex)
        {
            assert(parent != nullptr);
            hashes = parent->getBlockHashes(startBlockIndex, maxCount);
            blocksLeft = std::min(maxCount - hashes.size(), blockInfos.size());
        }
        else
        {
            start = startBlockIndex - startIndex;
            blocksLeft = std::min(blockInfos.size() - start, maxCount);
        }

        for (auto i = start; i < start + blocksLeft; ++i)
        {
            hashes.push_back(blockInfos.get<BlockIndexTag>()[i].blockHash);
        }

        return hashes;
    }

    IBlockchainCache *BlockchainCache::getParent() const
    {
        return parent;
    }

    void BlockchainCache::setParent(IBlockchainCache *p)
    {
        parent = p;
    }

    uint32_t BlockchainCache::getStartBlockIndex() const
    {
        return startIndex;
    }

    /* GLOBAL INDEX TRACKING REMOVED - getKeyOutputsCountForAmount() stub
     * Global output indexes are not tracked in the transparent system.
     * This function delegates to parent or returns 0. */
    size_t BlockchainCache::getKeyOutputsCountForAmount(uint64_t amount, uint32_t blockIndex) const
    {
        (void)amount;
        (void)blockIndex;

        if (parent != nullptr)
        {
            return parent->getKeyOutputsCountForAmount(amount, blockIndex);
        }

        return 0;
    }

    std::tuple<bool, uint64_t> BlockchainCache::getBlockHeightForTimestamp(uint64_t timestamp) const
    {
        const auto &index = blockInfos.get<BlockIndexTag>();

        /* Timestamp is too great for this segment */
        if (index.back().timestamp < timestamp)
        {
            return {false, 0};
        }

        /* Timestamp is in this segment */
        if (index.front().timestamp >= timestamp)
        {
            const auto bound =
                std::lower_bound(index.begin(), index.end(), timestamp, [](const auto &blockInfo, uint64_t value) {
                    return blockInfo.timestamp < value;
                });

            uint64_t result = startIndex + std::distance(index.begin(), bound);

            return {true, result};
        }

        /* No parent, we're at the start of the chain */
        if (parent == nullptr)
        {
            return {false, 0};
        }

        /* Try the parent */
        return parent->getBlockHeightForTimestamp(timestamp);
    }

    uint32_t BlockchainCache::getTimestampLowerBoundBlockIndex(uint64_t timestamp) const
    {
        assert(!blockInfos.empty());

        auto &index = blockInfos.get<BlockIndexTag>();
        if (index.back().timestamp < timestamp)
        {
            // we don't have it
            throw std::runtime_error("no blocks for this timestamp, too large");
        }

        if (index.front().timestamp < timestamp)
        {
            // we know the timestamp is in current segment for sure
            auto bound = std::lower_bound(
                index.begin(), index.end(), timestamp, [](const CachedBlockInfo &blockInfo, uint64_t value) {
                    return blockInfo.timestamp < value;
                });

            return startIndex + static_cast<uint32_t>(std::distance(index.begin(), bound));
        }

        // if index.front().timestamp >= timestamp we can't be sure the timestamp is in current segment
        // so we ask parent. If it doesn't have it then index.front() is the block being searched for.

        if (parent == nullptr)
        {
            // if given timestamp is less or equal genesis block timestamp
            return 0;
        }

        try
        {
            uint32_t blockIndex = parent->getTimestampLowerBoundBlockIndex(timestamp);
            return blockIndex != INVALID_BLOCK_INDEX ? blockIndex : startIndex;
        }
        catch (std::runtime_error &)
        {
            return startIndex;
        }
    }

    /* GLOBAL INDEX TRACKING REMOVED - getTransactionGlobalIndexes implementation removed */

    size_t BlockchainCache::getTransactionCount() const
    {
        size_t count = 0;

        if (parent != nullptr)
        {
            count = parent->getTransactionCount();
        }

        count += transactions.size();
        return count;
    }

    std::vector<RawBlock> BlockchainCache::getNonEmptyBlocks(const uint64_t startHeight, const size_t blockCount) const
    {
        std::vector<RawBlock> blocks;

        if (startHeight < startIndex)
        {
            blocks = parent->getNonEmptyBlocks(startHeight, blockCount);

            if (blocks.size() == blockCount)
            {
                return blocks;
            }
        }

        uint64_t startOffset = std::max(startHeight, static_cast<uint64_t>(startIndex));

        uint64_t storageBlockCount = storage->getBlockCount();

        uint64_t i = startOffset;

        while (blocks.size() < blockCount && i < startIndex + storageBlockCount)
        {
            auto block = storage->getBlockByIndex(i - startIndex);

            i++;

            if (block.transactions.empty())
            {
                continue;
            }

            blocks.push_back(block);
        }

        return blocks;
    }

    std::vector<RawBlock> BlockchainCache::getBlocksByHeight(const uint64_t startHeight, uint64_t endHeight) const
    {
        if (endHeight < startIndex)
        {
            return parent->getBlocksByHeight(startHeight, endHeight);
        }

        std::vector<RawBlock> blocks;

        if (startHeight < startIndex)
        {
            blocks = parent->getBlocksByHeight(startHeight, startIndex);
        }

        uint64_t startOffset = std::max(startHeight, static_cast<uint64_t>(startIndex));

        uint64_t blockCount = storage->getBlockCount();

        /* Make sure we don't overflow the storage (for example, the block might
           not exist yet) */
        if (endHeight > startIndex + blockCount)
        {
            endHeight = startIndex + blockCount;
        }

        for (uint64_t i = startOffset; i < endHeight; i++)
        {
            blocks.push_back(storage->getBlockByIndex(i - startIndex));
        }

        logger(Logging::DEBUGGING) << "\n\n"
                                   << "\n============================================="
                                   << "\n======= GetBlockByHeight (in memory) ========"
                                   << "\n* Start height: " << startHeight << "\n* End height: " << endHeight
                                   << "\n* Start index: " << startIndex << "\n* Start offset: " << startIndex
                                   << "\n* Block count: " << startIndex
                                   << "\n============================================="
                                   << "\n\n\n";

        return blocks;
    }

    /* GLOBAL INDEX TRACKING REMOVED - getGlobalIndexes implementation removed */

    RawBlock BlockchainCache::getBlockByIndex(uint32_t index) const
    {
        return index < startIndex ? parent->getBlockByIndex(index) : storage->getBlockByIndex(index - startIndex);
    }

    BinaryArray BlockchainCache::getRawTransaction(uint32_t index, uint32_t transactionIndex) const
    {
        if (index < startIndex)
        {
            return parent->getRawTransaction(index, transactionIndex);
        }
        else
        {
            auto rawBlock = storage->getBlockByIndex(index - startIndex);
            if (transactionIndex == 0)
            {
                auto block = fromBinaryArray<BlockTemplate>(rawBlock.block);
                return toBinaryArray(block.baseTransaction);
            }

            assert(rawBlock.transactions.size() >= transactionIndex - 1);
            return rawBlock.transactions[transactionIndex - 1];
        }
    }

    std::vector<BinaryArray>
        BlockchainCache::getRawTransactions(const std::vector<Crypto::Hash> &requestedTransactions) const
    {
        std::vector<Crypto::Hash> misses;
        auto ret = getRawTransactions(requestedTransactions, misses);
        assert(misses.empty());
        return ret;
    }

    std::vector<BinaryArray> BlockchainCache::getRawTransactions(
        const std::vector<Crypto::Hash> &requestedTransactions,
        std::vector<Crypto::Hash> &missedTransactions) const
    {
        std::vector<BinaryArray> res;
        getRawTransactions(requestedTransactions, res, missedTransactions);
        return res;
    }

    void BlockchainCache::getRawTransactions(
        const std::vector<Crypto::Hash> &requestedTransactions,
        std::vector<BinaryArray> &foundTransactions,
        std::vector<Crypto::Hash> &missedTransactions) const
    {
        auto &index = transactions.get<TransactionHashTag>();
        std::vector<Crypto::Hash> stillNeedToFind;

        for (const auto &transactionHash : requestedTransactions)
        {
            auto it = index.find(transactionHash);
            if (it == index.end())
            {
                /* Not found in local cache, check parent */
                stillNeedToFind.push_back(transactionHash);
                continue;
            }

            // assert(startIndex <= it->blockIndex);
            foundTransactions.push_back(getRawTransaction(it->blockIndex, it->transactionIndex));
        }

        /* If we have a parent cache, query it for missing transactions */
        if (!stillNeedToFind.empty() && parent)
        {
            parent->getRawTransactions(stillNeedToFind, foundTransactions, missedTransactions);
        }
        else if (!stillNeedToFind.empty())
        {
            /* No parent, add all to missed */
            missedTransactions.insert(missedTransactions.end(), stillNeedToFind.begin(), stillNeedToFind.end());
        }
    }

    size_t BlockchainCache::getChildCount() const
    {
        return children.size();
    }

    void BlockchainCache::addChild(IBlockchainCache *child)
    {
        assert(std::find(children.begin(), children.end(), child) == children.end());
        children.push_back(child);
    }

    bool BlockchainCache::deleteChild(IBlockchainCache *child)
    {
        auto it = std::find(children.begin(), children.end(), child);
        if (it == children.end())
        {
            return false;
        }

        children.erase(it);
        return true;
    }

    void BlockchainCache::serialize(ISerializer &s)
    {
        assert(s.type() == ISerializer::OUTPUT);

        uint32_t version = CURRENT_SERIALIZATION_VERSION;

        s(version, "version");

        if (s.type() == ISerializer::OUTPUT)
        {
            writeSequence<CachedTransactionInfo>(transactions.begin(), transactions.end(), "transactions", s);
            writeSequence<SpentKeyImage>(spentKeyImages.begin(), spentKeyImages.end(), "spent_key_images", s);
            writeSequence<CachedBlockInfo>(blockInfos.begin(), blockInfos.end(), "block_hash_indexes", s);
        }
        else
        {
            TransactionsCacheContainer restoredTransactions;
            SpentKeyImagesContainer restoredSpentKeyImages;
            BlockInfoContainer restoredBlockHashIndex;

            readSequence<CachedTransactionInfo>(
                std::inserter(restoredTransactions, restoredTransactions.end()), "transactions", s);
            readSequence<SpentKeyImage>(
                std::inserter(restoredSpentKeyImages, restoredSpentKeyImages.end()), "spent_key_images", s);
            readSequence<CachedBlockInfo>(std::back_inserter(restoredBlockHashIndex), "block_hash_indexes", s);

            transactions = std::move(restoredTransactions);
            spentKeyImages = std::move(restoredSpentKeyImages);
            blockInfos = std::move(restoredBlockHashIndex);
        }
    }

    void BlockchainCache::save()
    {
        std::ofstream file(filename.c_str());
        Common::StdOutputStream stream(file);
        Pastella::BinaryOutputStreamSerializer s(stream);

        serialize(s);
    }

    void BlockchainCache::load()
    {
        std::ifstream file(filename.c_str());
        Common::StdInputStream stream(file);
        Pastella::BinaryInputStreamSerializer s(stream);

        serialize(s);
    }

    bool BlockchainCache::isTransactionSpendTimeUnlocked(uint64_t unlockTime) const
    {
        return isTransactionSpendTimeUnlocked(unlockTime, getTopBlockIndex());
    }

    bool BlockchainCache::isTransactionSpendTimeUnlocked(uint64_t unlockTime, uint32_t blockIndex) const
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

    /* GLOBAL INDEX TRACKING REMOVED - extractKeyOutputKeys implementation removed */

    std::vector<uint32_t> BlockchainCache::getRandomOutsByAmount(Amount amount, size_t count, uint32_t blockIndex) const
    {
        /* GLOBAL INDEX TRACKING REMOVED - keyOutputsGlobalIndexes no longer exists
         * In transparent system, random output selection works differently
         * For now, delegate to parent or return empty vector */
        if (parent != nullptr)
        {
            return parent->getRandomOutsByAmount(amount, count, blockIndex);
        }

        return std::vector<uint32_t>();
    }

    /* GLOBAL INDEX TRACKING REMOVED - extractKeyOutputKeys, extractKeyOtputReferences, and extractKeyOutputs
     * implementations removed - these functions relied on global indexes which don't exist in transparent system */

    std::vector<Crypto::Hash>
        BlockchainCache::getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount) const
    {
        std::vector<Crypto::Hash> blockHashes;
        if (secondsCount == 0)
        {
            return blockHashes;
        }

        if (parent != nullptr)
        {
            blockHashes = parent->getBlockHashesByTimestamps(timestampBegin, secondsCount);
        }

        auto &index = blockInfos.get<TimestampTag>();
        auto begin = index.lower_bound(timestampBegin);
        auto end = index.upper_bound(timestampBegin + static_cast<uint64_t>(secondsCount) - 1);

        blockHashes.reserve(blockHashes.size() + std::distance(begin, end));
        for (auto it = begin; it != end; ++it)
        {
            blockHashes.push_back(it->blockHash);
        }

        logger(Logging::DEBUGGING) << "Found " << blockHashes.size() << " within timestamp interval "
                                   << "[" << timestampBegin << ":" << (timestampBegin + secondsCount) << "]";
        return blockHashes;
    }

    uint32_t BlockchainCache::getTopBlockIndex() const
    {
        assert(!blockInfos.empty());
        return startIndex + storage->getBlockCount() - 1;
    }

    const Crypto::Hash &BlockchainCache::getTopBlockHash() const
    {
        assert(!blockInfos.empty());
        return blockInfos.get<BlockIndexTag>().back().blockHash;
    }

    std::vector<uint64_t> BlockchainCache::getLastTimestamps(size_t count) const
    {
        return getLastTimestamps(count, getTopBlockIndex(), skipGenesisBlock);
    }

    std::vector<uint64_t>
        BlockchainCache::getLastTimestamps(size_t count, uint32_t blockIndex, UseGenesis useGenesis) const
    {
        return getLastUnits(count, blockIndex, useGenesis, [](const CachedBlockInfo &inf) { return inf.timestamp; });
    }

    std::vector<uint64_t> BlockchainCache::getLastBlocksSizes(size_t count) const
    {
        return getLastBlocksSizes(count, getTopBlockIndex(), skipGenesisBlock);
    }

    std::vector<uint64_t> BlockchainCache::getLastUnits(
        size_t count,
        uint32_t blockIndex,
        UseGenesis useGenesis,
        std::function<uint64_t(const CachedBlockInfo &)> pred) const
    {
        assert(blockIndex <= getTopBlockIndex());

        size_t to = blockIndex < startIndex ? 0 : blockIndex - startIndex + 1;
        auto realCount = std::min(count, to);
        auto from = to - realCount;
        if (!useGenesis && from == 0 && realCount != 0 && parent == nullptr)
        {
            from += 1;
            realCount -= 1;
        }

        auto &blocksIndex = blockInfos.get<BlockIndexTag>();

        std::vector<uint64_t> result;
        if (realCount < count && parent != nullptr)
        {
            result = parent->getLastUnits(
                count - realCount, std::min(blockIndex, parent->getTopBlockIndex()), useGenesis, pred);
        }

        std::transform(
            std::next(blocksIndex.begin(), from),
            std::next(blocksIndex.begin(), to),
            std::back_inserter(result),
            std::move(pred));
        return result;
    }

    std::vector<uint64_t>
        BlockchainCache::getLastBlocksSizes(size_t count, uint32_t blockIndex, UseGenesis useGenesis) const
    {
        return getLastUnits(count, blockIndex, useGenesis, [](const CachedBlockInfo &cb) { return cb.blockSize; });
    }

    uint64_t BlockchainCache::getDifficultyForNextBlock() const
    {
        return getDifficultyForNextBlock(getTopBlockIndex());
    }

    uint64_t BlockchainCache::getDifficultyForNextBlock(uint32_t blockIndex) const
    {
        assert(blockIndex <= getTopBlockIndex());
        uint8_t nextBlockMajorVersion = getBlockMajorVersionForHeight(blockIndex + 1);
        auto timestamps = getLastTimestamps(
            currency.difficultyBlocksCountByBlockVersion(nextBlockMajorVersion, blockIndex),
            blockIndex,
            skipGenesisBlock);
        auto commulativeDifficulties = getLastCumulativeDifficulties(
            currency.difficultyBlocksCountByBlockVersion(nextBlockMajorVersion, blockIndex),
            blockIndex,
            skipGenesisBlock);
        return currency.getNextDifficulty(
            nextBlockMajorVersion, blockIndex, std::move(timestamps), std::move(commulativeDifficulties));
    }

    uint64_t BlockchainCache::getCurrentCumulativeDifficulty() const
    {
        assert(!blockInfos.empty());
        return blockInfos.get<BlockIndexTag>().back().cumulativeDifficulty;
    }

    uint64_t BlockchainCache::getCurrentCumulativeDifficulty(uint32_t blockIndex) const
    {
        assert(!blockInfos.empty());
        assert(blockIndex <= getTopBlockIndex());
        return blockInfos.get<BlockIndexTag>().at(blockIndex - startIndex).cumulativeDifficulty;
    }

    uint64_t BlockchainCache::getAlreadyGeneratedCoins() const
    {
        return getAlreadyGeneratedCoins(getTopBlockIndex());
    }

    uint64_t BlockchainCache::getAlreadyGeneratedCoins(uint32_t blockIndex) const
    {
        if (blockIndex < startIndex)
        {
            assert(parent != nullptr);
            return parent->getAlreadyGeneratedCoins(blockIndex);
        }

        return blockInfos.get<BlockIndexTag>().at(blockIndex - startIndex).alreadyGeneratedCoins;
    }

    uint64_t BlockchainCache::getAlreadyGeneratedTransactions(uint32_t blockIndex) const
    {
        if (blockIndex < startIndex)
        {
            assert(parent != nullptr);
            return parent->getAlreadyGeneratedTransactions(blockIndex);
        }

        return blockInfos.get<BlockIndexTag>().at(blockIndex - startIndex).alreadyGeneratedTransactions;
    }

    std::vector<uint64_t>
        BlockchainCache::getLastCumulativeDifficulties(size_t count, uint32_t blockIndex, UseGenesis useGenesis) const
    {
        return getLastUnits(
            count, blockIndex, useGenesis, [](const CachedBlockInfo &info) { return info.cumulativeDifficulty; });
    }

    std::vector<uint64_t> BlockchainCache::getLastCumulativeDifficulties(size_t count) const
    {
        return getLastCumulativeDifficulties(count, getTopBlockIndex(), skipGenesisBlock);
    }

    TransactionValidatorState BlockchainCache::fillOutputsSpentByBlock(uint32_t blockIndex) const
    {
        TransactionValidatorState spentOutputs;

        /* TRANSPARENT SYSTEM: Spent outputs extraction returns empty state
         *
         * Original: Extracted spentKeyImages for blockchain queries
         * Transparent system: Spent tracking is validation-layer concern
         *
         * Why returning empty state is correct:
         * 1. Actual spent tracking: ValidateTransaction.cpp via spentTransactions set
         * 2. Database persistence: Spent hashes stored in spentKeyImagesByBlock column
         * 3. This extraction is for compatibility - real data is in validator state
         *
         * If you need spent outputs for a block:
         * - Query database: getExtendedPushedBlockInfo(blockIndex)
         * - Check validatorState.spentTransactions during validation
         */
        (void)blockIndex;

        return spentOutputs;
    }

    bool BlockchainCache::hasTransaction(const Crypto::Hash &transactionHash) const
    {
        auto &index = transactions.get<TransactionHashTag>();
        auto it = index.find(transactionHash);
        return it != index.end();
    }

    uint32_t BlockchainCache::getBlockIndexContainingTx(const Crypto::Hash &transactionHash) const
    {
        auto &index = transactions.get<TransactionHashTag>();
        auto it = index.find(transactionHash);
        assert(it != index.end());
        return it->blockIndex;
    }

    uint8_t BlockchainCache::getBlockMajorVersionForHeight(uint32_t height) const
    {
        UpgradeManager upgradeManager;
        upgradeManager.addMajorBlockVersion(BLOCK_MAJOR_VERSION_2, currency.upgradeHeight(BLOCK_MAJOR_VERSION_2));
        return upgradeManager.getBlockMajorVersion(height);
    }

    void BlockchainCache::fixChildrenParent(IBlockchainCache *p)
    {
        for (auto child : children)
        {
            child->setParent(p);
        }
    }

} // namespace Pastella
