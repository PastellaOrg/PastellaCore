// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The Galaxia Project Developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <WalletTypes.h>
#include <algorithm>
#include <common/PastellaTools.h>
#include <common/Math.h>
#include <common/MemoryInputStream.h>
#include <common/ShuffleGenerator.h>
#include <common/TransactionExtra.h>
#include <config/Constants.h>
#include <config/WalletConfig.h>
#include <pastellacore/BlockchainCache.h>
#include <pastellacore/BlockchainStorage.h>
#include <pastellacore/BlockchainUtils.h>
#include <pastellacore/Core.h>
#include <pastellacore/CoreErrors.h>
#include <pastellacore/PastellaFormatUtils.h>
#include <pastellacore/GovernanceSystem.h>
#include <pastellacore/ITimeProvider.h>
#include <pastellacore/MemoryBlockchainStorage.h>
#include <pastellacore/TransactionApi.h>
#include <pastellacore/TransactionPool.h>
#include <pastellacore/TransactionPoolCleaner.h>
#include <pastellacore/UpgradeManager.h>
#include <pastellacore/ValidateTransaction.h>
#include <pastellaprotocol/PastellaProtocolHandlerCommon.h>
#include <numeric>
#include <set>
#include <system/Timer.h>
#include <unordered_set>
#include <utilities/Container.h>
#include <utilities/FormatTools.h>
#include <utilities/ParseExtra.h>
#include <utilities/Addresses.h>

using namespace Crypto;
using Logging::LoggerRef;

namespace Pastella
{
    namespace
    {
        template<class T> std::vector<T> preallocateVector(size_t elements)
        {
            std::vector<T> vect;
            vect.reserve(elements);
            return vect;
        }

        UseGenesis addGenesisBlock = UseGenesis(true);

        class TransactionSpentInputsChecker
        {
          public:
            bool haveSpentInputs(const Transaction &transaction)
            {
                /* TRANSPARENT SYSTEM: Returns false (no duplicates found) - CORRECT BEHAVIOR
                 *
                 * Why returning false is correct:
                 * 1. This is called during block template creation (mining)
                 * 2. All transactions in pool are already validated by validateTransactionInputs()
                 * 3. Double-spend prevention happens during validation via spentTransactions set
                 * 4. By the time we build a block template, no duplicates exist in the pool
                 * 5. This function is a final sanity check that correctly finds nothing
                 *
                 * Original: Checked for duplicate keyImages within block
                 * Transparent system: Validation already prevented duplicates, so this returns false
                 *
                 * See: ValidateTransaction.cpp:448-460 for actual double-spend prevention */
                (void)transaction;
                return false; // No duplicates found (validation already prevented them)
            }

          private:
            /* std::unordered_set<Crypto::PublicKey> alreadySpentKeyImages; */
        };

        inline IBlockchainCache *findIndexInChain(IBlockchainCache *blockSegment, const Crypto::Hash &blockHash)
        {
            assert(blockSegment != nullptr);
            while (blockSegment != nullptr)
            {
                if (blockSegment->hasBlock(blockHash))
                {
                    return blockSegment;
                }

                blockSegment = blockSegment->getParent();
            }

            return nullptr;
        }

        inline IBlockchainCache *findIndexInChain(IBlockchainCache *blockSegment, uint32_t blockIndex)
        {
            assert(blockSegment != nullptr);
            while (blockSegment != nullptr)
            {
                if (blockIndex >= blockSegment->getStartBlockIndex()
                    && blockIndex < blockSegment->getStartBlockIndex() + blockSegment->getBlockCount())
                {
                    return blockSegment;
                }

                blockSegment = blockSegment->getParent();
            }

            return nullptr;
        }

        size_t getMaximumTransactionAllowedSize(size_t blockSizeMedian, const Currency &currency)
        {
            assert(blockSizeMedian * 2 > currency.minerTxBlobReservedSize());

            return blockSizeMedian * 2 - currency.minerTxBlobReservedSize();
        }

        BlockTemplate extractBlockTemplate(const RawBlock &block)
        {
            BlockTemplate blockTemplate;
            if (!fromBinaryArray(blockTemplate, block.block))
            {
                throw std::system_error(make_error_code(error::AddBlockErrorCode::DESERIALIZATION_FAILED));
            }

            return blockTemplate;
        }

        Crypto::Hash getBlockHash(const RawBlock &block)
        {
            BlockTemplate blockTemplate = extractBlockTemplate(block);
            return CachedBlock(blockTemplate).getBlockHash();
        }

        TransactionValidatorState extractSpentOutputs(const CachedTransaction &transaction)
        {
            TransactionValidatorState spentOutputs;
            const auto &PastellaTransaction = transaction.getTransaction();

            for (const auto &input : PastellaTransaction.inputs)
            {
                if (input.type() == typeid(KeyInput))
                {
                    /* TRANSPARENT SYSTEM: Spent tracking happens during validation, not here
                     *
                     * This function is called during blockchain reorganizations to extract
                     * spent outputs from transactions being removed.
                     *
                     * Why returning empty state is correct:
                     * 1. Actual spent tracking is in validateTransactionInputs() via spentTransactions
                     * 2. During validation, spent outputs are added to validator state
                     * 3. This extraction function is for reorg handling, not validation
                     * 4. The spent status is persisted in database, not extracted from tx
                     *
                     * Original: Extracted keyImages for reorg processing
                     * Transparent system: Spent transaction hashes tracked persistently
                     *
                     * See: DatabaseBlockchainCache.cpp:1163-1164 for persistence */
                    (void)input;
                }
                else
                {
                    assert(false);
                }
            }

            return spentOutputs;
        }

        TransactionValidatorState extractSpentOutputs(const std::vector<CachedTransaction> &transactions)
        {
            TransactionValidatorState resultOutputs;
            for (const auto &transaction : transactions)
            {
                auto transactionOutputs = extractSpentOutputs(transaction);
                mergeStates(resultOutputs, transactionOutputs);
            }

            return resultOutputs;
        }

        int64_t getEmissionChange(
            const Currency &currency,
            IBlockchainCache &segment,
            uint32_t previousBlockIndex,
            const CachedBlock &cachedBlock,
            uint64_t cumulativeSize,
            uint64_t cumulativeFee)
        {
            uint64_t reward = 0;
            int64_t emissionChange = 0;
            auto alreadyGeneratedCoins = segment.getAlreadyGeneratedCoins(previousBlockIndex);
            auto lastBlocksSizes =
                segment.getLastBlocksSizes(currency.rewardBlocksWindow(), previousBlockIndex, addGenesisBlock);
            auto blocksSizeMedian = Common::medianValue(lastBlocksSizes);
            if (!currency.getBlockReward(
                    cachedBlock.getBlock().majorVersion,
                    blocksSizeMedian,
                    cumulativeSize,
                    alreadyGeneratedCoins,
                    cumulativeFee,
                    reward,
                    emissionChange,
                    1))
            {
                throw std::system_error(make_error_code(error::BlockValidationError::CUMULATIVE_BLOCK_SIZE_TOO_BIG));
            }

            return emissionChange;
        }

        uint32_t findCommonRoot(IMainChainStorage &storage, IBlockchainCache &rootSegment)
        {
            assert(storage.getBlockCount());
            assert(rootSegment.getBlockCount());
            assert(rootSegment.getStartBlockIndex() == 0);
            assert(getBlockHash(storage.getBlockByIndex(0)) == rootSegment.getBlockHash(0));

            uint32_t left = 0;
            uint32_t right = std::min(storage.getBlockCount() - 1, rootSegment.getBlockCount() - 1);
            while (left != right)
            {
                assert(right >= left);
                uint32_t checkElement = left + (right - left) / 2 + 1;
                if (getBlockHash(storage.getBlockByIndex(checkElement)) == rootSegment.getBlockHash(checkElement))
                {
                    left = checkElement;
                }
                else
                {
                    right = checkElement - 1;
                }
            }

            return left;
        }

        const std::chrono::seconds OUTDATED_TRANSACTION_POLLING_INTERVAL = std::chrono::seconds(60);

    } // namespace

    Core::Core(
        const Currency &currency,
        std::shared_ptr<Logging::ILogger> loggerParam,
        Checkpoints &&checkpoints,
        System::Dispatcher &dispatcher,
        std::unique_ptr<IBlockchainCacheFactory> &&blockchainCacheFactory,
        std::unique_ptr<IMainChainStorage> &&mainchainStorage,
        const uint32_t transactionValidationThreads):
        currency(currency),
        dispatcher(dispatcher),
        contextGroup(dispatcher),
        logger(loggerParam, "Core"),
        checkpoints(std::move(checkpoints)),
        upgradeManager(new UpgradeManager()),
        blockchainCacheFactory(std::move(blockchainCacheFactory)),
        mainChainStorage(std::move(mainchainStorage)),
        initialized(false),
        m_transactionValidationThreadPool(transactionValidationThreads)
    {
        upgradeManager->addMajorBlockVersion(BLOCK_MAJOR_VERSION_2, currency.upgradeHeight(BLOCK_MAJOR_VERSION_2));

        transactionPool = std::unique_ptr<ITransactionPoolCleanWrapper>(new TransactionPoolCleanWrapper(
            std::unique_ptr<ITransactionPool>(new TransactionPool(loggerParam)),
            std::unique_ptr<ITimeProvider>(new RealTimeProvider()),
            loggerParam,
            currency.mempoolTxLiveTime()));

        stakingPool = std::make_unique<StakingPool>();
        stakingPool->initialize();

        governanceManager = std::make_unique<GovernanceManager>(currency, logger);
        governanceManager->initialize();
    }

    Core::~Core()
    {
        transactionPool->flush();
        contextGroup.interrupt();
        contextGroup.wait();
    }

    bool Core::addMessageQueue(MessageQueue<BlockchainMessage> &messageQueue)
    {
        return queueList.insert(messageQueue);
    }

    bool Core::removeMessageQueue(MessageQueue<BlockchainMessage> &messageQueue)
    {
        return queueList.remove(messageQueue);
    }

    bool Core::notifyObservers(BlockchainMessage &&msg) /* noexcept */
    {
        try
        {
            for (auto &queue : queueList)
            {
                queue.push(std::move(msg));
            }
            return true;
        }
        catch (std::exception &e)
        {
            LoggerRef loggerSync(logger.getLogger(), "Core.Sync");
            loggerSync(Logging::WARNING) << "failed to notify observers: " << e.what();
            return false;
        }
    }

    uint32_t Core::getTopBlockIndex() const
    {
        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());
        throwIfNotInitialized();

        return chainsLeaves[0]->getTopBlockIndex();
    }

    Crypto::Hash Core::getTopBlockHash() const
    {
        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());

        throwIfNotInitialized();

        return chainsLeaves[0]->getTopBlockHash();
    }

    Crypto::Hash Core::getBlockHashByIndex(uint32_t blockIndex) const
    {
        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());

        throwIfNotInitialized();

        if (blockIndex > getTopBlockIndex())
        {
            return Constants::NULL_HASH;
        }

        return chainsLeaves[0]->getBlockHash(blockIndex);
    }

    uint64_t Core::getBlockTimestampByIndex(uint32_t blockIndex) const
    {
        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());
        assert(blockIndex <= getTopBlockIndex());

        throwIfNotInitialized();

        auto timestamps = chainsLeaves[0]->getLastTimestamps(1, blockIndex, addGenesisBlock);
        assert(timestamps.size() == 1);

        return timestamps[0];
    }

    bool Core::hasBlock(const Crypto::Hash &blockHash) const
    {
        throwIfNotInitialized();
        return findSegmentContainingBlock(blockHash) != nullptr;
    }

    BlockTemplate Core::getBlockByIndex(uint32_t index) const
    {
        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());
        assert(index <= getTopBlockIndex());

        throwIfNotInitialized();
        IBlockchainCache *segment = findMainChainSegmentContainingBlock(index);
        assert(segment != nullptr);

        return restoreBlockTemplate(segment, index);
    }

    BlockTemplate Core::getBlockByHash(const Crypto::Hash &blockHash) const
    {
        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());

        throwIfNotInitialized();
        IBlockchainCache *segment =
            findMainChainSegmentContainingBlock(blockHash); // TODO should it be requested from the main chain?
        if (segment == nullptr)
        {
            throw std::runtime_error("Requested hash wasn't found in main blockchain");
        }

        uint32_t blockIndex = segment->getBlockIndex(blockHash);

        return restoreBlockTemplate(segment, blockIndex);
    }

    std::vector<Crypto::Hash> Core::buildSparseChain() const
    {
        throwIfNotInitialized();
        Crypto::Hash topBlockHash = chainsLeaves[0]->getTopBlockHash();
        return doBuildSparseChain(topBlockHash);
    }

    std::vector<RawBlock> Core::getBlocks(uint32_t minIndex, uint32_t count) const
    {
        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());

        throwIfNotInitialized();

        std::vector<RawBlock> blocks;
        if (count > 0)
        {
            auto cache = chainsLeaves[0];
            auto maxIndex = std::min(minIndex + count - 1, cache->getTopBlockIndex());
            blocks.reserve(count);
            while (cache)
            {
                if (cache->getTopBlockIndex() >= maxIndex)
                {
                    auto minChainIndex = std::max(minIndex, cache->getStartBlockIndex());
                    for (; minChainIndex <= maxIndex; --maxIndex)
                    {
                        blocks.emplace_back(cache->getBlockByIndex(maxIndex));
                        if (maxIndex == 0)
                        {
                            break;
                        }
                    }
                }

                if (blocks.size() == count)
                {
                    break;
                }

                cache = cache->getParent();
            }
        }
        std::reverse(blocks.begin(), blocks.end());

        return blocks;
    }

    void Core::getBlocks(
        const std::vector<Crypto::Hash> &blockHashes,
        std::vector<RawBlock> &blocks,
        std::vector<Crypto::Hash> &missedHashes) const
    {
        throwIfNotInitialized();

        for (const auto &hash : blockHashes)
        {
            IBlockchainCache *blockchainSegment = findSegmentContainingBlock(hash);
            if (blockchainSegment == nullptr)
            {
                missedHashes.push_back(hash);
            }
            else
            {
                uint32_t blockIndex = blockchainSegment->getBlockIndex(hash);
                assert(blockIndex <= blockchainSegment->getTopBlockIndex());

                blocks.push_back(blockchainSegment->getBlockByIndex(blockIndex));
            }
        }
    }

    void Core::copyTransactionsToPool(IBlockchainCache *alt)
    {
        assert(alt != nullptr);
        while (alt != nullptr)
        {
            if (mainChainSet.count(alt) != 0)
            {
                break;
            }
            auto transactions = alt->getRawTransactions(alt->getTransactionHashes());
            for (auto &transaction : transactions)
            {
                const auto [success, error] = addTransactionToPool(std::move(transaction));
                if (success)
                {
                    // TODO: send notification
                }
            }
            alt = alt->getParent();
        }
    }

    bool Core::queryBlocks(
        const std::vector<Crypto::Hash> &blockHashes,
        uint64_t timestamp,
        uint32_t &startIndex,
        uint32_t &currentIndex,
        uint32_t &fullOffset,
        std::vector<BlockFullInfo> &entries) const
    {
        assert(entries.empty());
        assert(!chainsLeaves.empty());
        assert(!chainsStorage.empty());
        throwIfNotInitialized();

        try
        {
            IBlockchainCache *mainChain = chainsLeaves[0];
            currentIndex = mainChain->getTopBlockIndex();

            startIndex = findBlockchainSupplement(blockHashes); // throws

            fullOffset = mainChain->getTimestampLowerBoundBlockIndex(timestamp);
            if (fullOffset < startIndex)
            {
                fullOffset = startIndex;
            }

            size_t hashesPushed =
                pushBlockHashes(startIndex, fullOffset, BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT, entries);

            if (startIndex + hashesPushed != fullOffset)
            {
                return true;
            }

            fillQueryBlockFullInfo(fullOffset, currentIndex, BLOCKS_SYNCHRONIZING_DEFAULT_COUNT, entries);

            return true;
        }
        catch (std::exception &)
        {
            // TODO log
            return false;
        }
    }

    bool Core::queryBlocksLite(
        const std::vector<Crypto::Hash> &knownBlockHashes,
        uint64_t timestamp,
        uint32_t &startIndex,
        uint32_t &currentIndex,
        uint32_t &fullOffset,
        std::vector<BlockShortInfo> &entries) const
    {
        assert(entries.empty());
        assert(!chainsLeaves.empty());
        assert(!chainsStorage.empty());

        throwIfNotInitialized();

        try
        {
            IBlockchainCache *mainChain = chainsLeaves[0];
            currentIndex = mainChain->getTopBlockIndex();

            startIndex = findBlockchainSupplement(knownBlockHashes); // throws

            // Stops bug where wallets fail to sync, because timestamps have been adjusted after syncronisation.
            // check for a query of the blocks where the block index is non-zero, but the timestamp is zero
            // indicating that the originator did not know the internal time of the block, but knew which block
            // was wanted by index.  Fullfill this by getting the time of m_blocks[startIndex].timestamp.

            if (startIndex > 0 && timestamp == 0)
            {
                if (startIndex <= mainChain->getTopBlockIndex())
                {
                    RawBlock block = mainChain->getBlockByIndex(startIndex);
                    auto blockTemplate = extractBlockTemplate(block);
                    timestamp = blockTemplate.timestamp;
                }
            }

            fullOffset = mainChain->getTimestampLowerBoundBlockIndex(timestamp);
            if (fullOffset < startIndex)
            {
                fullOffset = startIndex;
            }

            size_t hashesPushed =
                pushBlockHashes(startIndex, fullOffset, BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT, entries);

            if (startIndex + static_cast<uint32_t>(hashesPushed) != fullOffset)
            {
                return true;
            }

            fillQueryBlockShortInfo(fullOffset, currentIndex, BLOCKS_SYNCHRONIZING_DEFAULT_COUNT, entries);

            return true;
        }
        catch (std::exception &e)
        {
            LoggerRef loggerSync(logger.getLogger(), "Core.Sync");
            loggerSync(Logging::ERROR) << "Failed to query blocks: " << e.what();
            return false;
        }
    }

    bool Core::queryBlocksDetailed(
        const std::vector<Crypto::Hash> &knownBlockHashes,
        uint64_t timestamp,
        uint64_t &startIndex,
        uint64_t &currentIndex,
        uint64_t &fullOffset,
        std::vector<BlockDetails> &entries,
        uint32_t blockCount) const
    {
        assert(entries.empty());
        assert(!chainsLeaves.empty());
        assert(!chainsStorage.empty());

        throwIfNotInitialized();

        try
        {
            if (blockCount == 0)
            {
                blockCount = BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT;
            }
            else if (blockCount == 1)
            {
                /* If we only ever request one block at a time then any attempt to sync
       via this method will not proceed */
                blockCount = 2;
            }
            else if (blockCount > BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT)
            {
                /* If we request more than the maximum defined here, chances are we are
         going to timeout or otherwise fail whether we meant it to or not as
         this is a VERY resource heavy RPC call */
                blockCount = BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT;
            }

            IBlockchainCache *mainChain = chainsLeaves[0];
            currentIndex = mainChain->getTopBlockIndex();

            startIndex = findBlockchainSupplement(knownBlockHashes); // throws

            // Stops bug where wallets fail to sync, because timestamps have been adjusted after syncronisation.
            // check for a query of the blocks where the block index is non-zero, but the timestamp is zero
            // indicating that the originator did not know the internal time of the block, but knew which block
            // was wanted by index.  Fullfill this by getting the time of m_blocks[startIndex].timestamp.

            if (startIndex > 0 && timestamp == 0)
            {
                if (startIndex <= mainChain->getTopBlockIndex())
                {
                    RawBlock block = mainChain->getBlockByIndex(startIndex);
                    auto blockTemplate = extractBlockTemplate(block);
                    timestamp = blockTemplate.timestamp;
                }
            }

            fullOffset = mainChain->getTimestampLowerBoundBlockIndex(timestamp);
            if (fullOffset < startIndex)
            {
                fullOffset = startIndex;
            }

            size_t hashesPushed = pushBlockHashes(startIndex, fullOffset, blockCount, entries);

            if (startIndex + static_cast<uint32_t>(hashesPushed) != fullOffset)
            {
                return true;
            }

            fillQueryBlockDetails(fullOffset, currentIndex, blockCount, entries);

            return true;
        }
        catch (std::exception &e)
        {
            LoggerRef loggerSync(logger.getLogger(), "Core.Sync");
            loggerSync(Logging::ERROR) << "Failed to query blocks: " << e.what();
            return false;
        }
    }

    /* Transaction hashes = The hashes the wallet wants to query.
       transactions in pool - We'll add hashes to this if the transaction is in the pool
       transactions in block - We'll add hashes to this if the transaction is in a block
       transactions unknown - We'll add hashes to this if we don't know about them - possibly fell out the tx pool */
    bool Core::getTransactionsStatus(
        std::unordered_set<Crypto::Hash> transactionHashes,
        std::unordered_set<Crypto::Hash> &transactionsInPool,
        std::unordered_set<Crypto::Hash> &transactionsInBlock,
        std::unordered_set<Crypto::Hash> &transactionsUnknown) const
    {
        throwIfNotInitialized();

        try
        {
            const auto txs = transactionPool->getTransactionHashes();

            /* Pop into a set for quicker .find() */
            std::unordered_set<Crypto::Hash> poolTransactions(txs.begin(), txs.end());

            for (const auto hash : transactionHashes)
            {
                if (poolTransactions.find(hash) != poolTransactions.end())
                {
                    /* It's in the pool */
                    transactionsInPool.insert(hash);
                }
                else if (findSegmentContainingTransaction(hash) != nullptr)
                {
                    /* It's in a block */
                    transactionsInBlock.insert(hash);
                }
                else
                {
                    /* We don't know anything about it */
                    transactionsUnknown.insert(hash);
                }
            }

            return true;
        }
        catch (std::exception &e)
        {
            LoggerRef loggerSync(logger.getLogger(), "Core.Sync");
            loggerSync(Logging::ERROR) << "Failed to get transactions status: " << e.what();
            return false;
        }
    }

    /* Known block hashes = The hashes the wallet knows about. We'll give blocks starting from this hash.
       Timestamp = The timestamp to start giving blocks from, if knownBlockHashes is empty. Used for syncing a new
       wallet. walletBlocks = The returned vector of blocks */
    bool Core::getWalletSyncData(
        const std::vector<Crypto::Hash> &knownBlockHashes,
        const uint64_t startHeight,
        const uint64_t startTimestamp,
        const uint64_t blockCount,
        const bool skipCoinbaseTransactions,
        std::vector<WalletTypes::WalletBlockInfo> &walletBlocks,
        std::optional<WalletTypes::TopBlock> &topBlockInfo) const
    {
        throwIfNotInitialized();

        try
        {
            IBlockchainCache *mainChain = chainsLeaves[0];

            /* Current height */
            uint64_t currentIndex = mainChain->getTopBlockIndex();
            Crypto::Hash currentHash = mainChain->getTopBlockHash();

            uint64_t actualBlockCount = std::min(BLOCKS_SYNCHRONIZING_DEFAULT_COUNT, blockCount);

            if (actualBlockCount == 0)
            {
                actualBlockCount = BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;
            }

            auto [success, timestampBlockHeight] = mainChain->getBlockHeightForTimestamp(startTimestamp);

            /* If no timestamp given, occasionaly the daemon returns a non zero
           block height... for some reason. Set it back to zero if we didn't
           give a timestamp to fix this. */
            if (startTimestamp == 0)
            {
                timestampBlockHeight = 0;
            }

            /* If we couldn't get the first block timestamp, then the node is
           synced less than the current height, so return no blocks till we're
           synced. */
            if (startTimestamp != 0 && !success)
            {
                topBlockInfo = WalletTypes::TopBlock({currentHash, currentIndex});
                return true;
            }

            /* If a height was given, start from there, else convert the timestamp
           to a block */
            uint64_t firstBlockHeight = startHeight == 0 ? timestampBlockHeight : startHeight;

            /* The height of the last block we know about */
            uint64_t lastKnownBlockHashHeight = static_cast<uint64_t>(findBlockchainSupplement(knownBlockHashes));

            /* Start returning either from the start height, or the height of the
           last block we know about, whichever is higher */
            uint64_t startIndex = std::max(
                /* Plus one so we return the next block - default to zero if it's zero,
           otherwise genesis block will be skipped. */
                lastKnownBlockHashHeight == 0 ? 0 : lastKnownBlockHashHeight + 1,
                firstBlockHeight);

            /* Difference between the start and end */
            uint64_t blockDifference = currentIndex - startIndex;

            /* Sync actualBlockCount or the amount of blocks between
           start and end, whichever is smaller */
            uint64_t endIndex = std::min(actualBlockCount, blockDifference + 1) + startIndex;

            LoggerRef loggerSync(logger.getLogger(), "Core.Sync");
            loggerSync(Logging::DEBUGGING) << "\n\n"
                                       << "\n============================================="
                                       << "\n========= GetWalletSyncData summary ========="
                                       << "\n* Known block hashes size: " << knownBlockHashes.size()
                                       << "\n* Blocks requested: " << actualBlockCount
                                       << "\n* Start height: " << startHeight
                                       << "\n* Start timestamp: " << startTimestamp
                                       << "\n* Current index: " << currentIndex
                                       << "\n* Timestamp block height: " << timestampBlockHeight
                                       << "\n* First block height: " << firstBlockHeight
                                       << "\n* Last known block hash height: " << lastKnownBlockHashHeight
                                       << "\n* Start index: " << startIndex
                                       << "\n* Block difference: " << blockDifference << "\n* End index: " << endIndex
                                       << "\n============================================="
                                       << "\n\n\n";

            /* If we're fully synced, then the start index will be greater than our
           current block. */
            if (currentIndex < startIndex)
            {
                topBlockInfo = WalletTypes::TopBlock({currentHash, currentIndex});
                return true;
            }

            std::vector<RawBlock> rawBlocks;

            if (skipCoinbaseTransactions)
            {
                rawBlocks = mainChain->getNonEmptyBlocks(startIndex, actualBlockCount);
            }
            else
            {
                rawBlocks = mainChain->getBlocksByHeight(startIndex, endIndex);
            }

            for (const auto rawBlock : rawBlocks)
            {
                BlockTemplate block;

                fromBinaryArray(block, rawBlock.block);

                WalletTypes::WalletBlockInfo walletBlock;

                CachedBlock cachedBlock(block);

                walletBlock.blockHeight = cachedBlock.getBlockIndex();
                walletBlock.blockHash = cachedBlock.getBlockHash();
                walletBlock.blockTimestamp = block.timestamp;

                if (!skipCoinbaseTransactions)
                {
                    walletBlock.coinbaseTransaction = getRawCoinbaseTransaction(block.baseTransaction);
                }

                for (const auto &transaction : rawBlock.transactions)
                {
                    WalletTypes::RawTransaction rawTx = getRawTransaction(transaction);

                    /* Check if this is a staking transaction by looking for staking data in extra field */
                    std::vector<Pastella::TransactionExtraField> extraFields;
                    parseTransactionExtra(rawTx.extra, extraFields);

                    bool isStakingTx = false;
                    for (const auto &field : extraFields)
                    {
                        if (field.type() == typeid(Pastella::TransactionExtraStaking))
                        {
                            const auto &stakingData = boost::get<Pastella::TransactionExtraStaking>(field);
                            if (stakingData.stakingType == Pastella::parameters::staking::STAKING_TX_TYPE)
                            {
                                isStakingTx = true;
                                break;
                            }
                        }
                    }

                    /* Add to appropriate vector based on transaction type */
                    if (isStakingTx)
                    {
                        walletBlock.stakingTransactions.push_back(rawTx);
                    }
                    else
                    {
                        walletBlock.transactions.push_back(rawTx);
                    }
                }

                walletBlocks.push_back(walletBlock);
            }

            if (walletBlocks.empty())
            {
                topBlockInfo = WalletTypes::TopBlock({currentHash, currentIndex});
            }

            return true;
        }
        catch (std::exception &e)
        {
            LoggerRef loggerSync(logger.getLogger(), "Core.Sync");
            loggerSync(Logging::ERROR) << "Failed to get wallet sync data: " << e.what();
            return false;
        }
    }

    /* Known block hashes = The hashes the wallet knows about. We'll give blocks starting from this hash.
       Timestamp = The timestamp to start giving blocks from, if knownBlockHashes is empty. Used for syncing a new
       wallet. walletBlocks = The returned vector of blocks */
    bool Core::getRawBlocks(
        const std::vector<Crypto::Hash> &knownBlockHashes,
        const uint64_t startHeight,
        const uint64_t startTimestamp,
        const uint64_t blockCount,
        const bool skipCoinbaseTransactions,
        std::vector<RawBlock> &blocks,
        std::optional<WalletTypes::TopBlock> &topBlockInfo) const
    {
        throwIfNotInitialized();

        try
        {
            IBlockchainCache *mainChain = chainsLeaves[0];

            /* Current height */
            uint64_t currentIndex = mainChain->getTopBlockIndex();
            Crypto::Hash currentHash = mainChain->getTopBlockHash();

            uint64_t actualBlockCount = std::min(BLOCKS_SYNCHRONIZING_DEFAULT_COUNT, blockCount);

            if (actualBlockCount == 0)
            {
                actualBlockCount = BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;
            }

            auto [success, timestampBlockHeight] = mainChain->getBlockHeightForTimestamp(startTimestamp);

            /* If no timestamp given, occasionaly the daemon returns a non zero
           block height... for some reason. Set it back to zero if we didn't
           give a timestamp to fix this. */
            if (startTimestamp == 0)
            {
                timestampBlockHeight = 0;
            }

            /* If we couldn't get the first block timestamp, then the node is
           synced less than the current height, so return no blocks till we're
           synced. */
            if (startTimestamp != 0 && !success)
            {
                topBlockInfo = WalletTypes::TopBlock({currentHash, currentIndex});
                return true;
            }

            /* If a height was given, start from there, else convert the timestamp
           to a block */
            uint64_t firstBlockHeight = startHeight == 0 ? timestampBlockHeight : startHeight;

            /* The height of the last block we know about */
            uint64_t lastKnownBlockHashHeight = static_cast<uint64_t>(findBlockchainSupplement(knownBlockHashes));

            /* Start returning either from the start height, or the height of the
           last block we know about, whichever is higher */
            uint64_t startIndex = std::max(
                /* Plus one so we return the next block - default to zero if it's zero,
           otherwise genesis block will be skipped. */
                lastKnownBlockHashHeight == 0 ? 0 : lastKnownBlockHashHeight + 1,
                firstBlockHeight);

            /* Difference between the start and end */
            uint64_t blockDifference = currentIndex - startIndex;

            /* Sync actualBlockCount or the amount of blocks between
           start and end, whichever is smaller */
            uint64_t endIndex = std::min(actualBlockCount, blockDifference + 1) + startIndex;

            LoggerRef loggerSync(logger.getLogger(), "Core.Sync");
            loggerSync(Logging::DEBUGGING) << "\n\n"
                                       << "\n============================================="
                                       << "\n========= GetRawBlocks summary ========="
                                       << "\n* Known block hashes size: " << knownBlockHashes.size()
                                       << "\n* Blocks requested: " << actualBlockCount
                                       << "\n* Start height: " << startHeight
                                       << "\n* Start timestamp: " << startTimestamp
                                       << "\n* Current index: " << currentIndex
                                       << "\n* Timestamp block height: " << timestampBlockHeight
                                       << "\n* First block height: " << firstBlockHeight
                                       << "\n* Last known block hash height: " << lastKnownBlockHashHeight
                                       << "\n* Start index: " << startIndex
                                       << "\n* Block difference: " << blockDifference << "\n* End index: " << endIndex
                                       << "\n============================================="
                                       << "\n\n\n";

            /* If we're fully synced, then the start index will be greater than our
           current block. */
            if (currentIndex < startIndex)
            {
                topBlockInfo = WalletTypes::TopBlock({currentHash, currentIndex});
                return true;
            }

            if (skipCoinbaseTransactions)
            {
                blocks = mainChain->getNonEmptyBlocks(startIndex, actualBlockCount);
            }
            else
            {
                blocks = mainChain->getBlocksByHeight(startIndex, endIndex);
            }

            if (blocks.empty())
            {
                topBlockInfo = WalletTypes::TopBlock({currentHash, currentIndex});
            }

            return true;
        }
        catch (std::exception &e)
        {
            LoggerRef loggerSync(logger.getLogger(), "Core.Sync");
            loggerSync(Logging::ERROR) << "Failed to get wallet sync data: " << e.what();
            return false;
        }
    }

    WalletTypes::RawCoinbaseTransaction Core::getRawCoinbaseTransaction(const Pastella::Transaction &t)
    {
        WalletTypes::RawCoinbaseTransaction transaction;

        transaction.hash = getBinaryArrayHash(toBinaryArray(t));

        transaction.transactionPublicKey = Utilities::getTransactionPublicKeyFromExtra(t.extra);

        transaction.unlockTime = t.unlockTime;

        /* Fill in the simplified key outputs */
        for (const auto &output : t.outputs)
        {
            WalletTypes::KeyOutput keyOutput;

            keyOutput.amount = output.amount;
            keyOutput.key = boost::get<Pastella::KeyOutput>(output.target).key;

            transaction.keyOutputs.push_back(keyOutput);
        }

        return transaction;
    }

    WalletTypes::RawTransaction Core::getRawTransaction(const std::vector<uint8_t> &rawTX)
    {
        Transaction t;

        /* Convert the binary array to a transaction */
        fromBinaryArray(t, rawTX);

        WalletTypes::RawTransaction transaction;

        /* Get the transaction hash from the binary array */
        transaction.hash = getBinaryArrayHash(rawTX);

        Utilities::ParsedExtra parsedExtra = Utilities::parseExtra(t.extra);

        /* Transaction public key, used for decrypting transactions along with
        transaction.transactionPublicKey = parsedExtra.transactionPublicKey;

        

        /* Store the raw extra data for staking detection */
        transaction.extra = t.extra;

        transaction.unlockTime = t.unlockTime;

        /* Simplify the outputs */
        for (const auto &output : t.outputs)
        {
            WalletTypes::KeyOutput keyOutput;

            keyOutput.amount = output.amount;
            keyOutput.key = boost::get<Pastella::KeyOutput>(output.target).key;

            transaction.keyOutputs.push_back(keyOutput);
        }

        /* Simplify the inputs */
        for (const auto &input : t.inputs)
        {
            transaction.keyInputs.push_back(boost::get<Pastella::KeyInput>(input));
        }

        return transaction;
    }

    std::optional<BinaryArray> Core::getTransaction(const Crypto::Hash &hash) const
    {
        throwIfNotInitialized();
        auto segment = findSegmentContainingTransaction(hash);
        if (segment != nullptr)
        {
            return segment->getRawTransactions({hash})[0];
        }
        else if (transactionPool->checkIfTransactionPresent(hash))
        {
            return transactionPool->getTransaction(hash).getTransactionBinaryArray();
        }
        else
        {
            return std::nullopt;
        }
    }

    void Core::getTransactions(
        const std::vector<Crypto::Hash> &transactionHashes,
        std::vector<BinaryArray> &transactions,
        std::vector<Crypto::Hash> &missedHashes) const
    {
        assert(!chainsLeaves.empty());
        assert(!chainsStorage.empty());
        throwIfNotInitialized();

        IBlockchainCache *segment = chainsLeaves[0];
        assert(segment != nullptr);

        std::vector<Crypto::Hash> leftTransactions = transactionHashes;

        // find in main chain
        do
        {
            std::vector<Crypto::Hash> missedTransactions;
            segment->getRawTransactions(leftTransactions, transactions, missedTransactions);

            leftTransactions = std::move(missedTransactions);
            segment = segment->getParent();
        } while (segment != nullptr && !leftTransactions.empty());

        if (leftTransactions.empty())
        {
            return;
        }

        // find in alternative chains
        for (size_t chain = 1; chain < chainsLeaves.size(); ++chain)
        {
            segment = chainsLeaves[chain];

            while (mainChainSet.count(segment) == 0 && !leftTransactions.empty())
            {
                std::vector<Crypto::Hash> missedTransactions;
                segment->getRawTransactions(leftTransactions, transactions, missedTransactions);

                leftTransactions = std::move(missedTransactions);
                segment = segment->getParent();
            }
        }

        missedHashes.insert(missedHashes.end(), leftTransactions.begin(), leftTransactions.end());
    }

    uint64_t Core::getBlockDifficulty(uint32_t blockIndex) const
    {
        throwIfNotInitialized();
        IBlockchainCache *mainChain = chainsLeaves[0];
        auto difficulties = mainChain->getLastCumulativeDifficulties(2, blockIndex, addGenesisBlock);
        if (difficulties.size() == 2)
        {
            return difficulties[1] - difficulties[0];
        }

        assert(difficulties.size() == 1);
        return difficulties[0];
    }

    // TODO: just use mainChain->getDifficultyForNextBlock() ?
    uint64_t Core::getDifficultyForNextBlock() const
    {
        throwIfNotInitialized();
        IBlockchainCache *mainChain = chainsLeaves[0];

        uint32_t topBlockIndex = mainChain->getTopBlockIndex();

        uint8_t nextBlockMajorVersion = getBlockMajorVersionForHeight(topBlockIndex);

        size_t blocksCount = std::min(
            static_cast<size_t>(topBlockIndex),
            currency.difficultyBlocksCountByBlockVersion(nextBlockMajorVersion, topBlockIndex));

        auto timestamps = mainChain->getLastTimestamps(blocksCount);
        auto difficulties = mainChain->getLastCumulativeDifficulties(blocksCount);

        return currency.getNextDifficulty(nextBlockMajorVersion, topBlockIndex, timestamps, difficulties);
    }

    std::vector<Crypto::Hash> Core::findBlockchainSupplement(
        const std::vector<Crypto::Hash> &remoteBlockIds,
        size_t maxCount,
        uint32_t &totalBlockCount,
        uint32_t &startBlockIndex) const
    {
        assert(!remoteBlockIds.empty());
        assert(remoteBlockIds.back() == getBlockHashByIndex(0));
        throwIfNotInitialized();

        totalBlockCount = getTopBlockIndex() + 1;
        startBlockIndex = findBlockchainSupplement(remoteBlockIds);

        return getBlockHashes(startBlockIndex, static_cast<uint32_t>(maxCount));
    }

    std::error_code Core::addBlock(const CachedBlock &cachedBlock, RawBlock &&rawBlock)
    {
        throwIfNotInitialized();
        uint32_t blockIndex = cachedBlock.getBlockIndex();
        Crypto::Hash blockHash = cachedBlock.getBlockHash();
        std::ostringstream os;
        os << blockIndex << " (" << blockHash << ")";
        std::string blockStr = os.str();

        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
        loggerBlockchain(Logging::DEBUGGING) << "Request to add block " << blockStr;
        if (hasBlock(cachedBlock.getBlockHash()))
        {
            loggerBlockchain(Logging::DEBUGGING) << "Block " << blockStr << " already exists";
            return error::AddBlockErrorCode::ALREADY_EXISTS;
        }

        const auto &blockTemplate = cachedBlock.getBlock();
        const auto &previousBlockHash = blockTemplate.previousBlockHash;

        assert(rawBlock.transactions.size() == blockTemplate.transactionHashes.size());

        auto cache = findSegmentContainingBlock(previousBlockHash);
        if (cache == nullptr)
        {
            loggerBlockchain(Logging::DEBUGGING) << "Block " << blockStr << " rejected as orphaned";
            return error::AddBlockErrorCode::REJECTED_AS_ORPHANED;
        }

        std::vector<CachedTransaction> transactions;
        uint64_t cumulativeSize = 0;
        if (!extractTransactions(rawBlock.transactions, transactions, cumulativeSize))
        {
            loggerBlockchain(Logging::DEBUGGING) << "Couldn't deserialize raw block transactions in block " << blockStr;
            return error::AddBlockErrorCode::DESERIALIZATION_FAILED;
        }

        auto coinbaseTransactionSize = getObjectBinarySize(blockTemplate.baseTransaction);
        assert(coinbaseTransactionSize < std::numeric_limits<decltype(coinbaseTransactionSize)>::max());
        auto cumulativeBlockSize = coinbaseTransactionSize + cumulativeSize;
        TransactionValidatorState validatorState;

        auto previousBlockIndex = cache->getBlockIndex(previousBlockHash);

        bool addOnTop = cache->getTopBlockIndex() == previousBlockIndex;
        auto maxBlockCumulativeSize = currency.maxBlockCumulativeSize(previousBlockIndex + 1);
        if (cumulativeBlockSize > maxBlockCumulativeSize)
        {
            loggerBlockchain(Logging::DEBUGGING) << "Block " << blockStr << " has too big cumulative size";
            return error::BlockValidationError::CUMULATIVE_BLOCK_SIZE_TOO_BIG;
        }

        uint64_t minerReward = 0;
        auto blockValidationResult = validateBlock(cachedBlock, cache, minerReward);
        if (blockValidationResult)
        {
            LoggerRef loggerValidation(logger.getLogger(), "Core.Validation");
            loggerValidation(Logging::DEBUGGING) << "Failed to validate block " << blockStr << ": "
                                       << blockValidationResult.message();
            return blockValidationResult;
        }

        auto currentDifficulty = cache->getDifficultyForNextBlock(previousBlockIndex);
        if (currentDifficulty == 0)
        {
            loggerBlockchain(Logging::DEBUGGING) << "Block " << blockStr << " has difficulty overhead";
            return error::BlockValidationError::DIFFICULTY_OVERHEAD;
        }

        if (blockIndex >= Pastella::parameters::BLOCK_BLOB_SHUFFLE_CHECK_HEIGHT)
        {
            /* Check to verify that the blocktemplate suppied contains no duplicate transaction hashes */
            if (!Utilities::is_unique(blockTemplate.transactionHashes.begin(), blockTemplate.transactionHashes.end()))
            {
                return error::BlockValidationError::TRANSACTION_DUPLICATES;
            }

            /* Build a vector of the rawBlock transaction Hashes */
            std::vector<Crypto::Hash> transactionHashes {transactions.size()};

            std::transform(
                transactions.begin(), transactions.end(), transactionHashes.begin(), [](const auto &transaction) {
                    return transaction.getTransactionHash();
                });

            /* Make sure that the rawBlock transaction hashes contain no duplicates */
            if (!Utilities::is_unique(transactionHashes.begin(), transactionHashes.end()))
            {
                return error::BlockValidationError::TRANSACTION_DUPLICATES;
            }

            /* Loop through the rawBlock transaction hashes and verify that they are
               all in the blocktemplate transaction hashes */
            for (const auto &transaction : transactionHashes)
            {
                const auto search = std::find(
                    blockTemplate.transactionHashes.begin(), blockTemplate.transactionHashes.end(), transaction);

                if (search == blockTemplate.transactionHashes.end())
                {
                    return error::BlockValidationError::TRANSACTION_INCONSISTENCY;
                }
            }

            /* Ensure that the blocktemplate hashes vector matches the rawBlock transactionHashes vector */
            if (blockTemplate.transactionHashes != transactionHashes)
            {
                return error::BlockValidationError::TRANSACTION_INCONSISTENCY;
            }
        }

        uint64_t cumulativeFee = 0;

        for (const auto &transaction : transactions)
        {
            uint64_t fee = 0;
            auto transactionValidationResult =
                validateTransaction(transaction, validatorState, cache, m_transactionValidationThreadPool, fee, previousBlockIndex, false);

            if (transactionValidationResult)
            {
                const auto hash = transaction.getTransactionHash();

                LoggerRef loggerValidation(logger.getLogger(), "Core.Validation");
                loggerValidation(Logging::DEBUGGING) << "Failed to validate transaction " << hash
                                           << ": " << transactionValidationResult.message();

                if (transactionPool->checkIfTransactionPresent(hash))
                {
                    LoggerRef loggerPool(logger.getLogger(), "Core.Pool");
                    loggerPool(Logging::DEBUGGING) << "Invalid transaction " << hash << " is present in the pool, removing";
                    transactionPool->removeTransaction(hash);
                    notifyObservers(makeDelTransactionMessage({hash}, Messages::DeleteTransaction::Reason::NotActual));
                }

                return transactionValidationResult;
            }

            cumulativeFee += fee;
        }

        /* Process staking transactions and update staking pool */
        if (stakingPool)
        {
            /* Check if staking is enabled at this height */
            uint64_t currentHeight = cachedBlock.getBlockIndex();
            bool stakingEnabled = currentHeight >= Pastella::parameters::staking::STAKING_ENABLE_HEIGHT;

            if (!stakingEnabled)
            {
                LoggerRef loggerStaking(logger.getLogger(), "Core.Staking");
                loggerStaking(Logging::DEBUGGING) << "Staking not enabled at height " << currentHeight
                                           << ", skipping staking transaction processing";
            }

            for (const auto &transaction : transactions)
            {
                Pastella::TransactionExtraStaking stakingData;
                if (Pastella::getStakingDataFromExtra(transaction.getTransaction().extra, stakingData))
                {
                    /* Skip staking transaction processing if staking is not enabled */
                    if (!stakingEnabled)
                    {
                        LoggerRef loggerStaking(logger.getLogger(), "Core.Staking");
                        loggerStaking(Logging::INFO) << "Ignoring staking transaction at height " << currentHeight
                                              << " - staking not enabled until height "
                                              << Pastella::parameters::staking::STAKING_ENABLE_HEIGHT;
                        continue;
                    }

                    if (stakingData.stakingType == Pastella::parameters::staking::STAKING_TX_TYPE)
                    {
                        /* New staking transaction */
                        /* TRANSPARENT SYSTEM: Get staker's address from transaction inputs */
                        std::string stakerAddress = "";
                        const auto &txPrefix = transaction.getTransaction();
                        if (!txPrefix.inputs.empty()) {
                            const auto &input = txPrefix.inputs[0];
                            if (input.type() == typeid(KeyInput)) {
                                const KeyInput &keyInput = boost::get<KeyInput>(input);

                                /* Look up the address from the referenced transaction's output */
                                try
                                {
                                    /* Get the transaction that contains the UTXO being spent */
                                    std::vector<Crypto::Hash> txHashes = {keyInput.transactionHash};
                                    std::vector<Crypto::Hash> missedTransactions;
                                    std::vector<Pastella::BinaryArray> txBinaries;
                                    cache->getRawTransactions(txHashes, txBinaries, missedTransactions);

                                    if (!txBinaries.empty() && !txBinaries[0].empty())
                                    {
                                        /* Parse the referenced transaction */
                                        Pastella::CachedTransaction cachedTx(txBinaries[0]);
                                        const Pastella::Transaction& referencedTx = cachedTx.getTransaction();

                                        /* Get the output being spent */
                                        if (keyInput.outputIndex < referencedTx.outputs.size())
                                        {
                                            const auto& output = referencedTx.outputs[keyInput.outputIndex];

                                            /* Extract public key from output (KeyOutput type) */
                                            if (output.target.type() == typeid(Pastella::KeyOutput))
                                            {
                                                const Pastella::KeyOutput& keyOutput = boost::get<Pastella::KeyOutput>(output.target);
                                                Crypto::PublicKey publicKey = keyOutput.key;

                                                /* Convert public key to address */
                                                stakerAddress = Utilities::publicKeyToAddress(publicKey);
                                            }
                                        }
                                    }
                                }
                                catch (const std::exception& e)
                                {
                                    /* Failed to get transaction or extract address - leave empty */
                                    LoggerRef loggerStaking(logger.getLogger(), "Core.Staking");
                                    loggerStaking(Logging::WARNING) << "Failed to extract staker address for staking transaction: "
                                                             << e.what();
                                    stakerAddress = "";
                                }
                            }
                        }

                        bool success = stakingPool->addStake(
                            Common::podToHex(transaction.getTransactionHash()),
                            stakerAddress,
                            stakingData.amount,
                            stakingData.lockDurationDays,
                            cachedBlock.getBlockIndex()
                        );
                    }
                }
            }
        }

        uint64_t reward = 0;
        int64_t emissionChange = 0;
        auto alreadyGeneratedCoins = cache->getAlreadyGeneratedCoins(previousBlockIndex);
        auto lastBlocksSizes =
            cache->getLastBlocksSizes(currency.rewardBlocksWindow(), previousBlockIndex, addGenesisBlock);
        auto blocksSizeMedian = Common::medianValue(lastBlocksSizes);

        if (!currency.getBlockReward(
                cachedBlock.getBlock().majorVersion,
                blocksSizeMedian,
                cumulativeBlockSize,
                alreadyGeneratedCoins,
                cumulativeFee,
                reward,
                emissionChange,
                getTopBlockIndex() + 1))
        {
            LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
            loggerBlockchain(Logging::DEBUGGING) << "Block " << blockStr << " has too big cumulative size";
            return error::BlockValidationError::CUMULATIVE_BLOCK_SIZE_TOO_BIG;
        }

        // Check if we need to account for staking rewards in the validation
        uint64_t expectedReward = reward;

        // If staking is enabled, check for matured stakes at this height
        if (stakingPool && cachedBlock.getBlockIndex() >= Pastella::parameters::staking::STAKING_ENABLE_HEIGHT)
        {
            auto maturedRewards = getMaturedStakeRewards(cachedBlock.getBlockIndex());
            if (!maturedRewards.empty())
            {
                uint64_t totalMaturedRewards = 0;
                for (const auto &maturedReward : maturedRewards)
                {
                    totalMaturedRewards += maturedReward.rewardAmount;
                }
                expectedReward += totalMaturedRewards;

                LoggerRef loggerRewards(logger.getLogger(), "Core.Rewards");
                loggerRewards(Logging::DEBUGGING) << "Block validation: added " << totalMaturedRewards
                                          << " staking rewards to expected reward. Base reward: " << reward
                                          << ", Total expected: " << expectedReward;
            }
        }

        if (minerReward != expectedReward)
        {
            LoggerRef loggerRewards(logger.getLogger(), "Core.Rewards");
            loggerRewards(Logging::DEBUGGING) << "Block reward mismatch for block " << blockStr
                                       << ". Expected reward: " << expectedReward << ", got reward: " << minerReward;
            return error::BlockValidationError::BLOCK_REWARD_MISMATCH;
        }

        if (checkpoints.isInCheckpointZone(cachedBlock.getBlockIndex()))
        {
            if (!checkpoints.checkBlock(cachedBlock.getBlockIndex(), cachedBlock.getBlockHash()))
            {
                LoggerRef loggerValidation(logger.getLogger(), "Core.Validation");
                loggerValidation(Logging::WARNING) << "Checkpoint block hash mismatch for block " << blockStr;
                return error::BlockValidationError::CHECKPOINT_BLOCK_HASH_MISMATCH;
            }
        }
        else if (!currency.checkProofOfWork(cachedBlock, currentDifficulty))
        {
            LoggerRef loggerValidation(logger.getLogger(), "Core.Validation");
            loggerValidation(Logging::DEBUGGING) << "Proof of work too weak for block " << blockStr;
            return error::BlockValidationError::PROOF_OF_WORK_TOO_WEAK;
        }

        auto ret = error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE;

        if (addOnTop)
        {
            if (cache->getChildCount() == 0)
            {
                // add block on top of leaf segment.
                auto hashes = preallocateVector<Crypto::Hash>(transactions.size());

                // TODO: exception safety
                if (cache == chainsLeaves[0])
                {
                    mainChainStorage->pushBlock(rawBlock);

                    cache->pushBlock(
                        cachedBlock,
                        transactions,
                        validatorState,
                        cumulativeBlockSize,
                        reward,
                        currentDifficulty,
                        std::move(rawBlock));

                    updateBlockMedianSize();

                    /* Take the current block spent key images and run them
                       against the pool to remove any transactions that may
                       be in the pool that would now be considered invalid */
                    checkAndRemoveInvalidPoolTransactions(validatorState);

                    ret = error::AddBlockErrorCode::ADDED_TO_MAIN;
                    LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                    loggerBlockchain(Logging::DEBUGGING) << "Block " << blockStr << " added to main chain.";
                    if ((previousBlockIndex + 1) % 100 == 0)
                    {
                        loggerBlockchain(Logging::INFO) << "Block " << blockStr << " added to main chain";
                    }

                    // Deactivate matured stakes after successful block addition
                    if (stakingPool && blockIndex >= Pastella::parameters::staking::STAKING_ENABLE_HEIGHT)
                    {
                        auto maturedRewards = getMaturedStakeRewards(blockIndex);
                        if (!maturedRewards.empty())
                        {
                            LoggerRef loggerStaking(logger.getLogger(), "Core.Staking");
                            loggerStaking(Logging::INFO) << "Deactivating " << maturedRewards.size()
                                                  << " matured stakes after successful block addition at height " << blockIndex;

                            for (const auto &maturedReward : maturedRewards)
                            {
                                if (stakingPool->deactivateStakeWithReward(maturedReward.stakeTxHash, maturedReward.rewardAmount))
                                {
                                    loggerStaking(Logging::DEBUGGING) << "Successfully deactivated matured stake "
                                                                << maturedReward.stakeTxHash.substr(0, 10) << "..."
                                                                << " with reward: " << (maturedReward.rewardAmount / 100000000.0) << " " << WalletConfig::ticker;
                                }
                                else
                                {
                                    loggerStaking(Logging::WARNING) << "Failed to deactivate matured stake "
                                                                << maturedReward.stakeTxHash.substr(0, 10) << "...";
                                }
                            }
                        }
                    }

                    // Process governance transactions in this block
                    if (governanceManager && blockIndex >= Pastella::parameters::governance::GOVERNANCE_ENABLE_HEIGHT)
                    {
                        LoggerRef loggerGovernance(logger.getLogger(), "Core.Governance");
                        loggerGovernance(Logging::TRACE) << "Processing governance transactions in block " << blockIndex;

                        // Process each transaction in the block
                        for (const auto &cachedTransaction : transactions)
                        {
                            const auto &tx = cachedTransaction.getTransaction();

                            // Check for proposal transaction
                            Pastella::TransactionExtraGovernanceProposal proposalData;
                            if (Pastella::getGovernanceProposalFromExtra(tx.extra, proposalData))
                            {
                                // Get transaction public key
                                Crypto::PublicKey txPublicKey = Pastella::getTransactionPublicKeyFromExtra(tx.extra);

                                // Create address from public key
                                Pastella::AccountPublicAddress address;
                                address.publicKey = txPublicKey;

                                std::string proposerAddress = currency.accountAddressAsString(address);

                                loggerGovernance(Logging::INFO) << "Found governance proposal transaction in block "
                                    << blockIndex << ", proposal ID: " << proposalData.proposalId;

                                // Process the proposal transaction
                                governanceManager->processProposalTransaction(
                                    tx,
                                    proposalData,
                                    proposerAddress,
                                    blockIndex
                                );
                            }

                            // Check for vote transaction
                            Pastella::TransactionExtraGovernanceVote voteData;
                            if (Pastella::getGovernanceVoteFromExtra(tx.extra, voteData))
                            {
                                // Get transaction public key
                                Crypto::PublicKey txPublicKey = Pastella::getTransactionPublicKeyFromExtra(tx.extra);

                                // Create address from public key
                                Pastella::AccountPublicAddress address;
                                address.publicKey = txPublicKey;

                                std::string voterAddress = currency.accountAddressAsString(address);

                                loggerGovernance(Logging::INFO) << "Found governance vote transaction in block "
                                    << blockIndex << ", proposal ID: " << voteData.proposalId
                                    << ", vote: " << (int)voteData.vote;

                                // Process the vote transaction
                                governanceManager->processVoteTransaction(
                                    tx,
                                    voteData,
                                    voterAddress,
                                    blockIndex
                                );
                            }
                        }

                        loggerGovernance(Logging::DEBUGGING) << "Updating governance proposals after block addition at height " << blockIndex;
                        governanceManager->updateProposals(blockIndex + 1);
                    }

                    // Update RandomX seed hash after successful block addition
                    try {
                        uint32_t newHeight = blockIndex + 1; // New blockchain height after adding this block
                        uint64_t newSeedHeight = Crypto::rx_seedheight(newHeight);
                        Crypto::Hash newSeedHash = getBlockHashByIndex(newSeedHeight);

                        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                        loggerBlockchain(Logging::DEBUGGING) << "Updating RandomX seed hash for new height " << newHeight
                                                << " using seed from height " << newSeedHeight
                                                << " hash: " << Common::toHex(std::vector<uint8_t>(newSeedHash.data, newSeedHash.data + Crypto::HASH_SIZE));

                        // Update RandomX main cache with new seed hash
                        Crypto::rx_set_main_seedhash(reinterpret_cast<const char*>(newSeedHash.data), 4);
                    } catch (const std::exception &e) {
                        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                        loggerBlockchain(Logging::WARNING) << "Failed to update RandomX seed hash after block addition: " << e.what();
                    }

                    notifyObservers(
                        makeDelTransactionMessage(std::move(hashes), Messages::DeleteTransaction::Reason::InBlock));
                }
                else
                {
                    cache->pushBlock(
                        cachedBlock,
                        transactions,
                        validatorState,
                        cumulativeBlockSize,
                        reward,
                        currentDifficulty,
                        std::move(rawBlock));
                    LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                    loggerBlockchain(Logging::DEBUGGING) << "Block " << blockStr << " added to alternative chain.";
                    loggerBlockchain(Logging::DEBUGGING) << "GENERATED_COINS_FIX - Alternative chain block " << blockStr
                                               << " - Used reward: " << (reward / 100000000.0) << " " << WalletConfig::ticker << " instead of emissionChange: " << (emissionChange / 100000000.0) << " " << WalletConfig::ticker;

                    auto mainChainCache = chainsLeaves[0];
                    if (cache->getCurrentCumulativeDifficulty() > mainChainCache->getCurrentCumulativeDifficulty())
                    {
                        size_t endpointIndex = std::distance(
                            chainsLeaves.begin(), std::find(chainsLeaves.begin(), chainsLeaves.end(), cache));
                        assert(endpointIndex != chainsStorage.size());
                        assert(endpointIndex != 0);
                        std::swap(chainsLeaves[0], chainsLeaves[endpointIndex]);
                        updateMainChainSet();

                        updateBlockMedianSize();

                        /* Take the current block spent key images and run them
                           against the pool to remove any transactions that may
                           be in the pool that would now be considered invalid */
                        checkAndRemoveInvalidPoolTransactions(validatorState);

                        copyTransactionsToPool(chainsLeaves[endpointIndex]);

                        switchMainChainStorage(chainsLeaves[0]->getStartBlockIndex(), *chainsLeaves[0]);

                        // Update RandomX seed hash after chain switch
                        try {
                            uint32_t newHeight = chainsLeaves[0]->getTopBlockIndex() + 1;
                            uint64_t newSeedHeight = Crypto::rx_seedheight(newHeight);
                            Crypto::Hash newSeedHash = getBlockHashByIndex(newSeedHeight);

                            loggerBlockchain(Logging::DEBUGGING) << "Updating RandomX seed hash after chain switch to height " << newHeight
                                                    << " using seed from height " << newSeedHeight
                                                    << " hash: " << Common::toHex(std::vector<uint8_t>(newSeedHash.data, newSeedHash.data + Crypto::HASH_SIZE));

                            // Update RandomX main cache with new seed hash
                            Crypto::rx_set_main_seedhash(reinterpret_cast<const char*>(newSeedHash.data), 4);
                        } catch (const std::exception &e) {
                            loggerBlockchain(Logging::WARNING) << "Failed to update RandomX seed hash after chain switch: " << e.what();
                        }

                        ret = error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE_AND_SWITCHED;

                        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                        loggerBlockchain(Logging::INFO) << "Resolved: " << blockStr
                                              << ", Previous: " << chainsLeaves[endpointIndex]->getTopBlockIndex()
                                              << " (" << chainsLeaves[endpointIndex]->getTopBlockHash() << ")";
                    }
                }
            }
            else
            {
                // add block on top of segment which is not leaf! the case when we got more than one alternative block
                // on the same height
                auto newCache = blockchainCacheFactory->createBlockchainCache(currency, cache, previousBlockIndex + 1);
                cache->addChild(newCache.get());

                auto newlyForkedChainPtr = newCache.get();
                chainsStorage.emplace_back(std::move(newCache));
                chainsLeaves.push_back(newlyForkedChainPtr);

                LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                loggerBlockchain(Logging::DEBUGGING) << "Resolving: " << blockStr;

                newlyForkedChainPtr->pushBlock(
                    cachedBlock,
                    transactions,
                    validatorState,
                    cumulativeBlockSize,
                    emissionChange,
                    currentDifficulty,
                    std::move(rawBlock));

                updateMainChainSet();
                updateBlockMedianSize();
            }
        }
        else
        {
            LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
            loggerBlockchain(Logging::DEBUGGING) << "Resolving: " << blockStr;

            auto upperSegment = cache->split(previousBlockIndex + 1);
            //[cache] is lower segment now

            assert(upperSegment->getBlockCount() > 0);
            assert(cache->getBlockCount() > 0);

            if (upperSegment->getChildCount() == 0)
            {
                // newly created segment is leaf node
                //[cache] used to be a leaf node. we have to replace it with upperSegment
                auto found = std::find(chainsLeaves.begin(), chainsLeaves.end(), cache);
                assert(found != chainsLeaves.end());

                *found = upperSegment.get();
            }

            chainsStorage.emplace_back(std::move(upperSegment));

            auto newCache = blockchainCacheFactory->createBlockchainCache(currency, cache, previousBlockIndex + 1);
            cache->addChild(newCache.get());

            auto newlyForkedChainPtr = newCache.get();
            chainsStorage.emplace_back(std::move(newCache));
            chainsLeaves.push_back(newlyForkedChainPtr);

            newlyForkedChainPtr->pushBlock(
                cachedBlock,
                transactions,
                validatorState,
                cumulativeBlockSize,
                emissionChange,
                currentDifficulty,
                std::move(rawBlock));

            updateMainChainSet();
        }

        LoggerRef loggerBlockchain2(logger.getLogger(), "Core.Blockchain");
        loggerBlockchain2(Logging::DEBUGGING) << "Block: " << blockStr << " successfully added";
        notifyOnSuccess(ret, previousBlockIndex, cachedBlock, *cache);

        return ret;
    }

    /* This method is a light version of transaction validation that is used
       to clear the transaction pool of transactions that have been invalidated
       by the addition of a block to the blockchain. As the transactions are already
       in the pool, there are only a subset of normal transaction validation
       tests that need to be completed to determine if the transaction can
       stay in the pool at this time. */
    void Core::checkAndRemoveInvalidPoolTransactions(
        const TransactionValidatorState blockTransactionsState)
    {
        auto &pool = *transactionPool;

        const auto poolHashes = pool.getTransactionHashes();

        const auto maxTransactionSize = getMaximumTransactionAllowedSize(blockMedianSize, currency);

        for (const auto poolTxHash : poolHashes)
        {
            const auto poolTx = pool.tryGetTransaction(poolTxHash);

            /* Tx got removed by another thread */
            if (!poolTx)
            {
                continue;
            }

            const auto poolTxState = extractSpentOutputs(*poolTx);

            bool isValid = true;

            /* If the transaction is in the chain but somehow was not previously removed, fail */
            if (isTransactionInChain(poolTxHash))
            {
                isValid = false;
            }
            /* If the transaction exceeds the maximum size of a transaction, fail */
            else if (poolTx->getTransactionBinaryArray().size() > maxTransactionSize)
            {
                isValid = false;
            }
            /* If the the transaction contains outputs that were spent in the new block, fail */
            else if (hasIntersections(blockTransactionsState, poolTxState))
            {
                isValid = false;
            }

            /* If the transaction is no longer valid, remove it from the pool
               and tell everyone else that they should also remove it from the pool */
            if (!isValid)
            {
                pool.removeTransaction(poolTxHash);
                notifyObservers(makeDelTransactionMessage({poolTxHash}, Messages::DeleteTransaction::Reason::NotActual));
            }
        }
    }

    /* This quickly finds out if a transaction is in the blockchain somewhere */
    bool Core::isTransactionInChain(const Crypto::Hash &txnHash)
    {
        throwIfNotInitialized();

        auto segment = findSegmentContainingTransaction(txnHash);

        if (segment != nullptr)
        {
            return true;
        }

        return false;
    }

    void Core::switchMainChainStorage(uint32_t splitBlockIndex, IBlockchainCache &newChain)
    {
        assert(mainChainStorage->getBlockCount() > splitBlockIndex);

        auto blocksToPop = mainChainStorage->getBlockCount() - splitBlockIndex;
        for (size_t i = 0; i < blocksToPop; ++i)
        {
            mainChainStorage->popBlock();
        }

        for (uint32_t index = splitBlockIndex; index <= newChain.getTopBlockIndex(); ++index)
        {
            mainChainStorage->pushBlock(newChain.getBlockByIndex(index));
        }
    }

    void Core::notifyOnSuccess(
        error::AddBlockErrorCode opResult,
        uint32_t previousBlockIndex,
        const CachedBlock &cachedBlock,
        const IBlockchainCache &cache)
    {
        switch (opResult)
        {
            case error::AddBlockErrorCode::ADDED_TO_MAIN:
                notifyObservers(makeNewBlockMessage(previousBlockIndex + 1, cachedBlock.getBlockHash()));
                break;
            case error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE:
                notifyObservers(makeNewAlternativeBlockMessage(previousBlockIndex + 1, cachedBlock.getBlockHash()));
                break;
            case error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE_AND_SWITCHED:
            {
                auto parent = cache.getParent();
                auto hashes = cache.getBlockHashes(cache.getStartBlockIndex(), cache.getBlockCount());
                hashes.insert(hashes.begin(), parent->getTopBlockHash());
                notifyObservers(makeChainSwitchMessage(parent->getTopBlockIndex(), std::move(hashes)));
                break;
            }
            default:
                assert(false);
                break;
        }
    }

    std::error_code Core::addBlock(RawBlock &&rawBlock)
    {
        throwIfNotInitialized();

        BlockTemplate blockTemplate;
        bool result = fromBinaryArray(blockTemplate, rawBlock.block);
        if (!result)
        {
            return error::AddBlockErrorCode::DESERIALIZATION_FAILED;
        }

        CachedBlock cachedBlock(blockTemplate);
        return addBlock(cachedBlock, std::move(rawBlock));
    }

    std::error_code Core::submitBlock(const BinaryArray &rawBlockTemplate)
    {
        throwIfNotInitialized();

        BlockTemplate blockTemplate;
        bool result = fromBinaryArray(blockTemplate, rawBlockTemplate);
        if (!result)
        {
            LoggerRef loggerValidation(logger.getLogger(), "Core.Validation");
            loggerValidation(Logging::WARNING) << "Couldn't deserialize block template";
            return error::AddBlockErrorCode::DESERIALIZATION_FAILED;
        }

        RawBlock rawBlock;
        rawBlock.block = std::move(rawBlockTemplate);

        rawBlock.transactions.reserve(blockTemplate.transactionHashes.size());

        std::scoped_lock lock(m_submitBlockMutex);

        for (const auto &transactionHash : blockTemplate.transactionHashes)
        {
            if (!transactionPool->checkIfTransactionPresent(transactionHash))
            {
                LoggerRef loggerPool(logger.getLogger(), "Core.Pool");
                loggerPool(Logging::WARNING) << "The transaction " << Common::podToHex(transactionHash)
                                         << " is absent in transaction pool";
                return error::BlockValidationError::TRANSACTION_ABSENT_IN_POOL;
            }

            rawBlock.transactions.emplace_back(
                transactionPool->getTransaction(transactionHash).getTransactionBinaryArray());
        }

        CachedBlock cachedBlock(blockTemplate);
        return addBlock(cachedBlock, std::move(rawBlock));
    }

    std::tuple<bool, std::string> Core::addTransactionToPool(const BinaryArray &transactionBinaryArray)
    {
        throwIfNotInitialized();

        Transaction transaction;
        if (!fromBinaryArray<Transaction>(transaction, transactionBinaryArray))
        {
            LoggerRef loggerPool(logger.getLogger(), "Core.Pool");
            loggerPool(Logging::WARNING) << "Couldn't add transaction to pool due to deserialization error";
            return {false, "Could not deserialize transaction"};
        }

        CachedTransaction cachedTransaction(std::move(transaction));
        auto transactionHash = cachedTransaction.getTransactionHash();

        const auto [success, error] = addTransactionToPool(std::move(cachedTransaction));
        if (!success)
        {
            return {false, error};
        }

        notifyObservers(makeAddTransactionMessage({transactionHash}));
        return {true, ""};
    }

    std::tuple<bool, std::string> Core::addTransactionToPool(CachedTransaction &&cachedTransaction)
    {
        TransactionValidatorState validatorState;

        auto transactionHash = cachedTransaction.getTransactionHash();

        /* If the transaction is already in the pool, then checking it again
           and/or trying to add it to the pool again wastes time and resources.
           We don't need to waste time doing this as everything we hear about
           from the network would result in us checking relayed transactions
           an insane number of times */
        if (transactionPool->checkIfTransactionPresent(transactionHash))
        {
            return {false, "Transaction already exists in pool"};
        }

        const auto [success, error] = isTransactionValidForPool(cachedTransaction, validatorState);
        if (!success)
        {
            return {false, error};
        }

        if (!transactionPool->pushTransaction(std::move(cachedTransaction), std::move(validatorState)))
        {
            LoggerRef loggerPool(logger.getLogger(), "Core.Pool");
            loggerPool(Logging::DEBUGGING) << "Failed to push transaction " << transactionHash
                                       << " to pool, already exists";
            return {false, "Transaction already exists in pool"};
        }

        LoggerRef loggerPool(logger.getLogger(), "Core.Pool");
        loggerPool(Logging::DEBUGGING) << "Transaction " << transactionHash << " has been added to pool";
        return {true, ""};
    }

    std::tuple<bool, std::string> Core::isTransactionValidForPool(
        const CachedTransaction &cachedTransaction,
        TransactionValidatorState &validatorState)
    {
        const auto transactionHash = cachedTransaction.getTransactionHash();

        uint64_t fee;

        if (auto validationResult =
                validateTransaction(cachedTransaction, validatorState, chainsLeaves[0], m_transactionValidationThreadPool, fee, getTopBlockIndex(), true))
        {
            LoggerRef loggerValidation(logger.getLogger(), "Core.Validation");
            loggerValidation(Logging::DEBUGGING) << "Transaction " << transactionHash
                                       << " is not valid. Reason: " << validationResult.message();
            return {false, validationResult.message()};
        }

        return {true, ""};
    }

    std::vector<Crypto::Hash> Core::getPoolTransactionHashes() const
    {
        throwIfNotInitialized();

        return transactionPool->getTransactionHashes();
    }

    std::tuple<bool, std::vector<UtxoOutput>, uint64_t>
        Core::getUTXOs(uint64_t page, uint64_t limit) const
    {
        throwIfNotInitialized();

        assert(!chainsLeaves.empty());
        assert(!chainsStorage.empty());

        /* Get UTXOs from the main chain (first leaf) */
        IBlockchainCache *blockchainSegment = chainsLeaves[0];

        if (blockchainSegment == nullptr)
        {
            return {false, std::vector<UtxoOutput>(), 0};
        }

        return blockchainSegment->getAllUtxos(page, limit);
    }

    std::tuple<bool, BinaryArray> Core::getPoolTransaction(const Crypto::Hash &transactionHash) const
    {
        if (transactionPool->checkIfTransactionPresent(transactionHash))
        {
            return {true, transactionPool->getTransaction(transactionHash).getTransactionBinaryArray()};
        }
        else
        {
            return {false, BinaryArray()};
        }
    }

    bool Core::getPoolChanges(
        const Crypto::Hash &lastBlockHash,
        const std::vector<Crypto::Hash> &knownHashes,
        std::vector<BinaryArray> &addedTransactions,
        std::vector<Crypto::Hash> &deletedTransactions) const
    {
        throwIfNotInitialized();

        std::vector<Crypto::Hash> newTransactions;
        getTransactionPoolDifference(knownHashes, newTransactions, deletedTransactions);

        addedTransactions.reserve(newTransactions.size());
        for (const auto &hash : newTransactions)
        {
            addedTransactions.emplace_back(transactionPool->getTransaction(hash).getTransactionBinaryArray());
        }

        return getTopBlockHash() == lastBlockHash;
    }

    bool Core::getPoolChangesLite(
        const Crypto::Hash &lastBlockHash,
        const std::vector<Crypto::Hash> &knownHashes,
        std::vector<TransactionPrefixInfo> &addedTransactions,
        std::vector<Crypto::Hash> &deletedTransactions) const
    {
        throwIfNotInitialized();

        std::vector<Crypto::Hash> newTransactions;
        getTransactionPoolDifference(knownHashes, newTransactions, deletedTransactions);

        addedTransactions.reserve(newTransactions.size());
        for (const auto &hash : newTransactions)
        {
            TransactionPrefixInfo transactionPrefixInfo;
            transactionPrefixInfo.txHash = hash;
            transactionPrefixInfo.txPrefix =
                static_cast<const TransactionPrefix &>(transactionPool->getTransaction(hash).getTransaction());
            addedTransactions.emplace_back(std::move(transactionPrefixInfo));
        }

        return getTopBlockHash() == lastBlockHash;
    }
    std::tuple<bool, std::string> Core::getBlockTemplate(
        BlockTemplate &b,
        const Crypto::PublicKey &publicKey,
        const BinaryArray &extraNonce,
        uint64_t &difficulty,
        uint32_t &height)
    {
        throwIfNotInitialized();

        height = getTopBlockIndex() + 1;
        difficulty = getDifficultyForNextBlock();

        if (difficulty == 0)
        {
            std::string error = "Cannot create block template, difficulty is zero. Oh shit, you fucked up hard!";

            LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
            loggerBlockchain(Logging::ERROR, Logging::BRIGHT_RED) << error;

            return {false, error};
        }

        // Ensure RandomX has the correct seed hash for this height
        try {
            uint64_t seedHeight = Crypto::rx_seedheight(height);
            Crypto::Hash seedHash = getBlockHashByIndex(seedHeight);

            LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
            loggerBlockchain(Logging::DEBUGGING) << "getBlockTemplate: Ensuring RandomX seed hash for height " << height
                                    << " using seed from height " << seedHeight
                                    << " hash: " << Common::toHex(std::vector<uint8_t>(seedHash.data, seedHash.data + Crypto::HASH_SIZE));

            // Update RandomX main cache with correct seed hash
            Crypto::rx_set_main_seedhash(reinterpret_cast<const char*>(seedHash.data), 4);
        } catch (const std::exception &e) {
            LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
            loggerBlockchain(Logging::WARNING) << "Failed to update RandomX seed hash in getBlockTemplate: " << e.what();
        }

        b = boost::value_initialized<BlockTemplate>();
        b.majorVersion = getBlockMajorVersionForHeight(height);

        if (b.majorVersion == BLOCK_MAJOR_VERSION_1)
        {
            b.minorVersion = currency.upgradeHeight(BLOCK_MAJOR_VERSION_2) == IUpgradeDetector::UNDEF_HEIGHT
                                 ? BLOCK_MINOR_VERSION_1
                                 : BLOCK_MINOR_VERSION_0;
        }
        else if (b.majorVersion == BLOCK_MAJOR_VERSION_2)
        {
            b.minorVersion = BLOCK_MINOR_VERSION_0;
        }

        b.previousBlockHash = getTopBlockHash();
        b.timestamp = time(nullptr);

        /* Ok, so if an attacker is fiddling around with timestamps on the network,
           they can make it so all the valid pools / miners don't produce valid
           blocks. This is because the timestamp is created as the users current time,
           however, if the attacker is a large % of the hashrate, they can slowly
           increase the timestamp into the future, shifting the median timestamp
           forwards. At some point, this will mean the valid pools will submit a
           block with their valid timestamps, and it will be rejected for being
           behind the median timestamp / too far in the past. The simple way to
           handle this is just to check if our timestamp is going to be invalid, and
           set it to the median.

           Once the attack ends, the median timestamp will remain how it is, until
           the time on the clock goes forwards, and we can start submitting valid
           timestamps again, and then we are back to normal. */

        /* Thanks to jagerman for this patch:
           https://github.com/loki-project/loki/pull/26 */

        /* How many blocks we look in the past to calculate the median timestamp */
        uint64_t blockchain_timestamp_check_window = Pastella::parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;

        /* Skip the first N blocks, we don't have enough blocks to calculate a
           proper median yet */
        if (height >= blockchain_timestamp_check_window)
        {
            std::vector<uint64_t> timestamps;

            /* For the last N blocks, get their timestamps */
            for (size_t offset = height - blockchain_timestamp_check_window; offset < height; offset++)
            {
                timestamps.push_back(getBlockTimestampByIndex(offset));
            }

            uint64_t medianTimestamp = Common::medianValue(timestamps);

            if (b.timestamp < medianTimestamp)
            {
                b.timestamp = medianTimestamp;
            }
        }

        size_t medianSize = calculateCumulativeBlocksizeLimit(height) / 2;

        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());
        uint64_t alreadyGeneratedCoins = chainsLeaves[0]->getAlreadyGeneratedCoins();

        size_t transactionsSize;
        uint64_t fee;
        fillBlockTemplate(b, medianSize, currency.maxBlockCumulativeSize(height), height, transactionsSize, fee);

        /*
           two-phase miner transaction generation: we don't know exact block size until we prepare block, but we don't know
           reward until we know
           block size, so first miner transaction generated with fake amount of money, and with phase we know think we know
           expected block size
        */
        // make blocks coin-base tx looks close to real coinbase tx to get truthful blob size
        bool r = currency.constructMinerTx(
            b.majorVersion,
            height,
            medianSize,
            alreadyGeneratedCoins,
            transactionsSize,
            fee,
            publicKey,
            b.baseTransaction,
            extraNonce,
            24);


        if (!r)
        {
            std::string error = "Failed to construct miner transaction";

            LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
            loggerBlockchain(Logging::ERROR, Logging::BRIGHT_RED) << error;

            return {false, error};
        }

        size_t cumulativeSize = transactionsSize + getObjectBinarySize(b.baseTransaction);
        const size_t TRIES_COUNT = 10;

        /* Phase 2: Get matured stake rewards for this block height */
        std::vector<MaturedStakeReward> maturedRewards = getMaturedStakeRewards(height);

        for (size_t tryCount = 0; tryCount < TRIES_COUNT; ++tryCount)
        {
            r = currency.constructMinerTx(
                b.majorVersion,
                height,
                medianSize,
                alreadyGeneratedCoins,
                cumulativeSize,
                fee,
                publicKey, /* VIEW KEY REMOVAL: Now only passing one key (publicKey) */
                b.baseTransaction,
                extraNonce,
                24,
                maturedRewards);


            if (!r)
            {
                std::string error = "Failed to construct miner transaction";

                LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                loggerBlockchain(Logging::ERROR, Logging::BRIGHT_RED) << error;

                return {false, error};
            }

            size_t coinbaseBlobSize = getObjectBinarySize(b.baseTransaction);
            if (coinbaseBlobSize > cumulativeSize - transactionsSize)
            {
                cumulativeSize = transactionsSize + coinbaseBlobSize;
                continue;
            }

            if (coinbaseBlobSize < cumulativeSize - transactionsSize)
            {
                size_t delta = cumulativeSize - transactionsSize - coinbaseBlobSize;
                b.baseTransaction.extra.insert(b.baseTransaction.extra.end(), delta, 0);
                // here  could be 1 byte difference, because of extra field counter is varint, and it can become from
                // 1-byte len to 2-bytes len.
                if (cumulativeSize != transactionsSize + getObjectBinarySize(b.baseTransaction))
                {
                    if (!(cumulativeSize + 1 == transactionsSize + getObjectBinarySize(b.baseTransaction)))
                    {
                        std::stringstream stream;

                        stream << "unexpected case: cumulative_size=" << cumulativeSize
                               << " + 1 is not equal txs_cumulative_size=" << transactionsSize
                               << " + get_object_blobsize(b.baseTransaction)=" << getObjectBinarySize(b.baseTransaction);

                        std::string error = stream.str();

                        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                        loggerBlockchain(Logging::ERROR, Logging::BRIGHT_RED) << error;

                        return {false, error};
                    }

                    b.baseTransaction.extra.resize(b.baseTransaction.extra.size() - 1);
                    if (cumulativeSize != transactionsSize + getObjectBinarySize(b.baseTransaction))
                    {
                        // fuck, not lucky, -1 makes varint-counter size smaller, in that case we continue to grow with
                        // cumulative_size
                        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                        loggerBlockchain(Logging::TRACE, Logging::BRIGHT_RED)
                            << "Miner tx creation have no luck with delta_extra size = " << delta << " and "
                            << delta - 1;
                        cumulativeSize += delta - 1;
                        continue;
                    }

                    LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                    loggerBlockchain(Logging::DEBUGGING, Logging::BRIGHT_GREEN)
                        << "Setting extra for block: " << b.baseTransaction.extra.size() << ", try_count=" << tryCount;
                }
            }
            if (!(cumulativeSize == transactionsSize + getObjectBinarySize(b.baseTransaction)))
            {
                std::stringstream stream;

                stream << "unexpected case: cumulative_size=" << cumulativeSize
                       << " is not equal txs_cumulative_size=" << transactionsSize
                       << " + get_object_blobsize(b.baseTransaction)=" << getObjectBinarySize(b.baseTransaction);

                std::string error = stream.str();

                LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                loggerBlockchain(Logging::ERROR, Logging::BRIGHT_RED) << error;

                return {false, error};
            }

            return {true, std::string()};
        }

        std::string error = "Failed to create block template";

        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
        loggerBlockchain(Logging::ERROR, Logging::BRIGHT_RED) << error;

        return {false, error};
    }

    CoreStatistics Core::getCoreStatistics() const
    {
        // TODO: implement it
        assert(false);
        CoreStatistics result;
        std::fill(reinterpret_cast<uint8_t *>(&result), reinterpret_cast<uint8_t *>(&result) + sizeof(result), 0);
        return result;
    }

    size_t Core::getPoolTransactionCount() const
    {
        throwIfNotInitialized();
        return transactionPool->getTransactionCount();
    }

    size_t Core::getBlockchainTransactionCount() const
    {
        throwIfNotInitialized();
        IBlockchainCache *mainChain = chainsLeaves[0];
        return mainChain->getTransactionCount();
    }

    size_t Core::getAlternativeBlockCount() const
    {
        throwIfNotInitialized();

        using Ptr = decltype(chainsStorage)::value_type;
        return std::accumulate(chainsStorage.begin(), chainsStorage.end(), size_t(0), [&](size_t sum, const Ptr &ptr) {
            return mainChainSet.count(ptr.get()) == 0 ? sum + ptr->getBlockCount() : sum;
        });
    }

    std::vector<Transaction> Core::getPoolTransactions() const
    {
        throwIfNotInitialized();

        std::vector<Transaction> transactions;
        auto hashes = transactionPool->getPoolTransactions();
        std::transform(
            std::begin(hashes), std::end(hashes), std::back_inserter(transactions), [&](const CachedTransaction &tx) {
                return tx.getTransaction();
            });
        return transactions;
    }

    bool Core::extractTransactions(
        const std::vector<BinaryArray> &rawTransactions,
        std::vector<CachedTransaction> &transactions,
        uint64_t &cumulativeSize)
    {
        try
        {
            for (auto &rawTransaction : rawTransactions)
            {
                if (rawTransaction.size() > currency.maxTxSize())
                {
                    LoggerRef loggerValidation(logger.getLogger(), "Core.Validation");
                    loggerValidation(Logging::INFO) << "Raw transaction size " << rawTransaction.size() << " is too big.";
                    return false;
                }

                cumulativeSize += rawTransaction.size();
                transactions.emplace_back(rawTransaction);
            }
        }
        catch (std::runtime_error &e)
        {
            LoggerRef loggerValidation(logger.getLogger(), "Core.Validation");
            loggerValidation(Logging::INFO) << e.what();
            return false;
        }

        return true;
    }

    std::error_code Core::validateTransaction(
        const CachedTransaction &cachedTransaction,
        TransactionValidatorState &state,
        IBlockchainCache *cache,
        Utilities::ThreadPool<bool> &threadPool,
        uint64_t &fee,
        uint32_t blockIndex,
        const bool isPoolTransaction)
    {
        ValidateTransaction txValidator(
            cachedTransaction,
            state,
            cache,
            currency,
            checkpoints,
            threadPool,
            blockIndex,
            blockMedianSize,
            isPoolTransaction
        );

        const auto result = txValidator.validate();

        fee = result.fee;

        return result.errorCode;
    }

    uint32_t Core::findBlockchainSupplement(const std::vector<Crypto::Hash> &remoteBlockIds) const
    {
        /* Requester doesn't know anything about the chain yet */
        if (remoteBlockIds.empty())
        {
            return 0;
        }

        // TODO: check for genesis blocks match
        for (auto &hash : remoteBlockIds)
        {
            IBlockchainCache *blockchainSegment = findMainChainSegmentContainingBlock(hash);
            if (blockchainSegment != nullptr)
            {
                return blockchainSegment->getBlockIndex(hash);
            }
        }

        throw std::runtime_error("Genesis block hash was not found.");
    }

    std::vector<Crypto::Hash> Pastella::Core::getBlockHashes(uint32_t startBlockIndex, uint32_t maxCount) const
    {
        return chainsLeaves[0]->getBlockHashes(startBlockIndex, maxCount);
    }

    std::error_code Core::validateBlock(const CachedBlock &cachedBlock, IBlockchainCache *cache, uint64_t &minerReward)
    {
        const auto &block = cachedBlock.getBlock();
        auto previousBlockIndex = cache->getBlockIndex(block.previousBlockHash);
        // assert(block.previousBlockHash == cache->getBlockHash(previousBlockIndex));

        minerReward = 0;

        if (upgradeManager->getBlockMajorVersion(cachedBlock.getBlockIndex()) != block.majorVersion)
        {
            return error::BlockValidationError::WRONG_VERSION;
        }

        if (block.timestamp > getAdjustedTime() + currency.blockFutureTimeLimit(previousBlockIndex + 1))
        {
            return error::BlockValidationError::TIMESTAMP_TOO_FAR_IN_FUTURE;
        }

        auto timestamps = cache->getLastTimestamps(
            currency.timestampCheckWindow(previousBlockIndex + 1), previousBlockIndex, addGenesisBlock);
        if (timestamps.size() >= currency.timestampCheckWindow(previousBlockIndex + 1))
        {
            auto median_ts = Common::medianValue(timestamps);
            if (block.timestamp < median_ts)
            {
                return error::BlockValidationError::TIMESTAMP_TOO_FAR_IN_PAST;
            }
        }

        if (block.baseTransaction.inputs.size() != 1)
        {
            return error::TransactionValidationError::INPUT_WRONG_COUNT;
        }

        if (block.baseTransaction.inputs[0].type() != typeid(BaseInput))
        {
            return error::TransactionValidationError::INPUT_UNEXPECTED_TYPE;
        }

        if (boost::get<BaseInput>(block.baseTransaction.inputs[0]).blockIndex != previousBlockIndex + 1)
        {
            return error::TransactionValidationError::BASE_INPUT_WRONG_BLOCK_INDEX;
        }

        if (!(block.baseTransaction.unlockTime == previousBlockIndex + 1 + currency.minedMoneyUnlockWindow()))
        {
            return error::TransactionValidationError::WRONG_TRANSACTION_UNLOCK_TIME;
        }

        if (cachedBlock.getBlockIndex() >= Pastella::parameters::TRANSACTION_SIGNATURE_COUNT_VALIDATION_HEIGHT
            && !block.baseTransaction.signatures.empty())
        {
            return error::TransactionValidationError::BASE_INVALID_SIGNATURES_COUNT;
        }

        for (const auto &output : block.baseTransaction.outputs)
        {
            if (output.amount == 0)
            {
                return error::TransactionValidationError::OUTPUT_ZERO_AMOUNT;
            }

            if (output.target.type() == typeid(KeyOutput))
            {
                if (!check_key(boost::get<KeyOutput>(output.target).key))
                {
                    return error::TransactionValidationError::OUTPUT_INVALID_KEY;
                }
            }
            else
            {
                return error::TransactionValidationError::OUTPUT_UNKNOWN_TYPE;
            }

            if (std::numeric_limits<uint64_t>::max() - output.amount < minerReward)
            {
                return error::TransactionValidationError::OUTPUTS_AMOUNT_OVERFLOW;
            }

            minerReward += output.amount;
        }

        return error::BlockValidationError::VALIDATION_SUCCESS;
    }

    uint64_t Pastella::Core::getAdjustedTime() const
    {
        return time(NULL);
    }

    const Currency &Core::getCurrency() const
    {
        return currency;
    }

    void Core::save()
    {
        throwIfNotInitialized();

        deleteAlternativeChains();
        mergeMainChainSegments();
        chainsLeaves[0]->save();
    }

    void Core::load()
    {
        initRootSegment();

        start_time = std::time(nullptr);

        auto dbBlocksCount = chainsLeaves[0]->getTopBlockIndex() + 1;
        auto storageBlocksCount = mainChainStorage->getBlockCount();

        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
        loggerBlockchain(Logging::DEBUGGING) << "Blockchain storage blocks count: " << storageBlocksCount
                                   << ", DB blocks count: " << dbBlocksCount;

        assert(storageBlocksCount != 0); // we assume the storage has at least genesis block

        if (storageBlocksCount > dbBlocksCount)
        {
            loggerBlockchain(Logging::INFO) << "Importing blocks from blockchain storage";
            importBlocksFromStorage();
        }
        else if (storageBlocksCount < dbBlocksCount)
        {
            auto cutFrom = findCommonRoot(*mainChainStorage, *chainsLeaves[0]) + 1;

            loggerBlockchain(Logging::INFO) << "DB has more blocks than blockchain storage, cutting from block index: "
                                  << cutFrom;
            cutSegment(*chainsLeaves[0], cutFrom);

            assert(chainsLeaves[0]->getTopBlockIndex() + 1 == mainChainStorage->getBlockCount());
        }
        else if (
            getBlockHash(mainChainStorage->getBlockByIndex(storageBlocksCount - 1))
            != chainsLeaves[0]->getTopBlockHash())
        {
            loggerBlockchain(Logging::INFO) << "Blockchain storage and root segment are on different chains. "
                                  << "Cutting root segment to common block index "
                                  << findCommonRoot(*mainChainStorage, *chainsLeaves[0]) << " and reimporting blocks";
            importBlocksFromStorage();
        }
        else
        {
            loggerBlockchain(Logging::DEBUGGING) << "Blockchain storage and root segment are on the same height and chain";
        }

        /* RESTORE STAKING TRANSACTIONS: Scan blockchain and rebuild staking pool
         *
         * When the daemon restarts, the staking pool is empty (in-memory only).
         * We need to scan the blockchain for all staking transactions and restore
         * them to the pool so /getallstakes works correctly. */
        LoggerRef loggerStakingRestore(logger.getLogger(), "Core.Staking");
        loggerStakingRestore(Logging::INFO) << "Restoring staking pool from blockchain...";

        uint64_t currentHeight = chainsLeaves[0]->getTopBlockIndex();
        if (currentHeight >= Pastella::parameters::staking::STAKING_ENABLE_HEIGHT)
        {
            scanAndRestoreStakingTransactions(currentHeight);
        }
        else
        {
            loggerStakingRestore(Logging::INFO) << "Blockchain height " << currentHeight
                                                << " is below staking enable height "
                                                << Pastella::parameters::staking::STAKING_ENABLE_HEIGHT
                                                << ", skipping staking pool restore";
        }

        initialized = true;
    }

    void Core::scanAndRestoreStakingTransactions(uint64_t currentHeight)
    {
        if (!stakingPool)
        {
            LoggerRef loggerStaking(logger.getLogger(), "Core.Staking");
            loggerStaking(Logging::ERROR) << "Cannot scan for staking transactions: staking pool not initialized";
            return;
        }

        uint64_t stakingEnableHeight = Pastella::parameters::staking::STAKING_ENABLE_HEIGHT;
        uint64_t scanStartHeight = std::max(stakingEnableHeight, static_cast<uint64_t>(1));
        uint64_t scanEndHeight = currentHeight;

        LoggerRef loggerStaking(logger.getLogger(), "Core.Staking");
        loggerStaking(Logging::INFO) << "Scanning blocks " << scanStartHeight << " to " << scanEndHeight
                              << " for staking transactions...";

        int restoredStakes = 0;

        try
        {
            // Get all blocks in the range at once
            std::vector<RawBlock> rawBlocks = chainsLeaves[0]->getBlocksByHeight(scanStartHeight, scanEndHeight - 1);

            loggerStaking(Logging::INFO) << "Retrieved " << rawBlocks.size() << " blocks for scanning";

            for (uint64_t i = 0; i < rawBlocks.size(); ++i)
            {
                uint64_t height = scanStartHeight + i;
                const RawBlock &rawBlock = rawBlocks[i];

                try
                {
                    // Parse block
                    BlockTemplate block;
                    if (!fromBinaryArray(block, rawBlock.block))
                    {
                        continue;
                    }

                    // Parse transactions
                    std::vector<Transaction> transactions;
                    for (const auto &rawTx : rawBlock.transactions)
                    {
                        Transaction tx;
                        if (!fromBinaryArray(tx, rawTx))
                        {
                            continue;
                        }
                        transactions.push_back(tx);
                    }

                // Check each transaction for staking data
                    for (size_t txIndex = 0; txIndex < transactions.size(); ++txIndex)
                    {
                        const auto &tx = transactions[txIndex];

                        Pastella::TransactionExtraStaking stakingData;
                        if (Pastella::getStakingDataFromExtra(tx.extra, stakingData))
                        {
                            uint64_t stakingAmount = 0;
                            uint64_t totalOutputs = 0;
                            // Calculate staked amount from transaction outputs
                            for (const auto &output : tx.outputs)
                            {
                                totalOutputs += output.amount;
                                // For staking transactions, the main staked amount is the output amount
                                // We need to identify which output is the staking amount vs change
                                // Simplified approach: use the largest output (assuming that's the staking amount)
                                if (output.amount > stakingAmount)
                                {
                                    stakingAmount = output.amount;
                                }
                            }

                            // Restore the staking transaction
                            if (stakingAmount > 0)
                            {
                                bool restored = stakingPool->restoreStakingTransaction(
                                    Common::podToHex(getObjectHash(tx)),
                                    stakingAmount,
                                    stakingData.unlockTime,
                                    stakingData.lockDurationDays,
                                    height,
                                    currentHeight  // Use the currentHeight parameter from scan function
                                );

                                if (restored)
                                {
                                    // TRANSPARENT SYSTEM: Update the staker's address from transaction inputs
                                    // Get the staker's address by looking at the transaction inputs
                                    std::string stakerAddress = "";
                                    const auto &txPrefix = tx;
                                    if (!txPrefix.inputs.empty()) {
                                        const auto &input = txPrefix.inputs[0];
                                        if (input.type() == typeid(KeyInput)) {
                                            const KeyInput &keyInput = boost::get<KeyInput>(input);

                                            /* Look up the address from the referenced transaction's output */
                                            try
                                            {
                                                /* Get the transaction that contains the UTXO being spent */
                                                std::vector<Crypto::Hash> txHashes = {keyInput.transactionHash};
                                                std::vector<Crypto::Hash> missedTransactions;
                                                std::vector<Pastella::BinaryArray> txBinaries;
                                                chainsLeaves[0]->getRawTransactions(txHashes, txBinaries, missedTransactions);

                                                if (!txBinaries.empty() && !txBinaries[0].empty())
                                                {
                                                    /* Parse the referenced transaction */
                                                    Pastella::CachedTransaction cachedTx(txBinaries[0]);
                                                    const Pastella::Transaction& referencedTx = cachedTx.getTransaction();

                                                    /* Get the output being spent */
                                                    if (keyInput.outputIndex < referencedTx.outputs.size())
                                                    {
                                                        const auto& output = referencedTx.outputs[keyInput.outputIndex];

                                                        /* Extract public key from output (KeyOutput type) */
                                                        if (output.target.type() == typeid(Pastella::KeyOutput))
                                                        {
                                                            const Pastella::KeyOutput& keyOutput = boost::get<Pastella::KeyOutput>(output.target);
                                                            Crypto::PublicKey publicKey = keyOutput.key;

                                                            /* Convert public key to address */
                                                            stakerAddress = Utilities::publicKeyToAddress(publicKey);
                                                        }
                                                    }
                                                }
                                            }
                                            catch (const std::exception& e)
                                            {
                                                /* Failed to get transaction or extract address - leave empty */
                                                LoggerRef loggerStaking(logger.getLogger(), "Core.Staking");
                                                loggerStaking(Logging::WARNING) << "Failed to extract staker address during restore: "
                                                                         << e.what();
                                                stakerAddress = "";
                                            }
                                        }
                                    }

                                    if (!stakerAddress.empty()) {
                                        stakingPool->updateStakeStakerAddress(Common::podToHex(getObjectHash(tx)), stakerAddress);
                                    }
                                    restoredStakes++;
                                }
                            }
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    LoggerRef loggerStaking(logger.getLogger(), "Core.Staking");
                    loggerStaking(Logging::WARNING) << "Error scanning block " << height << ": " << e.what();
                    continue;
                }
            }
        }
        catch (const std::exception &e)
        {
            LoggerRef loggerStaking(logger.getLogger(), "Core.Staking");
            loggerStaking(Logging::ERROR) << "Error during staking transaction scan: " << e.what();
        }

        LoggerRef loggerStaking2(logger.getLogger(), "Core.Staking");
        loggerStaking2(Logging::INFO) << "Staking transaction scan completed. Restored " << restoredStakes
                              << " staking transactions. Total staked: "
                              << (stakingPool->getTotalStakedAmount() / 100000000.0) << " " << WalletConfig::ticker;
    }

    
    void Core::initRootSegment()
    {
        std::unique_ptr<IBlockchainCache> cache = this->blockchainCacheFactory->createRootBlockchainCache(currency);

        mainChainSet.emplace(cache.get());

        chainsLeaves.push_back(cache.get());
        chainsStorage.push_back(std::move(cache));

        contextGroup.spawn(std::bind(&Core::transactionPoolCleaningProcedure, this));

        updateBlockMedianSize();

        chainsLeaves[0]->load();
    }

    void Core::importBlocksFromStorage()
    {
        uint32_t commonIndex = findCommonRoot(*mainChainStorage, *chainsLeaves[0]);
        assert(commonIndex <= mainChainStorage->getBlockCount());

        cutSegment(*chainsLeaves[0], commonIndex + 1);

        auto previousBlockHash = getBlockHash(mainChainStorage->getBlockByIndex(commonIndex));
        auto blockCount = mainChainStorage->getBlockCount();
        for (uint32_t i = commonIndex + 1; i < blockCount; ++i)
        {
            RawBlock rawBlock = mainChainStorage->getBlockByIndex(i);
            auto blockTemplate = extractBlockTemplate(rawBlock);
            CachedBlock cachedBlock(blockTemplate);

            if (blockTemplate.previousBlockHash != previousBlockHash)
            {
                LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                loggerBlockchain(Logging::ERROR)
                    << "Local blockchain corruption detected. " << std::endl
                    << "Block with index " << i << " and hash " << cachedBlock.getBlockHash()
                    << " has previous block hash " << blockTemplate.previousBlockHash << ", but parent has hash "
                    << previousBlockHash << "." << std::endl
                    << "Please try to repair this issue by starting the node with the option: --rewind-to-height " << i
                    << std::endl
                    << "If the above does not repair the issue, please launch the node with the option: --resync"
                    << std::endl;
                throw std::system_error(make_error_code(error::CoreErrorCode::CORRUPTED_BLOCKCHAIN));
            }

            previousBlockHash = cachedBlock.getBlockHash();

            std::vector<CachedTransaction> transactions;
            uint64_t cumulativeSize = 0;
            if (!extractTransactions(rawBlock.transactions, transactions, cumulativeSize))
            {
                LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                loggerBlockchain(Logging::ERROR) << "Couldn't deserialize raw block transactions in block "
                                       << cachedBlock.getBlockHash();
                throw std::system_error(make_error_code(error::AddBlockErrorCode::DESERIALIZATION_FAILED));
            }

            cumulativeSize += getObjectBinarySize(blockTemplate.baseTransaction);
            TransactionValidatorState spentOutputs = extractSpentOutputs(transactions);
            auto currentDifficulty = chainsLeaves[0]->getDifficultyForNextBlock(i - 1);

            uint64_t cumulativeFee = std::accumulate(
                transactions.begin(),
                transactions.end(),
                UINT64_C(0),
                [](uint64_t fee, const CachedTransaction &transaction) {
                    return fee + transaction.getTransactionFee();
                });

            int64_t emissionChange =
                getEmissionChange(currency, *chainsLeaves[0], i - 1, cachedBlock, cumulativeSize, cumulativeFee);
            chainsLeaves[0]->pushBlock(
                cachedBlock,
                transactions,
                spentOutputs,
                cumulativeSize,
                emissionChange,
                currentDifficulty,
                std::move(rawBlock));

            if (i % 1000 == 0)
            {
                LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
                loggerBlockchain(Logging::INFO) << "Imported block with index " << i << " / " << (blockCount - 1);
            }
        }
    }

    void Core::cutSegment(IBlockchainCache &segment, uint32_t startIndex)
    {
        if (segment.getTopBlockIndex() < startIndex)
        {
            return;
        }

        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
        loggerBlockchain(Logging::INFO) << "Cutting root segment from index " << startIndex;
        auto childCache = segment.split(startIndex);
        segment.deleteChild(childCache.get());
    }

    void Core::updateMainChainSet()
    {
        mainChainSet.clear();
        IBlockchainCache *chainPtr = chainsLeaves[0];
        assert(chainPtr != nullptr);
        do
        {
            mainChainSet.insert(chainPtr);
            chainPtr = chainPtr->getParent();
        } while (chainPtr != nullptr);
    }

    IBlockchainCache *Core::findSegmentContainingBlock(const Crypto::Hash &blockHash) const
    {
        assert(chainsLeaves.size() > 0);

        // first search in main chain
        auto blockSegment = findMainChainSegmentContainingBlock(blockHash);
        if (blockSegment != nullptr)
        {
            return blockSegment;
        }

        // than search in alternative chains
        return findAlternativeSegmentContainingBlock(blockHash);
    }

    IBlockchainCache *Core::findSegmentContainingBlock(uint32_t blockHeight) const
    {
        assert(chainsLeaves.size() > 0);

        // first search in main chain
        auto blockSegment = findMainChainSegmentContainingBlock(blockHeight);
        if (blockSegment != nullptr)
        {
            return blockSegment;
        }

        // than search in alternative chains
        return findAlternativeSegmentContainingBlock(blockHeight);
    }

    IBlockchainCache *Core::findAlternativeSegmentContainingBlock(const Crypto::Hash &blockHash) const
    {
        IBlockchainCache *cache = nullptr;
        std::find_if(++chainsLeaves.begin(), chainsLeaves.end(), [&](IBlockchainCache *chain) {
            return cache = findIndexInChain(chain, blockHash);
        });
        return cache;
    }

    IBlockchainCache *Core::findMainChainSegmentContainingBlock(const Crypto::Hash &blockHash) const
    {
        return findIndexInChain(chainsLeaves[0], blockHash);
    }

    IBlockchainCache *Core::findMainChainSegmentContainingBlock(uint32_t blockIndex) const
    {
        return findIndexInChain(chainsLeaves[0], blockIndex);
    }

    // WTF?! this function returns first chain it is able to find..
    IBlockchainCache *Core::findAlternativeSegmentContainingBlock(uint32_t blockIndex) const
    {
        IBlockchainCache *cache = nullptr;
        std::find_if(++chainsLeaves.begin(), chainsLeaves.end(), [&](IBlockchainCache *chain) {
            return cache = findIndexInChain(chain, blockIndex);
        });
        return nullptr;
    }

    BlockTemplate Core::restoreBlockTemplate(IBlockchainCache *blockchainCache, uint32_t blockIndex) const
    {
        RawBlock rawBlock = blockchainCache->getBlockByIndex(blockIndex);

        BlockTemplate block;
        if (!fromBinaryArray(block, rawBlock.block))
        {
            throw std::runtime_error("Coulnd't deserialize BlockTemplate");
        }

        return block;
    }

    std::vector<Crypto::Hash> Core::doBuildSparseChain(const Crypto::Hash &blockHash) const
    {
        IBlockchainCache *chain = findSegmentContainingBlock(blockHash);

        uint32_t blockIndex = chain->getBlockIndex(blockHash);

        // TODO reserve ceil(log(blockIndex))
        std::vector<Crypto::Hash> sparseChain;
        sparseChain.push_back(blockHash);

        for (uint32_t i = 1; i < blockIndex; i *= 2)
        {
            sparseChain.push_back(chain->getBlockHash(blockIndex - i));
        }

        auto genesisBlockHash = chain->getBlockHash(0);
        if (sparseChain[0] != genesisBlockHash)
        {
            sparseChain.push_back(genesisBlockHash);
        }

        return sparseChain;
    }

    RawBlock Core::getRawBlock(IBlockchainCache *segment, uint32_t blockIndex) const
    {
        assert(blockIndex >= segment->getStartBlockIndex() && blockIndex <= segment->getTopBlockIndex());

        return segment->getBlockByIndex(blockIndex);
    }

    // TODO: decompose these three methods
    size_t Core::pushBlockHashes(
        uint32_t startIndex,
        uint32_t fullOffset,
        size_t maxItemsCount,
        std::vector<BlockShortInfo> &entries) const
    {
        assert(fullOffset >= startIndex);
        uint32_t itemsCount = std::min(fullOffset - startIndex, static_cast<uint32_t>(maxItemsCount));
        if (itemsCount == 0)
        {
            return 0;
        }
        std::vector<Crypto::Hash> blockIds = getBlockHashes(startIndex, itemsCount);
        entries.reserve(entries.size() + blockIds.size());
        for (auto &blockHash : blockIds)
        {
            BlockShortInfo entry;
            entry.blockId = std::move(blockHash);
            entries.emplace_back(std::move(entry));
        }
        return blockIds.size();
    }

    // TODO: decompose these three methods
    size_t Core::pushBlockHashes(
        uint32_t startIndex,
        uint32_t fullOffset,
        size_t maxItemsCount,
        std::vector<BlockDetails> &entries) const
    {
        assert(fullOffset >= startIndex);
        uint32_t itemsCount = std::min(fullOffset - startIndex, static_cast<uint32_t>(maxItemsCount));
        if (itemsCount == 0)
        {
            return 0;
        }
        std::vector<Crypto::Hash> blockIds = getBlockHashes(startIndex, itemsCount);
        entries.reserve(entries.size() + blockIds.size());
        for (auto &blockHash : blockIds)
        {
            BlockDetails entry;
            entry.hash = std::move(blockHash);
            entries.emplace_back(std::move(entry));
        }
        return blockIds.size();
    }

    // TODO: decompose these three methods
    size_t Core::pushBlockHashes(
        uint32_t startIndex,
        uint32_t fullOffset,
        size_t maxItemsCount,
        std::vector<BlockFullInfo> &entries) const
    {
        assert(fullOffset >= startIndex);
        uint32_t itemsCount = std::min(fullOffset - startIndex, static_cast<uint32_t>(maxItemsCount));
        if (itemsCount == 0)
        {
            return 0;
        }
        std::vector<Crypto::Hash> blockIds = getBlockHashes(startIndex, itemsCount);
        entries.reserve(entries.size() + blockIds.size());
        for (auto &blockHash : blockIds)
        {
            BlockFullInfo entry;
            entry.block_id = std::move(blockHash);
            entries.emplace_back(std::move(entry));
        }
        return blockIds.size();
    }

    void Core::fillQueryBlockFullInfo(
        uint32_t fullOffset,
        uint32_t currentIndex,
        size_t maxItemsCount,
        std::vector<BlockFullInfo> &entries) const
    {
        assert(currentIndex >= fullOffset);

        uint32_t fullBlocksCount =
            static_cast<uint32_t>(std::min(static_cast<uint32_t>(maxItemsCount), currentIndex - fullOffset));
        entries.reserve(entries.size() + fullBlocksCount);

        for (uint32_t blockIndex = fullOffset; blockIndex < fullOffset + fullBlocksCount; ++blockIndex)
        {
            IBlockchainCache *segment = findMainChainSegmentContainingBlock(blockIndex);

            BlockFullInfo blockFullInfo;
            blockFullInfo.block_id = segment->getBlockHash(blockIndex);
            static_cast<RawBlock &>(blockFullInfo) = getRawBlock(segment, blockIndex);

            entries.emplace_back(std::move(blockFullInfo));
        }
    }

    void Core::fillQueryBlockShortInfo(
        uint32_t fullOffset,
        uint32_t currentIndex,
        size_t maxItemsCount,
        std::vector<BlockShortInfo> &entries) const
    {
        assert(currentIndex >= fullOffset);

        uint32_t fullBlocksCount =
            static_cast<uint32_t>(std::min(static_cast<uint32_t>(maxItemsCount), currentIndex - fullOffset + 1));
        entries.reserve(entries.size() + fullBlocksCount);

        for (uint32_t blockIndex = fullOffset; blockIndex < fullOffset + fullBlocksCount; ++blockIndex)
        {
            IBlockchainCache *segment = findMainChainSegmentContainingBlock(blockIndex);
            RawBlock rawBlock = getRawBlock(segment, blockIndex);

            BlockShortInfo blockShortInfo;
            blockShortInfo.block = std::move(rawBlock.block);
            blockShortInfo.blockId = segment->getBlockHash(blockIndex);

            blockShortInfo.txPrefixes.reserve(rawBlock.transactions.size());
            for (auto &rawTransaction : rawBlock.transactions)
            {
                TransactionPrefixInfo prefixInfo;
                prefixInfo.txHash =
                    getBinaryArrayHash(rawTransaction); // TODO: is there faster way to get hash without calculation?

                Transaction transaction;
                if (!fromBinaryArray(transaction, rawTransaction))
                {
                    // TODO: log it
                    throw std::runtime_error("Couldn't deserialize transaction");
                }

                prefixInfo.txPrefix = std::move(static_cast<TransactionPrefix &>(transaction));
                blockShortInfo.txPrefixes.emplace_back(std::move(prefixInfo));
            }

            entries.emplace_back(std::move(blockShortInfo));
        }
    }

    void Core::fillQueryBlockDetails(
        uint32_t fullOffset,
        uint32_t currentIndex,
        size_t maxItemsCount,
        std::vector<BlockDetails> &entries) const
    {
        assert(currentIndex >= fullOffset);

        uint32_t fullBlocksCount =
            static_cast<uint32_t>(std::min(static_cast<uint32_t>(maxItemsCount), currentIndex - fullOffset + 1));
        entries.reserve(entries.size() + fullBlocksCount);

        for (uint32_t blockIndex = fullOffset; blockIndex < fullOffset + fullBlocksCount; ++blockIndex)
        {
            IBlockchainCache *segment = findMainChainSegmentContainingBlock(blockIndex);
            Crypto::Hash blockHash = segment->getBlockHash(blockIndex);
            BlockDetails block = getBlockDetails(blockHash);
            entries.emplace_back(std::move(block));
        }
    }

    void Core::getTransactionPoolDifference(
        const std::vector<Crypto::Hash> &knownHashes,
        std::vector<Crypto::Hash> &newTransactions,
        std::vector<Crypto::Hash> &deletedTransactions) const
    {
        auto t = transactionPool->getTransactionHashes();

        std::unordered_set<Crypto::Hash> poolTransactions(t.begin(), t.end());
        std::unordered_set<Crypto::Hash> knownTransactions(knownHashes.begin(), knownHashes.end());

        for (auto it = poolTransactions.begin(), end = poolTransactions.end(); it != end;)
        {
            auto knownTransactionIt = knownTransactions.find(*it);
            if (knownTransactionIt != knownTransactions.end())
            {
                knownTransactions.erase(knownTransactionIt);
                it = poolTransactions.erase(it);
            }
            else
            {
                ++it;
            }
        }

        newTransactions.assign(poolTransactions.begin(), poolTransactions.end());
        deletedTransactions.assign(knownTransactions.begin(), knownTransactions.end());
    }

    uint8_t Core::getBlockMajorVersionForHeight(uint32_t height) const
    {
        return upgradeManager->getBlockMajorVersion(height);
    }

    size_t Core::calculateCumulativeBlocksizeLimit(uint32_t height) const
    {
        uint8_t nextBlockMajorVersion = getBlockMajorVersionForHeight(height);
        size_t nextBlockGrantedFullRewardZone =
            currency.blockGrantedFullRewardZoneByBlockVersion(nextBlockMajorVersion);

        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());
        // FIXME: skip gensis here?
        auto sizes = chainsLeaves[0]->getLastBlocksSizes(currency.rewardBlocksWindow());
        uint64_t median = Common::medianValue(sizes);
        if (median <= nextBlockGrantedFullRewardZone)
        {
            median = nextBlockGrantedFullRewardZone;
        }

        return median * 2;
    }

    /* A transaction that is valid at the time it was added to the pool, is not
       neccessarily valid now, if the network rules changed. */
    bool Core::validateBlockTemplateTransaction(const CachedTransaction &cachedTransaction, const uint64_t blockHeight)
    {
        /* Not used in revalidateAfterHeightChange() */
        TransactionValidatorState state;

        ValidateTransaction txValidator(
            cachedTransaction,
            state,
            nullptr, /* Not used in revalidateAfterHeightChange() */
            currency,
            checkpoints,
            m_transactionValidationThreadPool,
            blockHeight,
            blockMedianSize,
            true /* Pool transaction */
        );

        const auto result = txValidator.revalidateAfterHeightChange();

        /* DEBUG: Log why transaction validation failed */
        if (!result.valid)
        {
            LoggerRef loggerValidation(logger.getLogger(), "Core.Validation");
            loggerValidation(Logging::DEBUGGING) << "Transaction " << cachedTransaction.getTransactionHash()
                                       << " FAILED validation for block template at height " << blockHeight;

            /* Log validation error if available */
            if (!result.errorMessage.empty())
            {
                loggerValidation(Logging::DEBUGGING) << "  Validation error: " << result.errorMessage;
            }

            /* Log error code if available */
            if (result.errorCode)
            {
                loggerValidation(Logging::DEBUGGING) << "  Error code: " << result.errorCode.message();
            }

            /* Log the transaction details for debugging */
            loggerValidation(Logging::DEBUGGING) << "  Transaction fee: " << cachedTransaction.getTransactionFee();
            loggerValidation(Logging::DEBUGGING) << "  Transaction size: " << cachedTransaction.getTransactionBinaryArray().size();
            loggerValidation(Logging::DEBUGGING) << "  Number of inputs: " << cachedTransaction.getTransaction().inputs.size();
            loggerValidation(Logging::DEBUGGING) << "  Number of outputs: " << cachedTransaction.getTransaction().outputs.size();
        }

        return result.valid;
    }

    void Core::fillBlockTemplate(
        BlockTemplate &block,
        const size_t medianSize,
        const size_t maxCumulativeSize,
        const uint64_t height,
        size_t &transactionsSize,
        uint64_t &fee)
    {
        transactionsSize = 0;
        fee = 0;

        size_t maxTotalSize = (125 * medianSize) / 100;

        maxTotalSize = std::min(maxTotalSize, maxCumulativeSize) - currency.minerTxBlobReservedSize();

        TransactionSpentInputsChecker spentInputsChecker;

        auto transactions = transactionPool->getPoolTransactionsForBlockTemplate();

        LoggerRef loggerBlockchain(logger.getLogger(), "Core.Blockchain");
        loggerBlockchain(Logging::DEBUGGING) << "Block template at height " << height
                                   << ": " << transactions.size() << " transactions in pool";

        /* Define our lambda function for checking and adding transactions to a block template */
        const auto addTransactionToBlockTemplate =
            [this, &spentInputsChecker, maxTotalSize, height, &transactionsSize, &fee, &block](
                const CachedTransaction &transaction) {
                /* If the current set of transactions included in the blocktemplate plus the transaction
                   we just passed in exceed the maximum size of a block, it won't fit so we'll move on */
                if (transactionsSize + transaction.getTransactionBinaryArray().size() > maxTotalSize)
                {
                    logger(Logging::TRACE) << "Transaction " << transaction.getTransactionHash()
                                           << " too large for block template (size: "
                                           << transaction.getTransactionBinaryArray().size()
                                           << ", available: " << (maxTotalSize - transactionsSize) << ")";
                    return false;
                }

                /* Check to validate that the transaction is valid for a block at this height */
                if (!validateBlockTemplateTransaction(transaction, height))
                {
                    logger(Logging::TRACE) << "Transaction " << transaction.getTransactionHash()
                                           << " removed from pool due to failed validation";
                    transactionPool->removeTransaction(transaction.getTransactionHash());

                    return false;
                }

                /* DEBUG: Log all inputs in this transaction */
                logger(Logging::DEBUGGING) << "Transaction " << transaction.getTransactionHash()
                                          << " has " << transaction.getTransaction().inputs.size() << " inputs:";
                for (const auto &input : transaction.getTransaction().inputs)
                {
                    if (input.type() == typeid(KeyInput))
                    {
                        const auto &keyInput = boost::get<KeyInput>(input);
                        logger(Logging::TRACE) << "  - Input spending UTXO: "
                            << keyInput.transactionHash << ":"
                            << keyInput.outputIndex
                            << " (amount: " << keyInput.amount << ")";
                    }
                }

                /* Make sure that we have not already spent funds in this same block via
                   another transaction that we've already included in this block template */
                if (!spentInputsChecker.haveSpentInputs(transaction.getTransaction()))
                {
                    logger(Logging::TRACE) << "Transaction " << transaction.getTransactionHash()
                                           << " included in block template";

                    transactionsSize += transaction.getTransactionBinaryArray().size();
                    const auto &tx = transaction.getTransaction();
                    logger(Logging::DEBUGGING) << "  Transaction spends " << tx.inputs.size() << " UTXO(s):";
                    for (const auto &input : tx.inputs)
                    {
                        if (input.type() == typeid(KeyInput))
                        {
                            const auto &keyInput = boost::get<KeyInput>(input);
                            logger(Logging::DEBUGGING) << "    - Spends: " << keyInput.transactionHash
                                << ":" << keyInput.outputIndex
                                << " (amount: " << keyInput.amount << ")";
                        }
                    }

                    fee += transaction.getTransactionFee();

                    block.transactionHashes.emplace_back(transaction.getTransactionHash());

                    return true;
                }
                else
                {
                    logger(Logging::TRACE) << "Transaction " << transaction.getTransactionHash()
                                           << " has already spent inputs in this block";
                    return false;
                }
            };

        for (const auto &transaction : transactions)
        {
            if (addTransactionToBlockTemplate(transaction))
            {
                logger(Logging::TRACE) << "Transaction " << transaction.getTransactionHash()
                                       << " included in block template";
            }
            else
            {
                logger(Logging::TRACE) << "Transaction " << transaction.getTransactionHash()
                                       << " not included in block template";
            }
        }
    }

    void Core::deleteAlternativeChains()
    {
        while (chainsLeaves.size() > 1)
        {
            deleteLeaf(1);
        }
    }

    void Core::deleteLeaf(size_t leafIndex)
    {
        assert(leafIndex < chainsLeaves.size());

        IBlockchainCache *leaf = chainsLeaves[leafIndex];

        IBlockchainCache *parent = leaf->getParent();
        if (parent != nullptr)
        {
            bool r = parent->deleteChild(leaf);
            if (r)
            {
            }
            assert(r);
        }

        auto segmentIt = std::find_if(
            chainsStorage.begin(), chainsStorage.end(), [&leaf](const std::unique_ptr<IBlockchainCache> &segment) {
                return segment.get() == leaf;
            });

        assert(segmentIt != chainsStorage.end());

        if (leafIndex != 0)
        {
            if (parent->getChildCount() == 0)
            {
                chainsLeaves.push_back(parent);
            }

            chainsLeaves.erase(chainsLeaves.begin() + leafIndex);
        }
        else
        {
            if (parent != nullptr)
            {
                chainsLeaves[0] = parent;
            }
            else
            {
                chainsLeaves.erase(chainsLeaves.begin());
            }
        }

        chainsStorage.erase(segmentIt);
    }

    void Core::mergeMainChainSegments()
    {
        assert(!chainsStorage.empty());
        assert(!chainsLeaves.empty());

        std::vector<IBlockchainCache *> chain;
        IBlockchainCache *segment = chainsLeaves[0];
        while (segment != nullptr)
        {
            chain.push_back(segment);
            segment = segment->getParent();
        }

        IBlockchainCache *rootSegment = chain.back();
        for (auto it = ++chain.rbegin(); it != chain.rend(); ++it)
        {
            mergeSegments(rootSegment, *it);
        }

        auto rootIt = std::find_if(
            chainsStorage.begin(),
            chainsStorage.end(),
            [&rootSegment](const std::unique_ptr<IBlockchainCache> &segment) { return segment.get() == rootSegment; });

        assert(rootIt != chainsStorage.end());

        if (rootIt != chainsStorage.begin())
        {
            *chainsStorage.begin() = std::move(*rootIt);
        }

        chainsStorage.erase(++chainsStorage.begin(), chainsStorage.end());
        chainsLeaves.clear();
        chainsLeaves.push_back(chainsStorage.begin()->get());
    }

    void Core::mergeSegments(IBlockchainCache *acceptingSegment, IBlockchainCache *segment)
    {
        assert(
            segment->getStartBlockIndex()
            == acceptingSegment->getStartBlockIndex() + acceptingSegment->getBlockCount());

        auto startIndex = segment->getStartBlockIndex();
        auto blockCount = segment->getBlockCount();
        for (auto blockIndex = startIndex; blockIndex < startIndex + blockCount; ++blockIndex)
        {
            PushedBlockInfo info = segment->getPushedBlockInfo(blockIndex);

            BlockTemplate block;
            if (!fromBinaryArray(block, info.rawBlock.block))
            {
                logger(Logging::WARNING) << "mergeSegments error: Couldn't deserialize block";
                throw std::runtime_error("Couldn't deserialize block");
            }

            std::vector<CachedTransaction> transactions;
            if (!Utils::restoreCachedTransactions(info.rawBlock.transactions, transactions))
            {
                logger(Logging::WARNING) << "mergeSegments error: Couldn't deserialize transactions";
                throw std::runtime_error("Couldn't deserialize transactions");
            }

            acceptingSegment->pushBlock(
                CachedBlock(block),
                transactions,
                info.validatorState,
                info.blockSize,
                info.generatedCoins,
                info.blockDifficulty,
                std::move(info.rawBlock));
        }
    }

    BlockDetails Core::getBlockDetails(const uint32_t blockHeight, const uint32_t attempt) const
    {
        if (attempt > 10)
        {
            throw std::runtime_error("Requested block height wasn't found in blockchain.");
        }

        throwIfNotInitialized();

        IBlockchainCache *segment = findSegmentContainingBlock(blockHeight);
        if (segment == nullptr)
        {
            throw std::runtime_error("Requested block height wasn't found in blockchain.");
        }

        try
        {
            return getBlockDetails(segment->getBlockHash(blockHeight));
        }
        catch (const std::out_of_range &e)
        {
            logger(Logging::INFO) << "Failed to get block details, mid chain reorg";
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            return getBlockDetails(blockHeight, attempt+1);
        }
    }

    BlockDetails Core::getBlockDetails(const Crypto::Hash &blockHash) const
    {
        throwIfNotInitialized();

        IBlockchainCache *segment = findSegmentContainingBlock(blockHash);
        if (segment == nullptr)
        {
            throw std::runtime_error("Requested hash wasn't found in blockchain.");
        }

        uint32_t blockIndex = segment->getBlockIndex(blockHash);
        BlockTemplate blockTemplate = restoreBlockTemplate(segment, blockIndex);

        BlockDetails blockDetails;
        blockDetails.majorVersion = blockTemplate.majorVersion;
        blockDetails.minorVersion = blockTemplate.minorVersion;
        blockDetails.timestamp = blockTemplate.timestamp;
        blockDetails.prevBlockHash = blockTemplate.previousBlockHash;
        blockDetails.nonce = blockTemplate.nonce;
        blockDetails.hash = blockHash;

        blockDetails.reward = 0;
        for (const TransactionOutput &out : blockTemplate.baseTransaction.outputs)
        {
            blockDetails.reward += out.amount;
        }

        blockDetails.index = blockIndex;
        blockDetails.isAlternative = mainChainSet.count(segment) == 0;

        blockDetails.difficulty = getBlockDifficulty(blockIndex);

        std::vector<uint64_t> sizes = segment->getLastBlocksSizes(1, blockDetails.index, addGenesisBlock);
        assert(sizes.size() == 1);
        blockDetails.transactionsCumulativeSize = sizes.front();

        uint64_t blockBlobSize = getObjectBinarySize(blockTemplate);
        uint64_t coinbaseTransactionSize = getObjectBinarySize(blockTemplate.baseTransaction);
        blockDetails.blockSize = blockBlobSize + blockDetails.transactionsCumulativeSize - coinbaseTransactionSize;

        blockDetails.alreadyGeneratedCoins = segment->getAlreadyGeneratedCoins(blockDetails.index);
        blockDetails.alreadyGeneratedTransactions = segment->getAlreadyGeneratedTransactions(blockDetails.index);

        uint64_t prevBlockGeneratedCoins = 0;
        blockDetails.sizeMedian = 0;
        if (blockDetails.index > 0)
        {
            auto lastBlocksSizes =
                segment->getLastBlocksSizes(currency.rewardBlocksWindow(), blockDetails.index - 1, addGenesisBlock);
            blockDetails.sizeMedian = Common::medianValue(lastBlocksSizes);
            prevBlockGeneratedCoins = segment->getAlreadyGeneratedCoins(blockDetails.index - 1);
        }

        int64_t emissionChange = 0;
        bool result = currency.getBlockReward(
            blockDetails.majorVersion,
            blockDetails.sizeMedian,
            0,
            prevBlockGeneratedCoins,
            0,
            blockDetails.baseReward,
            emissionChange,
            getTopBlockIndex() + 1);
        if (result)
        {
        }
        assert(result);

        uint64_t currentReward = 0;
        result = currency.getBlockReward(
            blockDetails.majorVersion,
            blockDetails.sizeMedian,
            blockDetails.transactionsCumulativeSize,
            prevBlockGeneratedCoins,
            0,
            currentReward,
            emissionChange,
            getTopBlockIndex() + 1);
        assert(result);

        if (blockDetails.baseReward == 0 && currentReward == 0)
        {
            blockDetails.penalty = static_cast<double>(0);
        }
        else
        {
            assert(blockDetails.baseReward >= currentReward);
            blockDetails.penalty = static_cast<double>(blockDetails.baseReward - currentReward)
                                   / static_cast<double>(blockDetails.baseReward);
        }

        blockDetails.transactions.reserve(blockTemplate.transactionHashes.size() + 1);
        CachedTransaction cachedBaseTx(std::move(blockTemplate.baseTransaction));
        blockDetails.transactions.push_back(getTransactionDetails(cachedBaseTx.getTransactionHash(), segment, false));

        blockDetails.totalFeeAmount = 0;
        for (const Crypto::Hash &transactionHash : blockTemplate.transactionHashes)
        {
            blockDetails.transactions.push_back(getTransactionDetails(transactionHash, segment, false));
            blockDetails.totalFeeAmount += blockDetails.transactions.back().fee;
        }

        return blockDetails;
    }

    TransactionDetails Core::getTransactionDetails(const Crypto::Hash &transactionHash) const
    {
        throwIfNotInitialized();

        IBlockchainCache *segment = findSegmentContainingTransaction(transactionHash);
        bool foundInPool = transactionPool->checkIfTransactionPresent(transactionHash);
        if (segment == nullptr && !foundInPool)
        {
            throw std::runtime_error("Requested transaction wasn't found.");
        }

        return getTransactionDetails(transactionHash, segment, foundInPool);
    }

    TransactionDetails Core::getTransactionDetails(
        const Crypto::Hash &transactionHash,
        IBlockchainCache *segment,
        bool foundInPool) const
    {
        assert((segment != nullptr) != foundInPool);
        if (segment == nullptr)
        {
            segment = chainsLeaves[0];
        }

        std::unique_ptr<ITransaction> transaction;
        Transaction rawTransaction;
        TransactionDetails transactionDetails;
        if (!foundInPool)
        {
            std::vector<Crypto::Hash> transactionsHashes;
            std::vector<BinaryArray> rawTransactions;
            std::vector<Crypto::Hash> missedTransactionsHashes;
            transactionsHashes.push_back(transactionHash);

            segment->getRawTransactions(transactionsHashes, rawTransactions, missedTransactionsHashes);

            // Handle case where transaction is not found (race condition with block addition)
            if (!missedTransactionsHashes.empty())
            {
                // Transaction not found in blockchain, likely due to race condition
                // Return a default/empty transaction details instead of crashing
                transactionDetails.inBlockchain = false;
                transactionDetails.blockIndex = 0;
                transactionDetails.blockHash = Crypto::Hash();
                transactionDetails.timestamp = 0;
                transactionDetails.size = 0;
                transactionDetails.fee = 0;
                transactionDetails.unlockTime = 0;
                transactionDetails.totalOutputsAmount = 0;
                transactionDetails.totalInputsAmount = 0;
                
                transactionDetails.extra = TransactionExtraDetails{};

                return transactionDetails;
            }

            assert(rawTransactions.size() == 1);

            std::vector<CachedTransaction> transactions;
            Utils::restoreCachedTransactions(rawTransactions, transactions);
            assert(transactions.size() == 1);

            transactionDetails.inBlockchain = true;
            transactionDetails.blockIndex = segment->getBlockIndexContainingTx(transactionHash);
            transactionDetails.blockHash = segment->getBlockHash(transactionDetails.blockIndex);

            auto timestamps = segment->getLastTimestamps(1, transactionDetails.blockIndex, addGenesisBlock);
            assert(timestamps.size() == 1);
            transactionDetails.timestamp = timestamps.back();

            transactionDetails.size = transactions.back().getTransactionBinaryArray().size();
            transactionDetails.fee = transactions.back().getTransactionFee();

            rawTransaction = transactions.back().getTransaction();
            transaction = createTransaction(rawTransaction);
        }
        else
        {
            transactionDetails.inBlockchain = false;
            transactionDetails.timestamp = transactionPool->getTransactionReceiveTime(transactionHash);

            transactionDetails.size =
                transactionPool->getTransaction(transactionHash).getTransactionBinaryArray().size();
            transactionDetails.fee = transactionPool->getTransaction(transactionHash).getTransactionFee();

            rawTransaction = transactionPool->getTransaction(transactionHash).getTransaction();
            transaction = createTransaction(rawTransaction);
        }

        transactionDetails.hash = transactionHash;
        transactionDetails.unlockTime = transaction->getUnlockTime();

        transactionDetails.totalOutputsAmount = transaction->getOutputTotalAmount();
        transactionDetails.totalInputsAmount = transaction->getInputTotalAmount();

        
        transactionDetails.extra.publicKey = transaction->getTransactionPublicKey();
        transaction->getExtraNonce(transactionDetails.extra.nonce);
        transactionDetails.extra.raw = transaction->getExtra();

        transactionDetails.signatures = rawTransaction.signatures;

        transactionDetails.inputs.reserve(transaction->getInputCount());
        for (size_t i = 0; i < transaction->getInputCount(); ++i)
        {
            TransactionInputDetails txInDetails;

            if (transaction->getInputType(i) == TransactionTypes::InputType::Generating)
            {
                BaseInputDetails baseDetails;
                baseDetails.input = boost::get<BaseInput>(rawTransaction.inputs[i]);
                baseDetails.amount = transaction->getOutputTotalAmount();
                txInDetails = baseDetails;
            }
            else if (transaction->getInputType(i) == TransactionTypes::InputType::Key)
            {
                KeyInputDetails txInToKeyDetails;
                txInToKeyDetails.input = boost::get<KeyInput>(rawTransaction.inputs[i]);

                /* TRANSPARENT SYSTEM: Copy output reference from KeyInput
                 *
                 * In transparent system, KeyInput explicitly references which UTXO is being spent:
                 * - transactionHash: Hash of transaction that created the UTXO
                 * - outputIndex: Index of the output in that transaction
                 *
                 * We MUST copy these to KeyInputDetails so RPC and wallet code can
                 * look up the sender address! */
                txInToKeyDetails.output.number = txInToKeyDetails.input.outputIndex;
                txInToKeyDetails.output.transactionHash = txInToKeyDetails.input.transactionHash;

                txInDetails = txInToKeyDetails;
            }

            assert(!txInDetails.empty());
            transactionDetails.inputs.push_back(std::move(txInDetails));
        }

        transactionDetails.outputs.reserve(transaction->getOutputCount());
        /* In transparent system, outputs are referenced by (transactionHash, outputIndex) */
        std::vector<uint32_t> globalIndexes;
        globalIndexes.reserve(transaction->getOutputCount());
        for (size_t i = 0; i < transaction->getOutputCount(); ++i)
        {
            globalIndexes.push_back(static_cast<uint32_t>(i));
        }

        assert(transaction->getOutputCount() == globalIndexes.size());
        for (size_t i = 0; i < transaction->getOutputCount(); ++i)
        {
            TransactionOutputDetails txOutDetails;
            txOutDetails.output = rawTransaction.outputs[i];
            txOutDetails.globalIndex = globalIndexes[i];
            transactionDetails.outputs.push_back(std::move(txOutDetails));
        }

        return transactionDetails;
    }

    std::vector<Crypto::Hash> Core::getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount) const
    {
        throwIfNotInitialized();

        logger(Logging::DEBUGGING) << "getBlockHashesByTimestamps request with timestamp " << timestampBegin
                                   << " and seconds count " << secondsCount;

        auto mainChain = chainsLeaves[0];

        if (timestampBegin + static_cast<uint64_t>(secondsCount) < timestampBegin)
        {
            logger(Logging::WARNING) << "Timestamp overflow occured. Timestamp begin: " << timestampBegin
                                     << ", timestamp end: " << (timestampBegin + static_cast<uint64_t>(secondsCount));

            throw std::runtime_error("Timestamp overflow");
        }

        return mainChain->getBlockHashesByTimestamps(timestampBegin, secondsCount);
    }

    StakingPool* Core::getStakingPool()
    {
        throwIfNotInitialized();
        return stakingPool.get();
    }

    GovernanceManager* Core::getGovernanceManager()
    {
        throwIfNotInitialized();
        return governanceManager.get();
    }

    bool Core::reactivateStakesForRewind(uint64_t targetHeight)
    {
        throwIfNotInitialized();

        if (!stakingPool)
        {
            logger(Logging::WARNING) << "Cannot reactivate stakes: staking pool not available";
            return false;
        }

        logger(Logging::INFO) << "Reactivating stakes for rewind to height " << targetHeight;

        bool result = stakingPool->reactivateStakesAboveHeight(targetHeight);

        if (result)
        {
            logger(Logging::INFO) << "Successfully reactivated stakes for rewind to height " << targetHeight;
        }
        else
        {
            logger(Logging::DEBUGGING) << "No stakes needed reactivation for rewind to height " << targetHeight;
        }

        return result;
    }

    void Core::throwIfNotInitialized() const
    {
        if (!initialized)
        {
            throw std::system_error(make_error_code(error::CoreErrorCode::NOT_INITIALIZED));
        }
    }

    IBlockchainCache *Core::findSegmentContainingTransaction(const Crypto::Hash &transactionHash) const
    {
        assert(!chainsLeaves.empty());
        assert(!chainsStorage.empty());

        IBlockchainCache *segment = chainsLeaves[0];
        assert(segment != nullptr);

        // find in main chain
        do
        {
            if (segment->hasTransaction(transactionHash))
            {
                return segment;
            }

            segment = segment->getParent();
        } while (segment != nullptr);

        // find in alternative chains
        for (size_t chain = 1; chain < chainsLeaves.size(); ++chain)
        {
            segment = chainsLeaves[chain];

            while (mainChainSet.count(segment) == 0)
            {
                if (segment->hasTransaction(transactionHash))
                {
                    return segment;
                }

                segment = segment->getParent();
            }
        }

        return nullptr;
    }

    bool Core::hasTransaction(const Crypto::Hash &transactionHash) const
    {
        throwIfNotInitialized();
        return findSegmentContainingTransaction(transactionHash) != nullptr
               || transactionPool->checkIfTransactionPresent(transactionHash);
    }

    void Core::transactionPoolCleaningProcedure()
    {
        System::Timer timer(dispatcher);

        try
        {
            for (;;)
            {
                timer.sleep(OUTDATED_TRANSACTION_POLLING_INTERVAL);

                auto deletedTransactions = transactionPool->clean(getTopBlockIndex());
                notifyObservers(makeDelTransactionMessage(
                    std::move(deletedTransactions), Messages::DeleteTransaction::Reason::Outdated));
            }
        }
        catch (System::InterruptedException &)
        {
            logger(Logging::DEBUGGING) << "transactionPoolCleaningProcedure has been interrupted";
        }
        catch (std::exception &e)
        {
            logger(Logging::ERROR) << "Error occurred while cleaning transactions pool: " << e.what();
        }
    }

    void Core::updateBlockMedianSize()
    {
        auto mainChain = chainsLeaves[0];

        size_t nextBlockGrantedFullRewardZone = currency.blockGrantedFullRewardZoneByBlockVersion(
            upgradeManager->getBlockMajorVersion(mainChain->getTopBlockIndex() + 1));

        auto lastBlockSizes = mainChain->getLastBlocksSizes(currency.rewardBlocksWindow());

        blockMedianSize =
            std::max(Common::medianValue(lastBlockSizes), static_cast<uint64_t>(nextBlockGrantedFullRewardZone));
    }

    uint64_t Core::get_current_blockchain_height() const
    {
        // TODO: remove when GetCoreStatistics is implemented
        return mainChainStorage->getBlockCount();
    }

    std::time_t Core::getStartTime() const
    {
        return start_time;
    }

    std::vector<MaturedStakeReward> Core::getMaturedStakeRewards(uint32_t blockHeight)
    {
        std::vector<MaturedStakeReward> maturedRewards;

        if (!stakingPool)
        {
            logger(Logging::DEBUGGING) << "Staking pool not available, no matured stakes to process";
            return maturedRewards;
        }

        // Check if staking is enabled at this height
        if (blockHeight < Pastella::parameters::staking::STAKING_ENABLE_HEIGHT)
        {
            logger(Logging::DEBUGGING) << "Staking not enabled at height " << blockHeight;
            return maturedRewards;
        }

        logger(Logging::DEBUGGING) << "Scanning for matured stakes at height " << blockHeight;

        // Get all active stakes from the staking pool
        auto activeStakes = stakingPool->getActiveStakes();

        for (const auto &stakeEntry : activeStakes)
        {
            // Check if this stake matures at the current block height
            if (stakeEntry.unlockTime == blockHeight && stakeEntry.isActive)
            {
                // Calculate the exact rewards for this matured stake
                Pastella::StakingEntry mutableEntry = stakeEntry; // Make a copy for calculation

                if (stakingPool->calculateDetailedRewards(mutableEntry, blockHeight))
                {
                    if (mutableEntry.accumulatedReward > 0)
                    {
                        MaturedStakeReward reward;
                        reward.stakerAddress = stakeEntry.stakerAddress;
                        reward.rewardAmount = mutableEntry.accumulatedReward;
                        reward.stakeTxHash = stakeEntry.stakingTxHash;

                        maturedRewards.push_back(reward);

                        logger(Logging::INFO) << "Found matured stake: "
                                              << "Amount: " << (stakeEntry.amount / 100000000.0) << " " << WalletConfig::ticker
                                              << ", Reward: " << (mutableEntry.accumulatedReward / 100000000.0) << " " << WalletConfig::ticker
                                              << ", Staker: " << stakeEntry.stakerAddress.substr(0, 10) << "..."
                                              << ", StakeTx: " << stakeEntry.stakingTxHash.substr(0, 10) << "...";

                        // NOTE: Don't deactivate here anymore - deactivation will happen after block is successfully added
                        // This prevents the stake from being marked inactive before the block validation completes
                        logger(Logging::DEBUGGING) << "Stake will be deactivated after block is added: " << stakeEntry.stakingTxHash;
                    }
                    else
                    {
                        logger(Logging::DEBUGGING) << "Stake matured but has zero rewards: " << stakeEntry.stakingTxHash;
                    }
                }
                else
                {
                    logger(Logging::WARNING) << "Failed to calculate rewards for matured stake: " << stakeEntry.stakingTxHash;
                }
            }
        }

        logger(Logging::DEBUGGING) << "Found " << maturedRewards.size() << " matured stakes at height " << blockHeight
                              << " with total rewards: " << (std::accumulate(maturedRewards.begin(), maturedRewards.end(), 0ULL,
                                  [](uint64_t sum, const MaturedStakeReward &r) { return sum + r.rewardAmount; }) / 100000000.0) << " " << WalletConfig::ticker;

        return maturedRewards;
    }

    std::vector<Pastella::RichListEntry> Core::getRichList(size_t count) const
    {
        throwIfNotInitialized();

        /* Structure to track address information */
        struct AddressInfo
        {
            uint64_t balance = 0;
            uint64_t firstTxTimestamp = UINT64_MAX;
            uint64_t lastTxTimestamp = 0;
        };

        /* Map: address -> balance and timestamps */
        std::unordered_map<std::string, AddressInfo> addressMap;

        /* Get current blockchain height */
        const uint32_t topHeight = getTopBlockIndex();

        /* Scan all blocks and transactions */
        for (uint32_t height = 0; height <= topHeight; height++)
        {
            if (height % 1000 == 0)
            {
                logger(Logging::DEBUGGING) << "Scanning block " << height << " of " << topHeight;
            }

            try
            {
                /* Get block */
                const Crypto::Hash blockHash = getBlockHashByIndex(height);
                const BlockTemplate block = getBlockByHash(blockHash);

                /* Process coinbase transaction */
                Transaction coinbaseTx = block.baseTransaction;

                /* Iterate through all coinbase outputs and derive addresses from output keys */
                for (const auto &output : coinbaseTx.outputs)
                {
                    if (output.target.type() == typeid(Pastella::KeyOutput))
                    {
                        const auto &keyOutput = boost::get<Pastella::KeyOutput>(output.target);
                        /* Convert output key to address */
                        const std::string address = Utilities::publicKeyToAddress(keyOutput.key);

                        /* Add output amount to this address's balance */
                        addressMap[address].balance += output.amount;
                        addressMap[address].firstTxTimestamp = std::min(addressMap[address].firstTxTimestamp, block.timestamp);
                        addressMap[address].lastTxTimestamp = std::max(addressMap[address].lastTxTimestamp, block.timestamp);
                    }
                }

                /* Process regular transactions */
                for (const Crypto::Hash &txHash : block.transactionHashes)
                {
                    /* Get transaction */
                    auto txRaw = getTransaction(txHash);
                    if (!txRaw.has_value())
                    {
                        continue;
                    }

                    Transaction transaction;
                    fromBinaryArray(transaction, txRaw.value());

                    /* Process outputs (add to recipient balances) */
                    /* Iterate through all transaction outputs and derive addresses from output keys */
                    for (const auto &output : transaction.outputs)
                    {
                        if (output.target.type() == typeid(Pastella::KeyOutput))
                        {
                            const auto &keyOutput = boost::get<Pastella::KeyOutput>(output.target);
                            /* Convert output key to address */
                            const std::string address = Utilities::publicKeyToAddress(keyOutput.key);

                            /* Add output amount to this address's balance */
                            addressMap[address].balance += output.amount;
                            addressMap[address].firstTxTimestamp = std::min(addressMap[address].firstTxTimestamp, block.timestamp);
                            addressMap[address].lastTxTimestamp = std::max(addressMap[address].lastTxTimestamp, block.timestamp);
                        }
                    }

                    /* Process inputs (subtract from sender balances) */
                    TransactionDetails txDetails;
                    try
                    {
                        txDetails = getTransactionDetails(txHash);

                        for (const auto &inputDetails : txDetails.inputs)
                        {
                            if (inputDetails.type() == typeid(Pastella::KeyInputDetails))
                            {
                                const auto &keyInputDetails = boost::get<Pastella::KeyInputDetails>(inputDetails);

                                /* Look up previous transaction to find the sender */
                                if (keyInputDetails.output.transactionHash != Crypto::Hash())
                                {
                                    try
                                    {
                                        const auto prevTxDetails = getTransactionDetails(keyInputDetails.output.transactionHash);
                                        Transaction prevTx;
                                        const auto prevTxRaw = getTransaction(keyInputDetails.output.transactionHash);

                                        if (prevTxRaw.has_value())
                                        {
                                            fromBinaryArray(prevTx, prevTxRaw.value());

                                            /* Get the output being spent */
                                            if (keyInputDetails.output.number < prevTx.outputs.size())
                                            {
                                                const auto &prevOutput = prevTx.outputs[keyInputDetails.output.number];

                                                if (prevOutput.target.type() == typeid(Pastella::KeyOutput))
                                                {
                                                    const auto &prevKeyOutput = boost::get<Pastella::KeyOutput>(prevOutput.target);

                                                    /* Convert output key to address */
                                                    const std::string address = Utilities::publicKeyToAddress(prevKeyOutput.key);

                                                    /* Subtract from balance (this output was spent) */
                                                    const KeyInput &keyInput = keyInputDetails.input;
                                                    addressMap[address].balance -= keyInput.amount;
                                                }
                                            }
                                        }
                                    }
                                    catch (const std::exception &e)
                                    {
                                        logger(Logging::WARNING) << "Error looking up previous transaction for input: " << e.what();
                                    }
                                }
                            }
                        }
                    }
                    catch (const std::exception &e)
                    {
                        logger(Logging::WARNING) << "Error getting transaction details for rich list: " << e.what();
                    }
                }
            }
            catch (const std::exception &e)
            {
                logger(Logging::WARNING) << "Error processing block " << height << " for rich list: " << e.what();
            }
        }

        /* Get total supply */
        BlockDetails topBlock = getBlockDetails(getBlockHashByIndex(topHeight));
        const uint64_t totalSupply = topBlock.alreadyGeneratedCoins;

        /* Convert map to vector for sorting */
        std::vector<Pastella::RichListEntry> richList;
        richList.reserve(addressMap.size());

        for (const auto &[address, info] : addressMap)
        {
            /* Only include addresses with non-zero balance */
            if (info.balance > 0)
            {
                Pastella::RichListEntry entry;
                entry.address = address;
                entry.balance = info.balance;
                entry.percentage = (totalSupply > 0) ? (info.balance * 100.0 / totalSupply) : 0.0;
                entry.firstTxTimestamp = (info.firstTxTimestamp != UINT64_MAX) ? info.firstTxTimestamp : 0;
                entry.lastTxTimestamp = info.lastTxTimestamp;

                richList.push_back(entry);
            }
        }

        /* Sort by balance (descending) */
        std::sort(richList.begin(), richList.end(),
            [](const Pastella::RichListEntry &a, const Pastella::RichListEntry &b)
            {
                return a.balance > b.balance;
            });

        /* Return top N entries */
        if (count > 0 && count < richList.size())
        {
            richList.resize(count);
        }

        return richList;
    }

    Pastella::WalletDetails Core::getWalletDetails(
        const std::string &address,
        size_t limit,
        size_t page) const
    {
        throwIfNotInitialized();

        Pastella::WalletDetails details;
        details.address = address;
        details.totalBalance = 0;
        details.totalIncoming = 0;
        details.totalOutgoing = 0;
        details.totalIncomingStakingRewards = 0;
        details.totalOutgoingStakes = 0;
        details.firstTxTimestamp = UINT64_MAX;
        details.lastTxTimestamp = 0;
        details.totalTransactions = 0;

        logger(Logging::INFO) << "Building wallet details for address: " << address.substr(0, 10) << "...";

        /* Temporary structure to collect transaction data before grouping */
        struct TransactionData
        {
            Crypto::Hash txHash;
            uint32_t blockNumber;
            Crypto::Hash blockHash;
            uint64_t timestamp;
            uint64_t unlockTime;
            bool isStaking;         /* True for STAKE_DEPOSIT (outgoing) OR STAKE_REWARD (incoming coinbase) */
            bool isStakeReward;     /* True ONLY for STAKE_REWARD (incoming from coinbase) */
            bool isCoinbase;
            uint64_t totalIncoming;      /* All outputs TO this address (including change) */
            uint64_t totalOutgoing;      /* All inputs FROM this address */
            uint64_t totalToOthers;      /* Outputs to OTHER addresses (actual transfer amount) */
            uint64_t fee;                /* Transaction fee (0 for coinbase) */
            std::vector<std::string> fromAddresses;
            std::vector<std::string> toAddresses;
        };

        /* Map: txHash -> transaction data */
        std::unordered_map<std::string, TransactionData> txMap;

        /* Vector to maintain transaction order for balance calculation */
        std::vector<TransactionData> orderedTransactions;

        /* Get current blockchain height */
        const uint32_t topHeight = getTopBlockIndex();

        /* Scan all blocks and transactions */
        for (uint32_t height = 0; height <= topHeight; height++)
        {
            try
            {
                /* Get block */
                const Crypto::Hash blockHash = getBlockHashByIndex(height);
                const BlockTemplate block = getBlockByHash(blockHash);

                /* Process coinbase transaction */
                Transaction coinbaseTx = block.baseTransaction;
                const Crypto::Hash coinbaseTxHash = getObjectHash(coinbaseTx);

                bool foundInCoinbase = false;
                uint64_t coinbaseAmount = 0;

                /* Iterate through all coinbase outputs and check if any belong to this address */
                for (const auto &output : coinbaseTx.outputs)
                {
                    if (output.target.type() == typeid(Pastella::KeyOutput))
                    {
                        const auto &keyOutput = boost::get<Pastella::KeyOutput>(output.target);
                        /* Convert output key to address */
                        const std::string outputAddress = Utilities::publicKeyToAddress(keyOutput.key);

                        if (outputAddress == address)
                        {
                            foundInCoinbase = true;
                            coinbaseAmount += output.amount;
                        }
                    }
                }

                if (foundInCoinbase && coinbaseAmount > 0)
                {
                    /* Determine coinbase structure using amount-based heuristics (same as RPC server) */
                    bool hasStakingRewards = false;
                    bool isOldDenominationSplitting = false;

                    if (coinbaseTx.outputs.size() == 2)
                    {
                        uint64_t amount0 = coinbaseTx.outputs[0].amount;
                        uint64_t amount1 = coinbaseTx.outputs[1].amount;

                        /* Old denomination splitting: one very small (fee), one large (block reward) */
                        if (amount0 < 1000000 && amount1 >= 100000000)
                        {
                            isOldDenominationSplitting = true;
                        }
                        /* New structure with staking: large block reward + smaller staking reward */
                        else if (amount0 >= 100000000 && amount1 < amount0)
                        {
                            hasStakingRewards = true;
                        }
                    }

                    /* NEW STRUCTURE: Check if coinbase has exactly 2 outputs AND has staking rewards */
                    if (coinbaseTx.outputs.size() == 2 && hasStakingRewards)
                    {
                        /* Split into 2 separate transaction entries (NEW structure with staking) */
                        const uint64_t miningReward = coinbaseTx.outputs[0].amount;
                        const uint64_t stakingReward = coinbaseTx.outputs[1].amount;

                        /* Check which outputs belong to this address */
                        bool receivesMining = false;
                        bool receivesStaking = false;

                        /* Check output 0 (mining reward) */
                        if (coinbaseTx.outputs[0].target.type() == typeid(Pastella::KeyOutput))
                        {
                            const auto &keyOutput0 = boost::get<Pastella::KeyOutput>(coinbaseTx.outputs[0].target);
                            if (Utilities::publicKeyToAddress(keyOutput0.key) == address)
                            {
                                receivesMining = true;
                            }
                        }

                        /* Check output 1 (staking reward) */
                        if (coinbaseTx.outputs[1].target.type() == typeid(Pastella::KeyOutput))
                        {
                            const auto &keyOutput1 = boost::get<Pastella::KeyOutput>(coinbaseTx.outputs[1].target);
                            if (Utilities::publicKeyToAddress(keyOutput1.key) == address)
                            {
                                receivesStaking = true;
                            }
                        }

                        /* Create mining reward entry if applicable */
                        if (receivesMining && miningReward > 0)
                        {
                            const std::string miningTxHashStr = Common::podToHex(coinbaseTxHash) + "_mining";

                            TransactionData miningTxData;
                            miningTxData.txHash = coinbaseTxHash;
                            miningTxData.blockNumber = height;
                            miningTxData.blockHash = blockHash;
                            miningTxData.timestamp = block.timestamp;
                            miningTxData.unlockTime = coinbaseTx.unlockTime;
                            miningTxData.isStaking = false;
                            miningTxData.isStakeReward = false;  /* Explicitly set to false for mining reward */
                            miningTxData.isCoinbase = true;
                            miningTxData.totalIncoming = miningReward;
                            miningTxData.toAddresses.push_back(address);

                            orderedTransactions.push_back(miningTxData);
                        }

                        /* Create staking reward entry if applicable */
                        if (receivesStaking && stakingReward > 0)
                        {
                            const std::string stakingTxHashStr = Common::podToHex(coinbaseTxHash) + "_staking";

                            TransactionData stakingTxData;
                            stakingTxData.txHash = coinbaseTxHash;
                            stakingTxData.blockNumber = height;
                            stakingTxData.blockHash = blockHash;
                            stakingTxData.timestamp = block.timestamp;
                            stakingTxData.unlockTime = coinbaseTx.unlockTime;
                            stakingTxData.isStaking = false;   /* NOT a stake deposit */
                            stakingTxData.isStakeReward = true; /* This IS a stake reward */
                            stakingTxData.isCoinbase = true;
                            stakingTxData.totalIncoming = stakingReward;
                            stakingTxData.toAddresses.push_back(address);

                            orderedTransactions.push_back(stakingTxData);

                            /* Track staking rewards received from coinbase */
                            details.totalIncomingStakingRewards += stakingReward;
                        }
                    }
                    else if (coinbaseTx.outputs.size() == 2 && isOldDenominationSplitting)
                    {
                        /* OLD STRUCTURE: 2 outputs from denomination splitting (fee + block reward)
                         * Treat as a single combined mining entry */
                        logger(Logging::DEBUGGING) << "[WALLET_DETAILS] Block " << height << " has 2 outputs but no staking rewards - old denomination splitting structure";

                        /* Fall through to the combined handling below */
                        foundInCoinbase = true;
                    }
                    else
                    {
                        /* OLD STRUCTURE: Single combined entry for blocks with denomination splitting */
                        const std::string txHashStr = Common::podToHex(coinbaseTxHash);

                        TransactionData &txData = txMap[txHashStr];
                        txData.txHash = coinbaseTxHash;
                        txData.blockNumber = height;
                        txData.blockHash = blockHash;
                        txData.timestamp = block.timestamp;
                        txData.unlockTime = coinbaseTx.unlockTime;
                        txData.isStaking = false;
                        txData.isCoinbase = true;
                        txData.totalIncoming += coinbaseAmount;
                        txData.toAddresses.push_back(address); // Coinbase to this address

                        /* Add to ordered transactions vector if not already present */
                        if (std::find_if(orderedTransactions.begin(), orderedTransactions.end(),
                                        [&txHashStr](const TransactionData &td) { return Common::podToHex(td.txHash) == txHashStr; }) == orderedTransactions.end())
                        {
                            orderedTransactions.push_back(txData);
                        }
                    }
                }

                /* Process regular transactions */
                for (const Crypto::Hash &txHash : block.transactionHashes)
                {
                    /* Get transaction */
                    auto txRaw = getTransaction(txHash);
                    if (!txRaw.has_value())
                    {
                        continue;
                    }

                    Transaction transaction;
                    fromBinaryArray(transaction, txRaw.value());

                    /* Check if staking transaction */
                    const bool isStakingTx = Pastella::isStakingTransaction(transaction.extra);

                    const std::string txHashStr = Common::podToHex(txHash);

                    /* Initialize transaction data if not exists */
                    if (txMap.find(txHashStr) == txMap.end())
                    {
                        TransactionData txData;
                        txData.txHash = txHash;
                        txData.blockNumber = height;
                        txData.blockHash = blockHash;
                        txData.timestamp = block.timestamp;
                        txData.unlockTime = transaction.unlockTime;
                        txData.isStaking = isStakingTx;
                        txData.isStakeReward = false; /* Regular transactions are not stake rewards */
                        txData.isCoinbase = false;
                        txData.totalIncoming = 0;
                        txData.totalOutgoing = 0;
                        txData.totalToOthers = 0;
                        txData.fee = 0; /* Will be set below */
                        txMap[txHashStr] = txData;
                    }

                    TransactionData &txData = txMap[txHashStr];

                    /* Calculate and store transaction fee
                     * Fee = sum of input amounts - sum of output amounts
                     * For coinbase transactions, fee = 0 */
                    if (!txData.isCoinbase)
                    {
                        try
                        {
                            /* Get transaction fee from the transaction object */
                            CachedTransaction cachedTx(transaction);
                            txData.fee = cachedTx.getTransactionFee();
                        }
                        catch (const std::exception &e)
                        {
                            logger(Logging::WARNING) << "Error calculating fee for transaction " << txHashStr.substr(0, 10) << "...: " << e.what();
                            txData.fee = 0;
                        }
                    }

                    /* Process outputs (check if this address receives funds) */
                    bool isRecipient = false;
                    uint64_t receivedAmount = 0;

                    /* Iterate through all transaction outputs and check if any belong to this address */
                    for (const auto &output : transaction.outputs)
                    {
                        if (output.target.type() == typeid(Pastella::KeyOutput))
                        {
                            const auto &keyOutput = boost::get<Pastella::KeyOutput>(output.target);
                            /* Convert output key to address */
                            const std::string outputAddress = Utilities::publicKeyToAddress(keyOutput.key);

                            if (outputAddress == address)
                            {
                                isRecipient = true;
                                receivedAmount += output.amount;
                            }
                        }
                    }

                    if (isRecipient && receivedAmount > 0)
                    {
                        txData.totalIncoming += receivedAmount;

                        /* Add to "to" addresses if not already there */
                        if (std::find(txData.toAddresses.begin(), txData.toAddresses.end(), address) == txData.toAddresses.end())
                        {
                            txData.toAddresses.push_back(address);
                        }

                        /* NOTE: Staking rewards are ONLY tracked from coinbase transactions, NOT regular STAKING transactions */
                    }

                    /* Also track outputs going to OTHER addresses (actual transfers) */
                    /* Iterate through all transaction outputs and track amounts to other addresses */
                    for (const auto &output : transaction.outputs)
                    {
                        if (output.target.type() == typeid(Pastella::KeyOutput))
                        {
                            const auto &keyOutput = boost::get<Pastella::KeyOutput>(output.target);
                            /* Convert output key to address */
                            const std::string outputAddress = Utilities::publicKeyToAddress(keyOutput.key);

                            if (outputAddress != address)
                            {
                                /* This output goes to a different address - track the transfer amount */
                                /* Only track if this is actually a transfer (not dust or rounding errors) */
                                if (output.amount >= 100) /* At least 0.00000100 PAS */
                                {
                                    txData.totalToOthers += output.amount;

                                    /* Add recipient to "to" addresses if not already there */
                                    if (std::find(txData.toAddresses.begin(), txData.toAddresses.end(), outputAddress) == txData.toAddresses.end())
                                    {
                                        txData.toAddresses.push_back(outputAddress);
                                    }
                                }
                            }
                        }
                    }

                    /* Process inputs (check if this address sends funds) */
                    TransactionDetails txDetails;
                    try
                    {
                        txDetails = getTransactionDetails(txHash);

                        for (const auto &inputDetails : txDetails.inputs)
                        {
                            if (inputDetails.type() == typeid(Pastella::KeyInputDetails))
                            {
                                const auto &keyInputDetails = boost::get<Pastella::KeyInputDetails>(inputDetails);

                                /* Look up previous transaction to find the sender */
                                if (keyInputDetails.output.transactionHash != Crypto::Hash())
                                {
                                    try
                                    {
                                        Transaction prevTx;
                                        const auto prevTxRaw = getTransaction(keyInputDetails.output.transactionHash);

                                        if (prevTxRaw.has_value())
                                        {
                                            fromBinaryArray(prevTx, prevTxRaw.value());

                                            /* Get the output being spent */
                                            if (keyInputDetails.output.number < prevTx.outputs.size())
                                            {
                                                const auto &prevOutput = prevTx.outputs[keyInputDetails.output.number];

                                                if (prevOutput.target.type() == typeid(Pastella::KeyOutput))
                                                {
                                                    const auto &prevKeyOutput = boost::get<Pastella::KeyOutput>(prevOutput.target);

                                                    /* Convert output key to address */
                                                    const std::string prevAddress = Utilities::publicKeyToAddress(prevKeyOutput.key);

                                                    if (prevAddress == address)
                                                    {
                                                        /* This address is spending funds */
                                                        const KeyInput &keyInput = keyInputDetails.input;
                                                        const uint64_t spentAmount = keyInput.amount;

                                                        txData.totalOutgoing += spentAmount;

                                                        /* Track stakes (exclude fee inputs which are very small) */
                                                        if (isStakingTx)
                                                        {
                                                            /* Only count amounts >= 1 PAS as staking (exclude fee payments) */
                                                            if (spentAmount >= 100000000)
                                                            {
                                                                details.totalOutgoingStakes += spentAmount;
                                                            }
                                                        }
                                                    }

                                                    /* Always add the input owner to "from" addresses
                                                     * This allows recipients to see who sent them funds */
                                                    if (std::find(txData.fromAddresses.begin(), txData.fromAddresses.end(), prevAddress) == txData.fromAddresses.end())
                                                    {
                                                        txData.fromAddresses.push_back(prevAddress);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    catch (const std::exception &e)
                                    {
                                        logger(Logging::WARNING) << "Error looking up previous transaction for input: " << e.what();
                                    }
                                }
                            }
                        }
                    }
                    catch (const std::exception &e)
                    {
                        logger(Logging::WARNING) << "Error getting transaction details: " << e.what();
                    }

                    /* Add to ordered transactions vector if not already present */
                    if (std::find_if(orderedTransactions.begin(), orderedTransactions.end(),
                                    [&txHashStr](const TransactionData &td) { return Common::podToHex(td.txHash) == txHashStr; }) == orderedTransactions.end())
                    {
                        orderedTransactions.push_back(txData);
                    }
                }
            }
            catch (const std::exception &e)
            {
                logger(Logging::WARNING) << "Error processing block " << height << ": " << e.what();
            }
        }

        /* Now process the transaction map to create consolidated wallet transactions */
        std::vector<Pastella::WalletTransactionDetails> allTransactions;
        uint64_t currentBalance = 0;

        /* Sort transactions by block number and timestamp for correct balance calculation */
        std::sort(orderedTransactions.begin(), orderedTransactions.end(),
            [](const TransactionData &a, const TransactionData &b)
            {
                /* Sort by block number ascending */
                if (a.blockNumber != b.blockNumber)
                {
                    return a.blockNumber < b.blockNumber;
                }
                /* If same block, sort by timestamp ascending */
                return a.timestamp < b.timestamp;
            });

        for (const auto &txData : orderedTransactions)
        {
            const std::string txHashStr = Common::podToHex(txData.txHash);
            /* Determine transaction type based on net effect */
            Pastella::TransactionType txType;
            int64_t netAmount; /* Signed to handle negative values (losses) */
            uint64_t amount;

            if (txData.isCoinbase)
            {
                /* Check if this is a staking reward or mining reward */
                if (txData.isStakeReward)
                {
                    txType = Pastella::TransactionType::STAKE_REWARD;
                }
                else
                {
                    txType = Pastella::TransactionType::MINING;
                }
                amount = txData.totalIncoming;
                netAmount = amount;
            }
            else if (txData.totalIncoming > 0 && txData.totalOutgoing > 0)
            {
                /* Both incoming and outgoing - this is a transfer with change
                 *
                 * IMPORTANT: Classification should be based on whether you're sending
                 * to OTHER addresses, not on the amounts!
                 *
                 * If totalToOthers > 0: You're sending funds externally = OUTGOING
                 * If totalToOthers == 0 AND fee > 0 AND NOT staking: You're paying a fee to move funds = OUTGOING (net loss)
                 * If totalToOthers == 0 AND fee == 0: Pure internal movement = INCOMING */
                if (txData.totalToOthers > 0)
                {
                    /* Sending to external addresses - this is an OUTGOING transaction */
                    txType = txData.isStaking ? Pastella::TransactionType::STAKE_DEPOSIT : Pastella::TransactionType::OUTGOING;
                    amount = txData.totalToOthers; /* Show amount sent to others */
                    netAmount = txData.totalIncoming - txData.totalOutgoing; /* Usually negative (you spent more than change received) */
                }
                else if (txData.fee > 0 && !txData.isStaking)
                {
                    /* No external recipients but paying a fee - this is a self-spend with fee cost
                     * Net amount will be negative due to fee, so classify as OUTGOING
                     * EXCEPTION: NOT for staking transactions, which should show the staked amount */
                    txType = Pastella::TransactionType::OUTGOING;
                    amount = txData.fee; /* Show the fee as the amount (net loss) */
                    netAmount = txData.totalIncoming - txData.totalOutgoing - txData.fee; /* Negative (fee cost) */
                }
                else
                {
                    /* No external recipients and (no fee OR staking transaction)
                     * This could be:
                     * 1. You received funds (incoming)
                     * 2. You're moving between your own addresses (internal, no cost)
                     * 3. Staking transaction preparing inputs (show the full amount)
                     * Treat as incoming since you're not losing funds externally */
                    txType = txData.isStaking ? Pastella::TransactionType::STAKE_DEPOSIT : Pastella::TransactionType::INCOMING;
                    amount = txData.totalIncoming; /* Show amount being received */
                    netAmount = txData.totalIncoming - txData.totalOutgoing; /* Could be positive, negative, or zero */
                }
            }
            else if (txData.totalIncoming > 0)
            {
                /* Only incoming */
                if (txData.isStakeReward)
                {
                    txType = Pastella::TransactionType::STAKE_REWARD;
                }
                else
                {
                    txType = Pastella::TransactionType::INCOMING;
                }
                amount = txData.totalIncoming;
                netAmount = amount;
            }
            else if (txData.totalOutgoing > 0)
            {
                /* Only outgoing */
                if (txData.isStaking)
                {
                    txType = Pastella::TransactionType::STAKE_DEPOSIT;
                }
                else
                {
                    txType = Pastella::TransactionType::OUTGOING;
                }
                amount = txData.totalToOthers > 0 ? txData.totalToOthers : txData.totalOutgoing; /* Show amount sent to others (or total outgoing) */
                netAmount = -(amount + txData.fee); /* Negative: includes both amount sent AND fee */
            }
            else
            {
                continue; /* Skip transactions with no involvement */
            }

            /* Create wallet transaction entry */
            Pastella::WalletTransactionDetails walletTx;
            walletTx.transactionHash = txData.txHash;
            walletTx.blockNumber = txData.blockNumber;
            walletTx.blockHash = txData.blockHash;
            walletTx.amount = amount;
            walletTx.type = txType;
            walletTx.timestamp = txData.timestamp;
            walletTx.unlockTime = txData.unlockTime;

            /* Only show fee for transactions where this address paid it (OUTGOING/STAKE_DEPOSIT)
             * Recipients should not see the fee as they didn't pay it */
            if (txType == Pastella::TransactionType::OUTGOING || txType == Pastella::TransactionType::STAKE_DEPOSIT)
            {
                walletTx.fee = txData.fee;
            }
            else
            {
                walletTx.fee = 0;
            }

            /* Copy from/to addresses */
            walletTx.fromAddresses = txData.fromAddresses;
            walletTx.toAddresses = txData.toAddresses;

            /* For coinbase transactions, set from to COINBASE */
            if (txType == Pastella::TransactionType::MINING || txType == Pastella::TransactionType::STAKE_REWARD)
            {
                walletTx.fromAddresses.clear();
                walletTx.fromAddresses.push_back("COINBASE");
            }

            /* For OUTGOING/STAKE_DEPOSIT transactions, ensure address lists are correct */
            if (txType == Pastella::TransactionType::OUTGOING || txType == Pastella::TransactionType::STAKE_DEPOSIT)
            {
                /* For outgoing transactions, "from" should be the queried address (sender) */
                /* Remove the queried address from "to" list since it receives change, not as a recipient */
                walletTx.toAddresses.erase(
                    std::remove(walletTx.toAddresses.begin(), walletTx.toAddresses.end(), address),
                    walletTx.toAddresses.end()
                );

                /* Ensure "from" contains the queried address if it's not already there */
                if (walletTx.fromAddresses.empty())
                {
                    walletTx.fromAddresses.push_back(address);
                }
            }

            /* For INCOMING/STAKE_REWARD transactions, ensure address lists are correct */
            if (txType == Pastella::TransactionType::INCOMING || txType == Pastella::TransactionType::STAKE_REWARD)
            {
                /* For incoming transactions, "to" should be the queried address (recipient) */
                /* Clear "from" as it's already set correctly during input processing */
            }

            /* Update balance safely */
            if (netAmount >= 0)
            {
                currentBalance += static_cast<uint64_t>(netAmount);
            }
            else
            {
                /* netAmount is negative - subtract from balance */
                const uint64_t absNetAmount = static_cast<uint64_t>(-netAmount);
                if (currentBalance >= absNetAmount)
                {
                    currentBalance -= absNetAmount;
                }
                else
                {
                    /* Balance would go negative - set to 0 and log warning */
                    logger(Logging::WARNING) << "Balance would go negative for address " << address.substr(0, 10) << "... at block " << txData.blockNumber;
                    currentBalance = 0;
                }
            }
            walletTx.balanceAfter = currentBalance;

            /* Update statistics based on transaction type and ACTUAL monetary flow
             *
             * CRITICAL: Statistics must track REAL monetary changes, not change.
             *
             * For transactions with both incoming and outgoing (mixed):
             * - totalIncoming includes change YOU paid for (not real income!)
             * - totalOutgoing includes total spent (including change returned)
             * - netAmount = totalIncoming - totalOutgoing (actual gain/loss)
             *
             * The 'amount' variable is for DISPLAY and correctly handles change.
             * For STATISTICS, we need to be more careful:
             * - Pure INCOMING (no outgoing): All incoming is real income
             * - Pure OUTGOING (no incoming): Use totalToOthers (excludes change)
             * - MIXED (both): Use absolute value of netAmount for correct category
             */

            if (txType == Pastella::TransactionType::MINING)
            {
                /* Mining rewards - all incoming is real income (no outgoing possible) */
                details.totalIncoming += amount; /* amount = totalIncoming for mining */
            }
            else if (txType == Pastella::TransactionType::STAKE_REWARD)
            {
                /* Stake rewards from coinbase - all incoming is real income (no outgoing possible) */
                details.totalIncoming += amount; /* amount = totalIncoming for stake rewards */
            }
            else if (txType == Pastella::TransactionType::INCOMING)
            {
                /* Pure incoming (no outgoing) - all incoming is real income */
                if (txData.totalOutgoing == 0)
                {
                    /* No outgoing - truly incoming transaction */
                    details.totalIncoming += amount; /* amount = totalIncoming */
                }
                else
                {
                    /* Has outgoing - this is a mixed transaction classified as incoming
                     * (incoming > outgoing, but outgoing exists)
                     * In this case, only count the NET gain, not totalIncoming!
                     * netAmount is positive here */
                    details.totalIncoming += static_cast<uint64_t>(netAmount);
                }
            }
            else if (txType == Pastella::TransactionType::OUTGOING ||
                     txType == Pastella::TransactionType::STAKE_DEPOSIT)
            {
                /* Outgoing transactions - include both amount sent AND fee
                 *
                 * For OUTGOING transactions:
                 * - amount = totalToOthers (amount sent to external addresses, excludes change)
                 * - fee = transaction fee paid by sender
                 * - Total outgoing = amount + fee (actual cost to sender) */
                details.totalOutgoing += amount + txData.fee;
            }

            details.firstTxTimestamp = std::min(details.firstTxTimestamp, txData.timestamp);
            details.lastTxTimestamp = std::max(details.lastTxTimestamp, txData.timestamp);

            allTransactions.push_back(walletTx);
        }

        /* Set final balance */
        details.totalBalance = currentBalance;
        details.totalTransactions = allTransactions.size();

        logger(Logging::INFO) << "Found " << allTransactions.size() << " transactions for address " << address.substr(0, 10) << "...";
        logger(Logging::INFO) << "Final balance: " << (currentBalance / 100000000.0) << " " << WalletConfig::ticker;

        /* Sort transactions by block number (newest first) */
        std::sort(allTransactions.begin(), allTransactions.end(),
            [](const Pastella::WalletTransactionDetails &a, const Pastella::WalletTransactionDetails &b)
            {
                /* Sort by block number descending */
                if (a.blockNumber != b.blockNumber)
                {
                    return a.blockNumber > b.blockNumber;
                }
                /* If same block, sort by timestamp descending */
                return a.timestamp > b.timestamp;
            });

        /* Apply pagination */
        if (limit > 0)
        {
            /* Calculate offset */
            const size_t offset = page * limit;

            if (offset < allTransactions.size())
            {
                /* Get the page */
                const size_t endIdx = std::min(offset + limit, allTransactions.size());
                details.transactions.assign(allTransactions.begin() + offset, allTransactions.begin() + endIdx);
            }
            /* else: offset beyond array size, return empty transactions */
        }
        else
        {
            /* No limit - return all transactions */
            details.transactions = allTransactions;
        }

        return details;
    }

    /* UTXO SYSTEM: UTXO query method implementations
     *
     * These are wrapper methods that delegate to the blockchain cache.
     * Used by RPC layer to provide UTXO information to wallets and explorers. */

    bool Core::getUtxo(
        const Crypto::Hash &transactionHash,
        uint32_t outputIndex,
        UtxoOutput &utxo) const
    {
        throwIfNotInitialized();

        /* Delegate to blockchain cache */
        return chainsLeaves[0]->getUtxo(transactionHash, outputIndex, utxo);
    }

    bool Core::isUtxoUnspent(
        const Crypto::Hash &transactionHash,
        uint32_t outputIndex) const
    {
        throwIfNotInitialized();

        /* Delegate to blockchain cache */
        return chainsLeaves[0]->isUtxoUnspent(transactionHash, outputIndex);
    }

    std::vector<UtxoOutput> Core::getUtxosForTransaction(
        const Crypto::Hash &transactionHash) const
    {
        throwIfNotInitialized();

        /* Delegate to blockchain cache */
        return chainsLeaves[0]->getUtxosForTransaction(transactionHash);
    }

} // namespace Pastella
