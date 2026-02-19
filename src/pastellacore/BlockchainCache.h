// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "BlockchainStorage.h"
#include "Currency.h"
#include "IBlockchainCache.h"
#include "UtxoOutput.h"
#include "common/StringView.h"
#include "pastellacore/UpgradeManager.h"

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index_container.hpp>
#include <map>
#include <unordered_map>
#include <vector>

namespace Pastella
{
    class ISerializer;

    struct SpentKeyImage
    {
        uint32_t blockIndex;

        /* TRANSPARENT SYSTEM: Repurposed struct for transaction hash tracking
         *
         * Transparent system: Stores transaction hash (as PublicKey for compatibility)
         *
         * Field name 'keyImage' is misleading but kept for:
         * 1. Database schema compatibility (column name in database)
         * 2. Binary compatibility (both KeyImage and PublicKey are 32-byte ed25519 values)
         * 3. Serialization compatibility
         *
         * Actual usage: Stores transaction hash to track spent transactions
         * - See: DatabaseBlockchainCache.cpp:1163-1164 (storage)
         * - See: DatabaseBlockchainCache.cpp:862-889 (retrieval for reorgs)
         */
        Crypto::PublicKey keyImage; // Actually: transactionHash stored as PublicKey

        void serialize(ISerializer &s);
    };

    struct CachedTransactionInfo
    {
        uint32_t blockIndex;

        uint32_t transactionIndex;

        Crypto::Hash transactionHash;

        uint64_t unlockTime;

        std::vector<TransactionOutputTarget> outputs;

        void serialize(ISerializer &s);
    };

    struct CachedBlockInfo
    {
        Crypto::Hash blockHash;

        uint64_t timestamp;

        uint64_t cumulativeDifficulty;

        uint64_t alreadyGeneratedCoins;

        uint64_t alreadyGeneratedTransactions;

        uint32_t blockSize;

        void serialize(ISerializer &s);
    };

    /* UTXO SYSTEM: Unspent Transaction Output tracking for transparent system
     *
     * In transparent Bitcoin-like system:
     * - UTXOs represent unspent outputs that can be spent as inputs
     * - Each UTXO is identified by (transactionHash, outputIndex)
     * - UTXOs are created when transactions are added to blockchain
     * - UTXOs are marked as spent when referenced by transaction inputs
     * - Double-spend protection: Check UTXO is unspent before allowing spend
     */

    struct UtxoKey
    {
        Crypto::Hash transactionHash;
        uint32_t outputIndex;

        bool operator==(const UtxoKey &other) const
        {
            return transactionHash == other.transactionHash && outputIndex == other.outputIndex;
        }

        bool operator!=(const UtxoKey &other) const
        {
            return !(*this == other);
        }
    };

    bool serialize(PackedOutIndex &value, Common::StringView name, Pastella::ISerializer &serializer);

    class DatabaseBlockchainCache;

    class BlockchainCache : public IBlockchainCache
    {
      public:
        BlockchainCache(
            const std::string &filename,
            const Currency &currency,
            std::shared_ptr<Logging::ILogger> logger,
            IBlockchainCache *parent,
            uint32_t startIndex = 0);

        // Returns upper part of segment. [this] remains lower part.
        // All of indexes on blockIndex == splitBlockIndex belong to upper part
        std::unique_ptr<IBlockchainCache> split(uint32_t splitBlockIndex) override;

        virtual void pushBlock(
            const CachedBlock &cachedBlock,
            const std::vector<CachedTransaction> &cachedTransactions,
            const TransactionValidatorState &validatorState,
            size_t blockSize,
            uint64_t generatedCoins,
            uint64_t blockDifficulty,
            RawBlock &&rawBlock) override;

        virtual PushedBlockInfo getPushedBlockInfo(uint32_t index) const override;

        /* STEALTH ADDRESS REMOVAL: Changed from KeyImage to PublicKey */
        bool checkIfSpent(const Crypto::PublicKey &keyImage, uint32_t blockIndex) const override;

        bool checkIfSpent(const Crypto::PublicKey &keyImage) const override;

        bool isTransactionSpendTimeUnlocked(uint64_t unlockTime) const override;

        bool isTransactionSpendTimeUnlocked(uint64_t unlockTime, uint32_t blockIndex) const override;

        /* GLOBAL INDEX TRACKING REMOVED - extractKeyOutputKeys methods removed (4 overloads) */

        uint32_t getTopBlockIndex() const override;

        const Crypto::Hash &getTopBlockHash() const override;

        uint32_t getBlockCount() const override;

        bool hasBlock(const Crypto::Hash &blockHash) const override;

        uint32_t getBlockIndex(const Crypto::Hash &blockHash) const override;

        bool hasTransaction(const Crypto::Hash &transactionHash) const override;

        std::vector<uint64_t> getLastTimestamps(size_t count) const override;

        std::vector<uint64_t> getLastTimestamps(size_t count, uint32_t blockIndex, UseGenesis) const override;

        std::vector<uint64_t> getLastBlocksSizes(size_t count) const override;

        std::vector<uint64_t> getLastBlocksSizes(size_t count, uint32_t blockIndex, UseGenesis) const override;

        std::vector<uint64_t>
            getLastCumulativeDifficulties(size_t count, uint32_t blockIndex, UseGenesis) const override;

        std::vector<uint64_t> getLastCumulativeDifficulties(size_t count) const override;

        uint64_t getDifficultyForNextBlock() const override;

        uint64_t getDifficultyForNextBlock(uint32_t blockIndex) const override;

        virtual uint64_t getCurrentCumulativeDifficulty() const override;

        virtual uint64_t getCurrentCumulativeDifficulty(uint32_t blockIndex) const override;

        uint64_t getAlreadyGeneratedCoins() const override;

        uint64_t getAlreadyGeneratedCoins(uint32_t blockIndex) const override;

        uint64_t getAlreadyGeneratedTransactions(uint32_t blockIndex) const override;

        std::vector<uint64_t> getLastUnits(
            size_t count,
            uint32_t blockIndex,
            UseGenesis use,
            std::function<uint64_t(const CachedBlockInfo &)> pred) const override;

        Crypto::Hash getBlockHash(uint32_t blockIndex) const override;

        virtual std::vector<Crypto::Hash> getBlockHashes(uint32_t startIndex, size_t maxCount) const override;

        virtual IBlockchainCache *getParent() const override;

        virtual void setParent(IBlockchainCache *p) override;

        virtual uint32_t getStartBlockIndex() const override;

        virtual size_t getKeyOutputsCountForAmount(uint64_t amount, uint32_t blockIndex) const override;

        std::tuple<bool, uint64_t> getBlockHeightForTimestamp(uint64_t timestamp) const override;

        virtual uint32_t getTimestampLowerBoundBlockIndex(uint64_t timestamp) const override;

        /* GLOBAL INDEX TRACKING REMOVED - getTransactionGlobalIndexes method removed */
        virtual size_t getTransactionCount() const override;

        virtual uint32_t getBlockIndexContainingTx(const Crypto::Hash &transactionHash) const override;

        virtual size_t getChildCount() const override;

        virtual void addChild(IBlockchainCache *child) override;

        virtual bool deleteChild(IBlockchainCache *) override;

        virtual void save() override;

        virtual void load() override;

        virtual std::vector<BinaryArray> getRawTransactions(
            const std::vector<Crypto::Hash> &transactions,
            std::vector<Crypto::Hash> &missedTransactions) const override;

        virtual std::vector<BinaryArray>
            getRawTransactions(const std::vector<Crypto::Hash> &transactions) const override;

        void getRawTransactions(
            const std::vector<Crypto::Hash> &transactions,
            std::vector<BinaryArray> &foundTransactions,
            std::vector<Crypto::Hash> &missedTransactions) const override;

        /* GLOBAL INDEX TRACKING REMOVED - getGlobalIndexes method removed */

        virtual RawBlock getBlockByIndex(uint32_t index) const override;

        virtual BinaryArray getRawTransaction(uint32_t blockIndex, uint32_t transactionIndex) const override;

        virtual std::vector<Crypto::Hash> getTransactionHashes() const override;

        virtual std::vector<uint32_t>
            getRandomOutsByAmount(uint64_t amount, size_t count, uint32_t blockIndex) const override;

        /* GLOBAL INDEX TRACKING REMOVED - extractKeyOutputs method removed */

        /* UTXO SYSTEM: Query method overrides */
        virtual bool getUtxo(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex,
            UtxoOutput &utxo) const override;

        virtual bool isUtxoUnspent(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex) const override;

        virtual std::vector<UtxoOutput> getUtxosForTransaction(
            const Crypto::Hash &transactionHash) const override;

        virtual std::tuple<bool, std::vector<UtxoOutput>, uint64_t> getAllUtxos(
            uint64_t page,
            uint64_t limit) const override;

        virtual std::vector<Crypto::Hash>
            getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount) const override;

        virtual std::vector<RawBlock>
            getBlocksByHeight(const uint64_t startHeight, const uint64_t endHeight) const override;

        virtual std::vector<RawBlock>
            getNonEmptyBlocks(const uint64_t startHeight, const size_t blockCount) const override;

      private:
        struct BlockIndexTag
        {
        };
        struct BlockHashTag
        {
        };
        struct TransactionHashTag
        {
        };
        struct KeyImageTag
        {
        };
        struct TransactionInBlockTag
        {
        };
        struct PackedOutputTag
        {
        };
        struct TimestampTag
        {
        };
        /* UTXO SYSTEM: Tags for UTXO container indexing */
        struct UtxoKeyTag
        {
        };
        struct UtxoSpentTag
        {
        };
        struct UtxoBlockIndexTag
        {
        };

        typedef boost::multi_index_container<
            SpentKeyImage,
            boost::multi_index::indexed_by<
                boost::multi_index::ordered_non_unique<
                    boost::multi_index::tag<BlockIndexTag>,
                    BOOST_MULTI_INDEX_MEMBER(SpentKeyImage, uint32_t, blockIndex)>,
                boost::multi_index::hashed_unique<
                    boost::multi_index::tag<KeyImageTag>,
                    /* STEALTH ADDRESS REMOVAL: Changed from Crypto::PublicKey to Crypto::PublicKey */
                    BOOST_MULTI_INDEX_MEMBER(SpentKeyImage, Crypto::PublicKey, keyImage)>>>
            SpentKeyImagesContainer;

        typedef boost::multi_index_container<
            CachedTransactionInfo,
            boost::multi_index::indexed_by<
                boost::multi_index::hashed_unique<
                    boost::multi_index::tag<TransactionInBlockTag>,
                    boost::multi_index::composite_key<
                        CachedTransactionInfo,
                        BOOST_MULTI_INDEX_MEMBER(CachedTransactionInfo, uint32_t, blockIndex),
                        BOOST_MULTI_INDEX_MEMBER(CachedTransactionInfo, uint32_t, transactionIndex)>>,
                boost::multi_index::ordered_non_unique<
                    boost::multi_index::tag<BlockIndexTag>,
                    BOOST_MULTI_INDEX_MEMBER(CachedTransactionInfo, uint32_t, blockIndex)>,
                boost::multi_index::hashed_unique<
                    boost::multi_index::tag<TransactionHashTag>,
                    BOOST_MULTI_INDEX_MEMBER(CachedTransactionInfo, Crypto::Hash, transactionHash)>>>
            TransactionsCacheContainer;

        /* UTXO SYSTEM: Container for UTXO tracking
         *
         * Provides fast lookup by (transactionHash, outputIndex) composite key
         * Also indexed by:
         * - spent status (for finding unspent UTXOs)
         * - blockIndex (for range queries and reorg handling)
         */
        typedef boost::multi_index_container<
            UtxoOutput,
            boost::multi_index::indexed_by<
                boost::multi_index::hashed_unique<
                    boost::multi_index::tag<UtxoKeyTag>,
                    boost::multi_index::composite_key<
                        UtxoOutput,
                        BOOST_MULTI_INDEX_MEMBER(UtxoOutput, Crypto::Hash, transactionHash),
                        BOOST_MULTI_INDEX_MEMBER(UtxoOutput, uint32_t, outputIndex) > >,
                boost::multi_index::ordered_non_unique<
                    boost::multi_index::tag<UtxoSpentTag>,
                    BOOST_MULTI_INDEX_MEMBER(UtxoOutput, bool, spent) >,
                boost::multi_index::ordered_non_unique<
                    boost::multi_index::tag<UtxoBlockIndexTag>,
                    BOOST_MULTI_INDEX_MEMBER(UtxoOutput, uint32_t, blockIndex) > >
            >
        UtxoContainer;

        typedef boost::multi_index_container<
            CachedBlockInfo,
            boost::multi_index::indexed_by<
                // The index here is blockIndex - startIndex
                boost::multi_index::random_access<boost::multi_index::tag<BlockIndexTag>>,
                boost::multi_index::hashed_unique<
                    boost::multi_index::tag<BlockHashTag>,
                    BOOST_MULTI_INDEX_MEMBER(CachedBlockInfo, Crypto::Hash, blockHash)>,
                boost::multi_index::ordered_non_unique<
                    boost::multi_index::tag<TimestampTag>,
                    BOOST_MULTI_INDEX_MEMBER(CachedBlockInfo, uint64_t, timestamp)>>>
            BlockInfoContainer;

        /* GLOBAL INDEX TRACKING REMOVED - OutputsGlobalIndexesContainer typedef removed */

        typedef std::map<BlockIndex, std::vector<std::pair<Amount, GlobalOutputIndex>>> OutputSpentInBlock;

        typedef std::set<std::pair<Amount, GlobalOutputIndex>> SpentOutputsOnAmount;

        const uint32_t CURRENT_SERIALIZATION_VERSION = 1;

        std::string filename;

        const Currency &currency;

        Logging::LoggerRef logger;

        IBlockchainCache *parent;

        // index of first block stored in this cache
        uint32_t startIndex;

        TransactionsCacheContainer transactions;

        SpentKeyImagesContainer spentKeyImages;

        /* UTXO SYSTEM: UTXO container for tracking unspent transaction outputs */
        UtxoContainer utxos;

        BlockInfoContainer blockInfos;

        /* GLOBAL INDEX TRACKING REMOVED - keyOutputsGlobalIndexes member removed */

        std::unique_ptr<BlockchainStorage> storage;

        std::vector<IBlockchainCache *> children;

        void serialize(ISerializer &s);

        /* STEALTH ADDRESS REMOVAL: Changed from KeyImage to PublicKey */
        void addSpentKeyImage(const Crypto::PublicKey &keyImage, uint32_t blockIndex);

        void pushTransaction(const CachedTransaction &tx, uint32_t blockIndex, uint16_t transactionBlockIndex);

        void splitSpentKeyImages(BlockchainCache &newCache, uint32_t splitBlockIndex);

        void splitTransactions(BlockchainCache &newCache, uint32_t splitBlockIndex);

        void splitBlocks(BlockchainCache &newCache, uint32_t splitBlockIndex);

        void splitKeyOutputsGlobalIndexes(BlockchainCache &newCache, uint32_t splitBlockIndex);

        uint32_t insertKeyOutputToGlobalIndex(uint64_t amount, PackedOutIndex output, uint32_t blockIndex);

        enum class OutputSearchResult : uint8_t
        {
            FOUND,
            NOT_FOUND,
            INVALID_ARGUMENT
        };

        TransactionValidatorState fillOutputsSpentByBlock(uint32_t blockIndex) const;

        uint8_t getBlockMajorVersionForHeight(uint32_t height) const;

        void fixChildrenParent(IBlockchainCache *p);

        void doPushBlock(
            const CachedBlock &cachedBlock,
            const std::vector<CachedTransaction> &cachedTransactions,
            const TransactionValidatorState &validatorState,
            size_t blockSize,
            uint64_t generatedCoins,
            uint64_t blockDifficulty,
            RawBlock &&rawBlock);
    };

} // namespace Pastella
