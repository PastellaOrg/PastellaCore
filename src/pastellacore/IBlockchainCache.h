// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "common/ArrayView.h"
#include "pastellacore/CachedBlock.h"
#include "pastellacore/CachedTransaction.h"
#include "pastellacore/TransactionValidatiorState.h"
#include "pastellacore/UtxoOutput.h"

#include <Pastella.h>
#include <unordered_map>
#include <vector>

namespace Pastella
{
    class ISerializer;

    struct TransactionValidatorState;

    enum class ExtractOutputKeysResult
    {
        SUCCESS,
        INVALID_GLOBAL_INDEX,
        OUTPUT_LOCKED
    };

    union PackedOutIndex {
        struct
        {
            uint32_t blockIndex;
            uint16_t transactionIndex;
            uint16_t outputIndex;
        };

        uint64_t packedValue;
    };

    const uint32_t INVALID_BLOCK_INDEX = std::numeric_limits<uint32_t>::max();

    struct PushedBlockInfo
    {
        RawBlock rawBlock;
        TransactionValidatorState validatorState;
        size_t blockSize;
        uint64_t generatedCoins;
        uint64_t blockDifficulty;
    };

    class UseGenesis
    {
      public:
        explicit UseGenesis(bool u): use(u) {}

        // emulate boolean flag
        operator bool()
        {
            return use;
        }

      private:
        bool use = false;
    };

    struct CachedBlockInfo;
    struct CachedTransactionInfo;

    class ITransactionPool;

    class IBlockchainCache
    {
      public:
        using BlockIndex = uint32_t;
        using GlobalOutputIndex = uint32_t;
        using Amount = uint64_t;

        virtual ~IBlockchainCache() {}

        virtual RawBlock getBlockByIndex(uint32_t index) const = 0;

        virtual BinaryArray getRawTransaction(uint32_t blockIndex, uint32_t transactionIndex) const = 0;

        virtual std::unique_ptr<IBlockchainCache> split(uint32_t splitBlockIndex) = 0;

        virtual void pushBlock(
            const CachedBlock &cachedBlock,
            const std::vector<CachedTransaction> &cachedTransactions,
            const TransactionValidatorState &validatorState,
            size_t blockSize,
            uint64_t generatedCoins,
            uint64_t blockDifficulty,
            RawBlock &&rawBlock) = 0;

        virtual PushedBlockInfo getPushedBlockInfo(uint32_t index) const = 0;

        /* TRANSPARENT SYSTEM: checkIfSpent interface still functional
         *
         * Original: Checked if KeyImage was spent by given block
         * Transparent system: Interface maintained for backward compatibility
         *
         * Current implementation (BlockchainCache.cpp:508-533):
         * - Still uses spentKeyImages container (now stores transaction hashes)
         * - Type changed from KeyImage to PublicKey (binary-compatible, both 32-byte ed25519)
         * - Interface works but is not the primary double-spend mechanism
         *
         * Primary double-spend prevention:
         * - Validation layer: ValidateTransaction.cpp via spentTransactions set
         * - This interface is legacy/compatibility layer, not main protection
         */
        virtual bool checkIfSpent(const Crypto::PublicKey &keyImage, uint32_t blockIndex) const = 0;

        virtual bool checkIfSpent(const Crypto::PublicKey &keyImage) const = 0;

        virtual bool isTransactionSpendTimeUnlocked(uint64_t unlockTime) const = 0;

        virtual bool isTransactionSpendTimeUnlocked(uint64_t unlockTime, uint32_t blockIndex) const = 0;

        /* GLOBAL INDEX TRACKING REMOVED - extractKeyOutputKeys methods removed (4 overloads) */

        /* GLOBAL INDEX TRACKING REMOVED - extractKeyOutputs method removed (used globalIndexes) */

        virtual uint32_t getTopBlockIndex() const = 0;

        virtual const Crypto::Hash &getTopBlockHash() const = 0;

        virtual uint32_t getBlockCount() const = 0;

        virtual bool hasBlock(const Crypto::Hash &blockHash) const = 0;

        virtual uint32_t getBlockIndex(const Crypto::Hash &blockHash) const = 0;

        virtual bool hasTransaction(const Crypto::Hash &transactionHash) const = 0;

        virtual std::vector<uint64_t> getLastTimestamps(size_t count) const = 0;

        virtual std::vector<uint64_t> getLastTimestamps(size_t count, uint32_t blockIndex, UseGenesis) const = 0;

        virtual std::vector<uint64_t> getLastBlocksSizes(size_t count) const = 0;

        virtual std::vector<uint64_t> getLastBlocksSizes(size_t count, uint32_t blockIndex, UseGenesis) const = 0;

        virtual std::vector<uint64_t>
            getLastCumulativeDifficulties(size_t count, uint32_t blockIndex, UseGenesis) const = 0;

        virtual std::vector<uint64_t> getLastCumulativeDifficulties(size_t count) const = 0;

        virtual uint64_t getDifficultyForNextBlock() const = 0;

        virtual uint64_t getDifficultyForNextBlock(uint32_t blockIndex) const = 0;

        virtual uint64_t getCurrentCumulativeDifficulty() const = 0;

        virtual uint64_t getCurrentCumulativeDifficulty(uint32_t blockIndex) const = 0;

        virtual uint64_t getAlreadyGeneratedCoins() const = 0;

        virtual uint64_t getAlreadyGeneratedCoins(uint32_t blockIndex) const = 0;

        virtual uint64_t getAlreadyGeneratedTransactions(uint32_t blockIndex) const = 0;

        virtual Crypto::Hash getBlockHash(uint32_t blockIndex) const = 0;

        virtual std::vector<Crypto::Hash> getBlockHashes(uint32_t startIndex, size_t maxCount) const = 0;

        virtual IBlockchainCache *getParent() const = 0;

        virtual void setParent(IBlockchainCache *parent) = 0;

        virtual uint32_t getStartBlockIndex() const = 0;

        virtual size_t getKeyOutputsCountForAmount(uint64_t amount, uint32_t blockIndex) const = 0;

        virtual std::tuple<bool, uint64_t> getBlockHeightForTimestamp(uint64_t timestamp) const = 0;

        virtual uint32_t getTimestampLowerBoundBlockIndex(uint64_t timestamp) const = 0;

        // NOTE: shouldn't be recursive otherwise we'll get quadratic complexity
        virtual void getRawTransactions(
            const std::vector<Crypto::Hash> &transactions,
            std::vector<BinaryArray> &foundTransactions,
            std::vector<Crypto::Hash> &missedTransactions) const = 0;

        virtual std::vector<BinaryArray> getRawTransactions(
            const std::vector<Crypto::Hash> &transactions,
            std::vector<Crypto::Hash> &missedTransactions) const = 0;

        virtual std::vector<BinaryArray> getRawTransactions(const std::vector<Crypto::Hash> &transactions) const = 0;

        /* GLOBAL INDEX TRACKING REMOVED - getTransactionGlobalIndexes and getGlobalIndexes methods removed */

        virtual size_t getTransactionCount() const = 0;

        virtual uint32_t getBlockIndexContainingTx(const Crypto::Hash &transactionHash) const = 0;

        virtual size_t getChildCount() const = 0;

        virtual void addChild(IBlockchainCache *) = 0;

        virtual bool deleteChild(IBlockchainCache *) = 0;

        virtual void save() = 0;

        virtual void load() = 0;

        virtual std::vector<uint64_t> getLastUnits(
            size_t count,
            uint32_t blockIndex,
            UseGenesis use,
            std::function<uint64_t(const CachedBlockInfo &)> pred) const = 0;

        virtual std::vector<Crypto::Hash> getTransactionHashes() const = 0;

        virtual std::vector<uint32_t>
            getRandomOutsByAmount(uint64_t amount, size_t count, uint32_t blockIndex) const = 0;

        /* UTXO SYSTEM: Query methods for UTXO tracking
         *
         * In transparent system, UTXOs are queried to:
         * - Check if an output exists and is unspent
         * - Get UTXO details for transaction validation
         * - Get UTXOs for specific transaction (for wallet sync)
         */

        /* Get a specific UTXO by (transactionHash, outputIndex)
         * Returns true if UTXO exists (whether spent or unspent)
         * Used to check if output exists before spending */
        virtual bool getUtxo(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex,
            UtxoOutput &utxo) const = 0;

        /* Check if a UTXO is currently unspent
         * Returns true if UTXO exists and spent == false
         * Used for double-spend protection */
        virtual bool isUtxoUnspent(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex) const = 0;

        /* Get all UTXOs created by a transaction
         * Returns vector of UTXOs (both spent and unspent)
         * Used for wallet synchronization and balance calculation */
        virtual std::vector<UtxoOutput> getUtxosForTransaction(
            const Crypto::Hash &transactionHash) const = 0;

        /* Get all UTXOs in the network with pagination
         * Returns tuple of: (success, vector of UTXOs for this page, total UTXO count)
         * Used by RPC endpoint /getutxos to query network UTXOs */
        virtual std::tuple<bool, std::vector<UtxoOutput>, uint64_t> getAllUtxos(
            uint64_t page,
            uint64_t limit) const = 0;

        virtual std::vector<Crypto::Hash>
            getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount) const = 0;

        virtual std::vector<RawBlock> getBlocksByHeight(const uint64_t startHeight, uint64_t endHeight) const = 0;

        virtual std::vector<RawBlock> getNonEmptyBlocks(const uint64_t startHeight, const size_t blockCount) const = 0;
    };

} // namespace Pastella
