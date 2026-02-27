// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "AddBlockErrorCondition.h"
#include "AddBlockErrors.h"
#include "BlockchainExplorerData.h"
#include "BlockchainMessages.h"
#include "CachedBlock.h"
#include "CachedTransaction.h"
#include "CoreStatistics.h"
#include "ICoreDefinitions.h"
#include "ICoreObserver.h"
#include "MessageQueue.h"
#include "StakingSystem.h"
#include "UtxoOutput.h"

#include <Pastella.h>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Pastella
{
    // Forward declarations to avoid circular dependency
    class StakingPool;
    enum class CoreEvent
    {
        POOL_UPDATED,
        BLOCKHAIN_UPDATED
    };

    class ICore
    {
      public:
        virtual ~ICore() {}

        virtual bool addMessageQueue(MessageQueue<BlockchainMessage> &messageQueue) = 0;

        virtual bool removeMessageQueue(MessageQueue<BlockchainMessage> &messageQueue) = 0;

        virtual uint32_t getTopBlockIndex() const = 0;

        virtual Crypto::Hash getTopBlockHash() const = 0;

        virtual Crypto::Hash getBlockHashByIndex(uint32_t blockIndex) const = 0;

        virtual uint64_t getBlockTimestampByIndex(uint32_t blockIndex) const = 0;

        virtual bool hasBlock(const Crypto::Hash &blockHash) const = 0;

        virtual BlockTemplate getBlockByIndex(uint32_t index) const = 0;

        virtual BlockTemplate getBlockByHash(const Crypto::Hash &blockHash) const = 0;

        virtual std::vector<Crypto::Hash> buildSparseChain() const = 0;

        virtual std::vector<Crypto::Hash> findBlockchainSupplement(
            const std::vector<Crypto::Hash> &remoteBlockIds,
            size_t maxCount,
            uint32_t &totalBlockCount,
            uint32_t &startBlockIndex) const = 0;

        virtual std::vector<RawBlock> getBlocks(uint32_t startIndex, uint32_t count) const = 0;

        virtual void getBlocks(
            const std::vector<Crypto::Hash> &blockHashes,
            std::vector<RawBlock> &blocks,
            std::vector<Crypto::Hash> &missedHashes) const = 0;

        virtual bool queryBlocks(
            const std::vector<Crypto::Hash> &blockHashes,
            uint64_t timestamp,
            uint32_t &startIndex,
            uint32_t &currentIndex,
            uint32_t &fullOffset,
            std::vector<BlockFullInfo> &entries) const = 0;

        virtual bool queryBlocksLite(
            const std::vector<Crypto::Hash> &knownBlockHashes,
            uint64_t timestamp,
            uint32_t &startIndex,
            uint32_t &currentIndex,
            uint32_t &fullOffset,
            std::vector<BlockShortInfo> &entries) const = 0;

        virtual bool queryBlocksDetailed(
            const std::vector<Crypto::Hash> &knownBlockHashes,
            uint64_t timestamp,
            uint64_t &startIndex,
            uint64_t &currentIndex,
            uint64_t &fullOffset,
            std::vector<BlockDetails> &entries,
            uint32_t blockCount) const = 0;

        virtual bool getWalletSyncData(
            const std::vector<Crypto::Hash> &knownBlockHashes,
            const uint64_t startHeight,
            const uint64_t startTimestamp,
            const uint64_t blockCount,
            const bool skipEmptyBlocks,
            std::vector<WalletTypes::WalletBlockInfo> &blocks,
            std::optional<WalletTypes::TopBlock> &topBlockInfo) const = 0;

        virtual bool getRawBlocks(
            const std::vector<Crypto::Hash> &knownBlockHashes,
            const uint64_t startHeight,
            const uint64_t startTimestamp,
            const uint64_t blockCount,
            const bool skipCoinbaseTransactions,
            std::vector<RawBlock> &walletBlocks,
            std::optional<WalletTypes::TopBlock> &topBlockInfo) const = 0;

        virtual bool getTransactionsStatus(
            std::unordered_set<Crypto::Hash> transactionHashes,
            std::unordered_set<Crypto::Hash> &transactionsInPool,
            std::unordered_set<Crypto::Hash> &transactionsInBlock,
            std::unordered_set<Crypto::Hash> &transactionsUnknown) const = 0;

        virtual bool hasTransaction(const Crypto::Hash &transactionHash) const = 0;

        /*!
         * \brief getTransaction Queries a single transaction details blob from the chain or transaction pool
         * \param hash The hash of the transaction
         * \return The binary blob of the queried transaction, or none if the transaction does not exist.
         */
        virtual std::optional<BinaryArray> getTransaction(const Crypto::Hash &hash) const = 0;

        virtual void getTransactions(
            const std::vector<Crypto::Hash> &transactionHashes,
            std::vector<BinaryArray> &transactions,
            std::vector<Crypto::Hash> &missedHashes) const = 0;

        virtual uint64_t getBlockDifficulty(uint32_t blockIndex) const = 0;

        virtual uint64_t getDifficultyForNextBlock() const = 0;

        virtual std::error_code addBlock(const CachedBlock &cachedBlock, RawBlock &&rawBlock) = 0;

        virtual std::error_code addBlock(RawBlock &&rawBlock) = 0;

        virtual std::error_code submitBlock(const BinaryArray &rawBlockTemplate) = 0;

        virtual std::tuple<bool, std::string> addTransactionToPool(const BinaryArray &transactionBinaryArray) = 0;

        virtual std::vector<Crypto::Hash> getPoolTransactionHashes() const = 0;

        /* UTXO SYSTEM: Query all UTXOs in the network with pagination */
        virtual std::tuple<bool, std::vector<UtxoOutput>, uint64_t>
            getUTXOs(uint64_t page, uint64_t limit) const = 0;

        virtual std::tuple<bool, BinaryArray>
            getPoolTransaction(const Crypto::Hash &transactionHash) const = 0;

        virtual bool getPoolChanges(
            const Crypto::Hash &lastBlockHash,
            const std::vector<Crypto::Hash> &knownHashes,
            std::vector<BinaryArray> &addedTransactions,
            std::vector<Crypto::Hash> &deletedTransactions) const = 0;

        virtual bool getPoolChangesLite(
            const Crypto::Hash &lastBlockHash,
            const std::vector<Crypto::Hash> &knownHashes,
            std::vector<TransactionPrefixInfo> &addedTransactions,
            std::vector<Crypto::Hash> &deletedTransactions) const = 0;
        virtual std::tuple<bool, std::string> getBlockTemplate(
            BlockTemplate &b,
            const Crypto::PublicKey &publicKey,
            const BinaryArray &extraNonce,
            uint64_t &difficulty,
            uint32_t &height) = 0;

        virtual CoreStatistics getCoreStatistics() const = 0;

        virtual void save() = 0;

        virtual void load() = 0;

        virtual BlockDetails getBlockDetails(const Crypto::Hash &blockHash) const = 0;

        virtual TransactionDetails getTransactionDetails(const Crypto::Hash &transactionHash) const = 0;

        virtual std::vector<Crypto::Hash>
            getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount) const = 0;

        virtual StakingPool* getStakingPool() = 0;

        /*!
         * \brief getRichList Get the top N richest addresses
         * \param count Number of addresses to return (e.g., 100 for top 100)
         * \return Vector of RichListEntry sorted by balance (descending)
         */
        virtual std::vector<Pastella::RichListEntry> getRichList(size_t count) const = 0;

        /*!
         * \brief getWalletDetails Get detailed wallet information and transaction history
         * \param address Wallet address to query
         * \param limit Number of transactions to return (0 = all)
         * \param page Page number for pagination (1-indexed, 0 = first page)
         * \return WalletDetails with address info and transaction list
         */
        virtual Pastella::WalletDetails getWalletDetails(
            const std::string &address,
            size_t limit = 100,
            size_t page = 0) const = 0;

        /* UTXO SYSTEM: UTXO query methods for RPC access
         *
         * These methods allow the RPC layer to query UTXO information
         * for wallet integration and blockchain exploration. */

        /*!
         * \brief getUtxo Get a specific UTXO by transaction hash and output index
         * \param transactionHash Hash of transaction that created the UTXO
         * \param outputIndex Index of the output in that transaction
         * \param utxo Output parameter to receive the UTXO data
         * \return true if UTXO exists, false otherwise
         */
        virtual bool getUtxo(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex,
            UtxoOutput &utxo) const = 0;

        /*!
         * \brief isUtxoUnspent Check if a UTXO is currently unspent
         * \param transactionHash Hash of transaction that created the UTXO
         * \param outputIndex Index of the output in that transaction
         * \return true if UTXO exists and is unspent, false otherwise
         */
        virtual bool isUtxoUnspent(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex) const = 0;

        /*!
         * \brief getUtxosForTransaction Get all UTXOs created by a transaction
         * \param transactionHash Hash of transaction to query
         * \return Vector of all UTXOs (spent and unspent) from that transaction
         */
        virtual std::vector<UtxoOutput> getUtxosForTransaction(
            const Crypto::Hash &transactionHash) const = 0;
    };
} // namespace Pastella
