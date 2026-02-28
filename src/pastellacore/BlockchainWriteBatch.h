// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "BlockchainCache.h"
#include "Pastella.h"
#include "DatabaseCacheData.h"
#include "IWriteBatch.h"

#include <string>

namespace Pastella
{
    class BlockchainWriteBatch : public IWriteBatch
    {
      public:
        BlockchainWriteBatch();

        ~BlockchainWriteBatch();

        BlockchainWriteBatch &
            insertSpentKeyImages(uint32_t blockIndex, const std::unordered_set<Crypto::PublicKey> &spentKeyImages);

        BlockchainWriteBatch &
            insertCachedTransaction(const ExtendedTransactionInfo &transaction, uint64_t totalTxsCount);

        BlockchainWriteBatch &insertCachedBlock(
            const CachedBlockInfo &block,
            uint32_t blockIndex,
            const std::vector<Crypto::Hash> &blockTxs);

        BlockchainWriteBatch &insertKeyOutputGlobalIndexes(
            IBlockchainCache::Amount amount,
            const std::vector<PackedOutIndex> &outputs,
            uint32_t totalOutputsCountForAmount);

        BlockchainWriteBatch &insertRawBlock(uint32_t blockIndex, const RawBlock &block);

        BlockchainWriteBatch &insertClosestTimestampBlockIndex(uint64_t timestamp, uint32_t blockIndex);

        BlockchainWriteBatch &insertKeyOutputAmounts(
            const std::set<IBlockchainCache::Amount> &amounts,
            uint32_t totalKeyOutputAmountsCount);

        BlockchainWriteBatch &insertTimestamp(uint64_t timestamp, const std::vector<Crypto::Hash> &blockHashes);

        BlockchainWriteBatch &insertKeyOutputInfo(
            IBlockchainCache::Amount amount,
            IBlockchainCache::GlobalOutputIndex globalIndex,
            const KeyOutputInfo &outputInfo);

        /* STEALTH ADDRESS REMOVAL: Changed KeyImage to PublicKey */
        BlockchainWriteBatch &
            removeSpentKeyImages(uint32_t blockIndex, const std::vector<Crypto::PublicKey> &spentKeyImages);

        BlockchainWriteBatch &removeCachedTransaction(const Crypto::Hash &transactionHash, uint64_t totalTxsCount);

        BlockchainWriteBatch &removeCachedBlock(const Crypto::Hash &blockHash, uint32_t blockIndex);

        BlockchainWriteBatch &removeKeyOutputGlobalIndexes(
            IBlockchainCache::Amount amount,
            uint32_t outputsToRemoveCount,
            uint32_t totalOutputsCountForAmount);

        BlockchainWriteBatch &removeRawBlock(uint32_t blockIndex);

        BlockchainWriteBatch &removeClosestTimestampBlockIndex(uint64_t timestamp);

        BlockchainWriteBatch &removeTimestamp(uint64_t timestamp);

        BlockchainWriteBatch &
            removeKeyOutputInfo(IBlockchainCache::Amount amount, IBlockchainCache::GlobalOutputIndex globalIndex);

        /* UTXO SYSTEM: Database write operations for UTXO persistence */
        BlockchainWriteBatch &insertUtxo(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex,
            const UtxoOutput &utxo);

        BlockchainWriteBatch &markUtxoSpent(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex,
            uint32_t spentBlockIndex);

        BlockchainWriteBatch &insertSpentUtxo(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex,
            uint32_t spentBlockIndex);

        BlockchainWriteBatch &removeUtxo(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex);

        BlockchainWriteBatch &removeSpentUtxo(
            const Crypto::Hash &transactionHash,
            uint32_t outputIndex);

        /* ADDRESS BALANCE INDEX: Database write operations for address balance persistence */
        BlockchainWriteBatch &insertAddressBalance(
            const std::string &address,
            const AddressBalanceInfo &balanceInfo);

        BlockchainWriteBatch &removeAddressBalance(const std::string &address);

        std::vector<std::pair<std::string, std::string>> extractRawDataToInsert() override;

        std::vector<std::string> extractRawKeysToRemove() override;

      private:
        std::vector<std::pair<std::string, std::string>> rawDataToInsert;

        std::vector<std::string> rawKeysToRemove;
    };

} // namespace Pastella
