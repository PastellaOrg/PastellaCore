// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "common/IInputStream.h"
#include "common/IOutputStream.h"
#include "serialization/ISerializer.h"
#include "transfers/TransfersSynchronizer.h"
#include "wallet/WalletIndices.h"

namespace Pastella
{
    class WalletSerializerV2
    {
      public:
        WalletSerializerV2(
            ITransfersObserver &transfersObserver,
            uint64_t &actualBalance,
            uint64_t &pendingBalance,
            WalletsContainer &walletsContainer,
            TransfersSyncronizer &synchronizer,
            UnlockTransactionJobs &unlockTransactions,
            WalletTransactions &transactions,
            WalletTransfers &transfers,
            UncommitedTransactions &uncommitedTransactions,
            std::string &extra,
            uint32_t transactionSoftLockTime);

        void load(Common::IInputStream &source, uint8_t version);

        void save(Common::IOutputStream &destination, WalletSaveLevel saveLevel);

        std::unordered_set<Crypto::PublicKey> &addedKeys();

        std::unordered_set<Crypto::PublicKey> &deletedKeys();

        static const uint8_t MIN_VERSION = 6;

        static const uint8_t SERIALIZATION_VERSION = 6;

      private:
        void loadKeyListAndBalances(Pastella::ISerializer &serializer, bool saveCache);

        void saveKeyListAndBalances(Pastella::ISerializer &serializer, bool saveCache);

        void loadTransactions(Pastella::ISerializer &serializer);

        void saveTransactions(Pastella::ISerializer &serializer);

        void loadTransfers(Pastella::ISerializer &serializer);

        void saveTransfers(Pastella::ISerializer &serializer);

        void loadTransfersSynchronizer(Pastella::ISerializer &serializer);

        void saveTransfersSynchronizer(Pastella::ISerializer &serializer);

        void loadUnlockTransactionsJobs(Pastella::ISerializer &serializer);

        void saveUnlockTransactionsJobs(Pastella::ISerializer &serializer);

        uint64_t &m_actualBalance;

        uint64_t &m_pendingBalance;

        WalletsContainer &m_walletsContainer;

        TransfersSyncronizer &m_synchronizer;

        UnlockTransactionJobs &m_unlockTransactions;

        WalletTransactions &m_transactions;

        WalletTransfers &m_transfers;

        UncommitedTransactions &m_uncommitedTransactions;

        std::string &m_extra;

        std::unordered_set<Crypto::PublicKey> m_addedKeys;

        std::unordered_set<Crypto::PublicKey> m_deletedKeys;
    };

} // namespace Pastella
