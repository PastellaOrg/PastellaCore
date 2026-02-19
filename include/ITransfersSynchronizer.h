// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "IStreamSerializable.h"
#include "ITransaction.h"
#include "ITransfersContainer.h"

#include <cstdint>
#include <system_error>

namespace Pastella
{
    struct SynchronizationStart
    {
        uint64_t timestamp;
        uint64_t height;
    };

    struct AccountSubscription
    {
        AccountKeys keys;
        SynchronizationStart syncStart;
        size_t transactionSpendableAge;
    };

    class ITransfersSubscription;

    class ITransfersObserver
    {
      public:
        virtual void onError(ITransfersSubscription *object, uint32_t height, std::error_code ec) {}

        virtual void onTransactionUpdated(ITransfersSubscription *object, const Crypto::Hash &transactionHash) {}

        /**
         * \note The sender must guarantee that onTransactionDeleted() is called only after onTransactionUpdated() is
         * called for the same \a transactionHash.
         */
        virtual void onTransactionDeleted(ITransfersSubscription *object, const Crypto::Hash &transactionHash) {}
    };

    class ITransfersSubscription : public IObservable<ITransfersObserver>
    {
      public:
        virtual ~ITransfersSubscription() {}

        virtual AccountPublicAddress getAddress() = 0;

        virtual ITransfersContainer &getContainer() = 0;
    };

    class ITransfersSynchronizerObserver
    {
      public:
        virtual void onBlocksAdded(const Crypto::PublicKey &publicKey, const std::vector<Crypto::Hash> &blockHashes)
        {
        }

        virtual void onBlockchainDetach(const Crypto::PublicKey &publicKey, uint32_t blockIndex) {}

        virtual void onTransactionDeleteBegin(const Crypto::PublicKey &publicKey, Crypto::Hash transactionHash) {}

        virtual void onTransactionDeleteEnd(const Crypto::PublicKey &publicKey, Crypto::Hash transactionHash) {}

        virtual void onTransactionUpdated(
            const Crypto::PublicKey &publicKey,
            const Crypto::Hash &transactionHash,
            const std::vector<ITransfersContainer *> &containers)
        {
        }
    };

    class ITransfersSynchronizer : public IStreamSerializable
    {
      public:
        virtual ~ITransfersSynchronizer() {}

        virtual ITransfersSubscription &addSubscription(const AccountSubscription &acc) = 0;

        virtual bool removeSubscription(const AccountPublicAddress &acc) = 0;

        virtual void getSubscriptions(std::vector<AccountPublicAddress> &subscriptions) = 0;

        // returns nullptr if address is not found
        virtual ITransfersSubscription *getSubscription(const AccountPublicAddress &acc) = 0;

        virtual std::vector<Crypto::Hash> getKeyKnownBlocks(const Crypto::PublicKey &publicKey) = 0;
    };

} // namespace Pastella
