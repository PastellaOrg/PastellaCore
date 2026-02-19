// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The BBSCoin Developers
// Copyright (c) 2018, The Karbo Developers
// Copyright (c) 2018, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "TransfersSynchronizer.h"

#include "TransfersConsumer.h"
#include "common/StdInputStream.h"
#include "common/StdOutputStream.h"
#include "pastellacore/PastellaBasicImpl.h"
#include "serialization/BinaryInputStreamSerializer.h"
#include "serialization/BinaryOutputStreamSerializer.h"

using namespace Common;
using namespace Crypto;

namespace Pastella
{
    const uint32_t TRANSFERS_STORAGE_ARCHIVE_VERSION = 0;

    TransfersSyncronizer::TransfersSyncronizer(
        const Pastella::Currency &currency,
        std::shared_ptr<Logging::ILogger> logger,
        IBlockchainSynchronizer &sync,
        INode &node):
        m_currency(currency),
        m_logger(logger, "TransfersSyncronizer"),
        m_sync(sync),
        m_node(node)
    {
    }

    TransfersSyncronizer::~TransfersSyncronizer()
    {
        m_sync.stop();
        for (const auto &kv : m_consumers)
        {
            m_sync.removeConsumer(kv.second.get());
        }
    }

    void TransfersSyncronizer::initTransactionPool(const std::unordered_set<Crypto::Hash> &uncommitedTransactions)
    {
        for (auto it = m_consumers.begin(); it != m_consumers.end(); ++it)
        {
            it->second->initTransactionPool(uncommitedTransactions);
        }
    }

    ITransfersSubscription &TransfersSyncronizer::addSubscription(const AccountSubscription &acc)
    {
        auto it = m_consumers.find(acc.keys.address.publicKey);

        if (it == m_consumers.end())
        {
            std::unique_ptr<TransfersConsumer> consumer(
                new TransfersConsumer(m_currency, m_node, m_logger.getLogger()));

            m_sync.addConsumer(consumer.get());
            consumer->addObserver(this);
            it = m_consumers.insert(std::make_pair(acc.keys.address.publicKey, std::move(consumer))).first;
        }

        return it->second->addSubscription(acc);
    }

    bool TransfersSyncronizer::removeSubscription(const AccountPublicAddress &acc)
    {
        auto it = m_consumers.find(acc.publicKey);
        if (it == m_consumers.end())
        {
            return false;
        }

        if (it->second->removeSubscription(acc))
        {
            m_sync.removeConsumer(it->second.get());
            m_consumers.erase(it);

            m_subscribers.erase(acc.publicKey);
        }

        return true;
    }

    void TransfersSyncronizer::getSubscriptions(std::vector<AccountPublicAddress> &subscriptions)
    {
        for (const auto &kv : m_consumers)
        {
            kv.second->getSubscriptions(subscriptions);
        }
    }

    ITransfersSubscription *TransfersSyncronizer::getSubscription(const AccountPublicAddress &acc)
    {
        auto it = m_consumers.find(acc.publicKey);
        return (it == m_consumers.end()) ? nullptr : it->second->getSubscription(acc);
    }

    void TransfersSyncronizer::addPublicKeysSeen(
        const AccountPublicAddress &acc,
        const Crypto::Hash &transactionHash,
        const Crypto::PublicKey &outputKey)
    {
        auto it = m_consumers.find(acc.publicKey);
        if (it != m_consumers.end())
        {
            it->second->addPublicKeysSeen(transactionHash, outputKey);
        }
    }

    std::vector<Crypto::Hash> TransfersSyncronizer::getKeyKnownBlocks(const Crypto::PublicKey &publicKey)
    {
        auto it = m_consumers.find(publicKey);
        if (it == m_consumers.end())
        {
            throw std::invalid_argument("Consumer not found");
        }

        return m_sync.getConsumerKnownBlocks(*it->second);
    }

    void
        TransfersSyncronizer::onBlocksAdded(IBlockchainConsumer *consumer, const std::vector<Crypto::Hash> &blockHashes)
    {
        auto it = findSubscriberForConsumer(consumer);
        if (it != m_subscribers.end())
        {
            it->second->notify(&ITransfersSynchronizerObserver::onBlocksAdded, it->first, blockHashes);
        }
    }

    void TransfersSyncronizer::onBlockchainDetach(IBlockchainConsumer *consumer, uint32_t blockIndex)
    {
        auto it = findSubscriberForConsumer(consumer);
        if (it != m_subscribers.end())
        {
            it->second->notify(&ITransfersSynchronizerObserver::onBlockchainDetach, it->first, blockIndex);
        }
    }

    void TransfersSyncronizer::onTransactionDeleteBegin(IBlockchainConsumer *consumer, Crypto::Hash transactionHash)
    {
        auto it = findSubscriberForConsumer(consumer);
        if (it != m_subscribers.end())
        {
            it->second->notify(&ITransfersSynchronizerObserver::onTransactionDeleteBegin, it->first, transactionHash);
        }
    }

    void TransfersSyncronizer::onTransactionDeleteEnd(IBlockchainConsumer *consumer, Crypto::Hash transactionHash)
    {
        auto it = findSubscriberForConsumer(consumer);
        if (it != m_subscribers.end())
        {
            it->second->notify(&ITransfersSynchronizerObserver::onTransactionDeleteEnd, it->first, transactionHash);
        }
    }

    void TransfersSyncronizer::onTransactionUpdated(
        IBlockchainConsumer *consumer,
        const Crypto::Hash &transactionHash,
        const std::vector<ITransfersContainer *> &containers)
    {
        auto it = findSubscriberForConsumer(consumer);
        if (it != m_subscribers.end())
        {
            it->second->notify(
                &ITransfersSynchronizerObserver::onTransactionUpdated, it->first, transactionHash, containers);
        }
    }

    void TransfersSyncronizer::subscribeConsumerNotifications(
        const Crypto::PublicKey &publicKey,
        ITransfersSynchronizerObserver *observer)
    {
        auto it = m_subscribers.find(publicKey);
        if (it != m_subscribers.end())
        {
            it->second->add(observer);
            return;
        }

        auto insertedIt =
            m_subscribers.emplace(publicKey, std::unique_ptr<SubscribersNotifier>(new SubscribersNotifier())).first;
        insertedIt->second->add(observer);
    }

    void TransfersSyncronizer::unsubscribeConsumerNotifications(
        const Crypto::PublicKey &publicKey,
        ITransfersSynchronizerObserver *observer)
    {
        m_subscribers.at(publicKey)->remove(observer);
    }

    void TransfersSyncronizer::save(std::ostream &os)
    {
        m_sync.save(os);

        StdOutputStream stream(os);
        Pastella::BinaryOutputStreamSerializer s(stream);
        s(const_cast<uint32_t &>(TRANSFERS_STORAGE_ARCHIVE_VERSION), "version");

        uint64_t subscriptionCount = m_consumers.size();

        s.beginArray(subscriptionCount, "consumers");

        for (const auto &consumer : m_consumers)
        {
            s.beginObject("");
            s(const_cast<PublicKey &>(consumer.first), "public_key");

            std::stringstream consumerState;
            // synchronization state
            m_sync.getConsumerState(consumer.second.get())->save(consumerState);

            std::string blob = consumerState.str();
            s(blob, "state");

            std::vector<AccountPublicAddress> subscriptions;
            consumer.second->getSubscriptions(subscriptions);
            uint64_t subCount = subscriptions.size();

            s.beginArray(subCount, "subscriptions");

            for (auto &addr : subscriptions)
            {
                auto sub = consumer.second->getSubscription(addr);
                if (sub != nullptr)
                {
                    s.beginObject("");

                    std::stringstream subState;
                    assert(sub);
                    sub->getContainer().save(subState);
                    // store data block
                    std::string blob = subState.str();
                    s(addr, "address");
                    s(blob, "state");

                    s.endObject();
                }
            }

            s.endArray();
            s.endObject();
        }
    }

    namespace
    {
        std::string getObjectState(IStreamSerializable &obj)
        {
            std::stringstream stream;
            obj.save(stream);
            return stream.str();
        }

        void setObjectState(IStreamSerializable &obj, const std::string &state)
        {
            std::stringstream stream(state);
            obj.load(stream);
        }

    } // namespace

    void TransfersSyncronizer::load(std::istream &is)
    {
        m_sync.load(is);

        StdInputStream inputStream(is);
        Pastella::BinaryInputStreamSerializer s(inputStream);
        uint32_t version = 0;

        s(version, "version");

        if (version > TRANSFERS_STORAGE_ARCHIVE_VERSION)
        {
            throw std::runtime_error("TransfersSyncronizer version mismatch");
        }

        struct ConsumerState
        {
            PublicKey publicKey;
            std::string state;
            std::vector<std::pair<AccountPublicAddress, std::string>> subscriptionStates;
        };

        std::vector<ConsumerState> updatedStates;

        try
        {
            uint64_t subscriptionCount = 0;
            s.beginArray(subscriptionCount, "consumers");

            while (subscriptionCount--)
            {
                s.beginObject("");
                PublicKey publicKey;
                s(publicKey, "public_key");

                std::string blob;
                s(blob, "state");

                auto subIter = m_consumers.find(publicKey);
                if (subIter != m_consumers.end())
                {
                    auto consumerState = m_sync.getConsumerState(subIter->second.get());
                    assert(consumerState);

                    {
                        // store previous state
                        auto prevConsumerState = getObjectState(*consumerState);
                        // load consumer state
                        setObjectState(*consumerState, blob);
                        updatedStates.push_back(ConsumerState {publicKey, std::move(prevConsumerState)});
                    }

                    // load subscriptions
                    uint64_t subCount = 0;
                    s.beginArray(subCount, "subscriptions");

                    while (subCount--)
                    {
                        s.beginObject("");

                        AccountPublicAddress acc;
                        std::string state;

                        s(acc, "address");
                        s(state, "state");

                        auto sub = subIter->second->getSubscription(acc);

                        if (sub != nullptr)
                        {
                            auto prevState = getObjectState(sub->getContainer());
                            setObjectState(sub->getContainer(), state);
                            updatedStates.back().subscriptionStates.push_back(std::make_pair(acc, prevState));
                        }
                        else
                        {
                            m_logger(Logging::DEBUGGING)
                                << "Subscription not found: " << m_currency.accountAddressAsString(acc);
                        }

                        s.endObject();
                    }

                    s.endArray();
                }
                else
                {
                    m_logger(Logging::DEBUGGING) << "Consumer not found: " << publicKey;
                }

                s.endObject();
            }

            s.endArray();
        }
        catch (...)
        {
            // rollback state
            for (const auto &consumerState : updatedStates)
            {
                auto consumer = m_consumers.find(consumerState.publicKey)->second.get();
                setObjectState(*m_sync.getConsumerState(consumer), consumerState.state);
                for (const auto &sub : consumerState.subscriptionStates)
                {
                    setObjectState(consumer->getSubscription(sub.first)->getContainer(), sub.second);
                }
            }
            throw;
        }
    }

    bool TransfersSyncronizer::findKeyForConsumer(IBlockchainConsumer *consumer, Crypto::PublicKey &publicKey) const
    {
        // since we have only couple of consumers linear complexity is fine
        auto it = std::find_if(
            m_consumers.begin(), m_consumers.end(), [consumer](const ConsumersContainer::value_type &subscription) {
                return subscription.second.get() == consumer;
            });

        if (it == m_consumers.end())
        {
            return false;
        }

        publicKey = it->first;
        return true;
    }

    TransfersSyncronizer::SubscribersContainer::const_iterator
        TransfersSyncronizer::findSubscriberForConsumer(IBlockchainConsumer *consumer) const
    {
        Crypto::PublicKey publicKey;
        if (findKeyForConsumer(consumer, publicKey))
        {
            auto it = m_subscribers.find(publicKey);
            if (it != m_subscribers.end())
            {
                return it;
            }
        }

        return m_subscribers.end();
    }

} // namespace Pastella
