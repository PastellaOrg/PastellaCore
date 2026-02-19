// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2018, The BBSCoin Developers
// Copyright (c) 2018, The Karbo Developers
//
// Please see the included LICENSE file for more information.

///////////////////////////////
#include <wallet/WalletGreen.h>
///////////////////////////////

#include "ITransaction.h"

#include <algorithm>
#include <cassert>
#include <common/PastellaTools.h>
#include <common/ScopeExit.h>
#include <common/ShuffleGenerator.h>
#include <common/StdInputStream.h>
#include <common/StdOutputStream.h>
#include <common/StreamTools.h>
#include <common/StringOutputStream.h>
#include <common/StringTools.h>
#include <crypto/crypto.h>
#include <crypto/random.h>
#include <pastellacore/Core.h>
#include <pastellacore/PastellaBasicImpl.h>
#include <pastellacore/PastellaFormatUtils.h>
#include <pastellacore/Currency.h>
#include <pastellacore/TransactionApi.h>
#include <ctime>
#include <fstream>
#include <numeric>
#include <random>
#include <serialization/PastellaSerialization.h>
#include <set>
#include <system/EventLock.h>
#include <system/RemoteContext.h>
#include <transfers/TransfersContainer.h>
#include <tuple>
#include <utilities/Addresses.h>
#include <utilities/ParseExtra.h>
#include <utilities/Utilities.h>
#include <utility>
#include <wallet/WalletErrors.h>
#include <wallet/WalletSerializationV2.h>
#include <wallet/WalletUtils.h>
#include <walletbackend/Constants.h>
#include <walletbackend/Transfer.h>
#include <walletbackend/WalletBackend.h>

#undef ERROR

using namespace Common;
using namespace Crypto;
using namespace Pastella;
using namespace Logging;

namespace
{
    void asyncRequestCompletion(System::Event &requestFinished)
    {
        requestFinished.set();
    }

    Pastella::WalletEvent makeTransactionUpdatedEvent(size_t id)
    {
        Pastella::WalletEvent event;
        event.type = Pastella::WalletEventType::TRANSACTION_UPDATED;
        event.transactionUpdated.transactionIndex = id;

        return event;
    }

    Pastella::WalletEvent makeTransactionCreatedEvent(size_t id)
    {
        Pastella::WalletEvent event;
        event.type = Pastella::WalletEventType::TRANSACTION_CREATED;
        event.transactionCreated.transactionIndex = id;

        return event;
    }

    Pastella::WalletEvent makeMoneyUnlockedEvent()
    {
        Pastella::WalletEvent event;
        event.type = Pastella::WalletEventType::BALANCE_UNLOCKED;

        return event;
    }

    Pastella::WalletEvent makeSyncProgressUpdatedEvent(uint32_t current, uint32_t total)
    {
        Pastella::WalletEvent event;
        event.type = Pastella::WalletEventType::SYNC_PROGRESS_UPDATED;
        event.synchronizationProgressUpdated.processedBlockCount = current;
        event.synchronizationProgressUpdated.totalBlockCount = total;

        return event;
    }

    Pastella::WalletEvent makeSyncCompletedEvent()
    {
        Pastella::WalletEvent event;
        event.type = Pastella::WalletEventType::SYNC_COMPLETED;

        return event;
    }

    size_t getTransactionSize(const ITransactionReader &transaction)
    {
        return transaction.getTransactionData().size();
    }

    uint64_t calculateDonationAmount(uint64_t freeAmount, uint64_t donationThreshold, uint64_t dustThreshold)
    {
        /* DENOMINATION REMOVED: No denomination splitting
         *
         * In Bitcoin-like systems, we don't split amounts for donations.
         * Simply donate up to the threshold if we have enough. */
        if (freeAmount >= donationThreshold)
        {
            return donationThreshold;
        }
        else if (freeAmount > dustThreshold)
        {
            /* Donate the full free amount if it's above dust */
            return freeAmount;
        }

        return 0;
    }

} // namespace

namespace Pastella
{
    WalletGreen::WalletGreen(
        System::Dispatcher &dispatcher,
        const Currency &currency,
        INode &node,
        std::shared_ptr<Logging::ILogger> logger,
        uint32_t transactionSoftLockTime):
        m_dispatcher(dispatcher),
        m_currency(currency),
        m_node(node),
        m_logger(logger, "Wallet"),
        m_stopped(false),
        m_blockchainSynchronizerStarted(false),
        m_blockchainSynchronizer(node, logger, currency.genesisBlockHash()),
        m_synchronizer(currency, logger, m_blockchainSynchronizer, node),
        m_eventOccurred(m_dispatcher),
        m_readyEvent(m_dispatcher),
        m_state(WalletState::NOT_INITIALIZED),
        m_actualBalance(0),
        m_pendingBalance(0),
        m_transactionSoftLockTime(transactionSoftLockTime)
    {
        m_readyEvent.set();
    }

    WalletGreen::~WalletGreen()
    {
        if (m_state == WalletState::INITIALIZED)
        {
            doShutdown();
        }

        m_dispatcher.yield(); // let remote spawns finish
    }

    void WalletGreen::initializeWithKey(
        const std::string &path,
        const std::string &password,
        const Crypto::SecretKey &secretKey,
        const uint64_t scanHeight,
        const bool newAddress)
    {
        Crypto::PublicKey publicKey;
        if (!Crypto::secret_key_to_public_key(secretKey, publicKey))
        {
            m_logger(ERROR) << "initializeWithKey(" << secretKey
                                        << ") Failed to convert secret key to public key";
            throw std::system_error(make_error_code(Pastella::error::KEY_GENERATION_ERROR));
        }

        initWithKeys(path, password, publicKey, secretKey, scanHeight, newAddress);
    }

    void WalletGreen::shutdown()
    {
        throwIfNotInitialized();
        doShutdown();

        m_dispatcher.yield(); // let remote spawns finish
        m_logger(INFO) << "Container shut down";
        m_logger = Logging::LoggerRef(m_logger.getLogger(), "WalletGreen/empty");
    }

    void WalletGreen::doShutdown()
    {
        if (m_walletsContainer.size() != 0)
        {
            m_synchronizer.unsubscribeConsumerNotifications(m_publicKey, this);
        }

        stopBlockchainSynchronizer();
        m_blockchainSynchronizer.removeObserver(this);

        m_containerStorage.close();
        m_walletsContainer.clear();

        clearCaches(true, true);

        std::queue<WalletEvent> noEvents;
        std::swap(m_events, noEvents);

        m_state = WalletState::NOT_INITIALIZED;
    }

    void WalletGreen::clearCaches(bool clearTransactions, bool clearCachedData)
    {
        if (clearTransactions)
        {
            m_transactions.clear();
            m_transfers.clear();
        }

        if (clearCachedData)
        {
            size_t walletIndex = 0;
            for (auto it = m_walletsContainer.begin(); it != m_walletsContainer.end(); ++it)
            {
                m_walletsContainer.modify(it, [&walletIndex](WalletRecord &wallet) {
                    wallet.actualBalance = 0;
                    wallet.pendingBalance = 0;
                    wallet.container = reinterpret_cast<Pastella::ITransfersContainer *>(
                        walletIndex++); // dirty hack. container field must be unique
                });
            }

            if (!clearTransactions)
            {
                for (auto it = m_transactions.begin(); it != m_transactions.end(); ++it)
                {
                    m_transactions.modify(it, [](WalletTransaction &tx) {
                        tx.state = WalletTransactionState::CANCELLED;
                        tx.blockHeight = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
                    });
                }
            }

            std::vector<AccountPublicAddress> subscriptions;
            m_synchronizer.getSubscriptions(subscriptions);
            std::for_each(subscriptions.begin(), subscriptions.end(), [this](const AccountPublicAddress &address) {
                m_synchronizer.removeSubscription(address);
            });

            m_uncommitedTransactions.clear();
            m_unlockTransactionsJob.clear();
            m_actualBalance = 0;
            m_pendingBalance = 0;
            m_blockchain.clear();
        }
    }

    void WalletGreen::decryptKeyPair(
        const EncryptedWalletRecord &cipher,
        PublicKey &publicKey,
        SecretKey &secretKey,
        uint64_t &creationTimestamp,
        const Crypto::chacha8_key &key)
    {
        std::array<char, sizeof(cipher.data)> buffer;
        chacha8(cipher.data, sizeof(cipher.data), key, cipher.iv, buffer.data());

        MemoryInputStream stream(buffer.data(), buffer.size());
        BinaryInputStreamSerializer serializer(stream);

        serializer(publicKey, "publicKey");
        serializer(secretKey, "secretKey");
        serializer.binary(&creationTimestamp, sizeof(uint64_t), "creationTimestamp");
    }

    void WalletGreen::decryptKeyPair(
        const EncryptedWalletRecord &cipher,
        PublicKey &publicKey,
        SecretKey &secretKey,
        uint64_t &creationTimestamp) const
    {
        decryptKeyPair(cipher, publicKey, secretKey, creationTimestamp, m_key);
    }

    EncryptedWalletRecord WalletGreen::encryptKeyPair(
        const PublicKey &publicKey,
        const SecretKey &secretKey,
        uint64_t creationTimestamp,
        const Crypto::chacha8_key &key,
        const Crypto::chacha8_iv &iv)
    {
        EncryptedWalletRecord result;

        std::string serializedKeys;
        StringOutputStream outputStream(serializedKeys);
        BinaryOutputStreamSerializer serializer(outputStream);

        serializer(const_cast<PublicKey &>(publicKey), "publicKey");
        serializer(const_cast<SecretKey &>(secretKey), "secretKey");
        serializer.binary(&creationTimestamp, sizeof(uint64_t), "creationTimestamp");

        assert(serializedKeys.size() == sizeof(result.data));

        result.iv = iv;
        chacha8(serializedKeys.data(), serializedKeys.size(), key, result.iv, reinterpret_cast<char *>(result.data));

        return result;
    }

    EncryptedWalletRecord WalletGreen::encryptKeyPair(
        const PublicKey &publicKey,
        const SecretKey &secretKey,
        uint64_t creationTimestamp) const
    {
        return encryptKeyPair(publicKey, secretKey, creationTimestamp, m_key, getNextIv());
    }

    Crypto::chacha8_iv WalletGreen::getNextIv() const
    {
        const auto *prefix = reinterpret_cast<const ContainerStoragePrefix *>(m_containerStorage.prefix());
        return prefix->nextIv;
    }

    void WalletGreen::incIv(Crypto::chacha8_iv &iv)
    {
        static_assert(sizeof(uint64_t) == sizeof(Crypto::chacha8_iv), "Bad Crypto::chacha8_iv size");
        uint64_t *i = reinterpret_cast<uint64_t *>(&iv);
        if (*i < std::numeric_limits<uint64_t>::max())
        {
            ++(*i);
        }
        else
        {
            *i = 0;
        }
    }

    void WalletGreen::incNextIv()
    {
        static_assert(sizeof(uint64_t) == sizeof(Crypto::chacha8_iv), "Bad Crypto::chacha8_iv size");
        auto *prefix = reinterpret_cast<ContainerStoragePrefix *>(m_containerStorage.prefix());
        incIv(prefix->nextIv);
    }

    void WalletGreen::initWithKeys(
        const std::string &path,
        const std::string &password,
        const Crypto::PublicKey &publicKey,
        const Crypto::SecretKey &secretKey,
        const uint64_t scanHeight,
        const bool newAddress)
    {
        if (m_state != WalletState::NOT_INITIALIZED)
        {
            m_logger(ERROR) << "Failed to initialize with keys: already initialized. Current state: "
                                        << m_state;
            throw std::system_error(make_error_code(Pastella::error::ALREADY_INITIALIZED));
        }

        throwIfStopped();

        ContainerStorage newStorage(path, Common::FileMappedVectorOpenMode::CREATE, sizeof(ContainerStoragePrefix));
        ContainerStoragePrefix *prefix = reinterpret_cast<ContainerStoragePrefix *>(newStorage.prefix());
        prefix->version = static_cast<uint8_t>(WalletSerializerV2::SERIALIZATION_VERSION);
        prefix->nextIv = Crypto::randomChachaIV();

        Crypto::generate_chacha8_key(password, m_key);

        uint64_t creationTimestamp;

        if (newAddress)
        {
            creationTimestamp = getCurrentTimestampAdjusted();
        }
        else
        {
            creationTimestamp = scanHeightToTimestamp(scanHeight);
        }

        prefix->encryptedKeys =
            encryptKeyPair(publicKey, secretKey, creationTimestamp, m_key, prefix->nextIv);

        newStorage.flush();
        m_containerStorage.swap(newStorage);
        incNextIv();

        m_publicKey = publicKey;
        m_privateKey = secretKey;
        m_password = password;
        m_path = path;
        m_logger = Logging::LoggerRef(m_logger.getLogger(), "WalletGreen/" + podToHex(m_publicKey).substr(0, 5));

        assert(m_blockchain.empty());
        m_blockchain.push_back(m_currency.genesisBlockHash());

        m_blockchainSynchronizer.addObserver(this);

        m_state = WalletState::INITIALIZED;
    }

    void WalletGreen::save(WalletSaveLevel saveLevel, const std::string &extra)
    {
        m_logger(INFO) << "Saving container...";

        throwIfNotInitialized();
        throwIfStopped();

        stopBlockchainSynchronizer();

        try
        {
            saveWalletCache(m_containerStorage, m_key, saveLevel, extra);
        }
        catch (const std::exception &e)
        {
            m_logger(ERROR) << "Failed to save container: " << e.what();
            startBlockchainSynchronizer();
            throw;
        }

        startBlockchainSynchronizer();
        m_logger(INFO) << "Container saved";
    }

    void WalletGreen::exportWallet(
        const std::string &path,
        bool encrypt,
        WalletSaveLevel saveLevel,
        const std::string &extra)
    {
        m_logger(INFO) << "Exporting container...";

        throwIfNotInitialized();
        throwIfStopped();

        stopBlockchainSynchronizer();

        try
        {
            bool storageCreated = false;
            Tools::ScopeExit failExitHandler([path, &storageCreated] {
                // Don't delete file if it has existed
                if (storageCreated)
                {
                    std::error_code ignore;
                    fs::remove(path, ignore);
                }
            });

            ContainerStorage newStorage(path, FileMappedVectorOpenMode::OPEN_OR_CREATE, m_containerStorage.prefixSize());
            newStorage.clear();

            storageCreated = true;

            chacha8_key newStorageKey;
            if (encrypt)
            {
                newStorageKey = m_key;
            }
            else
            {
                generate_chacha8_key("", newStorageKey);
            }

            copyContainerStoragePrefix(m_containerStorage, m_key, newStorage, newStorageKey);
            copyContainerStorageKeys(m_containerStorage, m_key, newStorage, newStorageKey);
            saveWalletCache(newStorage, newStorageKey, saveLevel, extra);

            failExitHandler.cancel();

            m_logger(DEBUGGING) << "Container export finished";
        }
        catch (const std::exception &e)
        {
            m_logger(ERROR) << "Failed to export container: " << e.what();
            startBlockchainSynchronizer();
            throw;
        }

        startBlockchainSynchronizer();
        m_logger(INFO) << "Container exported";
    }

    void WalletGreen::load(const std::string &path, const std::string &password, std::string &extra)
    {
        m_logger(INFO) << "Loading container...";

        if (m_state != WalletState::NOT_INITIALIZED)
        {
            m_logger(ERROR) << "Failed to load: already initialized. Current state: " << m_state;
            throw std::system_error(make_error_code(error::WRONG_STATE));
        }

        throwIfStopped();

        stopBlockchainSynchronizer();

        generate_chacha8_key(password, m_key);

        std::ifstream walletFileStream(path, std::ios_base::binary);
        int version = walletFileStream.peek();
        if (version == EOF)
        {
            m_logger(ERROR) << "Failed to read wallet version";
            throw std::system_error(make_error_code(error::WRONG_VERSION), "Failed to read wallet version");
        }

        if (version < WalletSerializerV2::MIN_VERSION || version > WalletSerializerV2::SERIALIZATION_VERSION)
        {
            m_logger(ERROR) << "Unsupported wallet version: " << version;
            throw std::system_error(make_error_code(error::WRONG_VERSION), "Unsupported wallet version");
        }
        else
        {
            walletFileStream.close();

            loadContainerStorage(path);
            subscribeWallets();

            if (m_containerStorage.suffixSize() > 0)
            {
                try
                {
                    std::unordered_set<Crypto::PublicKey> addedKeys;
                    std::unordered_set<Crypto::PublicKey> deletedKeys;
                    loadWalletCache(addedKeys, deletedKeys, extra);

                    if (!addedKeys.empty())
                    {
                        m_logger(WARNING)
                            << "Found addresses not saved in container cache. Resynchronize container";
                        clearCaches(false, true);
                        subscribeWallets();
                    }

                    if (!deletedKeys.empty())
                    {
                        m_logger(WARNING)
                            << "Found deleted addresses saved in container cache. Remove its transactions";
                        deleteOrphanTransactions(deletedKeys);
                    }

                    if (!addedKeys.empty() || !deletedKeys.empty())
                    {
                        saveWalletCache(m_containerStorage, m_key, WalletSaveLevel::SAVE_ALL, extra);
                    }
                }
                catch (const std::exception &e)
                {
                    m_logger(ERROR) << "Failed to load cache: " << e.what() << ", reset wallet data";
                    clearCaches(true, true);
                    subscribeWallets();
                }
            }
        }

        // Read all output keys cache
        try
        {
            std::vector<AccountPublicAddress> subscriptionList;
            m_synchronizer.getSubscriptions(subscriptionList);
            for (auto &addr : subscriptionList)
            {
                auto sub = m_synchronizer.getSubscription(addr);
                if (sub != nullptr)
                {
                    std::vector<TransactionOutputInformation> allTransfers;
                    ITransfersContainer *container = &sub->getContainer();
                    container->getOutputs(allTransfers, ITransfersContainer::IncludeAll);
                    m_logger(INFO) << "Known Transfers " << allTransfers.size();
                    for (auto &o : allTransfers)
                    {
                        if (o.type == TransactionTypes::OutputType::Key)
                        {
                            m_synchronizer.addPublicKeysSeen(addr, o.transactionHash, o.outputKey);
                        }
                    }
                }
            }
        }
        catch (const std::exception &e)
        {
            m_logger(ERROR) << "Failed to read output keys!! Continue without output keys: " << e.what();
        }

        m_blockchainSynchronizer.addObserver(this);

        initTransactionPool();

        assert(m_blockchain.empty());
        if (m_walletsContainer.get<RandomAccessIndex>().size() != 0)
        {
            m_synchronizer.subscribeConsumerNotifications(m_publicKey, this);
            initBlockchain(m_publicKey);

            startBlockchainSynchronizer();
        }
        else
        {
            m_blockchain.push_back(m_currency.genesisBlockHash());
            m_logger(DEBUGGING) << "Add genesis block hash to blockchain";
        }

        m_password = password;
        m_path = path;
        m_extra = extra;

        m_state = WalletState::INITIALIZED;
        m_logger(INFO) << "Container loaded, spend public key " << m_publicKey << ", wallet count "
                                     << m_walletsContainer.size() << ", actual balance "
                                     << m_currency.formatAmount(m_actualBalance) << ", pending balance "
                                     << m_currency.formatAmount(m_pendingBalance);
    }

    void WalletGreen::load(const std::string &path, const std::string &password)
    {
        std::string extra;
        load(path, password, extra);
    }

    void WalletGreen::loadContainerStorage(const std::string &path)
    {
        try
        {
            m_containerStorage.open(path, FileMappedVectorOpenMode::OPEN, sizeof(ContainerStoragePrefix));

            ContainerStoragePrefix *prefix = reinterpret_cast<ContainerStoragePrefix *>(m_containerStorage.prefix());
            assert(prefix->version >= WalletSerializerV2::MIN_VERSION);

            uint64_t creationTimestamp;
            decryptKeyPair(prefix->encryptedKeys, m_publicKey, m_privateKey, creationTimestamp);
            throwIfKeysMismatch(
                m_privateKey, m_publicKey, "Restored spend public key doesn't correspond to secret key");
            m_logger =
                Logging::LoggerRef(m_logger.getLogger(), "WalletGreen/" + podToHex(m_publicKey).substr(0, 5));

            load();

            m_logger(DEBUGGING) << "Container keys were successfully loaded";
        }
        catch (const std::exception &e)
        {
            m_logger(ERROR) << "Failed to load container keys: " << e.what();

            m_walletsContainer.clear();
            m_containerStorage.close();

            throw;
        }
    }

    void WalletGreen::loadWalletCache(
        std::unordered_set<Crypto::PublicKey> &addedKeys,
        std::unordered_set<Crypto::PublicKey> &deletedKeys,
        std::string &extra)
    {
        assert(m_containerStorage.isOpened());

        BinaryArray contanerData;
        loadAndDecryptContainerData(m_containerStorage, m_key, contanerData);

        WalletSerializerV2 s(
            *this,
            m_actualBalance,
            m_pendingBalance,
            m_walletsContainer,
            m_synchronizer,
            m_unlockTransactionsJob,
            m_transactions,
            m_transfers,
            m_uncommitedTransactions,
            extra,
            m_transactionSoftLockTime);

        Common::MemoryInputStream containerStream(contanerData.data(), contanerData.size());
        s.load(containerStream, reinterpret_cast<const ContainerStoragePrefix *>(m_containerStorage.prefix())->version);
        addedKeys = std::move(s.addedKeys());
        deletedKeys = std::move(s.deletedKeys());

        m_logger(DEBUGGING) << "Container cache loaded";
    }

    void WalletGreen::saveWalletCache(
        ContainerStorage &storage,
        const Crypto::chacha8_key &key,
        WalletSaveLevel saveLevel,
        const std::string &extra)
    {
        m_logger(DEBUGGING) << "Saving cache...";

        WalletTransactions transactions;
        WalletTransfers transfers;

        if (saveLevel == WalletSaveLevel::SAVE_KEYS_AND_TRANSACTIONS)
        {
            filterOutTransactions(transactions, transfers, [](const WalletTransaction &tx) {
                return tx.state == WalletTransactionState::CREATED || tx.state == WalletTransactionState::DELETED;
            });

            for (auto it = transactions.begin(); it != transactions.end(); ++it)
            {
                transactions.modify(it, [](WalletTransaction &tx) {
                    tx.state = WalletTransactionState::CANCELLED;
                    tx.blockHeight = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
                });
            }
        }
        else if (saveLevel == WalletSaveLevel::SAVE_ALL)
        {
            filterOutTransactions(transactions, transfers, [](const WalletTransaction &tx) {
                return tx.state == WalletTransactionState::DELETED;
            });
        }

        std::string containerData;
        Common::StringOutputStream containerStream(containerData);

        WalletSerializerV2 s(
            *this,
            m_actualBalance,
            m_pendingBalance,
            m_walletsContainer,
            m_synchronizer,
            m_unlockTransactionsJob,
            transactions,
            transfers,
            m_uncommitedTransactions,
            const_cast<std::string &>(extra),
            m_transactionSoftLockTime);

        s.save(containerStream, saveLevel);

        encryptAndSaveContainerData(storage, key, containerData.data(), containerData.size());
        storage.flush();

        m_extra = extra;

        m_logger(DEBUGGING) << "Container saving finished";
    }

    void WalletGreen::copyContainerStorageKeys(
        ContainerStorage &src,
        const chacha8_key &srcKey,
        ContainerStorage &dst,
        const chacha8_key &dstKey)
    {
        m_logger(DEBUGGING) << "Copying wallet keys...";
        dst.reserve(src.size());

        dst.setAutoFlush(false);
        Tools::ScopeExit exitHandler([&dst] {
            dst.setAutoFlush(true);
            dst.flush();
        });

        size_t counter = 0;
        for (auto &encryptedKeys : src)
        {
            Crypto::PublicKey publicKey;
            Crypto::SecretKey secretKey;
            uint64_t creationTimestamp;
            decryptKeyPair(encryptedKeys, publicKey, secretKey, creationTimestamp, srcKey);

            // push_back() can resize container, and dstPrefix address can be changed, so it is requested for each key
            // pair
            ContainerStoragePrefix *dstPrefix = reinterpret_cast<ContainerStoragePrefix *>(dst.prefix());
            Crypto::chacha8_iv keyPairIv = dstPrefix->nextIv;
            incIv(dstPrefix->nextIv);

            dst.push_back(encryptKeyPair(publicKey, secretKey, creationTimestamp, dstKey, keyPairIv));

            ++counter;
            if (counter % 100 == 0)
            {
                m_logger(DEBUGGING) << "Copied keys: " << counter << " / " << src.size();
            }
        }

        m_logger(DEBUGGING) << "Keys copied";
    }

    void WalletGreen::copyContainerStoragePrefix(
        ContainerStorage &src,
        const chacha8_key &srcKey,
        ContainerStorage &dst,
        const chacha8_key &dstKey)
    {
        ContainerStoragePrefix *srcPrefix = reinterpret_cast<ContainerStoragePrefix *>(src.prefix());
        ContainerStoragePrefix *dstPrefix = reinterpret_cast<ContainerStoragePrefix *>(dst.prefix());
        dstPrefix->version = srcPrefix->version;
        dstPrefix->nextIv = Crypto::randomChachaIV();

        Crypto::PublicKey publicKey;
        Crypto::SecretKey secretKey;
        uint64_t creationTimestamp;
        decryptKeyPair(srcPrefix->encryptedKeys, publicKey, secretKey, creationTimestamp, srcKey);
        dstPrefix->encryptedKeys =
            encryptKeyPair(publicKey, secretKey, creationTimestamp, dstKey, dstPrefix->nextIv);
        incIv(dstPrefix->nextIv);
    }

    void WalletGreen::encryptAndSaveContainerData(
        ContainerStorage &storage,
        const Crypto::chacha8_key &key,
        const void *containerData,
        size_t containerDataSize)
    {
        ContainerStoragePrefix *prefix = reinterpret_cast<ContainerStoragePrefix *>(storage.prefix());

        Crypto::chacha8_iv suffixIv = prefix->nextIv;
        incIv(prefix->nextIv);

        BinaryArray encryptedContainer;
        encryptedContainer.resize(containerDataSize);
        chacha8(containerData, containerDataSize, key, suffixIv, reinterpret_cast<char *>(encryptedContainer.data()));

        std::string suffix;
        Common::StringOutputStream suffixStream(suffix);
        BinaryOutputStreamSerializer suffixSerializer(suffixStream);
        suffixSerializer(suffixIv, "suffixIv");
        suffixSerializer(encryptedContainer, "encryptedContainer");

        storage.resizeSuffix(suffix.size());
        std::copy(suffix.begin(), suffix.end(), storage.suffix());
    }

    void WalletGreen::loadAndDecryptContainerData(
        ContainerStorage &storage,
        const Crypto::chacha8_key &key,
        BinaryArray &containerData)
    {
        Common::MemoryInputStream suffixStream(storage.suffix(), storage.suffixSize());
        BinaryInputStreamSerializer suffixSerializer(suffixStream);
        Crypto::chacha8_iv suffixIv;
        BinaryArray encryptedContainer;
        suffixSerializer(suffixIv, "suffixIv");
        suffixSerializer(encryptedContainer, "encryptedContainer");

        containerData.resize(encryptedContainer.size());
        chacha8(
            encryptedContainer.data(),
            encryptedContainer.size(),
            key,
            suffixIv,
            reinterpret_cast<char *>(containerData.data()));
    }

    void WalletGreen::initTransactionPool()
    {
        std::unordered_set<Crypto::Hash> uncommitedTransactionsSet;
        std::transform(
            m_uncommitedTransactions.begin(),
            m_uncommitedTransactions.end(),
            std::inserter(uncommitedTransactionsSet, uncommitedTransactionsSet.end()),
            [](const UncommitedTransactions::value_type &pair) { return getObjectHash(pair.second); });
        m_synchronizer.initTransactionPool(uncommitedTransactionsSet);
    }

    void WalletGreen::deleteOrphanTransactions(const std::unordered_set<Crypto::PublicKey> &deletedKeys)
    {
        for (auto publicKey : deletedKeys)
        {
            AccountPublicAddress deletedAccountAddress;
            deletedAccountAddress.publicKey = publicKey;
            auto deletedAddressString = m_currency.accountAddressAsString(deletedAccountAddress);

            std::vector<size_t> deletedTransactions;
            std::vector<size_t> updatedTransactions =
                deleteTransfersForAddress(deletedAddressString, deletedTransactions);
            deleteFromUncommitedTransactions(deletedTransactions);
        }
    }

    void WalletGreen::load()
    {
        for (size_t i = 0; i < m_containerStorage.size(); ++i)
        {
            WalletRecord wallet;
            uint64_t creationTimestamp;
            decryptKeyPair(m_containerStorage[i], wallet.publicKey, wallet.secretKey, creationTimestamp);
            wallet.creationTimestamp = creationTimestamp;

            throwIfKeysMismatch(
                wallet.secretKey,
                wallet.publicKey,
                "Restored public key doesn't correspond to secret key");

            wallet.actualBalance = 0;
            wallet.pendingBalance = 0;
            wallet.container =
                reinterpret_cast<Pastella::ITransfersContainer *>(i); // dirty hack. container field must be unique

            m_walletsContainer.push_back(std::move(wallet));
        }
    }

    void WalletGreen::subscribeWallets()
    {
        m_logger(DEBUGGING) << "Subscribing wallets...";

        try
        {
            auto &index = m_walletsContainer.get<RandomAccessIndex>();

            size_t counter = 0;
            for (auto it = index.begin(); it != index.end(); ++it)
            {
                const auto &wallet = *it;

                AccountSubscription sub;
                sub.keys.address.publicKey = wallet.publicKey;
                sub.keys.secretKey = wallet.secretKey;
                sub.transactionSpendableAge = m_transactionSoftLockTime;
                sub.syncStart.height = 0;
                sub.syncStart.timestamp = wallet.creationTimestamp;

                auto &subscription = m_synchronizer.addSubscription(sub);
                bool r = index.modify(
                    it, [&subscription](WalletRecord &rec) { rec.container = &subscription.getContainer(); });
                if (r)
                {
                }
                assert(r);

                subscription.addObserver(this);

                ++counter;
                if (counter % 100 == 0)
                {
                    m_logger(DEBUGGING) << "Subscribed " << counter << " wallets of " << m_walletsContainer.size();
                }
            }
        }
        catch (const std::exception &e)
        {
            m_logger(ERROR) << "Failed to subscribe wallets: " << e.what();

            std::vector<AccountPublicAddress> subscriptionList;
            m_synchronizer.getSubscriptions(subscriptionList);
            for (auto &subscription : subscriptionList)
            {
                m_synchronizer.removeSubscription(subscription);
            }

            throw;
        }
    }

    void WalletGreen::changePassword(const std::string &oldPassword, const std::string &newPassword)
    {
        throwIfNotInitialized();
        throwIfStopped();

        if (m_password.compare(oldPassword))
        {
            m_logger(ERROR) << "Failed to change password: the old password is wrong";
            throw std::system_error(make_error_code(error::WRONG_PASSWORD));
        }

        if (oldPassword == newPassword)
        {
            return;
        }

        Crypto::chacha8_key newKey;
        Crypto::generate_chacha8_key(newPassword, newKey);

        m_containerStorage.atomicUpdate([this, newKey](ContainerStorage &newStorage) {
            copyContainerStoragePrefix(m_containerStorage, m_key, newStorage, newKey);
            copyContainerStorageKeys(m_containerStorage, m_key, newStorage, newKey);

            if (m_containerStorage.suffixSize() > 0)
            {
                BinaryArray containerData;
                loadAndDecryptContainerData(m_containerStorage, m_key, containerData);
                encryptAndSaveContainerData(newStorage, newKey, containerData.data(), containerData.size());
            }
        });

        m_key = newKey;
        m_password = newPassword;

        m_logger(INFO) << "Container password changed";
    }

    size_t WalletGreen::getAddressCount() const
    {
        throwIfNotInitialized();
        throwIfStopped();

        return m_walletsContainer.get<RandomAccessIndex>().size();
    }

    std::string WalletGreen::getAddress(size_t index) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        if (index >= m_walletsContainer.get<RandomAccessIndex>().size())
        {
            m_logger(ERROR) << "Failed to get address: invalid address index " << index;
            throw std::system_error(make_error_code(std::errc::invalid_argument));
        }

        const WalletRecord &wallet = m_walletsContainer.get<RandomAccessIndex>()[index];
        AccountPublicAddress address;
        address.publicKey = wallet.publicKey;
        return m_currency.accountAddressAsString(address);
    }

    KeyPair WalletGreen::getAddressKey(size_t index) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        if (index >= m_walletsContainer.get<RandomAccessIndex>().size())
        {
            throw std::system_error(make_error_code(std::errc::invalid_argument));
        }

        const WalletRecord &wallet = m_walletsContainer.get<RandomAccessIndex>()[index];
        return {wallet.publicKey, wallet.secretKey};
    }

    KeyPair WalletGreen::getAddressKey(const std::string &address) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        Pastella::AccountPublicAddress pubAddr = parseAddress(address);

        auto it = m_walletsContainer.get<KeysIndex>().find(pubAddr.publicKey);
        if (it == m_walletsContainer.get<KeysIndex>().end())
        {
            throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND));
        }

        return {it->publicKey, it->secretKey};
    }

    std::string WalletGreen::createAddress()
    {
        KeyPair publicKey;

        Crypto::generate_keys(publicKey.publicKey, publicKey.secretKey);

        return doCreateAddress(publicKey.publicKey, publicKey.secretKey, 0, true);
    }

    std::string WalletGreen::createAddress(
        const Crypto::SecretKey &secretKey,
        const uint64_t scanHeight,
        const bool newAddress)
    {
        Crypto::PublicKey publicKey;

        if (!Crypto::secret_key_to_public_key(secretKey, publicKey))
        {
            m_logger(ERROR) << "createAddress(" << secretKey
                                        << ") Failed to convert secret key to public key";
            throw std::system_error(make_error_code(Pastella::error::KEY_GENERATION_ERROR));
        }

        return doCreateAddress(publicKey, secretKey, scanHeight, newAddress);
    }

    std::string WalletGreen::createAddress(
        const Crypto::PublicKey &publicKey,
        const uint64_t scanHeight,
        const bool newAddress)
    {
        if (!Crypto::check_key(publicKey))
        {
            m_logger(ERROR) << "createAddress(" << publicKey << ") Wrong public key format";
            throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "Wrong public key format");
        }

        return doCreateAddress(publicKey, Constants::NULL_SECRET_KEY, scanHeight, newAddress);
    }

    std::vector<std::string> WalletGreen::createAddressList(
        const std::vector<Crypto::SecretKey> &secretKeys,
        const uint64_t scanHeight,
        const bool newAddress)
    {
        std::vector<NewAddressData> addressDataList(secretKeys.size());

        for (size_t i = 0; i < secretKeys.size(); ++i)
        {
            Crypto::PublicKey publicKey;

            if (!Crypto::secret_key_to_public_key(secretKeys[i], publicKey))
            {
                m_logger(ERROR)
                    << "createAddressList(): failed to convert secret key to public key, secret key "
                    << secretKeys[i];
                throw std::system_error(make_error_code(Pastella::error::KEY_GENERATION_ERROR));
            }

            addressDataList[i].secretKey = secretKeys[i];
            addressDataList[i].publicKey = publicKey;
        }

        return doCreateAddressList(addressDataList, scanHeight, newAddress);
    }

    std::string WalletGreen::doCreateAddress(
        const Crypto::PublicKey &publicKey,
        const Crypto::SecretKey &secretKey,
        const uint64_t scanHeight,
        const bool newAddress)
    {
        std::vector<NewAddressData> addressDataList;

        addressDataList.push_back(NewAddressData {publicKey, secretKey});

        std::vector<std::string> addresses = doCreateAddressList(addressDataList, scanHeight, newAddress);

        assert(addresses.size() == 1);

        return addresses.front();
    }

    std::vector<std::string> WalletGreen::doCreateAddressList(
        const std::vector<NewAddressData> &addressDataList,
        const uint64_t scanHeight,
        const bool newAddress)
    {
        throwIfNotInitialized();
        throwIfStopped();

        stopBlockchainSynchronizer();

        std::vector<std::string> addresses;

        bool resetRequired = false;

        const auto &walletsIndex = m_walletsContainer.get<RandomAccessIndex>();

        /* If there are already existing wallets, we need to check their creation
     timestamps. If their creation timestamps are greater than the timestamp
     of the wallet we are currently adding, we will have to rescan from this
     lower height to get the blocks we need. */
        if (!walletsIndex.empty() && !newAddress)
        {
            uint64_t timestamp = scanHeightToTimestamp(scanHeight);

            time_t minTimestamp = std::numeric_limits<time_t>::max();

            for (const WalletRecord &wallet : walletsIndex)
            {
                if (wallet.creationTimestamp < minTimestamp)
                {
                    minTimestamp = wallet.creationTimestamp;
                }
            }

            if (timestamp < static_cast<uint64_t>(minTimestamp))
            {
                resetRequired = true;
            }
        }

        try
        {
            {
                if (addressDataList.size() > 1)
                {
                    m_containerStorage.setAutoFlush(false);
                }

                Tools::ScopeExit exitHandler([this] {
                    if (!m_containerStorage.getAutoFlush())
                    {
                        m_containerStorage.setAutoFlush(true);
                        m_containerStorage.flush();
                    }
                });

                for (auto &addressData : addressDataList)
                {
                    std::string address = addWallet(addressData, scanHeight, newAddress);

                    m_logger(INFO) << "New wallet added " << address;

                    addresses.push_back(std::move(address));
                }
            }

            m_containerStorage.setAutoFlush(true);

            if (resetRequired)
            {
                m_logger(DEBUGGING) << "A reset is required to scan from this new lower "
                                    << "block height" << std::endl;

                save(WalletSaveLevel::SAVE_KEYS_AND_TRANSACTIONS, m_extra);
                shutdown();
                load(m_path, m_password);
            }
        }
        catch (const std::exception &e)
        {
            m_logger(ERROR) << "Failed to add wallets: " << e.what();
            startBlockchainSynchronizer();
            throw;
        }

        startBlockchainSynchronizer();

        return addresses;
    }

    std::string WalletGreen::addWallet(const NewAddressData &addressData, uint64_t scanHeight, bool newAddress)
    {
        const SecretKey secretKey = addressData.secretKey;
        const PublicKey publicKey = addressData.publicKey;

        auto &index = m_walletsContainer.get<KeysIndex>();

        auto insertIt = index.find(publicKey);
        if (insertIt != index.end())
        {
            AccountPublicAddress address;
            address.publicKey = publicKey;
            m_logger(ERROR) << "Failed to add wallet: address already exists, "
                                        << m_currency.accountAddressAsString(address);
            throw std::system_error(make_error_code(error::ADDRESS_ALREADY_EXISTS));
        }

        try
        {
            AccountSubscription sub;
            sub.keys.address.publicKey = publicKey;
            sub.keys.secretKey = secretKey;
            sub.transactionSpendableAge = m_transactionSoftLockTime;
            sub.syncStart.height = scanHeight;

            if (newAddress)
            {
                sub.syncStart.timestamp = getCurrentTimestampAdjusted();
            }
            else
            {
                sub.syncStart.timestamp = scanHeightToTimestamp(scanHeight);
            }

            m_containerStorage.push_back(encryptKeyPair(publicKey, secretKey, sub.syncStart.timestamp));
            incNextIv();

            auto &trSubscription = m_synchronizer.addSubscription(sub);
            ITransfersContainer *container = &trSubscription.getContainer();

            WalletRecord wallet;
            wallet.publicKey = publicKey;
            wallet.secretKey = secretKey;
            wallet.container = container;
            wallet.creationTimestamp = static_cast<time_t>(sub.syncStart.timestamp);
            trSubscription.addObserver(this);

            index.insert(insertIt, std::move(wallet));
            m_logger(DEBUGGING) << "Wallet count " << m_walletsContainer.size();

            if (index.size() == 1)
            {
                m_synchronizer.subscribeConsumerNotifications(m_publicKey, this);
                initBlockchain(m_publicKey);
            }

            AccountPublicAddress address;
            address.publicKey = publicKey;
            auto addressString = m_currency.accountAddressAsString(address);
            m_logger(DEBUGGING) << "Wallet added " << addressString << ", creation timestamp " << sub.syncStart.timestamp;
            return addressString;
        }
        catch (const std::exception &e)
        {
            m_logger(ERROR) << "Failed to add wallet: " << e.what();

            try
            {
                m_containerStorage.pop_back();
            }
            catch (...)
            {
                m_logger(ERROR) << "Failed to rollback adding wallet to storage";
            }

            throw;
        }
    }

    uint64_t WalletGreen::scanHeightToTimestamp(const uint64_t scanHeight)
    {
        if (scanHeight == 0)
        {
            return 0;
        }

        /* Get the amount of seconds since the blockchain launched */
        uint64_t secondsSinceLaunch = scanHeight * Pastella::parameters::DIFFICULTY_TARGET;

        /* Add a bit of a buffer in case of difficulty weirdness, blocks coming
       out too fast */
        secondsSinceLaunch *= 0.95;

        /* Get the genesis block timestamp and add the time since launch */
        const uint64_t timestamp = Pastella::parameters::GENESIS_BLOCK_TIMESTAMP + secondsSinceLaunch;

        /* Timestamp in the future */
        if (timestamp >= static_cast<uint64_t>(std::time(nullptr)))
        {
            return getCurrentTimestampAdjusted();
        }

        return timestamp;
    }

    uint64_t WalletGreen::getCurrentTimestampAdjusted()
    {
        /* Get the current time as a unix timestamp */
        std::time_t time = std::time(nullptr);

        /* Take the amount of time a block can potentially be in the past/future */
        uint64_t adjust = Pastella::parameters::PASTELLA_BLOCK_FUTURE_TIME_LIMIT;

        /* Take the earliest timestamp that will include all possible blocks */
        return time - adjust;
    }

    void WalletGreen::reset(const uint64_t scanHeight)
    {
        throwIfNotInitialized();
        throwIfStopped();

        /* Stop so things can't be added to the container as we're looping */
        stop();

        /* Grab the wallet encrypted prefix */
        auto *prefix = reinterpret_cast<ContainerStoragePrefix *>(m_containerStorage.prefix());

        uint64_t newTimestamp = scanHeightToTimestamp(scanHeight);

        /* Reencrypt with the new creation timestamp so we rescan from here when we relaunch */
        prefix->encryptedKeys = encryptKeyPair(m_publicKey, m_privateKey, newTimestamp);

        /* As a reference so we can update it */
        for (auto &encryptedKeys : m_containerStorage)
        {
            Crypto::PublicKey publicKey;
            Crypto::SecretKey secretKey;
            uint64_t oldTimestamp;

            /* Decrypt the key pair we're pointing to */
            decryptKeyPair(encryptedKeys, publicKey, secretKey, oldTimestamp);

            /* Re-encrypt with the new timestamp */
            encryptedKeys = encryptKeyPair(publicKey, secretKey, newTimestamp);
        }

        /* Start again so we can save */
        start();

        /* Save just the keys + timestamp to file */
        save(Pastella::WalletSaveLevel::SAVE_KEYS_ONLY);

        /* Stop and shutdown */
        stop();

        /* Shutdown the wallet */
        shutdown();

        start();

        /* Reopen from truncated storage */
        load(m_path, m_password);
    }

    void WalletGreen::deleteAddress(const std::string &address)
    {
        throwIfNotInitialized();
        throwIfStopped();

        Pastella::AccountPublicAddress pubAddr = parseAddress(address);

        auto it = m_walletsContainer.get<KeysIndex>().find(pubAddr.publicKey);
        if (it == m_walletsContainer.get<KeysIndex>().end())
        {
            m_logger(ERROR) << "Failed to delete wallet: address not found " << address;
            throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND));
        }

        stopBlockchainSynchronizer();

        m_actualBalance -= it->actualBalance;
        m_pendingBalance -= it->pendingBalance;

        if (it->actualBalance != 0 || it->pendingBalance != 0)
        {
            m_logger(INFO) << "Container balance updated, actual "
                                         << m_currency.formatAmount(m_actualBalance) << ", pending "
                                         << m_currency.formatAmount(m_pendingBalance);
        }

        auto addressIndex = std::distance(
            m_walletsContainer.get<RandomAccessIndex>().begin(), m_walletsContainer.project<RandomAccessIndex>(it));

#if !defined(NDEBUG)
        Crypto::PublicKey publicKey;
        Crypto::SecretKey secretKey;
        uint64_t creationTimestamp;
        decryptKeyPair(m_containerStorage[addressIndex], publicKey, secretKey, creationTimestamp);
        assert(publicKey == it->publicKey);
        assert(secretKey == it->secretKey);
        assert(creationTimestamp == static_cast<uint64_t>(it->creationTimestamp));
#endif

        m_containerStorage.erase(std::next(m_containerStorage.begin(), addressIndex));

        m_synchronizer.removeSubscription(pubAddr);

        deleteContainerFromUnlockTransactionJobs(it->container);
        std::vector<size_t> deletedTransactions;
        std::vector<size_t> updatedTransactions = deleteTransfersForAddress(address, deletedTransactions);
        deleteFromUncommitedTransactions(deletedTransactions);

        m_walletsContainer.get<KeysIndex>().erase(it);
        m_logger(DEBUGGING) << "Wallet count " << m_walletsContainer.size();

        if (m_walletsContainer.get<RandomAccessIndex>().size() != 0)
        {
            startBlockchainSynchronizer();
        }
        else
        {
            m_blockchain.clear();
            m_blockchain.push_back(m_currency.genesisBlockHash());
        }

        for (auto transactionId : updatedTransactions)
        {
            pushEvent(makeTransactionUpdatedEvent(transactionId));
        }

        m_logger(INFO) << "Wallet deleted " << address;
    }

    uint64_t WalletGreen::getActualBalance() const
    {
        throwIfNotInitialized();
        throwIfStopped();

        return m_actualBalance;
    }

    uint64_t WalletGreen::getActualBalance(const std::string &address) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        const auto &wallet = getWalletRecord(address);
        return wallet.actualBalance;
    }

    uint64_t WalletGreen::getPendingBalance() const
    {
        throwIfNotInitialized();
        throwIfStopped();

        return m_pendingBalance;
    }

    uint64_t WalletGreen::getPendingBalance(const std::string &address) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        const auto &wallet = getWalletRecord(address);
        return wallet.pendingBalance;
    }

    size_t WalletGreen::getTransactionCount() const
    {
        throwIfNotInitialized();
        throwIfStopped();

        return m_transactions.get<RandomAccessIndex>().size();
    }

    WalletTransaction WalletGreen::getTransaction(size_t transactionIndex) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        if (m_transactions.size() <= transactionIndex)
        {
            m_logger(ERROR) << "Failed to get transaction: invalid index " << transactionIndex
                                        << ". Number of transactions: " << m_transactions.size();
            throw std::system_error(make_error_code(Pastella::error::INDEX_OUT_OF_RANGE));
        }

        return m_transactions.get<RandomAccessIndex>()[transactionIndex];
    }

    WalletGreen::TransfersRange WalletGreen::getTransactionTransfersRange(size_t transactionIndex) const
    {
        auto val = std::make_pair(transactionIndex, WalletTransfer());

        auto bounds = std::equal_range(
            m_transfers.begin(),
            m_transfers.end(),
            val,
            [](const TransactionTransferPair &a, const TransactionTransferPair &b) { return a.first < b.first; });

        return bounds;
    }

    size_t WalletGreen::transfer(const PreparedTransaction &preparedTransaction)
    {
        size_t id = WALLET_INVALID_TRANSACTION_ID;
        Tools::ScopeExit releaseContext([this, &id] {
            m_dispatcher.yield();

            if (id != WALLET_INVALID_TRANSACTION_ID)
            {
                auto &tx = m_transactions[id];
                m_logger(INFO)
                    << "Transaction created and send, ID " << id << ", hash " << tx.hash << ", state " << tx.state
                    << ", totalAmount " << m_currency.formatAmount(tx.totalAmount) << ", fee "
                    << m_currency.formatAmount(tx.fee)
                    << ", transfers: " << TransferListFormatter(m_currency, getTransactionTransfersRange(id));
            }
        });

        System::EventLock lk(m_readyEvent);

        throwIfNotInitialized();
        throwIfStopped();

        id = validateSaveAndSendTransaction(
            *preparedTransaction.transaction, preparedTransaction.destinations, true);
        return id;
    }

    size_t WalletGreen::transfer(const TransactionParameters &transactionParameters)
    {
        size_t id = WALLET_INVALID_TRANSACTION_ID;
        Tools::ScopeExit releaseContext([this, &id] {
            m_dispatcher.yield();

            if (id != WALLET_INVALID_TRANSACTION_ID)
            {
                auto &tx = m_transactions[id];
                m_logger(INFO)
                    << "Transaction created and send, ID " << id << ", hash " << m_transactions[id].hash << ", state "
                    << tx.state << ", totalAmount " << m_currency.formatAmount(tx.totalAmount) << ", fee "
                    << m_currency.formatAmount(tx.fee)
                    << ", transfers: " << TransferListFormatter(m_currency, getTransactionTransfersRange(id));
            }
        });

        System::EventLock lk(m_readyEvent);

        throwIfNotInitialized();
        throwIfStopped();

        m_logger(INFO) << "transfer"
                                     << ", from "
                                     << Common::makeContainerFormatter(transactionParameters.sourceAddresses) << ", to "
                                     << WalletOrderListFormatter(m_currency, transactionParameters.destinations)
                                     << ", change address '" << transactionParameters.changeDestination << '\''
                                     << ", mixin " << transactionParameters.mixIn << ", unlockTimestamp "
                                     << transactionParameters.unlockTimestamp;

        id = doTransfer(transactionParameters);
        return id;
    }

    uint64_t WalletGreen::getBalanceMinusDust(const std::vector<std::string> &addresses)
    {
        std::vector<WalletOuts> wallets = addresses.empty() ? pickWalletsWithMoney() : pickWallets(addresses);

        std::vector<OutputToTransfer> unused;

        /* We want to get the full balance, so don't stop getting outputs early */
        uint64_t needed = std::numeric_limits<uint64_t>::max();

        return selectTransfers(
            needed,
            /* Don't include dust outputs */
            false,
            m_currency.defaultDustThreshold(m_node.getLastKnownBlockHeight()),
            std::move(wallets),
            unused);
    }

    void WalletGreen::prepareTransaction(
        std::vector<WalletOuts> &&wallets,
        const std::vector<WalletOrder> &orders,
        WalletTypes::FeeType fee,
        uint16_t mixIn,
        const std::string &extra,
        uint64_t unlockTimestamp,
        const DonationSettings &donation,
        const Pastella::AccountPublicAddress &changeDestination,
        PreparedTransaction &preparedTransaction)
    {
        preparedTransaction.destinations = convertOrdersToTransfers(orders);

        /* To begin with, no estimate for fee per byte. We'll adjust once we
         * have more information. */
        uint64_t estimatedFee = fee.isFixedFee ? fee.fixedFee : 0;
        
        const uint64_t totalAmount = countNeededMoney(preparedTransaction.destinations, 0);

        while (true)
        {
            /* Remove outdated change destination */
            if (preparedTransaction.destinations.back().type == WalletTransferType::CHANGE)
            {
                /* Remove old change destination / amount */
                preparedTransaction.destinations.pop_back();
            }

            preparedTransaction.neededMoney = totalAmount + estimatedFee;

            std::vector<OutputToTransfer> selectedTransfers;

            uint64_t foundMoney = selectTransfers(
                preparedTransaction.neededMoney,
                mixIn == 0,
                m_currency.defaultDustThreshold(m_node.getLastKnownBlockHeight()),
                std::move(wallets),
                selectedTransfers);

            if (foundMoney < preparedTransaction.neededMoney)
            {
                m_logger(ERROR) << "Failed to create transaction: not enough money. Needed "
                                            << m_currency.formatAmount(preparedTransaction.neededMoney) << ", found "
                                            << m_currency.formatAmount(foundMoney);
                throw std::system_error(make_error_code(error::WRONG_AMOUNT), "Not enough money");
            }

            std::vector<RandomOuts> mixinResult;

            if (mixIn != 0)
            {
                requestMixinOuts(selectedTransfers, mixIn, mixinResult);
            }

            std::vector<InputInfo> keysInfo;
            prepareInputs(selectedTransfers, mixinResult, mixIn, keysInfo);

            preparedTransaction.changeAmount = foundMoney - preparedTransaction.neededMoney;

            std::vector<ReceiverAmounts> decomposedOutputs = splitDestinations(
                preparedTransaction.destinations,
                m_currency.defaultDustThreshold(m_node.getLastKnownBlockHeight()),
                m_currency);

            if (preparedTransaction.changeAmount != 0)
            {
                WalletTransfer changeTransfer;
                changeTransfer.type = WalletTransferType::CHANGE;
                changeTransfer.address = m_currency.accountAddressAsString(changeDestination);
                changeTransfer.amount = static_cast<int64_t>(preparedTransaction.changeAmount);
                preparedTransaction.destinations.emplace_back(std::move(changeTransfer));

                auto splittedChange = splitAmount(
                    preparedTransaction.changeAmount,
                    changeDestination,
                    m_currency.defaultDustThreshold(m_node.getLastKnownBlockHeight()));
                decomposedOutputs.emplace_back(std::move(splittedChange));
            }

            if (!fee.isFixedFee)
            {
                const double feePerByte = fee.isFeePerByte
                    ? fee.feePerByte
                    : Pastella::parameters::MINIMUM_FEE_PER_BYTE_V1;

                /* If we haven't made an estimate already */
                if (estimatedFee == 0)
                {
                    const uint64_t numOutputs = std::accumulate(
                        decomposedOutputs.begin(),
                        decomposedOutputs.end(),
                        0,
                        [](const uint64_t accumulator, const auto output) { return accumulator + output.amounts.size(); });

                    const size_t transactionSize = Utilities::estimateTransactionSize(
                        mixIn,
                        keysInfo.size(),
                        numOutputs,
                        extra.size()
                    );

                    estimatedFee = Utilities::getTransactionFee(
                        transactionSize,
                        m_node.getLastKnownBlockHeight(),
                        feePerByte
                    );
                    // pre-fork we still need assure the previous minimum fee
                    const uint64_t height = m_node.getLastKnownBlockHeight();
                    if (height < Pastella::parameters::MINIMUM_FEE_PER_BYTE_V1_HEIGHT && estimatedFee < Pastella::parameters::MINIMUM_FEE) {
                        estimatedFee = Pastella::parameters::MINIMUM_FEE;
                    }
                }

                /* Update change with actual fee */
                preparedTransaction.neededMoney = totalAmount + estimatedFee;

                /* Ok, we have enough inputs to add our estimated fee, lets
                 * go ahead and try and make the transaction. */
                if (foundMoney >= preparedTransaction.neededMoney)
                {
                    preparedTransaction.changeAmount = foundMoney - preparedTransaction.neededMoney;

                    const auto maybeChange = preparedTransaction.destinations.back();

                    /* If we have a change destination, and the amount is incorrect */
                    if (maybeChange.type == WalletTransferType::CHANGE
                     && maybeChange.amount != static_cast<int64_t>(preparedTransaction.changeAmount))
                    {
                        /* Remove old change destination / amount */
                        preparedTransaction.destinations.pop_back();
                        decomposedOutputs.pop_back();

                        /* Add new change destination if needed */
                        if (preparedTransaction.changeAmount != 0)
                        {
                            WalletTransfer changeTransfer;
                            changeTransfer.type = WalletTransferType::CHANGE;
                            changeTransfer.address = m_currency.accountAddressAsString(changeDestination);
                            changeTransfer.amount = static_cast<int64_t>(preparedTransaction.changeAmount);
                            preparedTransaction.destinations.emplace_back(std::move(changeTransfer));

                            auto splittedChange = splitAmount(
                                preparedTransaction.changeAmount,
                                changeDestination,
                                m_currency.defaultDustThreshold(m_node.getLastKnownBlockHeight()));
                            decomposedOutputs.emplace_back(std::move(splittedChange));
                        }
                    }

                    preparedTransaction.transaction = makeTransaction(decomposedOutputs, keysInfo, extra, unlockTimestamp);

                    const uint64_t actualFee = Utilities::getTransactionFee(
                        preparedTransaction.transaction->getTransactionData().size(),
                        m_node.getLastKnownBlockHeight(),
                        feePerByte
                    );

                    /* Great! The fee we estimated is greater than or equal
                     * to the min/specified fee per byte for a transaction
                     * of this size, so we can continue with sending the
                     * transaction. */
                    if (estimatedFee >= actualFee)
                    {
                        return;
                    }
                    /* Estimate was too low. Retry with actual fee for a transaction
                     * of the size we just created. */
                    else
                    {
                        estimatedFee = actualFee;
                        continue;
                    }
                }
                /* Didn't get enough money selecting transfers. Fee has already
                 * been updated, so we will select more next iteration */
                else
                {
                    continue;
                }
            }
            else
            {
                preparedTransaction.transaction = makeTransaction(decomposedOutputs, keysInfo, extra, unlockTimestamp);

                const uint64_t minFee = Utilities::getMinimumTransactionFee(
                    preparedTransaction.transaction->getTransactionData().size(),
                    m_node.getLastKnownBlockHeight()
                );

                /* User specified fixed fee, and fee is not enough to cover
                 * minimum fee per byte */
                if (fee.fixedFee < minFee)
                {
                    std::string message = "Fee is too small. Fee " + m_currency.formatAmount(fee.fixedFee)
                                          + ", minimum fee for a transaction of this size: " + m_currency.formatAmount(minFee);
                    m_logger(ERROR) << message;
                    throw std::system_error(make_error_code(error::FEE_TOO_SMALL), message);
                }

                return;
            }
        }
    }

    void WalletGreen::validateSourceAddresses(const std::vector<std::string> &sourceAddresses) const
    {
        validateAddresses(sourceAddresses);

        auto badAddr = std::find_if(sourceAddresses.begin(), sourceAddresses.end(), [this](const std::string &addr) {
            return !isMyAddress(addr);
        });

        if (badAddr != sourceAddresses.end())
        {
            m_logger(ERROR) << "Source address isn't belong to the container: " << *badAddr;
            throw std::system_error(
                make_error_code(error::BAD_ADDRESS), "Source address must belong to current container: " + *badAddr);
        }
    }

    void WalletGreen::checkIfEnoughMixins(std::vector<RandomOuts> &mixinResult, uint16_t mixIn) const
    {
        assert(mixIn != 0);

        auto notEnoughIt = std::find_if(
            mixinResult.begin(), mixinResult.end(), [mixIn](const auto ofa) { return ofa.outs.size() < mixIn; });

        if (notEnoughIt != mixinResult.end())
        {
            m_logger(ERROR) << "Input count is too big: " << mixIn;
            throw std::system_error(make_error_code(Pastella::error::MIXIN_COUNT_TOO_BIG));
        }
    }

    std::vector<WalletTransfer> WalletGreen::convertOrdersToTransfers(const std::vector<WalletOrder> &orders) const
    {
        std::vector<WalletTransfer> transfers;
        transfers.reserve(orders.size());

        for (const auto &order : orders)
        {
            WalletTransfer transfer;

            if (order.amount > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
            {
                std::string message = "Order amount must not exceed "
                                      + m_currency.formatAmount(std::numeric_limits<decltype(transfer.amount)>::max());
                m_logger(ERROR) << message;
                throw std::system_error(make_error_code(Pastella::error::WRONG_AMOUNT), message);
            }

            transfer.type = WalletTransferType::USUAL;
            transfer.address = order.address;
            transfer.amount = static_cast<int64_t>(order.amount);

            transfers.emplace_back(std::move(transfer));
        }

        return transfers;
    }

    uint64_t
        WalletGreen::countNeededMoney(const std::vector<Pastella::WalletTransfer> &destinations, uint64_t fee) const
    {
        uint64_t neededMoney = 0;
        for (const auto &transfer : destinations)
        {
            if (transfer.amount == 0)
            {
                m_logger(ERROR) << "Bad destination: zero amount, address " << transfer.address;
                throw std::system_error(make_error_code(Pastella::error::ZERO_DESTINATION));
            }
            else if (transfer.amount < 0)
            {
                m_logger(ERROR) << "Bad destination: negative amount, address " << transfer.address;
                throw std::system_error(make_error_code(std::errc::invalid_argument));
            }

            // to suppress warning
            uint64_t uamount = static_cast<uint64_t>(transfer.amount);
            if (neededMoney <= std::numeric_limits<uint64_t>::max() - uamount)
            {
                neededMoney += uamount;
            }
            else
            {
                m_logger(ERROR) << "Bad destinations: integer overflow";
                throw std::system_error(make_error_code(Pastella::error::SUM_OVERFLOW));
            }
        }

        if (neededMoney <= std::numeric_limits<uint64_t>::max() - fee)
        {
            neededMoney += fee;
        }
        else
        {
            m_logger(ERROR) << "Bad fee: integer overflow, fee=" << fee;
            throw std::system_error(make_error_code(Pastella::error::SUM_OVERFLOW));
        }

        return neededMoney;
    }

    Pastella::AccountPublicAddress WalletGreen::parseAccountAddressString(const std::string &addressString) const
    {
        Pastella::AccountPublicAddress address;

        if (!m_currency.parseAccountAddressString(addressString, address))
        {
            m_logger(ERROR) << "Bad address: " << addressString;
            throw std::system_error(make_error_code(Pastella::error::BAD_ADDRESS));
        }

        return address;
    }

    uint64_t WalletGreen::pushDonationTransferIfPossible(
        const DonationSettings &donation,
        uint64_t freeAmount,
        uint64_t dustThreshold,
        std::vector<WalletTransfer> &destinations) const
    {
        uint64_t donationAmount = 0;
        if (!donation.address.empty() && donation.threshold != 0)
        {
            if (donation.threshold > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
            {
                std::string message = "Donation threshold must not exceed "
                                      + m_currency.formatAmount(std::numeric_limits<int64_t>::max());
                m_logger(ERROR) << message;
                throw std::system_error(make_error_code(error::WRONG_AMOUNT), message);
            }

            donationAmount = calculateDonationAmount(freeAmount, donation.threshold, dustThreshold);
            if (donationAmount != 0)
            {
                destinations.emplace_back(WalletTransfer {
                    WalletTransferType::DONATION, donation.address, static_cast<int64_t>(donationAmount)});
                m_logger(DEBUGGING) << "Added donation: address " << donation.address << ", amount "
                                    << m_currency.formatAmount(donationAmount);
            }
        }

        return donationAmount;
    }

    void WalletGreen::validateAddresses(const std::vector<std::string> &addresses) const
    {
        for (const auto &address : addresses)
        {
            if (!Pastella::validateAddress(address, m_currency))
            {
                m_logger(ERROR) << "Bad address: " << address;
                throw std::system_error(make_error_code(Pastella::error::BAD_ADDRESS));
            }
        }
    }

    void WalletGreen::validateOrders(const std::vector<WalletOrder> &orders) const
    {
        for (const auto &order : orders)
        {
            if (!Pastella::validateAddress(order.address, m_currency))
            {
                m_logger(ERROR) << "Bad order address: " << order.address;
                throw std::system_error(make_error_code(Pastella::error::BAD_ADDRESS));
            }

            if (order.amount >= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
            {
                std::string message =
                    "Order amount must not exceed " + m_currency.formatAmount(std::numeric_limits<int64_t>::max());
                m_logger(ERROR) << message;
                throw std::system_error(make_error_code(Pastella::error::WRONG_AMOUNT), message);
            }
        }
    }

    void WalletGreen::validateChangeDestination(
        const std::vector<std::string> &sourceAddresses,
        const std::string &changeDestination) const
    {
        std::string message;
        if (changeDestination.empty())
        {
            if (sourceAddresses.size() > 1 || (sourceAddresses.empty() && m_walletsContainer.size() > 1))
            {
                message = "Change destination address is necessary";
                m_logger(ERROR) << message << ". Source addresses size=" << sourceAddresses.size()
                                            << ", wallets count=" << m_walletsContainer.size();
                throw std::system_error(
                    make_error_code(error::CHANGE_ADDRESS_REQUIRED),
                    message);
            }
        }
        else
        {
            if (!Pastella::validateAddress(changeDestination, m_currency))
            {
                message = "Bad change destination address: " + changeDestination;
                m_logger(ERROR) << message;
                throw std::system_error(make_error_code(Pastella::error::BAD_ADDRESS), message);
            }

            if (!isMyAddress(changeDestination))
            {
                message = "Change destination address is not found in current container: " + changeDestination;
                m_logger(ERROR) << message;
                throw std::system_error(
                    make_error_code(error::CHANGE_ADDRESS_NOT_FOUND),
                    message);
            }
        }
    }

    void WalletGreen::validateTransactionParameters(const TransactionParameters &transactionParameters) const
    {
        if (transactionParameters.destinations.empty())
        {
            m_logger(ERROR) << "No destinations";
            throw std::system_error(make_error_code(error::ZERO_DESTINATION));
        }

        if (transactionParameters.fee.isFixedFee && transactionParameters.fee.fixedFee < m_currency.minimumFee())
        {
            std::string message = "Fee is too small. Fee " + m_currency.formatAmount(transactionParameters.fee.fixedFee)
                                  + ", minimum fee " + m_currency.formatAmount(m_currency.minimumFee());
            m_logger(ERROR) << message;
            throw std::system_error(make_error_code(error::FEE_TOO_SMALL), message);
        }

        if (transactionParameters.donation.address.empty() != (transactionParameters.donation.threshold == 0))
        {
            std::string message = "DonationSettings must have both address and threshold parameters filled. Address '"
                                  + transactionParameters.donation.address + "'" + ", threshold "
                                  + m_currency.formatAmount(transactionParameters.donation.threshold);
            m_logger(ERROR) << message;
            throw std::system_error(make_error_code(error::WRONG_PARAMETERS), message);
        }

        validateSourceAddresses(transactionParameters.sourceAddresses);
        validateChangeDestination(
            transactionParameters.sourceAddresses, transactionParameters.changeDestination);
        validateOrders(transactionParameters.destinations);
    }

    size_t WalletGreen::doTransfer(const TransactionParameters &transactionParameters)
    {
        validateTransactionParameters(transactionParameters);
        Pastella::AccountPublicAddress changeDestination =
            getChangeDestination(transactionParameters.changeDestination, transactionParameters.sourceAddresses);
        m_logger(DEBUGGING) << "Change address " << m_currency.accountAddressAsString(changeDestination);

        std::vector<WalletOuts> wallets;
        if (!transactionParameters.sourceAddresses.empty())
        {
            wallets = pickWallets(transactionParameters.sourceAddresses);
        }
        else
        {
            wallets = pickWalletsWithMoney();
        }

        PreparedTransaction preparedTransaction;
        prepareTransaction(
            std::move(wallets),
            transactionParameters.destinations,
            transactionParameters.fee,
            transactionParameters.mixIn,
            transactionParameters.extra,
            transactionParameters.unlockTimestamp,
            transactionParameters.donation,
            changeDestination,
            preparedTransaction);

        return validateSaveAndSendTransaction(
            *preparedTransaction.transaction, preparedTransaction.destinations, true);
    }

    size_t WalletGreen::getTxSize(const PreparedTransaction &p)
    {
        return p.transaction->getTransactionData().size();
    }

    bool WalletGreen::txIsTooLarge(const PreparedTransaction &p)
    {
        return getTxSize(p) > getMaxTxSize();
    }

    PreparedTransaction WalletGreen::formTransaction(const TransactionParameters &sendingTransaction)
    {
        System::EventLock lk(m_readyEvent);

        throwIfNotInitialized();
        throwIfStopped();

        Pastella::AccountPublicAddress changeDestination =
            getChangeDestination(sendingTransaction.changeDestination, sendingTransaction.sourceAddresses);

        std::vector<WalletOuts> wallets;
        if (!sendingTransaction.sourceAddresses.empty())
        {
            wallets = pickWallets(sendingTransaction.sourceAddresses);
        }
        else
        {
            wallets = pickWalletsWithMoney();
        }

        PreparedTransaction preparedTransaction;
        prepareTransaction(
            std::move(wallets),
            sendingTransaction.destinations,
            sendingTransaction.fee,
            sendingTransaction.mixIn,
            sendingTransaction.extra,
            sendingTransaction.unlockTimestamp,
            sendingTransaction.donation,
            changeDestination,
            preparedTransaction);

        return preparedTransaction;
    }

    size_t WalletGreen::makeTransaction(const TransactionParameters &sendingTransaction)
    {
        size_t id = WALLET_INVALID_TRANSACTION_ID;
        Tools::ScopeExit releaseContext([this, &id] {
            m_dispatcher.yield();

            if (id != WALLET_INVALID_TRANSACTION_ID)
            {
                auto &tx = m_transactions[id];
                m_logger(INFO)
                    << "Delayed transaction created, ID " << id << ", hash " << m_transactions[id].hash << ", state "
                    << tx.state << ", totalAmount " << m_currency.formatAmount(tx.totalAmount) << ", fee "
                    << m_currency.formatAmount(tx.fee)
                    << ", transfers: " << TransferListFormatter(m_currency, getTransactionTransfersRange(id));
            }
        });

        System::EventLock lk(m_readyEvent);

        throwIfNotInitialized();
        throwIfStopped();

        m_logger(INFO) << "makeTransaction"
                                     << ", from " << Common::makeContainerFormatter(sendingTransaction.sourceAddresses)
                                     << ", to " << WalletOrderListFormatter(m_currency, sendingTransaction.destinations)
                                     << ", change address '" << sendingTransaction.changeDestination << '\'' << ", mixin "
                                     << sendingTransaction.mixIn << ", unlockTimestamp "
                                     << sendingTransaction.unlockTimestamp;

        validateTransactionParameters(sendingTransaction);
        Pastella::AccountPublicAddress changeDestination =
            getChangeDestination(sendingTransaction.changeDestination, sendingTransaction.sourceAddresses);
        m_logger(DEBUGGING) << "Change address " << m_currency.accountAddressAsString(changeDestination);

        std::vector<WalletOuts> wallets;
        if (!sendingTransaction.sourceAddresses.empty())
        {
            wallets = pickWallets(sendingTransaction.sourceAddresses);
        }
        else
        {
            wallets = pickWalletsWithMoney();
        }

        PreparedTransaction preparedTransaction;
        prepareTransaction(
            std::move(wallets),
            sendingTransaction.destinations,
            sendingTransaction.fee,
            sendingTransaction.mixIn,
            sendingTransaction.extra,
            sendingTransaction.unlockTimestamp,
            sendingTransaction.donation,
            changeDestination,
            preparedTransaction);

        id = validateSaveAndSendTransaction(
            *preparedTransaction.transaction, preparedTransaction.destinations, false);
        return id;
    }

    void WalletGreen::commitTransaction(size_t transactionId)
    {
        System::EventLock lk(m_readyEvent);

        throwIfNotInitialized();
        throwIfStopped();

        if (transactionId >= m_transactions.size())
        {
            m_logger(ERROR) << "Failed to commit transaction: invalid index " << transactionId
                                        << ". Number of transactions: " << m_transactions.size();
            throw std::system_error(make_error_code(Pastella::error::INDEX_OUT_OF_RANGE));
        }

        auto txIt = std::next(m_transactions.get<RandomAccessIndex>().begin(), transactionId);
        if (m_uncommitedTransactions.count(transactionId) == 0 || txIt->state != WalletTransactionState::CREATED)
        {
            m_logger(ERROR) << "Failed to commit transaction: bad transaction state. Transaction index "
                                        << transactionId << ", state " << txIt->state;
            throw std::system_error(make_error_code(error::TX_TRANSFER_IMPOSSIBLE));
        }

        System::Event completion(m_dispatcher);
        std::error_code ec;

        System::RemoteContext<void> relayTransactionContext(m_dispatcher, [this, transactionId, &ec, &completion]() {
            m_node.relayTransaction(
                m_uncommitedTransactions[transactionId], [&ec, &completion, this](std::error_code error) {
                    ec = error;
                    this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(completion)));
                });
        });
        relayTransactionContext.get();
        completion.wait();

        if (!ec)
        {
            updateTransactionStateAndPushEvent(transactionId, WalletTransactionState::SUCCEEDED);
            m_uncommitedTransactions.erase(transactionId);
        }
        else
        {
            m_logger(ERROR) << "Failed to relay transaction: " << ec << ", " << ec.message()
                                        << ". Transaction index " << transactionId;
            throw std::system_error(ec);
        }

        m_logger(INFO) << "Delayed transaction sent, ID " << transactionId << ", hash "
                                     << m_transactions[transactionId].hash;
    }

    void WalletGreen::rollbackUncommitedTransaction(size_t transactionId)
    {
        Tools::ScopeExit releaseContext([this] { m_dispatcher.yield(); });

        System::EventLock lk(m_readyEvent);

        throwIfNotInitialized();
        throwIfStopped();

        if (transactionId >= m_transactions.size())
        {
            m_logger(ERROR) << "Failed to rollback transaction: invalid index " << transactionId
                                        << ". Number of transactions: " << m_transactions.size();
            throw std::system_error(make_error_code(Pastella::error::INDEX_OUT_OF_RANGE));
        }

        auto txIt = m_transactions.get<RandomAccessIndex>().begin();
        std::advance(txIt, transactionId);
        if (m_uncommitedTransactions.count(transactionId) == 0 || txIt->state != WalletTransactionState::CREATED)
        {
            m_logger(ERROR) << "Failed to rollback transaction: bad transaction state. Transaction index "
                                        << transactionId << ", state " << txIt->state;
            throw std::system_error(make_error_code(error::TX_CANCEL_IMPOSSIBLE));
        }

        removeUnconfirmedTransaction(getObjectHash(m_uncommitedTransactions[transactionId]));
        m_uncommitedTransactions.erase(transactionId);

        m_logger(INFO) << "Delayed transaction rolled back, ID " << transactionId << ", hash "
                                     << m_transactions[transactionId].hash;
    }

    void WalletGreen::pushBackOutgoingTransfers(size_t txId, const std::vector<WalletTransfer> &destinations)
    {
        for (const auto &dest : destinations)
        {
            WalletTransfer d;
            d.type = dest.type;
            d.address = dest.address;
            d.amount = dest.amount;

            m_transfers.emplace_back(txId, std::move(d));
        }
    }

    size_t WalletGreen::insertOutgoingTransactionAndPushEvent(
        const Hash &transactionHash,
        uint64_t fee,
        const BinaryArray &extra,
        uint64_t unlockTimestamp)
    {
        WalletTransaction insertTx;
        insertTx.state = WalletTransactionState::CREATED;
        insertTx.creationTime = static_cast<uint64_t>(time(nullptr));
        insertTx.unlockTime = unlockTimestamp;
        insertTx.blockHeight = Pastella::WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
        insertTx.extra.assign(reinterpret_cast<const char *>(extra.data()), extra.size());
        insertTx.fee = fee;
        insertTx.hash = transactionHash;
        insertTx.totalAmount = 0; // 0 until transactionHandlingEnd() is called
        insertTx.timestamp = 0; // 0 until included in a block
        insertTx.isBase = false;

        size_t txId = m_transactions.get<RandomAccessIndex>().size();
        m_transactions.get<RandomAccessIndex>().push_back(std::move(insertTx));

        pushEvent(makeTransactionCreatedEvent(txId));

        return txId;
    }

    void WalletGreen::updateTransactionStateAndPushEvent(size_t transactionId, WalletTransactionState state)
    {
        auto it = std::next(m_transactions.get<RandomAccessIndex>().begin(), transactionId);

        if (it->state != state)
        {
            m_transactions.get<RandomAccessIndex>().modify(it, [state](WalletTransaction &tx) { tx.state = state; });

            pushEvent(makeTransactionUpdatedEvent(transactionId));
            m_logger(DEBUGGING) << "Transaction state changed, ID " << transactionId << ", hash " << it->hash
                                << ", new state " << it->state;
        }
    }

    bool WalletGreen::updateWalletTransactionInfo(
        size_t transactionId,
        const Pastella::TransactionInformation &info,
        int64_t totalAmount)
    {
        auto &txIdIndex = m_transactions.get<RandomAccessIndex>();
        assert(transactionId < txIdIndex.size());
        auto it = std::next(txIdIndex.begin(), transactionId);

        bool updated = false;
        bool r = txIdIndex.modify(it, [&info, totalAmount, &updated](WalletTransaction &transaction) {
            if (transaction.blockHeight != info.blockHeight)
            {
                transaction.blockHeight = info.blockHeight;
                updated = true;
            }

            if (transaction.timestamp != info.timestamp)
            {
                transaction.timestamp = info.timestamp;
                updated = true;
            }

            bool isSucceeded = transaction.state == WalletTransactionState::SUCCEEDED;
            // If transaction was sent to daemon, it can not have CREATED and FAILED states, its state can be SUCCEEDED,
            // CANCELLED or DELETED
            bool wasSent = transaction.state != WalletTransactionState::CREATED
                           && transaction.state != WalletTransactionState::FAILED;
            bool isConfirmed = transaction.blockHeight != WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
            if (!isSucceeded && (wasSent || isConfirmed))
            {
                // transaction may be deleted first then added again
                transaction.state = WalletTransactionState::SUCCEEDED;
                updated = true;
            }

            if (transaction.totalAmount != totalAmount)
            {
                transaction.totalAmount = totalAmount;
                updated = true;
            }

            // Fix LegacyWallet error. Some old versions didn't fill extra field
            if (transaction.extra.empty() && !info.extra.empty())
            {
                transaction.extra = Common::asString(info.extra);
                updated = true;
            }

            bool isBase = info.totalAmountIn == 0;
            if (transaction.isBase != isBase)
            {
                transaction.isBase = isBase;
                updated = true;
            }
        });

        if (r)
        {
        }
        assert(r);

        if (updated)
        {
            m_logger(DEBUGGING) << "Transaction updated, ID " << transactionId << ", hash " << it->hash << ", block "
                                << it->blockHeight << ", state " << it->state;
        }

        return updated;
    }

    size_t WalletGreen::insertBlockchainTransaction(const TransactionInformation &info, int64_t txBalance)
    {
        auto &index = m_transactions.get<RandomAccessIndex>();

        WalletTransaction tx;
        tx.state = WalletTransactionState::SUCCEEDED;
        tx.timestamp = info.timestamp;
        tx.blockHeight = info.blockHeight;
        tx.hash = info.transactionHash;
        tx.isBase = info.totalAmountIn == 0;
        if (tx.isBase)
        {
            tx.fee = 0;
        }
        else
        {
            tx.fee = info.totalAmountIn - info.totalAmountOut;
        }

        tx.unlockTime = info.unlockTime;
        tx.extra.assign(reinterpret_cast<const char *>(info.extra.data()), info.extra.size());
        tx.totalAmount = txBalance;
        tx.creationTime = info.timestamp;

        size_t txId = index.size();
        index.push_back(std::move(tx));

        m_logger(DEBUGGING) << "Transaction added, ID " << txId << ", hash " << tx.hash << ", block " << tx.blockHeight
                            << ", state " << tx.state;

        return txId;
    }

    bool WalletGreen::updateTransactionTransfers(
        size_t transactionId,
        const std::vector<ContainerAmounts> &containerAmountsList,
        int64_t allInputsAmount,
        int64_t allOutputsAmount)
    {
        assert(allInputsAmount <= 0);
        assert(allOutputsAmount >= 0);

        bool updated = false;

        auto transfersRange = getTransactionTransfersRange(transactionId);
        // Iterators can be invalidated, so the first transfer is addressed by its index
        size_t firstTransferIdx = std::distance(m_transfers.cbegin(), transfersRange.first);

        TransfersMap initialTransfers = getKnownTransfersMap(transactionId, firstTransferIdx);

        std::unordered_set<std::string> myInputAddresses;
        std::unordered_set<std::string> myOutputAddresses;
        int64_t myInputsAmount = 0;
        int64_t myOutputsAmount = 0;
        for (auto containerAmount : containerAmountsList)
        {
            AccountPublicAddress address;
            address.publicKey = getWalletRecord(containerAmount.container).publicKey;
            std::string addressString = m_currency.accountAddressAsString(address);

            updated |= updateAddressTransfers(
                transactionId,
                firstTransferIdx,
                addressString,
                initialTransfers[addressString].input,
                containerAmount.amounts.input);
            updated |= updateAddressTransfers(
                transactionId,
                firstTransferIdx,
                addressString,
                initialTransfers[addressString].output,
                containerAmount.amounts.output);

            myInputsAmount += containerAmount.amounts.input;
            myOutputsAmount += containerAmount.amounts.output;

            if (containerAmount.amounts.input != 0)
            {
                myInputAddresses.emplace(addressString);
            }

            if (containerAmount.amounts.output != 0)
            {
                myOutputAddresses.emplace(addressString);
            }
        }

        assert(myInputsAmount >= allInputsAmount);
        assert(myOutputsAmount <= allOutputsAmount);

        int64_t knownInputsAmount = 0;
        int64_t knownOutputsAmount = 0;
        auto updatedTransfers = getKnownTransfersMap(transactionId, firstTransferIdx);
        for (const auto &pair : updatedTransfers)
        {
            knownInputsAmount += pair.second.input;
            knownOutputsAmount += pair.second.output;
        }

        assert(myInputsAmount >= knownInputsAmount);
        assert(myOutputsAmount <= knownOutputsAmount);

        updated |= updateUnknownTransfers(
            transactionId,
            firstTransferIdx,
            myInputAddresses,
            knownInputsAmount,
            myInputsAmount,
            allInputsAmount,
            false);
        updated |= updateUnknownTransfers(
            transactionId,
            firstTransferIdx,
            myOutputAddresses,
            knownOutputsAmount,
            myOutputsAmount,
            allOutputsAmount,
            true);

        return updated;
    }

    WalletGreen::TransfersMap WalletGreen::getKnownTransfersMap(size_t transactionId, size_t firstTransferIdx) const
    {
        TransfersMap result;

        for (auto it = std::next(m_transfers.begin(), firstTransferIdx);
             it != m_transfers.end() && it->first == transactionId;
             ++it)
        {
            const auto &address = it->second.address;

            if (!address.empty())
            {
                if (it->second.amount < 0)
                {
                    result[address].input += it->second.amount;
                }
                else
                {
                    assert(it->second.amount > 0);
                    result[address].output += it->second.amount;
                }
            }
        }

        return result;
    }

    bool WalletGreen::updateAddressTransfers(
        size_t transactionId,
        size_t firstTransferIdx,
        const std::string &address,
        int64_t knownAmount,
        int64_t targetAmount)
    {
        assert(
            (knownAmount > 0 && targetAmount > 0) || (knownAmount < 0 && targetAmount < 0) || knownAmount == 0
            || targetAmount == 0);

        bool updated = false;

        if (knownAmount != targetAmount)
        {
            if (knownAmount == 0)
            {
                appendTransfer(transactionId, firstTransferIdx, address, targetAmount);
                updated = true;
            }
            else if (targetAmount == 0)
            {
                assert(knownAmount != 0);
                updated |= eraseTransfersByAddress(transactionId, firstTransferIdx, address, knownAmount > 0);
            }
            else
            {
                updated |= adjustTransfer(transactionId, firstTransferIdx, address, targetAmount);
            }
        }

        return updated;
    }

    bool WalletGreen::updateUnknownTransfers(
        size_t transactionId,
        size_t firstTransferIdx,
        const std::unordered_set<std::string> &myAddresses,
        int64_t knownAmount,
        int64_t myAmount,
        int64_t totalAmount,
        bool isOutput)
    {
        bool updated = false;

        if (std::abs(knownAmount) > std::abs(totalAmount))
        {
            updated |= eraseForeignTransfers(transactionId, firstTransferIdx, myAddresses, isOutput);
            if (totalAmount == myAmount)
            {
                updated |= eraseTransfersByAddress(transactionId, firstTransferIdx, std::string(), isOutput);
            }
            else
            {
                assert(std::abs(totalAmount) > std::abs(myAmount));
                updated |= adjustTransfer(transactionId, firstTransferIdx, std::string(), totalAmount - myAmount);
            }
        }
        else if (knownAmount == totalAmount)
        {
            updated |= eraseTransfersByAddress(transactionId, firstTransferIdx, std::string(), isOutput);
        }
        else
        {
            assert(std::abs(totalAmount) > std::abs(knownAmount));
            updated |= adjustTransfer(transactionId, firstTransferIdx, std::string(), totalAmount - knownAmount);
        }

        return updated;
    }

    void WalletGreen::appendTransfer(
        size_t transactionId,
        size_t firstTransferIdx,
        const std::string &address,
        int64_t amount)
    {
        auto it = std::next(m_transfers.begin(), firstTransferIdx);
        auto insertIt = std::upper_bound(
            it, m_transfers.end(), transactionId, [](size_t transactionId, const TransactionTransferPair &pair) {
                return transactionId < pair.first;
            });

        WalletTransfer transfer {WalletTransferType::USUAL, address, amount};
        m_transfers.emplace(
            insertIt, std::piecewise_construct, std::forward_as_tuple(transactionId), std::forward_as_tuple(transfer));
    }

    bool WalletGreen::adjustTransfer(
        size_t transactionId,
        size_t firstTransferIdx,
        const std::string &address,
        int64_t amount)
    {
        assert(amount != 0);

        bool updated = false;
        bool updateOutputTransfers = amount > 0;
        bool firstAddressTransferFound = false;
        auto it = std::next(m_transfers.begin(), firstTransferIdx);
        while (it != m_transfers.end() && it->first == transactionId)
        {
            assert(it->second.amount != 0);
            bool transferIsOutput = it->second.amount > 0;
            if (transferIsOutput == updateOutputTransfers && it->second.address == address)
            {
                if (firstAddressTransferFound)
                {
                    it = m_transfers.erase(it);
                    updated = true;
                }
                else
                {
                    if (it->second.amount != amount)
                    {
                        it->second.amount = amount;
                        updated = true;
                    }

                    firstAddressTransferFound = true;
                    ++it;
                }
            }
            else
            {
                ++it;
            }
        }

        if (!firstAddressTransferFound)
        {
            WalletTransfer transfer {WalletTransferType::USUAL, address, amount};
            m_transfers.emplace(
                it, std::piecewise_construct, std::forward_as_tuple(transactionId), std::forward_as_tuple(transfer));
            updated = true;
        }

        return updated;
    }

    bool WalletGreen::eraseTransfers(
        size_t transactionId,
        size_t firstTransferIdx,
        std::function<bool(bool, const std::string &)> &&predicate)
    {
        bool erased = false;
        auto it = std::next(m_transfers.begin(), firstTransferIdx);
        while (it != m_transfers.end() && it->first == transactionId)
        {
            bool transferIsOutput = it->second.amount > 0;
            if (predicate(transferIsOutput, it->second.address))
            {
                it = m_transfers.erase(it);
                erased = true;
            }
            else
            {
                ++it;
            }
        }

        return erased;
    }

    bool WalletGreen::eraseTransfersByAddress(
        size_t transactionId,
        size_t firstTransferIdx,
        const std::string &address,
        bool eraseOutputTransfers)
    {
        return eraseTransfers(
            transactionId,
            firstTransferIdx,
            [&address, eraseOutputTransfers](bool isOutput, const std::string &transferAddress) {
                return eraseOutputTransfers == isOutput && address == transferAddress;
            });
    }

    bool WalletGreen::eraseForeignTransfers(
        size_t transactionId,
        size_t firstTransferIdx,
        const std::unordered_set<std::string> &knownAddresses,
        bool eraseOutputTransfers)
    {
        return eraseTransfers(
            transactionId,
            firstTransferIdx,
            [&knownAddresses, eraseOutputTransfers](bool isOutput, const std::string &transferAddress) {
                return eraseOutputTransfers == isOutput && knownAddresses.count(transferAddress) == 0;
            });
    }

    std::unique_ptr<Pastella::ITransaction> WalletGreen::makeTransaction(
        const std::vector<ReceiverAmounts> &decomposedOutputs,
        std::vector<InputInfo> &keysInfo,
        const std::string &extra,
        uint64_t unlockTimestamp)
    {
        std::unique_ptr<ITransaction> tx = createTransaction();

        typedef std::pair<const AccountPublicAddress *, uint64_t> AmountToAddress;
        std::vector<AmountToAddress> amountsToAddresses;
        for (const auto &output : decomposedOutputs)
        {
            for (auto amount : output.amounts)
            {
                amountsToAddresses.emplace_back(AmountToAddress {&output.receiver, amount});
            }
        }

        std::shuffle(amountsToAddresses.begin(), amountsToAddresses.end(), Random::generator());
        std::sort(
            amountsToAddresses.begin(),
            amountsToAddresses.end(),
            [](const AmountToAddress &left, const AmountToAddress &right) { return left.second < right.second; });

        for (const auto &amountToAddress : amountsToAddresses)
        {
            tx->addOutput(amountToAddress.second, *amountToAddress.first);
        }

        tx->setUnlockTime(unlockTimestamp);
        tx->appendExtra(Common::asBinaryArray(extra));

        for (auto &input : keysInfo)
        {
            tx->addInput(makeAccountKeys(*input.walletRecord), input.keyInfo, input.ephKeys);
        }

        size_t i = 0;
        for (auto &input : keysInfo)
        {
            tx->signInputKey(i++, input.keyInfo, input.ephKeys);
        }

        m_logger(DEBUGGING) << "Transaction created, hash " << tx->getTransactionHash() << ", inputs "
                            << m_currency.formatAmount(tx->getInputTotalAmount()) << ", outputs "
                            << m_currency.formatAmount(tx->getOutputTotalAmount()) << ", fee "
                            << m_currency.formatAmount(tx->getInputTotalAmount() - tx->getOutputTotalAmount());
        return tx;
    }

    void WalletGreen::sendTransaction(const Pastella::Transaction &PastellaTransaction)
    {
        System::Event completion(m_dispatcher);
        std::error_code ec;

        throwIfStopped();

        System::RemoteContext<void> relayTransactionContext(
            m_dispatcher, [this, &PastellaTransaction, &ec, &completion]() {
                m_node.relayTransaction(PastellaTransaction, [&ec, &completion, this](std::error_code error) {
                    ec = error;
                    this->m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(completion)));
                });
            });
        relayTransactionContext.get();
        completion.wait();

        if (ec)
        {
            m_logger(ERROR) << "Failed to relay transaction: " << ec << ", " << ec.message()
                                        << ". Transaction hash " << getObjectHash(PastellaTransaction);
            throw std::system_error(ec);
        }
    }

    size_t WalletGreen::validateSaveAndSendTransaction(
        const ITransactionReader &transaction,
        const std::vector<WalletTransfer> &destinations,
        bool send)
    {
        BinaryArray transactionData = transaction.getTransactionData();

        size_t maxTxSize = getMaxTxSize();

        if (transactionData.size() > maxTxSize)
        {
            m_logger(ERROR) << "Transaction is too big. Transaction hash "
                                        << transaction.getTransactionHash() << ", size " << transactionData.size()
                                        << ", size limit " << maxTxSize;
            throw std::system_error(make_error_code(error::TRANSACTION_SIZE_TOO_BIG));
        }

        Pastella::Transaction PastellaTransaction;
        if (!fromBinaryArray(PastellaTransaction, transactionData))
        {
            m_logger(ERROR) << "Failed to deserialize created transaction. Transaction hash "
                                        << transaction.getTransactionHash();
            throw std::system_error(
                make_error_code(error::INTERNAL_WALLET_ERROR), "Failed to deserialize created transaction");
        }

        if (PastellaTransaction.outputs.size() > Pastella::parameters::NORMAL_TX_MAX_OUTPUT_COUNT_V1)
        {
            m_logger(ERROR) << "Transaction has an excessive number of outputs";

            throw std::system_error(make_error_code(error::EXCESSIVE_OUTPUTS));
        }

        if (PastellaTransaction.extra.size() >= Pastella::parameters::MAX_EXTRA_SIZE_V2)
        {
            m_logger(ERROR) << "Transaction extra is too large. Allowed: "
                                        << Pastella::parameters::MAX_EXTRA_SIZE_V2
                                        << ", actual: " << PastellaTransaction.extra.size() << ".";

            throw std::system_error(make_error_code(error::EXTRA_TOO_LARGE), "Transaction extra too large");
        }

        uint64_t fee = transaction.getInputTotalAmount() - transaction.getOutputTotalAmount();
        size_t transactionId = insertOutgoingTransactionAndPushEvent(
            transaction.getTransactionHash(), fee, transaction.getExtra(), transaction.getUnlockTime());
        m_logger(DEBUGGING) << "Transaction added to container, ID " << transactionId << ", hash "
                            << transaction.getTransactionHash() << ", block "
                            << m_transactions[transactionId].blockHeight << ", state "
                            << m_transactions[transactionId].state;
        Tools::ScopeExit rollbackTransactionInsertion([this, transactionId] {
            updateTransactionStateAndPushEvent(transactionId, WalletTransactionState::FAILED);
        });

        pushBackOutgoingTransfers(transactionId, destinations);

        addUnconfirmedTransaction(transaction);
        Tools::ScopeExit rollbackAddingUnconfirmedTransaction([this, &transaction] {
            try
            {
                removeUnconfirmedTransaction(transaction.getTransactionHash());
            }
            catch (...)
            {
                // Ignore any exceptions. If rollback fails then the transaction is stored as unconfirmed and will be
                // deleted after wallet relaunch during transaction pool synchronization
                m_logger(ERROR)
                    << "Unknown exception while removing unconfirmed transaction " << transaction.getTransactionHash();
            }
        });

        if (send)
        {
            sendTransaction(PastellaTransaction);
            m_logger(DEBUGGING) << "Transaction sent to node, ID " << transactionId << ", hash "
                                << transaction.getTransactionHash();
            updateTransactionStateAndPushEvent(transactionId, WalletTransactionState::SUCCEEDED);
        }
        else
        {
            assert(m_uncommitedTransactions.count(transactionId) == 0);
            m_uncommitedTransactions.emplace(transactionId, std::move(PastellaTransaction));
            m_logger(DEBUGGING) << "Transaction delayed, ID " << transactionId << ", hash "
                                << transaction.getTransactionHash();
        }

        rollbackAddingUnconfirmedTransaction.cancel();
        rollbackTransactionInsertion.cancel();

        return transactionId;
    }

    AccountKeys WalletGreen::makeAccountKeys(const WalletRecord &wallet) const
    {
        AccountKeys keys;
        keys.address.publicKey = wallet.publicKey;
        keys.secretKey = wallet.secretKey;

        return keys;
    }

    void WalletGreen::requestMixinOuts(
        const std::vector<OutputToTransfer> &selectedTransfers,
        uint16_t mixIn,
        std::vector<Pastella::RandomOuts> &mixinResult)
    {
        std::vector<uint64_t> amounts;
        for (const auto &out : selectedTransfers)
        {
            amounts.push_back(out.out.amount);
        }

        System::Event requestFinished(m_dispatcher);
        std::error_code mixinError;

        throwIfStopped();

        uint16_t requestMixinCount = mixIn + 1; //+1 to allow to skip real output

        m_logger(DEBUGGING) << "Requesting random outputs";
        System::RemoteContext<void> getOutputsContext(
            m_dispatcher, [this, amounts, requestMixinCount, &mixinResult, &requestFinished, &mixinError]() mutable {
                m_node.getRandomOutsByAmounts(
                    std::move(amounts),
                    requestMixinCount,
                    mixinResult,
                    [&requestFinished, &mixinError, this](std::error_code ec) mutable {
                        mixinError = ec;
                        m_dispatcher.remoteSpawn(std::bind(asyncRequestCompletion, std::ref(requestFinished)));
                    });
            });
        getOutputsContext.get();
        requestFinished.wait();

        checkIfEnoughMixins(mixinResult, requestMixinCount);

        if (mixinError)
        {
            m_logger(ERROR) << "Failed to get inputs: " << mixinError << ", "
                                        << mixinError.message();
            throw std::system_error(mixinError);
        }

        m_logger(DEBUGGING) << "Random outputs received";
    }

    uint64_t WalletGreen::selectTransfers(
        uint64_t neededMoney,
        bool dust,
        uint64_t dustThreshold,
        std::vector<WalletOuts> &&wallets,
        std::vector<OutputToTransfer> &selectedTransfers)
    {
        uint64_t foundMoney = 0;

        typedef std::pair<WalletRecord *, TransactionOutputInformation> OutputData;
        std::vector<OutputData> dustOutputs;
        std::vector<OutputData> walletOuts;
        for (auto walletIt = wallets.begin(); walletIt != wallets.end(); ++walletIt)
        {
            for (auto outIt = walletIt->outs.begin(); outIt != walletIt->outs.end(); ++outIt)
            {
                if (outIt->amount > dustThreshold)
                {
                    walletOuts.emplace_back(
                        std::piecewise_construct,
                        std::forward_as_tuple(walletIt->wallet),
                        std::forward_as_tuple(*outIt));
                }
                else if (dust)
                {
                    dustOutputs.emplace_back(
                        std::piecewise_construct,
                        std::forward_as_tuple(walletIt->wallet),
                        std::forward_as_tuple(*outIt));
                }
            }
        }

        ShuffleGenerator<size_t> indexGenerator(walletOuts.size());
        while (foundMoney < neededMoney && !indexGenerator.empty())
        {
            auto &out = walletOuts[indexGenerator()];
            foundMoney += out.second.amount;
            selectedTransfers.emplace_back(OutputToTransfer {std::move(out.second), std::move(out.first)});
        }

        if (dust && !dustOutputs.empty())
        {
            ShuffleGenerator<size_t> dustIndexGenerator(dustOutputs.size());
            do
            {
                auto &out = dustOutputs[dustIndexGenerator()];
                foundMoney += out.second.amount;
                selectedTransfers.emplace_back(OutputToTransfer {std::move(out.second), std::move(out.first)});
            } while (foundMoney < neededMoney && !dustIndexGenerator.empty());
        }

        return foundMoney;
    };

    std::vector<WalletGreen::WalletOuts> WalletGreen::pickWalletsWithMoney() const
    {
        auto &walletsIndex = m_walletsContainer.get<RandomAccessIndex>();

        std::vector<WalletOuts> walletOuts;
        for (const auto &wallet : walletsIndex)
        {
            if (wallet.actualBalance == 0)
            {
                continue;
            }

            ITransfersContainer *container = wallet.container;

            WalletOuts outs;
            container->getOutputs(outs.outs, ITransfersContainer::IncludeKeyUnlocked);
            outs.wallet = const_cast<WalletRecord *>(&wallet);

            walletOuts.push_back(std::move(outs));
        };

        return walletOuts;
    }

    WalletGreen::WalletOuts WalletGreen::pickWallet(const std::string &address) const
    {
        const auto &wallet = getWalletRecord(address);

        ITransfersContainer *container = wallet.container;
        WalletOuts outs;
        container->getOutputs(outs.outs, ITransfersContainer::IncludeKeyUnlocked);
        outs.wallet = const_cast<WalletRecord *>(&wallet);

        return outs;
    }

    std::vector<WalletGreen::WalletOuts> WalletGreen::pickWallets(const std::vector<std::string> &addresses) const
    {
        std::vector<WalletOuts> wallets;
        wallets.reserve(addresses.size());

        for (const auto &address : addresses)
        {
            WalletOuts wallet = pickWallet(address);
            if (!wallet.outs.empty())
            {
                wallets.emplace_back(std::move(wallet));
            }
        }

        return wallets;
    }

    std::vector<Pastella::WalletGreen::ReceiverAmounts> WalletGreen::splitDestinations(
        const std::vector<Pastella::WalletTransfer> &destinations,
        uint64_t dustThreshold,
        const Pastella::Currency &currency)
    {
        std::vector<ReceiverAmounts> decomposedOutputs;
        for (const auto &destination : destinations)
        {
            AccountPublicAddress address = parseAccountAddressString(destination.address);
            decomposedOutputs.push_back(splitAmount(destination.amount, address, dustThreshold));
        }

        return decomposedOutputs;
    }

    Pastella::WalletGreen::ReceiverAmounts
        WalletGreen::splitAmount(uint64_t amount, const AccountPublicAddress &destination, uint64_t dustThreshold)
    {
        ReceiverAmounts receiverAmounts;

        receiverAmounts.receiver = destination;
        receiverAmounts.amounts = SendTransaction::splitAmountIntoDenominations(amount);
        return receiverAmounts;
    }

    void WalletGreen::prepareInputs(
        const std::vector<OutputToTransfer> &selectedTransfers,
        std::vector<Pastella::RandomOuts> &mixinResult,
        uint16_t mixIn,
        std::vector<InputInfo> &keysInfo)
    {
        size_t i = 0;
        for (const auto &input : selectedTransfers)
        {
            TransactionTypes::InputKeyInfo keyInfo;
            keyInfo.amount = input.out.amount;

            if (mixinResult.size())
            {
                std::sort(mixinResult[i].outs.begin(), mixinResult[i].outs.end(), [](const auto &a, const auto &b) {
                    return a.global_amount_index < b.global_amount_index;
                });
                for (auto &fakeOut : mixinResult[i].outs)
                {
                    if (input.out.globalOutputIndex == fakeOut.global_amount_index)
                    {
                        continue;
                    }

                    TransactionTypes::GlobalOutput globalOutput;
                    globalOutput.outputIndex = static_cast<uint32_t>(fakeOut.global_amount_index);
                    globalOutput.targetKey = reinterpret_cast<PublicKey &>(fakeOut.out_key);
                    keyInfo.outputs.push_back(std::move(globalOutput));
                    if (keyInfo.outputs.size() >= mixIn)
                    {
                        break;
                    }
                }
            }

            // paste real transaction to the random index
            auto insertIn = std::find_if(
                keyInfo.outputs.begin(), keyInfo.outputs.end(), [&](const TransactionTypes::GlobalOutput &a) {
                    return a.outputIndex >= input.out.globalOutputIndex;
                });

            TransactionTypes::GlobalOutput realOutput;
            realOutput.outputIndex = input.out.globalOutputIndex;
            realOutput.targetKey = reinterpret_cast<const PublicKey &>(input.out.outputKey);

            auto insertedIn = keyInfo.outputs.insert(insertIn, realOutput);

            keyInfo.realOutput.transactionPublicKey =
                reinterpret_cast<const PublicKey &>(input.out.transactionPublicKey);
            keyInfo.realOutput.transactionIndex = static_cast<size_t>(insertedIn - keyInfo.outputs.begin());
            keyInfo.realOutput.outputInTransaction = input.out.outputInTransaction;

            // Important! outputs in selectedTransfers and in keysInfo must have the same order!
            InputInfo inputInfo;
            inputInfo.keyInfo = std::move(keyInfo);
            inputInfo.walletRecord = input.wallet;
            keysInfo.push_back(std::move(inputInfo));
            ++i;
        }
    }

    WalletTransactionWithTransfers WalletGreen::getTransaction(const Crypto::Hash &transactionHash) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        auto &hashIndex = m_transactions.get<TransactionIndex>();
        auto it = hashIndex.find(transactionHash);
        if (it == hashIndex.end())
        {
            m_logger(ERROR) << "Failed to get transaction: not found. Transaction hash " << transactionHash;
            throw std::system_error(make_error_code(error::OBJECT_NOT_FOUND), "Transaction not found");
        }

        WalletTransactionWithTransfers walletTransaction;
        walletTransaction.transaction = *it;
        walletTransaction.transfers = getTransactionTransfers(*it);

        return walletTransaction;
    }

    std::vector<TransactionsInBlockInfo> WalletGreen::getTransactions(const Crypto::Hash &blockHash, size_t count) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        auto &hashIndex = m_blockchain.get<BlockHashIndex>();
        auto it = hashIndex.find(blockHash);
        if (it == hashIndex.end())
        {
            return std::vector<TransactionsInBlockInfo>();
        }

        auto heightIt = m_blockchain.project<BlockHeightIndex>(it);

        uint32_t blockIndex =
            static_cast<uint32_t>(std::distance(m_blockchain.get<BlockHeightIndex>().begin(), heightIt));
        return getTransactionsInBlocks(blockIndex, count);
    }

    std::vector<TransactionsInBlockInfo> WalletGreen::getTransactions(uint32_t blockIndex, size_t count) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        return getTransactionsInBlocks(blockIndex, count);
    }

    std::vector<Crypto::Hash> WalletGreen::getBlockHashes(uint32_t blockIndex, size_t count) const
    {
        throwIfNotInitialized();
        throwIfStopped();

        auto &index = m_blockchain.get<BlockHeightIndex>();

        if (blockIndex >= index.size())
        {
            return std::vector<Crypto::Hash>();
        }

        auto start = std::next(index.begin(), blockIndex);
        auto end = std::next(index.begin(), std::min(index.size(), blockIndex + count));
        return std::vector<Crypto::Hash>(start, end);
    }

    uint32_t WalletGreen::getBlockCount() const
    {
        throwIfNotInitialized();
        throwIfStopped();

        uint32_t blockCount = static_cast<uint32_t>(m_blockchain.size());
        assert(blockCount != 0);

        return blockCount;
    }

    std::vector<WalletTransactionWithTransfers> WalletGreen::getUnconfirmedTransactions() const
    {
        throwIfNotInitialized();
        throwIfStopped();

        std::vector<WalletTransactionWithTransfers> result;
        auto lowerBound = m_transactions.get<BlockHeightIndex>().lower_bound(WALLET_UNCONFIRMED_TRANSACTION_HEIGHT);
        for (auto it = lowerBound; it != m_transactions.get<BlockHeightIndex>().end(); ++it)
        {
            if (it->state != WalletTransactionState::SUCCEEDED)
            {
                continue;
            }

            WalletTransactionWithTransfers transaction;
            transaction.transaction = *it;
            transaction.transfers = getTransactionTransfers(*it);

            result.push_back(transaction);
        }

        return result;
    }

    std::vector<size_t> WalletGreen::getDelayedTransactionIds() const
    {
        throwIfNotInitialized();
        throwIfStopped();

        std::vector<size_t> result;
        result.reserve(m_uncommitedTransactions.size());

        for (const auto &kv : m_uncommitedTransactions)
        {
            result.push_back(kv.first);
        }

        return result;
    }

    void WalletGreen::start()
    {
        m_logger(INFO) << "Starting container";
        m_stopped = false;
    }

    void WalletGreen::stop()
    {
        m_logger(INFO) << "Stopping container";
        m_stopped = true;
        m_eventOccurred.set();
    }

    WalletEvent WalletGreen::getEvent()
    {
        throwIfNotInitialized();
        throwIfStopped();

        while (m_events.empty())
        {
            m_eventOccurred.wait();
            m_eventOccurred.clear();
            throwIfStopped();
        }

        WalletEvent event = std::move(m_events.front());
        m_events.pop();

        return event;
    }

    void WalletGreen::throwIfNotInitialized() const
    {
        if (m_state != WalletState::INITIALIZED)
        {
            m_logger(ERROR) << "WalletGreen is not initialized. Current state: " << m_state;
            throw std::system_error(make_error_code(Pastella::error::NOT_INITIALIZED));
        }
    }

    void WalletGreen::onError(ITransfersSubscription *object, uint32_t height, std::error_code ec)
    {
        m_logger(ERROR) << "Synchronization error: " << ec << ", " << ec.message() << ", height " << height;
    }

    void WalletGreen::synchronizationProgressUpdated(uint32_t processedBlockCount, uint32_t totalBlockCount)
    {
        m_dispatcher.remoteSpawn([processedBlockCount, totalBlockCount, this]() {
            onSynchronizationProgressUpdated(processedBlockCount, totalBlockCount);
        });
    }

    void WalletGreen::synchronizationCompleted(std::error_code result)
    {
        m_dispatcher.remoteSpawn([this]() { onSynchronizationCompleted(); });
    }

    void WalletGreen::onSynchronizationProgressUpdated(uint32_t processedBlockCount, uint32_t totalBlockCount)
    {
        assert(processedBlockCount > 0);

        System::EventLock lk(m_readyEvent);

        m_logger(TRACE) << "onSynchronizationProgressUpdated processedBlockCount " << processedBlockCount
                        << ", totalBlockCount " << totalBlockCount;

        if (m_state == WalletState::NOT_INITIALIZED)
        {
            return;
        }

        pushEvent(makeSyncProgressUpdatedEvent(processedBlockCount, totalBlockCount));

        uint32_t currentHeight = processedBlockCount - 1;
        unlockBalances(currentHeight);
    }

    void WalletGreen::onSynchronizationCompleted()
    {
        System::EventLock lk(m_readyEvent);

        m_logger(TRACE) << "onSynchronizationCompleted";

        if (m_state == WalletState::NOT_INITIALIZED)
        {
            return;
        }

        pushEvent(makeSyncCompletedEvent());
    }

    void
        WalletGreen::onBlocksAdded(const Crypto::PublicKey &publicKey, const std::vector<Crypto::Hash> &blockHashes)
    {
        m_dispatcher.remoteSpawn([this, blockHashes]() { blocksAdded(blockHashes); });
    }

    void WalletGreen::blocksAdded(const std::vector<Crypto::Hash> &blockHashes)
    {
        System::EventLock lk(m_readyEvent);

        if (m_state == WalletState::NOT_INITIALIZED)
        {
            return;
        }

        m_blockchain.insert(m_blockchain.end(), blockHashes.begin(), blockHashes.end());
    }

    void WalletGreen::onBlockchainDetach(const Crypto::PublicKey &publicKey, uint32_t blockIndex)
    {
        m_dispatcher.remoteSpawn([this, blockIndex]() { blocksRollback(blockIndex); });
    }

    void WalletGreen::blocksRollback(uint32_t blockIndex)
    {
        System::EventLock lk(m_readyEvent);

        m_logger(TRACE) << "blocksRollback " << blockIndex;

        if (m_state == WalletState::NOT_INITIALIZED)
        {
            return;
        }

        auto &blockHeightIndex = m_blockchain.get<BlockHeightIndex>();
        blockHeightIndex.erase(std::next(blockHeightIndex.begin(), blockIndex), blockHeightIndex.end());
    }

    void WalletGreen::onTransactionDeleteBegin(const Crypto::PublicKey &publicKey, Crypto::Hash transactionHash)
    {
        m_dispatcher.remoteSpawn([=]() { transactionDeleteBegin(transactionHash); });
    }

    // TODO remove
    void WalletGreen::transactionDeleteBegin(Crypto::Hash transactionHash)
    {
        m_logger(TRACE) << "transactionDeleteBegin " << transactionHash;
    }

    void WalletGreen::onTransactionDeleteEnd(const Crypto::PublicKey &publicKey, Crypto::Hash transactionHash)
    {
        m_dispatcher.remoteSpawn([=]() { transactionDeleteEnd(transactionHash); });
    }

    // TODO remove
    void WalletGreen::transactionDeleteEnd(Crypto::Hash transactionHash)
    {
        m_logger(TRACE) << "transactionDeleteEnd " << transactionHash;
    }

    void WalletGreen::unlockBalances(uint32_t height)
    {
        auto &index = m_unlockTransactionsJob.get<BlockHeightIndex>();
        auto upper = index.upper_bound(height);

        if (index.begin() != upper)
        {
            for (auto it = index.begin(); it != upper; ++it)
            {
                updateBalance(it->container);
            }

            index.erase(index.begin(), upper);
            pushEvent(makeMoneyUnlockedEvent());
        }
    }

    void
        WalletGreen::onTransactionUpdated(ITransfersSubscription * /*object*/, const Crypto::Hash & /*transactionHash*/)
    {
        // Deprecated, ignore it. New event handler is onTransactionUpdated(const Crypto::PublicKey&, const
        // Crypto::Hash&, const std::vector<ITransfersContainer*>&)
    }

    void WalletGreen::onTransactionUpdated(
        const Crypto::PublicKey &,
        const Crypto::Hash &transactionHash,
        const std::vector<ITransfersContainer *> &containers)
    {
        assert(!containers.empty());

        TransactionInformation info;
        std::vector<ContainerAmounts> containerAmountsList;
        containerAmountsList.reserve(containers.size());
        for (auto container : containers)
        {
            uint64_t inputsAmount;
            // Don't move this code to the following remote spawn, because it guarantees that the container has the
            // transaction
            uint64_t outputsAmount;
            bool found = container->getTransactionInformation(transactionHash, info, &inputsAmount, &outputsAmount);
            if (found)
            {
            }
            assert(found);

            ContainerAmounts containerAmounts;
            containerAmounts.container = container;
            containerAmounts.amounts.input = -static_cast<int64_t>(inputsAmount);
            containerAmounts.amounts.output = static_cast<int64_t>(outputsAmount);
            containerAmountsList.emplace_back(std::move(containerAmounts));
        }

        m_dispatcher.remoteSpawn(
            [this, info, containerAmountsList] { this->transactionUpdated(info, containerAmountsList); });
    }

    void WalletGreen::transactionUpdated(
        const TransactionInformation &transactionInfo,
        const std::vector<ContainerAmounts> &containerAmountsList)
    {
        System::EventLock lk(m_readyEvent);

        m_logger(DEBUGGING) << "transactionUpdated event, hash " << transactionInfo.transactionHash << ", block "
                            << transactionInfo.blockHeight << ", totalAmountIn "
                            << m_currency.formatAmount(transactionInfo.totalAmountIn) << ", totalAmountOut "
                            << m_currency.formatAmount(transactionInfo.totalAmountOut);

        if (m_state == WalletState::NOT_INITIALIZED)
        {
            return;
        }

        bool updated = false;
        bool isNew = false;

        int64_t totalAmount = std::accumulate(
            containerAmountsList.begin(),
            containerAmountsList.end(),
            static_cast<int64_t>(0),
            [](int64_t sum, const ContainerAmounts &containerAmounts) {
                return sum + containerAmounts.amounts.input + containerAmounts.amounts.output;
            });

        size_t transactionId;
        auto &hashIndex = m_transactions.get<TransactionIndex>();
        auto it = hashIndex.find(transactionInfo.transactionHash);
        if (it != hashIndex.end())
        {
            transactionId = std::distance(
                m_transactions.get<RandomAccessIndex>().begin(), m_transactions.project<RandomAccessIndex>(it));
            updated |= updateWalletTransactionInfo(transactionId, transactionInfo, totalAmount);
        }
        else
        {
            isNew = true;
            transactionId = insertBlockchainTransaction(transactionInfo, totalAmount);
        }

        if (transactionInfo.blockHeight != Pastella::WALLET_UNCONFIRMED_TRANSACTION_HEIGHT)
        {
            // In some cases a transaction can be included to a block but not removed from m_uncommitedTransactions. Fix
            // it
            m_uncommitedTransactions.erase(transactionId);
        }

        // Update cached balance
        for (auto containerAmounts : containerAmountsList)
        {
            updateBalance(containerAmounts.container);

            if (transactionInfo.blockHeight != Pastella::WALLET_UNCONFIRMED_TRANSACTION_HEIGHT)
            {
                uint32_t unlockHeight = std::max(
                    transactionInfo.blockHeight + m_transactionSoftLockTime,
                    static_cast<uint32_t>(transactionInfo.unlockTime));
                insertUnlockTransactionJob(transactionInfo.transactionHash, unlockHeight, containerAmounts.container);
            }
        }

        bool transfersUpdated = updateTransactionTransfers(
            transactionId,
            containerAmountsList,
            -static_cast<int64_t>(transactionInfo.totalAmountIn),
            static_cast<int64_t>(transactionInfo.totalAmountOut));
        updated |= transfersUpdated;

        if (isNew)
        {
            const auto &tx = m_transactions[transactionId];
            m_logger(INFO) << "New transaction received, ID " << transactionId << ", hash " << tx.hash
                                         << ", state " << tx.state << ", totalAmount "
                                         << m_currency.formatAmount(tx.totalAmount) << ", fee "
                                         << m_currency.formatAmount(tx.fee) << ", transfers: "
                                         << TransferListFormatter(
                                                m_currency, getTransactionTransfersRange(transactionId));

            pushEvent(makeTransactionCreatedEvent(transactionId));
        }
        else if (updated)
        {
            if (transfersUpdated)
            {
                m_logger(DEBUGGING) << "Transaction transfers updated, ID " << transactionId << ", hash "
                                    << m_transactions[transactionId].hash << ", transfers: "
                                    << TransferListFormatter(m_currency, getTransactionTransfersRange(transactionId));
            }

            pushEvent(makeTransactionUpdatedEvent(transactionId));
        }
    }

    void WalletGreen::pushEvent(const WalletEvent &event)
    {
        m_events.push(event);
        m_eventOccurred.set();
    }

    size_t WalletGreen::getTransactionId(const Hash &transactionHash) const
    {
        auto it = m_transactions.get<TransactionIndex>().find(transactionHash);

        if (it == m_transactions.get<TransactionIndex>().end())
        {
            m_logger(ERROR) << "Failed to get transaction ID: hash not found. Transaction hash "
                                        << transactionHash;
            throw std::system_error(make_error_code(std::errc::invalid_argument));
        }

        auto rndIt = m_transactions.project<RandomAccessIndex>(it);
        auto txId = std::distance(m_transactions.get<RandomAccessIndex>().begin(), rndIt);

        return txId;
    }

    void WalletGreen::onTransactionDeleted(ITransfersSubscription *object, const Hash &transactionHash)
    {
        m_dispatcher.remoteSpawn(
            [object, transactionHash, this]() { this->transactionDeleted(object, transactionHash); });
    }

    void WalletGreen::transactionDeleted(ITransfersSubscription *object, const Hash &transactionHash)
    {
        System::EventLock lk(m_readyEvent);

        m_logger(DEBUGGING) << "transactionDeleted event, hash " << transactionHash;

        if (m_state == WalletState::NOT_INITIALIZED)
        {
            return;
        }

        auto it = m_transactions.get<TransactionIndex>().find(transactionHash);
        if (it == m_transactions.get<TransactionIndex>().end())
        {
            return;
        }

        Pastella::ITransfersContainer *container = &object->getContainer();
        updateBalance(container);
        deleteUnlockTransactionJob(transactionHash);

        bool updated = false;
        m_transactions.get<TransactionIndex>().modify(it, [&updated](Pastella::WalletTransaction &tx) {
            if (tx.state == WalletTransactionState::CREATED || tx.state == WalletTransactionState::SUCCEEDED)
            {
                tx.state = WalletTransactionState::CANCELLED;
                updated = true;
            }

            if (tx.blockHeight != WALLET_UNCONFIRMED_TRANSACTION_HEIGHT)
            {
                tx.blockHeight = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
                updated = true;
            }
        });

        if (updated)
        {
            auto transactionId = getTransactionId(transactionHash);
            auto tx = m_transactions[transactionId];
            m_logger(INFO) << "Transaction deleted, ID " << transactionId << ", hash " << transactionHash
                                         << ", state " << tx.state << ", block " << tx.blockHeight << ", totalAmount "
                                         << m_currency.formatAmount(tx.totalAmount) << ", fee "
                                         << m_currency.formatAmount(tx.fee);
            pushEvent(makeTransactionUpdatedEvent(transactionId));
        }
    }

    void WalletGreen::insertUnlockTransactionJob(
        const Hash &transactionHash,
        uint32_t blockHeight,
        Pastella::ITransfersContainer *container)
    {
        auto &index = m_unlockTransactionsJob.get<BlockHeightIndex>();
        index.insert({blockHeight, container, transactionHash});
    }

    void WalletGreen::deleteUnlockTransactionJob(const Hash &transactionHash)
    {
        auto &index = m_unlockTransactionsJob.get<TransactionHashIndex>();
        index.erase(transactionHash);
    }

    void WalletGreen::startBlockchainSynchronizer()
    {
        if (!m_walletsContainer.empty() && !m_blockchainSynchronizerStarted)
        {
            m_logger(DEBUGGING) << "Starting BlockchainSynchronizer";
            m_blockchainSynchronizer.start();
            m_blockchainSynchronizerStarted = true;
        }
    }

    /* The blockchain events are sent to us from the blockchain synchronizer,
       but they appear to not get executed on the dispatcher until the synchronizer
       stops. After some investigation, it appears that we need to run this
       odd line of code to run other code on the dispatcher? */
    void WalletGreen::updateInternalCache()
    {
        System::RemoteContext<void> updateInternalBC(m_dispatcher, []() {});
        updateInternalBC.get();
    }

    void WalletGreen::stopBlockchainSynchronizer()
    {
        if (m_blockchainSynchronizerStarted)
        {
            m_logger(DEBUGGING) << "Stopping BlockchainSynchronizer";
            System::RemoteContext<void> stopContext(m_dispatcher, [this]() { m_blockchainSynchronizer.stop(); });
            stopContext.get();

            m_blockchainSynchronizerStarted = false;
        }
    }

    void WalletGreen::addUnconfirmedTransaction(const ITransactionReader &transaction)
    {
        System::RemoteContext<std::error_code> context(m_dispatcher, [this, &transaction] {
            return m_blockchainSynchronizer.addUnconfirmedTransaction(transaction).get();
        });

        auto ec = context.get();
        if (ec)
        {
            m_logger(ERROR) << "Failed to add unconfirmed transaction: " << ec << ", " << ec.message();
            throw std::system_error(ec, "Failed to add unconfirmed transaction");
        }

        m_logger(DEBUGGING) << "Unconfirmed transaction added to BlockchainSynchronizer, hash "
                            << transaction.getTransactionHash();
    }

    void WalletGreen::removeUnconfirmedTransaction(const Crypto::Hash &transactionHash)
    {
        System::RemoteContext<void> context(m_dispatcher, [this, &transactionHash] {
            m_blockchainSynchronizer.removeUnconfirmedTransaction(transactionHash).get();
        });

        context.get();
        m_logger(DEBUGGING) << "Unconfirmed transaction removed from BlockchainSynchronizer, hash " << transactionHash;
    }

    void WalletGreen::updateBalance(Pastella::ITransfersContainer *container)
    {
        auto it = m_walletsContainer.get<TransfersContainerIndex>().find(container);

        if (it == m_walletsContainer.get<TransfersContainerIndex>().end())
        {
            return;
        }

        uint64_t actual = container->balance(ITransfersContainer::IncludeAllUnlocked);
        uint64_t pending = container->balance(ITransfersContainer::IncludeAllLocked);

        bool updated = false;

        if (it->actualBalance < actual)
        {
            m_actualBalance += actual - it->actualBalance;
            updated = true;
        }
        else if (it->actualBalance > actual)
        {
            m_actualBalance -= it->actualBalance - actual;
            updated = true;
        }

        if (it->pendingBalance < pending)
        {
            m_pendingBalance += pending - it->pendingBalance;
            updated = true;
        }
        else if (it->pendingBalance > pending)
        {
            m_pendingBalance -= it->pendingBalance - pending;
            updated = true;
        }

        if (updated)
        {
            m_walletsContainer.get<TransfersContainerIndex>().modify(it, [actual, pending](WalletRecord &wallet) {
                wallet.actualBalance = actual;
                wallet.pendingBalance = pending;
            });

            AccountPublicAddress address;
            address.publicKey = it->publicKey;
            m_logger(INFO) << "Wallet balance updated, address "
                                         << m_currency.accountAddressAsString(address)
                                         << ", actual " << m_currency.formatAmount(it->actualBalance) << ", pending "
                                         << m_currency.formatAmount(it->pendingBalance);
            m_logger(INFO) << "Container balance updated, actual "
                                         << m_currency.formatAmount(m_actualBalance) << ", pending "
                                         << m_currency.formatAmount(m_pendingBalance);
        }
    }

    const WalletRecord &WalletGreen::getWalletRecord(const PublicKey &key) const
    {
        auto it = m_walletsContainer.get<KeysIndex>().find(key);
        if (it == m_walletsContainer.get<KeysIndex>().end())
        {
            m_logger(ERROR) << "Failed to get wallet: not found. Spend public key " << key;
            throw std::system_error(make_error_code(error::WALLET_NOT_FOUND));
        }

        return *it;
    }

    const WalletRecord &WalletGreen::getWalletRecord(const std::string &address) const
    {
        Pastella::AccountPublicAddress pubAddr = parseAddress(address);
        return getWalletRecord(pubAddr.publicKey);
    }

    const WalletRecord &WalletGreen::getWalletRecord(Pastella::ITransfersContainer *container) const
    {
        auto it = m_walletsContainer.get<TransfersContainerIndex>().find(container);
        if (it == m_walletsContainer.get<TransfersContainerIndex>().end())
        {
            m_logger(ERROR) << "Failed to get wallet by container: not found";
            throw std::system_error(make_error_code(error::WALLET_NOT_FOUND));
        }

        return *it;
    }

    Pastella::AccountPublicAddress WalletGreen::parseAddress(const std::string &address) const
    {
        Pastella::AccountPublicAddress pubAddr;

        if (!m_currency.parseAccountAddressString(address, pubAddr))
        {
            m_logger(ERROR) << "Failed to parse address: " << address;
            throw std::system_error(make_error_code(error::BAD_ADDRESS));
        }

        return pubAddr;
    }

    void WalletGreen::throwIfStopped() const
    {
        if (m_stopped)
        {
            m_logger(ERROR) << "WalletGreen is already stopped";
            throw std::system_error(make_error_code(error::OPERATION_CANCELLED));
        }
    }

    std::vector<TransactionsInBlockInfo> WalletGreen::getTransactionsInBlocks(uint32_t blockIndex, size_t count) const
    {
        if (count == 0)
        {
            m_logger(ERROR) << "Bad argument: block count must be greater than zero";
            throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "blocks count must be greater than zero");
        }

        if (blockIndex == 0)
        {
            m_logger(ERROR) << "Bad argument: blockIndex must be greater than zero";
            throw std::system_error(make_error_code(error::WRONG_PARAMETERS), "blockIndex must be greater than zero");
        }

        std::vector<TransactionsInBlockInfo> result;

        if (blockIndex >= m_blockchain.size())
        {
            return result;
        }

        auto &blockHeightIndex = m_transactions.get<BlockHeightIndex>();
        uint32_t stopIndex = static_cast<uint32_t>(std::min(m_blockchain.size(), blockIndex + count));

        for (uint32_t height = blockIndex; height < stopIndex; ++height)
        {
            TransactionsInBlockInfo info;
            info.blockHash = m_blockchain[height - 1];

            auto lowerBound = blockHeightIndex.lower_bound(height);
            auto upperBound = blockHeightIndex.upper_bound(height);
            for (auto it = lowerBound; it != upperBound; ++it)
            {
                if (it->state != WalletTransactionState::SUCCEEDED)
                {
                    continue;
                }

                WalletTransactionWithTransfers transaction;
                transaction.transaction = *it;

                transaction.transfers = getTransactionTransfers(*it);

                info.transactions.emplace_back(std::move(transaction));
            }

            result.emplace_back(std::move(info));
        }

        return result;
    }

    Crypto::Hash WalletGreen::getBlockHashByIndex(uint32_t blockIndex) const
    {
        assert(blockIndex < m_blockchain.size());
        return m_blockchain.get<BlockHeightIndex>()[blockIndex];
    }

    std::vector<WalletTransfer> WalletGreen::getTransactionTransfers(const WalletTransaction &transaction) const
    {
        auto &transactionIdIndex = m_transactions.get<RandomAccessIndex>();

        auto it = transactionIdIndex.iterator_to(transaction);
        assert(it != transactionIdIndex.end());

        size_t transactionId = std::distance(transactionIdIndex.begin(), it);
        auto bounds = getTransactionTransfersRange(transactionId);

        std::vector<WalletTransfer> result;
        result.reserve(std::distance(bounds.first, bounds.second));

        for (auto it = bounds.first; it != bounds.second; ++it)
        {
            result.emplace_back(it->second);
        }

        return result;
    }

    void WalletGreen::filterOutTransactions(
        WalletTransactions &transactions,
        WalletTransfers &transfers,
        std::function<bool(const WalletTransaction &)> &&pred) const
    {
        size_t cancelledTransactions = 0;

        transactions.reserve(m_transactions.size());
        transfers.reserve(m_transfers.size());

        auto &index = m_transactions.get<RandomAccessIndex>();
        size_t transferIdx = 0;
        for (size_t i = 0; i < m_transactions.size(); ++i)
        {
            const WalletTransaction &transaction = index[i];

            if (pred(transaction))
            {
                ++cancelledTransactions;

                while (transferIdx < m_transfers.size() && m_transfers[transferIdx].first == i)
                {
                    ++transferIdx;
                }
            }
            else
            {
                transactions.push_back(transaction);

                while (transferIdx < m_transfers.size() && m_transfers[transferIdx].first == i)
                {
                    transfers.emplace_back(i - cancelledTransactions, m_transfers[transferIdx].second);
                    ++transferIdx;
                }
            }
        }
    }

    void WalletGreen::initBlockchain(const Crypto::PublicKey &publicKey)
    {
        std::vector<Crypto::Hash> blockchain = m_synchronizer.getKeyKnownBlocks(publicKey);
        m_blockchain.insert(m_blockchain.end(), blockchain.begin(), blockchain.end());
    }

    /// pre: changeDestinationAddress belongs to current container
    /// pre: source address belongs to current container
    Pastella::AccountPublicAddress WalletGreen::getChangeDestination(
        const std::string &changeDestinationAddress,
        const std::vector<std::string> &sourceAddresses) const
    {
        if (!changeDestinationAddress.empty())
        {
            return parseAccountAddressString(changeDestinationAddress);
        }

        if (m_walletsContainer.size() == 1)
        {
            AccountPublicAddress address;
            address.publicKey = m_walletsContainer.get<RandomAccessIndex>()[0].publicKey;
            return address;
        }

        assert(sourceAddresses.size() == 1 && isMyAddress(sourceAddresses[0]));
        return parseAccountAddressString(sourceAddresses[0]);
    }

    bool WalletGreen::isMyAddress(const std::string &addressString) const
    {
        Pastella::AccountPublicAddress address = parseAccountAddressString(addressString);
        return m_walletsContainer.get<KeysIndex>().count(address.publicKey) != 0;
    }

    void WalletGreen::deleteContainerFromUnlockTransactionJobs(const ITransfersContainer *container)
    {
        for (auto it = m_unlockTransactionsJob.begin(); it != m_unlockTransactionsJob.end();)
        {
            if (it->container == container)
            {
                it = m_unlockTransactionsJob.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    std::vector<size_t>
        WalletGreen::deleteTransfersForAddress(const std::string &address, std::vector<size_t> &deletedTransactions)
    {
        assert(!address.empty());

        int64_t deletedInputs = 0;
        int64_t deletedOutputs = 0;

        int64_t unknownInputs = 0;

        bool transfersLeft = false;
        size_t firstTransactionTransfer = 0;

        std::vector<size_t> updatedTransactions;

        for (size_t i = 0; i < m_transfers.size(); ++i)
        {
            WalletTransfer &transfer = m_transfers[i].second;

            if (transfer.address == address)
            {
                if (transfer.amount >= 0)
                {
                    deletedOutputs += transfer.amount;
                }
                else
                {
                    deletedInputs += transfer.amount;
                    transfer.address = "";
                }
            }
            else if (transfer.address.empty())
            {
                if (transfer.amount < 0)
                {
                    unknownInputs += transfer.amount;
                }
            }
            else if (isMyAddress(transfer.address))
            {
                transfersLeft = true;
            }

            size_t transactionId = m_transfers[i].first;
            if ((i == m_transfers.size() - 1) || (transactionId != m_transfers[i + 1].first))
            {
                // the last transfer for current transaction

                size_t transfersBeforeMerge = m_transfers.size();
                if (deletedInputs != 0)
                {
                    adjustTransfer(transactionId, firstTransactionTransfer, "", deletedInputs + unknownInputs);
                }

                assert(transfersBeforeMerge >= m_transfers.size());
                i -= transfersBeforeMerge - m_transfers.size();

                auto &randomIndex = m_transactions.get<RandomAccessIndex>();

                randomIndex.modify(
                    std::next(randomIndex.begin(), transactionId),
                    [this, transactionId, transfersLeft, deletedInputs, deletedOutputs](
                        WalletTransaction &transaction) {
                        transaction.totalAmount -= deletedInputs + deletedOutputs;

                        if (!transfersLeft)
                        {
                            transaction.state = WalletTransactionState::DELETED;
                            transaction.blockHeight = WALLET_UNCONFIRMED_TRANSACTION_HEIGHT;
                            m_logger(DEBUGGING) << "Transaction state changed, ID " << transactionId << ", hash "
                                                << transaction.hash << ", new state " << transaction.state;
                        }
                    });

                if (!transfersLeft)
                {
                    deletedTransactions.push_back(transactionId);
                }

                if (deletedInputs != 0 || deletedOutputs != 0)
                {
                    updatedTransactions.push_back(transactionId);
                }

                // reset values for next transaction
                deletedInputs = 0;
                deletedOutputs = 0;
                unknownInputs = 0;
                transfersLeft = false;
                firstTransactionTransfer = i + 1;
            }
        }

        return updatedTransactions;
    }

    void WalletGreen::deleteFromUncommitedTransactions(const std::vector<size_t> &deletedTransactions)
    {
        for (auto transactionId : deletedTransactions)
        {
            m_uncommitedTransactions.erase(transactionId);
        }
    }

    /* The formula for the block size is as follows. Calculate the
       maxBlockCumulativeSize. This is equal to:
       100,000 + ((height * 102,400) / 1,051,200)
       At a block height of 400k, this gives us a size of 138,964.
       The constants this calculation arise from can be seen below, or in
       src/PastellaCore/Currency.cpp::maxBlockCumulativeSize(). Call this value
       x.

       Next, calculate the median size of the last 100 blocks. Take the max of
       this value, and 100,000. Multiply this value by 1.25. Call this value y.

       Finally, return the minimum of x and y.

       Or, in short: min(140k (slowly rising), 1.25 * max(100k, median(last 100 blocks size)))
       Block size will always be 125k or greater (Assuming non testnet)

       To get the max transaction size, remove 600 from this value, for the
       reserved miner transaction.

       We are going to ignore the median(last 100 blocks size), as it is possible
       for a transaction to be valid for inclusion in a block when it is submitted,
       but not when it actually comes to be mined, for example if the median
       block size suddenly decreases. This gives a bit of a lower cap of max
       tx sizes, but prevents anything getting stuck in the pool.

    */
    size_t WalletGreen::getMaxTxSize()
    {
        uint32_t currentHeight = m_node.getLastKnownBlockHeight();

        size_t growth = (currentHeight * Pastella::parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR) /

                        Pastella::parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR;

        size_t x = Pastella::parameters::MAX_BLOCK_SIZE_INITIAL + growth;

        size_t y = 125000;

        return std::min(x, y) - Pastella::parameters::PASTELLA_COINBASE_BLOB_RESERVED_SIZE;
    }

    uint64_t WalletGreen::getMinTimestamp() const
    {
        uint64_t minTimestamp = std::numeric_limits<uint64_t>::max();

        if (m_containerStorage.size() == 0)
        {
            return 0;
        }

        auto &walletsIndex = m_walletsContainer.get<RandomAccessIndex>();

        for (const auto subWallet : walletsIndex)
        {
            if (static_cast<uint64_t>(subWallet.creationTimestamp) < minTimestamp)
            {
                minTimestamp = subWallet.creationTimestamp;
            }
        }

        return minTimestamp;
    }

    std::vector<Crypto::PublicKey> WalletGreen::getPublicKeys() const
    {
        std::vector<Crypto::PublicKey> publicKeys;

        auto &walletsIndex = m_walletsContainer.get<RandomAccessIndex>();

        for (const auto subWallet : walletsIndex)
        {
            publicKeys.push_back(subWallet.publicKey);
        }

        return publicKeys;
    }

    std::string WalletGreen::getPrimaryAddress() const
    {
        auto &walletsIndex = m_walletsContainer.get<RandomAccessIndex>();

        if (walletsIndex.empty())
        {
            return std::string();
        }

        /* Use first wallet as primary address */
        AccountPublicAddress address;
        address.publicKey = walletsIndex[0].publicKey;
        return m_currency.accountAddressAsString(address);
    }

    std::vector<std::tuple<WalletTypes::TransactionInput, Crypto::Hash>>
        WalletGreen::getInputs(const WalletRecord subWallet, const bool unspent) const
    {
        const uint64_t height = getBlockCount();

        std::vector<std::tuple<WalletTypes::TransactionInput, Crypto::Hash>> result;

        std::vector<SpentTransactionOutput> inputs;

        if (unspent)
        {
            inputs = subWallet.container->getUnspentInputs();
        }
        else
        {
            inputs = subWallet.container->getSpentInputs();
        }

        for (const auto &input : inputs)
        {
            const auto tx = getTransaction(input.transactionHash);

            /* Input is spent and is old enough to not need storing */
            const bool oldSpentInput =
                !unspent && tx.transaction.blockHeight + Constants::PRUNE_SPENT_INPUTS_INTERVAL < height;

            WalletTypes::TransactionInput newInput;

            newInput.amount = input.amount;
            newInput.blockHeight = tx.transaction.blockHeight;
            newInput.transactionPublicKey = input.transactionPublicKey;
            newInput.transactionIndex = input.outputInTransaction;
            newInput.globalOutputIndex = input.globalOutputIndex;
            newInput.key = input.outputKey;
            newInput.spendHeight = unspent ? 0 : input.spendingBlock.height;
            newInput.unlockTime = input.unlockTime;
            newInput.parentTransactionHash = input.transactionHash;

            result.push_back({newInput, input.spendingTransactionHash});
        }

        return result;
    }

    std::string WalletGreen::toNewFormatJSON() const
    {
        rapidjson::StringBuffer sb;
        rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

        std::unordered_map<Crypto::Hash, std::vector<std::tuple<int64_t, Crypto::PublicKey>>> transfers;

        writer.StartObject();
        {
            /* File format */
            writer.Key("walletFileFormatVersion");
            writer.Uint(Constants::WALLET_FILE_FORMAT_VERSION);

            /* Subwallets */
            writer.Key("subWallets");
            writer.StartObject();
            {
                writer.Key("publicKeys");
                writer.StartArray();
                {
                    for (const auto key : getPublicKeys())
                    {
                        key.toJSON(writer);
                    }
                }
                writer.EndArray();

                /* Each subwallet */
                writer.Key("subWallet");
                writer.StartArray();
                {
                    const std::string primaryAddress = getPrimaryAddress();

                    auto &walletsIndex = m_walletsContainer.get<RandomAccessIndex>();

                    for (const auto subWallet : walletsIndex)
                    {
                        AccountPublicAddress address;
                        address.publicKey = subWallet.publicKey;

                        const std::string addressString =
                            m_currency.accountAddressAsString(address);

                        writer.StartObject();
                        {
                            writer.Key("publicKey");
                            subWallet.publicKey.toJSON(writer);

                            writer.Key("privateKey");
                            subWallet.secretKey.toJSON(writer);

                            writer.Key("address");
                            writer.String(addressString);

                            /* Timestamp to begin syncing at */
                            writer.Key("syncStartTimestamp");
                            writer.Uint64(0);

                            /* Inputs that have been received and not spent */
                            writer.Key("unspentInputs");
                            writer.StartArray();
                            {
                                for (const auto &[input, spendingTransactionHash] :
                                     getInputs(subWallet, true))
                                {
                                    transfers[input.parentTransactionHash].push_back(
                                        {input.amount, subWallet.publicKey});
                                    input.toJSON(writer);
                                }
                            }
                            writer.EndArray();

                            /* Inputs that have been sent but not confirmed in a block */
                            /* We could probably fill this in, but it's simpler to
                           not do so - it will be resolved auomatically as the
                           transactions get confirmed, and it's likely we treat
                           locked inputs differently between the two formats. */
                            writer.Key("lockedInputs");
                            writer.StartArray();
                            {
                            }
                            writer.EndArray();

                            /* Input that have been spent */
                            writer.Key("spentInputs");
                            writer.StartArray();
                            {
                                for (const auto &[input, spendingTransactionHash] :
                                     getInputs(subWallet, false))
                                {
                                    transfers[input.parentTransactionHash].push_back(
                                        {input.amount, subWallet.publicKey});
                                    transfers[spendingTransactionHash].push_back(
                                        {-input.amount, subWallet.publicKey});
                                    input.toJSON(writer);
                                }
                            }
                            writer.EndArray();

                            /* Height to begin syncing at - Always stored as timestamp
                           in WalletGreen so static at 0 */
                            writer.Key("syncStartHeight");
                            writer.Uint64(Utilities::timestampToScanHeight(subWallet.creationTimestamp));

                            writer.Key("isPrimaryAddress");
                            writer.Bool(addressString == primaryAddress);

                            writer.Key("unconfirmedIncomingAmounts");
                            writer.StartArray();
                            {
                            }
                            writer.EndArray();
                        }
                        writer.EndObject();
                    }
                }
                writer.EndArray();

                /* Transactions in a block */
                writer.Key("transactions");
                writer.StartArray();
                {
                    const size_t numTransactions = getTransactionCount();

                    for (size_t i = 0; i < numTransactions; i++)
                    {
                        const auto tx = getTransaction(i);

                        WalletTypes::Transaction newTX;

                        for (const auto [amount, publicKey] : transfers[tx.hash])
                        {
                            newTX.transfers[publicKey] += amount;
                        }

                        newTX.hash = tx.hash;
                        newTX.fee = tx.fee;
                        newTX.blockHeight = tx.blockHeight;
                        newTX.timestamp = tx.timestamp;
                        newTX.unlockTime = tx.unlockTime;
                        newTX.isCoinbaseTransaction = tx.isBase;

                        newTX.toJSON(writer);
                    }
                }
                writer.EndArray();

                /* Outgoing transactions not in a block yet */
                /* Not going to fill in, as with locked inputs */
                writer.Key("lockedTransactions");
                writer.StartArray();
                {
                }
                writer.EndArray();

                writer.Key("privateKey");
                m_privateKey.toJSON(writer);

                /* Private keys of each transaction. Not stored in walletgreen. */
                writer.Key("txPrivateKeys");
                writer.StartArray();
                {
                }
                writer.EndArray();
            }
            writer.EndObject();

            /* Sync status */
            writer.Key("walletSynchronizer");
            writer.StartObject();
            {
                /* Sync history */
                writer.Key("transactionSynchronizerStatus");
                writer.StartObject();
                {
                    /* Lets not bother with this - it's all handed by lastKnownBlockHashes */
                    writer.Key("blockHashCheckpoints");
                    writer.StartArray();
                    {
                    }
                    writer.EndArray();

                    /* Hashes for sync history */
                    writer.Key("lastKnownBlockHashes");
                    writer.StartArray();
                    {
                        for (const auto hash : m_blockchainSynchronizer.getLastKnownBlockHashes())
                        {
                            hash.toJSON(writer);
                        }
                    }
                    writer.EndArray();

                    /* We could get the height of the largest hash above... but it
                   doesn't really matter */
                    writer.Key("lastKnownBlockHeight");
                    writer.Uint64(0);
                }
                writer.EndObject();

                /* Timestamp to start syncing from */
                writer.Key("startTimestamp");
                writer.Uint64(0);

                writer.Key("startHeight");
                writer.Uint64(Utilities::timestampToScanHeight(getMinTimestamp()));

                writer.Key("privateKey");
                m_privateKey.toJSON(writer);
            }
            writer.EndObject();
        }
        writer.EndObject();

        return sb.GetString();
    }

} // namespace Pastella
