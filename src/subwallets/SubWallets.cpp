// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

//////////////////////////////////
#include <subwallets/SubWallets.h>
//////////////////////////////////

#include <config/Constants.h>
#include <config/PastellaConfig.h>
#include <ctime>
#include <mutex>
#include <logger/Logger.h>
#include <random>
#include <utilities/Addresses.h>
#include <utilities/Utilities.h>

///////////////////////////////////
/* CONSTRUCTORS / DECONSTRUCTORS */
///////////////////////////////////

/* Makes a new subwallet */
SubWallets::SubWallets(
    const Crypto::SecretKey privateKey,
    const std::string address,
    const uint64_t scanHeight,
    const bool newWallet)
{
    Crypto::PublicKey publicKey;

    Crypto::secret_key_to_public_key(privateKey, publicKey);

    const uint64_t timestamp = newWallet ? Utilities::getCurrentTimestampAdjusted() : 0;

    const bool isPrimaryAddress = true;

    m_subWallets[publicKey] =
        SubWallet(publicKey, privateKey, address, scanHeight, timestamp, isPrimaryAddress);

    m_publicKeys.push_back(publicKey);
}

/* Copy constructor */
SubWallets::SubWallets(const SubWallets &other):
    m_subWallets(other.m_subWallets),
    m_transactions(other.m_transactions),
    m_lockedTransactions(other.m_lockedTransactions),
    m_publicKeys(other.m_publicKeys),
    m_transactionPrivateKeys(other.m_transactionPrivateKeys)
{
}

/////////////////////
/* CLASS FUNCTIONS */
/////////////////////

std::tuple<Error, std::string, Crypto::SecretKey, uint64_t> SubWallets::addSubWallet()
{

    Crypto::SecretKey primaryKey = getPrimaryKey();

    std::scoped_lock lock(m_mutex);

    /* HD WALLET SIMPLIFIED: Generate random key pair instead of deterministic subwallet
     * In transparent system, we use simple random key generation for additional addresses */
    Crypto::PublicKey newPublicKey;
    Crypto::SecretKey newPrivateKey;
    Crypto::generate_keys(newPublicKey, newPrivateKey);

    m_subWalletIndexCounter++;
    const std::string address = Utilities::privateKeyToAddress(newPrivateKey);

    const bool isPrimaryAddress = false;

    const uint64_t scanHeight = 0;

    m_subWallets[newPublicKey] = SubWallet(
        newPublicKey,
        newPrivateKey,
        address,
        scanHeight,
        Utilities::getCurrentTimestampAdjusted(),
        isPrimaryAddress,
        m_subWalletIndexCounter);

    m_publicKeys.push_back(newPublicKey);

    return {SUCCESS, address, newPrivateKey, m_subWalletIndexCounter};
}

std::tuple<Error, std::string>
    SubWallets::importSubWallet(const Crypto::SecretKey privateKey, const uint64_t scanHeight)
{

    std::scoped_lock lock(m_mutex);

    Crypto::PublicKey publicKey;

    Crypto::secret_key_to_public_key(privateKey, publicKey);

    uint64_t timestamp = 0;
    const std::string address = Utilities::privateKeyToAddress(privateKey);

    const bool isPrimaryAddress = false;

    if (m_subWallets.find(publicKey) != m_subWallets.end())
    {
        return {SUBWALLET_ALREADY_EXISTS, std::string()};
    }

    m_subWallets[publicKey] =
        SubWallet(publicKey, privateKey, address, scanHeight, timestamp, isPrimaryAddress);

    m_publicKeys.push_back(publicKey);

    return {SUCCESS, address};
}

std::tuple<Error, std::string>
    SubWallets::importSubWallet(const uint64_t walletIndex, const uint64_t scanHeight)
{

    Crypto::SecretKey primaryKey = getPrimaryKey();
    Crypto::PublicKey newPublicKey;
    Crypto::SecretKey newPrivateKey;
    Crypto::generate_keys(newPublicKey, newPrivateKey);

    const auto [status, address] = importSubWallet(newPrivateKey, scanHeight);

    if (status == SUCCESS && walletIndex > m_subWalletIndexCounter)
    {
        m_subWalletIndexCounter = walletIndex;
    }

    return {status, address};
}

std::tuple<Error, std::string>
    SubWallets::importViewSubWallet(const Crypto::PublicKey publicKey, const uint64_t scanHeight)
{

    std::scoped_lock lock(m_mutex);

    if (m_subWallets.find(publicKey) != m_subWallets.end())
    {
        return {SUBWALLET_ALREADY_EXISTS, std::string()};
    }

    uint64_t timestamp = 0;

    const std::string address = Utilities::publicKeyToAddress(publicKey);

    const bool isPrimaryAddress = false;

    m_subWallets[publicKey] = SubWallet(publicKey, address, scanHeight, timestamp, isPrimaryAddress);

    m_publicKeys.push_back(publicKey);

    return {SUCCESS, address};
}

Error SubWallets::deleteSubWallet(const std::string address)
{
    std::scoped_lock lock(m_mutex);
    const auto publicKey = Utilities::addressToPublicKey(address);

    const auto it = m_subWallets.find(publicKey);

    if (it == m_subWallets.end())
    {
        return ADDRESS_NOT_IN_WALLET;
    }

    /* We can't delete the primary address */
    if (it->second.isPrimaryAddress())
    {
        return CANNOT_DELETE_PRIMARY_ADDRESS;
    }

    m_subWallets.erase(it);

    /* Remove or update the transactions */
    deleteAddressTransactions(m_transactions, publicKey);
    deleteAddressTransactions(m_lockedTransactions, publicKey);

    const auto it2 = std::remove(m_publicKeys.begin(), m_publicKeys.end(), publicKey);

    if (it2 != m_publicKeys.end())
    {
        m_publicKeys.erase(it2, m_publicKeys.end());
    }

    return SUCCESS;
}

void SubWallets::deleteAddressTransactions(std::vector<WalletTypes::Transaction> &txs, const Crypto::PublicKey publicKey)
{
    const auto it = std::remove_if(txs.begin(), txs.end(), [publicKey](auto &tx) {
        /* See if this transaction contains the subwallet we're deleting */
        const auto key = tx.transfers.find(publicKey);

        /* OK, it does */
        if (key != tx.transfers.end())
        {
            /* It's the only element, delete the transaction */
            if (tx.transfers.size() == 1)
            {
                return true;
            }
            /* Otherwise just delete the transfer in the transaction */
            else
            {
                tx.transfers.erase(key);
            }
        }

        return false;
    });

    if (it != txs.end())
    {
        txs.erase(it, txs.end());
    }
}

/* Gets the starting height, and timestamp to begin the sync from. Only one of
   these will be non zero, which will the the lowest one (ignoring null values).

   So, if for example, one subwallet has a start height of 400,000, and another
   has a timestamp of something corresponding to 300,000, we would return
   zero for the start height, and the timestamp corresponding to 300,000.

   Alternatively, if the timestamp corresponded to 500,000, we would return
   400,000 for the height, and zero for the timestamp. */
std::tuple<uint64_t, uint64_t> SubWallets::getMinInitialSyncStart() const
{
    std::scoped_lock lock(m_mutex);

    /* Get the smallest sub wallet (by timestamp) */
    auto minElementByTimestamp =
        *std::min_element(m_subWallets.begin(), m_subWallets.end(), [](const auto &lhs, const auto &rhs) {
            return lhs.second.syncStartTimestamp() < rhs.second.syncStartTimestamp();
        });

    const uint64_t minTimestamp = minElementByTimestamp.second.syncStartTimestamp();

    /* Get the smallest sub wallet (by height) */
    auto minElementByHeight =
        *std::min_element(m_subWallets.begin(), m_subWallets.end(), [](const auto &lhs, const auto &rhs) {
            return lhs.second.syncStartHeight() < rhs.second.syncStartHeight();
        });

    const uint64_t minHeight = minElementByHeight.second.syncStartHeight();

    /* One or both of the values are zero, caller will use whichever is non
       zero */
    if (minHeight == 0 || minTimestamp == 0)
    {
        return {minHeight, minTimestamp};
    }

    /* Convert timestamp to height so we can compare them, then return the min
       of the two, and set the other to zero */
    const uint64_t timestampFromHeight = Utilities::scanHeightToTimestamp(minHeight);

    if (timestampFromHeight < minTimestamp)
    {
        return {minHeight, 0};
    }
    else
    {
        return {0, minTimestamp};
    }
}

void SubWallets::addUnconfirmedTransaction(const WalletTypes::Transaction tx)
{
    std::scoped_lock lock(m_mutex);

    const auto it2 =
        std::find_if(m_lockedTransactions.begin(), m_lockedTransactions.end(), [tx](const auto transaction) {
            return tx.hash == transaction.hash;
        });

    if (it2 != m_lockedTransactions.end())
    {
        std::stringstream stream;

        stream << "Unconfirmed transaction " << tx.hash << " already exists in wallet. Ignoring.";

        Logger::logger.log(
            stream.str(),
            Logger::WARNING,
            { Logger::SYNC }
        );

        return;
    }

    m_lockedTransactions.push_back(tx);
}

void SubWallets::addTransaction(const WalletTypes::Transaction tx)
{
    std::scoped_lock lock(m_mutex);

    /* If we sent this transaction, we will input it into the transactions
       vector instantly. This lets us display the data to the user, and then
       when the transaction actually comes in, we will update the transaction
       with the block infomation. */
    const auto it =
        std::remove_if(m_lockedTransactions.begin(), m_lockedTransactions.end(), [tx](const auto transaction) {
            return tx.hash == transaction.hash;
        });

    if (it != m_lockedTransactions.end())
    {
        /* Remove from the locked container */
        m_lockedTransactions.erase(it, m_lockedTransactions.end());
    }

    const auto it2 = std::find_if(m_transactions.begin(), m_transactions.end(), [tx](const auto transaction) {
        return tx.hash == transaction.hash;
    });

    if (it2 != m_transactions.end())
    {
        std::stringstream stream;

        stream << "Transaction " << tx.hash << " already exists in wallet. Ignoring.";

        Logger::logger.log(
            stream.str(),
            Logger::WARNING,
            { Logger::SYNC }
        );

        return;
    }

    m_transactions.push_back(tx);
}

/* STEALTH ADDRESS REMOVAL: Changed KeyImage to PublicKey, removed KeyDerivation */
std::tuple<Crypto::PublicKey, Crypto::SecretKey> SubWallets::getTxInputKeyImage(
    const Crypto::PublicKey publicKey,
    /* const Crypto::KeyDerivation derivation, - REMOVED */
    const size_t outputIndex) const
{
    std::scoped_lock lock(m_mutex);

    const auto it = m_subWallets.find(publicKey);

    /* Check it exists */
    if (it != m_subWallets.end())
    {
        return it->second.getTxInputKeyImage(outputIndex);
    }

    throw std::runtime_error("Subwallet not found!");
}

void SubWallets::storeTransactionInput(
    const Crypto::PublicKey publicKey,
    const WalletTypes::TransactionInput input)
{
    std::scoped_lock lock(m_mutex);

    const auto it = m_subWallets.find(publicKey);

    /* Check it exists */
    if (it != m_subWallets.end())
    {
        /* STEALTH ADDRESS REMOVAL: Changed m_keyImageOwners to m_publicKeyOwners */
        /* Add the new key image to the store, so we can detect when we
           spent a key image easily */
        m_publicKeyOwners[input.key] = publicKey;

        return it->second.storeTransactionInput(input);
    }

    throw std::runtime_error("Subwallet not found!");
}

/* STEALTH ADDRESS REMOVAL: Changed KeyImage to PublicKey */
std::tuple<bool, Crypto::PublicKey> SubWallets::getKeyImageOwner(const Crypto::PublicKey publicKey) const
{
    const auto it = m_publicKeyOwners.find(publicKey);

    if (it != m_publicKeyOwners.end())
    {
        return {true, it->second};
    }

    return {false, Crypto::PublicKey()};
}

/* Determine if the input given is available for spending */
bool SubWallets::haveSpendableInput(
    const WalletTypes::TransactionInput& input,
    const uint64_t height) const
{
    for (const auto &[pubKey, subWallet] : m_subWallets)
    {
        if (subWallet.haveSpendableInput(input, height))
        {
            return true;
        }
    }

    return false;
}

/* Remember if the transaction suceeds, we need to remove these key images
   so we don't double spend.

   This may throw if you don't validate the user has enough balance, and
   that each of the subwallets exist. */
std::vector<WalletTypes::TxInputAndOwner> SubWallets::getSpendableTransactionInputs(
    const bool takeFromAll,
    std::vector<Crypto::PublicKey> subWalletsToTakeFrom,
    const uint64_t height) const
{
    std::scoped_lock lock(m_mutex);

    /* If we're able to take from every subwallet, set the wallets to take from */
    if (takeFromAll)
    {
        subWalletsToTakeFrom = m_publicKeys;
    }

    std::vector<SubWallet> wallets;

    /* Loop through each public key and grab the associated wallet */
    for (const auto &publicKey : subWalletsToTakeFrom)
    {
        wallets.push_back(m_subWallets.at(publicKey));
    }

    std::vector<WalletTypes::TxInputAndOwner> availableInputs;

    /* Copy the transaction inputs from this sub wallet to inputs */
    for (const auto &subWallet : wallets)
    {
        const auto moreInputs = subWallet.getSpendableInputs(height);

        availableInputs.insert(availableInputs.end(), moreInputs.begin(), moreInputs.end());
    }

    /* Sort inputs by their amounts, largest first */
    std::sort(availableInputs.begin(), availableInputs.end(), [](const auto a, const auto b)
    {
        return a.input.amount > b.input.amount;
    });

    std::map<uint64_t, std::vector<WalletTypes::TxInputAndOwner>> buckets;

    /* Push into base 10 buckets. Smallest amount buckets will come first, and
     * largest amounts within those buckets come first */
    for (const auto &walletAmount : availableInputs)
    {
        /* Find out how many digits the amount has, i.e. 1337 has 4 digits,
           420 has 3 digits */
        int numberOfDigits = floor(log10(walletAmount.input.amount)) + 1;

        /* Insert the amount into the correct bucket */
        buckets[numberOfDigits].push_back(walletAmount);
    }

    std::vector<WalletTypes::TxInputAndOwner> ordered;

    while (!buckets.empty())
    {
        /* Take one element from each bucket, smallest first. */
        for (auto bucket = buckets.begin(); bucket != buckets.end();)
        {
            /* Bucket has been exhausted, remove from list */
            if (bucket->second.empty())
            {
                bucket = buckets.erase(bucket);
            }
            else
            {
                /* Add the final (smallest amount in this bucket) to the result */
                ordered.push_back(bucket->second.back());

                /* Remove amount we just added */
                bucket->second.pop_back();

                bucket++;
            }
        }
    }

    return ordered;
}

/* Gets the primary address, which is the first address created with the
   wallet */
std::string SubWallets::getPrimaryAddress() const
{
    std::scoped_lock lock(m_mutex);

    const auto it = std::find_if(m_subWallets.begin(), m_subWallets.end(), [](const auto subWallet) {
        return subWallet.second.isPrimaryAddress();
    });

    if (it == m_subWallets.end())
    {
        throw std::runtime_error("This container has no primary address!");
    }

    return it->second.address();
}

std::vector<std::string> SubWallets::getAddresses() const
{
    std::vector<std::string> addresses;

    for (const auto &[pubKey, subWallet] : m_subWallets)
    {
        addresses.push_back(subWallet.address());
    }

    return addresses;
}

uint64_t SubWallets::getWalletCount() const
{
    return m_subWallets.size();
}

/* Will throw if the public keys given don't exist */
std::tuple<uint64_t, uint64_t> SubWallets::getBalance(
    std::vector<Crypto::PublicKey> subWalletsToTakeFrom,
    const bool takeFromAll,
    const uint64_t currentHeight) const
{
    std::scoped_lock lock(m_mutex);

    /* If we're able to take from every subwallet, set the wallets to take from */
    if (takeFromAll)
    {
        subWalletsToTakeFrom = m_publicKeys;
    }

    uint64_t unlockedBalance = 0;

    uint64_t lockedBalance = 0;

    for (const auto &pubKey : subWalletsToTakeFrom)
    {
        const auto [unlocked, locked] = m_subWallets.at(pubKey).getBalance(currentHeight);

        unlockedBalance += unlocked;
        lockedBalance += locked;
    }

    return {unlockedBalance, lockedBalance};
}

/* STEALTH ADDRESS REMOVAL: Changed KeyImage to PublicKey */
/* Mark a key image as spent, no longer can be used in transactions */
void SubWallets::markInputAsSpent(
    const Crypto::PublicKey publicKey,
    const Crypto::Hash parentTransactionHash,
    const uint64_t transactionIndex,
    const uint64_t spendHeight)
{
    std::scoped_lock lock(m_mutex);

    m_subWallets.at(publicKey).markInputAsSpent(parentTransactionHash, transactionIndex, spendHeight);
}

/* TRANSPARENT SYSTEM: Mark input as locked by (parentTransactionHash, transactionIndex) */
/* Mark a key image as locked, can no longer be used in transactions till it
   returns from the pool, or we find it in a block, in which case we will
   mark it as spent. */
void SubWallets::markInputAsLocked(
    const Crypto::PublicKey publicKey,
    const Crypto::Hash parentTransactionHash,
    const uint64_t transactionIndex)
{
    std::scoped_lock lock(m_mutex);

    m_subWallets.at(publicKey).markInputAsLocked(parentTransactionHash, transactionIndex);
}

/* Unlock a previously locked input (move from locked back to unspent) */
void SubWallets::unlockInput(
    const Crypto::PublicKey publicKey,
    const Crypto::Hash parentTransactionHash,
    const uint64_t transactionIndex)
{
    std::scoped_lock lock(m_mutex);

    m_subWallets.at(publicKey).unlockInput(parentTransactionHash, transactionIndex);
}

/* Remove transactions and key images that occured on a forked chain */
void SubWallets::removeForkedTransactions(const uint64_t forkHeight)
{
    std::scoped_lock lock(m_mutex);

    const auto it = std::remove_if(m_transactions.begin(), m_transactions.end(), [forkHeight](auto tx) {
        /* Remove the transaction if it's height is >= than the fork height */
        return tx.blockHeight >= forkHeight;
    });

    if (it != m_transactions.end())
    {
        m_transactions.erase(it, m_transactions.end());
    }

    /* STEALTH ADDRESS REMOVAL: Changed KeyImage to PublicKey */
    std::vector<Crypto::PublicKey> publicKeysToRemove;

    /* Loop through each subwallet */
    for (auto &[publicKey, subWallet] : m_subWallets)
    {
        const auto toRemove = subWallet.removeForkedInputs(forkHeight);
        publicKeysToRemove.insert(publicKeysToRemove.end(), toRemove.begin(), toRemove.end());
    }

    for (const auto publicKey : publicKeysToRemove)
    {
        m_publicKeyOwners.erase(publicKey);
    }
}

void SubWallets::removeCancelledTransactions(const std::unordered_set<Crypto::Hash> cancelledTransactions)
{
    std::scoped_lock lock(m_mutex);

    /* Find any cancelled transactions */
    const auto it = std::remove_if(
        m_lockedTransactions.begin(), m_lockedTransactions.end(), [&cancelledTransactions](const auto &tx) {
            return cancelledTransactions.find(tx.hash) != cancelledTransactions.end();
        });

    if (it != m_lockedTransactions.end())
    {
        /* Remove the cancelled transactions */
        m_lockedTransactions.erase(it, m_lockedTransactions.end());
    }

    for (auto &[pubKey, subWallet] : m_subWallets)
    {
        subWallet.removeCancelledTransactions(cancelledTransactions);
    }
}

std::tuple<Error, Crypto::SecretKey, uint64_t> SubWallets::getPrivateKey(const Crypto::PublicKey publicKey) const
{
    const auto it = m_subWallets.find(publicKey);

    if (it == m_subWallets.end())
    {
        return {ADDRESS_NOT_IN_WALLET, Crypto::SecretKey(), 0};
    }

    return {SUCCESS, it->second.privateKey(), it->second.walletIndex()};
}

std::unordered_set<Crypto::Hash> SubWallets::getLockedTransactionsHashes() const
{
    std::scoped_lock lock(m_mutex);

    std::unordered_set<Crypto::Hash> result;

    for (const auto transaction : m_lockedTransactions)
    {
        result.insert(transaction.hash);
    }

    return result;
}

void SubWallets::reset(const uint64_t scanHeight)
{
    std::scoped_lock lock(m_mutex);

    m_lockedTransactions.clear();
    m_transactions.clear();
    m_transactionPrivateKeys.clear();

    for (auto &[pubKey, subWallet] : m_subWallets)
    {
        subWallet.reset(scanHeight);
    }
}

std::vector<Crypto::SecretKey> SubWallets::getPrivateKeys() const
{
    std::vector<Crypto::SecretKey> keys;

    for (const auto &[pubKey, subWallet] : m_subWallets)
    {
        keys.push_back(subWallet.privateKey());
    }

    return keys;
}

Crypto::SecretKey SubWallets::getPrimaryKey() const
{
    std::scoped_lock lock(m_mutex);

    const auto it = std::find_if(m_subWallets.begin(), m_subWallets.end(), [](const auto subWallet) {
        return subWallet.second.isPrimaryAddress();
    });

    if (it == m_subWallets.end())
    {
        throw std::runtime_error("This container has no primary address!");
    }

    return it->second.privateKey();
}

std::vector<WalletTypes::Transaction> SubWallets::getTransactions() const
{
    return m_transactions;
}

/* Note that this DOES NOT return incoming transactions in the pool. It only
   returns outgoing transactions which we sent but have not encountered in a
   block yet. */
std::vector<WalletTypes::Transaction> SubWallets::getUnconfirmedTransactions() const
{
    return m_lockedTransactions;
}

std::tuple<Error, std::string> SubWallets::getAddress(const Crypto::PublicKey publicKey) const
{
    const auto it = m_subWallets.find(publicKey);

    if (it != m_subWallets.end())
    {
        return {SUCCESS, it->second.address()};
    }

    return {ADDRESS_NOT_IN_WALLET, std::string()};
}

void SubWallets::storeTxPrivateKey(const Crypto::SecretKey txPrivateKey, const Crypto::Hash txHash)
{
    m_transactionPrivateKeys[txHash] = txPrivateKey;
}

std::tuple<bool, Crypto::SecretKey> SubWallets::getTxPrivateKey(const Crypto::Hash txHash) const
{
    const auto it = m_transactionPrivateKeys.find(txHash);

    if (it != m_transactionPrivateKeys.end())
    {
        return {true, it->second};
    }

    return {false, Crypto::SecretKey()};
}

void SubWallets::storeUnconfirmedIncomingInput(
    const WalletTypes::UnconfirmedInput input,
    const Crypto::PublicKey publicKey)
{
    std::scoped_lock lock(m_mutex);

    const auto it = m_subWallets.find(publicKey);

    if (it != m_subWallets.end())
    {
        it->second.storeUnconfirmedIncomingInput(input);
    }
}

void SubWallets::convertSyncTimestampToHeight(const uint64_t timestamp, const uint64_t height)
{
    std::scoped_lock lock(m_mutex);

    for (auto &[pubKey, subWallet] : m_subWallets)
    {
        subWallet.convertSyncTimestampToHeight(timestamp, height);
    }
}

std::vector<std::tuple<std::string, uint64_t, uint64_t>> SubWallets::getBalances(const uint64_t currentHeight) const
{
    std::vector<std::tuple<std::string, uint64_t, uint64_t>> balances;

    for (const auto &[pubKey, subWallet] : m_subWallets)
    {
        const auto [unlocked, locked] = subWallet.getBalance(currentHeight);

        balances.emplace_back(subWallet.address(), unlocked, locked);
    }

    return balances;
}

void SubWallets::pruneSpentInputs(const uint64_t pruneHeight)
{
    for (auto &[pubKey, subWallet] : m_subWallets)
    {
        subWallet.pruneSpentInputs(pruneHeight);
    }
}

void SubWallets::fromJSON(const JSONObject &j)
{
    for (const auto &x : getArrayFromJSON(j, "publicKeys"))
    {
        Crypto::PublicKey key;
        key.fromString(getStringFromJSONString(x));
        m_publicKeys.push_back(key);
    }

    if (j.HasMember("subWalletIndexCounter"))
    {
        m_subWalletIndexCounter = getUint64FromJSON(j, "subWalletIndexCounter");
    }

    for (const auto &x : getArrayFromJSON(j, "subWallet"))
    {
        SubWallet s;
        s.fromJSON(x);
        m_subWallets[s.publicKey()] = s;

        /* STEALTH ADDRESS REMOVAL: Changed m_keyImageOwners to m_publicKeyOwners */
        /* Load the key images hashmap from the loaded subwallets */
        for (const auto &[pubKey, subWallet] : m_subWallets)
        {
            for (const auto &keyImage : subWallet.getKeyImages())
            {
                m_publicKeyOwners[keyImage] = pubKey;
            }
        }
    }

    for (const auto &x : getArrayFromJSON(j, "transactions"))
    {
        WalletTypes::Transaction tx;
        tx.fromJSON(x);
        m_transactions.push_back(tx);
    }

    for (const auto &x : getArrayFromJSON(j, "lockedTransactions"))
    {
        WalletTypes::Transaction tx;
        tx.fromJSON(x);
        m_lockedTransactions.push_back(tx);
    }

    for (const auto &txKey : getArrayFromJSON(j, "txPrivateKeys"))
    {
        Crypto::Hash txHash;
        txHash.fromString(getStringFromJSON(txKey, "transactionHash"));

        Crypto::SecretKey privateKey;
        privateKey.fromString(getStringFromJSON(txKey, "txPrivateKey"));

        m_transactionPrivateKeys[txHash] = privateKey;
    }
}

void SubWallets::toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const
{
    writer.StartObject();

    writer.Key("publicKeys");
    writer.StartArray();
    for (const auto &key : m_publicKeys)
    {
        key.toJSON(writer);
    }
    writer.EndArray();

    writer.Key("subWalletIndexCounter");
    writer.Uint64(m_subWalletIndexCounter);

    writer.Key("subWallet");
    writer.StartArray();
    for (const auto &[publicKey, subWallet] : m_subWallets)
    {
        subWallet.toJSON(writer);
    }
    writer.EndArray();

    writer.Key("transactions");
    writer.StartArray();
    for (const auto &tx : m_transactions)
    {
        tx.toJSON(writer);
    }
    writer.EndArray();

    writer.Key("lockedTransactions");
    writer.StartArray();
    for (const auto &tx : m_lockedTransactions)
    {
        tx.toJSON(writer);
    }
    writer.EndArray();

    writer.Key("txPrivateKeys");
    writer.StartArray();
    for (const auto [txHash, txPrivateKey] : m_transactionPrivateKeys)
    {
        writer.StartObject();

        writer.Key("transactionHash");
        txHash.toJSON(writer);

        writer.Key("txPrivateKey");
        txPrivateKey.toJSON(writer);

        writer.EndObject();
    }
    writer.EndArray();

    writer.EndObject();
}
