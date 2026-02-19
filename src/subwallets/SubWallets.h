// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <crypto/crypto.h>
#include <subwallets/SubWallet.h>

class SubWallets
{
  public:
    //////////////////
    /* Constructors */
    //////////////////

    SubWallets() = default;

    /* Creates a new wallet */
    SubWallets(
        const Crypto::SecretKey privateKey,
        const std::string address,
        const uint64_t scanHeight,
        const bool newWallet);

    /* Copy constructor */
    SubWallets(const SubWallets &other);

    /////////////////////////////
    /* Public member functions */
    /////////////////////////////

    std::tuple<Error, std::string, Crypto::SecretKey, uint64_t> addSubWallet();

    std::tuple<Error, std::string> importSubWallet(const Crypto::SecretKey privateKey, const uint64_t scanHeight);

    /* Imports a sub wallet with the given wallet counter */
    std::tuple<Error, std::string> importSubWallet(const uint64_t walletIndex, const uint64_t scanHeight);

    std::tuple<Error, std::string>
        importViewSubWallet(const Crypto::PublicKey privateKey, const uint64_t scanHeight);

    Error deleteSubWallet(const std::string address);

    /* Returns (height, timestamp) to begin syncing at. Only one (if any)
       of the values will be non zero */
    std::tuple<uint64_t, uint64_t> getMinInitialSyncStart() const;

    /* Converts the class to a json object */
    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const;

    /* Initializes the class from a json string */
    void fromJSON(const JSONObject &j);

    /* Store a transaction */
    void addTransaction(const WalletTypes::Transaction tx);

    /* Store an outgoing tx, not yet in a block */
    void addUnconfirmedTransaction(const WalletTypes::Transaction tx);

    /* Get the key image for an input belonging to this subwallet.
     * Returns uninitialized PublicKey if not found */
    /* STEALTH ADDRESS REMOVAL: Removed KeyDerivation parameter, changed KeyImage to PublicKey */
    std::tuple<Crypto::PublicKey, Crypto::SecretKey> getTxInputKeyImage(
        const Crypto::PublicKey publicKey,
        const size_t outputIndex) const;

    void storeTransactionInput(const Crypto::PublicKey publicKey, const WalletTypes::TransactionInput input);

    /* Determine if the input is in the spendable container and is unlocked
     * at this height. */
    bool haveSpendableInput(
        const WalletTypes::TransactionInput& input,
        const uint64_t height) const;

    /* Get key images + amounts for the specified transfer amount. We
       can either take from all subwallets, or from some subset
       (usually just one address, e.g. if we're running a web wallet) */
    std::vector<WalletTypes::TxInputAndOwner> getSpendableTransactionInputs(
        const bool takeFromAll,
        std::vector<Crypto::PublicKey> subWalletsToTakeFrom,
        const uint64_t height) const;

    /* STEALTH ADDRESS REMOVAL: Changed KeyImage toPublicKey */
    /* Get the owner of the key image, if any */
    std::tuple<bool, Crypto::PublicKey> getKeyImageOwner(const Crypto::PublicKey publicKey) const;

    /* Gets the primary address (normally first created) address */
    std::string getPrimaryAddress() const;

    /* Gets all the addresses in the subwallets container */
    std::vector<std::string> getAddresses() const;

    /* Gets the number of wallets in the container */
    uint64_t getWalletCount() const;

    /* Get the sum of the balance of the subwallets pointed to. If
       takeFromAll, get the total balance from all subwallets. */
    std::tuple<uint64_t, uint64_t> getBalance(
        std::vector<Crypto::PublicKey> subWalletsToTakeFrom,
        const bool takeFromAll,
        const uint64_t currentHeight) const;

    /* Remove any transactions at this height or above, they were on a
       forked chain */
    void removeForkedTransactions(const uint64_t forkHeight);

    /* Gets the private key and subwallet index for the given public key, if it exists */
    std::tuple<Error, Crypto::SecretKey, uint64_t> getPrivateKey(const Crypto::PublicKey publicKey) const;

    std::vector<Crypto::SecretKey> getPrivateKeys() const;

    Crypto::SecretKey getPrimaryKey() const;

    /* TRANSPARENT SYSTEM: Identify UTXO by (parentTransactionHash, transactionIndex) not just key
     * IMPORTANT: Multiple outputs can have the same key, so we must identify by
     * (parentTransactionHash, transactionIndex) to uniquely mark the correct UTXO as spent! */
    void markInputAsSpent(
        const Crypto::PublicKey publicKey,
        const Crypto::Hash parentTransactionHash,
        const uint64_t transactionIndex,
        const uint64_t spendHeight);

    /* TRANSPARENT SYSTEM: Identify UTXO by (parentTransactionHash, transactionIndex) not just key
     * IMPORTANT: Multiple outputs can have the same key, so we must identify by
     * (parentTransactionHash, transactionIndex) to uniquely lock the correct UTXO! */
    void markInputAsLocked(
        const Crypto::PublicKey publicKey,
        const Crypto::Hash parentTransactionHash,
        const uint64_t transactionIndex);

    std::unordered_set<Crypto::Hash> getLockedTransactionsHashes() const;

    void removeCancelledTransactions(const std::unordered_set<Crypto::Hash> cancelledTransactions);

    void reset(const uint64_t scanHeight);

    std::vector<WalletTypes::Transaction> getTransactions() const;

    /* Note that this DOES NOT return incoming transactions in the pool. It only
       returns outgoing transactions which we sent but have not encountered in a
       block yet. */
    std::vector<WalletTypes::Transaction> getUnconfirmedTransactions() const;

    std::tuple<Error, std::string> getAddress(const Crypto::PublicKey publicKey) const;

    /* Store the private key used to create a transaction - can be used
       for auditing transactions */
    void storeTxPrivateKey(const Crypto::SecretKey txPrivateKey, const Crypto::Hash txHash);

    std::tuple<bool, Crypto::SecretKey> getTxPrivateKey(const Crypto::Hash txHash) const;

    void storeUnconfirmedIncomingInput(
        const WalletTypes::UnconfirmedInput input,
        const Crypto::PublicKey publicKey);

    void convertSyncTimestampToHeight(const uint64_t timestamp, const uint64_t height);

    std::vector<std::tuple<std::string, uint64_t, uint64_t>> getBalances(const uint64_t currentHeight) const;

    void pruneSpentInputs(const uint64_t pruneHeight);

    /////////////////////////////
    /* Public member variables */
    /////////////////////////////

    std::vector<Crypto::PublicKey> m_publicKeys;

  private:
    //////////////////////////////
    /* Private member functions */
    //////////////////////////////

    /* Removes transactions associated with the given public key and
       removes from the transfers array if there are multiple transfers
       in the tx */
    void deleteAddressTransactions(std::vector<WalletTypes::Transaction> &txs, const Crypto::PublicKey publicKey);

    //////////////////////////////
    /* Private member variables */
    //////////////////////////////

    /* The current subwallet index counter */
    uint64_t m_subWalletIndexCounter = 0;

    std::unordered_map<Crypto::PublicKey, SubWallet> m_subWallets;

    /* A vector of transactions */
    std::vector<WalletTypes::Transaction> m_transactions;

    /* Transactions which we sent, but haven't been added to a block yet */
    std::vector<WalletTypes::Transaction> m_lockedTransactions;

    /* Transaction private keys of sent transactions, used for auditing */
    std::unordered_map<Crypto::Hash, Crypto::SecretKey> m_transactionPrivateKeys;

    std::unordered_map<Crypto::PublicKey, Crypto::PublicKey> m_publicKeyOwners;

    /* Need a mutex for accessing inputs, transactions, and locked
       transactions, etc as these are modified on multiple threads */
    mutable std::mutex m_mutex;
};
