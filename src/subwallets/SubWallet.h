// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "CryptoTypes.h"
#include "WalletTypes.h"
#include "rapidjson/document.h"

#include <crypto/crypto.h>
#include <errors/Errors.h>
#include <string>
#include <unordered_set>

class SubWallet
{
  public:
    //////////////////
    /* Constructors */
    //////////////////

    SubWallet() = default;

    SubWallet(
        const Crypto::PublicKey publicKey,
        const std::string address,
        const uint64_t scanHeight,
        const uint64_t scanTimestamp,
        const bool isPrimaryAddress);

    SubWallet(
        const Crypto::PublicKey publicKey,
        const Crypto::SecretKey privateKey,
        const std::string address,
        const uint64_t scanHeight,
        const uint64_t scanTimestamp,
        const bool isPrimaryAddress,
        const uint64_t walletIndex = 0);

    /////////////////////////////
    /* Public member functions */
    /////////////////////////////

    /* Converts the class to a json object */
    void toJSON(rapidjson::Writer<rapidjson::StringBuffer> &writer) const;

    /* Initializes the class from a json string */
    void fromJSON(const JSONValue &j);

    /* TRANSPARENT SYSTEM: OBSOLETE FUNCTION - Key derivation no longer needed
     *
     * Original: Derived ephemeral key pair from key derivation for transaction signing
     * Transparent system: NOT NEEDED because:
     * 1. Wallet stores private keys directly (no derivation)
     * 2. Signing uses ownerPrivateKey directly in Transfer.cpp
     * 3. No stealth address privacy means no ephemeral keys
     *
     * This function is a stub kept for API compatibility
     * Actual signing: Transfer.cpp:generateRingSignatures() uses ownerPrivateKey
     */
    std::tuple<Crypto::PublicKey, Crypto::SecretKey> getTxInputKeyImage(
        /* const Crypto::KeyDerivation derivation, - REMOVED */
        const size_t outputIndex) const;

    /* Store a transaction input */
    void storeTransactionInput(const WalletTypes::TransactionInput input);

    std::tuple<uint64_t, uint64_t> getBalance(const uint64_t currentHeight) const;

    void reset(const uint64_t scanHeight);

    bool isPrimaryAddress() const;

    std::string address() const;

    uint64_t walletIndex() const;

    Crypto::PublicKey publicKey() const;

    Crypto::SecretKey privateKey() const;

    /* TRANSPARENT SYSTEM: Identify UTXO by (parentTransactionHash, transactionIndex) not just key
     * IMPORTANT: Multiple outputs can have the same key, so we must identify by
     * (parentTransactionHash, transactionIndex) to uniquely mark the correct UTXO as spent! */
    void markInputAsSpent(const Crypto::Hash parentTransactionHash, const uint64_t transactionIndex, const uint64_t spendHeight);

    /* TRANSPARENT SYSTEM: Identify UTXO by (parentTransactionHash, transactionIndex) not just key
     * IMPORTANT: Multiple outputs can have the same key, so we must identify by
     * (parentTransactionHash, transactionIndex) to uniquely lock the correct UTXO! */
    void markInputAsLocked(const Crypto::Hash parentTransactionHash, const uint64_t transactionIndex);

    /* Unlock a previously locked input (move from locked back to unspent) */
    void unlockInput(const Crypto::Hash parentTransactionHash, const uint64_t transactionIndex);

    std::vector<Crypto::PublicKey> removeForkedInputs(const uint64_t forkHeight);

    void removeCancelledTransactions(const std::unordered_set<Crypto::Hash> cancelledTransactions);
    
    bool haveSpendableInput(
        const WalletTypes::TransactionInput &input,
        const uint64_t height) const;

    /* Gets inputs that are spendable at the given height */
    std::vector<WalletTypes::TxInputAndOwner> getSpendableInputs(const uint64_t height) const;

    uint64_t syncStartHeight() const;

    uint64_t syncStartTimestamp() const;

    void storeUnconfirmedIncomingInput(const WalletTypes::UnconfirmedInput input);

    void convertSyncTimestampToHeight(const uint64_t timestamp, const uint64_t height);

    void pruneSpentInputs(const uint64_t pruneHeight);

    /* STEALTH ADDRESS REMOVAL: Changed from KeyImage to PublicKey */
    std::vector<Crypto::PublicKey> getKeyImages() const;

    /////////////////////////////
    /* Public member variables */
    /////////////////////////////

  private:
    /* A vector of the stored transaction input data, to be used for
       sending transactions later */
    std::vector<WalletTypes::TransactionInput> m_unspentInputs;

    /* Inputs which have been used in a transaction, and are waiting to
       either be put into a block, or return to our wallet */
    std::vector<WalletTypes::TransactionInput> m_lockedInputs;

    /* Inputs which have been spent in a transaction */
    std::vector<WalletTypes::TransactionInput> m_spentInputs;

    /* Inputs which have come in from a transaction we sent - either from
       change or from sending to ourself - we use this to display unlocked
       balance correctly */
    std::vector<WalletTypes::UnconfirmedInput> m_unconfirmedIncomingAmounts;

    /* This subwallet's public key */
    Crypto::PublicKey m_publicKey;

    /* The subwallet's private key */
    Crypto::SecretKey m_privateKey;

    /* The subwallet's deterministic index value */
    uint64_t m_walletIndex = 0;

    /* The timestamp to begin syncing the wallet at
       (usually creation time or zero) */
    uint64_t m_syncStartTimestamp = 0;

    /* The height to begin syncing the wallet at */
    uint64_t m_syncStartHeight = 0;

    /* This subwallet's public address */
    std::string m_address;

    /* The wallet has one 'main' address which we will use by default
       when treating it as a single user wallet */
    bool m_isPrimaryAddress;
};
