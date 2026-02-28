// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <pastellacore/BlockchainCache.h>
#include <map>

namespace Pastella
{
    struct KeyOutputInfo
    {
        Crypto::PublicKey publicKey;

        Crypto::Hash transactionHash;

        uint64_t unlockTime;

        uint16_t outputIndex;

        void serialize(Pastella::ISerializer &s);
    };

    // inherit here to avoid breaking IBlockchainCache interface
    struct ExtendedTransactionInfo : CachedTransactionInfo
    {
        // CachedTransactionInfo tx;
        std::map<IBlockchainCache::Amount, std::vector<IBlockchainCache::GlobalOutputIndex>>
            amountToKeyIndexes; // global key output indexes spawned in this transaction
        void serialize(ISerializer &s);
    };

    /* ADDRESS BALANCE INDEX: Persistent storage for richlist optimization
     *
     * AddressBalanceInfo stores the balance and timestamp data for a single address.
     * This data is persisted to the database to avoid rebuilding the richlist index
     * on every daemon restart. */

    struct AddressBalanceInfo
    {
        uint64_t balance = 0;
        uint64_t firstTxTimestamp = UINT64_MAX;
        uint64_t lastTxTimestamp = 0;

        void serialize(ISerializer &s);
    };

    /* TRANSACTION INDEX: Per-address transaction history for fast wallet details
     *
     * TransactionReference stores metadata about a transaction for an address.
     * This allows fast wallet lookups without scanning the entire blockchain.
     *
     * Stores the from/to addresses directly so we don't need to lookup transaction
     * details during API calls (expensive blockchain lookups). */

    struct TransactionReference
    {
        Crypto::Hash txHash;
        uint64_t timestamp;
        uint64_t amount;
        uint32_t blockHeight;
        uint8_t type; /* 0 = incoming, 1 = outgoing, 2 = stake_reward, 3 = stake_deposit */
        std::vector<std::string> fromAddresses; /* Sender addresses */
        std::vector<std::string> toAddresses;   /* Recipient addresses */

        void serialize(ISerializer &s);
    };

    /* Extended address info with transaction history */
    struct AddressInfoExtended
    {
        AddressBalanceInfo balanceInfo;
        std::vector<TransactionReference> transactions;

        void serialize(ISerializer &s);
    };

} // namespace Pastella
