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

} // namespace Pastella
