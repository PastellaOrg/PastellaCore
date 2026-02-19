// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "CachedTransaction.h"

#include <Pastella.h>
#include <crypto/crypto.h>
#include <set>
#include <unordered_set>

namespace Pastella
{
    struct UTXOId
    {
        Crypto::Hash transactionHash;
        uint32_t outputIndex;

        UTXOId() : outputIndex(0) {}

        UTXOId(const Crypto::Hash &txHash, uint32_t index)
            : transactionHash(txHash), outputIndex(index) {}

        bool operator==(const UTXOId &other) const
        {
            return transactionHash == other.transactionHash && outputIndex == other.outputIndex;
        }

        bool operator<(const UTXOId &other) const
        {
            /* Compare hashes using memcmp */
            int cmp = std::memcmp(transactionHash.data, other.transactionHash.data, sizeof(Crypto::Hash));
            if (cmp != 0)
            {
                return cmp < 0;
            }
            return outputIndex < other.outputIndex;
        }
    };

    struct TransactionValidatorState
    {
        /* TRANSPARENT SYSTEM: Track spent UTXOs instead of key images
         * Each spent output is identified by (transactionHash, outputIndex) */
        std::unordered_set<Crypto::Hash> spentTransactions;
    };

    void mergeStates(TransactionValidatorState &destination, const TransactionValidatorState &source);

    bool hasIntersections(const TransactionValidatorState &destination, const TransactionValidatorState &source);

    void excludeFromState(TransactionValidatorState &state, const CachedTransaction &transaction);

} // namespace Pastella
