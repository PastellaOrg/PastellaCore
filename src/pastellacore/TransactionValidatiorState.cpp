// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "TransactionValidatiorState.h"

namespace Pastella
{

    void mergeStates(TransactionValidatorState &destination, const TransactionValidatorState &source)
    {
        /* Merge spent transactions from source into destination
         * Used when combining transaction states from different sources */
        destination.spentTransactions.insert(
            source.spentTransactions.begin(),
            source.spentTransactions.end());
    }

    bool hasIntersections(const TransactionValidatorState &destination, const TransactionValidatorState &source)
    {
        /* Check if there are any common spent transactions
         * If true, this indicates a double-spend attempt */
        for (const auto &txHash : source.spentTransactions)
        {
            if (destination.spentTransactions.count(txHash) > 0)
            {
                return true;
            }
        }
        return false;
    }

    void excludeFromState(TransactionValidatorState &state, const CachedTransaction &cachedTransaction)
    {
        /* Remove transaction from spent set
         * Used when a transaction is removed from a block (during reorg) */
        state.spentTransactions.erase(cachedTransaction.getTransactionHash());
    }

} // namespace Pastella
