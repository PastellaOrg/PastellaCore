// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <Pastella.h>
#include <boost/optional.hpp>
#include <optional>

namespace Pastella
{
    class CachedTransaction
    {
      public:
        explicit CachedTransaction(Transaction &&transaction);

        explicit CachedTransaction(const Transaction &transaction);

        explicit CachedTransaction(const BinaryArray &transactionBinaryArray);

        const Transaction &getTransaction() const;

        const Crypto::Hash &getTransactionHash() const;

        const Crypto::Hash &getTransactionPrefixHash() const;

        const BinaryArray &getTransactionBinaryArray() const;

        uint64_t getTransactionFee() const;

        uint64_t getTransactionAmount() const;

      private:
        Transaction transaction;

        mutable std::optional<BinaryArray> transactionBinaryArray;

        mutable std::optional<Crypto::Hash> transactionHash;

        mutable std::optional<Crypto::Hash> transactionPrefixHash;

        mutable std::optional<uint64_t> transactionFee;

        mutable std::optional<uint64_t> transactionAmount;
    };

} // namespace Pastella
