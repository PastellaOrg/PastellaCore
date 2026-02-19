// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <common/PastellaTools.h>
#include <pastellacore/DatabaseCacheData.h>
#include <serialization/PastellaSerialization.h>
#include <serialization/SerializationOverloads.h>

namespace Pastella
{
    void ExtendedTransactionInfo::serialize(Pastella::ISerializer &s)
    {
        s(static_cast<CachedTransactionInfo &>(*this), "cached_transaction");
        s(amountToKeyIndexes, "key_indexes");
    }

    void KeyOutputInfo::serialize(ISerializer &s)
    {
        s(publicKey, "public_key");
        s(transactionHash, "transaction_hash");
        s(unlockTime, "unlock_time");
        s(outputIndex, "output_index");
    }

} // namespace Pastella
