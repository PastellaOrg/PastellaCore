// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "ITransaction.h"

#include <cstring>
#include <functional>

namespace Pastella
{
    inline bool operator==(const AccountPublicAddress &_v1, const AccountPublicAddress &_v2)
    {
        return memcmp(&_v1.publicKey, &_v2.publicKey, sizeof(Crypto::PublicKey)) == 0;
    }

} // namespace Pastella

namespace std
{
    template<> struct hash<Pastella::AccountPublicAddress>
    {
        size_t operator()(const Pastella::AccountPublicAddress &val) const
        {
            size_t spend = *(reinterpret_cast<const size_t *>(&val.publicKey));
            return spend;
        }
    };

} // namespace std
