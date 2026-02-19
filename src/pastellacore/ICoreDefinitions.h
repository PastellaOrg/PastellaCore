// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <Pastella.h>
#include <CryptoTypes.h>
#include <WalletTypes.h>
#include <vector>

namespace Pastella
{
    struct BlockFullInfo : public RawBlock
    {
        Crypto::Hash block_id;
    };

    struct TransactionPrefixInfo
    {
        Crypto::Hash txHash;
        TransactionPrefix txPrefix;
    };

    struct BlockShortInfo
    {
        Crypto::Hash blockId;
        BinaryArray block;
        std::vector<TransactionPrefixInfo> txPrefixes;
    };
} // namespace Pastella
