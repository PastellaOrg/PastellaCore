// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "INode.h"
#include "ITransaction.h"

#include <array>
#include <boost/optional.hpp>
#include <cstdint>
#include <memory>

namespace Pastella
{
    struct BlockchainInterval
    {
        uint32_t startHeight;
        std::vector<Crypto::Hash> blocks;
    };

    struct CompleteBlock
    {
        Crypto::Hash blockHash;
        boost::optional<Pastella::BlockTemplate> block;
        // first transaction is always coinbase
        std::list<std::shared_ptr<ITransactionReader>> transactions;
    };

} // namespace Pastella
