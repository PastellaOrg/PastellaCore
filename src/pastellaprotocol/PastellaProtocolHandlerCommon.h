// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <Pastella.h>
#include <pastellaprotocol/IPastellaProtocolQuery.h>
#include <vector>

namespace Pastella
{
    struct NOTIFY_NEW_BLOCK_request;

    /************************************************************************/
    /*                                                                      */
    /************************************************************************/
    struct IPastellaProtocol
    {
        virtual void relayBlock(NOTIFY_NEW_BLOCK_request &arg) = 0;

        virtual void relayTransactions(const std::vector<BinaryArray> &transactions) = 0;
    };

    struct IPastellaProtocolHandler : IPastellaProtocol, public IPastellaProtocolQuery
    {
        virtual ~IPastellaProtocolHandler() {};
    };
} // namespace Pastella
