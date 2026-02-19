// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <cstddef>
#include <cstdint>

namespace Pastella
{
    class IPastellaProtocolObserver;

    class IPastellaProtocolQuery
    {
      public:
        virtual bool addObserver(IPastellaProtocolObserver *observer) = 0;

        virtual bool removeObserver(IPastellaProtocolObserver *observer) = 0;

        virtual uint32_t getObservedHeight() const = 0;

        virtual uint32_t getBlockchainHeight() const = 0;

        virtual size_t getPeerCount() const = 0;

        virtual bool isSynchronized() const = 0;
    };

} // namespace Pastella
