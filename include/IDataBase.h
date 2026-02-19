// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "IReadBatch.h"
#include "IWriteBatch.h"

#include <string>
#include <system_error>

namespace Pastella
{
    class IDataBase
    {
      public:
        virtual ~IDataBase() {}

        virtual std::error_code write(IWriteBatch &batch) = 0;

        /* Write with sync option - forces immediate flush to disk for critical writes
         *
         * When sync=true, the database will flush the write-ahead log to disk before returning.
         * This ensures data is immediately visible for subsequent reads, at the cost of performance.
         *
         * Use sync=true for:
         * - Block writes (UTXOs must be immediately spendable)
         * - Critical state changes
         *
         * Use sync=false for:
         * - Bulk operations
         * - Non-critical writes where performance is more important */
        virtual std::error_code write(IWriteBatch &batch, bool sync) = 0;

        virtual std::error_code read(IReadBatch &batch) = 0;
#if !defined (USE_LEVELDB)
        virtual std::error_code readThreadSafe(IReadBatch &batch) = 0;
#endif
    };
} // namespace Pastella