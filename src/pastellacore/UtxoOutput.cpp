// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "UtxoOutput.h"
#include <serialization/ISerializer.h>
#include <serialization/PastellaSerialization.h>

namespace Pastella
{
    void UtxoOutput::serialize(ISerializer &s)
    {
        s(amount, "amount");
        s(publicKey, "public_key");
        s(blockIndex, "block_index");
        s(transactionHash, "transaction_hash");
        s(outputIndex, "output_index");
        s(spent, "spent");
        s(spentBlockIndex, "spent_block_index");
    }
} // namespace Pastella
