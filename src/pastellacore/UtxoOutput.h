// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <Pastella.h>

namespace Pastella
{
    class ISerializer;

    /* UTXO SYSTEM: UTXO (Unspent Transaction Output) structure
     *
     * In transparent Bitcoin-like systems, UTXOs represent unspent outputs
     * that can be used as inputs in new transactions. Each UTXO is uniquely
     * identified by (transactionHash, outputIndex).
     */
    struct UtxoOutput
    {
        uint64_t amount;                 /* Amount of the output */
        Crypto::PublicKey publicKey;     /* Output public key */
        uint32_t blockIndex;             /* Block where UTXO was created */
        Crypto::Hash transactionHash;    /* Transaction that created this UTXO */
        uint32_t outputIndex;            /* Index in transaction's outputs */
        bool spent;                      /* Whether this UTXO has been spent */
        uint32_t spentBlockIndex;        /* Block where UTXO was spent (0 if unspent) */

        void serialize(ISerializer &s);
    };
} // namespace Pastella
