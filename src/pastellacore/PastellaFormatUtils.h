// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "PastellaBasic.h"
#include "serialization/BinaryInputStreamSerializer.h"
#include "serialization/BinaryOutputStreamSerializer.h"
#include "serialization/PastellaSerialization.h"

#include <boost/utility/value_init.hpp>

namespace Logging
{
    class ILogger;
}

namespace Pastella
{
    /* TRANSPARENT SYSTEM: OBSOLETE FUNCTION - Stealth address output detection removed
     *
     * Original: Checked if output belongs to account using key derivation
     * Transparent system: NOT NEEDED - direct public key comparison instead
     *
     * See: TransfersConsumer.cpp:findMyOutputs() (lines 70-124)
     * - Directly compares: output.target.key == wallet.publicKey
     * - No key derivation needed
     *
     * This function is a stub kept for API compatibility but always returns false
     */
    bool is_out_to_acc(
        const AccountKeys &acc,
        const KeyOutput &out_key,
        /* const Crypto::KeyDerivation &derivation, - REMOVED */
        size_t keyIndex);

    bool lookup_acc_outs(
        const AccountKeys &acc,
        const Transaction &tx,
        const Crypto::PublicKey &tx_pub_key,
        std::vector<size_t> &outs,
        uint64_t &money_transfered);

    bool lookup_acc_outs(
        const AccountKeys &acc,
        const Transaction &tx,
        std::vector<size_t> &outs,
        uint64_t &money_transfered);

    bool get_tx_fee(const Transaction &tx, uint64_t &fee);

    uint64_t get_tx_fee(const Transaction &tx);

    /* TRANSPARENT SYSTEM: OBSOLETE FUNCTION - Key image generation removed
     *
     * Original: Derived key image for stealth address double-spend protection
     * Transparent system: NOT NEEDED - uses transaction hash for double-spend protection
     *
     * Double-spend protection in transparent system:
     * - UTXO identified by (transactionHash, outputIndex)
     * - Transaction hash tracked in spentTransactions set
     * - See: ValidateTransaction.cpp:448-460, TransactionUtils.cpp:22-48
     *
     * This function is a stub kept for API compatibility but does nothing
     */
    bool generate_key_image_helper(
        const AccountKeys &ack,
        const Crypto::PublicKey &tx_public_key,
        size_t real_output_index,
        KeyPair &in_ephemeral,
        Crypto::PublicKey &ki);

    bool checkInputTypesSupported(const TransactionPrefix &tx);

    bool checkOutsValid(const TransactionPrefix &tx, std::string *error = nullptr);

    bool checkInputsOverflow(const TransactionPrefix &tx);

    bool checkOutsOverflow(const TransactionPrefix &tx);

    std::vector<uint32_t> relativeOutputOffsetsToAbsolute(const std::vector<uint32_t> &off);

    std::vector<uint32_t> absolute_output_offsets_to_relative(const std::vector<uint32_t> &off);

    uint64_t getInputAmount(const Transaction &transaction);

    std::vector<uint64_t> getInputsAmounts(const Transaction &transaction);

    uint64_t getOutputAmount(const Transaction &transaction);

    void decomposeAmount(uint64_t amount, uint64_t dustThreshold, std::vector<uint64_t> &decomposedAmounts);

    // 62387455827 -> 455827 + 7000000 + 80000000 + 300000000 + 2000000000 + 60000000000, where 455827 <= dust_threshold
    template<typename chunk_handler_t, typename dust_handler_t>
    void decompose_amount_into_digits(
        uint64_t amount,
        uint64_t dust_threshold,
        const chunk_handler_t &chunk_handler,
        const dust_handler_t &dust_handler)
    {
        if (0 == amount)
        {
            return;
        }

        bool is_dust_handled = false;
        uint64_t dust = 0;
        uint64_t order = 1;
        while (0 != amount)
        {
            uint64_t chunk = (amount % 10) * order;
            amount /= 10;
            order *= 10;

            if (dust + chunk <= dust_threshold)
            {
                dust += chunk;
            }
            else
            {
                if (!is_dust_handled && 0 != dust)
                {
                    dust_handler(dust);
                    is_dust_handled = true;
                }
                if (0 != chunk)
                {
                    chunk_handler(chunk);
                }
            }
        }

        if (!is_dust_handled && 0 != dust)
        {
            dust_handler(dust);
        }
    }

} // namespace Pastella
