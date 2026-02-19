// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "TransactionUtils.h"

#include "PastellaFormatUtils.h"
#include "common/TransactionExtra.h"
#include "crypto/crypto.h"

#include <iostream>
#include <unordered_set>

using namespace Crypto;

namespace Pastella
{
    /* TRANSPARENT SYSTEM: Check for duplicate UTXO references in transaction inputs
     * Prevents a transaction from spending the same UTXO multiple times
     * In transparent system, each UTXO is uniquely identified by (transactionHash, outputIndex) */
    bool checkInputsKeyimagesDiff(const Pastella::TransactionPrefix &tx)
    {
        std::unordered_set<std::string> utxoRefs;

        for (const auto &input : tx.inputs)
        {
            if (input.type() == typeid(Pastella::KeyInput))
            {
                const Pastella::KeyInput &keyInput = boost::get<Pastella::KeyInput>(input);

                /* Create unique identifier for this UTXO: "transactionHash:outputIndex" */
                std::string utxoId = Common::podToHex(keyInput.transactionHash) + ":" +
                                     std::to_string(keyInput.outputIndex);

                /* Check if we've already seen this UTXO in this transaction */
                if (utxoRefs.count(utxoId) > 0)
                {
                    /* Duplicate UTXO reference found! This is a double-spend attempt. */
                    return false;
                }

                utxoRefs.insert(utxoId);
            }
        }

        return true;
    }

    // TransactionInput helper functions

    size_t getRequiredSignaturesCount(const TransactionInput &in)
    {
        if (in.type() == typeid(KeyInput))
        {
            return boost::get<KeyInput>(in).outputIndexes.size();
        }

        return 0;
    }

    uint64_t getTransactionInputAmount(const TransactionInput &in)
    {
        if (in.type() == typeid(KeyInput))
        {
            return boost::get<KeyInput>(in).amount;
        }

        return 0;
    }

    TransactionTypes::InputType getTransactionInputType(const TransactionInput &in)
    {
        if (in.type() == typeid(KeyInput))
        {
            return TransactionTypes::InputType::Key;
        }

        if (in.type() == typeid(BaseInput))
        {
            return TransactionTypes::InputType::Generating;
        }

        return TransactionTypes::InputType::Invalid;
    }

    const TransactionInput &getInputChecked(const Pastella::TransactionPrefix &transaction, size_t index)
    {
        if (transaction.inputs.size() <= index)
        {
            throw std::runtime_error("Transaction input index out of range");
        }

        return transaction.inputs[index];
    }

    const TransactionInput &getInputChecked(
        const Pastella::TransactionPrefix &transaction,
        size_t index,
        TransactionTypes::InputType type)
    {
        const auto &input = getInputChecked(transaction, index);
        if (getTransactionInputType(input) != type)
        {
            throw std::runtime_error("Unexpected transaction input type");
        }

        return input;
    }

    // TransactionOutput helper functions

    TransactionTypes::OutputType getTransactionOutputType(const TransactionOutputTarget &out)
    {
        if (out.type() == typeid(KeyOutput))
        {
            return TransactionTypes::OutputType::Key;
        }

        return TransactionTypes::OutputType::Invalid;
    }

    const TransactionOutput &getOutputChecked(const Pastella::TransactionPrefix &transaction, size_t index)
    {
        if (transaction.outputs.size() <= index)
        {
            throw std::runtime_error("Transaction output index out of range");
        }

        return transaction.outputs[index];
    }

    const TransactionOutput &getOutputChecked(
        const Pastella::TransactionPrefix &transaction,
        size_t index,
        TransactionTypes::OutputType type)
    {
        const auto &output = getOutputChecked(transaction, index);
        if (getTransactionOutputType(output.target) != type)
        {
            throw std::runtime_error("Unexpected transaction output target type");
        }

        return output;
    }

    bool findOutputsToAccount(
        const Pastella::TransactionPrefix &transaction,
        const AccountPublicAddress &addr,
        std::vector<uint32_t> &out,
        uint64_t &amount)
    {
        /* TRANSPARENT SYSTEM OUTPUT SCANNING
         * In transparent system, outputs go directly to public keys.
         * No key derivation needed - just compare keys directly! */

        /* DEBUG: Log what we're scanning */
        std::cout << "[WALLET DEBUG] Scanning transaction with " << transaction.outputs.size() << " outputs" << std::endl;

        amount = 0;
        uint32_t outputIndex = 0;

        for (const TransactionOutput &o : transaction.outputs)
        {
            assert(o.target.type() == typeid(KeyOutput));
            if (o.target.type() == typeid(KeyOutput))
            {
                const auto &keyOutput = boost::get<KeyOutput>(o.target);

                /* DEBUG: Log each output */
                std::cout << "[WALLET DEBUG] Output #" << outputIndex << " key: " << Common::podToHex(keyOutput.key) << std::endl;
                if (keyOutput.key == addr.publicKey)
                {
                    std::cout << "[WALLET DEBUG] MATCH FOUND! Output #" << outputIndex << " belongs to this wallet!" << std::endl;
                    std::cout << "[WALLET DEBUG] Amount: " << o.amount << " atomic units" << std::endl;

                    out.push_back(outputIndex);
                    amount += o.amount;
                }

                ++outputIndex;
            }
        }

        std::cout << "[WALLET DEBUG] Total outputs found: " << out.size() << ", Total amount: " << amount << std::endl;
        std::cout << "[WALLET DEBUG] ==============================" << std::endl;

        return true;
    }

} // namespace Pastella
