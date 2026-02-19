// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "ITransaction.h"
#include "pastellacore/PastellaBasic.h"

namespace Pastella
{
    bool checkInputsKeyimagesDiff(const Pastella::TransactionPrefix &tx);

    // TransactionInput helper functions
    size_t getRequiredSignaturesCount(const TransactionInput &in);

    uint64_t getTransactionInputAmount(const TransactionInput &in);

    TransactionTypes::InputType getTransactionInputType(const TransactionInput &in);

    const TransactionInput &getInputChecked(const Pastella::TransactionPrefix &transaction, size_t index);

    const TransactionInput &getInputChecked(
        const Pastella::TransactionPrefix &transaction,
        size_t index,
        TransactionTypes::InputType type);

    // TransactionOutput helper functions
    TransactionTypes::OutputType getTransactionOutputType(const TransactionOutputTarget &out);

    const TransactionOutput &getOutputChecked(const Pastella::TransactionPrefix &transaction, size_t index);

    const TransactionOutput &getOutputChecked(
        const Pastella::TransactionPrefix &transaction,
        size_t index,
        TransactionTypes::OutputType type);

    bool findOutputsToAccount(
        const Pastella::TransactionPrefix &transaction,
        const AccountPublicAddress &addr,
        std::vector<uint32_t> &out,
        uint64_t &amount);

} // namespace Pastella
