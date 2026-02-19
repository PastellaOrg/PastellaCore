// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The Galaxia Project Developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <system_error>

#include <Pastella.h>
#include <pastellacore/CachedTransaction.h>
#include <pastellacore/Checkpoints.h>
#include <pastellacore/Currency.h>
#include <pastellacore/IBlockchainCache.h>
#include <utilities/ThreadPool.h>

struct TransactionValidationResult
{
    /* A programmatic error code of the result */
    std::error_code errorCode;

    /* An error message describing the error code */
    std::string errorMessage;

    /* Whether the transaction is valid */
    bool valid = false;

    /* The fee of the transaction */
    uint64_t fee = 0;
};

class ValidateTransaction
{
    public:
        /////////////////
        /* CONSTRUCTOR */
        /////////////////
        ValidateTransaction(
            const Pastella::CachedTransaction &cachedTransaction,
            Pastella::TransactionValidatorState &state,
            Pastella::IBlockchainCache *cache,
            const Pastella::Currency &currency,
            const Pastella::Checkpoints &checkpoints,
            Utilities::ThreadPool<bool> &threadPool,
            const uint64_t blockHeight,
            const uint64_t blockSizeMedian,
            const bool isPoolTransaction);

        /////////////////////////////
        /* PUBLIC MEMBER FUNCTIONS */
        /////////////////////////////
        TransactionValidationResult validate();

        TransactionValidationResult revalidateAfterHeightChange();

    private:
        //////////////////////////////
        /* PRIVATE MEMBER FUNCTIONS */
        //////////////////////////////
        bool validateTransactionSize();

        bool validateGovernanceTransaction();

        bool validateTransactionInputs();

        bool validateTransactionOutputs();

        bool validateTransactionFee();

        bool validateTransactionExtra();

        bool validateInputOutputRatio();

        bool validateTransactionInputsExpensive();

        void setTransactionValidationResult(const std::error_code &error_code, const std::string &error_message = "");

        /////////////////////////
        /* PRIVATE MEMBER VARS */
        /////////////////////////
        const Pastella::Transaction m_transaction;

        const Pastella::CachedTransaction &m_cachedTransaction;

        Pastella::TransactionValidatorState &m_validatorState;

        const Pastella::IBlockchainCache *m_blockchainCache;

        const Pastella::Currency &m_currency;

        const Pastella::Checkpoints &m_checkpoints;

        const uint64_t m_blockHeight;

        const uint64_t m_blockSizeMedian;

        const bool m_isPoolTransaction;

        TransactionValidationResult m_validationResult;

        uint64_t m_sumOfOutputs = 0;
        uint64_t m_sumOfInputs = 0;

        Utilities::ThreadPool<bool> &m_threadPool;

        std::mutex m_mutex;
};
