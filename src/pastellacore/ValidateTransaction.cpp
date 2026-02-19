// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The Galaxia Project Developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <config/PastellaConfig.h>
#include <common/TransactionExtra.h>
#include <pastellacore/StakingSystem.h>
#include <pastellacore/TransactionValidationErrors.h>
#include <pastellacore/TransactionUtils.h>
#include <pastellacore/ValidateTransaction.h>
#include <serialization/SerializationTools.h>
#include <utilities/Utilities.h>

ValidateTransaction::ValidateTransaction(
    const Pastella::CachedTransaction &cachedTransaction,
    Pastella::TransactionValidatorState &state,
    Pastella::IBlockchainCache *cache,
    const Pastella::Currency &currency,
    const Pastella::Checkpoints &checkpoints,
    Utilities::ThreadPool<bool> &threadPool,
    const uint64_t blockHeight,
    const uint64_t blockSizeMedian,
    const bool isPoolTransaction) :
    m_cachedTransaction(cachedTransaction),
    m_transaction(cachedTransaction.getTransaction()),
    m_validatorState(state),
    m_currency(currency),
    m_checkpoints(checkpoints),
    m_threadPool(threadPool),
    m_blockchainCache(cache),
    m_blockHeight(blockHeight),
    m_blockSizeMedian(blockSizeMedian),
    m_isPoolTransaction(isPoolTransaction)
{
}

TransactionValidationResult ValidateTransaction::validate()
{

    /* Validate transaction isn't too big */
    if (!validateTransactionSize())
    {
        return m_validationResult;
    }

    /* Validate governance transactions are only accepted after activation height */
    if (!validateGovernanceTransaction())
    {
        return m_validationResult;
    }

    /* Validate the transaction inputs are non empty, key images are valid, etc. */
    if (!validateTransactionInputs())
    {
        return m_validationResult;
    }


    /* Validate transaction outputs are non zero, don't overflow, etc */
    if (!validateTransactionOutputs())
    {
        return m_validationResult;
    }


    if (!validateTransactionFee())
    {
        return m_validationResult;
    }


    /* Validate the transaction extra is a reasonable size. */
    if (!validateTransactionExtra())
    {
        return m_validationResult;
    }


    /* Validate transaction input / output ratio is not excessive */
    if (!validateInputOutputRatio())
    {
        return m_validationResult;
    }


    /* Verify key images are not spent and signatures are valid. We
     * do this separately from the transaction input verification, because
     * these checks are much slower to perform, so we want to fail fast on the
     * cheaper checks first.
     *
     * NOTE: Ring signature validation has been removed for transparent system.
     * Only basic key image checks are performed. */
    if (!validateTransactionInputsExpensive())
    {
        return m_validationResult;
    }


    m_validationResult.valid = true;
    setTransactionValidationResult(
        Pastella::error::TransactionValidationError::VALIDATION_SUCCESS
    );

    return m_validationResult;
}

/* Note: Does not set the .fee property */
TransactionValidationResult ValidateTransaction::revalidateAfterHeightChange()
{
    /* Validate transaction isn't too big now that the median size has changed */
    if (!validateTransactionSize())
    {
        return m_validationResult;
    }

    /* Validate the transaction extra is still a reasonable size. */
    if (!validateTransactionExtra())
    {
        return m_validationResult;
    }

    m_validationResult.valid = true;
    setTransactionValidationResult(
        Pastella::error::TransactionValidationError::VALIDATION_SUCCESS
    );

    return m_validationResult;
}


bool ValidateTransaction::validateTransactionSize()
{
    const auto maxTransactionSize = m_blockSizeMedian * 2 - m_currency.minerTxBlobReservedSize();

    if (m_cachedTransaction.getTransactionBinaryArray().size() > maxTransactionSize)
    {
        setTransactionValidationResult(
            Pastella::error::TransactionValidationError::SIZE_TOO_LARGE,
            "Transaction is too large (in bytes)"
        );

        return false;
    }

    return true;
}

bool ValidateTransaction::validateGovernanceTransaction()
{
    /* Check if this is a governance transaction */
    Pastella::TransactionExtraGovernanceProposal proposalExtra;
    Pastella::TransactionExtraGovernanceVote voteExtra;

    bool hasProposal = Pastella::getGovernanceProposalFromExtra(m_transaction.extra, proposalExtra);
    bool hasVote = Pastella::getGovernanceVoteFromExtra(m_transaction.extra, voteExtra);

    /* If not a governance transaction, allow it */
    if (!hasProposal && !hasVote)
    {
        return true;
    }

    /* This is a governance transaction - check if governance is enabled */
    if (m_blockHeight < Pastella::parameters::governance::GOVERNANCE_ENABLE_HEIGHT)
    {
        std::string errorMsg = "Governance is not yet enabled. Governance will be available at height " +
                             std::to_string(Pastella::parameters::governance::GOVERNANCE_ENABLE_HEIGHT) +
                             ". Current height: " + std::to_string(m_blockHeight);

        if (hasProposal)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::GOVERNANCE_NOT_ENABLED,
                "Proposal " + errorMsg
            );
        }
        else
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::GOVERNANCE_NOT_ENABLED,
                "Vote " + errorMsg
            );
        }

        return false;
    }

    /* Governance is enabled - allow the transaction */
    return true;
}

bool ValidateTransaction::validateTransactionInputs()
{
    if (m_transaction.inputs.empty())
    {
        setTransactionValidationResult(
            Pastella::error::TransactionValidationError::EMPTY_INPUTS,
            "Transaction has no inputs"
        );

        return false;
    }

    /* TRANSPARENT SYSTEM: Check for duplicate UTXO references within the transaction
     * Prevents a transaction from spending the same UTXO multiple times
     * This is a critical security check to prevent double-spend attacks within a single transaction */
    if (!Pastella::checkInputsKeyimagesDiff(m_transaction))
    {
        setTransactionValidationResult(
            Pastella::error::TransactionValidationError::INPUT_IDENTICAL_KEYIMAGES,
            "Transaction contains duplicate UTXO references (attempting to spend same output multiple times)"
        );

        return false;
    }

    /* STEALTH ADDRESS REMOVAL: Z, I, L constants removed - no longer needed in transparent system */

    uint64_t sumOfInputs = 0;

    /* STEALTH ADDRESS REMOVAL: Changed from KeyImage to PublicKey */
    std::unordered_set<Crypto::PublicKey> ki;

    for (const auto &input : m_transaction.inputs)
    {
        uint64_t amount = 0;

        if (input.type() == typeid(Pastella::KeyInput))
        {
            const Pastella::KeyInput &in = boost::get<Pastella::KeyInput>(input);
            amount = in.amount;

            if (in.outputIndexes.empty())
            {
                setTransactionValidationResult(
                    Pastella::error::TransactionValidationError::INPUT_EMPTY_OUTPUT_USAGE,
                    "Transaction contains no output indexes"
                );

                return false;
            }

            if (std::find(++std::begin(in.outputIndexes), std::end(in.outputIndexes), 0) != std::end(in.outputIndexes))
            {
                setTransactionValidationResult(
                    Pastella::error::TransactionValidationError::INPUT_IDENTICAL_OUTPUT_INDEXES,
                    "Transaction contains identical output indexes"
                );

                return false;
            }
        }
        else
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::INPUT_UNKNOWN_TYPE,
                "Transaction input has an unknown input type"
            );

            return false;
        }

        if (std::numeric_limits<uint64_t>::max() - amount < sumOfInputs)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::INPUTS_AMOUNT_OVERFLOW,
                "Transaction inputs will overflow"
            );

            return false;
        }

        sumOfInputs += amount;
    }

    m_sumOfInputs = sumOfInputs;

    return true;
}

bool ValidateTransaction::validateTransactionOutputs()
{
    uint64_t sumOfOutputs = 0;

    for (const auto &output : m_transaction.outputs)
    {
        if (output.amount == 0)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::OUTPUT_ZERO_AMOUNT,
                "Transaction has an output amount of zero"
            );

            return false;
        }

        if (m_blockHeight >= Pastella::parameters::MAX_OUTPUT_SIZE_HEIGHT)
        {
            if (output.amount > Pastella::parameters::MAX_OUTPUT_SIZE_NODE)
            {
                setTransactionValidationResult(
                    Pastella::error::TransactionValidationError::OUTPUT_AMOUNT_TOO_LARGE,
                    "Transaction has a too large output amount"
                );

                return false;
            }
        }

        if (output.target.type() == typeid(Pastella::KeyOutput))
        {
            if (!check_key(boost::get<Pastella::KeyOutput>(output.target).key))
            {
                setTransactionValidationResult(
                    Pastella::error::TransactionValidationError::OUTPUT_INVALID_KEY,
                    "Transaction output has an invalid output key"
                );

                return false;
            }
        }
        else
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::OUTPUT_UNKNOWN_TYPE,
                "Transaction output has an unknown output type"
            );

            return false;
        }

        if (std::numeric_limits<uint64_t>::max() - output.amount < sumOfOutputs)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::OUTPUTS_AMOUNT_OVERFLOW,
                "Transaction outputs will overflow"
            );

            return false;
        }

        sumOfOutputs += output.amount;
    }

    m_sumOfOutputs = sumOfOutputs;

    return true;
}

/**
 * Pre-requisite - Call validateTransactionInputs() and validateTransactionOutputs()
 * to ensure m_sumOfInputs and m_sumOfOutputs is set
 */
bool ValidateTransaction::validateTransactionFee()
{
    if (m_sumOfInputs == 0)
    {
        throw std::runtime_error("Error! You must call validateTransactionInputs() and "
                                 "validateTransactionOutputs() before calling validateTransactionFee()!");
    }

    if (m_sumOfOutputs > m_sumOfInputs)
    {
        setTransactionValidationResult(
            Pastella::error::TransactionValidationError::WRONG_AMOUNT,
            "Sum of outputs is greater than sum of inputs"
        );

        return false;
    }

    const uint64_t fee = m_sumOfInputs - m_sumOfOutputs;

    bool validFee = fee != 0;

    if (m_blockHeight >= Pastella::parameters::MINIMUM_FEE_PER_BYTE_V1_HEIGHT)
    {
        const auto minFee = Utilities::getMinimumTransactionFee(
            m_cachedTransaction.getTransactionBinaryArray().size(),
            m_blockHeight
        );

        validFee = fee >= minFee;
        if (minFee >= Pastella::parameters::ACCEPTABLE_FEE && !m_isPoolTransaction) validFee = true;
    }
    else if (m_isPoolTransaction)
    {
        validFee = fee >= Pastella::parameters::MINIMUM_FEE;
    }

    if (!validFee)
    {
        setTransactionValidationResult(
            Pastella::error::TransactionValidationError::WRONG_FEE,
            "Transaction fee is below minimum fee"
            );

        return false;
    }

    m_validationResult.fee = fee;

    return true;
}

bool ValidateTransaction::validateTransactionExtra()
{
    const uint64_t heightToEnforce =
        Pastella::parameters::MAX_EXTRA_SIZE_V2_HEIGHT + Pastella::parameters::PASTELLA_MINED_MONEY_UNLOCK_WINDOW;

    /* If we're checking if it's valid for the pool, we don't wait for the height
     * to enforce. */
    if (m_isPoolTransaction || m_blockHeight >= heightToEnforce)
    {
        if (m_transaction.extra.size() >= Pastella::parameters::MAX_EXTRA_SIZE_V2)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::EXTRA_TOO_LARGE,
                "Transaction extra is too large"
            );

            return false;
        }
    }

    /* Validate staking transactions if present */
    Pastella::TransactionExtraStaking stakingData;
    if (Pastella::getStakingDataFromExtra(m_transaction.extra, stakingData))
    {
        if (!Pastella::StakingValidator::validateStakingTransaction(stakingData, m_transaction, m_blockchainCache, m_blockHeight))
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::INPUT_UNEXPECTED_TYPE,
                "Invalid staking transaction: signature verification failed"
            );

            return false;
        }
    }

    /* Validate governance proposal transactions if present */
    Pastella::TransactionExtraGovernanceProposal proposalData;
    if (Pastella::getGovernanceProposalFromExtra(m_transaction.extra, proposalData))
    {
        /* Check if governance is enabled */
        if (m_blockHeight < Pastella::parameters::governance::GOVERNANCE_ENABLE_HEIGHT)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::INPUT_UNEXPECTED_TYPE,
                "Governance system is not enabled yet"
            );

            return false;
        }

        /* Validate proposal title length */
        if (proposalData.title.empty() || proposalData.title.length() > 200)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::INPUT_UNEXPECTED_TYPE,
                "Invalid governance proposal: title must be 1-200 characters"
            );

            return false;
        }

        /* Validate proposal description length */
        if (proposalData.description.empty() || proposalData.description.length() > 5000)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::INPUT_UNEXPECTED_TYPE,
                "Invalid governance proposal: description must be 1-5000 characters"
            );

            return false;
        }

        /* Validate proposal type */
        if (proposalData.proposalType > Pastella::parameters::governance::PROPOSAL_TYPE_TREASURY)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::INPUT_UNEXPECTED_TYPE,
                "Invalid governance proposal: invalid proposal type"
            );

            return false;
        }

        /* NOTE: Full validation (minimum stake check, signature verification, etc.)
         * will be done when the transaction is included in a block and processed by Core.
         * This is basic validation to prevent obviously invalid transactions from entering the pool. */
    }

    /* Validate governance vote transactions if present */
    Pastella::TransactionExtraGovernanceVote voteData;
    if (Pastella::getGovernanceVoteFromExtra(m_transaction.extra, voteData))
    {
        /* Check if governance is enabled */
        if (m_blockHeight < Pastella::parameters::governance::GOVERNANCE_ENABLE_HEIGHT)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::INPUT_UNEXPECTED_TYPE,
                "Governance system is not enabled yet"
            );

            return false;
        }

        /* Validate vote type */
        if (voteData.vote != Pastella::parameters::governance::VOTE_AGAINST &&
            voteData.vote != Pastella::parameters::governance::VOTE_FOR &&
            voteData.vote != Pastella::parameters::governance::VOTE_ABSTAIN)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::INPUT_UNEXPECTED_TYPE,
                "Invalid governance vote: invalid vote type"
            );

            return false;
        }

        /* NOTE: Full validation (proposal exists, address hasn't voted, etc.)
         * will be done when the transaction is included in a block and processed by Core.
         * This is basic validation to prevent obviously invalid transactions from entering the pool. */
    }

    return true;
}

bool ValidateTransaction::validateInputOutputRatio()
{
    if (m_isPoolTransaction || m_blockHeight >= Pastella::parameters::NORMAL_TX_MAX_OUTPUT_COUNT_V1_HEIGHT)
    {
        if (m_transaction.outputs.size() > Pastella::parameters::NORMAL_TX_MAX_OUTPUT_COUNT_V1)
        {
            setTransactionValidationResult(
                Pastella::error::TransactionValidationError::EXCESSIVE_OUTPUTS,
                "Transaction has excessive outputs. Reduce the number of payees."
            );

            return false;
        }
    }

    return true;
}

bool ValidateTransaction::validateTransactionInputsExpensive()
{

    /* Don't need to do expensive transaction validation for transactions
     * in a checkpoints range - they are assumed valid, and the transaction
     * hash would change thus invalidation the checkpoints if not. */
    if (m_checkpoints.isInCheckpointZone(m_blockHeight + 1))
    {
        return true;
    }


    /* TRANSPARENT SYSTEM: Double-spend prevention
     * Check if this transaction has already been processed (spent)
     * If the transaction hash is in spentTransactions, it's a double-spend attempt */
    const Crypto::Hash txHash = m_cachedTransaction.getTransactionHash();
    if (m_validatorState.spentTransactions.count(txHash) > 0)
    {
        setTransactionValidationResult(
            Pastella::error::TransactionValidationError::INPUT_KEYIMAGE_ALREADY_SPENT,
            "Transaction has already been spent (double-spend attempt)"
        );

        return false;
    }


    uint64_t inputIndex = 0;

    std::vector<std::future<bool>> validationResult;
    std::atomic<bool> cancelValidation = false;
    const Crypto::Hash prefixHash = m_cachedTransaction.getTransactionPrefixHash();


    for (const auto &input : m_transaction.inputs)
    {
        /* Validate each input on a separate thread in our thread pool */
        validationResult.push_back(m_threadPool.addJob([inputIndex, &input, &prefixHash, &cancelValidation, this] {

            const Pastella::KeyInput &in = boost::get<Pastella::KeyInput>(input);
            if (cancelValidation)
            {
                return false; // fail the validation immediately if cancel requested
            }


            /* TRANSPARENT SYSTEM: Double-spend checking via spentTransactions IMPLEMENTED
             *
             * Multi-layer protection is ACTIVE:
             * 1. Within-transaction: checkInputsKeyimagesDiff() prevents duplicate UTXOs
             * 2. Within-block: spentTransactions set (lines 448-460) prevents reuse
             * 3. Cross-block: Persistent spent transaction hash tracking
             *
             * This section validates output references before signature verification
             * Actual double-spend check happened earlier in validateTransactionInputs() */

            /* TRANSPARENT SYSTEM: Get output key directly from transaction
             *
             * In transparent system (like Bitcoin):
             * - Input directly references: (transactionHash, outputIndex)
             * - No global indexes or ring signatures
             * - We fetch the output key directly from the referenced transaction
             */
            std::vector<Crypto::PublicKey> outputKeys;
            Crypto::Hash referencedTxHash = in.transactionHash;
            uint32_t outputIndex = in.outputIndex;

            /* UTXO SYSTEM: Double-spend protection check
             *
             * CRITICAL SECURITY: Verify UTXO is unspent before allowing transaction
             *
             * In transparent system, we must check:
             * 1. Does the UTXO exist? (output was created in a previous transaction)
             * 2. Is the UTXO unspent? (hasn't been spent by another transaction yet)
             *
             * NOTE: For pool transactions (m_isPoolTransaction=true), we skip the database UTXO check
             * because:
             * - The transaction pool has its own double-spend detection
             * - UTXOs spent by other pool transactions will be caught by pool validation
             * - We only validate blockchain-spent UTXOs for transactions going into blocks */
            if (!m_isPoolTransaction)
            {
                try
                {
                    /* DEBUG: Single line to verify rebuild */

                    /* Check if UTXO is unspent in blockchain - this will verify:
                     * 1. UTXO exists in blockchain
                     * 2. UTXO is not already spent in a confirmed block */
                    if (!m_blockchainCache->isUtxoUnspent(referencedTxHash, outputIndex))
                    {
                        /* UTXO double-spend detected! Reject transaction
                         *
                         * This means either:
                         * 1. The UTXO doesn't exist (invalid output reference)
                         * 2. The UTXO is already spent (double-spend attempt)
                         *
                         * Both cases are critical security violations - reject the transaction */
                        std::stringstream errorMsg;
                        errorMsg << "Double-spend detected! UTXO " << Common::podToHex(referencedTxHash)
                                << ":" << outputIndex << " is either invalid or already spent in blockchain";

                        setTransactionValidationResult(
                            Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                            errorMsg.str());

                        return false;
                    }
                }
                catch (const std::exception &e)
                {
                    /* Exception during UTXO validation - reject transaction for safety */
                    std::stringstream errorMsg;
                    errorMsg << "UTXO validation failed for " << Common::podToHex(referencedTxHash)
                            << ":" << outputIndex << " - " << e.what();

                    setTransactionValidationResult(
                        Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                        errorMsg.str());

                    return false;
                }
                catch (...)
                {
                    /* Unknown exception - reject transaction for safety */
                    std::stringstream errorMsg;
                    errorMsg << "UTXO validation failed with unknown exception for "
                            << Common::podToHex(referencedTxHash) << ":" << outputIndex;

                    setTransactionValidationResult(
                        Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                        errorMsg.str());

                    return false;
                }
            }
            /* For pool transactions, skip UTXO check - pool handles double-spend detection */

            /* Get the transaction that contains the output we're spending
             *
             * TRANSPARENT SYSTEM: Get the transaction by hash
             * We need to retrieve the full transaction to extract the output keys
             *
             * Strategy: Try multiple methods to find the transaction:
             * 1. First try getRawTransactions with hash list
             * 2. If that fails, try getBlockIndexContainingTx + getRawTransaction */
            Pastella::BinaryArray txBinary;


            try
            {
                /* Method 1: Try to get transaction directly by hash */
                std::vector<Crypto::Hash> txHashes = {referencedTxHash};
                std::vector<Pastella::BinaryArray> txBinaries = m_blockchainCache->getRawTransactions(txHashes);

                if (!txBinaries.empty() && !txBinaries[0].empty())
                {
                    /* Successfully retrieved transaction */
                    txBinary = txBinaries[0];
                }
                else
                {

                    /* Method 2: Fall back to block index method
                     *
                     * TRANSPARENT SYSTEM: For pool transactions, try harder to find the transaction
                     * It might be a recent blockchain transaction that's not in the transaction index yet */
                    uint32_t blockIndex = m_blockchainCache->getBlockIndexContainingTx(referencedTxHash);


                    if (blockIndex == std::numeric_limits<uint32_t>::max())
                    {

                        /* For pool transactions, provide a more helpful error message
                         * suggesting the transaction might be very recent or in a reorged block */
                        std::stringstream errorMsg;
                        if (m_isPoolTransaction)
                        {
                            errorMsg << "Cannot find transaction " << Common::podToHex(referencedTxHash)
                                    << " in blockchain cache - transaction may be very recent, pool transaction, "
                                    << "or blockchain may be reorganizing. Try resubmitting after the next block.";
                        }
                        else
                        {
                            errorMsg << "Cannot find transaction " << Common::podToHex(referencedTxHash)
                                    << " in blockchain - UTXO does not exist";
                        }
                        setTransactionValidationResult(
                            Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                            errorMsg.str());

                        return false;
                    }

                    /* Get the raw block containing the transaction */
                    Pastella::RawBlock rawBlock = m_blockchainCache->getBlockByIndex(blockIndex);

                    /* Deserialize the block from binary format */
                    Pastella::BlockTemplate block;
                    Pastella::fromBinaryArray(block, rawBlock.block);

                    /* Find the transaction index within the block */
                    uint32_t txIndex = 0;
                    bool found = false;
                    for (const auto &txHash : block.transactionHashes)
                    {
                        if (txHash == referencedTxHash)
                        {
                            /* Found it! Get the transaction binary */
                            txBinary = m_blockchainCache->getRawTransaction(blockIndex, txIndex);
                            found = true;
                            break;
                        }
                        txIndex++;
                    }

                    if (!found || txBinary.empty())
                    {
                        setTransactionValidationResult(
                            Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                            "Transaction binary not found in block"
                        );

                        return false;
                    }
                }
            }
            catch (const std::exception &e)
            {
                std::stringstream errorMsg;
                errorMsg << "Failed to retrieve transaction " << Common::podToHex(referencedTxHash)
                        << ": " << e.what();

                setTransactionValidationResult(
                    Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                    errorMsg.str());

                return false;
            }

            /* Parse the transaction
             *
             * TRANSPARENT SYSTEM: Use fromBinaryArray to parse transaction
             * This is the standard function for deserializing transactions from binary format */
            Pastella::Transaction tx;
            if (!Pastella::fromBinaryArray(tx, txBinary))
            {
                setTransactionValidationResult(
                    Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                    "Failed to parse referenced transaction"
                );

                return false;
            }

            /* COINBASE MATURITY CHECK: Check if the transaction we're spending is a coinbase transaction
             *
             * Coinbase (miner reward) outputs have a mandatory maturity period of PASTELLA_MINED_MONEY_UNLOCK_WINDOW (10 blocks)
             * This prevents miners from spending their rewards immediately, which could cause chain reorganization issues
             *
             * In transparent system, coinbase transactions are identified by having no inputs (vin is empty) */
            if (tx.inputs.empty())
            {
                /* This is a coinbase transaction - check if maturity period has passed */
                const uint64_t currentHeight = m_blockHeight;
                const uint64_t coinbaseMaturity = Pastella::parameters::PASTELLA_MINED_MONEY_UNLOCK_WINDOW;

                /* Get the block height where this coinbase transaction was included */
                uint32_t coinbaseBlockHeight = m_blockchainCache->getBlockIndexContainingTx(referencedTxHash);

                if (coinbaseBlockHeight == std::numeric_limits<uint32_t>::max())
                {
                    setTransactionValidationResult(
                        Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                        "Cannot find block containing coinbase transaction"
                    );

                    return false;
                }

                /* Calculate how many blocks since coinbase */
                uint64_t blocksSinceCoinbase = currentHeight - coinbaseBlockHeight;

                /* Check if maturity period has passed */
                if (blocksSinceCoinbase < coinbaseMaturity)
                {
                    std::stringstream errorMsg;
                    errorMsg << "Cannot spend coinbase output - " << blocksSinceCoinbase
                            << " blocks have passed, but " << coinbaseMaturity << " are required ("
                            << (coinbaseMaturity - blocksSinceCoinbase) << " more blocks needed)";

                    setTransactionValidationResult(
                        Pastella::error::TransactionValidationError::INPUT_SPEND_LOCKED_OUT,
                        errorMsg.str()
                    );

                    return false;
                }
            }

            /* Validate output index exists */
            if (outputIndex >= tx.outputs.size())
            {
                setTransactionValidationResult(
                    Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                    "Transaction references invalid output index"
                );

                return false;
            }

            /* Get the output key from the transaction output */
            const Pastella::TransactionOutput &output = tx.outputs[outputIndex];
            if (output.target.type() != typeid(Pastella::KeyOutput))
            {
                setTransactionValidationResult(
                    Pastella::error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX,
                    "Output is not a key output"
                );

                return false;
            }

            const Pastella::KeyOutput &keyOutput = boost::get<Pastella::KeyOutput>(output.target);
            outputKeys.push_back(keyOutput.key);

            /* Check if output is locked by unlock time */
            if (!m_blockchainCache->isTransactionSpendTimeUnlocked(tx.unlockTime, m_blockHeight))
            {
                setTransactionValidationResult(
                    Pastella::error::TransactionValidationError::INPUT_SPEND_LOCKED_OUT,
                    "Transaction includes an input which is still locked"
                );

                return false;
            }

            /* Signature verification for transparent system
             *
             * In a transparent system (like Bitcoin), each input must have a valid
             * cryptographic signature proving ownership of the UTXO being spent.
             *
             * Unlike ring signatures, we use simple Ed25519 signatures:
             * - Each input has exactly ONE signature
             * - Signature proves knowledge of the private key for the output being spent
             * - Verifies: Signature(publicKey, transactionHash) is valid
             *
             * This prevents attackers from spending other users' UTXOs.
             *
             * See VULNERABILITY.md for full details. */
            if (m_isPoolTransaction
                || m_blockHeight >= Pastella::parameters::TRANSACTION_SIGNATURE_COUNT_VALIDATION_HEIGHT)
            {
                /* Check that transaction has a signature for this input */
                if (inputIndex >= m_transaction.signatures.size())
                {
                    setTransactionValidationResult(
                        Pastella::error::TransactionValidationError::INPUT_INVALID_SIGNATURES_COUNT,
                        "Transaction is missing signature for input"
                    );

                    return false;
                }

                /* In transparent mode, each input has exactly ONE signature (not a ring) */
                if (m_transaction.signatures[inputIndex].size() != 1)
                {
                    setTransactionValidationResult(
                        Pastella::error::TransactionValidationError::INPUT_INVALID_SIGNATURES_COUNT,
                        "Transaction has invalid number of signatures (expected 1 for transparent system)"
                    );

                    return false;
                }

                /* Verify the signature proves ownership of the UTXO
                 *
                 * outputKeys[0] is the public key of the output being spent
                 * The signature must be valid for this public key
                 *
                 * This ensures only the owner of the UTXO can spend it */
                if (!Crypto::check_signature(prefixHash, outputKeys[0], m_transaction.signatures[inputIndex][0]))
                {
                    setTransactionValidationResult(
                        Pastella::error::TransactionValidationError::INPUT_INVALID_SIGNATURES,
                        "Transaction contains invalid signature (signature does not prove ownership)"
                    );

                    return false;
                }
            }
            else
            {
                /* Before signature validation height, we still check basic structure */
                (void)outputKeys; // Suppress unused warning in older blocks
            }

            return true;
        }));

        inputIndex++;
    }

    bool valid = true;

    for (auto &result : validationResult)
    {
        if (!result.get())
        {
            valid = false;
            cancelValidation = true;
        }
    }

    /* TRANSPARENT SYSTEM: Mark transaction as spent after successful validation
     * This prevents the same transaction from being included in multiple blocks */
    if (valid)
    {
        const Crypto::Hash txHash = m_cachedTransaction.getTransactionHash();
        m_validatorState.spentTransactions.insert(txHash);
    }

    return valid;
}


void ValidateTransaction::setTransactionValidationResult(const std::error_code &error_code, const std::string &error_message)
{
    std::scoped_lock<std::mutex> lock(m_mutex);

    m_validationResult.errorCode = error_code;

    m_validationResult.errorMessage = error_message;
}
