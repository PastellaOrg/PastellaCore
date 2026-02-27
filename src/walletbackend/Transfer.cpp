// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

///////////////////////////////////
#include <walletbackend/Transfer.h>
///////////////////////////////////

#include <config/PastellaConfig.h>
#include <config/Constants.h>
#include <config/WalletConfig.h>
#include <common/Varint.h>
#include <errors/ValidateParameters.h>
#include <logger/Logger.h>
#include <utilities/Addresses.h>
#include <utilities/FormatTools.h>
#include <utilities/Utilities.h>
#include <walletbackend/WalletBackend.h>
#include <algorithm>
#include <map>
#include <limits>
#include <chrono>
#include <thread>
#include <iostream>

namespace SendTransaction
{

    /* A basic send transaction, the most common transaction, one destination,
       default fee, default change address

       WARNING: This is NOT suitable for multi wallet containers, as the change
       will be returned to the primary subwallet address.

       If you want to return change to a specific wallet, use
       sendTransactionAdvanced() */
    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendTransactionBasic(
        std::string destination,
        const uint64_t amount,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const bool sendAll,
        const bool sendTransaction)
    {
        std::vector<std::pair<std::string, uint64_t>> destinations = {{destination, amount}};

        WalletTypes::FeeType fee = WalletTypes::FeeType::MinimumFee();

        /* Assumes the container has at least one subwallet - this is true as long
           as the static constructors were used */
        const std::string changeAddress = subWallets->getPrimaryAddress();

        const uint64_t unlockTime = 0;

        return sendTransactionAdvanced(
            destinations,
            fee,
            {},
            changeAddress,
            daemon,
            subWallets,
            unlockTime,
            {},
            sendAll,
            sendTransaction
        );
    }

    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendTransactionAdvanced(
        std::vector<std::pair<std::string, uint64_t>> addressesAndAmounts,
        const WalletTypes::FeeType fee,
        const std::vector<std::string> addressesToTakeFrom,
        std::string changeAddress,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const uint64_t unlockTime,
        const std::vector<uint8_t> extraData,
        const bool sendAll,
        const bool sendTransaction)
    {
        /* Append the fee transaction, if a fee is being used */
        const auto [feeAmount, feeAddress] = daemon->nodeFee();

        if (feeAmount != 0)
        {
            addressesAndAmounts.push_back({feeAddress, feeAmount});
        }

        if (changeAddress == "")
        {
            changeAddress = subWallets->getPrimaryAddress();
        }

        /* Validate the transaction input parameters */
        Error error = validateTransaction(
            addressesAndAmounts,
            fee,
            addressesToTakeFrom,
            changeAddress,
            subWallets,
            daemon->networkBlockCount());

        if (error)
        {
            return {error, Crypto::Hash(), WalletTypes::PreparedTransactionInfo()};
        }

        /* If no address to take from is given, we will take from all available. */
        const bool takeFromAllSubWallets = addressesToTakeFrom.empty();

        /* The total amount we are sending */
        uint64_t totalAmount = Utilities::getTransactionSum(addressesAndAmounts);

        const std::vector<Crypto::PublicKey> subWalletsToTakeFrom =
            Utilities::addressesToPublicKeys(addressesToTakeFrom);

        /* Get inputs that are available to be spent so we can form the tx */
        auto availableInputs = subWallets->getSpendableTransactionInputs(
            takeFromAllSubWallets,
            subWalletsToTakeFrom,
            daemon->networkBlockCount()
        );

        Logger::logger.log(
            "Got " + std::to_string(availableInputs.size()) + " available inputs from getSpendableTransactionInputs",
            Logger::TRACE,
            {Logger::SYNC});

        uint64_t sumOfInputs = 0;

        std::vector<WalletTypes::TxInputAndOwner> ourInputs;

        if (fee.isFixedFee)
        {
            totalAmount += fee.fixedFee;
        }

        WalletTypes::TransactionResult txResult;
        uint64_t changeRequired;
        uint64_t requiredAmount = totalAmount;
        WalletTypes::PreparedTransactionInfo txInfo;

        for (const auto input : availableInputs)
        {
            std::stringstream ss;
            ss << "Selecting input: amount=" << input.input.amount
               << " unlockTime=" << input.input.unlockTime;

            Logger::logger.log(ss.str(), Logger::TRACE, {Logger::SYNC});

            ourInputs.push_back(input);
            sumOfInputs += input.input.amount;

            if (sumOfInputs >= totalAmount)
            {
                /* If the sum of inputs is > total amount, we need to send some back to
                   ourselves. */
                changeRequired = sumOfInputs - totalAmount;

                auto destinations = setupDestinations(addressesAndAmounts, changeRequired, changeAddress);

                /* Ok, we are using a fee per byte, lets take a guess at how
                 * large our fee is going to be, and then see if we have enough
                 * inputs to cover it. */
                if (!fee.isFixedFee)
                {
                    const size_t transactionSize = Utilities::estimateTransactionSize(
                        ourInputs.size(),
                        destinations.size(),
                        extraData.size()
                    );

                    const double feePerByte = fee.isFeePerByte
                        ? fee.feePerByte
                        : Pastella::parameters::MINIMUM_FEE_PER_BYTE_V1;

                    uint64_t estimatedFee = Utilities::getTransactionFee(
                        transactionSize,
                        daemon->networkBlockCount(),
                        feePerByte
                    );
                    // pre-fork we still need assure the previous minimum fee
                    const uint64_t height = daemon->networkBlockCount();
                    if (height < Pastella::parameters::MINIMUM_FEE_PER_BYTE_V1_HEIGHT && estimatedFee < Pastella::parameters::MINIMUM_FEE) {
                        estimatedFee = Pastella::parameters::MINIMUM_FEE;
                    }

                    if (sendAll)
                    {
                        const auto [address, amount] = addressesAndAmounts[0];

                        if (estimatedFee > amount)
                        {
                            txInfo.fee = estimatedFee;
                            return { NOT_ENOUGH_BALANCE, Crypto::Hash(), txInfo };
                        }

                        totalAmount -= estimatedFee;
                        addressesAndAmounts[0] = { address, amount - estimatedFee };
                        destinations = setupDestinations(addressesAndAmounts, changeRequired, changeAddress);
                    }

                    const uint64_t estimatedAmount = totalAmount + estimatedFee;

                    /* Ok, we have enough inputs to add our estimated fee, lets
                     * go ahead and try and make the transaction. */
                    if (sumOfInputs >= estimatedAmount)
                    {
                        const auto [success, result, change, needed] = tryMakeFeePerByteTransaction(
                            sumOfInputs,
                            totalAmount,
                            estimatedAmount,
                            feePerByte,
                            addressesAndAmounts,
                            changeAddress,
                            daemon,
                            ourInputs,
                            subWallets,
                            unlockTime,
                            extraData,
                            sendAll
                        );

                        if (success)
                        {
                            txResult = result;
                            changeRequired = change;
                            break;
                        }
                        else
                        {
                            requiredAmount = needed;
                            continue;
                        }
                    }
                    else
                    {
                        /* Need to ensure we update this so if we run out of
                         * inputs we correctly check if we have enough balance */
                        requiredAmount = estimatedAmount;
                    }
                }
                else
                {
                    txResult = makeTransaction(
                        daemon,
                        ourInputs,
                        destinations,
                        subWallets,
                        unlockTime,
                        extraData
                    );

                    const uint64_t minFee = Utilities::getMinimumTransactionFee(
                        toBinaryArray(txResult.transaction).size(),
                        daemon->networkBlockCount()
                    );

                    if (fee.fixedFee >= minFee)
                    {
                        break;
                    }
                    else
                    {
                        return { FEE_TOO_SMALL, Crypto::Hash(), WalletTypes::PreparedTransactionInfo() };
                    }
                }
            }
        }

        if (sumOfInputs < requiredAmount)
        {
            txInfo.fee = requiredAmount - totalAmount;
            return {NOT_ENOUGH_BALANCE, Crypto::Hash(), txInfo};
        }

        if (txResult.error)
        {
            return {txResult.error, Crypto::Hash(), txInfo};
        }

        error = isTransactionPayloadTooBig(txResult.transaction, daemon->networkBlockCount());

        if (error)
        {
            return {error, Crypto::Hash(), txInfo};
        }

        if (!verifyAmounts(txResult.transaction))
        {
            return {AMOUNTS_NOT_PRETTY, Crypto::Hash(), txInfo};
        }

        const uint64_t actualFee = sumTransactionFee(txResult.transaction);

        if (!verifyTransactionFee(fee, actualFee, daemon->networkBlockCount(), txResult.transaction))
        {
            return {UNEXPECTED_FEE, Crypto::Hash(), txInfo};
        }

        txInfo.fee = actualFee;
        txInfo.inputs = ourInputs;
        txInfo.changeAddress = changeAddress;
        txInfo.changeRequired = changeRequired;
        txInfo.tx = txResult;

        if (sendTransaction)
        {
            const auto [sendError, txHash] = relayTransaction(txResult.transaction, daemon);

            if (sendError)
            {
                return {sendError, Crypto::Hash(), WalletTypes::PreparedTransactionInfo()};
            }

            txInfo.transactionHash = txHash;

            /* Store the unconfirmed transaction, update our balance */
            storeSentTransaction(txHash, actualFee, ourInputs, changeAddress, changeRequired, subWallets);

            /* Update our locked balance with the incoming funds */
            storeUnconfirmedIncomingInputs(subWallets, txResult.outputs, txResult.txKeyPair.publicKey, txHash);

            subWallets->storeTxPrivateKey(txResult.txKeyPair.secretKey, txHash);

            /* STEALTH ADDRESS REMOVAL: Changed keyImage to publicKey, swapped parameter order */
            /* Lock the input for spending till it is confirmed as spent in a block */
            for (const auto input : ourInputs)
            {
                subWallets->markInputAsLocked(input.publicKey, input.input.parentTransactionHash, input.input.transactionIndex);
            }

            return {SUCCESS, txHash, txInfo};
        }
        else
        {
            txInfo.transactionHash = getTransactionHash(txResult.transaction);
            return {SUCCESS, txInfo.transactionHash, txInfo};
        }
    }

    std::tuple<Error, Crypto::Hash> sendPreparedTransaction(
        const WalletTypes::PreparedTransactionInfo txInfo,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets)
    {
        for (const auto &input : txInfo.inputs)
        {
            if (!subWallets->haveSpendableInput(input.input, daemon->networkBlockCount()))
            {
                return {PREPARED_TRANSACTION_EXPIRED, Crypto::Hash()};
            }
        }

        const auto [sendError, txHash] = relayTransaction(txInfo.tx.transaction, daemon);

        if (sendError)
        {
            return {sendError, Crypto::Hash()};
        }

        /* Store the unconfirmed transaction, update our balance */
        storeSentTransaction(
            txHash,
            txInfo.fee,
            txInfo.inputs,
            txInfo.changeAddress,
            txInfo.changeRequired,
            subWallets
        );

        /* Update our locked balance with the incoming funds */
        storeUnconfirmedIncomingInputs(
            subWallets,
            txInfo.tx.outputs,
            txInfo.tx.txKeyPair.publicKey,
            txHash
        );

        subWallets->storeTxPrivateKey(txInfo.tx.txKeyPair.secretKey, txHash);

        /* STEALTH ADDRESS REMOVAL: Changed keyImage to publicKey, swapped parameter order */
        /* Lock the input for spending till it is confirmed as spent in a block */
        for (const auto input : txInfo.inputs)
        {
            subWallets->markInputAsLocked(input.publicKey, input.input.parentTransactionHash, input.input.transactionIndex);
        }

        return {SUCCESS, txHash};
    }

    std::tuple<bool, WalletTypes::TransactionResult, uint64_t, uint64_t> tryMakeFeePerByteTransaction(
        const uint64_t sumOfInputs,
        uint64_t amountPreFee,
        uint64_t amountIncludingFee,
        const double feePerByte,
        std::vector<std::pair<std::string, uint64_t>> addressesAndAmounts,
        const std::string changeAddress,
        const std::shared_ptr<Nigel> daemon,
        const std::vector<WalletTypes::TxInputAndOwner> ourInputs,
        const std::shared_ptr<SubWallets> subWallets,
        const uint64_t unlockTime,
        const std::vector<uint8_t> extraData,
        const bool sendAll)
    {
        while (true)
        {
            const uint64_t changeRequired = sumOfInputs - amountIncludingFee;

            /* Need to recalculate destinations since amount of change, err, changed! */
            const auto destinations = setupDestinations(addressesAndAmounts, changeRequired, changeAddress);

            WalletTypes::TransactionResult txResult = makeTransaction(
                daemon,
                ourInputs,
                destinations,
                subWallets,
                unlockTime,
                extraData
            );

            const size_t actualTxSize = toBinaryArray(txResult.transaction).size();

            uint64_t actualFee = Utilities::getTransactionFee(
                actualTxSize,
                daemon->networkBlockCount(),
                feePerByte
            );
            // pre-fork we still need assure the previous minimum fee
            const uint64_t height = daemon->networkBlockCount();
            if (height < Pastella::parameters::MINIMUM_FEE_PER_BYTE_V1_HEIGHT && actualFee < Pastella::parameters::MINIMUM_FEE) {
                actualFee = Pastella::parameters::MINIMUM_FEE;
            }


            /* Great! The fee we estimated is greater than or equal
             * to the min/specified fee per byte for a transaction
             * of this size, so we can continue with sending the
             * transaction. */
            if (amountIncludingFee - amountPreFee >= actualFee)
            {
                return { true, txResult, changeRequired, 0 };
            }

            /* If we're sending all, then we adjust the amount we're sending,
             * rather than the change we're returning. */
            if (sendAll)
            {
                amountPreFee = amountIncludingFee - actualFee;
                const auto [address, amount] = addressesAndAmounts[0];
                addressesAndAmounts[0] = { address, amountPreFee };
            }

            /* The actual fee required for a tx of this size is not
             * covered by the amount of inputs we have so far, lets
             * go select some more then try again. */
            if (amountPreFee + actualFee > sumOfInputs)
            {
                return { false, txResult, changeRequired, amountPreFee + actualFee };
            }
            
            /* Our fee was too low. Lets try making the transaction again,
             * this time using the actual fee calculated. Note that this still
             * may fail, since we are possibly adding more outputs, and so have
             * a large transaction size. If we keep increasing the fee and keep
             * failing, eventually we'll hit a point where we either succeed
             * or we need to gather more inputs. */
            amountIncludingFee = amountPreFee + actualFee;
        }

        throw std::runtime_error("Programmer error @ tryMakeFeePerByteTransaction");
    }

    Error isTransactionPayloadTooBig(const Pastella::Transaction tx, const uint64_t currentHeight)
    {
        const uint64_t txSize = toBinaryArray(tx).size();

        const uint64_t maxTxSize = Utilities::getMaxTxSize(currentHeight);

        if (txSize > maxTxSize)
        {
            std::stringstream errorMsg;

            errorMsg << "Transaction is too large: (" << Utilities::prettyPrintBytes(txSize)
                     << "). Max allowed size is " << Utilities::prettyPrintBytes(maxTxSize)
                     << ". Decrease the amount you are sending.";

            return Error(TOO_MANY_INPUTS_TO_FIT_IN_BLOCK, errorMsg.str());
        }

        return SUCCESS;
    }

    /* Possibly we could abstract some of this from processTransactionOutputs...
       but I think it would make the code harder to follow */
    void storeUnconfirmedIncomingInputs(
        const std::shared_ptr<SubWallets> subWallets,
        const std::vector<WalletTypes::KeyOutput> keyOutputs,
        const Crypto::PublicKey txPublicKey,
        const Crypto::Hash txHash)
    {
        /* STEALTH ADDRESS REMOVAL: KeyDerivation removed - no key derivation in transparent system */
        (void)txPublicKey; /* Suppress unused warning */

        uint64_t outputIndex = 0;

        for (const auto output : keyOutputs)
        {
            /* STEALTH ADDRESS REMOVAL: In transparent system, compare keys directly */
            Crypto::PublicKey publicKey = output.key;

            /* Not our output */
            /* Crypto::underive_public_key() removed - no key derivation in transparent system */

            const auto keys = subWallets->m_publicKeys;

            const auto it = std::find(keys.begin(), keys.end(), publicKey);

            if (it != keys.end())
            {
                Crypto::PublicKey ourKey = *it;

                WalletTypes::UnconfirmedInput input;

                input.amount = keyOutputs[outputIndex].amount;
                input.key = keyOutputs[outputIndex].key;
                input.parentTransactionHash = txHash;

                subWallets->storeUnconfirmedIncomingInput(input, ourKey);
            }

            outputIndex++;
        }
    }

    void storeSentTransaction(
        const Crypto::Hash hash,
        const uint64_t fee,
        const std::vector<WalletTypes::TxInputAndOwner> ourInputs,
        const std::string changeAddress,
        const uint64_t changeRequired,
        const std::shared_ptr<SubWallets> subWallets)
    {
        std::unordered_map<Crypto::PublicKey, int64_t> transfers;

        /* Loop through each input, and minus that from the transfers array */
        for (const auto input : ourInputs)
        {
            transfers[input.publicKey] -= input.input.amount;
        }
        const auto publicKey = Utilities::addressToPublicKey(changeAddress);

        /* Increment the change address with the amount we returned to ourselves */
        if (changeRequired != 0)
        {
            transfers[publicKey] += changeRequired;
        }

        /* Not initialized till it's in a block */
        const uint64_t timestamp(0), blockHeight(0), unlockTime(0);

        const bool isCoinbaseTransaction = false;

        /* Create the unconfirmed transaction (Will be overwritten by the
           confirmed transaction later) */
        WalletTypes::Transaction tx(
            transfers, hash, fee, timestamp, blockHeight, unlockTime, isCoinbaseTransaction);

        subWallets->addUnconfirmedTransaction(tx);
    }

    std::tuple<Error, Crypto::Hash>
        relayTransaction(const Pastella::Transaction tx, const std::shared_ptr<Nigel> daemon)
    {
        const auto [success, connectionError, error] = daemon->sendTransaction(tx);

        if (connectionError)
        {
            return {DAEMON_OFFLINE, Crypto::Hash()};
        }

        if (!success)
        {
            return {Error(DAEMON_ERROR, error), Crypto::Hash()};
        }

        return {SUCCESS, getTransactionHash(tx)};
    }

    std::vector<WalletTypes::TransactionDestination> setupDestinations(
        std::vector<std::pair<std::string, uint64_t>> addressesAndAmounts,
        const uint64_t changeRequired,
        const std::string changeAddress)
    {
        /* Need to send change back to our own address */
        if (changeRequired != 0)
        {
            addressesAndAmounts.push_back({changeAddress, changeRequired});
        }

        std::vector<WalletTypes::TransactionDestination> destinations;

        for (const auto [address, amount] : addressesAndAmounts)
        {
            const auto publicKey = Utilities::addressToPublicKey(address);

            /* Split transfer into denominations and create an output for each */
            for (const auto denomination : splitAmountIntoDenominations(amount))
            {
                WalletTypes::TransactionDestination destination;

                destination.amount = denomination;
                destination.receiverPublicKey = publicKey;

                destinations.push_back(destination);
            }
        }

        return destinations;
    }

    std::tuple<Error, std::vector<Pastella::RandomOuts>> getRingParticipants(
        const std::shared_ptr<Nigel> daemon,
        const std::vector<WalletTypes::TxInputAndOwner> sources)
    {
        (void)daemon;
        (void)sources;
        return {SUCCESS, {}};
    }

    /* Take our inputs and prepare them for the transparent system */
    std::tuple<Error, std::vector<WalletTypes::ObscuredInput>> prepareRingParticipants(
        std::vector<WalletTypes::TxInputAndOwner> sources,
        const std::shared_ptr<Nigel> daemon)
    {
        std::vector<WalletTypes::ObscuredInput> result;

        for (const auto walletAmount : sources)
        {
            WalletTypes::ObscuredInput obscuredInput;

            /* The real public key of the transaction */
            obscuredInput.realTransactionPublicKey = walletAmount.input.transactionPublicKey;

            /* The real index of the transaction output index */
            obscuredInput.realOutputTransactionIndex = walletAmount.input.transactionIndex;

            /* The amount of the transaction */
            obscuredInput.amount = walletAmount.input.amount;

            obscuredInput.ownerPublicKey = walletAmount.publicKey;

            obscuredInput.ownerPrivateKey = walletAmount.privateKey;
            obscuredInput.parentTransactionHash = walletAmount.input.parentTransactionHash;

            /* STEALTH ADDRESS REMOVAL: keyImage and privateEphemeral fields removed from ObscuredInput */

            /* Add the real output being spent - required for transaction validation */
            if (walletAmount.input.globalOutputIndex)
            {
                WalletTypes::GlobalIndexKey realOutput;

                realOutput.index = *walletAmount.input.globalOutputIndex;
                realOutput.key = walletAmount.input.key;

                obscuredInput.outputs.push_back(realOutput);

                /* Real output is always at index 0 in transparent system */
                obscuredInput.realOutput = 0;
            }
            else
            {
                std::cout << "[ERROR] prepareRingParticipants: Missing globalOutputIndex for input!" << std::endl;
            }

            result.push_back(obscuredInput);
        }

        return {SUCCESS, result};
    }
    std::tuple<Error, std::vector<Pastella::KeyInput>, std::vector<Crypto::SecretKey>> setupInputs(
        const std::vector<WalletTypes::ObscuredInput> inputsAndFakes)
    {
        std::vector<Pastella::KeyInput> inputs;

        std::vector<Crypto::SecretKey> tmpSecretKeys;

        int numPregenerated = 0;
        int numGeneratedOnDemand = 0;

        for (auto input : inputsAndFakes)
        {
            Pastella::KeyInput keyInput;

            keyInput.amount = input.amount;

            /* TRANSPARENT SYSTEM: Populate UTXO reference fields
             * Explicitly identify which previous transaction output is being spent */
            keyInput.transactionHash = input.parentTransactionHash;
            keyInput.outputIndex = static_cast<uint32_t>(input.realOutputTransactionIndex);

            /* TRANSPARENT SYSTEM: Store private key for signature generation
             * In transparent system, we directly sign with ownerPrivateKey
             * No key derivation needed like stealth addresses required */
            tmpSecretKeys.push_back(input.ownerPrivateKey);

            std::stringstream ss;
            ss << "Spending UTXO "
               << Common::podToHex(input.parentTransactionHash) << ":"
               << input.realOutputTransactionIndex
               << " (amount: " << input.amount << ")";

            Logger::logger.log(ss.str(), Logger::TRACE, {Logger::SYNC});

            numGeneratedOnDemand++;

            /* Add each output index from the outputs (transparent: no fake outs) */
            std::transform(
                input.outputs.begin(),
                input.outputs.end(),
                std::back_inserter(keyInput.outputIndexes),
                [](const auto output) { return static_cast<uint32_t>(output.index); });

            /* Make a copy */
            auto copy = keyInput.outputIndexes;

            if (!keyInput.outputIndexes.empty())
            {
                /* Convert our indexes to relative indexes - for example, if we
                   originally had [5, 10, 20, 21, 22], this would become
                   [5, 5, 10, 1, 1]. Due to this, the indexes MUST be sorted - they
                   are serialized as a uint32_t, so negative values will overflow! */
                for (size_t i = 1; i < copy.size(); i++)
                {
                    copy[i] = keyInput.outputIndexes[i] - keyInput.outputIndexes[i - 1];
                }

                keyInput.outputIndexes = copy;
            }

            /* Store the key input */
            inputs.push_back(keyInput);
        }

        Logger::logger.log(
            "Generated private ephemerals for " + std::to_string(numGeneratedOnDemand) + " inputs, "
            "used pre-generated ephemerals for " + std::to_string(numPregenerated) + " inputs.",
            Logger::DEBUG,
            { Logger::TRANSACTIONS }
        );

        return {SUCCESS, inputs, tmpSecretKeys};
    }

    std::tuple<std::vector<WalletTypes::KeyOutput>, Pastella::KeyPair>
        setupOutputs(std::vector<WalletTypes::TransactionDestination> destinations)
    {
        /* Don't sort destinations - we're transparent, not private */
        /* std::sort(destinations.begin(), destinations.end(), [](const auto &lhs, const auto &rhs) {
            return lhs.amount < rhs.amount;
        }); */

        /* Generate a random key pair for the transaction */
        Pastella::KeyPair randomTxKey;
        Crypto::generate_keys(randomTxKey.publicKey, randomTxKey.secretKey);

        /* Index of the output */
        uint32_t outputIndex = 0;

        std::vector<WalletTypes::KeyOutput> outputs;

        for (const auto destination : destinations)
        {
            /* TRANSPARENT SYSTEM: Direct output to recipient
             * No key derivation needed - simple and transparent!
             *
             * Each UTXO is identified by: (transactionHash, outputIndex) */

            WalletTypes::KeyOutput keyOutput;

            keyOutput.key = destination.receiverPublicKey;
            keyOutput.amount = destination.amount;

            std::stringstream ss;
            ss << "Output #" << outputIndex << ": "
               << destination.amount << " atomic units to DIRECT key: "
               << Common::podToHex(destination.receiverPublicKey);

            Logger::logger.log(ss.str(), Logger::TRACE, {Logger::SYNC});

            outputs.push_back(keyOutput);

            outputIndex++;
        }

        return {outputs, randomTxKey};
    }

    std::tuple<Error, Pastella::Transaction> generateRingSignatures(
        Pastella::Transaction tx,
        const std::vector<WalletTypes::ObscuredInput> inputsAndFakes,
        const std::vector<Crypto::SecretKey> tmpSecretKeys)
    {
        /* Signature generation for transparent system
         *
         * In a transparent Bitcoin-like system, each input must have a valid
         * Ed25519 signature proving ownership of the UTXO being spent.
         *
         * Unlike ring signatures, we use simple Ed25519 signatures:
         * - Each input has exactly ONE signature (not a ring)
         * - Signature proves knowledge of the private key for the output being spent
         * - Signature = Sign(transactionPrefixHash, outputPublicKey, privateKey)
         *
         * This ensures only the owner of a UTXO can spend it.
         *
         * See VULNERABILITY.md for full details. */

        /* Get the transaction prefix hash (everything except signatures) */
        Pastella::CachedTransaction cachedTx(tx);
        const Crypto::Hash prefixHash = cachedTx.getTransactionPrefixHash();

        Logger::logger.log(
            "Generating signatures for " + std::to_string(tx.inputs.size()) + " inputs",
            Logger::TRACE,
            {Logger::SYNC});

        Logger::logger.log(
            "Transaction prefix hash: " + Common::podToHex(prefixHash),
            Logger::TRACE,
            {Logger::SYNC});

        /* Clear any existing signatures */
        tx.signatures.clear();

        /* Resize signatures vector: one signature vector per input */
        tx.signatures.resize(tx.inputs.size());

        /* Generate ONE signature for each input */
        for (size_t inputIndex = 0; inputIndex < tx.inputs.size(); ++inputIndex)
        {
            /* All inputs should be KeyInput in transparent system */
            if (tx.inputs[inputIndex].type() != typeid(Pastella::KeyInput))
            {
                Logger::logger.log(
                    "ERROR: Input " + std::to_string(inputIndex) + " is not a KeyInput!",
                    Logger::FATAL,
                    {Logger::SYNC});

                return {UNKNOWN_ERROR, tx};
            }

            const Pastella::KeyInput &keyInput = boost::get<Pastella::KeyInput>(tx.inputs[inputIndex]);
            const WalletTypes::ObscuredInput &obscuredInput = inputsAndFakes[inputIndex];

            /* TRANSPARENT SYSTEM: Direct Ed25519 signature
             *
             * This is simpler and more transparent than CryptoNote's key derivation.
             *
             * The signature proves: "I know the private key for this UTXO"
             *
             * Verification will check: verify(prefixHash, publicKey, signature) == true */

            Crypto::PublicKey outputPublicKey = obscuredInput.ownerPublicKey;
            Crypto::SecretKey privateKey = obscuredInput.ownerPrivateKey;

            std::stringstream ss;
            ss << "Input #" << inputIndex << ": "
               << "amount=" << keyInput.amount << ", "
               << "publicKey=" << Common::podToHex(outputPublicKey).substr(0, 16) << "...";

            Logger::logger.log(ss.str(), Logger::TRACE, {Logger::SYNC});

            Logger::logger.log(
                "  Signing with public key: " + Common::podToHex(outputPublicKey).substr(0, 16) + "...",
                Logger::TRACE,
                {Logger::SYNC});

            /* Generate Ed25519 signature */
            Crypto::Signature signature;
            Crypto::generate_signature(prefixHash, outputPublicKey, privateKey, signature);

            Logger::logger.log(
                "  Generated signature: " + Common::podToHex(signature).substr(0, 16) + "...",
                Logger::TRACE,
                {Logger::SYNC});

            /* Add the ONE signature for this input */
            tx.signatures[inputIndex].push_back(signature);

            Logger::logger.log(
                "  ✓ Signature added for input #" + std::to_string(inputIndex),
                Logger::TRACE,
                {Logger::SYNC});
        }

        Logger::logger.log("All signatures generated successfully!", Logger::TRACE, {Logger::SYNC});
        Logger::logger.log("Total signatures: " + std::to_string(tx.signatures.size()), Logger::TRACE, {Logger::SYNC});

        /* Suppress unused parameter warning (tmpSecretKeys not needed in transparent system) */
        (void)tmpSecretKeys;

        return {SUCCESS, tx};
    }

    /* BITCOIN-LIKE TRANSACTIONS: No denomination splitting
     *
     * In Bitcoin-like systems, we don't split amounts into denominations.
     * Each transaction output is exactly the amount we want to send.
     * Simple: 1 output for recipient, 1 output for change (if needed).
     *
     * Previously: 1234567 = 1000000 + 200000 + 30000 + 4000 + 500 + 60 + 7
     * Now: 1234567 = 1234567 (just the amount) */
    std::vector<uint64_t> splitAmountIntoDenominations(uint64_t amount, bool preventTooLargeOutputs)
    {
        std::vector<uint64_t> splitAmounts;

        /* Return the amount as-is, no splitting
         * This is how Bitcoin works - simple and clean */
        splitAmounts.push_back(amount);

        return splitAmounts;
    }

    std::vector<Pastella::TransactionInput>
        keyInputToTransactionInput(const std::vector<Pastella::KeyInput> keyInputs)
    {
        std::vector<Pastella::TransactionInput> result;

        for (const auto input : keyInputs)
        {
            result.push_back(input);
        }

        return result;
    }

    std::vector<Pastella::TransactionOutput>
        keyOutputToTransactionOutput(const std::vector<WalletTypes::KeyOutput> keyOutputs)
    {
        std::vector<Pastella::TransactionOutput> result;

        for (const auto output : keyOutputs)
        {
            Pastella::TransactionOutput tmpOutput;

            tmpOutput.amount = output.amount;

            Pastella::KeyOutput tmpKey;

            tmpKey.key = output.key;

            tmpOutput.target = tmpKey;

            result.push_back(tmpOutput);
        }

        return result;
    }

    WalletTypes::TransactionResult makeTransaction(
        const std::shared_ptr<Nigel> daemon,
        const std::vector<WalletTypes::TxInputAndOwner> ourInputs,
        const std::vector<WalletTypes::TransactionDestination> destinations,
        const std::shared_ptr<SubWallets> subWallets,
        const uint64_t unlockTime,
        const std::vector<uint8_t> extraData)
    {
        /* Prepare our inputs for the transaction */
        const auto [prepareError, inputsAndFakes] = prepareRingParticipants(ourInputs, daemon);

        WalletTypes::TransactionResult result;

        if (prepareError)
        {
            result.error = prepareError;
            return result;
        }

        /* Setup the transaction inputs */
        const auto [inputError, transactionInputs, tmpSecretKeys] =
            setupInputs(inputsAndFakes);

        if (inputError)
        {
            result.error = inputError;
            return result;
        }

        /* Setup the transaction outputs */
        std::tie(result.outputs, result.txKeyPair) = setupOutputs(destinations);

        /* Initialize extra vector and handle staking/messaging data first */
        std::vector<uint8_t> extra;

        if (!extraData.empty())
        {
            /* Append staking/messaging data directly to extra (not wrapped in nonce) */
            std::copy(extraData.begin(), extraData.end(), std::back_inserter(extra));
        }

        std::vector<uint8_t> extraNonce;

        if (!extraNonce.empty())
        {
            /* Indicate this is the extra nonce */
            extra.push_back(Constants::TX_EXTRA_NONCE_IDENTIFIER);

            /* Determine the length of the nonce data and varint encode it */
            std::vector<uint8_t> extraNonceSize = Tools::uintToVarintVector(extraNonce.size());

            /* Write the extra nonce length to extra */
            std::copy(extraNonceSize.begin(), extraNonceSize.end(), std::back_inserter(extra));

            /* Write the data to extra */
            std::copy(extraNonce.begin(), extraNonce.end(), std::back_inserter(extra));
        }

        /* Add the pub key identifier to extra */
        extra.push_back(Constants::TX_EXTRA_PUBKEY_IDENTIFIER);

        const auto pubKey = result.txKeyPair.publicKey;

        /* Append the pub key to extra */
        std::copy(std::begin(pubKey.data), std::end(pubKey.data), std::back_inserter(extra));

        Pastella::Transaction setupTX;

        setupTX.version = Pastella::CURRENT_TRANSACTION_VERSION;

        setupTX.unlockTime = unlockTime;

        /* Convert from key inputs to the boost uglyness */
        setupTX.inputs = keyInputToTransactionInput(transactionInputs);

        /* We can't really remove boost from here yet and simplify our data types
           since we take a hash of the transaction prefix. Once we've got this
           working, maybe we can work some magic. TODO */
        setupTX.outputs = keyOutputToTransactionOutput(result.outputs);

        if (setupTX.outputs.size() > Pastella::parameters::NORMAL_TX_MAX_OUTPUT_COUNT_V1)
        {
            result.error = OUTPUT_DECOMPOSITION;
            return result;
        }

        setupTX.extra = extra;

        /* Fill in the transaction signatures */
        /* NOTE: Do not modify the transaction after this, or the ring signatures
           will be invalidated */
        std::tie(result.error, result.transaction) = generateRingSignatures(setupTX, inputsAndFakes, tmpSecretKeys);

        return result;
    }

    bool verifyAmounts(const Pastella::Transaction tx)
    {
        std::vector<uint64_t> amounts;

        /* Note - not verifying inputs as it's possible to have received inputs
           from another wallet which don't enforce this rule */
        for (const auto output : tx.outputs)
        {
            amounts.push_back(output.amount);
        }

        return verifyAmounts(amounts);
    }

    /* BITCOIN-LIKE TRANSACTIONS: No denomination checks
     *
     * In Bitcoin-like systems, any amount is valid.
     * We don't need "pretty" denomination amounts anymore.
     * This function now always returns true to allow any output amount. */
    bool verifyAmounts(const std::vector<uint64_t> amounts)
    {
        /* All amounts are valid in Bitcoin-like transparent system */
        return true;
    }

    uint64_t sumTransactionFee(const Pastella::Transaction tx)
    {
        uint64_t inputTotal = 0;
        uint64_t outputTotal = 0;

        for (const auto input : tx.inputs)
        {
            inputTotal += boost::get<Pastella::KeyInput>(input).amount;
        }

        for (const auto output : tx.outputs)
        {
            outputTotal += output.amount;
        }

        return inputTotal - outputTotal;
    }

    bool verifyTransactionFee(
        const WalletTypes::FeeType expectedFee,
        const uint64_t actualFee,
        const uint64_t height,
        const Pastella::Transaction tx)
    {
        if (expectedFee.isFixedFee)
        {
            return expectedFee.fixedFee == actualFee;
        }
        else
        {
            const double feePerByte = expectedFee.isFeePerByte
                ? expectedFee.feePerByte
                : Pastella::parameters::MINIMUM_FEE_PER_BYTE_V1;

            const size_t txSize = toBinaryArray(tx).size();

            size_t calculatedFee = static_cast<uint64_t>(feePerByte * txSize);
            // pre-fork we still need assure the previous minimum fee
            if (height < Pastella::parameters::MINIMUM_FEE_PER_BYTE_V1_HEIGHT && calculatedFee < Pastella::parameters::MINIMUM_FEE) {
                calculatedFee = Pastella::parameters::MINIMUM_FEE;
            }

            /* Ensure fee is greater or equal to the fee per byte specified,
             * and no more than two times the fee per byte specified. */
            return actualFee >= calculatedFee && actualFee <= calculatedFee * 2;
        }
    }

  /* Staking transaction creation functions */
    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo, std::string> sendStakingTransaction(
        const uint64_t amount,
        const uint32_t lockDurationDays,
        const std::string address,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const bool sendTransaction)
    {
        /* Get current height */
        const uint64_t currentHeight = daemon->networkBlockCount();
        if (currentHeight == 0)
        {
            return std::make_tuple(DAEMON_OFFLINE, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
        }

        /* Check if staking is allowed at this height */
        if (currentHeight < Pastella::parameters::staking::STAKING_ENABLE_HEIGHT)
        {
            return std::make_tuple(STAKING_NOT_ENABLED, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
        }

        /* Step 1: Check if we have precise staking outputs available */
        if (!hasPreciseStakingOutputs(amount, subWallets))
        {
            /* Step 2: Create precise outputs by sending transaction to self */
            const auto [error, preparationTxs] = prepareStakingOutputs(amount, address, daemon, subWallets);
            if (error)
            {
                return std::make_tuple(error, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
            }

            if (!preparationTxs.empty())
            {
                /* Step 3: Monitor for outputs to become available */
                const auto [monitorError, outputsAvailable] = waitForStakingOutputs(amount, subWallets, daemon, 300); // 5 minutes

                if (monitorError)
                {
                    return std::make_tuple(monitorError, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
                }

                if (!outputsAvailable)
                {
                    /* Timeout occurred - return to normal menu */
                    return std::make_tuple(SUCCESS, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
                }
            }
        }

        /* Step 3: Create one-time reward address for staking rewards */
        const auto [rewardError, rewardAddress, rewardKey, rewardIndex] = subWallets->addSubWallet();
        if (rewardError)
        {
            return std::make_tuple(rewardError, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
        }

        /* Step 4: Create actual staking transaction with proper unlock time */
        const uint64_t unlockTime = Pastella::calculateUnlockTime(lockDurationDays, currentHeight);

        /* Get the required denominations for this amount */
        const std::vector<uint64_t> requiredDenominations = getStakingDenominations(amount);

        /* Create staking extra data */
        /* TRANSPARENT SYSTEM: rewardAddress removed from staking extra - staker's address is tracked in StakingEntry */
        Pastella::TransactionExtraStaking stakingExtra;
        stakingExtra.stakingType = Pastella::parameters::staking::STAKING_TX_TYPE;
        stakingExtra.amount = amount;
        stakingExtra.unlockTime = unlockTime;
        stakingExtra.lockDurationDays = lockDurationDays;

        /* Convert to extra data */
        std::vector<uint8_t> extraData;
        if (!Pastella::addStakingDataToExtra(extraData, stakingExtra))
        {
            return std::make_tuple(FAILED_TO_CREATE_TX_EXTRA, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
        }

        /* Manually select inputs for staking transaction */

        /* Get all available unlocked inputs */
        const auto unlockedInputs = subWallets->getSpendableTransactionInputs(
            true, /* takeFromAll */
            {}, /* all subwallets */
            currentHeight /* Use actual blockchain height, NOT max()! */
        );

        /* We need to select inputs that sum to at least: amount + fee */
        const uint64_t fee = Pastella::parameters::MINIMUM_FEE;
        const uint64_t requiredAmount = amount + fee;

        /* For staking, we need exactly TWO inputs:
         * 1. One input for the exact staking amount
         * 2. One input for the fee (1000)
         *
         * This is much simpler than the old denomination system */
        std::vector<WalletTypes::TxInputAndOwner> stakingInputs;
        uint64_t totalInput = 0;

        /* Find input for the staking amount */
        bool foundAmountInput = false;
        for (const auto &input : unlockedInputs)
        {
            if (input.input.amount == amount)
            {
                stakingInputs.push_back(input);
                totalInput += amount;
                foundAmountInput = true;
                break;
            }
        }

        if (!foundAmountInput)
        {
            return std::make_tuple(NOT_ENOUGH_BALANCE, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
        }

        /* Find input for the fee */
        bool foundFeeInput = false;
        for (const auto &input : unlockedInputs)
        {
            /* Don't use the same input twice - check both transaction public key AND transaction index
             * In transparent system, we can use multiple outputs from the same transaction */
            if (input.input.amount == fee &&
                (input.input.transactionPublicKey != stakingInputs[0].input.transactionPublicKey ||
                 input.input.transactionIndex != stakingInputs[0].input.transactionIndex))
            {
                stakingInputs.push_back(input);
                totalInput += fee;
                foundFeeInput = true;
                break;
            }
        }

        if (!foundFeeInput)
        {
            return std::make_tuple(NOT_ENOUGH_BALANCE, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
        }

        /* Verify we have enough */
        if (totalInput < requiredAmount)
        {
            return std::make_tuple(NOT_ENOUGH_BALANCE, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
        }

        /* Calculate change amount (should be zero with this new design) */
        uint64_t changeAmount = totalInput - amount - fee;

        /* Setup destinations with staking output and optional change output */
        std::vector<std::pair<std::string, uint64_t>> destinations;
        destinations.push_back({address, amount});  /* Staking output - will be locked */

        /* Only add change output if there's actual change (shouldn't happen with new design) */
        if (changeAmount > 0)
        {
            destinations.push_back({address, changeAmount});  /* Change output - spendable now */
        }

        /* Setup the transaction destinations */
        const auto finalizedDestinations = setupDestinations(
            destinations,
            0, /* setupDestinations will handle change calculation */
            address
        );

        /* CRITICAL: Generate cryptographic signature proving ownership of staked funds
         *
         * This MUST be done here after inputs are selected so we can access private keys,
         * but BEFORE the transaction is created so the signature is included in extraData */
        std::vector<uint8_t> message;
        message.reserve(sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint64_t));

        /* Add amount */
        const uint8_t* amountBytes = reinterpret_cast<const uint8_t*>(&stakingExtra.amount);
        message.insert(message.end(), amountBytes, amountBytes + sizeof(uint64_t));

        /* Add lockDurationDays */
        const uint8_t* lockBytes = reinterpret_cast<const uint8_t*>(&stakingExtra.lockDurationDays);
        message.insert(message.end(), lockBytes, lockBytes + sizeof(uint32_t));

        /* Add unlockTime */
        const uint8_t* unlockBytes = reinterpret_cast<const uint8_t*>(&stakingExtra.unlockTime);
        message.insert(message.end(), unlockBytes, unlockBytes + sizeof(uint64_t));

        /* Hash the message */
        Crypto::Hash messageHash;
        Crypto::cn_fast_hash(message.data(), message.size(), messageHash);

        /* Get private key from one of the staking inputs and sign */
        Crypto::Signature stakingSignature;
        bool signatureGenerated = false;

        for (const auto &input : stakingInputs)
        {
            /* TxInputAndOwner has privateKey directly available */
            if (input.privateKey.data[0] != 0) /* Check if key is not all zeros */
            {
                /* Sign the message with the input's private key and public key */
                Crypto::generate_signature(messageHash, input.publicKey, input.privateKey, stakingSignature);
                signatureGenerated = true;
                break;
            }
        }

        if (!signatureGenerated)
        {
            return std::make_tuple(FAILED_TO_CREATE_TX_EXTRA, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
        }

        /* Update the staking extra with the signature */
        stakingExtra.signature = stakingSignature;

        /* Re-convert to extra data with signature included */
        extraData.clear();
        if (!Pastella::addStakingDataToExtra(extraData, stakingExtra))
        {
            return std::make_tuple(FAILED_TO_CREATE_TX_EXTRA, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{}, std::string{});
        }

        /* Create the transaction using the makeTransaction function directly */
        const auto result = makeTransaction(
            daemon,
            stakingInputs, /* Use our manually selected inputs + fee input */
            finalizedDestinations,
            subWallets,
            unlockTime,
            extraData
        );

        if (result.error)
        {
            WalletTypes::PreparedTransactionInfo errorTx;
            return std::make_tuple(result.error, Crypto::Hash(), errorTx, std::string{});
        }

        const auto txHash = getTransactionHash(result.transaction);

        /* Create proper PreparedTransactionInfo return structure */
        WalletTypes::PreparedTransactionInfo preparedTx;
        preparedTx.fee = Pastella::parameters::MINIMUM_FEE;
        preparedTx.inputs = stakingInputs;
        preparedTx.changeAddress = address;
        preparedTx.changeRequired = 0; /* No change since using exact inputs */
        preparedTx.tx = result;
        preparedTx.transactionHash = txHash;

        if (sendTransaction)
        {
            /* Relay the transaction to the network */
            const auto [relayError, relayResult] = relayTransaction(result.transaction, daemon);
            if (relayError)
            {
                return std::make_tuple(relayError, Crypto::Hash(), preparedTx, std::string{});
            }

            /* Store the transaction in wallet */
            storeSentTransaction(
                txHash,
                Pastella::parameters::MINIMUM_FEE,
                stakingInputs,
                address, /* Change address */
                0, /* No change */
                subWallets
            );

            /* Convert TransactionOutput to KeyOutput for storeUnconfirmedIncomingInputs */
            std::vector<WalletTypes::KeyOutput> keyOutputs;
            for (const auto& txOutput : result.transaction.outputs)
            {
                WalletTypes::KeyOutput keyOutput;
                keyOutput.amount = txOutput.amount;
                // Extract KeyOutput from the variant
                const auto& keyOutputTarget = boost::get<Pastella::KeyOutput>(txOutput.target);
                keyOutput.key = keyOutputTarget.key;
                keyOutputs.push_back(keyOutput);
            }

            /* Update locked balance with the incoming staked funds */
            storeUnconfirmedIncomingInputs(
                subWallets,
                keyOutputs,
                result.txKeyPair.publicKey,
                txHash
            );
        }

        return std::make_tuple(SUCCESS, txHash, preparedTx, rewardAddress);
    }

    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendGovernanceProposalTransaction(
        const std::string title,
        const std::string description,
        const uint8_t proposalType,
        const uint64_t amount,
        const std::string recipientAddress,
        const uint64_t proposalId,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const bool sendTransaction)
    {
        /* Get current height */
        const uint64_t currentHeight = daemon->networkBlockCount();
        if (currentHeight == 0)
        {
            return std::make_tuple(DAEMON_OFFLINE, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{});
        }

        /* Check if governance is enabled at this height */
        if (currentHeight < Pastella::parameters::governance::GOVERNANCE_ENABLE_HEIGHT)
        {
            return std::make_tuple(GOVERNANCE_NOT_ENABLED, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{});
        }

        /* Create signature for proposal */
        /* Sign: hash(title + description + proposalType + amount + recipientAddress + proposalId) */
        std::vector<uint8_t> proposalData;
        proposalData.insert(proposalData.end(), title.begin(), title.end());
        proposalData.insert(proposalData.end(), description.begin(), description.end());
        proposalData.push_back(proposalType);

        /* Add amount to data */
        const uint8_t *amountBytes = reinterpret_cast<const uint8_t*>(&amount);
        proposalData.insert(proposalData.end(), amountBytes, amountBytes + sizeof(amount));

        /* Add recipient address */
        proposalData.insert(proposalData.end(), recipientAddress.begin(), recipientAddress.end());

        /* Add proposal ID */
        const uint8_t *proposalIdBytes = reinterpret_cast<const uint8_t*>(&proposalId);
        proposalData.insert(proposalData.end(), proposalIdBytes, proposalIdBytes + sizeof(proposalId));

        /* Hash the proposal data */
        Crypto::Hash proposalHash = Crypto::cn_fast_hash(proposalData.data(), proposalData.size());

        /* Get wallet primary address and keys for signing */
        const auto primaryAddress = subWallets->getPrimaryAddress();
        Crypto::PublicKey publicKey;
        Crypto::SecretKey privateKey;

        /* Get the primary key for signing */
        privateKey = subWallets->getPrimaryKey();

        /* Derive public key from private key */
        if (!Crypto::secret_key_to_public_key(privateKey, publicKey))
        {
            return std::make_tuple(INVALID_PRIVATE_KEY, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{});
        }

        /* Create signature */
        Crypto::Signature proposalSignature;
        Crypto::generate_signature(proposalHash, publicKey, privateKey, proposalSignature);

        /* Create governance extra data */
        Pastella::TransactionExtraGovernanceProposal proposalExtra;
        proposalExtra.proposalId = proposalId;
        proposalExtra.title = title;
        proposalExtra.description = description;
        proposalExtra.proposalType = proposalType;
        proposalExtra.amount = amount;
        proposalExtra.recipientAddress = recipientAddress;
        proposalExtra.signature = proposalSignature;

        /* Convert to extra data */
        std::vector<uint8_t> extraData;
        if (!Pastella::createGovernanceProposalExtra(
            proposalId,
            title,
            description,
            proposalType,
            amount,
            recipientAddress,
            proposalSignature,
            extraData))
        {
            return std::make_tuple(FAILED_TO_CREATE_TX_EXTRA, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{});
        }

        /* For governance proposals, we need a minimal fee input */
        const uint64_t fee = Pastella::parameters::MINIMUM_FEE;

        /* Get unlocked inputs for fee */
        const auto unlockedInputs = subWallets->getSpendableTransactionInputs(
            true, /* takeFromAll */
            {}, /* all subwallets */
            currentHeight
        );

        /* Find input for the fee */
        std::vector<WalletTypes::TxInputAndOwner> governanceInputs;
        for (const auto &input : unlockedInputs)
        {
            if (input.input.amount >= fee)
            {
                governanceInputs.push_back(input);
                break;
            }
        }

        if (governanceInputs.empty())
        {
            return std::make_tuple(NOT_ENOUGH_BALANCE, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{});
        }

        /* No outputs needed for proposal transaction - it's data-only */
        std::vector<WalletTypes::TransactionDestination> destinations;

        /* Create the transaction */
        const auto result = makeTransaction(
            daemon,
            governanceInputs,
            destinations,
            subWallets,
            0, /* unlockTime */
            extraData
        );

        if (result.error)
        {
            WalletTypes::PreparedTransactionInfo errorTx;
            return std::make_tuple(result.error, Crypto::Hash(), errorTx);
        }

        const auto txHash = getTransactionHash(result.transaction);

        /* Create PreparedTransactionInfo */
        WalletTypes::PreparedTransactionInfo preparedTx;
        preparedTx.fee = fee;
        preparedTx.inputs = governanceInputs;
        preparedTx.changeAddress = primaryAddress;
        preparedTx.changeRequired = 0;
        preparedTx.tx = result;
        preparedTx.transactionHash = txHash;

        if (sendTransaction)
        {
            /* Relay the transaction to the network */
            const auto [relayError, relayResult] = relayTransaction(result.transaction, daemon);
            if (relayError)
            {
                return std::make_tuple(relayError, Crypto::Hash(), preparedTx);
            }

            /* Store the transaction in wallet */
            storeSentTransaction(
                txHash,
                fee,
                governanceInputs,
                primaryAddress,
                0,
                subWallets
            );
        }

        return std::make_tuple(SUCCESS, txHash, preparedTx);
    }

    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendGovernanceVoteTransaction(
        const uint64_t proposalId,
        const uint8_t vote,
        const uint64_t stakeWeight,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const bool sendTransaction)
    {
        /* Get current height */
        const uint64_t currentHeight = daemon->networkBlockCount();
        if (currentHeight == 0)
        {
            return std::make_tuple(DAEMON_OFFLINE, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{});
        }

        /* Check if governance is enabled */
        if (currentHeight < Pastella::parameters::governance::GOVERNANCE_ENABLE_HEIGHT)
        {
            return std::make_tuple(GOVERNANCE_NOT_ENABLED, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{});
        }

        /* Create governance vote extra data */
        Pastella::TransactionExtraGovernanceVote voteExtra;
        voteExtra.proposalId = proposalId;
        voteExtra.vote = vote;
        voteExtra.stakeWeight = stakeWeight;

        /* Convert to extra data */
        std::vector<uint8_t> extraData;
        if (!Pastella::createGovernanceVoteExtra(
            proposalId,
            vote,
            stakeWeight,
            extraData))
        {
            return std::make_tuple(FAILED_TO_CREATE_TX_EXTRA, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{});
        }

        /* For governance votes, we need a minimal fee input */
        const uint64_t fee = Pastella::parameters::MINIMUM_FEE;

        /* Get unlocked inputs for fee */
        const auto unlockedInputs = subWallets->getSpendableTransactionInputs(
            true, /* takeFromAll */
            {}, /* all subwallets */
            currentHeight
        );

        /* Find input for the fee */
        std::vector<WalletTypes::TxInputAndOwner> voteInputs;
        for (const auto &input : unlockedInputs)
        {
            if (input.input.amount >= fee)
            {
                voteInputs.push_back(input);
                break;
            }
        }

        if (voteInputs.empty())
        {
            return std::make_tuple(NOT_ENOUGH_BALANCE, Crypto::Hash(), WalletTypes::PreparedTransactionInfo{});
        }

        /* No outputs needed for vote transaction - it's data-only */
        std::vector<WalletTypes::TransactionDestination> destinations;

        /* Create the transaction */
        const auto result = makeTransaction(
            daemon,
            voteInputs,
            destinations,
            subWallets,
            0, /* unlockTime */
            extraData
        );

        if (result.error)
        {
            WalletTypes::PreparedTransactionInfo errorTx;
            return std::make_tuple(result.error, Crypto::Hash(), errorTx);
        }

        const auto txHash = getTransactionHash(result.transaction);

        /* Create PreparedTransactionInfo */
        WalletTypes::PreparedTransactionInfo preparedTx;
        preparedTx.fee = fee;
        preparedTx.inputs = voteInputs;
        preparedTx.changeAddress = subWallets->getPrimaryAddress();
        preparedTx.changeRequired = 0;
        preparedTx.tx = result;
        preparedTx.transactionHash = txHash;

        if (sendTransaction)
        {
            /* Relay the transaction to the network */
            const auto [relayError, relayResult] = relayTransaction(result.transaction, daemon);
            if (relayError)
            {
                return std::make_tuple(relayError, Crypto::Hash(), preparedTx);
            }

            /* Store the transaction in wallet */
            storeSentTransaction(
                txHash,
                fee,
                voteInputs,
                subWallets->getPrimaryAddress(),
                0,
                subWallets
            );
        }

        return std::make_tuple(SUCCESS, txHash, preparedTx);
    }


    /* Helper functions for precise output staking */
    std::vector<uint64_t> getStakingDenominations(const uint64_t amount)
    {
        /* For staking transactions, we want a SINGLE output, not multiple denominations
         *
         * Staking transactions should create exactly one output for the staked amount
         * This ensures the staking system can properly track and lock the staked funds */
        return {amount};
    }

    bool hasPreciseStakingOutputs(
        const uint64_t amount,
        const std::shared_ptr<SubWallets> subWallets)
    {
        /* For staking, we need an input of the exact amount (no denominations)
         *
         * This is simpler than the old denomination-based system - we just need
         * to find one input that matches the exact staking amount */
        const auto unlockedInputs = subWallets->getSpendableTransactionInputs(
            true, /* takeFromAll */
            {}, /* all subwallets */
            std::numeric_limits<uint64_t>::max() /* current height */
        );

        /* Check if we have an input of the exact amount */
        for (const auto &input : unlockedInputs)
        {
            if (input.input.amount == amount)
            {
                return true;
            }
        }

        return false;
    }

    std::tuple<Error, std::vector<Crypto::Hash>> prepareStakingOutputs(
        const uint64_t amount,
        const std::string address,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets)
    {
        std::vector<Crypto::Hash> preparationTxs;

        try
        {
            /* Get the required denominations */
            const std::vector<uint64_t> denominations = getStakingDenominations(amount);

            /* Create a self-transaction to generate the precise outputs */
            std::vector<std::pair<std::string, uint64_t>> destinations;
            for (uint64_t denom : denominations)
            {
                destinations.push_back({address, denom});
            }

            /* Add an extra output for the minimum fee so staking denominations remain intact */
            destinations.push_back({address, Pastella::parameters::MINIMUM_FEE});

            /* Send transaction to self with immediate unlock */
            const auto [error, hash, txInfo] = sendTransactionAdvanced(
                destinations,
                WalletTypes::FeeType::FixedFee(Pastella::parameters::MINIMUM_FEE),
                {address}, // Take from this address
                address, // Change back to same address
                daemon,
                subWallets,
                0, // Immediate unlock
                {}, // No extra data
                false, // Not sendAll
                true // Send transaction
            );

            if (error)
            {
                return std::make_tuple(error, preparationTxs);
            }

            preparationTxs.push_back(hash);
            return std::make_tuple(SUCCESS, preparationTxs);
        }
        catch (const std::exception &e)
        {
            return std::make_tuple(FAILED_TO_CREATE_TX_EXTRA, preparationTxs);
        }
    }

    std::tuple<Error, bool> waitForStakingOutputs(
        const uint64_t amount,
        const std::shared_ptr<SubWallets> subWallets,
        const std::shared_ptr<Nigel> daemon,
        const int timeoutSeconds)
    {
        using namespace std::chrono;

        const auto startTime = steady_clock::now();
        const auto timeout = seconds(timeoutSeconds);

        std::cout << "\n" << std::endl;
        std::cout << "Waiting for precise staking outputs to become available..." << std::endl;
        std::cout << "Required amount: " << Utilities::formatAmount(amount) << " " << WalletConfig::ticker << std::endl;
        std::cout << "Timeout: " << timeoutSeconds << " seconds" << std::endl;
        std::cout << std::endl;

        while (true)
        {
            // Check if we have the required outputs
            if (hasPreciseStakingOutputs(amount, subWallets))
            {
                std::cout << "✓ Required staking outputs are now available!" << std::endl;
                std::cout << "Continuing with staking transaction..." << std::endl;
                return std::make_tuple(SUCCESS, true);
            }

            // Check timeout
            const auto elapsedTime = steady_clock::now() - startTime;
            if (elapsedTime >= timeout)
            {
                std::cout << "\n" << std::endl;
                std::cout << "✗ Timeout: Required staking outputs did not become available within "
                         << timeoutSeconds << " seconds." << std::endl;
                std::cout << "Please try again later or create the outputs manually." << std::endl;
                return std::make_tuple(SUCCESS, false);
            }

            // Show progress
            const auto remainingTime = duration_cast<seconds>(timeout - elapsedTime);
            std::cout << "\rChecking for outputs... "
                     << "Time remaining: " << remainingTime.count() << "s ";
            std::cout.flush();

            // Wait before next check (check every 5 seconds)
            std::this_thread::sleep_for(seconds(5));
        }
    }

} // namespace SendTransaction
