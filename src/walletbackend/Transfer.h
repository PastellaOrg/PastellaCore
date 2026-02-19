// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <Pastella.h>
#include <WalletTypes.h>
#include <errors/Errors.h>
#include <nigel/Nigel.h>
#include <serialization/SerializationTools.h>
#include <subwallets/SubWallets.h>
#include <vector>

namespace SendTransaction
{
    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendTransactionBasic(
        std::string destination,
        const uint64_t amount,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const bool sendAll = false,
        const bool sendTransaction = true);

    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendTransactionAdvanced(
        std::vector<std::pair<std::string, uint64_t>> addressesAndAmounts,
        const WalletTypes::FeeType fee,
        const std::vector<std::string> addressesToTakeFrom,
        std::string changeAddress,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const uint64_t unlockTime,
        const std::vector<uint8_t> extraData,
        const bool sendAll = false,
        const bool sendTransaction = true);

    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo, std::string> sendStakingTransaction(
        const uint64_t amount,
        const uint32_t lockDurationDays,
        const std::string address,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const bool sendTransaction = true);

    std::tuple<Error, std::vector<Crypto::Hash>> prepareStakingOutputs(
        const uint64_t amount,
        const std::string address,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets);

    bool hasPreciseStakingOutputs(
        const uint64_t amount,
        const std::shared_ptr<SubWallets> subWallets);

    std::vector<uint64_t> getStakingDenominations(const uint64_t amount);

    std::tuple<Error, bool> waitForStakingOutputs(
        const uint64_t amount,
        const std::shared_ptr<SubWallets> subWallets,
        const std::shared_ptr<Nigel> daemon,
        const int timeoutSeconds = 300);

    
    
    std::tuple<Error, Crypto::Hash> sendPreparedTransaction(
        const WalletTypes::PreparedTransactionInfo txInfo,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets);

    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendGovernanceProposalTransaction(
        const std::string title,
        const std::string description,
        const uint8_t proposalType,
        const uint64_t amount,
        const std::string recipientAddress,
        const uint64_t proposalId,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const bool sendTransaction = true);

    std::tuple<Error, Crypto::Hash, WalletTypes::PreparedTransactionInfo> sendGovernanceVoteTransaction(
        const uint64_t proposalId,
        const uint8_t vote,
        const uint64_t stakeWeight,
        const std::shared_ptr<Nigel> daemon,
        const std::shared_ptr<SubWallets> subWallets,
        const bool sendTransaction = true);

    std::vector<WalletTypes::TransactionDestination> setupDestinations(
        std::vector<std::pair<std::string, uint64_t>> addressesAndAmounts,
        const uint64_t changeRequired,
        const std::string changeAddress);

    std::tuple<Error, std::vector<WalletTypes::ObscuredInput>> prepareRingParticipants(
        std::vector<WalletTypes::TxInputAndOwner> sources,
        const std::shared_ptr<Nigel> daemon);
    std::tuple<Error, std::vector<Pastella::KeyInput>, std::vector<Crypto::SecretKey>> setupInputs(
        const std::vector<WalletTypes::ObscuredInput> inputsAndFakes);

    std::tuple<std::vector<WalletTypes::KeyOutput>, Pastella::KeyPair>
        setupOutputs(std::vector<WalletTypes::TransactionDestination> destinations);

    std::tuple<Error, Pastella::Transaction> generateRingSignatures(
        Pastella::Transaction tx,
        const std::vector<WalletTypes::ObscuredInput> inputsAndFakes,
        const std::vector<Crypto::SecretKey> tmpSecretKeys);

    std::vector<uint64_t> splitAmountIntoDenominations(
        const uint64_t amount,
        const bool preventTooLargeOutputs = true);

    std::vector<Pastella::TransactionInput>
        keyInputToTransactionInput(const std::vector<Pastella::KeyInput> keyInputs);

    std::vector<Pastella::TransactionOutput>
        keyOutputToTransactionOutput(const std::vector<WalletTypes::KeyOutput> keyOutputs);

    std::tuple<Error, std::vector<Pastella::RandomOuts>> getRingParticipants(
        const std::shared_ptr<Nigel> daemon,
        const std::vector<WalletTypes::TxInputAndOwner> sources);

    WalletTypes::TransactionResult makeTransaction(
        const std::shared_ptr<Nigel> daemon,
        const std::vector<WalletTypes::TxInputAndOwner> ourInputs,
        const std::vector<WalletTypes::TransactionDestination> destinations,
        const std::shared_ptr<SubWallets> subWallets,
        const uint64_t unlockTime,
        const std::vector<uint8_t> extraData);

    std::tuple<Error, Crypto::Hash>
        relayTransaction(const Pastella::Transaction tx, const std::shared_ptr<Nigel> daemon);

    void storeSentTransaction(
        const Crypto::Hash hash,
        const uint64_t fee,
        const std::vector<WalletTypes::TxInputAndOwner> ourInputs,
        const std::string changeAddress,
        const uint64_t changeRequired,
        const std::shared_ptr<SubWallets> subWallets);

    std::tuple<bool, WalletTypes::TransactionResult, uint64_t, uint64_t> tryMakeFeePerByteTransaction(
        const uint64_t sumOfInputs,
        uint64_t totalAmount,
        uint64_t estimatedAmount,
        const double feePerByte,
        std::vector<std::pair<std::string, uint64_t>> addressesAndAmounts,
        const std::string changeAddress,
        const std::shared_ptr<Nigel> daemon,
        const std::vector<WalletTypes::TxInputAndOwner> ourInputs,
        const std::shared_ptr<SubWallets> subWallets,
        const uint64_t unlockTime,
        const std::vector<uint8_t> extraData,
        const bool sendAll);

    Error isTransactionPayloadTooBig(const Pastella::Transaction tx, const uint64_t currentHeight);

    void storeUnconfirmedIncomingInputs(
        const std::shared_ptr<SubWallets> subWallets,
        const std::vector<WalletTypes::KeyOutput> keyOutputs,
        const Crypto::PublicKey txPublicKey,
        const Crypto::Hash txHash);

    /* Verify all amounts in the transaction given are PRETTY_AMOUNTS */
    bool verifyAmounts(const Pastella::Transaction tx);

    /* Verify all amounts given are PRETTY_AMOUNTS */
    bool verifyAmounts(const std::vector<uint64_t> amounts);

    /* Compute the fee of the transaction */
    uint64_t sumTransactionFee(const Pastella::Transaction tx);

    /* Verify fee is as expected (or expected range, in the case of fee per byte) */
    bool verifyTransactionFee(
        const WalletTypes::FeeType expectedFee,
        const uint64_t actualFee,
        const uint64_t height,
        const Pastella::Transaction tx);

    /* Template so we can do transaction, and transactionprefix */
    template<typename T> Crypto::Hash getTransactionHash(T tx)
    {
        std::vector<uint8_t> data = toBinaryArray(tx);
        return Crypto::cn_fast_hash(data.data(), data.size());
    }
} // namespace SendTransaction
