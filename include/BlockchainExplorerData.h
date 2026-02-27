// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include "Pastella.h"
#include "CryptoTypes.h"

#include <array>
#include <boost/variant.hpp>
#include <string>
#include <vector>

namespace Pastella
{
    enum class TransactionRemoveReason : uint8_t
    {
        INCLUDED_IN_BLOCK = 0,
        TIMEOUT = 1
    };

    struct TransactionOutputDetails
    {
        TransactionOutput output;
        uint64_t globalIndex;
    };

    struct TransactionOutputReferenceDetails
    {
        Crypto::Hash transactionHash;
        uint64_t number;
    };

    struct BaseInputDetails
    {
        BaseInput input;
        uint64_t amount;
    };

    struct KeyInputDetails
    {
        KeyInput input;
        TransactionOutputReferenceDetails output;
    };

    typedef boost::variant<BaseInputDetails, KeyInputDetails> TransactionInputDetails;

    struct TransactionExtraDetails
    {
        Crypto::PublicKey publicKey;
        BinaryArray nonce;
        BinaryArray raw;
    };

    struct TransactionDetails
    {
        Crypto::Hash hash;
        uint64_t size = 0;
        uint64_t fee = 0;
        uint64_t totalInputsAmount = 0;
        uint64_t totalOutputsAmount = 0;
        uint64_t unlockTime = 0;
        uint64_t timestamp = 0;
        
        bool inBlockchain = false;
        Crypto::Hash blockHash;
        uint32_t blockIndex = 0;
        TransactionExtraDetails extra;
        std::vector<std::vector<Crypto::Signature>> signatures;
        std::vector<TransactionInputDetails> inputs;
        std::vector<TransactionOutputDetails> outputs;
    };

    struct BlockDetails
    {
        uint8_t majorVersion = 0;
        uint8_t minorVersion = 0;
        uint64_t timestamp = 0;
        Crypto::Hash prevBlockHash;
        uint32_t nonce = 0;
        bool isAlternative = false;
        uint32_t index = 0;
        Crypto::Hash hash;
        uint64_t difficulty = 0;
        uint64_t reward = 0;
        uint64_t baseReward = 0;
        uint64_t blockSize = 0;
        uint64_t transactionsCumulativeSize = 0;
        uint64_t alreadyGeneratedCoins = 0;
        uint64_t alreadyGeneratedTransactions = 0;
        uint64_t sizeMedian = 0;
        double penalty = 0.0;
        uint64_t totalFeeAmount = 0;
        std::vector<TransactionDetails> transactions;
    };

    struct RichListEntry
    {
        std::string address;
        uint64_t balance;
        double percentage; /* Percentage of total supply (0-100) */
        uint64_t firstTxTimestamp;
        uint64_t lastTxTimestamp;
    };

    enum class TransactionType : uint8_t
    {
        MINING = 0,        /* Coinbase/miner reward */
        STAKE_REWARD = 1,   /* Staking reward received from coinbase */
        INCOMING = 2,      /* Received funds */
        OUTGOING = 3,      /* Sent funds */
        STAKE_DEPOSIT = 4, /* Stake deposited (outgoing) */
        STAKE_UNLOCK = 5,  /* Stake unlocked */
        UNKNOWN = 255
    };

    struct WalletTransactionDetails
    {
        Crypto::Hash transactionHash;
        uint32_t blockNumber;
        Crypto::Hash blockHash;
        uint64_t amount;
        TransactionType type;
        uint64_t balanceAfter; /* Balance after this transaction */
        uint64_t timestamp;
        uint64_t unlockTime;
        uint64_t fee; /* Transaction fee (0 for coinbase) */
        std::vector<std::string> fromAddresses; /* Addresses sending funds (COINBASE for mining) */
        std::vector<std::string> toAddresses;   /* Addresses receiving funds */
    };

    struct WalletDetails
    {
        std::string address;
        uint64_t totalBalance;
        uint64_t totalIncoming;
        uint64_t totalOutgoing;
        uint64_t totalIncomingStakingRewards;
        uint64_t totalOutgoingStakes;
        uint64_t firstTxTimestamp;
        uint64_t lastTxTimestamp;
        uint32_t totalTransactions;
        std::vector<WalletTransactionDetails> transactions;
    };

} // namespace Pastella
