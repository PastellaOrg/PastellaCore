// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#include <Pastella.h>
#include <algorithm>
#include <boost/variant.hpp>
#include <vector>

#define TX_EXTRA_PADDING_MAX_COUNT 255
#define TX_EXTRA_NONCE_MAX_COUNT 255

#define TX_EXTRA_TAG_PADDING 0x00
#define TX_EXTRA_TAG_PUBKEY 0x01
#define TX_EXTRA_NONCE 0x02
#define TX_EXTRA_MERGE_MINING_TAG 0x03
#define TX_EXTRA_STAKING 0x04
#define TX_EXTRA_GOVERNANCE_PROPOSAL 0x05
#define TX_EXTRA_GOVERNANCE_VOTE 0x06

namespace Pastella
{
    struct TransactionExtraPadding
    {
        size_t size;
    };

    struct TransactionExtraPublicKey
    {
        Crypto::PublicKey publicKey;
    };

    struct TransactionExtraNonce
    {
        std::vector<uint8_t> nonce;
    };

    struct TransactionExtraMergeMiningTag
    {
        size_t depth;
        Crypto::Hash merkleRoot;
    };

    /* Simple Reward Staking Extra Fields */
    /* TRANSPARENT SYSTEM: rewardAddress removed - rewards go to wallet's main address */
    struct TransactionExtraStaking
    {
        uint8_t stakingType; // 101 = staking
        uint64_t amount;     // Amount being staked
        uint64_t unlockTime; // When funds can be unlocked
        uint32_t lockDurationDays; // Lock period in days
        Crypto::Signature signature; // Staker's signature to authorize operation

        template <class Serializer>
        void serialize(Serializer &serializer)
        {
            serializer(stakingType, "staking_type");
            serializer(amount, "amount");
            serializer(unlockTime, "unlock_time");
            serializer(lockDurationDays, "lock_duration_days");
            serializer(signature, "signature");
        }
    };

    /* Governance Proposal Extra Field */
    struct TransactionExtraGovernanceProposal
    {
        uint64_t proposalId;           // Unique proposal identifier
        std::string title;             // Proposal title
        std::string description;       // Detailed description
        uint8_t proposalType;          // Type of proposal (0=parameter, 1=upgrade, 2=treasury)
        uint64_t amount;               // Amount requested (only for treasury proposals, 0 for others)
        std::string recipientAddress;  // Recipient address (only for treasury proposals, empty for others)
        Crypto::Signature signature;   // Proposer's signature

        template <class Serializer>
        void serialize(Serializer &serializer)
        {
            serializer(proposalId, "proposal_id");
            serializer(title, "title");
            serializer(description, "description");
            serializer(proposalType, "proposal_type");
            serializer(amount, "amount");
            serializer(recipientAddress, "recipient_address");
            serializer(signature, "signature");
        }
    };

    /* Governance Vote Extra Field */
    struct TransactionExtraGovernanceVote
    {
        uint64_t proposalId;           // Proposal being voted on
        uint8_t vote;                  // 0 = against, 1 = for, 2 = abstain
        uint64_t stakeWeight;          // Voting power (amount × lock multiplier)

        template <class Serializer>
        void serialize(Serializer &serializer)
        {
            serializer(proposalId, "proposal_id");
            serializer(vote, "vote");
            serializer(stakeWeight, "stake_weight");
        }
    };

    // tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
    //   varint tag;
    //   varint size;
    //   varint data[];
    typedef boost::variant<
        TransactionExtraPadding,
        TransactionExtraPublicKey,
        TransactionExtraNonce,
        TransactionExtraMergeMiningTag,
        TransactionExtraStaking,
        TransactionExtraGovernanceProposal,
        TransactionExtraGovernanceVote>
        TransactionExtraField;

    template<typename T>
    bool findTransactionExtraFieldByType(const std::vector<TransactionExtraField> &tx_extra_fields, T &field)
    {
        auto it = std::find_if(tx_extra_fields.begin(), tx_extra_fields.end(), [](const TransactionExtraField &f) {
            return typeid(T) == f.type();
        });

        if (tx_extra_fields.end() == it)
        {
            return false;
        }

        field = boost::get<T>(*it);
        return true;
    }

    bool parseTransactionExtra(
        const std::vector<uint8_t> &tx_extra,
        std::vector<TransactionExtraField> &tx_extra_fields);

    bool writeTransactionExtra(
        std::vector<uint8_t> &tx_extra,
        const std::vector<TransactionExtraField> &tx_extra_fields);

    Crypto::PublicKey getTransactionPublicKeyFromExtra(const std::vector<uint8_t> &tx_extra);

    bool addTransactionPublicKeyToExtra(std::vector<uint8_t> &tx_extra, const Crypto::PublicKey &tx_pub_key);

    bool addExtraNonceToTransactionExtra(std::vector<uint8_t> &tx_extra, const BinaryArray &extra_nonce);

    bool appendMergeMiningTagToExtra(std::vector<uint8_t> &tx_extra, const TransactionExtraMergeMiningTag &mm_tag);

    bool getMergeMiningTagFromExtra(const std::vector<uint8_t> &tx_extra, TransactionExtraMergeMiningTag &mm_tag);

/* Simple Reward Staking Transaction Extra Functions */
    bool addStakingDataToExtra(std::vector<uint8_t> &tx_extra, const TransactionExtraStaking &staking_data);

    bool getStakingDataFromExtra(const std::vector<uint8_t> &tx_extra, TransactionExtraStaking &staking_data);

    bool createStakingExtra(uint8_t stakingType, uint64_t amount, uint64_t unlockTime,
                           uint32_t lockDurationDays, const Crypto::Signature &signature,
                           std::vector<uint8_t> &extra);

    bool isStakingTransaction(const std::vector<uint8_t> &tx_extra);

/* Governance Transaction Extra Functions */
    bool addGovernanceProposalToExtra(std::vector<uint8_t> &tx_extra, const TransactionExtraGovernanceProposal &proposal_data);

    bool getGovernanceProposalFromExtra(const std::vector<uint8_t> &tx_extra, TransactionExtraGovernanceProposal &proposal_data);

    bool createGovernanceProposalExtra(uint64_t proposalId, const std::string &title, const std::string &description,
                                       uint8_t proposalType, uint64_t amount, const std::string &recipientAddress,
                                       const Crypto::Signature &signature, std::vector<uint8_t> &extra);

    bool isGovernanceProposalTransaction(const std::vector<uint8_t> &tx_extra);

    bool addGovernanceVoteToExtra(std::vector<uint8_t> &tx_extra, const TransactionExtraGovernanceVote &vote_data);

    bool getGovernanceVoteFromExtra(const std::vector<uint8_t> &tx_extra, TransactionExtraGovernanceVote &vote_data);

    bool createGovernanceVoteExtra(uint64_t proposalId, uint8_t vote, uint64_t stakeWeight,
                                   std::vector<uint8_t> &extra);

    bool isGovernanceVoteTransaction(const std::vector<uint8_t> &tx_extra);

} // namespace Pastella
