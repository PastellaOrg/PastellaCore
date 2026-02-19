// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "TransactionExtra.h"

#include "common/MemoryInputStream.h"
#include "common/StreamTools.h"
#include "common/StringTools.h"
#include "common/Varint.h"
#include "config/Constants.h"
#include "serialization/BinaryInputStreamSerializer.h"
#include "serialization/BinaryOutputStreamSerializer.h"
#include "serialization/SerializationTools.h"

using namespace Crypto;
using namespace Constants;
using namespace Common;

namespace Pastella
{
    bool parseTransactionExtra(
        const std::vector<uint8_t> &transactionExtra,
        std::vector<TransactionExtraField> &transactionExtraFields)
    {
        transactionExtraFields.clear();

        if (transactionExtra.empty())
        {
            return true;
        }

        bool seen_tx_extra_tag_padding = false;
        bool seen_tx_extra_tag_pubkey = false;
        bool seen_tx_extra_nonce = false;
        bool seen_tx_extra_merge_mining_tag = false;
        bool seen_tx_extra_staking = false;

        try
        {
            MemoryInputStream iss(transactionExtra.data(), transactionExtra.size());
            BinaryInputStreamSerializer ar(iss);

            int c = 0;

            while (!iss.endOfStream())
            {
                c = read<uint8_t>(iss);
                switch (c)
                {
                    case TX_EXTRA_TAG_PADDING:
                    {
                        if (seen_tx_extra_tag_padding)
                        {
                            return true;
                        }

                        seen_tx_extra_tag_padding = true;

                        size_t size = 1;
                        for (; !iss.endOfStream() && size <= TX_EXTRA_PADDING_MAX_COUNT; ++size)
                        {
                            if (read<uint8_t>(iss) != 0)
                            {
                                return false; // all bytes should be zero
                            }
                        }

                        if (size > TX_EXTRA_PADDING_MAX_COUNT)
                        {
                            return false;
                        }

                        transactionExtraFields.push_back(TransactionExtraPadding {size});
                        break;
                    }

                    case TX_EXTRA_TAG_PUBKEY:
                    {
                        if (seen_tx_extra_tag_pubkey)
                        {
                            return true;
                        }

                        seen_tx_extra_tag_pubkey = true;

                        TransactionExtraPublicKey extraPk;
                        ar(extraPk.publicKey, "public_key");
                        transactionExtraFields.push_back(extraPk);
                        break;
                    }

                    case TX_EXTRA_NONCE:
                    {
                        if (seen_tx_extra_nonce)
                        {
                            return true;
                        }

                        seen_tx_extra_nonce = true;

                        TransactionExtraNonce extraNonce;
                        uint8_t size = read<uint8_t>(iss);
                        if (size > 0)
                        {
                            extraNonce.nonce.resize(size);
                            read(iss, extraNonce.nonce.data(), extraNonce.nonce.size());
                        }

                        transactionExtraFields.push_back(extraNonce);
                        break;
                    }

                    case TX_EXTRA_MERGE_MINING_TAG:
                    {
                        if (seen_tx_extra_merge_mining_tag)
                        {
                            break;
                        }

                        seen_tx_extra_merge_mining_tag = true;

                        TransactionExtraMergeMiningTag mmTag;
                        ar(mmTag, "mm_tag");
                        transactionExtraFields.push_back(mmTag);
                        break;
                    }

                    case TX_EXTRA_STAKING:
                    {
                        if (seen_tx_extra_staking)
                        {
                            break;
                        }

                        seen_tx_extra_staking = true;

                        TransactionExtraStaking stakingTag;
                        ar(stakingTag.stakingType, "staking_type");
                        ar(stakingTag.amount, "amount");
                        ar(stakingTag.unlockTime, "unlock_time");
                        ar(stakingTag.lockDurationDays, "lock_duration_days");
                        ar(stakingTag.signature, "signature");
                        // TRANSPARENT SYSTEM: rewardAddress removed - rewards go to wallet's main address

                        transactionExtraFields.push_back(stakingTag);
                        break;
                    }
                }
            }
        }
        catch (std::exception &)
        {
            return false;
        }

        return true;
    }

    struct ExtraSerializerVisitor : public boost::static_visitor<bool>
    {
        std::vector<uint8_t> &extra;

        ExtraSerializerVisitor(std::vector<uint8_t> &tx_extra): extra(tx_extra) {}

        bool operator()(const TransactionExtraPadding &t)
        {
            if (t.size > TX_EXTRA_PADDING_MAX_COUNT)
            {
                return false;
            }
            extra.insert(extra.end(), t.size, 0);
            return true;
        }

        bool operator()(const TransactionExtraPublicKey &t)
        {
            return addTransactionPublicKeyToExtra(extra, t.publicKey);
        }

        bool operator()(const TransactionExtraNonce &t)
        {
            return addExtraNonceToTransactionExtra(extra, t.nonce);
        }

        bool operator()(const TransactionExtraMergeMiningTag &t)
        {
            return appendMergeMiningTagToExtra(extra, t);
        }

        bool operator()(const TransactionExtraStaking &t)
        {
            return addStakingDataToExtra(extra, t);
        }

        bool operator()(const TransactionExtraGovernanceProposal &t)
        {
            return addGovernanceProposalToExtra(extra, t);
        }

        bool operator()(const TransactionExtraGovernanceVote &t)
        {
            return addGovernanceVoteToExtra(extra, t);
        }
    };

    bool
        writeTransactionExtra(std::vector<uint8_t> &tx_extra, const std::vector<TransactionExtraField> &tx_extra_fields)
    {
        ExtraSerializerVisitor visitor(tx_extra);

        for (const auto &tag : tx_extra_fields)
        {
            if (!boost::apply_visitor(visitor, tag))
            {
                return false;
            }
        }

        return true;
    }

    PublicKey getTransactionPublicKeyFromExtra(const std::vector<uint8_t> &tx_extra)
    {
        std::vector<TransactionExtraField> tx_extra_fields;
        parseTransactionExtra(tx_extra, tx_extra_fields);

        // Find all transaction public keys and return the last one found
        // This handles complex transactions like staking that may have multiple public keys
        PublicKey lastPublicKey;
        for (const auto &field : tx_extra_fields)
        {
            if (field.type() == typeid(TransactionExtraPublicKey))
            {
                const auto &pub_key_field = boost::get<TransactionExtraPublicKey>(field);
                lastPublicKey = pub_key_field.publicKey; // Keep overwriting to get the last one
            }
        }

        if (lastPublicKey != Crypto::PublicKey())
        {
            return lastPublicKey;
        }

        return Crypto::PublicKey();
    }

    bool addTransactionPublicKeyToExtra(std::vector<uint8_t> &tx_extra, const PublicKey &tx_pub_key)
    {
        tx_extra.resize(tx_extra.size() + 1 + sizeof(PublicKey));
        tx_extra[tx_extra.size() - 1 - sizeof(PublicKey)] = TX_EXTRA_TAG_PUBKEY;
        *reinterpret_cast<PublicKey *>(&tx_extra[tx_extra.size() - sizeof(PublicKey)]) = tx_pub_key;
        return true;
    }

    bool addExtraNonceToTransactionExtra(std::vector<uint8_t> &tx_extra, const BinaryArray &extra_nonce)
    {
        if (extra_nonce.size() > TX_EXTRA_NONCE_MAX_COUNT)
        {
            return false;
        }

        size_t start_pos = tx_extra.size();
        tx_extra.resize(tx_extra.size() + 2 + extra_nonce.size());
        // write tag
        tx_extra[start_pos] = TX_EXTRA_NONCE;
        // write len
        ++start_pos;
        tx_extra[start_pos] = static_cast<uint8_t>(extra_nonce.size());
        // write data
        ++start_pos;
        memcpy(&tx_extra[start_pos], extra_nonce.data(), extra_nonce.size());
        return true;
    }

    bool appendMergeMiningTagToExtra(std::vector<uint8_t> &tx_extra, const TransactionExtraMergeMiningTag &mm_tag)
    {
        BinaryArray blob;
        if (!toBinaryArray(mm_tag, blob))
        {
            return false;
        }

        tx_extra.push_back(TX_EXTRA_MERGE_MINING_TAG);
        std::copy(
            reinterpret_cast<const uint8_t *>(blob.data()),
            reinterpret_cast<const uint8_t *>(blob.data() + blob.size()),
            std::back_inserter(tx_extra));
        return true;
    }

    bool getMergeMiningTagFromExtra(const std::vector<uint8_t> &tx_extra, TransactionExtraMergeMiningTag &mm_tag)
    {
        std::vector<TransactionExtraField> tx_extra_fields;
        parseTransactionExtra(tx_extra, tx_extra_fields);

        return findTransactionExtraFieldByType(tx_extra_fields, mm_tag);
    }

    /* Simple Reward Staking Transaction Extra Functions Implementation */
    bool addStakingDataToExtra(std::vector<uint8_t> &tx_extra, const TransactionExtraStaking &staking_data)
    {
        BinaryArray blob;
        if (!toBinaryArray(staking_data, blob))
        {
            return false;
        }

        tx_extra.push_back(TX_EXTRA_STAKING);
        std::copy(
            reinterpret_cast<const uint8_t *>(blob.data()),
            reinterpret_cast<const uint8_t *>(blob.data() + blob.size()),
            std::back_inserter(tx_extra));

        return true;
    }

    bool getStakingDataFromExtra(const std::vector<uint8_t> &tx_extra, TransactionExtraStaking &staking_data)
    {
        std::vector<TransactionExtraField> tx_extra_fields;
        parseTransactionExtra(tx_extra, tx_extra_fields);

        return findTransactionExtraFieldByType(tx_extra_fields, staking_data);
    }

    bool createStakingExtra(uint8_t stakingType, uint64_t amount, uint64_t unlockTime,
                           uint32_t lockDurationDays, const Crypto::Signature &signature,
                           std::vector<uint8_t> &extra)
    {
        TransactionExtraStaking staking_data;
        staking_data.stakingType = stakingType;
        staking_data.amount = amount;
        staking_data.unlockTime = unlockTime;
        staking_data.lockDurationDays = lockDurationDays;
        staking_data.signature = signature;

        return addStakingDataToExtra(extra, staking_data);
    }

    bool isStakingTransaction(const std::vector<uint8_t> &tx_extra)
    {
        TransactionExtraStaking staking_data;
        if (!getStakingDataFromExtra(tx_extra, staking_data))
        {
            return false;
        }
        return staking_data.stakingType == Pastella::parameters::staking::STAKING_TX_TYPE;
    }

    /* Governance Transaction Extra Functions Implementation */

    bool addGovernanceProposalToExtra(std::vector<uint8_t> &tx_extra, const TransactionExtraGovernanceProposal &proposal_data)
    {
        BinaryArray blob;
        if (!toBinaryArray(proposal_data, blob))
        {
            return false;
        }

        tx_extra.push_back(TX_EXTRA_GOVERNANCE_PROPOSAL);
        std::copy(
            reinterpret_cast<const uint8_t *>(blob.data()),
            reinterpret_cast<const uint8_t *>(blob.data() + blob.size()),
            std::back_inserter(tx_extra));

        return true;
    }

    bool getGovernanceProposalFromExtra(const std::vector<uint8_t> &tx_extra, TransactionExtraGovernanceProposal &proposal_data)
    {
        std::vector<TransactionExtraField> tx_extra_fields;
        parseTransactionExtra(tx_extra, tx_extra_fields);

        return findTransactionExtraFieldByType(tx_extra_fields, proposal_data);
    }

    bool createGovernanceProposalExtra(uint64_t proposalId, const std::string &title, const std::string &description,
                                       uint8_t proposalType, uint64_t amount, const std::string &recipientAddress,
                                       const Crypto::Signature &signature, std::vector<uint8_t> &extra)
    {
        TransactionExtraGovernanceProposal proposal_data;
        proposal_data.proposalId = proposalId;
        proposal_data.title = title;
        proposal_data.description = description;
        proposal_data.proposalType = proposalType;
        proposal_data.amount = amount;
        proposal_data.recipientAddress = recipientAddress;
        proposal_data.signature = signature;

        return addGovernanceProposalToExtra(extra, proposal_data);
    }

    bool isGovernanceProposalTransaction(const std::vector<uint8_t> &tx_extra)
    {
        std::vector<TransactionExtraField> tx_extra_fields;
        parseTransactionExtra(tx_extra, tx_extra_fields);

        return std::any_of(tx_extra_fields.begin(), tx_extra_fields.end(), [](const TransactionExtraField &field) {
            return field.type() == typeid(TransactionExtraGovernanceProposal);
        });
    }

    bool addGovernanceVoteToExtra(std::vector<uint8_t> &tx_extra, const TransactionExtraGovernanceVote &vote_data)
    {
        BinaryArray blob;
        if (!toBinaryArray(vote_data, blob))
        {
            return false;
        }

        tx_extra.push_back(TX_EXTRA_GOVERNANCE_VOTE);
        std::copy(
            reinterpret_cast<const uint8_t *>(blob.data()),
            reinterpret_cast<const uint8_t *>(blob.data() + blob.size()),
            std::back_inserter(tx_extra));

        return true;
    }

    bool getGovernanceVoteFromExtra(const std::vector<uint8_t> &tx_extra, TransactionExtraGovernanceVote &vote_data)
    {
        std::vector<TransactionExtraField> tx_extra_fields;
        parseTransactionExtra(tx_extra, tx_extra_fields);

        return findTransactionExtraFieldByType(tx_extra_fields, vote_data);
    }

    bool createGovernanceVoteExtra(uint64_t proposalId, uint8_t vote, uint64_t stakeWeight,
                                   std::vector<uint8_t> &extra)
    {
        TransactionExtraGovernanceVote vote_data;
        vote_data.proposalId = proposalId;
        vote_data.vote = vote;
        vote_data.stakeWeight = stakeWeight;

        return addGovernanceVoteToExtra(extra, vote_data);
    }

    bool isGovernanceVoteTransaction(const std::vector<uint8_t> &tx_extra)
    {
        std::vector<TransactionExtraField> tx_extra_fields;
        parseTransactionExtra(tx_extra, tx_extra_fields);

        return std::any_of(tx_extra_fields.begin(), tx_extra_fields.end(), [](const TransactionExtraField &field) {
            return field.type() == typeid(TransactionExtraGovernanceVote);
        });
    }

} // namespace Pastella
