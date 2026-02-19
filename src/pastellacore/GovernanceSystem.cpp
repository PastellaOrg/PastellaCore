// Copyright (c) 2024, The Pastella Developers
//
// Governance System Implementation

#include "GovernanceSystem.h"
#include "StakingSystem.h"
#include "IBlockchainCache.h"
#include "Currency.h"
#include <config/PastellaConfig.h>
#include <common/StringTools.h>

using namespace Crypto;
using Logging::LoggerRef;

namespace Pastella
{
    /* Constructor */
    GovernanceManager::GovernanceManager(const Currency &currency, Logging::LoggerRef logger)
        : m_currency(currency), nextProposalId(1), currentHeight(0), logger(logger)
    {
    }

    /* Destructor */
    GovernanceManager::~GovernanceManager()
    {
    }

    /* Initialize governance system */
    bool GovernanceManager::initialize()
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        LoggerRef loggerGovernance(logger.getLogger(), "Governance");
        loggerGovernance(Logging::INFO) << "Initializing governance system...";

        /* Initialize with empty state */
        proposals.clear();
        votes.clear();
        votedAddresses.clear();
        nextProposalId = 1;

        loggerGovernance(Logging::INFO) << "Governance system initialized successfully";
        return true;
    }

    /* Calculate lock duration multiplier for voting power */
    uint64_t GovernanceManager::calculateLockMultiplier(uint32_t lockDurationDays) const
    {
        /* Lock duration multipliers based on config */
        if (lockDurationDays >= 360)
            return parameters::governance::LOCK_MULTIPLIER_360_DAYS;
        else if (lockDurationDays >= 180)
            return parameters::governance::LOCK_MULTIPLIER_180_DAYS;
        else if (lockDurationDays >= 90)
            return parameters::governance::LOCK_MULTIPLIER_90_DAYS;
        else if (lockDurationDays >= 30)
            return parameters::governance::LOCK_MULTIPLIER_30_DAYS;
        else
            return 1; /* Minimal lock, 1x multiplier */
    }

    /* Get required threshold for proposal type */
    uint8_t GovernanceManager::getRequiredThreshold(uint8_t proposalType) const
    {
        switch (proposalType)
        {
            case parameters::governance::PROPOSAL_TYPE_PARAMETER:
                return parameters::governance::SIMPLE_MAJORITY_THRESHOLD;
            case parameters::governance::PROPOSAL_TYPE_UPGRADE:
                return parameters::governance::SUPERMAJORITY_THRESHOLD;
            case parameters::governance::PROPOSAL_TYPE_TREASURY:
                return parameters::governance::SIMPLE_MAJORITY_THRESHOLD;
            default:
                return parameters::governance::SIMPLE_MAJORITY_THRESHOLD;
        }
    }

    /* Check if proposal is expired */
    bool GovernanceManager::isProposalExpired(const WalletTypes::GovernanceProposal &proposal) const
    {
        return currentHeight >= proposal.expirationHeight;
    }

    /* Update proposal status based on votes */
    void GovernanceManager::updateProposalStatus(WalletTypes::GovernanceProposal &proposal)
    {
        if (!proposal.isActive)
        {
            return; /* Already completed */
        }

        /* Check if expired */
        if (isProposalExpired(proposal))
        {
            proposal.isActive = false;

            /* Calculate result */
            uint64_t totalVotes = proposal.votesFor + proposal.votesAgainst;

            /* Check minimum participation requirement (10% of total voting power) */
            uint64_t minimumParticipation = (proposal.totalVotingPower * 10) / 100;

            if (totalVotes < minimumParticipation)
            {
                proposal.result = "failed";
                LoggerRef loggerGovernance(logger.getLogger(), "Governance");
                loggerGovernance(Logging::INFO) << "Proposal " << proposal.proposalId
                    << " failed due to insufficient participation ("
                    << totalVotes << " votes < " << minimumParticipation << " required)";
                return;
            }

            if (totalVotes == 0)
            {
                proposal.result = "failed";
                return;
            }

            uint8_t threshold = getRequiredThreshold(proposal.proposalType);
            uint64_t requiredVotes = (proposal.totalVotingPower * threshold) / 100;

            if (proposal.votesFor >= requiredVotes)
            {
                proposal.result = "passed";
            }
            else
            {
                proposal.result = "failed";
            }

            return;
        }

        /* Still active */
        proposal.result = "active";
    }

    /* Create a new governance proposal */
    uint64_t GovernanceManager::createProposal(
        const std::string &title,
        const std::string &description,
        const std::string &proposerAddress,
        uint8_t proposalType,
        uint64_t creationHeight,
        uint64_t amount,
        const std::string &recipientAddress)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        LoggerRef loggerGovernance(logger.getLogger(), "Governance");
        loggerGovernance(Logging::INFO) << "Creating new proposal: " << title;

        WalletTypes::GovernanceProposal proposal;
        proposal.proposalId = nextProposalId++;
        proposal.title = title;
        proposal.description = description;
        proposal.proposerAddress = proposerAddress;
        proposal.creationHeight = creationHeight;
        proposal.expirationHeight = creationHeight + parameters::governance::PROPOSAL_DURATION_BLOCKS;
        proposal.proposalType = proposalType;
        proposal.isActive = true;
        proposal.votesFor = 0;
        proposal.votesAgainst = 0;
        proposal.totalVotingPower = 0;
        proposal.result = "active";
        proposal.amount = amount;
        proposal.recipientAddress = recipientAddress;

        proposals[proposal.proposalId] = proposal;
        votedAddresses[proposal.proposalId] = std::unordered_map<std::string, bool>();

        loggerGovernance(Logging::INFO) << "Proposal created with ID: " << proposal.proposalId;
        return proposal.proposalId;
    }

    /* Validate proposal */
    bool GovernanceManager::validateProposal(
        const WalletTypes::GovernanceProposal &proposal,
        uint64_t currentHeight) const
    {
        /* Check title length */
        if (proposal.title.empty() || proposal.title.length() > 200)
        {
            return false;
        }

        /* Check description length */
        if (proposal.description.empty() || proposal.description.length() > 5000)
        {
            return false;
        }

        /* Check proposal type */
        if (proposal.proposalType > parameters::governance::PROPOSAL_TYPE_TREASURY)
        {
            return false;
        }

        /* Check heights */
        if (proposal.creationHeight >= proposal.expirationHeight)
        {
            return false;
        }

        return true;
    }

    /* Get all active proposals */
    std::vector<WalletTypes::GovernanceProposal> GovernanceManager::getActiveProposals() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<WalletTypes::GovernanceProposal> active;
        for (const auto &pair : proposals)
        {
            if (pair.second.isActive)
            {
                active.push_back(pair.second);
            }
        }

        return active;
    }

    /* Get all proposals */
    std::vector<WalletTypes::GovernanceProposal> GovernanceManager::getAllProposals() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<WalletTypes::GovernanceProposal> all;
        for (const auto &pair : proposals)
        {
            all.push_back(pair.second);
        }

        return all;
    }

    /* Get specific proposal */
    bool GovernanceManager::getProposal(uint64_t proposalId, WalletTypes::GovernanceProposal &proposal) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = proposals.find(proposalId);
        if (it == proposals.end())
        {
            return false;
        }

        proposal = it->second;
        return true;
    }

    /* Cast a vote on a proposal */
    bool GovernanceManager::castVote(
        uint64_t proposalId,
        const std::string &voterAddress,
        uint8_t vote,
        uint64_t stakeWeight,
        uint64_t voteHeight)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        LoggerRef loggerGovernance(logger.getLogger(), "Governance");
        loggerGovernance(Logging::DEBUGGING) << "Casting vote: proposal=" << proposalId
                                            << ", voter=" << voterAddress
                                            << ", vote=" << (int)vote
                                            << ", weight=" << stakeWeight;

        /* Check if proposal exists */
        auto it = proposals.find(proposalId);
        if (it == proposals.end())
        {
            loggerGovernance(Logging::WARNING) << "Proposal not found: " << proposalId;
            return false;
        }

        WalletTypes::GovernanceProposal &proposal = it->second;

        /* Check if proposal is active */
        if (!proposal.isActive)
        {
            loggerGovernance(Logging::WARNING) << "Proposal is not active: " << proposalId;
            return false;
        }

        /* Check if already voted */
        if (hasVoted(proposalId, voterAddress))
        {
            loggerGovernance(Logging::WARNING) << "Address already voted: " << voterAddress;
            return false;
        }

        /* Validate vote */
        if (vote != parameters::governance::VOTE_AGAINST &&
            vote != parameters::governance::VOTE_FOR &&
            vote != parameters::governance::VOTE_ABSTAIN)
        {
            loggerGovernance(Logging::WARNING) << "Invalid vote type: " << (int)vote;
            return false;
        }

        /* Record vote */
        WalletTypes::GovernanceVote govVote;
        govVote.proposalId = proposalId;
        govVote.voterAddress = voterAddress;
        govVote.vote = vote;
        govVote.stakeWeight = stakeWeight;
        govVote.voteHeight = voteHeight;

        votes[proposalId].push_back(govVote);
        votedAddresses[proposalId][voterAddress] = true;

        /* Update proposal tallies */
        if (vote == parameters::governance::VOTE_FOR)
        {
            proposal.votesFor += stakeWeight;
        }
        else if (vote == parameters::governance::VOTE_AGAINST)
        {
            proposal.votesAgainst += stakeWeight;
        }

        proposal.totalVotingPower += stakeWeight;

        loggerGovernance(Logging::INFO) << "Vote cast successfully: proposal=" << proposalId
                                         << ", for=" << proposal.votesFor
                                         << ", against=" << proposal.votesAgainst;

        /* Update status */
        updateProposalStatus(proposal);

        return true;
    }

    /* Get voting power for an address */
    uint64_t GovernanceManager::getVotingPower(const std::string &address, const IBlockchainCache *blockchain) const
    {
        /* This will be implemented to query the StakingPool
         * For now, return 0 to indicate it needs the blockchain cache */
        return 0;
    }

    /* Check if address has voted on proposal */
    bool GovernanceManager::hasVoted(uint64_t proposalId, const std::string &address) const
    {
        auto it = votedAddresses.find(proposalId);
        if (it == votedAddresses.end())
        {
            return false;
        }

        auto addrIt = it->second.find(address);
        return addrIt != it->second.end();
    }

    /* Get votes for a proposal */
    std::vector<WalletTypes::GovernanceVote> GovernanceManager::getVotes(uint64_t proposalId) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = votes.find(proposalId);
        if (it == votes.end())
        {
            return std::vector<WalletTypes::GovernanceVote>();
        }

        return it->second;
    }

    /* Execute a passed proposal */
    bool GovernanceManager::executeProposal(uint64_t proposalId)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        LoggerRef loggerGovernance(logger.getLogger(), "Governance");

        auto it = proposals.find(proposalId);
        if (it == proposals.end())
        {
            loggerGovernance(Logging::ERROR) << "Cannot execute proposal: not found: " << proposalId;
            return false;
        }

        WalletTypes::GovernanceProposal &proposal = it->second;

        if (proposal.result != "passed")
        {
            loggerGovernance(Logging::WARNING) << "Cannot execute proposal: not passed: " << proposalId;
            return false;
        }

        loggerGovernance(Logging::INFO) << "Executing proposal: " << proposalId << " - " << proposal.title;

        /* TODO: Implement execution logic based on proposal type
         * For now, just mark as executed */
        proposal.isActive = false;

        return true;
    }

    /* Update all proposals (call on new block) */
    void GovernanceManager::updateProposals(uint64_t newHeight)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        currentHeight = newHeight;

        LoggerRef loggerGovernance(logger.getLogger(), "Governance");
        loggerGovernance(Logging::TRACE) << "Updating proposals at height " << newHeight;

        /* Update status of all proposals */
        for (auto &pair : proposals)
        {
            updateProposalStatus(pair.second);
        }
    }

    /* Deactivate a proposal */
    bool GovernanceManager::deactivateProposal(uint64_t proposalId)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = proposals.find(proposalId);
        if (it == proposals.end())
        {
            return false;
        }

        it->second.isActive = false;
        it->second.result = "deactivated";

        return true;
    }

    /* Process proposal transaction from block */
    bool GovernanceManager::processProposalTransaction(
        const Pastella::Transaction &tx,
        const Pastella::TransactionExtraGovernanceProposal &proposalExtra,
        const std::string &proposerAddress,
        uint64_t blockHeight)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        LoggerRef loggerGovernance(logger.getLogger(), "Governance");
        loggerGovernance(Logging::INFO) << "Processing proposal transaction: ID=" << proposalExtra.proposalId
                                         << ", proposer=" << proposerAddress
                                         << ", height=" << blockHeight;

        /* CRITICAL SECURITY: Verify signature to prove ownership */
        /* Create hash of proposal data for signature verification */
        std::vector<uint8_t> proposalData;
        proposalData.insert(proposalData.end(), proposalExtra.title.begin(), proposalExtra.title.end());
        proposalData.insert(proposalData.end(), proposalExtra.description.begin(), proposalExtra.description.end());
        proposalData.push_back(proposalExtra.proposalType);

        /* Add amount to data */
        const uint8_t *amountBytes = reinterpret_cast<const uint8_t*>(&proposalExtra.amount);
        proposalData.insert(proposalData.end(), amountBytes, amountBytes + sizeof(proposalExtra.amount));

        /* Add recipient address */
        proposalData.insert(proposalData.end(), proposalExtra.recipientAddress.begin(), proposalExtra.recipientAddress.end());

        /* Add proposal ID */
        const uint8_t *proposalIdBytes = reinterpret_cast<const uint8_t*>(&proposalExtra.proposalId);
        proposalData.insert(proposalData.end(), proposalIdBytes, proposalIdBytes + sizeof(proposalExtra.proposalId));

        /* Hash the proposal data */
        Crypto::Hash proposalHash = Crypto::cn_fast_hash(proposalData.data(), proposalData.size());

        /* Get the transaction public key (which should be the proposer's public key) */
        Crypto::PublicKey txPublicKey = Pastella::getTransactionPublicKeyFromExtra(tx.extra);

        /* Verify the signature */
        bool signatureValid = Crypto::check_signature(proposalHash, txPublicKey, proposalExtra.signature);

        if (!signatureValid)
        {
            loggerGovernance(Logging::ERROR) << "Proposal transaction rejected: INVALID SIGNATURE! Proposal ID: "
                                                << proposalExtra.proposalId;
            return false;
        }

        loggerGovernance(Logging::DEBUGGING) << "Proposal signature verified successfully for ID: " << proposalExtra.proposalId;

        /* CRITICAL SECURITY: For treasury proposals, validate recipient address */
        if (proposalExtra.proposalType == parameters::governance::PROPOSAL_TYPE_TREASURY)
        {
            /* Check recipient address is not empty */
            if (proposalExtra.recipientAddress.empty())
            {
                loggerGovernance(Logging::ERROR) << "Treasury proposal rejected: recipient address is empty! Proposal ID: "
                                                    << proposalExtra.proposalId;
                return false;
            }

            /* Validate recipient address format */
            AccountPublicAddress recipientAddr;
            if (!m_currency.parseAccountAddressString(proposalExtra.recipientAddress, recipientAddr))
            {
                loggerGovernance(Logging::ERROR) << "Treasury proposal rejected: invalid recipient address format! "
                                                    << "Address: " << proposalExtra.recipientAddress
                                                    << ", Proposal ID: " << proposalExtra.proposalId;
                return false;
            }

            loggerGovernance(Logging::DEBUGGING) << "Treasury recipient address validated: " << proposalExtra.recipientAddress;
        }

        /* Create proposal in system */
        WalletTypes::GovernanceProposal proposal;
        proposal.proposalId = proposalExtra.proposalId;
        proposal.title = proposalExtra.title;
        proposal.description = proposalExtra.description;
        proposal.proposerAddress = proposerAddress;
        proposal.proposalType = proposalExtra.proposalType;
        proposal.amount = proposalExtra.amount;
        proposal.recipientAddress = proposalExtra.recipientAddress;
        proposal.creationHeight = blockHeight;
        proposal.expirationHeight = blockHeight + parameters::governance::PROPOSAL_DURATION_BLOCKS;
        proposal.isActive = true;
        proposal.votesFor = 0;
        proposal.votesAgainst = 0;
        proposal.totalVotingPower = 0;
        proposal.result = "active";

        proposals[proposal.proposalId] = proposal;
        votedAddresses[proposal.proposalId] = std::unordered_map<std::string, bool>();

        loggerGovernance(Logging::INFO) << "Proposal created from transaction: " << proposal.proposalId
                                         << ", type=" << (int)proposal.proposalType
                                         << ", expires=" << proposal.expirationHeight;

        return true;
    }

    /* Process vote transaction from block */
    bool GovernanceManager::processVoteTransaction(
        const Pastella::Transaction &tx,
        const Pastella::TransactionExtraGovernanceVote &voteExtra,
        const std::string &voterAddress,
        uint64_t voteHeight)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        LoggerRef loggerGovernance(logger.getLogger(), "Governance");
        loggerGovernance(Logging::INFO) << "Processing vote transaction: proposal=" << voteExtra.proposalId
                                         << ", voter=" << voterAddress
                                         << ", vote=" << (int)voteExtra.vote
                                         << ", height=" << voteHeight;

        /* Use the voting power from the transaction extra field */
        uint64_t stakeWeight = voteExtra.stakeWeight;

        /* Check if proposal exists and is active */
        auto it = proposals.find(voteExtra.proposalId);
        if (it == proposals.end())
        {
            loggerGovernance(Logging::WARNING) << "Vote transaction rejected: proposal not found: " << voteExtra.proposalId;
            return false;
        }

        WalletTypes::GovernanceProposal &proposal = it->second;

        /* Check if proposal is active */
        if (!proposal.isActive)
        {
            loggerGovernance(Logging::WARNING) << "Vote transaction rejected: proposal not active: " << voteExtra.proposalId;
            return false;
        }

        /* Check if already voted */
        if (hasVoted(voteExtra.proposalId, voterAddress))
        {
            loggerGovernance(Logging::WARNING) << "Vote transaction rejected: address already voted: " << voterAddress;
            return false;
        }

        /* Validate vote type */
        if (voteExtra.vote != parameters::governance::VOTE_AGAINST &&
            voteExtra.vote != parameters::governance::VOTE_FOR &&
            voteExtra.vote != parameters::governance::VOTE_ABSTAIN)
        {
            loggerGovernance(Logging::WARNING) << "Vote transaction rejected: invalid vote type: " << (int)voteExtra.vote;
            return false;
        }

        /* Record vote */
        WalletTypes::GovernanceVote govVote;
        govVote.proposalId = voteExtra.proposalId;
        govVote.voterAddress = voterAddress;
        govVote.vote = voteExtra.vote;
        govVote.stakeWeight = stakeWeight;
        govVote.voteHeight = voteHeight;

        votes[voteExtra.proposalId].push_back(govVote);
        votedAddresses[voteExtra.proposalId][voterAddress] = true;

        /* Update proposal tallies with overflow protection */
        if (voteExtra.vote == parameters::governance::VOTE_FOR)
        {
            /* Check for overflow */
            if (proposal.votesFor > UINT64_MAX - stakeWeight)
            {
                loggerGovernance(Logging::ERROR) << "Vote transaction rejected: votesFor overflow detected";
                votedAddresses[voteExtra.proposalId].erase(voterAddress);
                votes[voteExtra.proposalId].pop_back();
                return false;
            }
            proposal.votesFor += stakeWeight;
        }
        else if (voteExtra.vote == parameters::governance::VOTE_AGAINST)
        {
            /* Check for overflow */
            if (proposal.votesAgainst > UINT64_MAX - stakeWeight)
            {
                loggerGovernance(Logging::ERROR) << "Vote transaction rejected: votesAgainst overflow detected";
                votedAddresses[voteExtra.proposalId].erase(voterAddress);
                votes[voteExtra.proposalId].pop_back();
                return false;
            }
            proposal.votesAgainst += stakeWeight;
        }

        /* Check for overflow in total voting power */
        if (proposal.totalVotingPower > UINT64_MAX - stakeWeight)
        {
            loggerGovernance(Logging::ERROR) << "Vote transaction rejected: totalVotingPower overflow detected";
            votedAddresses[voteExtra.proposalId].erase(voterAddress);
            votes[voteExtra.proposalId].pop_back();
            if (voteExtra.vote == parameters::governance::VOTE_FOR)
            {
                proposal.votesFor -= stakeWeight;
            }
            else if (voteExtra.vote == parameters::governance::VOTE_AGAINST)
            {
                proposal.votesAgainst -= stakeWeight;
            }
            return false;
        }
        proposal.totalVotingPower += stakeWeight;

        loggerGovernance(Logging::INFO) << "Vote processed successfully: proposal=" << voteExtra.proposalId
                                         << ", for=" << proposal.votesFor
                                         << ", against=" << proposal.votesAgainst;

        /* Update status */
        updateProposalStatus(proposal);

        return true;
    }

    /* Load from database */
    void GovernanceManager::loadFromDatabase(IDataBase &database)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        LoggerRef loggerGovernance(logger.getLogger(), "Governance");
        loggerGovernance(Logging::INFO) << "Loading governance state from database...";

        /* TODO: Implement database loading
         * For now, governance state is rebuilt from blockchain scan */

        loggerGovernance(Logging::INFO) << "Governance state loaded";
    }

    /* Save to database */
    void GovernanceManager::saveToDatabase(IDataBase &database)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        LoggerRef loggerGovernance(logger.getLogger(), "Governance");
        loggerGovernance(Logging::TRACE) << "Saving governance state to database...";

        /* TODO: Implement database saving
         * Proposals and votes are saved to database */

        loggerGovernance(Logging::TRACE) << "Governance state saved";
    }

    /* Get total proposals count */
    uint64_t GovernanceManager::getTotalProposals() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return proposals.size();
    }

    /* Get active proposals count */
    uint64_t GovernanceManager::getActiveProposalsCount() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        uint64_t count = 0;
        for (const auto &pair : proposals)
        {
            if (pair.second.isActive)
            {
                count++;
            }
        }

        return count;
    }

    /* Get vote totals */
    std::pair<uint64_t, uint64_t> GovernanceManager::getTotalVotes(uint64_t proposalId) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = proposals.find(proposalId);
        if (it == proposals.end())
        {
            return {0, 0};
        }

        return {it->second.votesFor, it->second.votesAgainst};
    }

    /* Get next available proposal ID */
    uint64_t GovernanceManager::getNextProposalId() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return nextProposalId;
    }

} // namespace Pastella
