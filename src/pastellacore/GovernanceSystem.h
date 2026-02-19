// Copyright (c) 2024, The Pastella Developers
//
// Governance System for On-Chain Proposal and Voting Management

#pragma once

#include <Pastella.h>
#include <WalletTypes.h>
#include <logging/LoggerRef.h>
#include <logging/ILogger.h>
#include <common/TransactionExtra.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>

namespace Pastella
{
    /* Forward declarations */
    class IBlockchainCache;
    class IDataBase;
    class Currency;

    /* Governance Manager Class
     *
     * Manages on-chain governance including:
     * - Proposal creation and lifecycle
     * - Vote tracking and tallying
     * - Proposal execution
     * - Database persistence */
    class GovernanceManager
    {
    private:
        /* Currency reference for address validation */
        const Currency &m_currency;
        /* Proposal storage */
        std::unordered_map<uint64_t, WalletTypes::GovernanceProposal> proposals;

        /* Vote storage: proposalId -> list of votes */
        std::unordered_map<uint64_t, std::vector<WalletTypes::GovernanceVote>> votes;

        /* Track which addresses voted on which proposals: proposalId -> {address -> voted} */
        std::unordered_map<uint64_t, std::unordered_map<std::string, bool>> votedAddresses;

        /* Next proposal ID */
        uint64_t nextProposalId;

        /* Current blockchain height */
        uint64_t currentHeight;

        /* Thread safety */
        mutable std::mutex m_mutex;

        /* Logger */
        Logging::LoggerRef logger;

        /* Helper methods */
        uint64_t calculateLockMultiplier(uint32_t lockDurationDays) const;
        uint8_t getRequiredThreshold(uint8_t proposalType) const;
        bool isProposalExpired(const WalletTypes::GovernanceProposal &proposal) const;
        void updateProposalStatus(WalletTypes::GovernanceProposal &proposal);

    public:
        GovernanceManager(const Currency &currency, Logging::LoggerRef logger);
        ~GovernanceManager();

        /* Initialization */
        bool initialize();

        /* Proposal management */
        uint64_t createProposal(
            const std::string &title,
            const std::string &description,
            const std::string &proposerAddress,
            uint8_t proposalType,
            uint64_t creationHeight,
            uint64_t amount = 0,
            const std::string &recipientAddress = "");

        bool validateProposal(
            const WalletTypes::GovernanceProposal &proposal,
            uint64_t currentHeight) const;

        std::vector<WalletTypes::GovernanceProposal> getActiveProposals() const;
        std::vector<WalletTypes::GovernanceProposal> getAllProposals() const;

        bool getProposal(uint64_t proposalId, WalletTypes::GovernanceProposal &proposal) const;

        /* Voting */
        bool castVote(
            uint64_t proposalId,
            const std::string &voterAddress,
            uint8_t vote,
            uint64_t stakeWeight,
            uint64_t voteHeight);

        uint64_t getVotingPower(const std::string &address, const IBlockchainCache *blockchain) const;
        bool hasVoted(uint64_t proposalId, const std::string &address) const;

        std::vector<WalletTypes::GovernanceVote> getVotes(uint64_t proposalId) const;

        /* Proposal lifecycle */
        bool executeProposal(uint64_t proposalId);
        void updateProposals(uint64_t newHeight);
        bool deactivateProposal(uint64_t proposalId);

        /* Process governance transactions from blocks */
        bool processProposalTransaction(
            const Pastella::Transaction &tx,
            const Pastella::TransactionExtraGovernanceProposal &proposalExtra,
            const std::string &proposerAddress,
            uint64_t blockHeight);

        bool processVoteTransaction(
            const Pastella::Transaction &tx,
            const Pastella::TransactionExtraGovernanceVote &voteExtra,
            const std::string &voterAddress,
            uint64_t voteHeight);

        /* State management */
        void loadFromDatabase(IDataBase &database);
        void saveToDatabase(IDataBase &database);

        /* Statistics */
        uint64_t getTotalProposals() const;
        uint64_t getActiveProposalsCount() const;
        std::pair<uint64_t, uint64_t> getTotalVotes(uint64_t proposalId) const; // for, against

        /* Get next available proposal ID */
        uint64_t getNextProposalId() const;
    };

} // namespace Pastella
