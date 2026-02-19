// Copyright (c) 2026, The Pastella Team
//
// Simple Reward Staking System Implementation
// Please see the included LICENSE file for more information.

#pragma once

#include "IBlockchainCache.h"
#include <Pastella.h>
#include <common/TransactionExtra.h>
#include <common/StringTools.h>
#include <crypto/crypto.h>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <string>
#include <mutex>

namespace Pastella
{
    /* Staking entry structure for tracking active stakes */
    /* TRANSPARENT SYSTEM: stakerAddress stores the wallet address that created the stake
     * This is needed so we know where to send the rewards when the stake matures */
    struct StakingEntry
    {
        std::string stakingTxHash;
        std::string stakerAddress;   // Wallet address that created the stake (for reward payouts)
        uint64_t amount;
        uint64_t lockDurationDays;
        uint64_t unlockTime;
        uint64_t accumulatedReward;
        uint32_t lastCalculatedBlock;
        bool isActive;
        uint64_t creationHeight;

        /* Enhanced reward calculation fields */
        uint64_t blocksStaked;
        uint64_t dailyRewardRate;
        uint64_t estDailyReward;
        uint64_t estWeeklyReward;
        uint64_t estMonthlyReward;
        uint64_t estYearlyReward;
        uint64_t accumulatedEarnings; /* Total earned so far */
        uint64_t totalRewardAtMaturity; /* Total reward when stake completes */

        StakingEntry() :
            amount(0), lockDurationDays(0), unlockTime(0), accumulatedReward(0),
            lastCalculatedBlock(0), isActive(false), creationHeight(0), blocksStaked(0),
            dailyRewardRate(0), estDailyReward(0), estWeeklyReward(0),
            estMonthlyReward(0), estYearlyReward(0), accumulatedEarnings(0), totalRewardAtMaturity(0) {}
    };

    /* Staking pool state management */
    class StakingPool
    {
    private:
        uint64_t totalPoolBalance;
        uint64_t totalStakedAmount;
        uint64_t currentBlockHeight;
        std::unordered_map<std::string, StakingEntry> activeStakes;
        std::vector<uint64_t> blockRewardContributions;
        mutable std::mutex m_mutex;

    public:
        StakingPool();

        /* Pool management */
        bool initialize();
        bool restoreStakingTransaction(const std::string &txHash,
                                    uint64_t amount, uint64_t unlockTime, uint32_t lockDurationDays,
                                    uint64_t creationHeight, uint64_t currentBlockchainHeight);
        bool addTransactionFee(uint64_t fee);
        uint64_t getAvailableBalance() const;
        uint64_t getTotalStakedAmount() const;
        uint64_t getTotalPoolBalance() const;
        uint64_t getTotalPaidStakingRewards() const;

        /* Staking operations */
        /* TRANSPARENT SYSTEM: stakerAddress is the wallet address that created the stake */
        bool addStake(const std::string &txHash,
                     const std::string &stakerAddress, uint64_t amount, uint32_t lockDurationDays, uint64_t creationHeight);
        
        /* Reward calculations */
        uint64_t calculateReward(uint64_t amount, uint32_t lockDurationDays,
                               uint64_t blocksStaked) const;
        uint64_t getPendingRewards(const std::string &address) const;

        /* Enhanced reward calculations */
        bool calculateDetailedRewards(Pastella::StakingEntry &entry, uint64_t currentHeight) const;

        /* Staking information */
        std::vector<StakingEntry> getActiveStakes() const;
        std::vector<StakingEntry> getInactiveStakes() const;
        std::vector<StakingEntry> getStakesByHashes(const std::vector<std::string> &stakingTxHashes) const;

        /* Phase 2: Stake lifecycle management */
        bool deactivateStake(const std::string &stakingTxHash);
        bool deactivateStakeWithReward(const std::string &stakingTxHash, uint64_t finalRewardAmount);

        /* Update staker address for restored stake */
        bool updateStakeStakerAddress(const std::string &stakingTxHash, const std::string &stakerAddress);

        /* Reactivation functionality for rewind */
        bool reactivateStakesAboveHeight(uint64_t targetHeight);
        bool reactivateStake(const std::string &stakingTxHash);

        /* Validation */
        bool validateLockDuration(uint32_t lockDurationDays) const;
        bool validateMinimumAmount(uint64_t amount) const;

        /* Governance voting power calculation */
        uint64_t getVotingPower(const std::string &address, uint64_t currentHeight) const;
        bool hasActiveStake(const std::string &address) const;
        std::vector<std::pair<std::string, uint64_t>> getAllVotingPowers(uint64_t currentHeight) const;

        /* Block reward calculation */
        uint64_t calculateBlockReward(uint64_t height, uint64_t alreadyGeneratedCoins = 0) const;

        /* Historical rewards tracking */
        bool isHistoricalRewardsInitialized;
    };

    /* Staking transaction validation */
    class StakingValidator
    {
    public:
        static bool validateStakingTransaction(const TransactionExtraStaking &stakingData,
                                              const TransactionPrefix &tx,
                                              const Pastella::IBlockchainCache *blockchainCache,
                                              uint64_t currentHeight);

    private:
        static bool isValidStakingType(uint8_t stakingType);

        /* CRITICAL: Verify signature proves ownership of inputs being staked */
        static bool verifyStakingSignatureForTransaction(const TransactionExtraStaking &stakingData,
                                                         const TransactionPrefix &tx,
                                                         const Pastella::IBlockchainCache *blockchainCache);
    };

    /* Utility functions */
    uint64_t calculateUnlockTime(uint32_t lockDurationDays, uint64_t currentHeight);
    uint32_t getRewardRateForLockPeriod(uint32_t lockDurationDays);
    bool isValidLockPeriod(uint32_t lockDurationDays);
}